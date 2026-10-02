# ADR 0003: Remote configuration overlay

- Date: 2026-09-30
- ADR 0002 is reserved for evidence-v3.

## Context

Operators want to see the configuration each agent is running and to change it from the API (new schedules, plugin
config, temporary inline policies) without logging in to every host. The local config file must stay the bootstrap and
the host owner's control: the API connection, the daemon flag and the remote-configuration policy itself must never be
changeable remotely, and a bad remote change must never take a working agent down.

The shared configuration model lives in the API module (`api/pkg/agentconfig` and `api/pkg/agentconfig/regocheck`), so
the agent, the API's validation and the UI preview classify and validate changes the same way.

## Decision

### Declared and runtime forms

`agentconfig.Config` is the *declared* form: what is decoded, merged (RFC 7396), classified, validated, redacted,
digested and reported. The agent's existing private structs remain the *runtime* form, built by one `toRuntime`
conversion. Type aliases were not possible (methods on the structs, an unexported field, and many tests), and keeping
the runtime form keeps `agentConfigurationHash`, and so evidence identity, byte-identical.

The file is decoded through viper's weak decoder exactly as before (R51). Only a remote overlay is decoded strictly
(`ValidateOverlay`): unknown keys and wrongly-typed values reject the revision (R27).

### Prepare, then cancel

One reconciler goroutine serializes every trigger (config file change, poll). A trigger builds a complete candidate:
overlay validation, the `Classify` gate, merge, validation, `${env:}` resolution, inline bundle materialization and
checks, and every download (`Prefetch`). Only then is the running configuration cancelled. Any failure leaves the
running configuration untouched and is reported. Each network step of a prepare is bounded (5 minutes), so a hung
registry is a `download-failed`, not a stalled reconciler. In-flight plugin runs drain for up to 5 minutes on a swap; a
SIGINT/SIGTERM during the drain still exits within 30 seconds. A run that fails on its own after a swap falls back to
the previous configuration and that candidate (overlay or file-only) enters the failed backoff, so it is not re-applied
on every poll. A candidate whose effective configuration equals the running one (a no-op revision, a comment-only file
edit) is recorded as applied without a restart: the heartbeat, evidence and report show its revision. An applied
overlay that a file edit makes invalid is remembered as rejected and the last good configuration keeps running.
Materialized inline bundles are garbage-collected at startup and after every swap. Startup tries the fetched overlay,
then the cached applied overlay, then the file alone; only an unusable file exits (a download failure of the file
alone still sends the startup-failure agent evidence first, as before).

### The agent is the Classify authority

The API validates and previews, but the agent classifies every revision against its own base and its own
`remote_config` before applying it (`agentconfig.Classify` + `WillApply`). Forbidden changes (the locked keys, local
sources, `${env:CCF_API_AUTH_*}`) reject the whole revision in every mode (R23). Nothing touches the network before the
gate passes.

### Per-path compile unit and transitive denied builtins

Plugins evaluate every policy path as its own bundle, so the agent checks an inline bundle per (plugin, policy path)
through the same `policyeval.NewFromBundlePath` prepare path `policy-manager` uses (R21). Cross-bundle imports are
unsupported. The API's Rego check is parse-level; the agent additionally walks every rule reachable from the bundle's
authored rules in the compiled rule graph and rejects any `policyeval.DeniedBuiltins` reference (`http.send`,
`net.lookup_ip_addr`, `opa.runtime`), including through vendor helpers and `with ... as http.send` (R19, R20).
When the walk finds one, the bundle's Rego tests are not run. The tests themselves run sandboxed: they compile under
`policyeval.SandboxCapabilities` with every denied builtin rewritten to a stub that errors, so no denied builtin ever
executes on the agent host while a revision is checked (D17); a vendor test that needs one simply fails (a warning).

Residual risk (R20): a vendor rule that already calls `http.send` with a URL taken from `data` makes `policy_data`
edits to that plugin effectively able to direct its requests. Eval-time capabilities are a follow-up.

### Policy contract: the agent is authoritative (R63, R65)

The API's `regocheck` runs `policyeval.CheckContract` on the authored modules only (it lacks the extends trees). The
agent, after the compile and the tests pass, adds what needs the whole tree: the static check on the vendor-only
packages (warnings, never re-run on authored modules), and a dry run on an empty input through `policyeval.Execute`
and `policy-manager`'s `GetRiskTemplates`, sandboxed like the tests. Decode errors and `Result.Issues` become located
`PolicyError`s with the contract codes: errors for packages that contain an authored non-test module, warnings for
vendor-only packages; conflicts that only show on `{}` and input-dependent titles are warnings. A package that fails to evaluate is
left out of the next attempt, so one broken package does not hide the others. A compile error in a vendor file whose
package an authored module also defines carries an override hint (R65). The per-plugin results are de-duplicated before they are reported.

### Evidence identity across a plugin's paths (R66, R75)

`policy-manager` seeds evidence UUIDs from the policy's package, file and plugin path; we never change that seed, so
the identity of an existing stream never changes. The agent checks identity statically over every module of every
policy path of each plugin that uses an inline bundle: the same identity from two paths (equal seeds, or the same
package and bundle-relative file) is `duplicate-policy-identity`, an error when the overlay introduces it (it gives
the plugin a policy entry the file does not, or changes a bundle involved) and a warning otherwise (R34), so an
overlay never fails on the file's own duplicates; what is left of R66 (the same package with different identities)
stays a warning. For an `extends` bundle, an override that changes the `package` of the vendor module it replaces is
`policy-package-changed` (a warning).

### Path shadowing (R83, R88)

A plugin seeds evidence UUIDs from the policy path string it receives, so a bundle that extends a relative source is
given to plugins at the source's own path, and the plugin runs with a per-plugin view directory as its working
directory (`internal/policyview`), in which that path's parent links to the bundle's tree and everything else mirrors
the agent's working directory. Evidence identity is then the vendor's by construction, for every plugin build. The
agent resolves every relative policy path of such a plugin through its view (artifact uploads, source props). We
rejected declaring the identity in the policy instead (an authored `policy_id` replacing the location in the seed):
it only works for plugins rebuilt on a newer agent library, while shadowing works for every build. Where a view cannot represent the paths (absolute `extends`, a plugin loading the source and the bundle
together, no symlinks) the bundle is given to plugins at its own `_inline` path and its modules start path-based
streams; each plugin that uses it gets a `policy-stream-forked` warning with the reason.
Risk: a plugin that relies on its working directory sees the view (mirrored, so reads and writes inside existing
directories still reach the agent's; new top-level files stay in the view).
Plugin contract (rule 1): plugins must not rely on creating new files relative to their working directory (use
absolute paths or `os.TempDir()`); such entries stay in the plugin's view and are removed with it. A real
(non-symlink) entry in a view is plugin-owned: when the agent's working directory later gets the same name, the
view keeps the plugin's entry instead of mirroring the agent's, warns once per view and name, and never fails a run
or an activation. Only the shadow link is agent-owned: a real entry at its path is a conflict that fails that
plugin's runs with a clear error and is not removed. Activation only logs it: views are content-addressed and
survive restarts, so failing the configuration over one plugin's view would stop every plugin and could crash-loop
the agent at startup. View GC removes whole views, plugin-owned entries included, and never follows links.

### Plugin library checks (R76, R88)

What a plugin can do with a policy depends on the `policy-manager` compiled into it, not on the running agent. The
agent reads the `github.com/compliance-framework/agent` version from each plugin binary with
`debug/buildinfo.ReadFile` (memoized by path, size and modification time) after prefetch and reports it
(`lib-version`). Shadowing makes inline bundles work with every build, so there is no gate: only an
overlay-introduced set-form `violation contains` for a plugin older than v0.7.1 is rejected (that `policy-manager`
panics on it). File bundles and unknown versions (a `replace` or devel build, which local
development relies on) only warn. Versions compare as semver and a pseudo-version counts as its base tag, so
release candidates and untagged commits before the minimum are older.

### Stable inline paths (R67)

`policy-manager` seeds evidence UUIDs with the policy file path. Materialized bundles stay write-once,
content-addressed directories (`<state>/inline/<name>/<digest>/policies`), but plugins receive a bundle that is not
shadowed at `.compliance-framework/policies/_inline/<name>/policies`, where `.compliance-framework/policies/_inline/<name>`
is a symlink swapped with an atomic rename. The path is relative, like an OCI source's, so it does not depend on the
state directory, and `_inline` cannot collide with the OCI cache next to it (repository path components start with
`[a-z0-9]`). The symlink is an intermediate path component on purpose: OPA's bundle loader does not descend into a
symlinked root directory and would silently load nothing. The run loop swaps it only
between two configuration runs, after the reload drain, and on a fallback; a plugin run therefore sees one tree from
start to end, and its API helper resolves the path when the run starts, so evidence artifacts are the tree the run
evaluated. The candidate identity still hashes the digest directories, so any tree change restarts the plugins. GC and
the swap share a lock; GC keeps the trees of the running, pending, starting and fallback candidates and whatever
the bundle's link points to.

### One channel for policy sources (R62)

The UI needs the vendor sources to pre-fill an override, and the API never sees them. Rather than a second route, the
agent reuses the evidence artifact store: one process-wide `runner.ArtifactUploader` is shared by the reconciler and
every plugin's API helper, and one archiver (`internal/policytree`: `ReadTree` + `TarFiles`) serves both, so the
configuration-time and evaluation-time uploads of a tree are the same bytes and the same artifact. At report time the
reconciler uploads each reported tree once (memoized by tree digest per API) within the remote request timeout and
fills `artifact-digest` on the bundle and its `extends`; the field survives report truncation. Failures leave it empty
and never reject or fail a revision.

### Plugin environment filter

go-plugin hands the whole host environment to plugins. The agent now sets `SkipHostEnv` and passes the host
environment minus `CCF_API_AUTH_*`, so plugins never see the agent's API credentials; cloud credentials, `PATH`,
`HOME` and the rest still pass through (R26).

### Opaque ETag

The overlay ETag is opaque (`"r<rev>-<uuid>"`). The agent stores the raw header in its cache and sends it back
verbatim as `If-None-Match`; it never builds one from a revision number, so a reset or recreated API can never produce
a false 304 (R7). The cache is bound to `api.url` and `client_id`, and a rejected revision is remembered per
(ETag, base fingerprint), never per revision number alone. A response without an ETag (a stripping proxy) is keyed by
revision + sha256 of the overlay instead, so one rejection never blocks later revisions. The remembered rejection keeps
its status, reason, error, unsafe changes and (up to 100) policy errors, so the agent re-reports it after a restart
and while the fetch keeps answering 304.

### File-origin tolerance (R34)

The shared `Validate` is stricter than the agent used to be in one way: it parses `schedule`. A bad schedule in the
file used to be only logged, and the plugin never ran. To stay non-breaking, a validation error is attributed by
origin: an error at a pointer the overlay touched (equal, prefix or extension, segment-wise) is overlay-origin and
rejects the revision; otherwise it is file-origin. File-origin errors on the closed tolerated list (only
`/plugins/<p>/schedule`) become reported warnings and the plugin is skipped. A second, warn-only list covers values
that load on `main` with a meaning the agent keeps: a negative `verbosity` (hclog Warn) and a literal `${env:...}`
outside `plugins.*.config` (except in `policy_bundles`, a new feature). They are reported as warnings; nothing is
skipped and the value is unchanged. Every other file-origin error stays fatal (startup exit 1, or last-known-good on
reload). Overlay-origin errors are always strict.

### Unset `${env:}` in the file (R60)

Owner decision (2026-09-30, review of agent#95): R24 resolves `${env:NAME}` in the file's `plugins.*.config` too, but
an unset variable that the file references is a **warning** and the literal value is passed to the plugin unchanged,
exactly as on `main`, where placeholders were never resolved. "File-origin" is decided per (pointer, variable): the
base's value at that pointer references the variable. An unset variable that the overlay introduces still fails the
revision with `failed/env-missing`.

## Consequences

- Reports never carry resolved secrets: base and effective are the unresolved forms, redacted with the same masked
  pointers the effective digest uses (R24, R25, R55).
- The default state directory depends on the config path; containers must pin `CCF_STATE_DIR` (R52).
- A new agent that does not understand a newer overlay key rejects the revision with `unknown-field`, visible in the UI.
- Known limit: viper stops watching the config file after a `Remove` event (follow-up).
