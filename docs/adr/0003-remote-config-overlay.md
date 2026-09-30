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

### Plugin environment filter

go-plugin hands the whole host environment to plugins. The agent now sets `SkipHostEnv` and passes the host
environment minus `CCF_API_AUTH_*`, so plugins never see the agent's API credentials; cloud credentials, `PATH`,
`HOME` and the rest still pass through (R26).

### Opaque ETag

The overlay ETag is opaque (`"r<rev>-<uuid>"`). The agent stores the raw header in its cache and sends it back
verbatim as `If-None-Match`; it never builds one from a revision number, so a reset or recreated API can never produce
a false 304 (R7). The cache is bound to `api.url` and `client_id`, and a rejected revision is remembered per
(ETag, base fingerprint), never per revision number alone. A response without an ETag (a stripping proxy) is keyed by
revision + sha256 of the overlay instead, so one rejection never blocks later revisions.

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
