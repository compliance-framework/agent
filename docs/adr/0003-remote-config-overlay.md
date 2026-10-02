# ADR 0003: Remote configuration overlay

- Date: 2026-09-30
- ADR 0002 is reserved for evidence-v3.

## Context

Operators want to see the configuration each agent is running and to change it from the API (new schedules, plugin
config, policy data, policy sources) without logging in to every host. The local config file must stay the bootstrap and
the host owner's control: the API connection, the daemon flag and the remote-configuration policy itself must never be
changeable remotely, and a bad remote change must never take a working agent down.

The shared configuration model lives in the API module (`api/pkg/agentconfig`), so the agent, the API's validation and
the UI preview classify and validate changes the same way.

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
overlay validation, the `Classify` gate, merge, validation, `${env:}` resolution, and every download (`Prefetch`). Only then is the running configuration cancelled. Any failure leaves the
running configuration untouched and is reported. Each network step of a prepare is bounded (5 minutes), so a hung
registry is a `download-failed`, not a stalled reconciler. In-flight plugin runs drain for up to 5 minutes on a swap; a
SIGINT/SIGTERM during the drain still exits within 30 seconds. A run that fails on its own after a swap falls back to
the previous configuration and that candidate (overlay or file-only) enters the failed backoff, so it is not re-applied
on every poll. A candidate whose effective configuration equals the running one (a no-op revision, a comment-only file
edit) is recorded as applied without a restart: the heartbeat, evidence and report show its revision. An applied
overlay that a file edit makes invalid is remembered as rejected and the last good configuration keeps running.
Startup tries the fetched overlay,
then the cached applied overlay, then the file alone; only an unusable file exits (a download failure of the file
alone still sends the startup-failure agent evidence first, as before).

### The agent is the Classify authority

The API validates and previews, but the agent classifies every revision against its own base and its own
`remote_config` before applying it (`agentconfig.Classify` + `WillApply`). Forbidden changes (the locked keys, local
sources, `${env:CCF_API_AUTH_*}`) reject the whole revision in every mode (R23). Nothing touches the network before the
gate passes.

### Inline policy bundles are out of scope

Inline policy bundles (authoring, overriding or deleting policy modules through the config file or an overlay) are not
part of this design (decision of 2026-10-02): keeping vendor evidence streams, checking the policy contract and
sandboxing the checks made them the largest and riskiest part of the change. Policies
reach plugins only as OCI or local sources, which an overlay may add, remove or reorder under the `Classify` rules. An
overlay that sets `policy_bundles` is rejected with `unknown-field`, and the report has no policy errors.

### Plugin library versions (R76)

What a plugin does with a policy depends on the `policy-manager` compiled into it, not on the running agent. The agent
reads the `github.com/compliance-framework/agent` version from each plugin binary with `debug/buildinfo.ReadFile`
(memoized by path, size and modification time) after prefetch and reports it (`plugins[].lib-version`) as diagnostics.
Nothing is gated on it. A `replace` or devel build reports an empty version.

### One channel for policy sources (R62)

The UI needs to show the policy sources an instance loads, and the API never sees them. Rather than a second route, the
agent reuses the evidence artifact store: one process-wide `runner.ArtifactUploader` is shared by the reconciler and
every plugin's API helper, and one archiver (`internal/policytree`: `ReadTree` + `TarFiles`) serves both, so the
configuration-time and evaluation-time uploads of a tree are the same bytes and the same artifact. At report time the
reconciler uploads each reported tree once (memoized by tree digest per API) within the remote request timeout and
fills `artifact-digest` on its `policy-bundles[]` entry; the field survives report truncation. Failures leave it empty
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
its status, reason, error and unsafe changes, so the agent re-reports it after a restart and while the fetch keeps
answering 304.

### File-origin tolerance (R34)

The shared `Validate` is stricter than the agent used to be in one way: it parses `schedule`. A bad schedule in the
file used to be only logged, and the plugin never ran. To stay non-breaking, a validation error is attributed by
origin: an error at a pointer the overlay touched (equal, prefix or extension, segment-wise) is overlay-origin and
rejects the revision; otherwise it is file-origin. File-origin errors on the closed tolerated list (only
`/plugins/<p>/schedule`) become reported warnings and the plugin is skipped. A second, warn-only list covers values
that load on `main` with a meaning the agent keeps: a negative `verbosity` (hclog Warn) and a literal `${env:...}`
outside `plugins.*.config`. They are reported as warnings; nothing is
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
