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
running configuration untouched and is reported. In-flight plugin runs drain for up to 5 minutes on a swap. A run that
fails on its own after a swap falls back to the previous configuration. Startup tries the fetched overlay, then the
cached applied overlay, then the file alone; only an unusable file exits.

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
(ETag, base fingerprint), never per revision number.

### File-origin tolerance (R34)

The shared `Validate` is stricter than the agent used to be in one way: it parses `schedule`. A bad schedule in the
file used to be only logged, and the plugin never ran. To stay non-breaking, a validation error is attributed by
origin: an error at a pointer the overlay touched (equal, prefix or extension, segment-wise) is overlay-origin and
rejects the revision; otherwise it is file-origin. File-origin errors on the closed tolerated list (only
`/plugins/<p>/schedule`) become reported warnings and the plugin is skipped; every other file-origin error stays fatal
(startup exit 1, or last-known-good on reload).

## Consequences

- Reports never carry resolved secrets: base and effective are the unresolved forms, redacted with the same masked
  pointers the effective digest uses (R24, R25, R55).
- The default state directory depends on the config path; containers must pin `CCF_STATE_DIR` (R52).
- A new agent that does not understand a newer overlay key rejects the revision with `unknown-field`, visible in the UI.
- Known limit: viper stops watching the config file after a `Remove` event (follow-up).
