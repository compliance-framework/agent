# Agent Configuration

## Introduction

In order to configure an agent you must make a YAML, JSON or TOML config file at a location of your choice and pass the
path to the agent when you run it as follows:
```shell
$ ccf-agent -c /path/to/config.yaml
```

The configuration file must include `api`. Configure `plugins` when the agent should collect plugin evidence; if no
plugins are configured, daemon mode still emits its own passing run evidence on the configured interval.

```yaml
api:
  url: http://localhost:8080

plugins:
  <plugin_identifier>:  # Can have as many of these as you like
    labels:
      <key>: <value>
      <key>: <value>
    source: <plugin_source>
    policies:
      - <policy1>
      - <policy2>
      ...
    config:
      <config1>: <value1>
      <config2>: <value2>
      ...
    policy_data:  # Optional dynamic data for policies
      <key>: <value>
      ...

agent_evidence:
  enabled: true
  emit_on_run_completion: true
  interval: 1h
```

The `plugin_identifier` is a unique identifier for the plugin, and is used to identify the plugin in the logs, you can
name this whatever you like but it must be unique.

The `labels` should uniquely identify this agent instance. The agent sets the `_agent` label on plugin evidence using
the following fallback chain: `api.auth.client_id` when available, then `KUBERNETES_POD_NAME` or `KUBERNETES_POD`, and
finally a deterministic SHA-256 hash of the runtime plugin and agent evidence configuration. Because evidence UUIDs are
seeded from labels, changing either the agent identity or runtime configuration changes the evidence stream for plugin
evidence.

The `plugin_source` is the path to the plugin binary that the agent will run. This can be a relative or absolute path or
even a URL to a remote plugin.

The `policies` field is a list of paths to the policy files that the plugin will use to assess the data it collects.

The `config` field is a map of configuration values that the plugin will use to connect to the data source. The values
will be passed to the plugin when it is run.

The `policy_data` field is an optional map of dynamic data that will be passed to the plugin's policy manager. This data
can be of any shape and is made available to OPA/Rego policies during evaluation. This allows you to provide runtime
configuration to policies without modifying the policy files themselves.

Usage: `satisfied if input.value == data.allowed_value`

You can specify as many plugins as you wish, as long as each identifier is unique. You can even reuse the same plugin
multiple times with different configurations.

The `agent_evidence` field configures evidence emitted by ccf-agent about its own plugin collection run. By default,
ccf-agent emits this evidence when a run reaches a terminal point, such as after the first complete plugin run, after a
non-daemon run completes, or when startup plugin or policy downloads fail. The daemon also emits evidence every `1h`
whether or not every plugin has run yet. If any plugin has failed, the evidence status is `not-satisfied`; otherwise it
is `satisfied`. A plugin remains in the `Plugins with errors` summary until it finishes a later run successfully.
Plugins that have never run are listed as pending. Failed plugin errors are attached as back-matter resources and linked
from the evidence so they can be downloaded.

Agent evidence uses these labels: `_agent`, `tool`, and `type`. The `_agent` label uses the following fallback chain:
`api.auth.client_id` when available, then `KUBERNETES_POD_NAME` or `KUBERNETES_POD`, and finally a SHA-256 hash of
plugin names, sources, protocol versions, schedules, policies, plugin config, plugin labels, and `agent_evidence`
settings. The hash does not include API URL, API auth, or verbosity. The `tool` label is `ccf`; the `type` label is
`operations`.

If no plugins are configured, ccf-agent still emits passing agent evidence on the configured interval when running in
daemon mode. In non-daemon mode, ccf-agent can emit agent evidence only once per invocation.

As an example, a configuration file might look like this:
```yaml
api:
  url: http://localhost:8080
  auth:
    client_id: "123e4567-e89b-12d3-a456-426614174000"
    client_secret: "agent-client-secret"

plugins:
  local-ssh-security:
    labels:
      type: ssh
      group: production

    source: "../plugin-local-ssh/cf-plugin-local-ssh"
    policies:
      - "../plugin-local-ssh-policies/dist/bundle.tar.gz"

    config:
      host: "10.0.0.4"
      username: "user"
      password: "password"

  local-ssh-security2:
    labels:
      type: ssh
      group: production

    source: "../plugin-local-ssh/cf-plugin-local-ssh"
    policies:
      - "../plugin-local-ssh-policies/dist/bundle.tar.gz"

    config:
      host: "10.0.0.5"
      username: "user"
      password: "password"
```

## Optional Configuration Fields

The following fields are optional:
```yaml
api:
  auth:
    client_id: ""
    client_secret: ""

plugins:
  <plugin_identifier>:
    schedule: <cron_expression>

agent_evidence:
  enabled: true|false
  emit_on_run_completion: true|false
  interval: <duration>

verbosity: <log_level>
```

The `schedule` field is a cron expression that specifies when the plugin should run. If this field is not present the
plugin will run on a default `* * * * *`. The schedule is in the format `minute hour day month day_of_week`.

The `api.auth` fields are optional. If you set either `client_id` or `client_secret`, you must set both. The
`client_id` must be a valid UUID.

The `agent_evidence.interval` value is a Go-style duration such as `30m`, `1h`, or `2h45m`. Set it to `0s` to disable
periodic agent evidence while keeping `emit_on_run_completion` behavior enabled. Set `agent_evidence.enabled` to
`false` to disable all ccf-agent self-evidence. Agent evidence expires after five configured intervals, so the default
`1h` interval produces a `5h` expiry. When `interval` is `0s`, periodic agent evidence is disabled and agent evidence has
no expiry. Set `agent_evidence.emit_on_run_completion` to `false` to disable immediate agent evidence on run completion
and startup failures while leaving periodic daemon evidence controlled by `interval`.

The `log_level` is one of the following, defaulting to `0` if not specified (a remote overlay's `verbosity` wins over
the `-v` flag):
- 0: Shows all ERROR, WARN and INFO
- 1: Shows all of 0 plus DEBUG logs
- 2: Shows all of 1 plus TRACE logs

## Plugin `enabled`

```yaml
plugins:
  <plugin_identifier>:
    enabled: false   # default true
```

A disabled plugin gets no schedule, no download and no run state, but it stays in the configuration the agent reports.

## Typing of plugin values

Values in the config file keep viper's weak typing exactly as before: `collect_ip_allow_list: false` reaches the plugin
as `"0"`, `account_id: 123456789012` as `"123456789012"`, and `port: 22` as `"22"`. Values set by a remote overlay
must already be strings: a remote `port: 2222` (a number) is rejected with `invalid-type` (R27, R51).

Viper lowercases keys and splits them on dots. Plugin names and config keys in the file are therefore lowercase and
cannot contain dots; a remote overlay that uses `GitHub` addresses a different plugin than the file's `github`. Plugin
names an overlay introduces must match `^[a-z0-9][a-z0-9_-]{0,62}$` (R28).

## `${env:NAME}` placeholders

A `plugins.<p>.config` value may reference environment variables, whole or embedded:

```yaml
plugins:
  postgres:
    config:
      password: "${env:PG_PASSWORD}"
      dsn: "postgres://app:${env:PG_PASSWORD}@db:5432/app"
```

Placeholders are resolved **only** in `plugins.*.config`, in the file and in a remote overlay. Anywhere else (for
example `policy_data` or `labels`) a placeholder is not resolved: in the file it is passed through as a literal string,
as it always was, and reported as a warning; a remote overlay that puts one there is rejected. `CCF_API_AUTH_*` may
never be referenced. An unset variable that the **file** references is a warning, and the value reaches the plugin
unchanged (the literal `${env:NAME}`), exactly as before placeholders were resolved (R60). An unset variable that a
remote overlay introduces fails the revision with `env-missing`; the error names the variable, never a value. Reports,
redaction and the configuration digest always use the unresolved placeholder, so rotating a secret never changes them
(R24).

Plugin values set through viper environment variables (`CCF_PLUGINS_<P>_CONFIG_<K>`, see the README) are masked as
`••••` in every report, as are keys that look like secrets (`secret`, `token`, `password`, `key`, `credential`,
`auth`) (R25).

## Tolerated file problems

A plugin `schedule` in the file that does not parse does not stop the agent: that plugin is skipped, the others run,
and the problem is logged and reported as a warning (R34). A few other file values that always loaded are also only
warnings, and are kept unchanged: a negative `verbosity` (`-1` logs WARN and above), a literal `${env:...}` outside
`plugins.*.config`, and an unset variable referenced from the file's `plugins.*.config` (see above). Every other
invalid value in the file (for example a missing `api.url`) still fails startup, and on a live reload the agent keeps
running its last good configuration. Values set by a remote overlay are always validated strictly.

## Remote configuration

An agent with `api.auth` credentials can pick up a configuration overlay stored in the API. The `remote_config` block
controls it. It is **set locally only** (file, host environment, CLI flags), never remotely (R30):

```yaml
remote_config:
  mode: apply_safe            # off | report | apply_safe | apply_all
  poll_interval: 60s          # at least 15s
  trusted_sources: []         # glob list of plugin/policy sources an overlay may introduce
  overridable_config_flags: []  # glob list of plugins.*.config keys an overlay may change
  allow_local_sources: false
```

Defaults (R29): `mode` is `apply_safe` when `api.auth` is set and `off` otherwise (no credentials always forces
`off`); `poll_interval` is `60s`; `trusted_sources` and `overridable_config_flags` are empty;
`allow_local_sources` is `false`. `CCF_REMOTE_CONFIG_MODE` sets the mode even when the file has no
`remote_config` block.

| Mode | Behaviour |
|---|---|
| `off` | No report, no fetch. The heartbeat carries no configuration fields. |
| `report` | The agent reports its configuration (status `not-applicable`) but never fetches an overlay. |
| `apply_safe` | The agent fetches the overlay and applies it only when every change is safe (table below). |
| `apply_all` | The agent applies safe and unsafe changes. Forbidden changes are still rejected. |

A change is classified as follows (the agent is the authority; the API preview uses the same rules):

| Change | Class |
|---|---|
| `api`, `daemon` or `remote_config` in the overlay | **forbidden** (the whole revision is rejected in every mode) |
| `verbosity`, `agent_evidence.*` | safe |
| a plugin's `schedule`, `labels`, `policy_behavior`, `protocol_version`, `enabled`, `policy_data` | safe |
| removing a plugin or a policy entry | safe |
| a plugin source or policy entry already used by the file | safe |
| a new source matching `trusted_sources` | safe |
| a new OCI source not in `trusted_sources` | unsafe |
| a new local path | forbidden, unless `apply_all` with `allow_local_sources: true` (then unsafe) |
| a `plugins.<p>.config.<k>` change matching `overridable_config_flags` (`key`, `plugin:key` or `*`) | safe |
| any other plugin config change | unsafe |
| a new `${env:NAME}` reference | unsafe (`CCF_API_AUTH_*`: forbidden) |

A rejected or failed revision never interrupts the running configuration: the agent prepares the whole new
configuration (validation, downloads) first and swaps only when it is ready. Every outcome is reported to the API with
a reason (`unsafe-changes`, `forbidden-changes`, `invalid-config`, `invalid-type`, `unknown-field`, `env-missing`,
`download-failed`, `cache-corrupt`, `internal`). When a new configuration is applied,
in-flight plugin runs get up to 5 minutes to finish (R33). Evidence produced under an overlay carries the prop
`agent-config-revision` (namespace `https://compliance-framework.github.io/ns`).

The agent caches the last fetched and applied overlay in `<state>/remote-config.json` (mode 0600, bound to `api.url`
and `api.auth.client_id`), so it keeps running the last good overlay when the API is unreachable. At startup it tries,
in order: the freshly fetched overlay, the cached applied overlay, the file alone. Only an unusable file stops the agent.
A fetched overlay already rejected for the same file is skipped, and its rejection (with the unsafe changes) is reported
again, so the instance still shows as rejected after a restart.

### Sources for the UI (R62)

Outside mode `off`, the configuration report inventories every policy source the instance's plugins load (each OCI or
local source) as `policy-bundles[]`: the source, its tree digest and its files (path, SHA-256 and, for a Rego module,
its package). The agent also uploads each tree as a policy bundle artifact and reports its `artifact-digest` next to the
tree digest, so the UI can show the sources. These are the same artifacts evidence references for playback: one
uploader serves both, and a tree is uploaded once. Uploads are best effort: a failure (an API without artifacts, a tree
over the API's size limit, a timeout) leaves `artifact-digest` empty and never rejects or fails a revision. Note that
artifacts are readable with `artifact:read`. When the report is too large, the file lists are dropped first, then the
`base` document; the digests are kept.

### Plugin library versions (R76)

The report also lists the instance's plugins as `plugins[]` (`name`, `source`, `lib-version`), where `lib-version` is
the version of this agent library the plugin binary was built with, read from its Go build info without starting it.
It is empty when unknown (a `replace`d or `(devel)` build, or a binary without build info). It is diagnostic only:
nothing is gated on it.

## State directory and instance ID

Each agent instance keeps state in `.compliance-framework/state/<key>/`, relative to the working directory, where
`<key>` is derived from the absolute path of the config file (R31): the instance ID (`instance-id`) and the remote
configuration cache. The OCI download caches in `.compliance-framework/plugins` and
`.compliance-framework/policies` are shared.

| Setting | Flag | Environment |
|---|---|---|
| State directory | `--state-dir` | `CCF_STATE_DIR` |
| Instance ID (a UUID; not persisted) | `--instance-id` | `CCF_INSTANCE_ID` |

Because the default key depends on the config file's path, **moving or renaming the config file creates a new
instance** (R52). The agent logs the state directory, where it came from and the instance ID at startup. Containers and
Helm deployments should pin `CCF_STATE_DIR` to a mounted volume; ephemeral one-shot runs (CI, Kubernetes jobs) can
set `CCF_INSTANCE_ID` so repeated runs report as one instance.

Plugins receive the agent's environment except `CCF_API_AUTH_*` (R26).
