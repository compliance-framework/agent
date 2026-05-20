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
    policy_behavior:  # Optional mapping of policy sources to behavior types
      <policy1>: <behavior1>
      <policy2>: <behavior2>
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

The `policy_behavior` field is an optional mapping of policy substrings to behavior types. This allows plugins that evaluate
multiple resource types to filter policies per resource type, preventing policies from evaluating incompatible data. For
example, a plugin that evaluates both VPCs and Security Groups can use this mapping to ensure VPC policies only evaluate
VPC data and Security Group policies only evaluate Security Group data. The mapping keys must be substrings that match
the policy paths from the `policies` list. For example, if a policy is specified as
`/path/to/plugin-aws-networking-security-policies/dist/bundle.tar.gz`, you can use `plugin-aws-networking-security-policies`
as the key. The agent uses substring matching to find the corresponding policy. This approach provides flexibility while
ensuring uniqueness. If a key does not match any policy path, a warning is logged and that key is ignored. Plugins that
support this feature will use the `policyManager.GetPoliciesFor()` helper to filter policies during evaluation. If this
field is not set, all policies are passed to the plugin (backwards compatible).

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

The `log_level` is one of the following, defaulting to `0` if not specified:
- 0: Shows all ERROR, WARN and INFO
- 1: Shows all of 0 plus DEBUG logs
- 2: Shows all of 1 plus TRACE logs
