# Agent Configuration

## Introduction

In order to configure an agent you must make a YAML, JSON or TOML config file at a location of your choice and pass the
path to the agent when you run it as follows:
```shell
$ concom-agent -c /path/to/config.yaml
```

The configuration file must have the following fields:

```yaml
nats:
  domain: <nats_domain>
  port: <nats_port>

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
```

The `nats_domain` and `nats_port` items are the domain and port of the NATS server that the agent will connect to.

The `plugin_identifier` is a unique identifier for the plugin, and is used to identify the plugin in the logs, you can
name this whatever you like but it must be unique.

The `labels` should uniquely identify this agent instance.

The `plugin_source` is the path to the plugin binary that the agent will run. This can be a relative or absolute path or
even a URL to a remote plugin.

The `policies` field is a list of paths to the policy files that the plugin will use to assess the data it collects.

The `config` field is a map of configuration values that the plugin will use to connect to the data source. The values
will be passed to the plugin when it is run.

You can specify as many plugins as you wish, as long as each identifier is unique. You can even reuse the same plugin
multiple times with different configurations.

As an example, a configuration file might look like this:
```yaml
nats:
  domain: localhost
  port: 4222

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
plugins:
  <plugin_identifier>:
    schedule: <cron_expression>

verbose: <log_level>
```

The `schedule` field is a cron expression that specifies when the plugin should run. If this field is not present the
plugin will run on a default `* * * * *`. The schedule is in the format `minute hour day month day_of_week`.

The `log_level` is one of the following, defaulting to `0` if not specified:
- 0: Shows all ERROR, WARN and INFO
- 1: Shows all of 0 plus DEBUG logs
- 2: Shows all of 1 plus TRACE logs
