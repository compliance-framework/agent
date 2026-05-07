# Compliance Framework Agent

The Compliance Framework Agent, is the central component responsible for running plugins on schedule, passing them
policies, and keeping plugins and policies up to date based on upstream plugins and policies.

## Plugins

Plugins are the primary method of gathering data for policy checks. Plugins will execute some code to fetch the
data necessary for specific compliance checks, and then run these against policies to ensure compliance with a
businesses' policies.

As an example, there is a plugin called `local-ssh`. This plugin will retrieve the SSH configuration on a machine,
convert it to a usable json structure, and then run company policies against the SSH configuration to ensure a host
machine complies with all regulatory and security policies.

The Agent is responsible for starting and calling these plugins, when it is necessary, usually on a set schedule.

Plugins are entirely flexible in that they can be used to test any type of configuration or data, as long as they report
findings and observations about what they found.

## Policies

Polices, although not strictly required, are written in Rego, and passed to each plugin so it can assert whether
the data it has collected, conforms with organisational policies.

For each violation of the policies, the plugin will report findings and observations to the agent, which in turn will
report these to the central configuration api.

## Configuration

The agent must be configured using a configuration file that can be in any of YAML, JSON or TOML. We'll assume YAML
because it's fairly human-readable and widespread.

### Basic

```
daemon: true|false
verbosity: 0|1|2
api:
  url: http://localhost:8080
  auth:
    client_id: ""
    client_secret: ""

plugins:
  <plugin_identifier>:  # Can have as many of these as you like
    source: <plugin_source>
    labels:
      type: plugin-check
      host: 12345
    policies:
      - <policy>
      - <policy>
    config:
      <config1>: <value>
      <config2>: <value>

agent_evidence:
  enabled: true
  emit_on_run_completion: true
  interval: 1h
```

See [configuration](./docs/configuration.md) for more information.

### Environment variables

The agent can load specific configruation values from environment variables, which are prefixed with `CCF_` and the path 
in the config is specified using underscore-separated key.

For example, to specify the `token` value in the GitHub config, you may set an environment variable `CCF_PLUGINS_GITHUB_CONFIG_TOKEN`
```yaml
plugins:
  github:
    config: 
      token: ""
```

The API auth settings follow the same rule, so `api.auth.client_id` and `api.auth.client_secret` can be provided with
`CCF_API_AUTH_CLIENT_ID` and `CCF_API_AUTH_CLIENT_SECRET`. These values must be configured together; setting only one
will fail agent startup validation. The `client_id` value must be a valid UUID.

## Usage

To run the agent, you must first build the agent, and then run it with the `agent` command. It is recommended,
particularly if you wish to run the agent as a daemon, that you copy it into the PATH of the machine in something like
`/usr/local/bin`.

To run after checking out this repository you can run the following:
```shell
go build -o concom main.go
./concom agent --config PATH_TO_CONFIG_FILE
```
or even simpler:
```shell
go run main.go agent --config PATH_TO_CONFIG_FILE
```

### Submit evidence

For CI systems that already know the evidence they want to report, use `submit-evidence` to send a single evidence
record without running plugins or policies.

```shell
./concom submit-evidence "Pipeline ran successfully" \
  --api-url https://your-compliance-framework.url.com \
  --status satisfied \
  --label provider=gitlab \
  --label evidence-kind=pipeline-artifact \
  --link "Pipeline=https://gitlab.example.com/group/project/-/pipelines/123"
```

The command also accepts a YAML or JSON evidence file:

```shell
./concom submit-evidence -f evidence.yaml --label provider=gitlab
```

Labels are mandatory and are used to derive the evidence UUID. Do not provide a UUID in the evidence file.
`--api-url` can also be provided by `CCF_API_URL` or `INPUT_API_URL`. API authentication uses
`CCF_API_AUTH_CLIENT_ID` and `CCF_API_AUTH_CLIENT_SECRET`.

# Development

## Generating Protobufs

You'll need the `buf` cli installed. See installation instructions: https://buf.build/docs/installation/

```shell
make proto-gen
