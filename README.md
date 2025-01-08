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

## NATS

Upon the plugin(s) running, they'll send the results of the Observations and/or Findings to an event queue (-flag
configured).

To run an instance of NATS, checkout the [local-dev](https://github.com/compliance-framework/local-dev) repository:

## Configuration

The agent must be configured using a configuration file that can be in any of YAML, JSON or TOML. We'll assume YAML
because it's fairly human-readable and widespread.

### Basic

```
daemon: true|false
verbosity: 0|1|2

nats:
  url: nats://127.0.0.1:4222

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
```

See [configuration](./docs/configuration.md) for more information.

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

# Development

## Generating Protobufs

You'll need the `buf` cli installed. See installation instructions: https://buf.build/docs/installation/

```shell
make proto-gen
