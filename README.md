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

Upon the plugin(s) running, they'll send the results of the Observations and/or Findings to an event queue (-flag configured).

To run a local instance of NATS run this [docker command](https://docs.nats.io/running-a-nats-service/nats_docker) (note `-DVV` flag for verbosity): 

```shell
docker run --name nats --network nats --rm -p 4222:4222 -p 8222:8222 nats --http_port 8222 -DVV
```

## Usage

```shell
go run main.go agent --policy PATH_TO_OPA_DIR_OR_BUNDLE --plugin PATH_TO_PLUGIN_EXECUTABLE --natsServer="nats://localhost:4222"
```
