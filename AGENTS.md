# AGENTS.md: compliance-framework/agent

Guidance for coding agents working in this repo. The README and `docs/` cover running and
configuring the agent. This file covers what you need to change it without breaking CI, the
API, or the plugins built against it.

## How this repo fits

- **agent** (this repo): runs plugins on a schedule, evaluates their Rego policies, and posts
  evidence to the API.
- **api**: Go/Echo service on Postgres. It stores evidence and policy artifacts. We import its
  `sdk/` and `pkg/policyeval`.
- **plugin-\***: one repo per plugin. Each imports this repo's `runner`, `runner/proto` and
  usually `policy-manager`. Policies live in `plugin-*-policies` repos and are published as
  OCI bundles.
- **ui**: Vue app that talks only to the API.
- **local-dev**: Docker Compose stack running all of the above. Use it for end-to-end checks.

Versions are coupled:
- `go.mod` pins `github.com/compliance-framework/api`, and the OPA versions must match;
- plugins pin this module;
- the UI depends on the API's JSON shapes.

Releases are tags (`vX.Y.Z`, or `vX.Y.Z-rcN`). CI publishes the `agent`, `agent-ci` and
`agent-custodian` images to ghcr.io. A mixed-version rollout must keep working: a new
agent with old plugins, an old agent with new plugins, and either with an older API.

## Commands

There is no lint target. CI (`.github/workflows/main.yml`) runs a build, the tests, the OPA
check, and a gofmt check. The gofmt check fails on *any* change in the tree after `go fmt`,
so commit everything, including new files, before relying on it. `go vet` is not in CI but
costs nothing.

```sh
make build                 # go build -o dist/concom main.go
make test                  # go test ./... with coverage; also run go test -race ./... for concurrency changes
gofmt -l .                 # must print nothing: CI fails on any diff after go fmt
go vet ./...
make check-opa-version     # the agent's OPA version must equal the one compliance-framework/api requires
make proto-gen             # buf generate; needs the buf CLI and network access to buf.build
```

- **Committed generated files.** `runner/proto/*.pb.go` and `*_grpc.pb.go` are generated
  and committed. They come from protoc-gen-go v1.36.11 and protoc-gen-go-grpc v1.3.0, both
  pinned in `buf.gen.yaml`. Any other version churns every generated file.
- **Installing buf.** `buf` is not a Go tool dependency. Install it with
  `brew install bufbuild/buf/buf` or from the buf releases page.
- **Working against an unreleased API change.** Use a temporary `go.work` or `replace`, and
  never commit it. Before pushing, run the tests with `GOWORK=off`, so they build against the
  pinned version as CI does.

## Layout

- `main.go`: Cobra root (`agent`, `download-plugin`, `submit-evidence`).
- `cmd/agent.go`: config loading (Viper, `CCF_` prefix), the scheduler, plugin and policy
  download, plugin launch, protocol v1/v2 selection, and the `_agent` label.
- `internal/oci.go`: OCI download and extraction, with a cache keyed by reference. It also
  writes `.ccf-source.json` with the registry digest.
- `runner/`: **the plugin contract**:
  - `plugin.go`: `Runner`/`RunnerV2`, `HandshakeConfig`, `PluginMap`;
  - `grpc.go`: the `ApiHelper` client and server;
  - `evidence_stream.go`: streaming evidence from plugin to agent;
  - `result.go`: the agent-side helper that converts evidence and posts it to the API;
  - `proto/`: the `.proto` definitions and generated code.
- `policy-manager/`: Rego evaluation (`PolicyProcessor.GenerateResults`), built on
  `api/pkg/policyeval`.
- `docs/`:
  - `configuration.md`;
  - `policy_artifacts.md` (evidence props, artifacts, sources);
  - `adr/0001-support-versioned-runner-plugins.md` (protocol v1 and v2).

## The plugin contract

Plugins are compiled against a pinned version of this module and run as separate processes
over go-plugin gRPC. Plugins already in the field can't be updated with this repo, so a
change here must keep working with them.

**These break plugins:**
- `HandshakeConfig` (protocol version, magic cookie);
- the `"runner"` dispense name;
- the method sets of `Runner`, `RunnerV2` and `ApiHelper`;
- the `GenerateResults(ctx, policyPath, data)` signature;
- renumbering, retyping or removing proto fields.

**Rules:**
- Add proto fields and RPCs; never repurpose them. Run `make proto-gen` and commit the
  generated code with the `.proto` change.
- A new RPC needs a fallback for peers that predate it. The pattern to copy is in
  `runner/evidence_stream.go`: try `CreateEvidenceStream`, and on `codes.Unimplemented`
  fall back to `CreateEvidence`.
- New data from plugins should travel in new optional proto fields, so old plugins (field
  unset) and old agents (field ignored) both keep working.
- **New optional plugin behaviour.** Don't add methods to `Runner` or `RunnerV2`. Define a
  separate optional interface instead, and have the gRPC server check for it on the plugin
  implementation, returning `codes.Unimplemented` when it's missing. The agent side treats
  `Unimplemented` as "not supported". `GRPCServer.Init` in `runner/grpc.go` is the model
  (v1 plugins don't implement `RunnerV2`).
- When adding an agent-owned prop, add it to the list under "Domain rules" below too.

## Change together

- **Config key**: the struct in `cmd/agent.go`, `docs/configuration.md` and the README config
  section.
- **Evidence props the agent adds**: `runner/result.go`, `docs/policy_artifacts.md` and the
  tests in `runner/source_props_test.go`.
- **API version bump in `go.mod`**: run `make check-opa-version`; bump OPA to match if needed.

## Domain rules that are easy to break

- **Agent-owned props.** The agent sets `_agent`, `_plugin_source`, `_plugin_digest`,
  `_policy_source` and `_policy_digest`, and replaces any value a plugin sends for them.
- **API-owned props.** The API alone writes `_policy_bundle_digest`, `_policy_input_digest`
  and `_policy_data_digest`.
- **The agent never computes artifact digests.** It passes each evaluation's policy
  directory, input and policy data through to the API, which canonicalises and hashes them.
- **Evidence identity.** `policy-manager`'s `newEvidence` seed is every evidence stream's UUID, and plugins in the
  field compute it. Never change it. The golden test in `policy-manager/evidence_seed_test.go` pins the UUIDs.
- **Plugin library version.** `internal/pluginlib` reads the agent library a plugin binary was built with from its
  Go build info. The config report lists it per plugin (`plugins[].lib-version`) as diagnostics only; nothing is
  gated on it.
- **Storage failure doesn't drop evidence.** If artifact storage fails, the evidence is still
  sent, without digests.
- **OCI policy bundles.** The agent evaluates the extracted `policies/` subdirectory, and that
  directory is what is uploaded as the bundle. Never write files into it (e.g. caches or
  records): they would change the bundle's digest.

## Don't

- Commit the root build outputs `concom` or `agent`, `dist/`, `cover.out`, `.config/`, or a `go.work`.
- Change the generated `*.pb.go` files by hand.
