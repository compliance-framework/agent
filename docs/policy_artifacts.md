# Policy artifacts for playback

Evidence produced by `GenerateResults` can record what its policy evaluation depended on,
so the API can replay it later. The API stores three artifacts and writes their digests on
the evidence as signed props:

| Artifact | Source | Evidence prop |
| --- | --- | --- |
| Policy bundle | The bundle directory the agent downloaded (`policyPath`) | `_policy_bundle_digest` |
| Input data | The `data` the plugin passes to `GenerateResults` | `_policy_input_digest` |
| Policy data | The plugin's configured `policy_data` | `_policy_data_digest` (absent when none is configured) |

The API does all canonicalisation and hashing; see its `docs/artifacts.md`.

## How the data travels

1. `GenerateResults` attaches a `PolicyEvaluation` to each evidence: the policy path, and
   the input and policy data as JSON. Plugins call it exactly as before.
2. The plugin sends the evidence with `CreateEvidence`, as before. Underneath, the plugin's
   client streams it to the agent one evidence per message (`CreateEvidenceStream`). Each
   evaluation's data is sent in full once per stream; later evidence from the same
   evaluation carries only its Id. Against an agent that predates the stream, the client
   falls back to the single `CreateEvidence` call.
3. The agent handles each evidence as it arrives. For an evaluation it has not seen in the
   stream, it archives the policy bundle and uploads the bundle, input and policy data, and
   keeps only the digests the API returns. It then sends the evidence to the API with those
   digests, before the next message arrives. The raw data is never forwarded with the
   evidence, and the agent never holds the whole batch in memory.

The agent only reads bundles at the policy paths it gave that plugin. Symlinks inside a
bundle are skipped, as OPA skips them. The agent remembers what it has already uploaded to
each API, so unchanged content is not uploaded again on later runs. The same process-wide uploader
serves the configuration report, which uploads the policy trees it names (see
`configuration.md`, "Sources for the UI"); a tree uploaded there is not uploaded again for
evidence, and both produce the same artifact digest.

## Plugins

Plugins need no code changes. A plugin gets this by moving to an agent version that
includes it and rebuilding, because `GenerateResults` runs inside the plugin's own binary.

## Versions work together in any combination

| Plugin | Agent | API | Result |
| --- | --- | --- | --- |
| Not rebuilt | Any | Any | Evidence as before, without digests |
| Rebuilt | Old | Any | Evidence as before, without digests: the plugin falls back to the single call, and the old agent ignores the `PolicyEvaluation` field |
| Rebuilt | New | Old | Evidence as before, without digests; the agent logs a warning and checks the API again every 10 minutes |
| Rebuilt | New | New | Artifacts stored; evidence carries digests |

## When artifacts cannot be stored

Evidence is never lost because its artifacts could not be stored. If storing an
evaluation's artifacts fails, the agent sends that evaluation's evidence as before, without
digests, and logs a warning with the reason. That evidence cannot be played back. Other
evaluations in the same call keep their digests.

- Server errors (5xx), rate limiting (429) and network errors are retried up to three times
  with a short backoff first, so a temporary failure usually still ends in replayable
  evidence.
- Failures that retrying cannot fix fall back straight away: content the API cannot read
  (400), an artifact over the API's `CCF_ARTIFACT_MAX_BYTES` (413), a bundle that cannot be
  archived, a policy path the agent did not give the plugin, or a stream reference to an
  evaluation that was never sent.

## Message size

Because evidence is streamed, there is no limit on a whole call. The limit is per message:
one evidence, whose `PolicyEvaluation` may carry a large input such as a whole cluster, may
be up to 256 MiB, above gRPC's 4 MiB default. Each evaluation's data crosses once however
many evidence records it produces.

## Plugin and policy sources

Every evidence the agent sends also records where its plugin and policy bundle came from:

| Evidence prop | Value |
| --- | --- |
| `_plugin_source` | The plugin's configured `source`: an OCI reference such as `ghcr.io/compliance-framework/plugin-apt-versions:v0.4.0`, or a local path |
| `_plugin_digest` | For an OCI source, the registry digest the reference resolved to when the agent downloaded it; for a local plugin binary, its SHA-256 |
| `_policy_source` | The configured source of the policy bundle the evaluation used (only when the evidence carries a `PolicyEvaluation`, or, from plugins built on an older agent library, a `_policy_path` label naming one of the plugin's policy paths, so the bundle is known) |
| `_policy_digest` | For an OCI source, the registry digest the reference resolved to when the agent downloaded it. Not set for a local directory; `_policy_bundle_digest` covers its content |

With `_plugin_source` and `_plugin_digest`, the image is pinned (`ref@digest`) even if the tag
later moves.

The agent records the registry digest in `.ccf-source.json` next to the extracted files when
it downloads them, so later runs, which skip the download, still report it. Files extracted
before digests were recorded have no such record: their evidence carries the source but no
digest until they are downloaded again (a new version, a cleared cache, or a fresh agent
volume).

The agent looks the policy source up by the path it gave the plugin, which is the path the
plugin reports the evaluation under.

The agent owns these props: any a plugin sets itself are replaced. They are recorded whether
or not the evaluation's artifacts could be stored.
