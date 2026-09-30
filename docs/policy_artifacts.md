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
2. The plugin sends the evidence with `CreateEvidence`, as before.
3. The agent groups the evidence by evaluation. For each evaluation it archives the policy
   bundle, uploads the bundle, input and policy data once, and sends the evidence with the
   digests the API returns. The raw data is never forwarded with the evidence.

The agent only reads bundles at the policy paths it gave that plugin. It remembers what it
has already uploaded, so unchanged content is not uploaded again on later runs.

## Plugins

Plugins need no code changes. A plugin gets this by moving to an agent version that
includes it and rebuilding, because `GenerateResults` runs inside the plugin's own binary.

## Versions work together in any combination

| Plugin | Agent | API | Result |
| --- | --- | --- | --- |
| Not rebuilt | Any | Any | Evidence as before, without digests |
| Rebuilt | Old | Any | Evidence as before, without digests: the old agent ignores the `PolicyEvaluation` field |
| Rebuilt | New | Old | Evidence as before, without digests; the agent logs a warning and checks the API again every 10 minutes |
| Rebuilt | New | New | Artifacts stored; evidence carries digests |

## Storage failures are strict

When the API supports artifacts but storing an evaluation's artifacts fails, the agent
holds back that evaluation's evidence and returns an error naming it. Evidence from other
evaluations in the same call is still sent, and the next scheduled run tries again.

- Server errors (5xx), rate limiting (429) and network errors are retried up to three
  times with a short backoff.
- Rejections are not retried: content the API cannot read (400), an artifact over the API's
  `CCF_ARTIFACT_MAX_BYTES` (413), or a policy path the agent did not give the plugin.

## Message size

Each evidence in a `CreateEvidence` call carries its evaluation's input and policy data, so
plugin-to-agent messages may be up to 256 MiB, above gRPC's 4 MiB default.
