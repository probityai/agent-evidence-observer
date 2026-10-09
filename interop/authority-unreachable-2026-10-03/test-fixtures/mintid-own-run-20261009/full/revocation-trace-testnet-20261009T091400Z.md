# Revocation trace — testnet — 2026-10-09T09:14:00.189Z

Chain `mintid-testnet-2`, issuer `3d2a9df3cc5cb853…`, verifier `6f4c5d1becd3c47e…`. Raw events: `revocation-trace-testnet-20261009T091400Z.jsonl`. Decision log: not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD).

## Authority evidence

| Field | Value |
|---|---|
| Source | the issuer's status root on chain `mintid-testnet-2`, read by the verifier with an ics23 proof against the node's committed app hash at each decision (R15) |
| Revision | verifier `1c57bc06a670` (public-v2026-10-08.1), issuer `1c57bc06a670` (public-v2026-10-08.1); verifier engine `proof-core 0.4.0`, SDK 0.3.0, SPEC-1 v3.2 |
| Issuer signing key | `9ddd3b08a70e3506…` (a key id, not a revision) |
| Status/root | before: epoch 13598, finalized height 192287; after: epoch 13616, finalized height 192538 |
| Observation time | before 2026-10-09T09:14:02.000Z; after 2026-10-09T09:23:09.000Z (verifier `/v1/status`) |
| Actual age | before 27 s; after 34 s |
| Deployed freshness limit | 180 s maximum root age (heartbeat 30 s; verifier height lag 100 blocks; K = 5 s) |
| Check performed | condition 5: the proof is verified against the issuer definition (BBS key + accumulator) the newest *provable* finalized root anchors; condition 7: the presented root is the current root, or a ring entry inside its validity window, superseded within the height lag and followed by no emergency root; chain unreadable → refuse |

Presentation lifetime: 10 s (R14) — bounds replay, not revocation; a separate field from the revocation latency below.

## Temporal revocation

| Path | Trigger time (t0) | Authority evidence consulted at the denial | Last accepted action | Required deny point (bound) | First observed denial | Root carrying the revocation |
|---|---|---|---|---|---|---|
| issuer | — | — | — | — | skipped: baseline of sibling_control not accepted within 60 s (last answer `deadline_exceeded`): no trigger fired | — |
| kill_switch | 2026-10-09T09:17:02.757Z — the recording of the nullifier on chain (block time of the relay's tx) | current root epoch 13605 (finalized height 192386, generated 2026-10-09T09:17:05.000Z) | none after t0 (—) | t0 + 245 s (t0 + G + A + K) = 2026-10-09T09:21:07.757Z | 2026-10-09T09:17:19.967Z (+17.2 s), `status_root_stale` | — |
| cascade (cascade_agent_1) | 2026-10-09T09:19:05.000Z — generation of the trigger root (the root carrying the principal's revocation) | current root epoch 13610 (finalized height 192457, generated 2026-10-09T09:19:35.000Z) | 2026-10-09T09:19:22.056Z (+17.1 s) | t0 + 395 s (t_T + 7·H + A + K) = 2026-10-09T09:25:40.000Z | 2026-10-09T09:19:44.369Z (+39.4 s), `status_root_stale` | trigger root epoch 13609, finalized height 192443 at 2026-10-09T09:19:05.807Z |
| cascade (cascade_agent_2) | 2026-10-09T09:19:05.000Z — generation of the trigger root (the root carrying the principal's revocation) | current root epoch 13611 (finalized height 192471, generated 2026-10-09T09:20:05.000Z) | 2026-10-09T09:20:03.467Z (+58.5 s) | t0 + 395 s (t_T + 7·H + A + K) = 2026-10-09T09:25:40.000Z | 2026-10-09T09:20:19.369Z (+74.4 s), `status_root_stale` | trigger root epoch 13609, finalized height 192443 at 2026-10-09T09:19:05.807Z |

## Measured deny point per path

| Path | First observed denial − t0 | Bound | Within the bound |
|---|---|---|---|
| kill_switch | 17.2 s | 245 s | yes |
| cascade/cascade_agent_1 | 39.4 s | 395 s | yes |
| cascade/cascade_agent_2 | 74.4 s | 395 s | yes |

Times are wall-clock UTC of this machine; a root's "finalized at" is the CometBFT block time (BFT time), which trails wall-clock by up to about one block, so it can read earlier than the root's own `generated_at`. Each forced attempt takes about a second (proof + verdict), which is the granularity of the measured points.

## Decision-log lines (R18 fixed-slot records)

| Path | Decision | Verifier answer | Decision-log line |
|---|---|---|---|
| kill_switch first refused | 2026-10-09T09:17:19.967Z | `status_root_stale` | not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD) |
| cascade/cascade_agent_1 last accepted | 2026-10-09T09:19:22.056Z | `accepted` | not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD) |
| cascade/cascade_agent_1 first refused | 2026-10-09T09:19:44.369Z | `status_root_stale` | not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD) |
| cascade/cascade_agent_2 last accepted | 2026-10-09T09:20:03.467Z | `accepted` | not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD) |
| cascade/cascade_agent_2 first refused | 2026-10-09T09:20:19.369Z | `status_root_stale` | not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD) |

## Attribution

The verifier's record shows the root a decision rested on; revocation is shown by the failed witness refresh.

A first refusal marks when a root newer than the agent's witness became provable to the verifier, which a never-revoked agent forcing an old witness meets too. A revoked agent cannot obtain a newer witness; a live one can, and is accepted again. Times are seconds after the path's t0.

| Path | Revoked agent | First refused | Witness refresh |
|---|---|---|---|
| kill_switch | `agent_kill_switch` | +17.2 s `status_root_stale` | refused +34.0 s, `credential_revoked` |
| cascade (cascade_agent_1) | `cascade_agent_1` | +39.4 s `status_root_stale` | refused +241.5 s, `credential_revoked` |
| cascade (cascade_agent_2) | `cascade_agent_2` | +74.4 s `status_root_stale` | refused +92.2 s, `credential_revoked` |

## Service interruptions

Answers that were not decisions: the verifier did not serve (5xx, or unreachable), so it decided nothing; the trace carried on.

| When | Path | Agent | Attempt | Answer |
|---|---|---|---|---|
| 2026-10-09T09:16:46.302Z | issuer | `sibling_control` | baseline | never accepted within 60 s (last `deadline_exceeded`): path skipped |

## Rule

- **kill_switch**: `status_root_stale`; its decision-log line was not read (not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD)), so the rule that decided is not recorded here.
- **cascade (cascade_agent_1)**: `status_root_stale`; its decision-log line was not read (not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD)), so the rule that decided is not recorded here.
- **cascade (cascade_agent_2)**: `status_root_stale`; its decision-log line was not read (not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD)), so the rule that decided is not recorded here.

