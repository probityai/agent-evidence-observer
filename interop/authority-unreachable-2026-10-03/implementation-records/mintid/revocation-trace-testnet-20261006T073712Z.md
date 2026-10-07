# Revocation trace — testnet — 2026-10-06T07:37:12.212Z

Chain `mintid-testnet-2`, issuer `3d2a9df3cc5cb853…`, verifier `6f4c5d1becd3c47e…`. Raw events: `revocation-trace-testnet-20261006T073712Z.jsonl`. Decision log: verifier console /console/decisions (MINT-307).

## Authority evidence

| Field | Value |
|---|---|
| Source | the issuer's status root on chain `mintid-testnet-2`, read by the verifier with an ics23 proof against the node's committed app hash at each decision (R15) |
| Revision | verifier `497509ebf0c3` (public-v2026-10-06.2), issuer `497509ebf0c3` (public-v2026-10-06.2); verifier engine `proof-core 0.4.0`, SDK 0.3.0, SPEC-1 v3.2 |
| Issuer signing key | `9ddd3b08a70e3506…` (a key id, not a revision) |
| Status/root | before: epoch 4792, finalized height 67885; after: epoch 4808, finalized height 68098 |
| Observation time | before 2026-10-06T07:37:15.000Z; after 2026-10-06T07:44:19.000Z (verifier `/v1/status`) |
| Actual age | before 31 s; after 4 s |
| Deployed freshness limit | 180 s maximum root age (heartbeat 30 s; verifier height lag 100 blocks; K = 5 s) |
| Check performed | condition 5: the proof is verified against the issuer definition (BBS key + accumulator) the newest *provable* finalized root anchors; condition 7: the presented root is the current root, or a ring entry inside its validity window, superseded within the height lag and followed by no emergency root; chain unreadable → refuse |

Presentation lifetime: 10 s (R14) — bounds replay, not revocation; a separate field from the revocation latency below.

## Temporal revocation

| Path | Trigger time (t0) | Authority evidence consulted at the denial | Last accepted action | Required deny point (bound) | First observed denial | Root carrying the revocation |
|---|---|---|---|---|---|---|
| issuer | 2026-10-06T07:38:49.530Z — the issuer's removal of the agent (revoke response) | current root epoch 4796 (finalized height 67942, generated 2026-10-06T07:38:45.000Z) | none after t0 (—) | t0 + 185 s (t0 + A + K) = 2026-10-06T07:41:54.530Z | 2026-10-06T07:38:58.870Z (+9.3 s), `status_root_stale` | epoch 4797, finalized height 67956 at 2026-10-06T07:39:13.643Z |
| kill_switch | 2026-10-06T07:39:45.428Z — the recording of the nullifier on chain (block time of the relay's tx) | current root epoch 4799 (finalized height 67985, generated 2026-10-06T07:40:15.000Z) | 2026-10-06T07:40:15.852Z (+30.4 s) | t0 + 245 s (t0 + G + A + K) = 2026-10-06T07:43:50.428Z | 2026-10-06T07:40:22.210Z (+36.8 s), `status_root_stale` | epoch 4799, finalized height 67985 at 2026-10-06T07:40:15.056Z |
| cascade (cascade_agent_1) | 2026-10-06T07:41:15.000Z — generation of the trigger root (the root carrying the principal's revocation) | current root epoch 4806 (finalized height 68084, generated 2026-10-06T07:43:45.000Z) | 2026-10-06T07:43:44.533Z (+149.5 s) | t0 + 395 s (t_T + 7·H + A + K) = 2026-10-06T07:47:50.000Z | 2026-10-06T07:43:51.071Z (+156.1 s), `status_root_stale` | trigger root epoch 4801, finalized height 68013 at 2026-10-06T07:41:14.459Z |
| cascade (cascade_agent_2) | 2026-10-06T07:41:15.000Z — generation of the trigger root (the root carrying the principal's revocation) | current root epoch 4802 (finalized height 68027, generated 2026-10-06T07:41:45.000Z) | 2026-10-06T07:41:35.851Z (+20.9 s) | t0 + 395 s (t_T + 7·H + A + K) = 2026-10-06T07:47:50.000Z | 2026-10-06T07:41:50.138Z (+35.1 s), `status_root_stale` | trigger root epoch 4801, finalized height 68013 at 2026-10-06T07:41:14.459Z |
| emergency | 2026-10-06T07:44:07.403Z — the emergency root's submission (the issuer's answer; the bound itself is block-based) | current root epoch 4807 (finalized height 68094, generated 2026-10-06T07:44:06.000Z) EMERGENCY | none after t0 (—) | t0 + 0 s (the emergency root's finalisation: measured in blocks below) = 2026-10-06T07:44:07.403Z | 2026-10-06T07:44:11.903Z (+4.5 s), `status_root_stale` | epoch 4807, finalized height 68094 at 2026-10-06T07:44:05.874Z |

## Measured deny point per path

| Path | First observed denial − t0 | Bound | Within the bound |
|---|---|---|---|
| issuer | 9.3 s | 185 s | yes |
| kill_switch | 36.8 s | 245 s | yes |
| cascade/cascade_agent_1 | 156.1 s | 395 s | yes |
| cascade/cascade_agent_2 | 35.1 s | 395 s | yes |
| emergency | 4.5 s after the submission; last accepted at node head None, first refused at node head 68095; the emergency root entered block 68094 | the block of the emergency root (+1 header to prove it) | yes |

Times are wall-clock UTC of this machine; a root's "finalized at" is the CometBFT block time (BFT time), which trails wall-clock by up to about one block, so it can read earlier than the root's own `generated_at`. Each forced attempt takes about a second (proof + verdict), which is the granularity of the measured points.

## Decision-log lines (R18 fixed-slot records)

| Path | Decision | Verifier answer | Decision-log line |
|---|---|---|---|
| issuer first refused | 2026-10-06T07:38:58.870Z | `status_root_stale` | `accepted=False reason=status_root_stale condition=5 decided_at_unix=2026-10-06 07:38:58Z root_epoch=4796 root_height=67942 root_age_seconds=13` |
| kill_switch last accepted | 2026-10-06T07:40:15.852Z | `accepted` | `accepted=True reason=accepted condition=9 decided_at_unix=2026-10-06 07:40:13Z root_epoch=4798 root_height=67970 root_age_seconds=28` |
| kill_switch first refused | 2026-10-06T07:40:22.210Z | `status_root_stale` | `accepted=False reason=status_root_stale condition=5 decided_at_unix=2026-10-06 07:40:21Z root_epoch=4799 root_height=67985 root_age_seconds=6` |
| cascade/cascade_agent_1 last accepted | 2026-10-06T07:43:44.533Z | `accepted` | `accepted=True reason=accepted condition=9 decided_at_unix=2026-10-06 07:43:42Z root_epoch=4805 root_height=68070 root_age_seconds=27` |
| cascade/cascade_agent_1 first refused | 2026-10-06T07:43:51.071Z | `status_root_stale` | `accepted=False reason=status_root_stale condition=5 decided_at_unix=2026-10-06 07:43:50Z root_epoch=4806 root_height=68084 root_age_seconds=5` |
| cascade/cascade_agent_2 last accepted | 2026-10-06T07:41:35.851Z | `accepted` | `accepted=True reason=accepted condition=9 decided_at_unix=2026-10-06 07:41:33Z root_epoch=4801 root_height=68013 root_age_seconds=18` |
| cascade/cascade_agent_2 first refused | 2026-10-06T07:41:50.138Z | `status_root_stale` | `accepted=False reason=status_root_stale condition=5 decided_at_unix=2026-10-06 07:41:49Z root_epoch=4802 root_height=68027 root_age_seconds=4` |
| emergency first refused | 2026-10-06T07:44:11.903Z | `status_root_stale` | `accepted=False reason=status_root_stale condition=5 decided_at_unix=2026-10-06 07:44:11Z root_epoch=4807 root_height=68094 root_age_seconds=5` |

## Control (issuer path): a sibling agent that is not revoked

The sibling forced a proof over the witness it held at the trigger, never refreshing: last accepted —, first refused 2026-10-06T07:38:54.151Z `status_root_stale`; after refreshing its witness it was `accepted`.

## Attribution

The verifier's record shows the root a decision rested on; revocation is shown by the failed witness refresh.

A first refusal marks when a root newer than the agent's witness became provable to the verifier, which a never-revoked agent forcing an old witness meets too. A revoked agent cannot obtain a newer witness; a live one can, and is accepted again. Times are seconds after the path's t0.

| Path | Revoked agent | First refused | Witness refresh |
|---|---|---|---|
| issuer | `agent_issuer` | +9.3 s `status_root_stale`, root epoch 4796 | refused +5.5 s, `credential_revoked` |
| kill_switch | `agent_kill_switch` | +36.8 s `status_root_stale`, root epoch 4799 | refused +32.9 s, `credential_revoked` |
| cascade (cascade_agent_1) | `cascade_agent_1` | +156.1 s `status_root_stale`, root epoch 4806 | refused +152.3 s, `credential_revoked` |
| cascade (cascade_agent_2) | `cascade_agent_2` | +35.1 s `status_root_stale`, root epoch 4802 | refused +122.5 s, `credential_revoked` |
| emergency | `agent_emergency` | +4.5 s `status_root_stale`, root epoch 4807 | refused +0.7 s, `credential_revoked` |

Control on the issuer path (`sibling_control`, never revoked, forcing the witness it held at the trigger): refused +4.6 s `status_root_stale`, root epoch 4796; its witness refresh: a newer witness obtained +32.0 s; after the refresh accepted +37.6 s `accepted`, root epoch 4797.

## Rule

- **issuer**: `status_root_stale`, decided by condition 5 (the proof verifies and is bound to the challenge); the root of epoch 4796 (finalized height 67942, 13 s old at the decision).
- **issuer control (never revoked)**: `status_root_stale`, decided by condition 5 (the proof verifies and is bound to the challenge); the root of epoch 4796 (finalized height 67942, 8 s old at the decision).
- **kill_switch**: `status_root_stale`, decided by condition 5 (the proof verifies and is bound to the challenge); the root of epoch 4799 (finalized height 67985, 6 s old at the decision).
- **cascade (cascade_agent_1)**: `status_root_stale`, decided by condition 5 (the proof verifies and is bound to the challenge); the root of epoch 4806 (finalized height 68084, 5 s old at the decision).
- **cascade (cascade_agent_2)**: `status_root_stale`, decided by condition 5 (the proof verifies and is bound to the challenge); the root of epoch 4802 (finalized height 68027, 4 s old at the decision).
- **emergency**: `status_root_stale`, decided by condition 5 (the proof verifies and is bound to the challenge); the root of epoch 4807 (finalized height 68094, 5 s old at the decision).

Condition 5 verifies every agent proof against the issuer material — definition, BBS key and accumulator, scope anchors — that the newest provable root anchors (issuer metadata `anchoring`). A refusal there with `status_root_stale` means the material had moved to a newer root than the one the proof was made against and the proof was not accepted against it; the root named is the root the proof was checked against. The ring rule of condition 7 is not reached. An honest client refreshes its witness and retries; a revoked one cannot obtain a newer witness. The SPEC-1 §9.1 bound is what every conforming verifier guarantees (one that accepts a ring root inside its validity window); condition 5 is this verifier's stricter check, so its deny point can come before the bound.

