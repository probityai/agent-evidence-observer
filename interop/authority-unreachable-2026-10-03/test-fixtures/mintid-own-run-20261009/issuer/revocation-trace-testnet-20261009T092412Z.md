# Revocation trace — testnet — 2026-10-09T09:24:12.197Z

Chain `mintid-testnet-2`, issuer `3d2a9df3cc5cb853…`, verifier `6f4c5d1becd3c47e…`. Raw events: `revocation-trace-testnet-20261009T092412Z.jsonl`. Decision log: not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD).

## Authority evidence

| Field | Value |
|---|---|
| Source | the issuer's status root on chain `mintid-testnet-2`, read by the verifier with an ics23 proof against the node's committed app hash at each decision (R15) |
| Revision | verifier `1c57bc06a670` (public-v2026-10-08.1), issuer `1c57bc06a670` (public-v2026-10-08.1); verifier engine `proof-core 0.4.0`, SDK 0.3.0, SPEC-1 v3.2 |
| Issuer signing key | `9ddd3b08a70e3506…` (a key id, not a revision) |
| Status/root | before: epoch 13619, finalized height 192580; after: epoch 13625, finalized height 192665 |
| Observation time | before 2026-10-09T09:24:16.000Z; after 2026-10-09T09:27:24.000Z (verifier `/v1/status`) |
| Actual age | before 11 s; after 19 s |
| Deployed freshness limit | 180 s maximum root age (heartbeat 30 s; verifier height lag 100 blocks; K = 5 s) |
| Check performed | condition 5: the proof is verified against the issuer definition (BBS key + accumulator) the newest *provable* finalized root anchors; condition 7: the presented root is the current root, or a ring entry inside its validity window, superseded within the height lag and followed by no emergency root; chain unreadable → refuse |

Presentation lifetime: 10 s (R14) — bounds replay, not revocation; a separate field from the revocation latency below.

## Temporal revocation

| Path | Trigger time (t0) | Authority evidence consulted at the denial | Last accepted action | Required deny point (bound) | First observed denial | Root carrying the revocation |
|---|---|---|---|---|---|---|
| issuer | 2026-10-09T09:26:36.761Z — the issuer's removal of the agent (revoke response) | current root epoch 13624 (finalized height 192651, generated 2026-10-09T09:26:35.000Z) | none after t0 (—) | t0 + 185 s (t0 + A + K) = 2026-10-09T09:29:41.761Z | 2026-10-09T09:26:58.910Z (+22.1 s), `deadline_exceeded` | epoch 13625, finalized height 192665 at 2026-10-09T09:27:04.859Z |

## Measured deny point per path

| Path | First observed denial − t0 | Bound | Within the bound |
|---|---|---|---|
| issuer | 22.1 s | 185 s | yes |

Times are wall-clock UTC of this machine; a root's "finalized at" is the CometBFT block time (BFT time), which trails wall-clock by up to about one block, so it can read earlier than the root's own `generated_at`. Each forced attempt takes about a second (proof + verdict), which is the granularity of the measured points.

## Decision-log lines (R18 fixed-slot records)

| Path | Decision | Verifier answer | Decision-log line |
|---|---|---|---|
| issuer first refused | 2026-10-09T09:26:58.910Z | `deadline_exceeded` | not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD) |

## Control (issuer path): a sibling agent that is not revoked

The sibling forced a proof over the witness it held at the trigger, never refreshing: last accepted —, first refused 2026-10-09T09:26:45.567Z `status_root_stale`; after refreshing its witness it was `accepted`.

## Attribution

The verifier's record shows the root a decision rested on; revocation is shown by the failed witness refresh.

A first refusal marks when a root newer than the agent's witness became provable to the verifier, which a never-revoked agent forcing an old witness meets too. A revoked agent cannot obtain a newer witness; a live one can, and is accepted again. Times are seconds after the path's t0.

| Path | Revoked agent | First refused | Witness refresh |
|---|---|---|---|
| issuer | `agent_issuer` | +22.1 s `deadline_exceeded` | refused +9.7 s, `credential_revoked` |

Control on the issuer path (`sibling_control`, never revoked, forcing the witness it held at the trigger): refused +8.8 s `status_root_stale`; its witness refresh: a newer witness obtained +35.4 s; after the refresh accepted +44.8 s `accepted`.

## Rule

- **issuer**: `deadline_exceeded`; its decision-log line was not read (not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD)), so the rule that decided is not recorded here.
- **issuer control (never revoked)**: `status_root_stale`; its decision-log line was not read (not read (operator only: MINTID_VERIFIER_CONSOLE_PASSWORD)), so the rule that decided is not recorded here.

