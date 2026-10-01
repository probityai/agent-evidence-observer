# REMORA post-approval cases, local file effects

This probe reads the six [REMORA AutoReview-to-Effect vectors](https://github.com/darklordVirtual/REMORA-research/blob/b25e735d36590154ff53768b4d245ad4c7996f64/conformance/autoreview-to-effect-v1/vectors.json) at commit `b25e735d36590154ff53768b4d245ad4c7996f64`. It requires the exact source bytes with SHA-256 `f896178eac35aab8843f0902934f1433eb6dccb2a212fc4139a67890faaabd27` before any case runs.

The exercise uses Probity's `ProtectedDispatcher` and real broker file replacements. Each case has a fresh signed grant, an exact consumer request, a host-side authorization journal, and a separate witness key. The output retains those records, the submitted candidate, the approved content, the case outcome, source hashes and a file hash list. The CI job saves the whole output as an artifact and checks it again in a separate process.

| Case | Local result | Scope |
| --- | --- | --- |
| AR-00 | One write; retained packet and current bytes verify | Local file control |
| AR-01 | Changed destination path refused before a write | Path analogue of changed arguments |
| AR-02 | Changed principal label refused before a write | No external credential check |
| AR-03 | Changed tool label refused, exact case unsupported | No registered reachable alternate tool |
| AR-04 | A caller-supplied new policy digest refuses the old store | No automatic policy-bundle update |
| AR-05 | A saved success response cannot validate later changed file bytes | Same-operator current read-back; no account ledger |

The source suite tests a funds-transfer tool. This probe never transfers funds or runs REMORA's dispatcher. It does not report a conformance score. The `nativeWriteEvents` count comes from Probity's retained native history, and a refusal with a write event fails the run. AR-05 deliberately changes the file outside the dispatcher after its one native write; that second, unmediated change is detected but does not count as a tool body. It is not a test of an authoritative financial ledger.

Run against an independently checked out source tree:

```sh
python examples/remora_effect_bridge.py ./remora-bridge-run --remora-vectors ./remora-source/conformance/autoreview-to-effect-v1/vectors.json
python examples/remora_effect_bridge.py ./remora-bridge-run --remora-vectors ./remora-source/conformance/autoreview-to-effect-v1/vectors.json --verify
```

The source pin, checker hash and protected-effect module hashes are retained in `source-pins.json`. The read-only verification recomputes the hash list, checks the submitted candidates against the pinned vector fields, checks the two completed signed bundles and four untouched stores, and confirms the current-state mismatch. The hash list is stored with the output, so it is not an independent integrity anchor by itself. All role keys and file evidence are under one operator, with `PEER` witness scope. Direct host calls do not establish isolated child execution or complete control of alternate effect routes.

The AAE unsigned kernel and local effect link remain a separate path. AAE can compare a consumer-pinned mandate digest before its broker write, but this exercise does not join that mandate to the protected dispatch journal or assert issuer authentication. A combined authorization route would need one pre-effect record binding both decisions and the same exact dispatch.
