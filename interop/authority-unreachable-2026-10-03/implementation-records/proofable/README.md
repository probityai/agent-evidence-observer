# Proofable — Authority-at-Dispatch Evidence

Proofable's implementation evidence for the authority/effect comparison associated with
[AAIF Identity & Trust issue #13](https://github.com/aaif/wg-identity-and-trust/issues/13).

**Run.** Live production hosted MCP, protocol revision `e1217327a1568b39d5153686b8085471b5329cde`, run `aaif-e1217327a-20261008`,
assembled from 2 source runs:
- `aaif-e1217327a-20261008` — eight-case authority suite
- `aaif-e1217327a-20261008` — ordered post-revocation probe
Executed by the Proofable operator under a non-privileged review profile (not an administrative
path), with the dedicated agent `proofable-authority-review` under an explicit pinned delegation
per case. The ordered post-revocation boundary is a second source run in the same packet, not a
re-observation of the same run.

**Signer and subject.** Every disclosed envelope is signed by the Proofable service wallet
`0xa41494e1e5f9e5eaf786961e6ef84cd1a3071eec`. The signature means *Proofable attests this
server-observed statement*; it is not the controller signing their own outcome. The controller
`0x0d4e513a3a7eb92bab65c97786c67b198d9dca15` is the statement's subject/owner whose record is
stored. The two addresses differ by design.

## Results

| Scenario | Result |
| --- | --- |
| Binding veto / action outside delegated authority | **SUPPORTED** — unauthorized execution is denied before executor assignment |
| Revoked authority / stale grant | **SUPPORTED** — revoked authority is denied while the never-revoked control remains accepted |
| Remote authority unavailable | **NOT APPLICABLE TO CURRENT PATH** — Proofable evaluates current authority state locally at dispatch and has no remote authorization dependency on this path |
| Revocation after dispatch | **SUPPORTED** — the dispatch decision, the later revocation, the resulting effect/outcome, and the refusal of the next dispatch are separately attributable |

**Protocol boundary:** authority → decision → dispatch → effect/outcome → receipt.

**Revocation after dispatch.** One grant is dispatched under, revoked while the action is in flight, and
then used for the next dispatch. The earlier action was allowed at dispatch and its effect was already
committed and read back at the platform; the next dispatch under the same revoked grant was refused with
a reason. When authorization was refused is therefore reported separately from whether the prior action
had already committed an effect. Revocation latency is **not measured** in this run.

The result is a portable proof/receipt of the protocol decision and outcome; disclosure controls
which fields are shared. Where Proofable does not independently observe a target-side effect, the
record states `platform_observed_only`.

**Evidence scope:** author-operated; independent reproduction not yet claimed.

This is implementation evidence for the comparison in #13 — not AAIF certification or WG
conformance.

## Files

| File | Role |
| --- | --- |
| `README.md` | this summary |
| `manifest.json` | machine-readable manifest: revision, run, custody, results, disclosure |
| `authority-effect-results.md` | results under the shared authority/effect contract |
| `authority-effect-results.json` | machine-readable results |
| `trace.jsonl` | one sanitized record per supporting case (6 records) |
| `portable-proofs.json` | disclosed CAIP-380 job and authority envelopes |
| `verify-portable-proofs.mjs` | offline SDK verification of every envelope |
| `SHA256SUMS` | SHA-256 for every payload file beside it |

`SHA256SUMS` covers every payload file in this directory except itself. Verify with
`sha256sum -c SHA256SUMS`.

Install the pinned `@proofable/sdk@0.1.4` package once. Then verify every signature and qHash offline:

`node verify-portable-proofs.mjs`

Disclosure controls which fields of the Proofable record are shared; non-public fields are not
required to evaluate these results.
