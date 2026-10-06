# Proofable — Authority-at-Dispatch Evidence

Proofable's implementation evidence for the authority/effect comparison associated with
[AAIF Identity & Trust issue #13](https://github.com/aaif/wg-identity-and-trust/issues/13).

**Run.** Live production hosted MCP, protocol revision
`f92faf39a4bae480cca3e5c07ce2c95d6ab68411`, run `four-case-run-f92faf39a4ba`. Executed by an
ordinary non-admin Pro review tenant (`admin:false`) with the dedicated agent
`proofable-authority-review` under an explicit pinned delegation per case.

## Results

| Scenario | Result |
| --- | --- |
| Binding veto / action outside delegated authority | **SUPPORTED** — unauthorized execution is denied before executor assignment |
| Revoked authority / stale grant | **SUPPORTED** — revoked authority is denied while the never-revoked control remains accepted |
| Remote authority unavailable | **NOT APPLICABLE TO CURRENT PATH** — Proofable evaluates current authority state locally at dispatch and has no remote authorization dependency on this path |
| Revocation after dispatch | **SUPPORTED** — the dispatch decision, later revocation, resulting effect/outcome, and receipt remain separately attributable |

**Protocol boundary:** authority → decision → dispatch → effect/outcome → receipt.

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
| `SHA256SUMS` | SHA-256 for the five payload files beside it |

`SHA256SUMS` covers every payload file in this directory except itself. Verify with
`sha256sum -c SHA256SUMS`.

Disclosure controls which fields of the Proofable record are shared; non-public fields are not
required to evaluate these results.
