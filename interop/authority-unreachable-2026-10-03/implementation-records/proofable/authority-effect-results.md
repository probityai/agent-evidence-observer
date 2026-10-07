# Proofable — Authority-at-Dispatch Results

Proofable's implementation records for the four scenarios, expressed under the shared authority/effect
contract ([`probityai/agent-evidence-observer`](https://github.com/probityai/agent-evidence-observer)
`fb8cabc5c9c54459743497f2325bfef49b137a1a`, `interop/authority-unreachable-2026-10-03/CONTRACT.md`).
Deployed revision `f92faf39a4bae480cca3e5c07ce2c95d6ab68411`; environment: live production hosted MCP.
Custody: **SELF** (author-operated).

| Scenario | Decision | Dispatch | Effect/outcome | Protocol record | Result |
| --- | --- | --- | --- | --- | --- |
| binding_veto | DENY (`JOB_AUTHORITY_DENIED`) | refused before executor assignment | none — no effect could commit | recorded | **SUPPORTED** |
| revoked_stale | revoked: DENY (`DELEGATION_PROOF_DENIED`); never-revoked control: ALLOW | revoked: no job created; control: dispatched | none | recorded | **SUPPORTED** |
| unreachable | NOT APPLICABLE TO CURRENT PATH | not attempted | not applicable | not applicable | **NOT APPLICABLE TO CURRENT PATH** |
| post_dispatch_revoke | ALLOW at dispatch | dispatched; revocation occurred in flight | effect/outcome remained attributable to the original dispatch | recorded | **SUPPORTED** |

## Protocol boundary

**authority → decision → dispatch → effect/outcome → receipt.** In Proofable these are distinct
states; collapsing them would treat a failed task as evidence that no effect committed, or a later
denial as retroactively preventing an earlier effect.

## How Proofable produces the result (public-safe summary)

- **Identity is not authority.** An agent can have its own identity independent of how it receives
  authority. When authority is delegated, Proofable records the grant separately and evaluates its
  current state at the action boundary. An agent can be authenticated and still lack the authority to
  act.
- **Authority is evaluated at the action boundary.** For this delegated-authority scenario, the
  dispatch path resolves the selected grant from current state and checks the requested action against
  it — revoked or expired authority is denied rather than inherited from a still-valid identity.
- **A denial is itself evidence.** A refused dispatch produces a signed authority-decision record
  (`outcome`, `reason`, `policyVersion`), not only a silent failure.
- **The record is portable.** The same signed record can be carried to another relying party, which
  applies its own appraisal; disclosure is separate from evidentiary validity, so the full grant,
  runtime policy, and internal execution state need not be disclosed.
- **Layers stay separate.** Proofable treats identity, authority, execution evidence and appraisal as
  distinct layers. Authority may be native or delegated; the proof/receipt is the evidence layer that
  connects them, not an authorization model in itself.

Authority policy version: `authority-policy.v1`.

## Remote authority unavailable (NOT APPLICABLE TO CURRENT PATH)

Proofable evaluates dispatch authority from its own current authority state; this path has no remote
authority dependency to make unavailable. A genuine comparison requires a path with a real remote
authority dependency, which is a separate joint comparison, and is not inferred as passing.

## Evidence scope

Author-operated; independent reproduction not yet claimed.

## Reader appraisal

- **Trace:** recompute SHA-256 of `trace.jsonl` and compare against `manifest.json` → `public_trace.sha256`.
- **Record:** the underlying Proofable proof/receipt is a CAIP-380 envelope. An independent reader can verify such an envelope offline with `verifyPortableProofEnvelope` from the public **Apache-2.0** `@proofable/sdk` — the signature is checked without a call to Proofable.
- **Policy identity:** the policy version (`authority-policy.v1`) identifies the policy; a canonical policy digest is not emitted by the deployed system.

## Public references

- SDK: `@proofable/sdk` (Apache-2.0) · MCP: `proofable/mcp` · Docs: `docs.proofable.me`
- Portable Proof profile: [CAIP-380](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-380.md)

## Known limitations of this run

- Custody is author-operated; there is no independent peer witness or target-side effect byte.
- Revocation latency is not measured in this run; the freshness rule is delegation expiry, revocation and supersession (this path is not root-based, so root age is not applicable).
- The public trace is a sanitized projection of the Proofable records, not the raw records themselves.
