# Proposed authority, effect and terminal comparison

Use one record per attempted action. Keep implemented checks, known gaps and simulation results in their own implementation rows. An approval signature answers a different question from whether a side effect committed.

| Record field | Required meaning |
| --- | --- |
| Implementation and source | Exact producer revision, adapter revision and executed path; source inspection and runtime execution have different evidence classes. |
| Action identity | Run, attempt, request/idempotency, tenant, principal, action/tool and exact target IDs. |
| Approved action | Actual text/payload bytes, media bytes or immutable byte digest, destination, tool-catalogue revision and approval time. Mutable references alone leave a binding gap. |
| Delegation and fallback | Original decision deadline, grant expiry, exact pre-authorized fallback and its scope. Availability does not widen authority. |
| Authority evidence | Source, revision, status/root, observation time, actual age, deployed freshness limit and the check performed at dispatch. Unperformed checks remain unperformed. |
| Temporal revocation | Trigger time, authority evidence consulted, last accepted action, required deny point and first observed denial, per path. Presentation lifetime and revocation latency have separate fields. |
| Dispatch decision | Allow, deny or indeterminate, plus exact reason and the enforcement point reached. |
| Observed effect | Target-read evidence, committed object/effect ID, exact bytes/digest, revision/count and observation coverage. A failed return cannot substitute for this evidence. |
| Task and recovery | Terminal status, safe blocking/completion, recovery latency, every retry, duplicate count and interruption point. Recovery remains unknown unless measured. |
| Reader appraisal | Selected trust pins, checks actually performed, missing proof, contradictions, publication/consumer decision and retained evidence. |
| Operation and custody | Who ran the producer, gate, status source and reader; who controlled each key/store; retained artifact location and covered effect boundary. |

The reference profile implements eighteen deterministic cases over one local native ticket per case. Availability is a controlled input, not a live human outage. A host-supplied signed status snapshot models current authority, with a selected 180-second maximum age; it is not a MintID root verifier or a deployed revocation measurement. The deadline prevents a newly valid late grant from reopening an expired request.

| Cases | Bounded result to inspect |
| --- | --- |
| Approved action; unavailable human with prior fallback | One local ticket commits. |
| No fallback; expired grant; late fresh grant after original deadline | No local ticket commits. |
| Revoked approver; stale authority evidence | Admission stops before native mutation. |
| Changed media, text, catalogue or destination | Exact approved bytes differ; no native mutation. |
| Revocation between durable intent and effect | Native persistent revocation blocks the second transaction. |
| Crash after intent; crash inside effect transaction | Recovery retains incomplete closure and refuses automatic replay. |
| Committed effect followed by lost response | Native row remains observed; task fails; publication is blocked. |
| Same-request retry | Two calls retain one native revision and one effect identity. |
| Effect followed by revocation | Earlier effect remains observed; later dispatch is denied. |
| Missing retained completion signature | The native row remains observed; complete publication proof is unavailable. |

The peer reader authenticates the profile record and native service state, opens the retained SQLite database read-only, checks the signed event chain, and compares the actual ticket identity and bytes. Native completion appraisal reuses Observer's source-pinned verifier. This is a separately installed consumer, not an independently implemented or independently operated verifier. The reference table has no general remote publication, multi-hop delegation, OAuth descendant-token revocation, funded recourse or private-chain proof.

## Source-backed Alakris discriminator

The original implementation source is `68054425873b9b373ce07359f8e994b817bee210`; the public review package is `6e0beb6d39bb1faa279087fd06cf2fe6c98e639c`. `source_discriminator.py` admits only the publisher's SHA-256 `3a928ff97f2eb13d2138809d1aebbacd645a07210663d74e2d77bae7fa1002df`, then executes its unmodified `_dict` and `compute_fingerprint` functions on controlled inputs. It does not import platform dependencies or run a live provider.

| Controlled input | Fingerprint changes |
| --- | --- |
| Title | Yes |
| Body changed by a direct database-style write | Yes |
| Media asset reference | Yes |
| Different media bytes behind unchanged reference | No; bytes are absent from the fingerprint inputs |
| Platform-specific packaging | No |
| External destination | No |

Alakris's [evidence scope](https://git.elibot.ru/agent-bot/aaif-publication-reference/src/commit/6e0beb6d39bb1faa279087fd06cf2fe6c98e639c/EVIDENCE.md) documents the distinction between test source, source inspection and actual runtime results. Its complete source package does not contain the original staging trace or all full-application dependencies. Deployment comparisons therefore need an implementation-owned run before filling a measured-result row.

## A shared run

The next useful contribution is an implementation-owned record against the same scenario: pre-delegation, unavailable escalation with and without fallback, timeout and late arrival, stale/revoked authority, changed final content, and acceptance followed by lost response. Each implementer supplies the native runner and intended deny point; a separate operator retains target-side evidence. Adapters preserve each system's own semantics. Any denominator or latency claim names the actual workload and sampling unit. Local harness counts stay local harness counts.
