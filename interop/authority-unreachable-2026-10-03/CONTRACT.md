# Proposed authority, effect and terminal comparison

Use one record per attempted action. Keep implemented checks, known gaps and simulation results in their own implementation rows. An approval signature answers a different question from whether a side effect committed.

## Contract identifier

Every trace written against this record MUST carry

```
"contractId": "https://probityai.github.io/agent-evidence-observer/contract/authority-at-dispatch/v1"
```

The reader checks it before any other field and refuses a trace that omits it (`trace contract id is missing`) or names another version (`trace contract id differs`). A change to a field's required meaning is a new version; the reader for `v1` never interprets a `v2` trace.

Each field that a trace leaves unfilled carries one of three states, kept apart as Imran Siddique asked on the list (6 October): `not_applicable` (the implementation has no such step), `not_emitted` (the step exists and the record does not carry it) and `not_measured` (the record could carry it and this run did not measure it).

| Record field | Required meaning |
| --- | --- |
| Implementation and source | Exact producer revision, adapter revision and executed path; source inspection and runtime execution have different evidence classes. |
| Action identity | Run, attempt, request/idempotency, tenant, principal, action/tool and exact target IDs. |
| Approved action | Actual text/payload bytes, media bytes or immutable byte digest, destination, tool-catalogue revision and approval time. Mutable references alone leave a binding gap. |
| Delegation and fallback | Original decision deadline, grant expiry, exact pre-authorized fallback and its scope. Availability does not widen authority. |
| Authority evidence | Source, revision, status/root, observation time, `evidenceAgeSeconds` (decision time minus observation time), `freshnessLimitSeconds` (the deployed limit) and the check performed at dispatch. Unperformed checks remain unperformed. The two named fields follow Imran Siddique's request (list, 3 October) that each comparison keep the deployed freshness limit beside the actual age; the reader refuses an age that disagrees with the signed observation time and a limit other than the one the consumer selected. |
| Delegation chain | `delegationRoot` and ordered `delegationHops`, each with delegator, delegate, actions and targets. Each hop's scope is a subset of the hop before it, and the last hop's delegate is the requesting principal. A wider later hop is amplification and is refused (`delegation hop widens scope`). |
| Temporal revocation | Trigger time, authority evidence consulted, last accepted action, required deny point and first observed denial, per path. Presentation lifetime and revocation latency have separate fields. |
| Dispatch decision | Allow, deny or indeterminate, plus exact reason and the enforcement point reached. |
| Observed effect | Target-read evidence, committed object/effect ID, exact bytes/digest, revision/count and observation coverage. A failed return cannot substitute for this evidence. |
| Task and recovery | Terminal status, safe blocking/completion, recovery latency, every retry, duplicate count and interruption point. Recovery remains unknown unless measured. |
| Reader appraisal | Selected trust pins, checks actually performed, missing proof, contradictions, publication/consumer decision and retained evidence. |
| Operation and custody | Who ran the producer, gate, status source and reader; who controlled each key/store; retained artifact location and covered effect boundary. |

The reference profile implements nineteen deterministic cases over one local native ticket per case. Availability is a controlled input, not a live human outage. A host-supplied signed status snapshot models current authority, with a selected 180-second maximum age; it is not a MintID root verifier or a deployed revocation measurement. The deadline prevents a newly valid late grant from reopening an expired request.

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
| Second delegation hop widens action and target scope | Admission stops before native mutation; the reader reports `delegationStatus: not-admitted`. |

The peer reader authenticates the profile record and native service state, opens the retained SQLite database read-only, replays the exact native event bodies and transitions, and compares the actual ticket identity and bytes. Retained completion must match every field of the observed signed native state. Completed dispatch returns must match the observed immutable state and a real unrevoked prefix of its native history; a task terminal must agree with its retained final dispatch return. Signed contradictions are refused. Native completion appraisal reuses Observer's source-pinned verifier. This is a separately installed consumer, not an independently implemented or independently operated verifier. The reference table has no general remote publication, delegation beyond the recorded two-hop chain, OAuth descendant-token revocation, funded recourse or private-chain proof.

## Delegated-authority cases mapped to this record

The working group list carries six vendor-neutral delegated-authority cases (2 October), each stated as an expected invariant, failure condition, observable evidence and residual risk. Five of them run in this profile today; case 4 is the unreachable-human pair above. Each row names the reference cases and the record fields that decide it.

| Case | Expected invariant | Failure condition | Observable evidence in this record | Reference cases | Residual risk this profile leaves |
| --- | --- | --- | --- | --- | --- |
| 1. Delegator revoked after downstream delegation | No dispatch after the revocation reaches the enforcement point | A dispatch is allowed after the revocation | Temporal revocation fields; dispatch decision and reason; native row count after the trigger | `approver-revoked-at-dispatch`, `revoked-between-intent-and-effect`, `effect-then-authority-revoked` | Revocation is a local status snapshot; propagation latency across a real directory is not measured |
| 2. Valid delegation presented for the wrong object or action | The approved digest binds text, media bytes, destination and tool catalogue | Dispatch proceeds with bytes other than the approved ones | `dispatchContentSha256` against the approved request digest; native row bytes | `media-bytes-mutated`, `platform-content-mutated`, `catalogue-mutated`, `destination-mutated` | Platform rewriting after the local effect is outside the native table |
| 3. Stale revocation information | Authority evidence older than the deployed limit is refused | Dispatch on evidence older than `freshnessLimitSeconds` | `evidenceAgeSeconds`, `freshnessLimitSeconds`, refusal reason | `authority-evidence-stale` | The limit is a consumer choice (180 s here); a status source can lie within it |
| 5. Authority amplified across a multi-hop chain | Each hop's actions and targets are a subset of the hop before | A later hop holds an action or target its delegator lacked | `delegationHops`, `delegationStatus`, refusal reason | `delegation-hop-amplified` | Two hops only; no descendant-token revocation |
| 6. Identity valid, effective authority expired | Grant expiry and the original decision deadline both bound dispatch | Dispatch after expiry, or a late fresh grant reopening an expired request | Grant validity, `requestDeadline`, refusal reason | `fallback-expired`, `late-approval-for-expired-request` | The reference clock is trusted; clock skew is not modelled |

Each record carries `residualRisks`, the right-hand column above as identifiers: `revocation-propagation-unmeasured`, `post-effect-platform-rewrite-unobserved`, `status-source-trusted-within-freshness-limit`, `two-hop-chain-only`, `descendant-token-revocation-absent` and `reference-clock-trusted`. The reader refuses a record that omits one its case leaves open (`record closes a residual risk this profile leaves open`), and one that adds an identifier the profile does not name. A residual risk is therefore never read as covered.

cA2A maps onto case 3 the same way. Its `verify_chain` reports `REVOCATION_STATUS_UNKNOWN` for a snapshot older than `max_revocation_staleness`, and reports a hop revoked in a stale snapshot as `CREDENTIAL_REVOKED` first ([delegation-chain.md at 858f666](https://github.com/agentrust-io/ca2a/blob/858f6661ab1d7efe145b5d37a8289dfcaffcea17/docs/spec/delegation-chain.md)). With that bound unset, the default, verification states it did not check revocation; in this record that is an unperformed check, never a pass.

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

## Implementation records read by this profile

`implementation_records.py` reads each implementation's own published records against the fields above. It re-derives every value from the raw bytes (JSONL events, checksum files, run reports) and compares the implementation's manifest or summary against that derivation. Each check passes, fails with the exact contradiction, or is reported as not performed with its reason. The records are vendored under `implementation-records/` with their upstream URL, size and SHA-256 in `SOURCES.json`, and CI re-fetches every URL and compares bytes before the reader runs.

| Implementation and evidence read | Fields the records fill | What the reader found |
| --- | --- | --- |
| MintID, `revocation-trace-testnet-20261006T073712Z` at `public-v2026-10-07` (`b678e5c`), public testnet, production parameters | Authority evidence (180 s maximum root age, 30 s heartbeat, chain and policy pins); temporal revocation per path; dispatch decision with reason code and deciding condition. Observed effect, task and lost response are outside the implementation. Funded recourse planned; sub-delegation unavailable | All 34 decisions rebuild from the JSONL and agree with the verifier's log lines. Every trigger instant re-derives from its trigger event. First refusal after the trigger: issuer +9.3 s (bound 185 s), kill switch +36.8 s (245 s), cascade +35.1 s and +156.1 s (395 s), emergency at the block after the emergency root. No revoked agent is accepted after its first refusal. Each revoked agent's own refresh is refused `credential_revoked`. On the issuer path the first refusal fell on the same root rollover that refused the never-revoked control, so that refusal does not by itself distinguish revocation; the refused refresh does. The ten-second presentation lifetime is a source constant (`PRESENTATION_LIFETIME_SECONDS`), not a field in the record |
| Proofable, `proofable/docs` `3a45f02`, `four-case-run-f92faf39a4ba`, live hosted MCP | Dispatch decision per case; observed effect (`none_no_executor`, `none_no_dispatch`, `observed_at_platform`); unreachable authority not applicable to the current path | `trace.jsonl` does not match its `SHA256SUMS` line or `manifest.public_trace.sha256`: the published digest is the hash of the CRLF form, while the published bytes use LF. `stale_authority` is denied with no reason code. The post-dispatch revocation case states its deny point as the next dispatch after revocation, but the trace has no revocation time and no later dispatch under that delegation. All three terminal receipts are private, so the CAIP-380 envelope check the manifest names cannot run from the public package |
| Alakris, `aaif-publication-reference` `ebd9dcf`, operator rerun of 2026-10-04 | Approved action (fingerprint inputs); original tests (37 run, 35 pass, 2 fail at import); the eighteen cases this profile had on 2026-10-04, rerun by the implementer (the delegation case added later is reported as not rerun) | Checksums and the four-file source pin hold. The implementer's rerun of this profile matches this run case by case on every output axis, including the lost-response case (effect observed, task failed, publication blocked). The six fingerprint inputs reproduce when the pinned source is supplied. The deployed publication path has no runtime trace, so dispatch and committed effect stay unmeasured there |

The lost-response case is the one no implementation row yet measures on its own path: MintID ends at the relying party's decision, Proofable's package does not exercise it, and Alakris states that a retry after a lost response can publish twice. The reference case shows the record a reader needs: the committed effect stays observed after the failed return, the task stays failed, and publication stays blocked.

## A shared run

The next useful contribution is an implementation-owned record against the same scenario: pre-delegation, unavailable escalation with and without fallback, timeout and late arrival, stale/revoked authority, changed final content, and acceptance followed by lost response. Each implementer supplies the native runner and intended deny point; a separate operator retains target-side evidence. Adapters preserve each system's own semantics. Any denominator or latency claim names the actual workload and sampling unit. Local harness counts stay local harness counts.
