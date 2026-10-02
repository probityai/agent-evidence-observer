# Agent Evidence Observer (prototype)

The [HTTP ticket service](docs/HTTP-TICKET-SERVICE.md) owns a persistent native
ticket, checks exact grants before dispatch, and joins retained completion with
a separate HTTP read-back. Its local demo covers restart, revocation, persistent
bypass and hard process crashes across nine declared controls.

[Artifact consumption records](docs/ARTIFACT-CONSUMPTION.md) retain checked input
bytes and attribution, bound to one action and claim. The runnable example keeps
authorization, observation and use separate; it does not assign economic value.

[Declared pilot replay](docs/PILOT-REPLAY.md) reruns native authorization,
history and target checks against a consumer-pinned context. A valid signature
over a fabricated success is not enough: contradictory replay blocks the gate.
This is post-action checking, not durable admission or independent custody.

The [evaluation-history reference](docs/EVALUATION-HISTORY.md) retains every
declared sample and epoch, including wrong answers, errors, interruptions, and
absent native entries. Its optional Inspect AI example runs the official mock
provider locally and checks native-log, source, score mapping, and summary bindings.
This is a harness contract, not LLM performance or independent custody.

The optional [five-tier result contract](interop/evaluation-contract-2026-10-01/README.md)
checks frozen attempts, honest retries and retained outcome mappings across reasoning,
tools, agents, workloads and A2A. Its five-tier demonstration is synthetic accounting.
An optional native bridge now reconstructs the same envelope from pinned Inspect
mock logs, retaining task failures, harness errors, incomplete records and unknown
starts. Native model benchmarks and independent operation remain separate gates.

The [AAE enforcement adapter](docs/AAE-ENFORCEMENT.md) recomputes pinned enforce-core fixtures and links a consumer-pinned local write decision to an observer record. The [protected AAE dispatch path](docs/AAE-PROTECTED-DISPATCH.md) now commits that decision before the local effect and verifies it against the retained grant and native history.

The [Protected Action Kit](docs/PROTECTED-ACTION-KIT.md) checks a signed grant before the broker writes a file. The grant binds principal and tenant labels, tool, target, content and validity window. The [reference example](examples/protected_action_demo.py) verifies its link to the recorded write before consumer admission.

The [protected socket](docs/PROTECTED-DISPATCH.md) adds a measured Linux launch: an isolated child sends exact requests to a host-owned authorization gate, which witnesses the grant relation before dispatch. Completed responses survive restart without another write; ambiguous pending effects are refused. Run `python examples/protected_dispatch_demo.py ./protected-run` on a host that permits bubblewrap. A passing gate requires all 26 child checks, a matching host-recorded effect, restart replay and consumer admission. A denied launch retains an incomplete result. Both paths remain local `PEER` / `artifact` experiments; signed identity labels do not authenticate a remote caller or establish independent custody.

This repository is a local prototype for recording brokered file writes. Before a run, the broker signs the declared authority and starting file-tree state. It records accepted, denied, and repeated requests in a durable hash chain, then signs the final record. A second key signs the chain head before and after the run. The offline verifier checks those records using retained files and public keys pinned by the consumer.

The [declaration-to-action crosswalk](docs/DECLARATION-CROSSWALK.md) compares a
pinned Agent Manifest payload with supplied runtime values, local grant-verifier
results and actual file read-back. Its optional native run checks a pinned
upstream COSE vector and SDK. A matching comparison is not permission, native
conformance, hardware measurement or independent custody.

The basic demo runs without agent isolation. A separate Linux command tests a fixed workload under bubblewrap, as described below. Both produce `witnessScope: PEER` records: neither a second local key nor this launch test establishes an independently operated observer.

## Run the demo

Python 3.12 or later and [`uv`](https://docs.astral.sh/uv/) are needed for these commands:

```sh
uv venv .venv --python python3.12
uv pip install --python .venv/bin/python -e '.[test,aae]'
.venv/bin/pytest -q
.venv/bin/agent-evidence-observer demo ./sample-run
.venv/bin/agent-evidence-observer verify ./sample-run
```

The two CLI commands print `status: verified`, `witnessScope: PEER`, and `noDetectedGap: true`. The last field means the broker's sequential file-tree snapshots found no divergence; it does not mean every agent effect was observed. `sample-run/` contains the signed packet, history, public keys, witness state, and current file tree. Private keys exist only in memory. Verification works offline. Outside this demo, consumers need independently obtained key pins; the bundle's own `trusted-keys.json` is not a source of trust.

## Claim and trust boundary

| Mechanism | What the prototype checks | What it does not establish |
| --- | --- | --- |
| Authority and prior commitment | The observer signed the authority digest, before-root, interval ID, nonce, and commitment time before the first journaled write; a separate key checkpointed that first entry. | That the clock was honest, the authority was appropriate, or the keys belonged to an independent operator. |
| Brokered write | A normalized path under a literal scope was replaced; its content digest and before/after content-tree roots are recorded. An identical retry returns the prior effect. | Intermediate file bytes, transient writes, reads, file modes, network effects, writes outside the workspace, or exactly-once effects outside this broker. |
| Coverage | A direct change to the observed workspace or a symlink detected at a snapshot becomes an explicit known gap. The population is broker calls with a valid ASCII request ID, and `noDetectedGap` says only that the snapshots caught no divergence. | Complete agent effects, changes between snapshots that are later undone, or an agent prevented from bypassing the broker. The sample process is not isolated. A hostile host operator can omit or forge observations. |
| History | An ordered SHA-256 chain and two Ed25519-signed checkpoints reject alteration, truncation, or an extension that diverges from the witness's retained head. | Non-equivocation unless a separately operated witness retains and publishes the head. The current witness runs locally under the same operator. |

The signature format accepts ASCII strings and safe integers, but rejects floats and non-ASCII values. It is deterministic JSON, not a full RFC 8785/JCS implementation. A `probity-observer-prototype-v0` packet is neither a DSSE envelope nor an Observed Effect v0.4.0 statement. Those integrations are planned. The format reserves `doesNotAssert` and fixes `witnessScope` to `PEER`; the verifier rejects stronger claims. File-tree walks are sequential rather than atomic, so a race may go undetected or be attributed to the wrong call. `noDetectedGap` is not proof that no other effect occurred.

## Tests and remaining gaps

Tests cover generated file contents, path traversal and prefix confusion, idempotency-key reuse, direct workspace changes, symlinks, altered and truncated history, forged claims, unpinned witness keys, duplicate JSON members, and unsafe integers. Passing these tests is not a security audit of the isolation boundary.

The next isolation milestone extends the fixed Linux probe to an unmodified agent. The agent must have no direct writable path to the watched tree and no access to the observer process, key, journal, or witness state. Tests need to cover direct writes, platform-specific namespace escapes, broker interruption, key access, and a defined set of attempted effects for each channel. An outside-operated run is also needed before consumers can treat the records as `EXTERNAL` or `below-observed` rather than `PEER`.

The detailed acceptance criteria are in [`docs/ISOLATED-PRODUCER.md`](docs/ISOLATED-PRODUCER.md). A retry checks the current tree before returning the prior effect, but it cannot see a transient bypass that was later undone.

## Linux boundary gate

The `boundary-probe` command commits the probe bytes, observer source digest,
interpreter, bubblewrap binary, launch arguments, before-root, and expiry before
starting a fixed adversarial workload. It exposes one Unix socket to the host
broker and no host workspace, key, journal, or witness path to the workload.

```sh
.venv/bin/agent-evidence-observer boundary-probe ./boundary-run
```

The command returns zero only if direct file write, observer key read, host
process signal, and outbound TCP attempts fail, while a brokered write, exact
retry, changed retry denial, and traversal denial produce the expected durable
history. It writes raw child output and `boundary-report.json` even on failure.
On failed sandbox setup or a failed probe, it writes a witnessed
`incomplete.json` and no complete packet. The report maps to AVE's
`evidence_vantage: artifact`; the signed packet still says `witnessScope: PEER`.
An offline reader can run `verify-boundary ./boundary-run --observer-key KEY
--witness-key KEY` with keys pinned outside the bundle; the command checks the
signed report, authority, raw output, history, and terminal checkpoint.
The fixed probe is a test of one launch policy, not a general proof that an
arbitrary agent has no other effect channel. See
[`docs/BOUNDARY-GATE.md`](docs/BOUNDARY-GATE.md) for its limits and CI command.

A write now has a durable intent before file replacement. If the process dies before the matching effect event, `recover_interrupted(history, workspace, witness)` appends an `incomplete` event with the request ID and a fresh tree root. It checkpoints that history. A consumer can check the signed prior commitment and both witnessed heads with `verify_incomplete(history, start_checkpoint, checkpoint, pinned_observer_key, pinned_witness_key)`.

`LedgerWitness` can retain signed begin and terminal receipts for multiple intervals under one key. It refuses a second branch for an interval and serializes local writers. An offline reader checks the full receipt log with `verify_ledger_receipts`, including extension from a previously pinned log head. The packet still says `PEER`: this does not run a remote service, protect local storage from its operator, or prove that an agent could not reach it. See [`docs/WITNESS-LEDGER.md`](docs/WITNESS-LEDGER.md).

`LedgerWitness.signed_head()` exports a signed count and log head for separate
consumer retention. `verify_ledger_head` checks a later log against that head
and names registered intervals missing a terminal receipt. This detects a
withheld suffix only when the consumer already holds a head beyond it. It does
not establish independent witness custody, freshness, or coverage of intervals
that never reached the witness.

The snapshot describes the state at recovery, not the state at failure. An unresolved intent cannot produce a complete packet, even when recovery finds the same tree root as before.

Recovery currently covers an orphaned write intent. A crash after the effect event and before `seal()` still leaves an unsealed interval.

## Consumer admission

`AdmissionPolicy` and `AdmissionStore` add consumer-selected authority,
interval, key, and retained witness-head checks to packet verification. A
protected local store refuses repeated admissions and receipt-log rollback,
and retains decisions linked to the verified claim and history. Initialization
is explicit; a missing store does not reset replay protection. Run
`python examples/admission_demo.py ./admission-run` for a retained declaration,
brokered write, bounded verification, admission, and replay refusal. See
[`docs/CONSUMER-ADMISSION.md`](docs/CONSUMER-ADMISSION.md) for CLI commands,
ordering, storage ownership, and evidence limits. This same-operator fixture
and the admitted records remain PEER.

## Roadmap

1. **Agent isolation.** A pinned Linux launch will run an unmodified agent with file writes available only through the host broker. The published result will include the launch digest, bypass attempts, and missing broker, snapshot, or journal records. Missing records must prevent a complete-coverage claim.
2. **Standard records.** An adapter will emit the [Observed Effect draft](https://github.com/probityai/agent-evidence-vectors/blob/main/spec/predicates/observed-effect.md) and run its [corpus](https://github.com/probityai/agent-evidence-vectors/tree/main/vectors-observed-effect) through a named external verifier. The in-toto subject will bind the final tree root, and the prior commitment will bind authority, starting root, interval, and nonce. The integration will use `jcs-admit` and `dsse` for byte and signature handling.
3. **Independent history.** A separately operated witness will retain the highest accepted head, refuse forks, and publish checkpoint, inclusion, and consistency records for offline readers. Host-held signatures alone cannot prevent host equivocation.
4. **Independent use.** Replay packages for other implementers will include the verifier, attack corpus, key pins, run bundle, and a one-command replay. Reports will include attempted and observed effects, coverage, missing or unresolved observations, refusals, and overhead, including null and incomplete results.

The vocabulary and corpus define the records and their checks; this repository implements the broker and producer boundary. The current release remains a PEER prototype. Isolation and independent witnessing are tracked in [`docs/ISOLATED-PRODUCER.md`](docs/ISOLATED-PRODUCER.md).

## License

Apache License 2.0; see `LICENSE`.
