# Agent Evidence Observer (prototype)

This repository is a **local protocol prototype** for an agent action record made by a broker outside the action's claimed effects. It fixes an authority digest and a before-state before the interval, mediates file replacements, records each accepted, denied, and repeated request in a durable hash chain, and signs a final bounded claim. A second key witnesses the chain head before and after the interval. The offline verifier recomputes the bindings from retained bytes and consumer-pinned public keys.

The prototype does **not** launch or isolate an agent. Its records say `witnessScope: PEER`; neither the broker code nor a second local key proves that the agent could not control the observer. This is the implementation boundary for the next milestone, not a label to change in the sample output.

## Run the bounded demonstration

Python 3.12 or later and [`uv`](https://docs.astral.sh/uv/) are needed for these commands:

```sh
uv venv .venv --python python3
uv pip install --python .venv/bin/python -e '.[test]'
.venv/bin/pytest -q
.venv/bin/agent-evidence-observer demo ./sample-run
.venv/bin/agent-evidence-observer verify ./sample-run
```

The two CLI commands print `status: verified`, `witnessScope: PEER`, and `noDetectedGap: true`. The last value means no divergence was detected during the broker's sequential file-tree snapshots; it does **not** mean every agent effect was observed. `sample-run/` contains the authority-bound packet, all history entries, both public verification keys, witness state, and the current file tree. Private keys are ephemeral and are not written to disk. `verify` needs no network connection. It verifies the retained packet against the supplied keys; a real consumer must obtain and pin those keys independently rather than trusting `trusted-keys.json` from the same bundle.

## Claim and trust boundary

| Mechanism | What the prototype checks | What it does not establish |
| --- | --- | --- |
| Authority and prior commitment | The observer signed the authority digest, before-root, interval ID, nonce, and commitment time before the first journaled write; a separate key checkpointed that first entry. | That the clock was honest, the authority was appropriate, or the keys belonged to an independent operator. |
| Brokered write | A normalized path under a literal scope was replaced; the file bytes and before/after content-tree roots are recorded. An identical retry returns the prior effect. | Transient writes, reads, file modes, network effects, writes outside the workspace, or exactly-once effects outside this broker. |
| Coverage | A direct change to the observed workspace or a symlink detected at a snapshot becomes an explicit known gap. The population is broker calls with a valid ASCII request ID, and `noDetectedGap` says only that the snapshots caught no divergence. | Complete agent effects, changes between snapshots that are later undone, or an agent prevented from bypassing the broker. The sample process is not isolated. A hostile host operator can omit or forge observations. |
| History | An ordered SHA-256 chain and two Ed25519-signed checkpoints reject alteration, truncation, or an extension that diverges from the witness's retained head. | Non-equivocation unless a separately operated witness retains and publishes the head. The current witness runs locally under the same operator. |

The JSON signature profile deliberately accepts ASCII strings and safe integers, and rejects floats and non-ASCII values. It is a restricted deterministic JSON profile, **not** a full RFC 8785/JCS implementation. The packet is a `probity-observer-prototype-v0` record, **not** a DSSE envelope or a conformant Observed Effect v0.4.0 statement. Those formats are integration targets after the observer vantage is real. The current format reserves `doesNotAssert` and fixes `witnessScope` to `PEER`; the verifier refuses a packet that claims a stronger value. The file-tree walk is sequential, not an atomic filesystem snapshot. A race can be missed or attributed to the wrong broker call. `noDetectedGap` must never be read as a proof of absence.

## Reached and unreached attacks

The tests exercise file-byte binding over generated contents, path traversal and prefix confusion, idempotency-key reuse, direct workspace mutation, symlink gaps, changed and truncated history, forged claim content, an unpinned witness, duplicate JSON members, and unsafe integers. A passing suite measures these code paths in this version. It is not a security audit of an isolation boundary.

The next implementation gate is a host-side launcher that gives the agent no writable path to the watched tree and no access to the observer process, key, journal, or witness state. It must demonstrate that boundary with attempted direct writes, namespace escape probes appropriate to the chosen platform, broker interruption, key access attempts, and a declared denominator for every effect channel. Until the launcher and an external operator are tested, a relying party has no basis to promote `PEER` to `EXTERNAL` or `below-observed`.

The detailed acceptance criteria are in [`docs/ISOLATED-PRODUCER.md`](docs/ISOLATED-PRODUCER.md). A crash after file replacement but before the history append can leave a durable effect without a write event. The current process cannot seal a complete record after that failure; recovery needs a write-ahead journal. A retry checks the current tree before returning the prior effect, but it cannot see a transient bypass that was later undone.

## Proposed next milestones

1. **Below-agent producer.** Run an unmodified agent under a pinned Linux isolation configuration. Mediate one `write-file` effect through a host broker; keep the observed workspace read-only or unreachable to the agent except through that broker. Publish the launch configuration digest and an attempted-bypass result. Refuse strong coverage when the broker, snapshot, or journal loses a record.
2. **Standard record.** Emit the existing [Observed Effect draft](https://github.com/probityai/agent-evidence-vectors/blob/main/spec/predicates/observed-effect.md) and run its [conformance corpus](https://github.com/probityai/agent-evidence-vectors/tree/main/vectors-observed-effect) through a named external verifier. Bind the in-toto subject to the after-root and the observer's prior commitment to the authority digest, before-root, interval ID, and nonce. Use `jcs-admit` and `dsse` for production byte and signature handling.
3. **Independent history.** Move the witness to a separate principal or operator that stores the highest accepted head and refuses forks; publish checkpoint, inclusion, and consistency evidence for offline consumers. A signed chain head held only by the host is insufficient against host equivocation.
4. **Evidence-led adoption.** Give an independent implementer the verifier, attack corpus, pinned keys, run bundle, and a one-command replay. Report the number of attempts and observed effects, declared coverage population, dropped or unresolved observations, refusal reasons, and measured overhead. Preserve null and incomplete results.

The vocabulary and corpus define and test claims. This repository builds the producer boundary. Its first release is a PEER prototype; the isolated producer and independent witness are tracked in [`docs/ISOLATED-PRODUCER.md`](docs/ISOLATED-PRODUCER.md).

## License

Apache License 2.0; see `LICENSE`.
