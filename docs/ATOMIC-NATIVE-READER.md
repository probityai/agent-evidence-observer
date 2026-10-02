# Read Atomic's native delegation evaluation

`agent-evidence-read-atomic` checks a retained run of Atomic's native Rust delegation tests. It is an installed, offline consumer: it launches neither Atomic nor an agent framework. The wheel contains the reader; a separate Observer source checkout is unnecessary. Python 3.12 and the root package's normal dependencies are required. Install from a reviewed immutable revision or retained wheel:

```sh
python -m pip install 'agent-evidence-observer @ git+https://github.com/probityai/agent-evidence-observer.git@REVIEWED_COMMIT'
agent-evidence-read-atomic describe --packet /retained/atomic-run > /policy/candidate-selection.json
# Review this candidate through the consumer's accepted selection process.
# After selection, pin the file's SHA-256 separately in consumer policy/CI.
agent-evidence-read-atomic verify --packet /retained/atomic-run --selection /policy/selected-inputs.json --selection-sha256 SELECTED_SHA256 --output /consumer/new-receipt.json
```

The selection file and receipt must be outside the producer packet. The receipt must be new. Verification exits nonzero on refusal and retains a refusal receipt when the output path is valid. A zero exit means selected retained bytes and control records are consistent. It does not mean this consumer reran Atomic, authenticated the operator or established an external trust root. `describe` prints candidate hashes for review; accepting an untrusted producer's candidate without a separate selection decision does not authenticate it.

## Native contract and controls

Version 1 accepts only `atomic-native-delegation-evaluation/v1`, produced by Atomic's `tools/native-evaluation/run.py`. The initial producer revision is `astrogilda/atomic@80be8dae6feb8b9106181b78fba2c7c6a7c8f4d8`. That is a proposed upstream implementation; it does not establish Atomic maintainer acceptance. The shipped reader fixes the following four-case population:

- Exact retry and a fresh process preserve a narrow local grant.
- Local revocation survives restart; a distinct renewal remains selectable.
- Expired, changed-scope and ambiguous JSON grants stay inactive; a valid control restores selection.
- Local selection accepts a self-contained valid grant, while its native test refuses verification with an unrelated issuer key; another subject's grant does not replace it.

The retained worker observations describe local grant selection, counts, local revocation, allowed scope and operating-system process IDs. The reader checks exact case order, expected 2/4/4/2 observation counts, native pass lines, distinct worker IDs within each case, control values, and bindings between the report and original stdout. The native test also asserts child process and key verification behavior internally. The report records those test outcomes; this reader does not independently replay the native assertions or verify grant signatures from public certificate bytes.

The consumer selection pins the exact report, clean source commit label, installed `atomic_reader.py` bytes and all 18 retained artifacts: source test, runner, runner documentation, CI source, Cargo lockfile, empty source diff, exact native executable, complete test population, build stdout/stderr and each case's stdout/stderr. Missing logs, a changed executable, altered lockfile, dropped cases, changed scope, changed test population and a wrong selection digest fail. Duplicate JSON members, nonfinite numbers, symlink paths, dirty source records and changed coverage claims also fail. The installed reader pin covers this module, not every root package dependency or the interpreter. Review and pin the distribution and environment under the consumer's own policy.

The schema supports finite declared budgets: JSON inputs at most 8 MiB; each retained artifact at most 256 MiB. The reader streams artifact hashes. The current runner's executable and full source/input files remain part of the packet; a report-only summary is insufficient.

## Coverage and custody

Keys, clock, temporary identity store and producer/consumer are operated by the same author. Private signing keys are ephemeral and are not retained. The native tests evaluate distinct operating-system processes over a local store. Server authorization, remote revocation, independent effect custody, external effects, crashes during a write and model execution remain outside this contract. A digest manifest establishes byte selection and consistency, not those properties.

The dedicated `Installed Atomic native reader` workflow builds the pinned native producer, retains its original bundle, builds and installs this wheel into a clean consumer environment, accepts the selected native packet, and exercises seven refusal controls. `examples/atomic_consumer_demo.py` deliberately selects operator-local bytes for that demonstration. Source schema tests use synthetic bytes and do not count as native execution. The workflow uploads original native artifacts, the wheel, selections, receipts and refusal stdout/stderr. This is author-operated CI; recurring use in another project's workflow is a separate adoption event.

For upgrades, install a reviewed new wheel, review the reader module's changed digest and supported contract, then make a new selection. Never silently reuse a previous selection after replacing the reader, native binary, lockfile or producer source revision. Native tests can be rerun repeatedly at the selected producer revision to generate fresh packets; select each run's actual bytes rather than treating one successful run as permanent authorization.
