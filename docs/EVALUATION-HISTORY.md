# Declared evaluation history

This reference checks a finite declared sample-by-epoch population against
retained attempts, native logs, source bytes, and summary counts. Errors,
interruptions, wrong answers, and absent native entries stay in the population.
It does not establish execution truth, independent custody, or global completeness.

## Run the official mock harness

The native example requires the optional dependency:

```sh
python -m pip install -e '.[test,inspect]'
python examples/evaluation_history_demo.py --output-dir evaluation-receipts
```

The output directory must be new. Inspect AI 0.3.273 runs its real `Task`,
`generate`, and `match` implementations with the official `mockllm/model`
provider. No paid model or external model API is invoked. Mock answers test the
logging and grading contract; they are not evidence of LLM performance.

The example declares and writes each plan before invoking Inspect. It retains
the original native JSON log, launch receipt, source/configuration bytes,
per-attempt envelopes, checker results, and mutation controls. The graded case
has four completed attempts, including two wrong answers. The finite-stream
failure case records one completed attempt and two native errors. This local
ordering is operator-run behavior, not an independently witnessed commitment.

The core test suite needs only the existing test extra; it does not import Inspect:

```sh
python -m pip install -e '.[test]'
python -m pytest tests/test_evaluation_history.py tests/test_inspect_history.py
```

## What is bound

| Role | Required evidence |
| --- | --- |
| Task | Versioned task configuration, complete text samples, IDs, inputs, targets, epochs, and concurrency |
| Model | Mock identity, finite declared text-output stream, explicit zero usage, and retained provider source |
| Solver | `generate`, default options, Inspect version, and retained implementation bytes |
| Checker | Separate checker identity/version and a bundle matching the local verifier source files |
| Scorer | `match`, default options, Inspect version, and retained implementation bytes |
| Policy | Separate `match-C-I` version `v0`: C means pass, I means fail, absent/error means unscored |
| Harness | Inspect version and retained implementation bytes |

Every retained artifact has an exact name, SHA-256, and byte count. Names are
mapping identities, not paths to resolve or URIs to fetch. Reference JSON uses
sorted members and refuses duplicate members and non-finite numbers. Each JSON
artifact is limited to 8 MiB, 128 nesting levels, and 100,000 decoded values.
The encoding does not
claim RFC 8785 or a protocol standard.

`verify_history` checks one ordered record per declared attempt, exact artifact
and source populations, UTC timing, status/outcome constraints, and recomputed
counts. Record ordinals follow declaration order, not completion order.

`verify_inspect_history` additionally selects the native run ID, evaluation ID,
and original log digest, then reconstructs every record and envelope from those
native bytes. Supplied records or envelopes must match that reconstruction.
Native metadata must bind the program run ID and full plan digest. The verifier
checks task input/target/configuration bindings and the policy's mapping of
retained native C/I score records to pass/fail,
the local checker bundle, and the completion multiset of a declared mock-output
prefix. This multiset comparison does not establish model-call order: Inspect
can sort retained samples by epoch and ID. Scorer, solver,
and harness source pins establish retained bytes and native identities, not
independently proven execution of those implementations. A self-consistent
edit of a native score can change pass/fail even when the completion and target
stay fixed. This checker does not independently rescore `match`.

Use `InspectBinding(run_id, eval_id, log_sha256)` from a consumer-selected launch
receipt. Repeating a run ID is insufficient to accept replaced native bytes.
Selecting a new digest also selects a new authority: a receipt supplied by the
same operator is not independent evidence of execution.

## Explicit limits

The native adapter supports JSON log schema 2 from Inspect AI 0.3.273, a finite
text task, serial concurrency, the official mock provider, one `generate` step,
and default `match`. It refuses unsupported finish solvers, scorer/solver options,
sample retries, limits, invalidation, log rewrites, and changed populations.
Provider-internal retries and activity outside the retained native transcript
are not established. Real model providers need a separately reviewed profile.

A successful native log missing a declared sample is refused. An interrupted or
errored log can retain an explicit `not_run`/`absent-from-native-log` entry. This
means no native sample entry was retained, not proof that the sample never ran.
A started sample without a completion time is `interrupted`; its end time is not
invented. An execution error remains unscored even if partial output is retained.

The same operator can fabricate a consistent plan, log, and receipt. These checks
do not prove that all possible attempts were declared, that task quality is good,
that native transcripts capture all external effects, or that anyone independent
held the evidence. Fresh process/custody witnesses and real model evaluation are
separate next steps.

## Source basis

The adapter follows the official Inspect AI evaluation-log schema and mock-model
API. The local execution pins the actual installed 0.3.273 source files and a
manifest of its Python files. An upstream Git revision is not substituted for
those executed-file hashes.

- [Official evaluation-log documentation](https://inspect.aisi.org.uk/eval-logs.html)
- [Pinned upstream log schema](https://github.com/UKGovernmentBEIS/inspect_ai/blob/0321960a92aa52390413ce011d67ffb5962a2b11/src/inspect_ai/log/_log.py)
- [Pinned official mock provider](https://github.com/UKGovernmentBEIS/inspect_ai/blob/0321960a92aa52390413ce011d67ffb5962a2b11/src/inspect_ai/model/_providers/mockllm.py)

The example retains Inspect's MIT license alongside copied source bytes.
