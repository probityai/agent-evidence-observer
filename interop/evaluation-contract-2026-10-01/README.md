# Five-tier result reference

A standalone validator for frozen attempt declarations, retained outputs and separate result axes. This optional reference does not change Observer's existing `evaluation_history` or Inspect adapter.

```sh
python -m pip install -e '.[test]'
python -m pytest -q
python demo.py run-001
```

The demo declares seven attempts across reasoning, tools, agents, workloads and A2A. It retains an unsuccessful agent attempt and its retry, an unstarted workload and an incomplete workload. The resulting counts are seven planned, six started, four complete, four scored, one unsuccessful, one unstarted and one incomplete. Task outcomes separately count three passes and one failure; a failed task is distinct from a harness error. **These are synthetic contract exercises, not native reasoning, agent, workload or A2A benchmark results.**

`validate` receives the original plan/history bytes, an in-memory mapping of retained artifacts and two independently selected consumer pins. `demo.py` writes those pins as a convenience for inspecting its same-operator output; copying them from an untrusted packet does not authenticate that packet. Nothing is fetched, signed, executed or admitted by validation.

## What the contract preserves

- Separate catalog authority, capability, runtime target, logical request, attempt, interval, effect and consumer-decision identities. An absent effect or undecided consumer ID stays null.
- Exact task, model, harness, rubric, policy and configuration references. SHA-256 describes original bytes; deterministic wrapper encoding is not RFC 8785 or native signature input.
- Every declared attempt, including errors, timeouts, interruption, incompleteness, explicitly not-started records and start-unknown records where evidence cannot establish a start. Repeated requests need a new attempt and an earlier parent with unchanged request scope.
- Independent task, judge reliability, trust, authority, effect, coverage and consumer outcomes, with reason codes, native explanation, policy profile and supporting artifact references.
- Nullable resource measurements and observed-effect counts. Zero observed effects with incomplete capture remains permissible; the reference `no_effect_in_scope` pass rule additionally requires complete declared capture and zero observations. Consistent completeness assertions do not prove actual coverage.
- The roles of author, implementer, runner, witness, key holder, retention holder, policy owner and consumer. Role strings never establish independence.

Both the records and ordered start ledger must account for the frozen population. Retry starts must follow their parent. Not-started and start-unknown attempts cannot contain resource or observed-effect measurements and do not enter the start ledger. Start-unknown requires a named `start_evidence_missing` gap and cannot carry a decisive effect claim. The report's `missing` count remains explicitly not-started; `unknown_start` is separate. Unknown fields in this wrapper are refused because their semantic treatment has not been specified. Native artifacts are retained unchanged; their unknown fields are never stripped.

Every attempt output contains its normalized record without its own `output` reference. The validator compares that exact structure type-strictly with the report. This checks the reported mapping, not whether a native evaluator produced it. Native adapters must preserve original logs, their signatures, trusted launch binding and mapping assumptions as separate evidence.

## Native integration boundary

`source-manifest.json` records the earlier exact public Observer source inspected. The optional `inspect_contract.py` bridge now verifies selected native logs through Observer's existing Inspect adapter before reconstructing the common packet. It supports `inspect-ai==0.3.273`, `mockllm/model`, one `generate` solver, the default `match` scorer and zero native sample retries. Native retries, invalidation, changed options and log rewrites remain refusals.

From this directory, run the native example with:

```sh
python -m pip install -e '.[test]' -e '../..[inspect]'
python inspect_demo.py native-run-001
```

The official Inspect harness runs four graded attempts (two passes and two task failures) and an exhausted mock-output task with three retained attempts (one completed and two harness errors). These are native mock harness runs, not real-model benchmark scores. The latter run retained all three starts; no missing execution is invented. Missing and incomplete native records are separate mutation controls. The five-tier synthetic demo still exercises the other tiers; this native profile exercises reasoning only.

Each logical request is a framed task/sample/epoch identity, while each attempt retains its original declaration ID. Configured epochs are distinct requests, not inferred native retries. Consumer decision and effect IDs stay null. Resource counters and timing stay in the original native bytes; this mapping leaves normalized resources unknown. Trust, authority, effect, coverage, judge reliability and consumer outcomes remain not exercised.

An absent native entry maps to `start-unknown`, with an unknown task outcome and a named absence gap. A native start without a completion maps to `incomplete`; that missing completion is not itself evidence of cancellation. An explicit native error maps to `error`, and a completed sample without a score stays complete and unscored. The ledger lists retained starts in declaration order; it does not assert native dispatch chronology. The common declaration is written before the demo run and bound to the prior native declaration, but this same-operator file is not an authenticated prior commitment.

The mapping is pinned as `probity-inspect-five-tier-v1`. `verify` recomputes the common plan, records, ledger and artifact population from the caller-selected native log, native binding and original declaration. A fabricated outcome remains refused even if its wrapper is rehashed and passes standalone consistency validation. Selected common digests are additional trust inputs; copying all pins from an untrusted packet does not authenticate it. Original logs, installed runtime code hashes, implementation source bytes, package metadata, license, plans and verification reports are retained by the native demo and CI.

A native adapter may emit this envelope only after selecting a versioned mapping and retaining its original output. The envelope cannot discover undeclared executions, verify source authorship, authenticate a start ledger, establish prior commitment, judge task correctness, verify native signatures or prove independent custody. `retained-native` labels origin intent; accepting that string is not native-adapter certification. Five-tier native runs and host acceptance remain separate completion gates.

The dedicated CI workflow retains measured test output, the synthetic demo and native mock packets as artifacts. Historical outputs should remain immutable; run another demo in a fresh directory. Run commands above from this directory. The repository Apache-2.0 license applies; retained Inspect files carry their native license in the run output.

## Native tools, agents and local workload

`inspect_execution.py` adds the separate `probity-inspect-execution-v1` profile. It leaves the reasoning adapter unchanged. With the same pinned Inspect dependency, run:

```sh
python inspect_execution.py native-execution-001
```

The official native `use_tools`/`generate` path executes a bounded arithmetic tool. The native `react(submit=False)` agent executes that tool through its actual tool loop. A local workload uses the native agent to read an `OPEN` ticket file and write `DONE`; its file read-back is retained separately from the model transcript. The mock provider selects finite tool calls and responses. This tests actual framework execution and retention, not model planning ability or benchmark quality.

The pre-run declaration contains six entries: a tool pass, a tool task failure, an agent pass, an agent that exhausts its mock outputs and records a native harness error, a completed local workload, and an explicitly unscheduled workload. The normal demo retains five starts, four completions, three task passes, one task failure, one harness error and one planned unstarted entry. The unstarted classification comes from the same operator's `launch:false` declaration; it is not independently observed. Missing logs or native samples for a scheduled entry instead remain `start-unknown`. A retained start without completion maps to `incomplete`. Actual run errors and mutation controls are distinguished in the receipt.

The mapper joins each retained assistant tool call, native tool event and tool reply by exact call ID, function and arguments, then recomputes the owned tool's arithmetic or read/write values. The workload's retained file bytes must be `DONE`. The supported final strings are finite, so the selected native C/I score is also checked against the declared final response. This is an implementation consistency check, not an independent judge. Native retries, altered solver/configuration/source identities, duplicate samples, changed tool values and wrong read-back bytes are refused.

Normalized `elapsed_ns` is `floor(sample.total_time * 1e9)`, representing the native sample duration in seconds. It does not create nanosecond precision: Inspect's original duration and rounding remain in the original bytes and measurement manifest. Successful owned tool bodies measure `perf_counter_ns` elapsed time and `thread_time_ns` CPU time. The supplementary CPU total excludes framework work, other threads and failed tool bodies; it is not process or workload CPU. Native tool-event counts are operation counts, not effect or completeness counts. Mock token zeros and unmeasured memory stay null in the common resources.

Authority, trust, coverage, consumer decisions and judge reliability stay not exercised. The local workload effect axis remains unknown with retained read-back evidence; it is not an authenticated effect attestation. Capture remains incomplete, and effect and consumer IDs remain null. Start order is derived from the declaration, not authenticated native chronology. Pre-run local files, a selected source manifest and matching digests do not prove independent custody, prior witness commitment, global containment or host adoption.

`verify` receives the selected original declaration, raw native logs, external native bindings, original source bytes and local read-back bytes. It reconstructs the entire common plan, history and artifact mapping before checking external common pins. Changing normalized outcomes, resources, axes or supplemental measurements and rehashing the packet does not bypass this reconstruction. Select native and common digests outside an untrusted packet; the demo's convenience `consumer-pins.json` is not a trust authority.

CI retains the actual native logs, packet, source pins, installed runtime manifest, distribution metadata and Inspect license. `OUTPUT/receipt.json` gives the scoped run result and `OUTPUT/packet/report.json` gives separate common population counts. Use a fresh output directory for each run.

For an offline consumer run, select the original declaration, source-manifest, native-binding, common-plan and common-history digests outside the received packet, place them in a JSON file with the same five keys shown in the demo's convenience pin file, then run:

```sh
python inspect_execution.py native-execution-001 --verify --pins-file selected-pins.json
```

This command invokes no framework or provider. It checks those externally selected pins, refuses artifact path escapes and reconstructs every supported native join. A copied in-packet pin file is useful for a local round trip but establishes no external trust. Altered source bytes, changed bindings, added artifacts and rehashed normalized records remain refusals.
