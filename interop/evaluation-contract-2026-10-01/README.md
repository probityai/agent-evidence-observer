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

- Separate catalog authority, capability, runtime target, logical request, attempt, interval, effect and consumer-decision identities. An absent effect ID stays null.
- Exact task, model, harness, rubric, policy and configuration references. SHA-256 describes original bytes; deterministic wrapper encoding is not RFC 8785 or native signature input.
- Every declared attempt, including errors, timeouts, interruption, incompleteness and not-started records. Repeated requests need a new attempt and an earlier parent with unchanged request scope.
- Independent task, judge reliability, trust, authority, effect, coverage and consumer outcomes, with reason codes, native explanation, policy profile and supporting artifact references.
- Nullable resource measurements and observed-effect counts. Zero observed effects with incomplete capture remains permissible; the reference `no_effect_in_scope` pass rule additionally requires complete declared capture and zero observations. Consistent completeness assertions do not prove actual coverage.
- The roles of author, implementer, runner, witness, key holder, retention holder, policy owner and consumer. Role strings never establish independence.

Both the records and ordered start ledger must account for the frozen population. Retry starts must follow their parent; a not-started attempt cannot contain resource or observed-effect measurements. Unknown fields in this new wrapper are refused because their semantic treatment has not been specified. Native artifacts are retained unchanged; their unknown fields are never stripped.

Every attempt output contains its normalized record without its own `output` reference. The validator compares that exact structure type-strictly with the report. This checks the reported mapping, not whether a native evaluator produced it. Native adapters must preserve original logs, their signatures, trusted launch binding and mapping assumptions as separate evidence.

## Native integration boundary

`source-manifest.json` records the exact existing public Observer source inspected. The Inspect adapter already supports `inspect-ai==0.3.273` with `mockllm/model` and `offline-contract` mode. That native mock harness is not an LLM benchmark. No native Inspect run or new protected-dispatch run is claimed by this package.

A native adapter may emit this envelope only after selecting a versioned mapping and retaining its original output. The envelope cannot discover undeclared executions, verify source authorship, authenticate a start ledger, establish prior commitment, judge task correctness, verify native signatures or prove independent custody. `retained-native` labels origin intent; accepting that string is not native-adapter certification. Five-tier native runs and host acceptance remain separate completion gates.

The dedicated CI workflow retains its measured test output and synthetic demo as artifacts. Historical outputs should remain immutable; run another demo in a fresh directory. Run commands above from this directory. The repository Apache-2.0 license applies.
