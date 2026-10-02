# Native A2A SDK exchange

This optional reference launches the official A2A Python SDK **1.2.1**, pinned to `041c17bbe8d5ced7a8f6c48761152ce01ffbfc14`, as a separate local server process. Its SDK JSON-RPC client sends actual HTTP requests with `A2A-Version: 1.0`. The target is a deterministic arithmetic executor; no model, paid API, independent operator or external host is involved. This exercises a native protocol path, not A2A project adoption or benchmark quality.

The runner writes the finite declaration and source snapshots before launching the server or sending a request. Six attempts remain visible:

| Attempt | Native result | Common result |
| --- | --- | --- |
| Decimal addition | Returned SDK Message containing `5` | Complete, task pass |
| Same operation, expected `6` | Returned SDK Message containing `5` | Complete, task fail |
| Executor exception | SDK JSON-RPC internal error | Error, task unknown |
| Explicit failed task | SDK Task with `TASK_STATE_FAILED` | Error, task unknown |
| Executor waiting indefinitely | HTTP client reaches its timeout; response absent | Incomplete, task unknown |
| Declared request never launched | No native launch evidence | Start unknown, task unknown |

The failed-Task row represents a native unsuccessful execution. It is not a scored rubric failure. An absent native launch is not proof that nothing ran. The planned denominator is six, the observed client/server start denominator is five, and two completed attempts are scored. The waiting executor is terminated with its server process after the client timeout. No completion is invented.

The packet retains the original AgentCard, HTTP JSON bodies and bounded request metadata, fsynced server executor events, client launch/finish ledger, client errors, selected installed SDK source bytes, SDK license and source pins, exact local mapper and common validator source, runtime versions and raw server log. The mapping checks the exact HTTP target and protocol version, JSON-RPC method/id, declared message/context/input, returned message id/text, and native Task id/context/state/history against the server's retained execution event. The catalog task id remains a separate declared identity from the SDK's generated task UUID. Original bytes are retained; JSON normalization is used only for the separate common packet.

`elapsed_ns` is measured around the actual SDK client call with `perf_counter_ns`. It includes local client and network work; the unit does not imply nanosecond accuracy. Tokens and peak memory remain unknown. No task score establishes trust, authority, effects, independent judgement or consumer approval. Effect and decision identities remain null. Coverage remains incomplete with named gaps. Both parties, their retention and their source declaration are controlled by the same operator. The on-disk pre-run declaration is not an independently witnessed commitment, and the unsigned AgentCard does not authenticate a producer.

Run from the repository root with Python 3.12:

```sh
python -m pip install -e 'interop/a2a-native-2026-10-02[test]'
python -m pytest -q interop/a2a-native-2026-10-02/tests
python interop/a2a-native-2026-10-02/a2a_demo.py new-a2a-run
```

The demo refuses an existing output directory. CI retains the complete native and mapped packets even when a later step fails. The source manifest covers the selected SDK client, dispatcher, routes, request handler, executor interface and message helpers; it does not claim that every transitive dependency is source-pinned. Runtime package versions are retained separately.

The consumer must select original native digests and the common plan/history digests outside the submitted packet. For a local reproduction, copy `selected-native-pins.json` and the plan/history values from `report.json` into your retained receipt, then invoke:

```sh
python interop/a2a-native-2026-10-02/a2a_verify.py new-a2a-run \
  --native-pins retained-native-pins.json \
  --plan-sha256 SELECTED_PLAN_SHA256 \
  --history-sha256 SELECTED_HISTORY_SHA256
```

The reader reconstructs the entire common declaration, history and artifact map from those native inputs before validating common pins. Merely rehashing a fabricated score is refused. Reading pins supplied by the producer establishes byte consistency only; it does not establish independent custody. This reader is a separate invocation of the same Probity implementation, not a second implementation. Its source and recorded runtime must match the selected packet; an environment or profile change needs an explicit new reproduction.

The tests run the actual local SDK exchange and then apply explicit mutation controls. They cover changed content, context, method, RPC id, task id/state/history, target endpoint and protocol; a successful command with no retained response; hidden starts and extra artifacts; boolean elapsed values; selected native pins; and a rehashed fabricated common score. These controls are distinct from the six native attempts.
