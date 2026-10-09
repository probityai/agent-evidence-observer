# Pydantic AI native tool → authorized HTTP effect → installed consumer

This is an additive Probity-operated execution reference. It runs actual `pydantic-ai-slim==1.68.0` agents,
typed tools, native retries and native message serialization against Observer's
existing protected HTTP ticket service. `FunctionModel` supplies scripted local
responses: there is no provider call, model inference, task-quality score,
independent custody, framework adoption or production deployment claim.

## Seven fixed v1 cases

| Case | Native tool behavior | HTTP/native state | Consumer classification |
| --- | --- | --- | --- |
| permit | One typed `DONE` argument | Signed grant; POST 200; separate GET revision 1 | Verified local ticket effect |
| deny | One typed `DONE` argument | Host revokes authority before launch; POST 409; GET revision 0 | Refused, no recorded local row |
| changed-arguments | Native tool calls `CHANGED` against grant for `DONE` | Original content commitment retained; POST 409; GET revision 0 | Refused, no recorded local row |
| retry | Native `ModelRetry` before dispatch, followed by `DONE` | Both calls and native retry retained; second call POST 200; GET revision 1 | One effect after one retained retry |
| producer-error | Tool raises selected `RuntimeError` before HTTP | Original native call and exception retained; final GET revision 0 | Execution error, no task score |
| retry-exhausted | Both typed calls raise `ModelRetry`; native retry budget is one | One native retry prompt, two retained wrapper attempts, terminal `UnexpectedModelBehavior`; GET revision 0 | Retry exhaustion, no recorded local row |
| committed-effect-error | POST commits, then tool raises selected `RuntimeError` before returning | POST 200; separate GET revision 1; native history ends at tool call | Execution error and verified retained effect together |

The producer freezes the public case population, exact ActionRequest, grant,
issuer policy, service key, initial signed native snapshot and source manifest
before the first agent execution. Each case has its own ephemeral issuer and
service keys, request/attempt/target identity and fresh SQLite store. Private
keys and stores are discarded after retained HTTP readback; no private key is
written to the packet.

`ModelMessagesTypeAdapter.dump_json` output is retained **verbatim**. Its field
order and formatting are not rewritten. The offline parser refuses duplicate
names and checks native request/response order, native run identity, model,
clock order bounded by precise consumer evaluation time, exact tool IDs and arguments, retry content, return IDs, terminal
output and error status. The typed argument's actual UTF-8 bytes join to the
exact POST body. The native return joins to a SHA-256 of the original HTTP
packet. A separate GET response must match the signed receipt, issuer-selected
grant, exact request and content digest through the existing ticket verifier.

The reader neither imports Pydantic AI nor calls HTTP. It requires three hashes
and a historical evaluation time selected **outside** the packet. Native times are
checked at their original precision; the existing signed-grant and ticket
verifier receive the reference time projected to their UTC-second contract. The producer
writes `consumer-pins.json` for inspection; selecting or copying that file in
this same-operator demonstration does not establish independent prior selection.
A deployed consumer must select its own policy pins and reference clock.

## Installed execution and separate offline consumer

Run from this profile directory using Python 3.13. Create a fresh virtual
environment first. The locked requirements include runtime, tests and build
packages; `--require-hashes` refuses unselected dependency bytes. Wheel builds
and installations propagate failures. Framework/runtime dependencies are
isolated from Observer's root project and other profiles.

```bash
python -m pip install --require-hashes -r requirements.lock
python -m pip wheel --no-deps --no-build-isolation ../.. . --wheel-dir /tmp/probity-pydantic-wheels
python -m pip install --no-deps /tmp/probity-pydantic-wheels/agent_evidence_observer-0.0.1-py3-none-any.whl /tmp/probity-pydantic-wheels/probity_pydantic_reference-0.0.1-py3-none-any.whl
python -m pip check
python -m pytest tests -q
probity-pydantic-run /tmp/probity-pydantic-fresh-packet --source-revision YOUR_SELECTED_COMMIT
```

The output directory must not exist. The seven-case v1 packet is newly generated;
there is no fallback to a committed report or earlier artifact. The workflow
runs the installed wheel outside the source directory, then installs another
wheel into a separate environment with the core cryptography and canonicalization dependencies.

```bash
python -m venv /tmp/probity-pydantic-reader
/tmp/probity-pydantic-reader/bin/python -m pip install --require-hashes -r requirements-reader.lock
/tmp/probity-pydantic-reader/bin/python -m pip install --no-deps /tmp/probity-pydantic-wheels/agent_evidence_observer-0.0.1-py3-none-any.whl /tmp/probity-pydantic-wheels/probity_pydantic_reference-0.0.1-py3-none-any.whl
/tmp/probity-pydantic-reader/bin/python -m pip check
# Inspect and select hashes/reference time as your policy before this step.
/tmp/probity-pydantic-reader/bin/probity-pydantic-read /tmp/probity-pydantic-fresh-packet --pins-file /tmp/consumer-selected-pins.json
```

Missing pins, installation errors, native producer errors outside the declared
control, verifier refusals and mismatched fresh reports fail the workflow.
The declared producer-error control passes the reference's capture requirement
while remaining an execution error in every report. This is admission of a
bounded historical record, not authorization for another dispatch.

## Provenance and limits

Framework agent/model/message sources, MIT license and package metadata are
captured from the installed distribution before the agent run. Observer and
adapter Python sources are also retained. Requirements locks account for the
selected dependency artifacts. Source hashes and public role keys authenticate
selected records; they do not prove independently witnessed execution or
complete interception of arbitrary agent effects. Signed initial/readback
snapshots establish only the selected local row and service event population.
The HTTP bearer caller's identity remains unestablished.

FunctionModel token counters estimate prompt/output usage; they are not measured
inference resources. Only the fixed local case population is claimed. This
profile uses the existing restricted ASCII JSON signing contract unchanged;
it does not introduce a Unicode authorization profile.

Fifty-five pytest cases include Hypothesis-generated native argument and actual
HTTP byte mutations. Other refusals include omitted retry messages/attempts,
hidden retry traces, swapped signed readbacks, altered native return hashes,
false successful error terminals, refusal-to-effect substitution, duplicate
native JSON names, extra artifacts, links and wrong external pins. Deep
mutation tests deliberately select a tampered manifest anew to exercise
semantic checks after hashes; a real fixed policy rejects earlier at its pin.

Official API references:
- https://pydantic.dev/docs/ai/api/models/function/
- https://pydantic.dev/docs/ai/core-concepts/retries/
- https://github.com/pydantic/pydantic-ai/tree/v1.68.0


## Upgrade and recovery decisions

The current producer emits `probity-pydantic-ai-ticket-v1` with seven fixed
cases. The reader also reconstructs the original five-case v0 packets and
returns their original reports exactly; the archived ZIP and original policy
pins remain unchanged. Select both the source bytes and the intended profile
and denominator in host policy. Rebuild and install reviewed reader wheels in a
fresh environment before replaying the original and new refusal populations.
See [failure controls](FAILURE-CONTROLS-2026-10-02.md) for the retained run.

Retry exhaustion preserves two actual retrying tool invocations. Pydantic AI
raises `UnexpectedModelBehavior` before appending a second native retry prompt;
we retain the framework's original message bytes and disclose the last retry
through the tool trace and exact exception, without inventing a message.

Failure after a committed effect is an error requiring recovery assessment.
An operator must inspect the authenticated effect before considering another
dispatch: task failure does not erase the committed revision or authorize a
repeat action. This reference raises after retaining the successful POST and
separate GET, before any native tool return. It establishes local controlled
capture, with no crash/power-loss durability or independent custody claim.
