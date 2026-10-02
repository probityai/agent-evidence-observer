# Native Inspect authority and effect join

This bounded profile connects actual Inspect ReAct tool events to one selected AAE decision and a native HTTP ticket update. It exercises Inspect 0.3.273 with controlled mock outputs, the existing unsigned native AAE kernel and the existing signed HTTP ticket profile. It is an executable same-operator reference, with no claim of model quality, authenticated AAE issuer identity, independent custody or production adoption.

Run it from a new directory after installing the optional native dependencies:

```sh
python -m pip install -e '.[test,inspect,aae]'
python interop/evaluation-contract-2026-10-01/inspect_ticket.py ./inspect-ticket-run --source-revision "$(git rev-parse HEAD)"
```

Before any framework call, `plan-before-run.json` selects every attempt, the exact action request, content, unsigned mandate and native decision, local grant, issuer and service public keys, signed initial ticket snapshot and decision-bound service configuration. It also selects the source manifest, which retains the actual implementation and relevant framework bytes, Inspect metadata, license and installed Python source digests. The local plan records prior selection; it is not an authenticated external witness. Role keys belong to this demo operator, and private keys are never placed in the retained packet.

The native registered tool sends the selected request to the actual loopback HTTP service and separately retrieves its native SQLite readback. Exact HTTP request/response bodies are retained as hex in an artifact, alongside the status and literal routes. The native tool result carries that artifact's digest, status and native revision. The offline reader reconstructs the relationship from the original Inspect call, tool event and tool reply IDs and arguments, then replays the original AAE inputs and verifies the signed local grant, service configuration, receipt and native readback. A producer summary alone cannot establish this join.

| Attempt | Native task | Selected kernel | Local effect |
| --- | --- | --- | --- |
| permit-pass | complete, pass | PERMIT | verified ticket update |
| permit-task-fail | complete, fail | PERMIT | verified ticket update |
| kernel-deny | complete, pass against the DENIED target | DENY | no ticket row in the signed local snapshot |
| pending-effect | complete, pass against the INCOMPLETE target | PERMIT | durable intent, pending effect, no automatic replay |
| model-error-after-effect | real exhausted mock-provider error, no task score | PERMIT | verified ticket update retained despite the later error |
| planned-unstarted | declared launch false, not started | PERMIT | unknown |

The pending-effect case really interrupts the service after its durable intent and before its effect transaction. Its HTTP response is a refusal and the separately signed native readback remains pending at revision zero. This establishes an incomplete local effect, not a native Inspect interruption. The test suite separately exercises a selected native log with absent completion as a mutation control; it does not describe that control as an observed framework run.

An outside reader must select the hashes in `consumer-pins.json` separately from candidate output, including the original native/HTTP artifact manifest and the historical evaluation time. A copy adjacent to the packet is a convenience for the demo operator, not independent pin selection. Keep the pre-run plan and source manifest before execution, then select the native output manifest from your retained originals. The one-hour local grants are checked at that selected historical time and at the signed dispatch/effect times; the report does not establish current authorization or current revocation.

```sh
python interop/evaluation-contract-2026-10-01/inspect_ticket.py ./inspect-ticket-run --verify --pins-file /path/to/externally-selected-pins.json
```

This reader invokes neither Inspect nor HTTP. It rejects changed native arguments or scores, mismatched raw HTTP joins, rehashed request substitution, receipts from a different attempt, altered signed state or readback content, source substitution, artifact additions, altered or additional original native logs, and symlinks anywhere in the retained packet. All six planned attempts remain in the result. A selected population missing a scheduled native record becomes start-unknown and effect-unknown rather than disappearing from the denominator. There is no aggregate score and no task-to-effect inference.

The service owns its local key, SQLite store and clock. The record's unsigned native mandate still does not authenticate an AAE issuer. The scope remains the declared task population, retained native logs and one local ticket per attempt; remote identity, native JWS verification, EVM effects, general containment, outside custody and broader capture completeness remain unresolved. Source hashes retain the precise implementation used; a revision label alone does not replace them.
