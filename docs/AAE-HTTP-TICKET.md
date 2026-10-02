# Native AAE decision joined to an HTTP ticket

`AaeTicketStore` adds an optional native decision commitment to the existing HTTP service. The action is `ticket-update` / `native-ticket`, with exact constraints for all eight `ActionRequest` fields. It is a SQLite ticket update, rather than the file-write crosswalk used by the other AAE adapter.

The service freezes canonical mandate, transaction and core bytes. It independently replays enforce-core, checks a separately selected native mandate digest, and commits the resulting `decisionDigest` in the configuration authenticated by the initial service state. That configuration is already committed when the native intent is written. Every dispatch, including a completed retry, replays the frozen inputs and requires PERMIT before reaching the existing signed grant and persistent ticket gate. A bounded forbid decision may be initialized and retained, but its HTTP dispatch is refused with the native ticket still at revision zero.

`verify_aae_ticket_result` requires the same native replay and commitment before checking the signed completion, current signed read-back, exact local grant, identity fields, grant times and native content bytes. The plain reader omits the optional commitment and refuses joined records because their configuration digest differs. It never strips the commitment to make the record fit. Existing plain service configuration and records remain unchanged.

```bash
python -m pip install -e '.[test,aae]'
pytest -q tests/test_ticket_service.py tests/test_aae_ticket.py
python examples/aae_ticket_demo.py ./aae-ticket-run --source-revision YOUR_EXACT_COMMIT
```

The demo retains twelve controls: native PERMIT with actual HTTP mutation and separate GET read-back; restart with one native revision; native DENY with no effect; changed request; revoked fresh and cached dispatch; three hard-killed server processes; wrong consumer mandate pin; rehashed native core; and plain-reader downgrade refusal. Interrupted intent or effect transactions recover as incomplete and refuse automatic replay. A crash after the effect commit recovers the completed result. Additional tests change native persistent bytes and rehash/resign a surrounding wrapper; neither bypasses the native relation or native core replay.

Each store retains its raw native decision, demonstration consumer pins, pre-effect configuration and signed initial state, HTTP input, raw results and SQLite state. The top-level packet carries per-file SHA-256 digests and implementation hashes. Demonstration pins are selected by the same operator and do not establish independent custody. `working-tree` identifies a local run without an asserted commit; CI records the exact checkout revision.

The native kernel fixtures remain pinned to [MoltyCel/aae-conformance-vectors at `531f880155ea1ce993a7ca74137b12c255d5b2ee`](https://github.com/MoltyCel/aae-conformance-vectors/tree/531f880155ea1ce993a7ca74137b12c255d5b2ee). Their source manifest, license and notice remain unchanged. The ticket crosswalk and join are Probity reference code. This covers unsigned kernel replay and an authenticated local grant/service effect. It does not run native JWS verification, authenticate the AAE issuer, establish EVM execution, prove independent custody or claim upstream adoption.

## Outside-operator acceptance

An outside operator should select the exact request and native mandate pin through its own channel, create its own grant issuer and separate service key, and own the SQLite directory and trusted UTC clock. The listener remains loopback-only. HTTP possession of a bearer grant does not establish the caller's identity. A process retaining the host key, native store or host objects remains trusted and can bypass this reference boundary.

Keep the initial signed configuration receipt separately before dispatch and retain a signed head outside the service store after each accepted state. Use that retained head when reopening the service so a whole-store rollback cannot hide a previously observed history. The store verifies the retained prefix; a checkpoint stored only beside the candidate database is not independent rollback evidence. The offline completion reader checks the currently supplied signed HTTP read-back; it does not independently inspect an operator's filesystem or infer global history freshness.

Run the public commands against a fresh directory, retain the raw packet and exact code revision, and check all twelve outcomes before accepting the local reference result. Then repeat the exact action and consumer admission using independently selected request, mandate pin, local issuer key, service key and clock. Preserve DENY, incomplete and refused outcomes with their read-back instead of converting them into successful completions. Acceptance establishes only the selected unsigned kernel decision and one native local ticket effect. An independently operated receipt should name who owned the keys, store, clock and retained checkpoint, and keep those facts separate from native issuer authentication or production deployment.
