# Protected Action Kit: signed invocation binding

This first runnable increment connects a consumer-pinned issuer grant to one real brokered file replacement, a signed observation/history packet, an offline authorization reader, and persisted consumer admission. It adds to the existing observer; it does not replace its signing profile or rewrite published corpus bytes.

Run from the repository root with Python 3.12 or later:

```sh
python -m pip install -e '.[test]'
python examples/protected_action_demo.py ./protected-action-run
pytest -q
```

The output directory must be new or empty. The example generates ephemeral issuer, observer, and witness keys. It publishes their public pins and retains no private keys. All three roles belong to one operator. Supply independently obtained key pins and owner-controlled policy for any outside run; trusting keys copied from a received packet would remove the intended authentication boundary.

## What the command actually exercises

An issuer signs an exact request: run, attempt, logical request, tenant, principal, tool, literal target path, and content SHA-256. `AuthorizedBroker.write` checks the configured issuer, complete signed identity, finite validity window, exact bytes, and unchanged native authority/key configuration before calling the native broker. A changed identity or content is refused before dispatch. An identical retry returns the earlier result within the same broker instance.

The native broker records its durable intent and file replacement. Its existing prior commitment binds the native authority, and its separately keyed witness signs history heads. `AuthorizedBroker.seal` adds an observer-signed relation between the complete grant, exact invocation, native claim, and observer-reported dispatch time. `verify_authorized_packet` checks that relation, issuer policy, native signatures/history, exactly one matching recorded write, and timestamp consistency. The demo also compares the current durable workspace to the signed root.

The combined reader runs before `AdmissionStore.admit`. The consumer persists admission and rejects a second admission after reopening the state store. The native admission API alone does not authenticate the added authorization relation.

The demo retains thirteen actual refusal results: changed run, attempt, request, tenant, principal, tool, target, digest, content, issuer, signature, expired grant, and consumer replay. Runtime identity/content controls call the dispatch wrapper; issuer/signature/expiry controls call the grant reader without executing effects. The final file and recorded write population are checked independently of refusal messages. The automated tests exercise broader malformed-input, chronology, signature, state, and effect-binding cases.

## Retained bundle

`producer/` contains the exact signed grant, request, native packet plus authorization binding, hash-chain history, witness ledger, and durable file bytes. `consumer/` contains issuer policy, native admission policy, combined verification result, decision, and persisted replay state. `demo-report.json` records actual results, runtime versions, elapsed time, and unsupported claims. `manifest.json` hashes every preceding bundle file over exact octets. This author-produced manifest establishes byte binding to that retained copy; it is not an independent transparency witness.

## Boundaries of this increment

This is an experimental local reference authorization profile. It does not claim APS, MCP, A2A, DSSE, or Observed Effect conformance. Tenant/principal/tool names are exact labels chosen by the relying party; their signature does not authenticate a remote identity provider or establish the issuer's legal entitlement. The public observer restricted JSON profile supports ASCII strings and safe integers, not arbitrary Unicode/floating-point model transcripts or general RFC 8785 canonicalization.

The observer's grant-to-claim signature is produced after the effect. Its dispatch time is an observer attestation; it is not a prior witness commitment to the grant or independent proof of wall-clock truth. Native authority ordering and grant ordering are distinct. Evidence remains `PEER` / `artifact`, operated by one author.

The wrapper mediates one call path. Someone with the underlying broker or host workspace can bypass it. The offline reader refuses extra recorded writes and mismatched durable roots; it cannot establish absence of omitted or transient effects. The workspace requires one writer under the existing native broker assumptions. In-memory retry behavior and persisted consumer admission do not establish global exactly-once execution across replacement processes or external services.

The existing Linux boundary command remains a separate tested launch configuration:

```sh
agent-evidence-observer boundary-probe ./boundary-run
```

A passing native boundary probe does not automatically mean the new signed-action wrapper was used inside that sandbox. Failure to create the OS boundary is retained as an incomplete result. The kit's next integration connects the authorization wrapper to that broker socket and runs its mutations in the isolated child.

## Next adapters

Keep one exact-request/result contract and add multiple native adapters. The first native authority candidate is APS's current MCP signed-request profile; its native signing bytes, historical issuer-key rules, replay callback, and authority callback must remain explicit. Current MCP transport additionally needs header/body method/name agreement and retry/continuation identity tests. A2A requires separate task/context/message/audience/tenant mapping; a local file write is not a real A2A interoperability run.

Run multiple sandbox backends against the same controlled target and effect checks where useful. September releases of Anthropic sandbox-runtime and NVIDIA OpenShell are candidates for measured adapters. Their confinement claims and runtime policies remain separate from independently retained target observations. Source versions, actual commands, measured behavior, custody, and unsupported coverage must be recorded before comparison.

Advance checkable evaluation and retained runtime/CI history alongside these adapters. Preserve all started attempts and failed retries, hash raw input/output octets, and keep task score, authorization, effect, coverage, and consumer decision separate. A correct answer and authentic record are different findings.
