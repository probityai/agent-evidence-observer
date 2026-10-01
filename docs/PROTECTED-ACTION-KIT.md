# Protected Action Kit

The kit checks a signed grant before writing a file, records the write, and lets a consumer verify both before accepting the result. It uses the existing observer and signing format without changing published corpus files.

Run these commands from the repository root with Python 3.12 or later:

```sh
python -m pip install -e '.[test]'
python examples/protected_action_demo.py ./protected-action-run
pytest -q
```

The output directory must be new or empty. The example creates issuer, observer, and witness keys in memory and saves only their public keys. One operator controls all three. For an outside run, the consumer needs independently obtained key pins and its own policy; keys included in a received packet cannot authenticate that packet on their own.

## How it works

An issuer signs the run, attempt, request, tenant, principal, tool, target path, and content SHA-256. Before dispatch, `AuthorizedBroker.write` checks the issuer key, signed request, validity window and duration limit, file bytes, and broker authority and keys. Changed requests or content are refused. An identical retry returns the earlier result while the same broker instance is running.

The broker records a durable write intent, replaces the file, and records the result. Its prior commitment binds the declared authority; a witness using another key signs the history heads. At sealing, the observer signs the link between the grant, invocation, claim, and reported dispatch time. `verify_authorized_packet` checks that link, the issuer policy, signatures, history, timestamp ordering, and one matching recorded write. The demo also compares the final workspace with the signed tree root.

This combined verification runs before `AdmissionStore.admit`. The consumer saves its decision and refuses a second admission after reopening the store. Calling the native admission API alone does not check the added authorization binding.

The demo records thirteen refusal cases: changed run, attempt, request, tenant, principal, tool, target, digest, content, issuer, signature, expired grant, and consumer replay. Request and content changes exercise the dispatch wrapper. Issuer, signature, and expiry cases exercise the grant reader without applying a write. The demo checks the final file and recorded write count as well as the refusal messages. Tests cover additional malformed inputs, timestamps, signatures, state, and mismatched effects.

## Saved files

`producer/` holds the signed grant, request, packet, authorization binding, history, witness ledger, and file contents. `consumer/` holds the grant and admission policies, verification result, decision, and replay state. `demo-report.json` records results, runtime versions, elapsed time, and limitations. `manifest.json` contains SHA-256 hashes of all preceding bundle files. These hashes identify the saved bytes; the manifest is not an independent witness.

## Limits

The kit is a local authorization experiment, not an APS, MCP, A2A, DSSE, or Observed Effect implementation. Tenant, principal, and tool names are labels chosen by the consumer. Signing those labels does not authenticate an external identity provider or establish the issuer's entitlement to authorize the action. The observer's JSON format accepts ASCII strings and safe integers, not arbitrary Unicode, floating-point transcripts, or full RFC 8785 canonicalization.

The grant-to-claim signature is made after the write. The observer reports the dispatch time, but no outside witness commits to the grant before the effect or independently checks the clock. The broker's prior authority commitment does not supply that missing grant commitment. Records remain `PEER` / `artifact`, under one operator.

The wrapper controls one path into the broker. A holder of the underlying broker or host workspace can bypass it. Verification rejects extra recorded writes and mismatched final roots, but cannot rule out omitted effects or temporary changes undone between observations. The workspace still requires one writer. In-memory retries and saved consumer admission do not provide global exactly-once execution across restarted processes or external services.

The Linux boundary probe is a separate command:

```sh
agent-evidence-observer boundary-probe ./boundary-run
```

Passing that probe does not mean the signed-action wrapper ran inside its sandbox. A failed isolation launch produces an incomplete result. The next integration will connect authorization to the broker socket and test altered requests from the isolated child.

## Planned integrations

APS's MCP signed-request profile is the first planned authority adapter. It will preserve APS signing bytes, historical key rules, replay checks, and authority callbacks. The MCP adapter also needs method and tool-name agreement between headers and bodies, plus retry and continuation identity checks. A2A will have its own task, context, message, audience, and tenant mapping. None of these native protocol paths has run in this kit yet.

Sandbox comparisons will use the same controlled target and effect checks under Anthropic sandbox-runtime and NVIDIA OpenShell. Reports will record source versions, commands, policies, measured behavior, and observation gaps. Sandbox enforcement and independently retained target observations are separate parts of the comparison.

Evaluation and CI/runtime history adapters will retain every started attempt, including failed retries, and hash raw inputs and outputs. Task score, authorization, effect, coverage, and consumer acceptance will remain separate results: a correct answer is not proof of an authorized action.
