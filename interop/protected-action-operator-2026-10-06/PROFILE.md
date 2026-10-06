# Protected action with separate operator processes

A company permits one exact agent action. The gateway checks that approval,
writes the target, and saves the result. A reply can disappear after the write.
The operator then needs a safe answer: return a recorded completed result, or
refuse another attempt when the history leaves the outcome unresolved.

This route uses the existing protected dispatcher and native witness protocol.
The gateway receives public witness clients. It holds the observer key; the
witness key stays with a separate service. A separate consumer checks the
approval and native history, retains signed prefixes, and records one admission.

The actual substrate is one local file replacement. The companion HTTP ticket
run separately tests SQLite effects, GET read-back and transaction failures.
Its outcomes do not turn a file witness into an observer of the ticket row.

## Run the complete route

Use a job-owned Linux machine with `uv` 0.12.8 and `sudo`. The command
builds three wheels, installs five environments, checks all selected installed
Python source bytes against the frozen source, runs the suites, then starts the
role processes. It also repeats the existing native witness profile and its
separate reader. Python 3.12.14 is installed inside the fresh job root, so role
execution does not depend on access to another user's Python installation.
It selects the documented process UID and GID with `setuid` and `setgid`; it does
not change system users, groups, services or shared configuration.

```sh
bash interop/protected-action-operator-2026-10-06/verify_install.sh \
  /tmp/protected-operator-qualification
```

The output directory must be new. Its environment files are readable by the
selected identities. Keys and authoritative stores use separate job-owned
directories with mode `0700`; key files use mode `0600`. All fresh private keys
and private runtime roots are removed when the fixed run ends. Public proof
bytes and original process output remain in the output directory.

On a pool whose gate user cannot use `sudo`, the operator can use the explicit
`--root-coordinator` mode. The normal job verifies the source and suites, records
the exact administrator request, and keeps its existing heavy slot. An authorized
administrator checks that request and starts the frozen coordinator with the
recorded job marker, holder and request SHA-256. The gate waits for its actual
final status and retains its outputs before releasing the slot. This mode does
not grant privileges or change pool configuration. Source and installed-map
readbacks run as the pinned checkout owner; effect controls run as the
administrator. A changed checkout owner is refused before the controls start.

| Role | Job UID | Owns | Receives |
| --- | ---: | --- | --- |
| Issuer | 65529 | Issuer key | Exact selected action |
| Gateway | 65530 | Observer key, dispatch state, target tree | Grant, exact host policy, two public witness clients |
| Witness | 65531 | Witness key, native ledger, authorization journal | Bounded history bytes from the selected gateway UID |
| Consumer | 65533 | Retained prefixes and admission state | Public pins, external head files, captured candidate proof |
| Workload | 65534 | No role key or authoritative store | Public action request, grant and gateway endpoint |

Each role uses the listed number for both its UID and GID, with no supplementary
groups. The gate job's actual UID and GID are recorded separately; they are not
inferred from a role number or from each other.

The bootstrap administrator creates the fresh keys and can access every role.
These identities establish tested process permissions under one administrator.
They do not establish an independent human operator or independent custody.

## What the fixed run exercises

| Route | Actual effect and decision to check |
| --- | --- |
| Completed action | One target replacement; matching bytes; one consumer admission |
| Exact duplicate and restart | Saved completed result; unchanged target bytes and inode |
| A different valid grant for the same action | Refusal of the changed retry grant; unchanged target |
| Lost first workload reply | First permitted client closes without acknowledgment; target completes; separate consumer admits; restart replays without replacement |
| Wrong tenant, principal, tool, request or digest | Refusal before the target exists |
| Wrong issuer or changed content | Refusal before the target exists |
| Wrong gateway peer | Kernel UID refusal before the action API |
| Wrong witness peers | Valid history requests from the workload UID are refused; heads remain unchanged |
| Wrong consumer policy and repeated admission | Consumer refuses; no second admission |
| Authorization acknowledgment lost at phase 2 | Witness process exits after retaining the prior; no target effect |
| Authorization acknowledgment lost at phase 3 | Witness process exits after retaining completion; actual target exists but the gateway has no completed response |
| Native begin acknowledgment lost | Witness process exits after retention; no target effect |
| Native terminal acknowledgment lost | Witness process exits after retention; target exists but the completed dispatch response is missing |
| Gateway exits before or after target replacement | Real process exit around the durable write; pending retry is refused |
| Native witness unavailable | No target effect; automatic restart retry is refused |
| Missing, truncated or rolled-back stores | Existing key/configuration/head commands refuse state; no reset |
| Replacement witness key | Both services refuse the selected key mismatch |
| Signed native fork | Alternate branch signatures pass; held consumer prefix refuses the branch |
| Private key and store reads | All five identities attempt prohibited reads and retain actual permission errors |

Fault selection is host-only qualification configuration. It is absent from
workload messages. Target crash controls wrap the installed atomic replacement
and call `os._exit(74)` before or after it. Witness loss controls call
`os._exit(73)` after durable retention. The retained outputs identify these
controls; they are not natural deployment failures or a workload study.

## Reuse the runtime seam

Keep issuer, observer and witness public keys distinct. Select policy and the
exact action outside the candidate. Supply the witness ports explicitly:

```python
ports = DispatchWitnessPorts(witness_public_key, authorization_client, native_client)
dispatcher = ProtectedDispatcher(
    workspace, gateway_state, expected_request, issuer_policy, observer_signer,
    ports, retained_authorization_head=previous_authorization_checkpoint,
)
```

Both clients must use the same selected witness key. The dispatcher checks that
pair and verifies exact checkpoints before the effect. The native proof copy in
gateway state contains public signed receipts; it is not the witness's private
authoritative ledger. The existing local `SigningKey` route remains available
with its original signing bytes and same-operator scope.

The authorization service admits only the existing three journal phases:
creation, signed prior relation, and recorded completion. Its host configuration
selects the exact dispatcher configuration, initial root, signer, private store,
socket and gateway UID. Its requests carry bounded history bytes and a digest.
They cannot select a server pathname, replace a key or reset a store.

## Bootstrap, retain and restart

Bootstrap and restart are different operations. Create the witness key once
with `agent-evidence-witness keygen --output /absolute/private/key.raw`.
Construct the native host configuration using the existing
[witness operator profile](../witness-operator-2026-10-03/PROFILE.md).
Construct the authorization configuration using the fields in
[`AuthorizationConfiguration.read`](probity_protected_operator/store.py).
Select its SHA-256 outside the request channel.

```sh
agent-evidence-authorization-witness init \
  --config /absolute/authorization-config.json --config-sha256 "$CONFIG_SHA256"
agent-evidence-authorization-witness serve \
  --config /absolute/authorization-config.json --config-sha256 "$CONFIG_SHA256" \
  --retained-checkpoint /absolute/separate/authorization-head.json \
  --retained-sha256 "$RETAINED_SHA256"
```

Save the initial signed checkpoint outside the authoritative store. Start the
native service with its own retained signed ledger head. Initialize gateway
state explicitly and retain its first authorization checkpoint before the
action. The fixed run then initializes the separate consumer store before the
effect. Afterward it obtains current signed heads from the witness commands,
passes them through a separate host channel, verifies them against the captured
histories, and persists them in consumer-owned retention.

Restart requires existing keys, stores, exact configuration and retained signed
prefixes. A stale socket can be removed only through the explicit host flag,
after checking its owner, type, inode and refused connection. Missing history
or a missing key never creates a new identity or empty store.

Use the retained consumer prefix when checking a new candidate. A checkpoint
bundled only with the current candidate cannot detect an earlier rollback.
Protect admission state too: restoring it can erase its replay memory.

## Evidence and limits

`native/process-results.jsonl` records every child command, selected UID and GID,
PID, exit status and output hashes. Original stdout and stderr remain under
`native/processes/`. Exact role inputs remain under `native/inputs/`. Each case
retains its selected public policy, bundles and actual target read-back.
`cases/*/action-attempts.jsonl` separates workload exit, gateway response and
actual target observations before any result assertion. Its target reads remain
under `target-readbacks/`, including failed attempts. `wire-replies/` retains
exact received socket bytes; parsing removes only the documented LF frame byte.
`cases/*/witness-exports/` retains the full native receipt log and authorization
journal obtained from the witness's host commands, including fault states whose
acknowledgments did not reach the gateway. Store controls retain the exact public
state bytes before and during each change; private key bytes are never captured.
Consumer retention and admission snapshots establish unchanged state after a
wrong-policy refusal and refused replay. A separate fixed case loses the first
permitted reply before the client receives a completed result.
`native/report.json` is derived after the declared controls pass. Installation
records, source comparisons, wheels, suite reports and HTTP artifacts remain
outside that packet. Failed runs keep their original outputs.

The consumer copies the whole candidate before verification, checks the full
grant-to-native relation, and then uses the existing admission store. That is
artifact verification. The separate target read-back records what this local
host actually stored. The witness signs recorded histories; its signature alone
does not prove target truth, clock truth, complete capture or global consensus.

The route remains `PEER` with evidence vantage `artifact`. An outside deployment
still needs a named operator to accept the key/store responsibilities and run
an actual maintained workload. This fixed qualification records zero outside
human operators. It establishes no provider refund, payment, customer, or SLA.
