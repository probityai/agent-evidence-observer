# Protected socket dispatch

The protected socket joins signed exact-action grants to the Linux boundary
probe. The child can send an invocation to one host-owned socket. It cannot
call the native broker directly, initialize or recover the store, select a
clock, access the target tree, or read signing keys through this interface.

The [separate operator route](../interop/protected-action-operator-2026-10-06/PROFILE.md)
uses this same dispatcher with public authorization and native witness ports.
Both ports must match the selected witness key. Its witness signer and stores
run outside the gateway; its consumer retains public heads in separate storage.

Run with Python 3.12 or later on a Linux host that permits bubblewrap:

```sh
python -m pip install -e '.[test]'
python examples/protected_dispatch_demo.py ./protected-run
pytest -q
```

The output directory must be empty. The example exits with status 2 and keeps
an incomplete report if the operating system denies socket creation or
isolation, the child times out, a check fails, or consumer verification fails.
Do not count an incomplete run as a passing boundary result. Tests that replace
the child exercise host components only; they are not evidence of isolation.

## Before the effect

The host selects one exact run, attempt, request, tenant, principal, tool,
target path and content digest. It pins the issuer, observer and witness keys,
and commits the concrete launch-policy digest to the protected store.

The socket accepts only a canonical `request`, signed `grant` and lowercase
hexadecimal `contentHex`. It limits each connection to one 65,536-byte request
and a two-second read deadline. Unknown fields, legacy native write requests,
caller timestamps, altered identities, changed bytes, wrong issuers, invalid
signatures and invalid validity windows are refused before any target write.

After authenticating a request with the host clock, the dispatcher begins the
native interval. It signs a relation between the exact grant, request,
configuration, native prior commitment and native witness checkpoint. A
separate-key local witness retains the authorization journal head. That
checkpoint and a pending state are flushed before the native write path runs.
Authorization and clock ordering are checked again immediately before dispatch.

The native broker still writes its durable intent, atomically replaces the
target, flushes it and records the effect. It seals the existing native packet
without changing the native signing format. The completed authorization journal
then binds the packet and result; its final checkpoint and completed response
are durably saved before success returns.

## Restart and recovery

One protected store permits one exact action. A completed retry verifies the
same grant, current validity, request, role keys, authorization history, prior
checkpoint, native packet, native history, witness ledger and current target
tree. It returns the saved result without another target write, including after
the response was lost or the service was reopened.

A crash after preparation but before durable completion does not trigger an
automatic retry. A pending intent, incomplete state/journal pair, missing
witness or restored prefix is refused. The target may already have changed.
The original intent, history and bytes remain available for operator review;
the interface provides no override that guesses the effect away. Starting a
new interval requires a separate, explicit decision about the unresolved effect.

Local locks serialize cooperating writers using the same host-owned directory.
Protect the state, lock and witness directories from deletion, replacement and
rollback. To detect a restoration of every local file together, retain a signed
authorization checkpoint outside that storage and supply it when reopening or
verifying. A head copied from the current bundle cannot detect a withheld suffix.

## The measured workload

The fixed child runs 26 checks: four operating-system bypass attempts; all eight
action identity substitutions; malformed, oversized, duplicate-member and
missing-newline inputs; direct native-broker and caller-clock attempts; wrong
issuer, wrong signature, expired and future grants; changed content; a lost
response followed by replay; another replay; and a changed retry.

A passing host gate also requires one matching durable target write, verified
prior authorization and native evidence, restart replay and saved consumer
admission. The bundle retains exact launch inputs and policy, source digests,
raw stdout/stderr, both histories, witness records, native packet, consumer
checks and a signed report. The manifest identifies saved bytes; it is not a
separate witness.

## What this establishes

This is one measured Linux namespace launch and one finite file replacement,
under one operator. Records remain `PEER` / `artifact`. Separate role keys do
not establish independent custody or independent clock truth. The observed
tree still requires one writer and uses call-boundary snapshots, not continuous
capture of transient, omitted or host-originated effects. The host can bypass
the service; the isolated child workload tests one launch configuration, not
every possible malicious program or a compromised kernel.

Durable cached responses and conservative ambiguity handling are bounded local
recovery controls. They do not establish global exactly-once execution,
cross-host consensus, exactly-once remote side effects, or automatic recovery
of an ambiguous write. Labels such as tenant and principal are selected by the
consumer; this profile does not authenticate an external identity provider.
The socket checks signed principal and tenant labels for the configured child;
it does not prove possession of a principal's key or authenticate a remote
caller. A copied valid grant can invoke the same exact action while it remains
valid, but cannot select a different action or trigger another completed write.
The [APS refund route](APS-REFUND-RETRIES.md) checks native approvals around a
local SQLite operation. The [A2A SDK route](../interop/a2a-native-2026-10-02/README.md)
retains native protocol exchanges. Each route declares its own action, authority
and evidence boundary.
