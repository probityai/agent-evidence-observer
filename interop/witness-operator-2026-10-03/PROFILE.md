# Local operator interface

`probity-witness-operator-reference` supplies `agent-evidence-witness`, a Linux
Unix IPC server, a public-key-only `WitnessClient`, and an offline reader.
Install the retained core and operator wheels into each separate environment:

```sh
uv venv /absolute/operator --python 3.12
uv pip install --python /absolute/operator/bin/python --require-hashes -r requirements-reader.lock
uv pip install --python /absolute/operator/bin/python --no-deps /absolute/wheels/*.whl
uv pip check --python /absolute/operator/bin/python
```

The core `WitnessPort` keeps existing local witness use compatible. `Broker` and
`AuthorizedBroker` select a witness public key without inspecting a private
signer. The local adapter keeps the existing filesystem-boundary refusals.
`ProtectedDispatcher` still uses its existing local authorization witness.

## Operator setup

The operator chooses the private key file, private store, observer public key,
socket path and permitted producer UID. The socket directory must be owned by
the operator and not writable by peers. Private files have mode 0600 and the
store has mode 0700. The socket permits connections, then both ends require
Linux `SO_PEERCRED`: the server selects the producer UID and the client selects
the operator UID. This is a local OS boundary, not remote organization identity.

Key generation is an explicit exclusive command, separate from restart:

```sh
agent-evidence-witness keygen --output /absolute/private/witness.raw
```

Write the host configuration with `probity_observer.crypto.canonical` and
`Path.write_bytes`, selecting these exact fields:

```json
{"clientUid":65534,"format":"probity-witness-operator-v0","keyPath":"/absolute/private/witness.raw","observerKey":"<selected 64 lowercase hex characters>","socketPath":"/absolute/ipc/witness.sock","storePath":"/absolute/private/state","witnessKey":"<selected 64 lowercase hex characters>"}
```

Use a key pinned by the operator; do not take that selection from a submitted
packet. Supply the exact SHA-256 of the host configuration on every command.
`init` creates a new store once and writes its signed genesis head to stdout:

```sh
agent-evidence-witness init --config /absolute/host.json --config-sha256 "$config_sha" > /absolute/retained/genesis.json
agent-evidence-witness serve --config /absolute/host.json --config-sha256 "$config_sha" --retained-head /absolute/retained/head.json --retained-sha256 "$head_sha"
```

Select and retain the genesis head as the initial `head.json` before serving.
Retained heads must live outside the operator store. Restart requires existing
key, configuration and log bytes and verifies extension from the selected
retained head. There is no automatic re-key, missing-store reset or network
listener. After an actual process crash, the explicit `--remove-stale-socket`
flag removes only an operator-owned socket that refuses connections; it refuses
a live endpoint or any regular file.

`head` exports a signed current head; `export` exports full public receipt bytes
and a signed current head. Both require the same configuration and outside head
pins as `serve`. The caller must acquire and retain each accepted head through
its trusted channel before relying on rollback detection. A head copied from the
current candidate cannot expose a withheld suffix. The public-key-only client
checks the full returned receipt log and advances its last verified prefix;
`retained_head` returns a copy for separate host persistence.

### Durable consumer retention

The installed `probity_witness_operator.retention` command verifies public
receipt bytes and a signed current head before promoting the consumer's
separately retained prefix. It requires no private witness key or store.
Choose a new destination inside a consumer-owned 0700 directory and retain
that directory outside producer and witness-store authority. Pin the witness
public key through the consumer's trusted channel.

```sh
python -I -B -m probity_witness_operator.retention "$ledger" "$candidate" "$retained" --witness-key "$witness_key" --ledger-sha256 "$ledger_sha" --candidate-sha256 "$candidate_sha" --initial
```

For subsequent promotions, replace `--initial` with
`--previous-sha256 "$previous_sha"`, the digest of the already retained head.
The command checks every receipt, verifies both signed prefixes, and requires
the candidate to describe the complete selected log. A rollback, same-key
fork, wrong key, stale pin or missing retained state refuses without replacing
the prior head. A private lock serializes cooperating consumer processes.

Successful acknowledgment follows file fsync, atomic replacement and parent
directory fsync. An error before replacement preserves the old head. A failed
directory fsync may leave the new head visible without acknowledgment; inspect
its bytes and retry under its observed pin. The native lost-ack/restart controls
now use this promotion path. Heads bind receipt count and hash, not a trusted
timestamp; authorization replay uses its recorded reference time.

The request contains bounded exact canonical JSONL history bytes and their digest,
never an operator-local pathname, private key or reset choice. The operator checks
the selected observer signature, a 1-128 printable ASCII interval ID, SHA-256
authority digest, prior begin and terminal-intent rules before append. Identical
durably acknowledged retries return the original receipt; conflicting retries
refuse. History and log are limited to 256 KiB, history to 512 entries, IPC frames
to 2 MiB. The log cap uses actual serialized receipt bytes under its append lock.
This finite service stops at capacity; it does not rotate or reset the log.

## Native acceptance run

`verify_install.sh` builds immutable installed core/operator wheels, creates
separate operator, producer and reader environments, and checks all core and
operator tests. The Linux CI run executes real Unix IPC and a producer under UID
65534 with cleared groups. Actual attempted key/log reads must fail.

The five new cases are `permit`, `failed-after`, `unavailable-before`,
`unavailable-after` and `lost-ack`. They are direct native broker/process controls,
not ADK tasks, model inference or an update to the earlier ADK population.
Both completed and deliberately failed producers retain a signed authorized
effect terminal. A witness killed after a write leaves a real retained target
and registered missing terminal; the reader calls that retained target evidence,
not a signed effect terminal. A killed process before a begin reply commits one
receipt; its separately launched exact retry must produce no second receipt.

Actual installed CLI controls reject a coherent rollback, a same-count fork
signed by the operator, a missing ledger, a replacement key and a wrong peer UID.
Exact process exits and stdout/stderr are retained before interpretation. Private
keys and host runtime state are excluded from the public artifact.

The reader requires an external host policy and its digest, checks the exact
retained source/file population, verifies selected keys/requests/history/targets,
and releases only the matched permit. Repeated installed replay must be byte
identical:

```sh
/absolute/reader/bin/python -I -B -m probity_witness_operator.reader /absolute/native/packet --host-policy /absolute/native/host-policy.json --policy-sha256 "$policy_sha"
```

The source population contains Python files owned by the installed core and
operator wheels. Dependencies and interpreter source are outside that selection.
Reader JSON is unsigned; native effect packets, witness receipts, checkpoints
and ledger heads have their respective signatures.

All keys, clock choices, process launches and consumer selections in this
author-run population remain under one operator. Every native claim remains
`PEER`; different UIDs do not establish independent custody, remote identity,
complete capture, absence of transient effects, or outside adoption. A separate
operator can install this interface and select its own key/store/head retention;
an outside-custody claim needs that actual deployment and its retained records.
