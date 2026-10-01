# Consumer admission for the PEER prototype

`verify_packet` establishes signature and internal history consistency. A
consumer decision also needs independently selected authority, interval, key,
and witness-head expectations. `AdmissionStore.admit` checks those expectations
and persists a decision before reporting success.

## Policy and storage ownership

An `AdmissionPolicy` requires the exact `interval_id`, `authority_digest`,
`observer_key`, `witness_key`, and `retained_witness_head`. Compute the authority
digest from the consumer's expected declaration with
`digest("probity-authority-v0", expected_authority)`. The declaration includes
the scope and operation, and, when present, all measured launch fields. Copying
the digest from a candidate packet does not authorize that packet. Acquire the
public keys and signed head through trusted channels outside the candidate
bundle. A bundled signed head is not rollback protection.

Keep consumer state and its sibling lock in a protected directory outside
producer-writable paths. Initialization is explicit and exclusive. A missing,
corrupt, or differently keyed store is refused; `admit` never creates a new
store implicitly. Protect the state against deletion, replacement, and rollback.
Restoring an earlier consumer state can erase its replay protection. The state
is unsigned local consumer data, not a witness statement.

## Admission order

1. Check the existing store's key pair and refuse an already admitted interval.
2. Capture private copies of packet, broker-history, and receipt-log bytes.
   Every subsequent check uses those captured bytes.
3. Run `verify_packet`. Require a complete sealed interval, consumer-pinned
   signatures, matching roots and request history, `PEER`, and no detected gap
   on the declared broker channel. Abort or unresolved histories cannot pass.
4. Compare the verified interval and full authority digest with consumer policy.
5. Authenticate the retained signed witness head and require receipt-log prefix
   continuity. Verify inclusion of the packet's begin and terminal checkpoints,
   and bind both receipt identities to the expected interval, authority, and
   observer key.
6. Require continuity from the consumer's last accepted receipt-log count/head,
   even when the policy's signed head is older.
7. Append the unsigned decision to consumer state, atomically replace the state
   file, and flush the file and directory before returning `status: admitted`.

The stable sibling lock serializes local Linux processes using this store.
The returned decision binds `intervalId`, `authorityDigest`, `claimDigest`,
`afterRoot`, terminal `historyHead`, current receipt-log `ledger`, and
`witnessScope`. The stored admission history retains the same decision. Refusals
leave prior decisions unchanged, except that a directory-flush failure after
atomic replacement may have already persisted a decision. That uncertain call
does not return success; a retry refuses the already persisted interval.

## Runnable fixture

Install the project and run the demonstration:

```sh
python -m pip install -e '.[test]'
python examples/admission_demo.py ./admission-run
```

The command creates consumer policy and its signed head before the broker
begins, mediates one actual durable file replacement, seals and verifies its
history, records one consumer admission, and refuses its replay. It retains:

| File | Purpose |
| --- | --- |
| `producer/packet.json` | Signed authority-bound claim and checkpoint receipts |
| `producer/history.jsonl` | Broker commitment, intent, effect, and seal |
| `producer/ledger.jsonl` | Witness-signed begin and terminal receipt log |
| `producer/workspace/result.txt` | Retained durable file bytes |
| `consumer/policy.json` | Consumer-selected authority, interval, key, and head fixture pins |
| `consumer/state.json` | Protected local admission history and latest accepted head |
| `consumer/decision.json` | Returned unsigned admission decision |
| `demo-report.json` | Successful first admission and exact replay refusal |

This is an author-produced same-operator fixture. Separate directories and keys
do not establish independent operation or custody. CI runs this demonstration,
the pytest/Hypothesis attack cases, and the existing live Linux boundary probe;
its retained bundles remain `evidence_vantage: artifact` and `witnessScope: PEER`.

For a new consumer store, the CLI requires explicit trusted public keys:

```sh
agent-evidence-admit init --state ./consumer-state.json \
  --observer-key "$OBSERVER_PUBLIC_KEY" --witness-key "$WITNESS_PUBLIC_KEY"
agent-evidence-admit admit --state ./consumer-state.json \
  --policy ./consumer-policy.json --packet ./producer/packet.json \
  --history ./producer/history.jsonl --ledger ./producer/ledger.jsonl
```

`consumer-policy.json` is canonical JSON with the five snake-case
`AdmissionPolicy` field names above. The CLI does not discover keys or policy
from a bundle. It exits zero only after durable success and one for refusal.

## Limits

Admission applies to the requested interval. Another registered interval with
a missing terminal remains visible to `verify_ledger_head`; this gate does not
assert completion of all intervals. It accepts no claim about unmediated
effects or changes between snapshots. It does not compare the current workspace
with the earlier observed tree, prove independent witness custody, establish
wall-clock freshness, or provide cross-host consensus. At-most-once admission
does not make a later application effect exactly-once. Independent witness
operation and separately reproduced live effects remain external requirements.
