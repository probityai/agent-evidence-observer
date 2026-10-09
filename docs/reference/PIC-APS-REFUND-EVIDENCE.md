# PIC and APS refund evidence: exact reference

Start in the Observer repository root on a Linux runner with Git, Node.js 22
(including npm) and uv 0.12.8. The recipe creates its own Python 3.12 environment.

```sh
set -eu
results="$(mktemp -d)/pic-aps-refund"
bash interop/pic-aps-refund-reader-2026-10-09/verify_install.sh "$results"
```

This is the same script run by the profile's hosted workflow. The result directory
contains `restart.json`, `after-intent.json` and `approval-reissue.json`, with the
actual exit statuses and control outputs. The restart report checks the retained
completion across a retry.

<details>
<summary>Run through the installed shared pool</summary>

The pool enforces its unchanged 15 GiB free-disk floor.

```sh
set -eu
BOX_RUN_NO_BURST=1 ~/.claude/scripts/box_run.sh pic-aps-readonly --no-sync -- \
  bash interop/pic-aps-refund-reader-2026-10-09/verify_install.sh \
  /home/gate/work/pic-aps-readonly-results
```

</details>

Use a fresh result path for each run. The recipe installs hash-locked dependencies,
builds normal wheels, checks each installed source file, runs the controls, and
retains the actual output and exit status. A failed step stops it.

The three installed CLI calls print reports and exit **3**. That means native
evidence was checked but combined admission is not established. The recipe checks
that exact result. Invalid evidence exits **2**, with empty stdout and a refusal
on stderr. There is no command here that signs or dispatches a refund.

## Native source and bytes

The [PIC refund example](https://github.com/pic-standard/pic-standard/tree/236ecb81ad1cf2a44d8b3599734cccc334b12e95/examples/refund-approval)
merged in PIC #172. Its actual Python SDK is commit
`330fdd817ef81d43461ea1787939e0d1cc87d589`, not the different `v0.9.0` tag.
The package reports version `0.9.0`; the reader checks every native package file
against that exact source. It uses the real `verify_proposal` pipeline, strict
trust, canonical inline `PIC-ATT/1.0` evidence, and the selected public keyring.

The original proposal, merchant decision, keyring, public key and constraints are
retained byte-for-byte. No private test key is copied. Cryptography `49.0.0` matches
the PIC example's pin and satisfies both native package ranges. This is a new
reader environment. It does not change the earlier APS environment pinned to
`46.0.7` or replay the author's whole PIC test suite.

PIC's `args_digest` and `claims_digest` use `PIC-CJSON/1.0`. Its `intent_digest`
hashes the exact UTF-8 intent string. The claim's JSON string carries
`decision_id` and `approval_ref`; PIC binds its bytes, while this refund profile
checks those two fields. The profile permits only `refund`, impact `money`, and
the closed `{payment_id, amount_minor, currency}` tuple. The amount is a positive
safe JSON integer, with booleans refused. The selected currency is `EUR`.

The [APS candidate](https://github.com/agent-passport-system/agent-passport-system/tree/c31d94aad86713ae9b2e4cbc811deeab4b5d91ed/examples/interop/refund-exact-approval)
uses the installed native SDK `7.2.1`. The existing Observer reader checks its
raw signed receipt and action, native payload/action references, selected keys,
recorded clocks, signed history, retained SQLite state and completion.
The three original captures come from Observer's qualified source
`89ebae615ccf47b8de1fad92db30805d6d8a8278`; the current reader is unchanged from
merged source `00e92b0a3fcf53376ebafc6cc9b4abde7e9fdc8c`.
Their fixture clock is `2026-10-05T20:00:00.000Z`, not current admission.

## What the report separates

| Record | What is checked |
| --- | --- |
| PIC decision | Signed claim text with `decision-001` and `approval-001` |
| APS approval | Genuine verified native `receipt_id`, `action_ref`, and `payload_ref` |
| Local operation | Host tenant plus exact signed APS `action_ref`, including its nonce |
| Local request attempt | Retained request field, separate from the operation identity |
| Local effect | Original signed SQLite observation; interruption stays incomplete |

The matching refund fields do not equate PIC and APS hashes. In these captures,
PIC's `args_digest` even differs from APS's domain-selected `payload_ref`.
APS's `decision_ref` is retained separately. Its merchant-decision preimage is not
supplied here. Neither its digest nor `action_type` silently becomes a merchant
decision or a shared tool-string commitment.

## Inputs for the proposed combined case

The [public scope discussion](https://github.com/aeoess/agent-governance-vocabulary/issues/193#issuecomment-6074324617)
calls for native decision evidence containing the PIC decision ID, a PIC approval
reference that matches the verified APS receipt, and an authenticated durable
decision-to-operation mapping. Approval reissue must preserve the original
evidence binding. Shared refund tool binding remains a separate check.

The captured thread does not supply a runnable public Conduit fixture or its
authenticated handoff. That input must distinguish `admission_ref` from
`aps_evidence_ref`, with operation, attempt and observed effect records and a
public reader for their binding. The private baseline and reported draft tests
do not establish that combined run.

The reader exposes these missing inputs. It verifies existing evidence only.
No payment rail, signer authority, decision mapping, provider access, independent
operator or independent custody is created or inferred.
