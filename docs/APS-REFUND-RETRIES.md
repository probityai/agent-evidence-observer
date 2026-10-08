# Retry an approved refund without recording it twice

A refund request succeeds, but the connection drops before the caller gets the
reply. The caller tries again. Should the application record another refund or
return the result it already has?

This example shows how Observer answers that question. It records a synthetic
refund in a local SQLite database, then interrupts and retries the process. You
can inspect what happened and check the records from another installation.

## What happens on a retry?

The host identifies an operation by its tenant and signed action. A new approval
receipt does not create a new operation. Each attempt must also pass the signed
approval check and the host's own permission check.

| Situation | What the example does | Why |
| --- | --- | --- |
| Approval is reissued for the same action | Refuses the changed approval. A retry with the original approval returns the stored completion. | The operation is the same, but its selected authorization has changed. |
| The refund row commits, then the acknowledgement is lost | Returns the stored completion without another refund row. | The effect already happened. |
| The process stops after recording intent, before completion | Refuses automatic replay and reports that completion is not established. | An intent record cannot prove that the effect happened. |

The host must keep the same protected database. Starting with a new store loses
the history on which these decisions depend.

## Run the controlled example

Follow the [installation and run instructions](reference/APS-REFUND-RETRIES.md#run-the-controlled-example).
They select the exact source and dependencies, run the crash cases, and save the
records. The example uses APS approval receipts and a fixed test clock.

## Read the retained result from another installation

The reader checks the approval, the host's permission, the signed history and
the actual database row. It receives public records and keys, rather than the
producer's signing keys. It also needs a policy that the consumer has chosen to
trust; computing a hash of an unfamiliar policy does not make it trusted.

Use the [reader commands and expected results](reference/APS-REFUND-RETRIES.md#read-the-retained-result-from-another-installation)
to inspect each case. An accepted incomplete record still means completion is
not established.

## Check a real refusal

Give the reader the wrong policy hash. It must refuse, produce no accepted
result, and leave the database unchanged. The [refusal check](reference/APS-REFUND-RETRIES.md#check-a-real-refusal)
shows the exact commands and expected exit status.

## What this establishes

The result concerns a local refund-record row and controlled process crashes on
one filesystem. A completed payment-provider refund, power-loss recovery and
distributed failover need their own evidence.

The same author operates both installations. A separate installation helps check
the records, but it does not establish an independent operator or independent
custody. The fixed test clock checks the selected timing rules; freshness against
an outside clock needs a separate check.

## For developers and agents

The [technical reference](reference/APS-REFUND-RETRIES.md) holds the commands,
source pin, output fields, file map and exact evidence boundary in one place.
The [profile protocol](../interop/aps-durable-refund-2026-10-05/PROTOCOL.md) defines
the authority and storage contract. The [workflow](../.github/workflows/aps-durable-refund.yml)
runs the complete qualification and retains its public artifacts.
