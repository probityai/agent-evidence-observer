# Check whether an approved request matches the file write

Approval is useful only if it still applies to the operation that is dispatched.
Changing the destination, acting identity, or policy can change that decision.
A saved success response also cannot prove that a file still has the same content.

This example takes six REMORA cases and applies them to local file writes through
Probity's protected dispatcher. It preserves the original cases and states where
the local exercise covers a different kind of effect.

## What the example shows

The permitted request writes one file. Changed paths and identity labels refuse
before a write. A changed tool label also refuses, although this example has no
reachable alternate tool with which to exercise the full original case. A new
policy hash cannot silently replace the policy selected for an existing store.

The last case changes a file after a successful write. A fresh read detects the
change even though the saved response still says success. The recorded write
and that later change remain distinct.

## Run and inspect it

The [technical reference](reference/REMORA-EFFECT-BRIDGE.md) provides the pinned
vectors, commands, case-by-case scope, retained records, and verification checks.
It explains which authority inputs the consumer must select separately.

## What the result establishes

The effect is a local file replacement. The example does not run REMORA's funds
transfer dispatcher, validate an external credential, or observe a financial
ledger. One operator controls the role keys and files. A hash list stored beside
the evidence is not an independent integrity anchor.
