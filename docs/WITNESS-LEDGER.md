# Witness ledger

`LedgerWitness` uses the broker's `checkpoint(history)` interface. It signs the
history head and appends a receipt to one log across intervals. Each receipt
names the interval, authority digest, observer key, phase, history checkpoint,
and preceding receipt hash. The first receipt requires a signed begin event
with no effects. The second requires that same begin and a terminal seal or
incomplete event. A reused interval ID or a second terminal is refused.

The log file and its `.lock` file must be writable only by the witness process.
Concurrent callers on one POSIX filesystem take the same advisory lock. A
partial receipt line stops further signing until an operator investigates it.
The witness key and log must be operated outside the agent's reach for this
separation to have any force.

Use `verify_packet` (or `verify_incomplete`) for the broker history and signed
claim. Then call `verify_ledger_receipts` with the retained witness log, both
checkpoints, a separately pinned witness key, and any earlier published log
head. The verifier checks every receipt and returns the current count and
head. Retain or publish that returned head before accepting a later log. The
full log is the consistency proof; there is no compact proof or remote API yet.

`LedgerWitness.signed_head()` exports an Ed25519-signed log count and head under
the `probity-witness-ledger-head-v0` domain. Export takes the same local lock as
receipt append. The method does not publish the head. A consumer must acquire
and retain it separately before accepting a later evidence bundle.

Call `verify_ledger_head(ledger_path, retained_head, pinned_witness_key)` first.
It authenticates the retained head and checks that the supplied log includes
that exact prefix. A correctly signed extension is permitted. A restored
prefix or a different branch fails even when all remaining receipts verify.
Using only the head supplied beside the current log cannot detect that attack.

The result reports `count`, `head`, `registeredIntervals`, and `missingTerminals`.
Each missing terminal names its begin receipt's interval ID, authority digest,
and observer key. This exposes registered intervals whose terminal receipts are
absent from the supplied log. A terminal receipt can describe either a sealed
or an incomplete history; verify the corresponding history to distinguish them.
An empty missing list does not establish complete action coverage. An interval
never registered with the witness, or a later head the consumer never acquired,
cannot be detected by this interface. Signed heads have no trusted clock and
do not establish freshness.

This is still a local PEER prototype. If the witness operator restores an old
log and withholds the published head, it can sign a different branch. A key
controlled by the observed agent can also fabricate the entire log. The next
gate is a separately operated witness service with durable state and a
published head that independent consumers actually retain.
