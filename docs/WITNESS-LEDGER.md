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

This is still a local PEER prototype. If the witness operator restores an old
log and withholds the published head, it can sign a different branch. A key
controlled by the observed agent can also fabricate the entire log. The next
gate is a separately operated witness service with durable state and a
published head that independent consumers actually retain.
