# Architecture decisions

## Share native ticket capture validation

`verify_ticket_capture` validates externally selected native state, complete
signed history, retained profile/head and actual native row populations.
It receives only captured records and a selected request, issuer policy,
service public key and optional native decision digest. It performs no
storage operation and needs no private key. Its typed result separates
validated state/content from measured admissions and local effects.

`TicketStore._load` queries its native SQLite populations and delegates to
this validator, preserving its existing `(state, content)` interface. The
public consumer queries selected SQLite bytes in read-only mode and uses
the same validator. Configuration construction also shares the supported
ticket tool, literal ticket/tenant and separate-role-key constraints.
Retained heads must name the exact selected request, issuer and PEER scope.
There is no compatibility alias or second native state machine.

The shared history transition function dispatches a closed five-event
vocabulary. Its phase/type predicates are intrinsic to that finite state
algorithm. The shared history verifier traverses signatures, SQL and signed
sequence, hash chain, selected retained prefix and final phase/revocation.
Their complexity above 10 is inherent algorithmic dispatch and signed-tree
traversal. Splitting these predicates into cosmetic wrappers would obscure
the proof rather than create a separate trust boundary. State authentication,
history transitions and physical row validation are separate real boundaries.

Signed/canonical fault controls cover booleans, reordered semantic history,
unsupported events, retained claim changes and actual SQLite REAL counters.
Store and public entry points must both refuse without changing storage.
Full core tests and changed-file branch coverage qualify the extracted code.

The selected configuration helper (complexity 13) checks one closed tool,
literal identifiers, role keys and decision digest. Those independent input
predicates define one host-selection boundary. The existing state-schema
validator (27) dispatches exact phase-dependent type, time and digest
relations. The existing completion consumer (30) joins current and historical
authority, two signed records and native bytes. The existing dispatch method
(20) orchestrates two durable transactions, recovery/refusal and host fault
controls. These are intrinsic schema, cryptographic-join and transaction
algorithms. Full core qualification covers their valid and hostile behavior;
no predicate aliases or exclusions reduce their reported complexity.

## Keep APS profile trust boundaries explicit

The APS refund reader separates external source/policy selection, genuine
SDK verification and host authority, shared native capture validation,
physical outcome validation and approval reissue replay. Each stage receives
and returns explicit typed data. It delegates the native phase/history
algorithm to `verify_ticket_capture`; it does not carry a second copy.
Canonical byte comparison rejects a copied boolean value that Python equality
would otherwise equate with an integer.

The native capture runner (complexity 20) orchestrates actual restart,
concurrent-instance, three process-crash and changed-approval controls.
Its fault isolation is intrinsic process orchestration. The payload validator
(14) checks a closed refund schema; the APS verifier (13) joins selected SDK
bytes, signed action, approval and clock; the SDK digest function (12) traverses
installed runtime files and refuses symlinks or missing bytes. These are
intrinsic schema, cryptographic-join and filesystem-traversal algorithms.
They remain visible and are qualified with actual hostile and positive
controls. Predicate wrappers or aliases would obscure the same checks.

Read-only SQL connections use `contextlib.closing`. A SQLite transaction
context alone does not close its connection. This corrects the new profile's
count/readback helpers; the existing core transaction already closes its
connection in `finally` and has no corresponding lifecycle defect.
