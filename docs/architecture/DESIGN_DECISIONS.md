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

## Authorize inside each native transaction

`TicketStore._authorize` receives the already sampled intent/effect time and
returns the authenticated `AuthorizedAction`. The default checks the local
grant. The APS override checks the genuine installed native approval and
frozen join at that same instant, then checks the local grant. Fault callbacks
remain separate from authorization. Waiting for the second transaction cannot
reuse an earlier native approval check.

Shared capture validation requires the selected payload digest and deterministic
effect identity. At a retained head's event count, every retained native state
field must match the state reconstructed from the validated history prefix.
Matching signatures or prefix hashes alone do not establish those relations.
The public APS consumer checks current local and native authority plus genuine
SDK replay at each retained intent/effect observation.


## Select an observation precision explicitly

The public `validate_utc_time` function validates an aware UTC observation
against a closed seconds or milliseconds selection. It preserves the input
and rejects finer observations. Grant issuance and expiry remain canonical
whole seconds. `verify_grant(reference_precision="milliseconds")` changes
only the observation contract.

The ticket store and both public validators accept an explicit
`time_precision`. The default seconds configuration and timestamp bytes stay
unchanged. The selected milliseconds configuration includes
`timePrecision: "milliseconds"`, and its exact timestamps use `.sssZ`.
That declaration is part of the signed configuration, including ready states
that have no timestamps. There is no timestamp inference or alternate input
spelling. The new APS profile selects milliseconds so a fractional approval
window remains checkable at both retained transaction times. Its default
clock samples wall time at that resolution; an injected finer clock refuses.

## Dispatch through selected public witness ports

The existing dispatcher owns grant validation, prior retention, target execution,
native receipt capture and completion. A pair of typed public ports supplies the
authorization checkpoint and native receipt operations. The local signer route
constructs local ports and uses that same dispatcher. Both ports must match the
explicit selected witness key before an effect. There is no second orchestration,
inferred identity or private witness path in a remote client.

The generic broker now verifies each returned checkpoint against the exact
submitted history and its selected key. It also refuses a changed port key before
an active write. A valid transport signature does not replace that binding check.
The dispatcher retains a verified public receipt mirror before target execution;
the witness keeps its private authoritative store.

The new authorization configuration and journal validators have intrinsic closed
schema and signed-relation predicates. They bind the selected action, issuer,
observer, witness, prior native interval and recorded completion. Complexity above
10 in those validators is accepted for that finite cryptographic join. The worker's
consumer operation selects explicit initialization, retention, admission and fork
controls; its closed type dispatch is intrinsic. The native harness and held-slot
administrator coordinator isolate failures and retain actual child outputs across
the declared service cases. Their complexity above 10 is process orchestration and
fault isolation, not a second runtime policy. The installed qualification records
their unmodified complexity values. No predicate wrappers or aliases hide them.

Bootstrap is explicit. Restart uses an existing key, authoritative store and
separately retained signed prefix. Missing stores never reset history. The fixed
different-UID run tests private reads, peer checks, duplicate effects and real
process failures under one administrator. It establishes no independent human
operator, customer workload or independent custody.

## Verify complete native source before starting children

The CrewAI bootstrap's `launch` (complexity 17) checks selected Observer
metadata, all runtime Python files, dependency locks and the complete native
source inventory before it runs native cases.
It then coordinates the producer, SDK-free reader and repeated consumer.
The branches are intrinsic source traversal and process orchestration, with
distinct refusal reasons at each selected boundary.

Its `child` helper (complexity 16) retains actual exit, timeout, stdout and
stderr before reporting a failure. Its nested diagnostic traversal preserves
the native publication records that explain a failed reader. This is process
fault isolation. The finite native gate and hostile reader controls exercise
these boundaries; the reported complexity remains visible.
