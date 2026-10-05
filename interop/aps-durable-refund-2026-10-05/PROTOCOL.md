# Local consumer protocol

The installed Python boundary preserves raw action and receipt JSON for the
SDK's serialized entry points. It rejects duplicate decoded payload member
names before parsing can discard them. The closed payload has a literal
payment identifier, a positive safe integer amount in minor units and a
three-letter currency. Equivalent JSON numbers such as 4000, 4000.0 and 4e3
retain the SDK's RFC 8785 meaning.

The host selects the boundary identity, exact signing key and key ID, acting
agent, exact requested payload, tenant, local grant, service key, protected
state directory, clock and source bytes. The SDK checks the receipt signature
and stage, action construction and payload digest. The consumer joins the
receipt subject to the acting agent and the request to the local effect.
Only a permit with no constraints is supported. The local time rule is
issuance <= dispatch time < expiry; exact expiry is refused. Native validity
is checked again after the durable intent and before the local effect.

Host tenant plus the exact APS action reference selects one logical operation
and its store filename. The action reference includes the signed nonce. An
approval receipt ID is authorization evidence. Reissuing approval for the same
action cannot create another operation; a changed frozen authorization refuses
the retained configuration. A separately approved different action has its own
operation. The host must retain that store in the same protected root. New roots, lost
state, host code changes and host compromise do not establish replay
protection. The APS receipt does not encode a tenant; tenant selection and
the separate signed local grant are consumer authority, not an APS claim.
Bearer evidence does not authenticate an HTTP caller. Key rotation,
revocation and real delegation authority require their own host policy and
are not provided by this synthetic fixture.

SQLite serializes fresh processes. Its signed intent precedes the local
row, and the row and signed completion commit in one transaction. Retrying
that completed logical operation returns the original result. It creates
no second intent or local row. An interrupted pending operation refuses
automatic replay; explicit recovery records an incomplete terminal. These
are process-crash controls on one host filesystem. They do not test power
loss, filesystem corruption, a remote provider or distributed failover.
The fixture uses the fixed control clock `2026-10-05T20:00:00Z`. This tests
the stated time boundaries, not freshness against an outside clock.

The commitment uses SDK-verified receipt ID, action and payload references,
selected identity/key/time fields, tenant and verifier/runtime byte pins.
Outer host JSON member order and equivalent numeric spellings do not
change logical identity. Retained host-policy hashes separately select the
exact raw capture bytes. The installed SDK inventory includes runtime files
in all npm dependencies; npm's metadata cache and CLI symlink directory are
excluded because this program invokes a selected Node binary and imports
library files directly. The host must protect code and state during use.

The fresh reader receives only public keys, signed records, captured SQLite
bytes and separately selected policy/member hashes. It replays the installed
SDK, checks the exact native/local join, signed event chain, admission count
and actual row. The reader validates these boundaries in order: external
policy and member selection; native approval and host intent binding;
signed SQLite state and readback through the shared public ticket capture
validator; the full native event-phase chain; measured local
effect and installed completion verification; optional reissued-approval
refusal. Each stage returns an explicit typed result to the next stage.
The selected expectation has exactly two JSON integer fields. Booleans,
floating counts and extra effect categories refuse before native verification.
The store and public reader use the same validator for selected ticket
configuration, separate issuer/service keys, signed state types, ordered
phase and revocation transitions, retained profile/head, SQL row types and
actual content. A valid signature does not excuse a malformed phase or a
boolean counter. Receipt copies compare canonical bytes rather than Python
boolean/integer equality. Owned read-only SQLite connections close after
capture selection. No private signing key is needed for public consumption.
Incomplete captures remain incomplete. Producer and reader
are operated under the same author mandate. Different wheels, processes
and keys do not establish independence or custody.

The originating scope remains in [vocabulary issue 193](https://github.com/aeoess/agent-governance-vocabulary/issues/193).
This artifact makes no joint adapter or provider commitment. The upstream
SDK and candidate are Apache-2.0 work by Tymofii Pidlisnyi; the SDK is used
unchanged. No archived storage adapter or SDK compatibility alias is used.
