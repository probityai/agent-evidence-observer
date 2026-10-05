# Finite HTTP ticket service

The service owns a native SQLite ticket row. `POST /dispatch` authenticates one
consumer-selected grant and exact request, persists its signed intent, and then
commits the actual ticket bytes and completed receipt in one SQLite transaction.
`GET /tickets/<tenant>/<ticket>` separately queries that row. The consumer joins
the retained POST receipt with the GET bytes, exact invocation, issuer and
service key pins, content digest, and host-observed intent/effect times.

```sh
python -m pip install -e '.[test]'
pytest -q tests/test_ticket_service.py
python examples/ticket_service_demo.py ./ticket-service-run
```

The demo runs real loopback HTTP listeners over eight new stores and retains nine
declared control outcomes: native completion, restart retry, changed-content
refusal, revocation before and after completion, persistent native bypass,
process death after intent, death inside the native transaction, and death after
commit before response. The crash cases kill the server process with `os._exit`;
they are not mock HTTP response errors. `report.json` is written only after every
declared control succeeds. Each store retains its selected public test inputs,
initial receipt and control outputs. The signing keys stay in memory.

## Native authority and recovery

The existing grant profile binds tenant, principal label, tool, literal target,
run, attempt, logical request, replacement digest, issuer and validity window.
The HTTP tool is exactly `ticket-update`; targets identify one literal ticket
under `/work/tickets/`. The effect ID is a framed, domain-separated digest of the
configuration, request and complete signed grant. Request, attempt and effect
remain separate fields. The reference uses public ASCII test payloads and its
existing restricted canonical JSON signature profile, rather than DSSE or full
RFC 8785 conformance.

SQLite `BEGIN IMMEDIATE` serializes dispatch and host-only revocation across
threads and cooperating processes. Both admission and the native mutation
recheck grant validity and revocation under that lock. Revocation can block a
pending action or a cached retry; it retains an earlier committed effect.
There is no network revocation/admin endpoint. The host clock and key custody
are explicit trust inputs; the recorded times permit recomputation of grant
validity at intent and effect, without claiming a trustworthy remote clock.

The intent commits before the effect transaction. A missing response after a
completed transaction recovers the same receipt without a second native update.
A pending intent remains incomplete and refuses automatic retry, including when
SQLite rolled back an interrupted effect transaction. Recovery retains the
logical request/effect IDs, observed native revision and unresolved outcome.
Read-back distinguishes observed absent bytes from the broader claim that no
effect occurred during an interrupted interval.

Normal opens use SQLite `mode=rw`; missing or malformed state refuses instead of
creating a new store. Initialization requires a new path. The signed event chain
and current signed state must agree with actual native bytes, tenant, ticket,
revision and effect ID. Extra rows, changed bytes/revision, deleted history and
missing state are refusal controls. A consumer-retained signed receipt supplied
as `retained_head` also rejects restoration of a coherent older store. Restoring
all local data together cannot be detected without that externally retained pin.

## Bounded evidence

This is a same-operator reference service. HTTP transport, separate role keys
and separate endpoints do not establish independent custody, remote principal
identity, containment or complete capture. A signed grant is a bearer capability;
the principal label is bound, but the HTTP caller is not authenticated as that
principal. The listener binds loopback only, serves one ticket and has no TLS,
production deployment or arbitrary agent sandbox. A host that controls the key
and database can forge or omit records. Transient bypasses restored between
snapshots and effects beyond this ticket row remain outside coverage.

Both HTTP envelopes have a 65,536-byte limit. Dispatch checks the complete
request envelope and the exact future GET envelope before it records an intent.
The GET calculation includes the hex-encoded content, escaped identity fields,
signed completion and native row fields. Digests and timestamps have fixed
widths; Ed25519 signatures have 88 base64 bytes. The size calculation uses an
unsigned placeholder and does not sign a completion before the effect.
Content that fits POST but cannot fit GET refuses without a new intent or row.
Direct dispatch applies the same request and read-back limits. HTTP clients
refuse oversized outbound requests and inbound responses; the server bounds
its actual response too. Arbitrary native content bytes travel as hex. Signed
JSON identity remains restricted to the existing ASCII profile.

Outside operation requires a separately controlled host, keys, SQLite store,
clock and retained checkpoint channel. The local run provides an executable
service target and explicit measured controls for that deployment discussion.
