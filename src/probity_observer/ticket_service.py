"""Finite HTTP-owned ticket state with exact authorization and durable recovery.

The server owns a SQLite ticket, not a file-write adapter. An intent commits
before mutation; ticket and receipt commit atomically afterwards. Read-back
queries the native row on a separate HTTP endpoint. This is same-operator
reference evidence, with no claim of remote identity or independent custody.
"""

from __future__ import annotations

import base64
import hashlib
import sqlite3
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from .authorization import ActionRequest, GrantPolicy, utc_clock, verify_grant
from .crypto import SigningKey, VerificationError, canonical, digest, strict_loads, verify_signature

DOMAIN = "probity-http-ticket-v0"
MAX_BODY = 65536
STATE_FIELDS = frozenset({"format", "configuration", "phase", "revision", "contentDigest", "effectId", "grantDigest", "revoked", "eventCount", "eventHead", "intentTime", "effectTime"})
RECEIPT_FIELDS = STATE_FIELDS | {"request", "authorityKey", "witnessScope", "coverage"}
READBACK_FIELDS = frozenset({"tenantId", "ticketId", "contentHex", "revision", "effectId", "receipt"})


def _timestamp(value: datetime) -> str:
    """Keep host reference times in the grant profile's exact UTC representation."""
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _time(value: Any) -> datetime:
    """Refuse noncanonical timestamps before checking historical authorization."""
    from datetime import timezone
    if not isinstance(value, str):
        raise VerificationError("ticket reference time is malformed")
    try:
        result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise VerificationError("ticket reference time is malformed") from error
    if _timestamp(result) != value:
        raise VerificationError("ticket reference time is noncanonical")
    return result


def _hex(value: Any) -> bool:
    """Require a literal lowercase SHA-256 digest, without integer coercion."""
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _state_schema(state: Any, *, receipt: bool = False) -> None:
    """Apply exact schemas and phase-dependent native relations to signed state."""
    fields = RECEIPT_FIELDS if receipt else STATE_FIELDS
    if not isinstance(state, dict) or set(state) != fields:
        raise VerificationError("ticket signed state fields differ")
    if state["format"] != DOMAIN or not _hex(state["configuration"]) or not _hex(state["eventHead"]):
        raise VerificationError("ticket signed state domain or digest differs")
    if type(state["revision"]) is not int or state["revision"] not in {0, 1} or type(state["eventCount"]) is not int or not 1 <= state["eventCount"] <= 5 or type(state["revoked"]) is not bool:
        raise VerificationError("ticket signed state counters or revocation differ")
    phase = state["phase"]
    if not isinstance(phase, str) or phase not in {"ready", "pending", "completed", "incomplete"}:
        raise VerificationError("ticket signed state phase differs")
    if phase == "ready":
        if state["revision"] != 0 or any(state[name] is not None for name in ("contentDigest", "effectId", "grantDigest", "intentTime", "effectTime")):
            raise VerificationError("ticket ready state carries an effect")
        return
    if not _hex(state["effectId"]) or not _hex(state["grantDigest"]):
        raise VerificationError("ticket intent identity differs")
    intent_time = _time(state["intentTime"])
    if phase == "completed":
        if state["revision"] != 1 or not _hex(state["contentDigest"]) or _time(state["effectTime"]) < intent_time:
            raise VerificationError("ticket completed native relation differs")
    elif state["revision"] != 0 or state["contentDigest"] is not None or state["effectTime"] is not None:
        raise VerificationError("ticket incomplete state claims a completed effect")


def _signed(payload: dict[str, Any], key: SigningKey) -> dict[str, Any]:
    """Sign native service state under a separately selected service key."""
    return {"payload": payload, "keyid": key.public_hex, "signature": key.sign(DOMAIN, payload)}


def _checked(record: Any, public_key: str) -> dict[str, Any]:
    """Authenticate a fixed envelope without accepting its own key as policy."""
    if not isinstance(record, dict) or set(record) != {"payload", "keyid", "signature"}:
        raise VerificationError("ticket envelope fields differ")
    if not _hex(public_key) or record["keyid"] != public_key or not isinstance(record["payload"], dict) or not isinstance(record["signature"], str):
        raise VerificationError("ticket key differs from consumer pin")
    verify_signature(public_key, DOMAIN, record["payload"], record["signature"])
    return record["payload"]


class TicketStore:
    """Own one exact ticket update, native persistence and monotonic history.

    ``request.tool_id`` must be ``ticket-update`` and its literal target must
    identify one ticket under ``/work/tickets/``. Tenant, principal, run,
    attempt, request, content and issuer are bound by the existing signed grant.
    The service key and SQLite directory belong to the host. A bearer grant is
    not proof of the HTTP caller's identity. A trusted host clock and local
    SQLite filesystem are required. The optional crash hook is host-only.
    An optional decision digest extends the committed configuration; the native
    decision profile must replay its own inputs before calling this base gate.
    """

    def __init__(
        self, path: Path, request: ActionRequest, policy: GrantPolicy,
        key: SigningKey, *, clock: Callable[[], datetime] = utc_clock,
        crash_hook: Callable[[str], None] | None = None,
        retained_head: dict[str, Any] | None = None,
        decision_digest: str | None = None,
    ) -> None:
        self.path, self.request, self.policy, self.key = path, request, policy, key
        self.clock, self.crash_hook = clock, crash_hook
        self.retained_head = retained_head
        if request.tool_id != "ticket-update" or not request.target_path.startswith("/work/tickets/"):
            raise VerificationError("ticket action or target is unsupported")
        self.ticket_id = request.target_path.removeprefix("/work/tickets/")
        safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
        if not self.ticket_id or any(c not in safe for c in self.ticket_id + request.tenant_id):
            raise VerificationError("ticket and tenant must use literal URL-safe identifiers")
        if key.public_hex == policy.issuer_key:
            raise VerificationError("service and issuer keys must differ")
        self.configuration = {"request": asdict(request), "policy": asdict(policy), "serviceKey": key.public_hex}
        if decision_digest is not None:
            if not _hex(decision_digest):
                raise VerificationError("ticket decision commitment differs")
            self.configuration["decisionDigest"] = decision_digest
        self.configuration_digest = digest(DOMAIN + "-configuration", self.configuration)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialize threads and processes with SQLite's durable write lock."""
        try:
            connection = sqlite3.connect(self.path.resolve().as_uri() + "?mode=rw", uri=True, timeout=5, isolation_level=None)
        except sqlite3.Error as error:
            raise VerificationError("ticket store is missing or unavailable") from error
        try:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except sqlite3.Error as error:
            connection.rollback()
            raise VerificationError("ticket native store is malformed or unavailable") from error
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> dict[str, Any]:
        """Create a fresh store once; never reset a missing restart state."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive creation keeps a pre-existing or interrupted store distinct.
        with self.path.open("xb"):
            pass
        self.path.chmod(0o600)
        with self._transaction() as db:
            db.execute("CREATE TABLE state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), record BLOB NOT NULL)")
            db.execute("CREATE TABLE tickets (tenant TEXT, ticket TEXT, content BLOB NOT NULL, revision INTEGER NOT NULL, effect TEXT NOT NULL, PRIMARY KEY(tenant,ticket))")
            db.execute("CREATE TABLE events (sequence INTEGER PRIMARY KEY, record BLOB NOT NULL)")
            state = {"format": DOMAIN, "configuration": self.configuration_digest, "phase": "ready", "revision": 0, "contentDigest": None, "effectId": None, "grantDigest": None, "revoked": False, "eventCount": 0, "eventHead": "0" * 64, "intentTime": None, "effectTime": None}
            self._event(db, state, {"kind": "initialize", "configuration": self.configuration_digest})
            db.execute("INSERT INTO state VALUES(1,?)", (canonical(_signed(state, self.key)),))
        return self.readback()

    def _event(self, db: sqlite3.Connection, state: dict[str, Any], event: dict[str, Any]) -> None:
        """Append a service-signed event inside the current native transaction."""
        body = {"sequence": state["eventCount"] + 1, "previous": state["eventHead"], "event": event}
        body["hash"] = digest(DOMAIN + "-event", body)
        db.execute("INSERT INTO events VALUES(?,?)", (body["sequence"], canonical(_signed(body, self.key))))
        state["eventCount"], state["eventHead"] = body["sequence"], body["hash"]

    def _save(self, db: sqlite3.Connection, state: dict[str, Any]) -> None:
        """Commit the state signature in the same transaction as native rows."""
        db.execute("UPDATE state SET record=? WHERE singleton=1", (canonical(_signed(state, self.key)),))

    def _load(self, db: sqlite3.Connection) -> tuple[dict[str, Any], bytes | None]:
        """Recheck configuration, history prefix and actual native ticket row."""
        row = db.execute("SELECT record FROM state WHERE singleton=1").fetchone()
        if row is None:
            raise VerificationError("ticket state is missing")
        state = _checked(strict_loads(row[0]), self.key.public_hex)
        _state_schema(state)
        if state["format"] != DOMAIN or state["configuration"] != self.configuration_digest:
            raise VerificationError("ticket configuration differs on restart")
        rows = db.execute("SELECT sequence,record FROM events ORDER BY sequence").fetchall()
        head = "0" * 64
        phase, revoked = "ready", False
        intent = None
        retained = None
        if self.retained_head is not None:
            retained = _checked(self.retained_head, self.key.public_hex)
            _state_schema(retained, receipt=True)
            if retained["configuration"] != self.configuration_digest:
                raise VerificationError("retained ticket head configuration differs")
        for number, (sequence, raw) in enumerate(rows, 1):
            event = _checked(strict_loads(raw), self.key.public_hex)
            if set(event) != {"sequence", "previous", "event", "hash"} or type(event["sequence"]) is not int:
                raise VerificationError("ticket event schema differs")
            body = {name: event[name] for name in ("sequence", "previous", "event")}
            if sequence != number or event["sequence"] != number or event["previous"] != head or event["hash"] != digest(DOMAIN + "-event", body):
                raise VerificationError("ticket history differs")
            carried = event["event"]
            if not isinstance(carried, dict) or not isinstance(carried.get("kind"), str):
                raise VerificationError("ticket event body differs")
            kind = carried["kind"]
            if kind == "initialize":
                if number != 1 or carried != {"kind": "initialize", "configuration": self.configuration_digest}:
                    raise VerificationError("ticket initialization history differs")
            elif number == 1:
                raise VerificationError("ticket history lacks initial configuration")
            elif kind == "intent":
                expected = {"kind": "intent", "request": asdict(self.request), "grantDigest": state["grantDigest"], "effectId": state["effectId"], "beforeRevision": 0, "intentTime": state["intentTime"]}
                if phase != "ready" or revoked or carried != expected or type(carried.get("beforeRevision")) is not int:
                    raise VerificationError("ticket intent history differs")
                phase, intent = "pending", carried
            elif kind == "effect":
                expected = {"kind": "effect", "effectId": state["effectId"], "revision": 1, "contentDigest": self.request.content_sha256, "effectTime": state["effectTime"], "grantDigest": state["grantDigest"]}
                if phase != "pending" or revoked or intent is None or carried != expected or type(carried.get("revision")) is not int:
                    raise VerificationError("ticket native effect history differs")
                phase = "completed"
            elif kind == "revoke":
                if revoked or carried != {"kind": "revoke", "authorityKey": self.policy.issuer_key}:
                    raise VerificationError("ticket revocation history differs")
                revoked = True
            elif kind == "incomplete":
                expected = {"kind": "incomplete", "effectId": state["effectId"], "requestId": self.request.request_id, "outcome": "not-established-after-interruption"}
                if phase != "pending" or carried != expected:
                    raise VerificationError("ticket interruption history differs")
                phase = "incomplete"
            else:
                raise VerificationError("ticket history has unsupported event")
            head = event["hash"]
            if retained is not None and number == retained["eventCount"] and head != retained["eventHead"]:
                raise VerificationError("ticket history changed retained prefix")
        if len(rows) != state["eventCount"] or head != state["eventHead"]:
            raise VerificationError("ticket history is incomplete")
        if phase != state["phase"] or revoked != state["revoked"]:
            raise VerificationError("ticket terminal state differs from native history")
        if retained is not None and retained["eventCount"] > len(rows):
            raise VerificationError("ticket history predates retained head")
        tickets = db.execute("SELECT tenant,ticket,content,revision,effect FROM tickets").fetchall()
        if state["revision"] == 0:
            if tickets:
                raise VerificationError("unrecorded ticket bypass detected")
            return state, None
        if len(tickets) != 1:
            raise VerificationError("native ticket population differs")
        tenant, ticket, content, revision, effect = tickets[0]
        if not isinstance(content, bytes) or type(revision) is not int:
            raise VerificationError("native ticket row types differ")
        if (tenant, ticket, revision, effect) != (self.request.tenant_id, self.ticket_id, state["revision"], state["effectId"]):
            raise VerificationError("native ticket relation differs")
        if hashlib.sha256(content).hexdigest() != state["contentDigest"]:
            raise VerificationError("native ticket bytes differ")
        return state, content

    def dispatch(self, candidate: Any) -> dict[str, Any]:
        """Authorize, persist an intent, then atomically mutate ticket and receipt."""
        if not isinstance(candidate, dict) or set(candidate) != {"request", "grant", "contentHex"}:
            raise VerificationError("ticket dispatch fields differ")
        if len(canonical(candidate)) > MAX_BODY:
            raise VerificationError("ticket dispatch envelope exceeds finite limit")
        if candidate["request"] != asdict(self.request):
            raise VerificationError("ticket request differs")
        encoded = candidate["contentHex"]
        if not isinstance(encoded, str) or len(encoded) > MAX_BODY or len(encoded) % 2 or any(c not in "0123456789abcdef" for c in encoded):
            raise VerificationError("ticket content encoding differs")
        content = bytes.fromhex(encoded)
        if hashlib.sha256(content).hexdigest() != self.request.content_sha256:
            raise VerificationError("ticket content digest differs")
        with self._transaction() as db:
            state, _ = self._load(db)
            # Fresh grant validity and host revocation apply to cached retries too.
            intent_time = self.clock()
            authorized = verify_grant(candidate["grant"], self.request, self.policy, now=intent_time)
            if state["revoked"]:
                raise VerificationError("ticket authority is revoked")
            if state["grantDigest"] not in (None, authorized.grant_digest):
                raise VerificationError("ticket grant differs from committed intent")
            if state["phase"] == "completed":
                if intent_time < _time(state["effectTime"]):
                    raise VerificationError("ticket host clock predates cached effect")
                return self._response(state)
            if state["phase"] != "ready":
                raise VerificationError("ticket effect remains incomplete; automatic replay refused")
            self._require_readable_completion(state, encoded, authorized.grant_digest, intent_time)
            state["phase"], state["grantDigest"] = "pending", authorized.grant_digest
            state["intentTime"] = _timestamp(intent_time)
            state["effectId"] = digest(DOMAIN + "-effect", {"configuration": self.configuration_digest, "requestId": self.request.request_id, "grantDigest": authorized.grant_digest})
            self._event(db, state, {"kind": "intent", "request": asdict(self.request), "grantDigest": authorized.grant_digest, "effectId": state["effectId"], "beforeRevision": 0, "intentTime": state["intentTime"]})
            self._save(db, state)
        self._fault("after-intent")
        with self._transaction() as db:
            state, _ = self._load(db)
            # A revocation racing the gap between transactions wins admission.
            effect_time = self.clock()
            verify_grant(candidate["grant"], self.request, self.policy, now=effect_time)
            if effect_time < _time(state["intentTime"]):
                raise VerificationError("ticket host clock moved backwards before effect")
            if state["revoked"] or state["phase"] != "pending":
                raise VerificationError("ticket pending authority or phase differs")
            db.execute("INSERT INTO tickets VALUES(?,?,?,?,?)", (self.request.tenant_id, self.ticket_id, content, 1, state["effectId"]))
            self._fault("inside-effect-transaction")
            state.update(phase="completed", revision=1, contentDigest=self.request.content_sha256, effectTime=_timestamp(effect_time))
            self._event(db, state, {"kind": "effect", "effectId": state["effectId"], "revision": 1, "contentDigest": self.request.content_sha256, "effectTime": state["effectTime"], "grantDigest": state["grantDigest"]})
            self._save(db, state)
        self._fault("after-effect")
        return self.readback()["receipt"]

    def _fault(self, point: str) -> None:
        """Invoke an optional host-only interruption control."""
        if self.crash_hook is not None:
            self.crash_hook(point)

    def _receipt_payload(self, state: dict[str, Any]) -> dict[str, Any]:
        """Use one receipt shape for size admission and completed signatures."""
        return {**state, "request": asdict(self.request), "authorityKey": self.policy.issuer_key, "witnessScope": "PEER", "coverage": "one-native-ticket-row-and-service-events"}

    def _response(self, state: dict[str, Any]) -> dict[str, Any]:
        """Sign a bounded service receipt retaining each identity separately."""
        return _signed(self._receipt_payload(state), self.key)

    def _native_response(self, state: dict[str, Any], encoded: str | None, receipt: dict[str, Any]) -> dict[str, Any]:
        """Build the exact GET envelope used by admission and actual read-back."""
        return {"tenantId": self.request.tenant_id, "ticketId": self.ticket_id, "contentHex": encoded, "revision": state["revision"], "effectId": state["effectId"], "receipt": receipt}

    def _require_readable_completion(self, state: dict[str, Any], encoded: str, grant_digest: str, intent_time: datetime) -> None:
        """Refuse an unreadable native effect before its durable intent exists."""
        completed = {**state, "phase": "completed", "revision": 1, "contentDigest": self.request.content_sha256, "effectId": "0" * 64, "grantDigest": grant_digest, "eventCount": state["eventCount"] + 2, "eventHead": "0" * 64, "intentTime": _timestamp(intent_time), "effectTime": _timestamp(intent_time)}
        # Every digest has 64 ASCII bytes; both timestamps have 20. Ed25519's
        # 64-byte signature always has 88 base64 bytes. This unsigned shape
        # measures the future envelope without signing an unobserved effect.
        receipt = {"payload": self._receipt_payload(completed), "keyid": self.key.public_hex, "signature": base64.b64encode(bytes(64)).decode("ascii")}
        if len(canonical(self._native_response(completed, encoded, receipt))) > MAX_BODY:
            raise VerificationError("ticket completion read-back exceeds finite limit")

    def readback(self) -> dict[str, Any]:
        """Query actual SQLite ticket bytes separately from dispatch responses."""
        if not self.path.exists():
            raise VerificationError("ticket store is missing; initialization required")
        with self._transaction() as db:
            state, content = self._load(db)
            return self._native_response(state, None if content is None else content.hex(), self._response(state))

    def revoke(self) -> dict[str, Any]:
        """Persist host-only revocation; there is no network admin endpoint."""
        with self._transaction() as db:
            state, _ = self._load(db)
            if not state["revoked"]:
                state["revoked"] = True
                self._event(db, state, {"kind": "revoke", "authorityKey": self.policy.issuer_key})
                self._save(db, state)
            return self._response(state)

    def recover(self) -> dict[str, Any]:
        """Retain an incomplete terminal for pending effects without repeating them."""
        with self._transaction() as db:
            state, _ = self._load(db)
            if state["phase"] == "pending":
                state["phase"] = "incomplete"
                self._event(db, state, {"kind": "incomplete", "effectId": state["effectId"], "requestId": self.request.request_id, "outcome": "not-established-after-interruption"})
                self._save(db, state)
            return self._response(state)


class TicketHTTPServer(ThreadingHTTPServer):
    """Serve one local ticket on distinct dispatch and read-back HTTP routes."""

    daemon_threads = True

    def __init__(self, store: TicketStore, address: tuple[str, int] = ("127.0.0.1", 0)) -> None:
        if address[0] != "127.0.0.1":
            raise VerificationError("reference ticket server binds only loopback")
        self.store = store
        super().__init__(address, _TicketHandler)

    @property
    def url(self) -> str:
        """Return the concrete bound local HTTP endpoint."""
        return f"http://127.0.0.1:{self.server_address[1]}"


class _TicketHandler(BaseHTTPRequestHandler):
    """Apply finite HTTP framing before reaching the host-owned ticket store."""

    server: TicketHTTPServer

    def log_message(self, format: str, *args: Any) -> None:
        """Keep caller content and bearer grants out of request logs."""

    def _reply(self, code: int, value: dict[str, Any]) -> None:
        """Return a finite canonical JSON response."""
        raw = canonical(value)
        if len(raw) > MAX_BODY:
            raise VerificationError("ticket HTTP response exceeds finite limit")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:
        """Dispatch only an exact route, bounded body and canonical JSON object."""
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if self.path != "/dispatch" or len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal() or self.headers.get("Transfer-Encoding") is not None:
                raise VerificationError("ticket HTTP framing or route differs")
            length = int(lengths[0])
            if not 1 <= length <= MAX_BODY:
                raise VerificationError("ticket HTTP body exceeds finite limit")
            self.connection.settimeout(5)
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise VerificationError("ticket HTTP body is incomplete")
            self._reply(200, self.server.store.dispatch(strict_loads(raw)))
        except (VerificationError, ValueError, TimeoutError, RecursionError):
            self._reply(409, {"status": "refused", "reason": "ticket request, authority, state or framing differs"})

    def do_GET(self) -> None:
        """Read native persisted state through a separate tenant/ticket route."""
        store = self.server.store
        if self.path != f"/tickets/{store.request.tenant_id}/{store.ticket_id}":
            self._reply(404, {"status": "unsupported"})
            return
        try:
            self._reply(200, store.readback())
        except (VerificationError, RecursionError):
            self._reply(409, {"status": "refused", "reason": "native ticket state differs"})


@contextmanager
def running_server(store: TicketStore) -> Iterator[TicketHTTPServer]:
    """Run a real local HTTP listener and close all resources on exit."""
    with TicketHTTPServer(store) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(timeout=5)


def http_json(url: str, candidate: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    """Perform a bounded native HTTP request, preserving refusal status codes."""
    body = None if candidate is None else canonical(candidate)
    if body is not None and len(body) > MAX_BODY:
        raise VerificationError("ticket HTTP request exceeds finite limit")
    request = Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        response = urlopen(request, timeout=5)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise VerificationError("ticket HTTP response exceeds finite limit")
        return response.code, strict_loads(raw)


def verify_ticket_result(
    receipt: Mapping[str, Any], readback: Mapping[str, Any],
    request: ActionRequest, policy: GrantPolicy, service_key: str,
    grant: Mapping[str, Any], *, now: datetime,
    decision_digest: str | None = None,
) -> dict[str, Any]:
    """Join signed completion with separately retrieved native bytes and policy.

    This reader requires current grant validity and an unrevoked read-back,
    authenticates both service receipts, and recomputes content from native
    response bytes. It does not assign custody, authenticate the bearer caller,
    or infer general containment from a local HTTP gate. A selected optional
    decision digest is a configuration binding; native decision recomputation
    belongs to the profile reader. Omitting it refuses records that carry it.
    """
    authorized = verify_grant(grant, request, policy, now=now)
    if not isinstance(readback, Mapping) or set(readback) != READBACK_FIELDS or type(readback["revision"]) is not int:
        raise VerificationError("ticket native read-back fields or counter differ")
    carried = _checked(dict(receipt), service_key)
    current = _checked(readback["receipt"], service_key)
    configuration_fields = {"request": asdict(request), "policy": asdict(policy), "serviceKey": service_key}
    if decision_digest is not None:
        if not _hex(decision_digest):
            raise VerificationError("ticket consumer decision commitment differs")
        configuration_fields["decisionDigest"] = decision_digest
    configuration = digest(DOMAIN + "-configuration", configuration_fields)
    for record in (carried, current):
        _state_schema(record, receipt=True)
        if record["request"] != asdict(request) or record["configuration"] != configuration or record["authorityKey"] != policy.issuer_key or record["grantDigest"] != authorized.grant_digest:
            raise VerificationError("ticket consumer binding differs")
        if record["phase"] != "completed" or record["revoked"] or record["revision"] != 1 or record["witnessScope"] != "PEER" or record["coverage"] != "one-native-ticket-row-and-service-events":
            raise VerificationError("ticket consumer requires unrevoked bounded completion")
        for field in ("intentTime", "effectTime"):
            verify_grant(grant, request, policy, now=_time(record[field]))
        if now < _time(record["effectTime"]):
            raise VerificationError("ticket consumer clock predates completed effect")
    if carried != current:
        raise VerificationError("ticket current state differs from retained completion")
    expected_effect = digest(DOMAIN + "-effect", {"configuration": configuration, "requestId": request.request_id, "grantDigest": authorized.grant_digest})
    if carried["effectId"] != expected_effect:
        raise VerificationError("ticket effect identity differs")
    if readback["tenantId"] != request.tenant_id or readback["ticketId"] != request.target_path.removeprefix("/work/tickets/") or readback["revision"] != 1 or readback["effectId"] != expected_effect:
        raise VerificationError("ticket native read-back identity differs")
    encoded = readback["contentHex"]
    if not isinstance(encoded, str) or len(encoded) > MAX_BODY or len(encoded) % 2 or any(c not in "0123456789abcdef" for c in encoded):
        raise VerificationError("ticket native read-back encoding differs")
    try:
        content = bytes.fromhex(encoded)
    except (TypeError, ValueError) as error:
        raise VerificationError("ticket native read-back bytes are malformed") from error
    if hashlib.sha256(content).hexdigest() != request.content_sha256 or carried["contentDigest"] != request.content_sha256:
        raise VerificationError("ticket native read-back content differs")
    return {"status": "verified", "requestId": request.request_id, "attemptId": request.attempt_id, "effectId": expected_effect, "nativeRevision": 1, "witnessScope": "PEER"}
