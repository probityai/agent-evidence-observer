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
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from .authorization import ActionRequest, AuthorizedAction, GrantPolicy, utc_clock, validate_utc_time, verify_grant
from .crypto import SigningKey, VerificationError, canonical, digest, strict_loads, verify_signature

DOMAIN = "probity-http-ticket-v0"
MAX_BODY = 65536
STATE_FIELDS = frozenset({"format", "configuration", "phase", "revision", "contentDigest", "effectId", "grantDigest", "revoked", "eventCount", "eventHead", "intentTime", "effectTime"})
RECEIPT_FIELDS = STATE_FIELDS | {"request", "authorityKey", "witnessScope", "coverage"}
READBACK_FIELDS = frozenset({"tenantId", "ticketId", "contentHex", "revision", "effectId", "receipt"})


def _timestamp(value: datetime, time_precision: Literal["seconds", "milliseconds"] = "seconds") -> str:
    """Serialize the selected UTC observation precision without input rounding."""
    reference = validate_utc_time(value, "ticket reference time", precision=time_precision)
    return reference.isoformat(timespec=time_precision).replace("+00:00", "Z")


def _time(value: Any, time_precision: Literal["seconds", "milliseconds"] = "seconds") -> datetime:
    """Refuse noncanonical timestamps before checking historical authorization."""
    from datetime import timezone
    if not isinstance(value, str):
        raise VerificationError("ticket reference time is malformed")
    try:
        format_string = "%Y-%m-%dT%H:%M:%SZ" if time_precision == "seconds" else "%Y-%m-%dT%H:%M:%S.%fZ"
        result = datetime.strptime(value, format_string).replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise VerificationError("ticket reference time is malformed") from error
    if _timestamp(result, time_precision) != value:
        raise VerificationError("ticket reference time is noncanonical")
    return result


def _hex(value: Any) -> bool:
    """Require a literal lowercase SHA-256 digest, without integer coercion."""
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _state_schema(state: Any, *, receipt: bool = False, time_precision: Literal["seconds", "milliseconds"] = "seconds") -> None:
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
    intent_time = _time(state["intentTime"], time_precision)
    if phase == "completed":
        if state["revision"] != 1 or not _hex(state["contentDigest"]) or _time(state["effectTime"], time_precision) < intent_time:
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


def _ticket_configuration(request: ActionRequest, policy: GrantPolicy, service_key: str,
                          decision_digest: str | None,
                          time_precision: Literal["seconds", "milliseconds"] = "seconds") -> dict[str, Any]:
    """Validate one supported host selection before committing its configuration."""
    if not isinstance(time_precision, str) or time_precision not in {"seconds", "milliseconds"}:
        raise VerificationError("ticket selected time precision is unsupported")
    if request.tool_id != "ticket-update" or not isinstance(request.target_path, str) or not request.target_path.startswith("/work/tickets/"):
        raise VerificationError("ticket action or target is unsupported")
    ticket_id = request.target_path.removeprefix("/work/tickets/")
    safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
    if not isinstance(request.tenant_id, str) or not ticket_id or any(c not in safe for c in ticket_id + request.tenant_id):
        raise VerificationError("ticket and tenant must use literal URL-safe identifiers")
    if not _hex(service_key) or not _hex(policy.issuer_key):
        raise VerificationError("ticket selected role keys differ")
    if service_key == policy.issuer_key:
        raise VerificationError("service and issuer keys must differ")
    configuration = {"request": asdict(request), "policy": asdict(policy), "serviceKey": service_key}
    if time_precision == "milliseconds":
        configuration["timePrecision"] = time_precision
    if decision_digest is not None:
        if not _hex(decision_digest):
            raise VerificationError("ticket decision commitment differs")
        configuration["decisionDigest"] = decision_digest
    return configuration


@dataclass(frozen=True)
class VerifiedTicketCapture:
    """Authenticated native state and measured populations under selected public policy.

    This result establishes the supplied signed history and local row relation.
    It does not establish current grant validity, custody or provider execution.
    """
    state: dict[str, Any]
    content: bytes | None
    logical_admissions: int
    local_effects: int


@dataclass(frozen=True)
class _TicketHistoryProgress:
    """Native phase and authority after one verified history prefix."""
    phase: str = "ready"
    revoked: bool = False
    admissions: int = 0


def _ticket_history_transition(number: int, carried: Any, state: dict[str, Any],
                               request: ActionRequest, policy: GrantPolicy,
                               progress: _TicketHistoryProgress) -> _TicketHistoryProgress:
    """Apply the closed native event vocabulary to one authenticated prefix."""
    if not isinstance(carried, dict) or not isinstance(carried.get("kind"), str):
        raise VerificationError("ticket event body differs")
    kind = carried["kind"]
    if kind == "initialize":
        if number != 1 or carried != {"kind": "initialize", "configuration": state["configuration"]}:
            raise VerificationError("ticket initialization history differs")
        return progress
    if number == 1:
        raise VerificationError("ticket history lacks initial configuration")
    if kind == "intent":
        expected = {"kind": "intent", "request": asdict(request), "grantDigest": state["grantDigest"],
                    "effectId": state["effectId"], "beforeRevision": 0, "intentTime": state["intentTime"]}
        if progress.phase != "ready" or progress.revoked or carried != expected or type(carried.get("beforeRevision")) is not int:
            raise VerificationError("ticket intent history differs")
        return _TicketHistoryProgress("pending", progress.revoked, progress.admissions + 1)
    if kind == "effect":
        expected = {"kind": "effect", "effectId": state["effectId"], "revision": 1,
                    "contentDigest": request.content_sha256, "effectTime": state["effectTime"], "grantDigest": state["grantDigest"]}
        if progress.phase != "pending" or progress.revoked or progress.admissions != 1 or carried != expected or type(carried.get("revision")) is not int:
            raise VerificationError("ticket native effect history differs")
        return _TicketHistoryProgress("completed", progress.revoked, progress.admissions)
    if kind == "revoke":
        if progress.revoked or carried != {"kind": "revoke", "authorityKey": policy.issuer_key}:
            raise VerificationError("ticket revocation history differs")
        return _TicketHistoryProgress(progress.phase, True, progress.admissions)
    if kind == "incomplete":
        expected = {"kind": "incomplete", "effectId": state["effectId"], "requestId": request.request_id,
                    "outcome": "not-established-after-interruption"}
        if progress.phase != "pending" or carried != expected:
            raise VerificationError("ticket interruption history differs")
        return _TicketHistoryProgress("incomplete", progress.revoked, progress.admissions)
    raise VerificationError("ticket history has unsupported event")


def _verify_ticket_history(events: Sequence[tuple[int, bytes]], state: dict[str, Any],
                           request: ActionRequest, policy: GrantPolicy, service_key: str,
                           retained: dict[str, Any] | None) -> _TicketHistoryProgress:
    """Verify signed ordering, native transitions and the externally retained prefix."""
    head, progress = "0" * 64, _TicketHistoryProgress()
    for number, (sequence, raw) in enumerate(events, 1):
        event = _checked(strict_loads(raw), service_key)
        if set(event) != {"sequence", "previous", "event", "hash"} or type(event["sequence"]) is not int or type(sequence) is not int:
            raise VerificationError("ticket event schema differs")
        body = {name: event[name] for name in ("sequence", "previous", "event")}
        if sequence != number or event["sequence"] != number or event["previous"] != head or event["hash"] != digest(DOMAIN + "-event", body):
            raise VerificationError("ticket history differs")
        progress = _ticket_history_transition(number, event["event"], state, request, policy, progress)
        head = event["hash"]
        if retained is not None and number == retained["eventCount"]:
            if head != retained["eventHead"]:
                raise VerificationError("ticket history changed retained prefix")
            prefix = {**state, "phase": progress.phase, "revoked": progress.revoked,
                "eventCount": number, "eventHead": head, "revision": int(progress.phase == "completed"),
                "contentDigest": request.content_sha256 if progress.phase == "completed" else None,
                "effectTime": state["effectTime"] if progress.phase == "completed" else None}
            if progress.phase == "ready":
                prefix.update(effectId=None, grantDigest=None, intentTime=None)
            if canonical({name: retained[name] for name in STATE_FIELDS}) != canonical(prefix):
                raise VerificationError("ticket retained state differs from native history")
    if len(events) != state["eventCount"] or head != state["eventHead"]:
        raise VerificationError("ticket history is incomplete")
    if progress.phase != state["phase"] or progress.revoked != state["revoked"]:
        raise VerificationError("ticket terminal state differs from native history")
    if retained is not None and retained["eventCount"] > len(events):
        raise VerificationError("ticket history predates retained head")
    return progress


def _verify_ticket_rows(tickets: Sequence[tuple[str, str, bytes, int, str]],
                        state: dict[str, Any], request: ActionRequest) -> bytes | None:
    """Join the actual native row population, storage types and exact content bytes."""
    if state["revision"] == 0:
        if tickets:
            raise VerificationError("unrecorded ticket bypass detected")
        return None
    if len(tickets) != 1:
        raise VerificationError("native ticket population differs")
    tenant, ticket, content, revision, effect = tickets[0]
    if not isinstance(content, bytes) or type(revision) is not int:
        raise VerificationError("native ticket row types differ")
    if (tenant, ticket, revision, effect) != (request.tenant_id, request.target_path.removeprefix("/work/tickets/"), state["revision"], state["effectId"]):
        raise VerificationError("native ticket relation differs")
    if state["contentDigest"] != request.content_sha256 or hashlib.sha256(content).hexdigest() != request.content_sha256:
        raise VerificationError("native ticket bytes differ")
    return content


def verify_ticket_capture(
    state_record: bytes, events: Sequence[tuple[int, bytes]],
    tickets: Sequence[tuple[str, str, bytes, int, str]], request: ActionRequest,
    policy: GrantPolicy, service_key: str, *, decision_digest: str | None = None,
    retained_head: dict[str, Any] | None = None,
    time_precision: Literal["seconds", "milliseconds"] = "seconds",
) -> VerifiedTicketCapture:
    """Verify selected native populations with public keys and no storage mutation.

    The caller selects the request, issuer policy, service key, optional decision
    digest and captured bytes. This authenticates native state, complete phase
    history, retained prefix and actual row relation. Current grant authorization
    and external native decision replay remain separate consumer checks.
    """
    configuration = _ticket_configuration(request, policy, service_key, decision_digest, time_precision)
    configuration_digest = digest(DOMAIN + "-configuration", configuration)
    state = _checked(strict_loads(state_record), service_key)
    _state_schema(state, time_precision=time_precision)
    if state["configuration"] != configuration_digest:
        raise VerificationError("ticket configuration differs on restart")
    if state["phase"] != "ready" and state["effectId"] != digest(DOMAIN + "-effect", {
            "configuration": configuration_digest, "requestId": request.request_id, "grantDigest": state["grantDigest"]}):
        raise VerificationError("ticket deterministic effect identity differs")
    retained = None
    if retained_head is not None:
        retained = _checked(retained_head, service_key)
        _state_schema(retained, receipt=True, time_precision=time_precision)
        if retained["configuration"] != configuration_digest:
            raise VerificationError("retained ticket head configuration differs")
        if canonical(retained["request"]) != canonical(asdict(request)) or retained["authorityKey"] != policy.issuer_key or retained["witnessScope"] != "PEER" or retained["coverage"] != "one-native-ticket-row-and-service-events":
            raise VerificationError("retained ticket head profile differs")
    history = _verify_ticket_history(events, state, request, policy, service_key, retained)
    content = _verify_ticket_rows(tickets, state, request)
    return VerifiedTicketCapture(state, content, history.admissions, len(tickets))


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
        time_precision: Literal["seconds", "milliseconds"] = "seconds",
    ) -> None:
        self.path, self.request, self.policy, self.key = path, request, policy, key
        self.clock, self.crash_hook = clock, crash_hook
        self.retained_head = retained_head
        self.time_precision = time_precision
        self.configuration = _ticket_configuration(request, policy, key.public_hex, decision_digest, time_precision)
        self.ticket_id = request.target_path.removeprefix("/work/tickets/")
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
        """Query native populations and apply the shared public capture validator."""
        row = db.execute("SELECT record FROM state WHERE singleton=1").fetchone()
        if row is None:
            raise VerificationError("ticket state is missing")
        capture = verify_ticket_capture(row[0],
            db.execute("SELECT sequence,record FROM events ORDER BY sequence").fetchall(),
            db.execute("SELECT tenant,ticket,content,revision,effect FROM tickets").fetchall(),
            self.request, self.policy, self.key.public_hex,
            decision_digest=self.configuration.get("decisionDigest"), retained_head=self.retained_head,
            time_precision=self.time_precision)
        return capture.state, capture.content

    def _authorize(self, grant: Any, *, now: datetime) -> AuthorizedAction:
        """Check host authorization at the transaction's exact sampled reference time."""
        return verify_grant(grant, self.request, self.policy, now=now, reference_precision=self.time_precision)

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
            state, stored_content = self._load(db)
            # Fresh grant validity and host revocation apply to cached retries too.
            intent_time = self.clock()
            authorized = self._authorize(candidate["grant"], now=intent_time)
            if state["revoked"]:
                raise VerificationError("ticket authority is revoked")
            if state["grantDigest"] not in (None, authorized.grant_digest):
                raise VerificationError("ticket grant differs from committed intent")
            if state["phase"] == "completed":
                if intent_time < _time(state["effectTime"], self.time_precision):
                    raise VerificationError("ticket host clock predates cached effect")
                self._require_readable_readback(state, None if stored_content is None else stored_content.hex())
                return self._response(state)
            if state["phase"] != "ready":
                raise VerificationError("ticket effect remains incomplete; automatic replay refused")
            self._require_readable_completion(state, encoded, authorized.grant_digest, intent_time)
            state["phase"], state["grantDigest"] = "pending", authorized.grant_digest
            state["intentTime"] = _timestamp(intent_time, self.time_precision)
            state["effectId"] = digest(DOMAIN + "-effect", {"configuration": self.configuration_digest, "requestId": self.request.request_id, "grantDigest": authorized.grant_digest})
            self._event(db, state, {"kind": "intent", "request": asdict(self.request), "grantDigest": authorized.grant_digest, "effectId": state["effectId"], "beforeRevision": 0, "intentTime": state["intentTime"]})
            self._save(db, state)
        self._fault("after-intent")
        with self._transaction() as db:
            state, _ = self._load(db)
            # A revocation racing the gap between transactions wins admission.
            effect_time = self.clock()
            self._authorize(candidate["grant"], now=effect_time)
            if effect_time < _time(state["intentTime"], self.time_precision):
                raise VerificationError("ticket host clock moved backwards before effect")
            if state["revoked"] or state["phase"] != "pending":
                raise VerificationError("ticket pending authority or phase differs")
            db.execute("INSERT INTO tickets VALUES(?,?,?,?,?)", (self.request.tenant_id, self.ticket_id, content, 1, state["effectId"]))
            self._fault("inside-effect-transaction")
            state.update(phase="completed", revision=1, contentDigest=self.request.content_sha256, effectTime=_timestamp(effect_time, self.time_precision))
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
        completed = {**state, "phase": "completed", "revision": 1, "contentDigest": self.request.content_sha256, "effectId": "0" * 64, "grantDigest": grant_digest, "eventCount": state["eventCount"] + 2, "eventHead": "0" * 64, "intentTime": _timestamp(intent_time, self.time_precision), "effectTime": _timestamp(intent_time, self.time_precision)}
        self._require_readable_readback(completed, encoded)

    def _require_readable_readback(self, state: dict[str, Any], encoded: str | None) -> None:
        """Apply one exact envelope bound to new and retained native state."""
        # Every digest has 64 ASCII bytes; an Ed25519 signature has 88 base64
        # bytes. Selected timestamp precision determines their exact width.
        # This unsigned shape
        # measures the future envelope without signing an unobserved effect.
        receipt = {"payload": self._receipt_payload(state), "keyid": self.key.public_hex, "signature": base64.b64encode(bytes(64)).decode("ascii")}
        if len(canonical(self._native_response(state, encoded, receipt))) > MAX_BODY:
            raise VerificationError("ticket native read-back exceeds finite limit")

    def readback(self) -> dict[str, Any]:
        """Query actual SQLite ticket bytes separately from dispatch responses."""
        if not self.path.exists():
            raise VerificationError("ticket store is missing; initialization required")
        with self._transaction() as db:
            state, content = self._load(db)
            encoded = None if content is None else content.hex()
            self._require_readable_readback(state, encoded)
            return self._native_response(state, encoded, self._response(state))

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
    time_precision: Literal["seconds", "milliseconds"] = "seconds",
) -> dict[str, Any]:
    """Join signed completion with separately retrieved native bytes and policy.

    This reader requires current grant validity and an unrevoked read-back,
    authenticates both service receipts, and recomputes content from native
    response bytes. It does not assign custody, authenticate the bearer caller,
    or infer general containment from a local HTTP gate. A selected optional
    decision digest is a configuration binding; native decision recomputation
    belongs to the profile reader. Omitting it refuses records that carry it.
    """
    authorized = verify_grant(grant, request, policy, now=now, reference_precision=time_precision)
    if not isinstance(readback, Mapping) or set(readback) != READBACK_FIELDS or type(readback["revision"]) is not int:
        raise VerificationError("ticket native read-back fields or counter differ")
    carried = _checked(dict(receipt), service_key)
    current = _checked(readback["receipt"], service_key)
    configuration_fields = _ticket_configuration(request, policy, service_key, decision_digest, time_precision)
    configuration = digest(DOMAIN + "-configuration", configuration_fields)
    for record in (carried, current):
        _state_schema(record, receipt=True, time_precision=time_precision)
        if record["request"] != asdict(request) or record["configuration"] != configuration or record["authorityKey"] != policy.issuer_key or record["grantDigest"] != authorized.grant_digest:
            raise VerificationError("ticket consumer binding differs")
        if record["phase"] != "completed" or record["revoked"] or record["revision"] != 1 or record["witnessScope"] != "PEER" or record["coverage"] != "one-native-ticket-row-and-service-events":
            raise VerificationError("ticket consumer requires unrevoked bounded completion")
        for field in ("intentTime", "effectTime"):
            verify_grant(grant, request, policy, now=_time(record[field], time_precision), reference_precision=time_precision)
        if now < _time(record["effectTime"], time_precision):
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
