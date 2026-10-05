"""Real HTTP, durable process crashes and service-native consumer controls."""

from __future__ import annotations

import copy
import hashlib
import multiprocessing
import os
import socket
import sqlite3
import threading
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant
from probity_observer.crypto import SigningKey, VerificationError, canonical
from probity_observer.ticket_service import DOMAIN, MAX_BODY, TicketHTTPServer, TicketStore, http_json, running_server, verify_ticket_result


@pytest.fixture
def case(tmp_path: Path) -> dict[str, Any]:
    """Select an exact ticket action and role keys outside candidate evidence."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    issuer, server_key = SigningKey.generate(), SigningKey.generate()
    content = b'{"status":"approved","summary":"finite ticket"}'
    request = ActionRequest("run-ticket", "attempt-ticket", "request-ticket", "tenant-1", "principal-1", "ticket-update", "/work/tickets/ticket-1", hashlib.sha256(content).hexdigest())
    policy = GrantPolicy(issuer.public_hex)
    grant = issue_grant(request, issuer, issued_at=now - timedelta(seconds=1), expires_at=now + timedelta(seconds=120))
    store = TicketStore(tmp_path / "service.sqlite", request, policy, server_key, clock=lambda: now)
    initial = store.initialize()
    return {"store": store, "request": request, "policy": policy, "key": server_key, "issuer": issuer, "now": now, "grant": grant, "initial": initial, "candidate": {"request": asdict(request), "grant": grant, "contentHex": content.hex()}}


def reopen(case: dict[str, Any], **kwargs: Any) -> TicketStore:
    """Restart under externally retained request, policy and service key."""
    return TicketStore(case["store"].path, case["request"], case["policy"], case["key"], clock=kwargs.pop("clock", lambda: case["now"]), **kwargs)


def read_url(server: TicketHTTPServer) -> str:
    """Select the separate native read-back route outside the POST response."""
    return server.url + "/tickets/tenant-1/ticket-1"


def consume(case: dict[str, Any], receipt: Any, readback: Any) -> dict[str, Any]:
    """Use keys, grant, clock and request from consumer policy, not the bundle."""
    return verify_ticket_result(receipt, readback, case["request"], case["policy"], case["key"].public_hex, case["grant"], now=case["now"])


def payload_case(case: dict[str, Any], path: Path, content: bytes, **identity: str) -> dict[str, Any]:
    """Select fresh authority and native storage for an exact boundary payload."""
    request = replace(case["request"], content_sha256=hashlib.sha256(content).hexdigest(), **identity)
    grant = issue_grant(request, case["issuer"], issued_at=case["now"] - timedelta(seconds=1), expires_at=case["now"] + timedelta(seconds=120))
    store = TicketStore(path, request, case["policy"], case["key"], clock=lambda: case["now"])
    initial = store.initialize()
    return {**case, "request": request, "grant": grant, "store": store, "initial": initial, "candidate": {"request": asdict(request), "grant": grant, "contentHex": content.hex()}}


@pytest.mark.parametrize("identity", [{}, {"principal_id": '"' * 128, "run_id": "\\" * 128, "attempt_id": '"' * 128, "request_id": "\\" * 128, "tenant_id": "t" * 128, "target_path": "/work/tickets/" + "x" * (256 - len("/work/tickets/"))}])
@pytest.mark.parametrize("unit", [b"x", b"\x00", '{"summary":"\u00e9\U0001f512"}'.encode()])
def test_exact_http_round_trip_boundary(case: dict[str, Any], tmp_path: Path, identity: dict[str, str], unit: bytes) -> None:
    """Escaped identities and arbitrary native bytes obey both envelope budgets."""
    sample = payload_case(case, tmp_path / "sample.sqlite", b"x", **identity)
    sample_receipt = sample["store"].dispatch(sample["candidate"])
    sample_native = sample["store"].readback()
    assert consume(sample, sample_receipt, sample_native)["status"] == "verified"
    request_overhead = len(canonical(sample["candidate"])) - 2
    response_overhead = len(canonical(sample_native)) - 2
    size = (MAX_BODY - max(request_overhead, response_overhead)) // 2
    content = (unit * (size // len(unit) + 1))[:size]
    bounded = payload_case(case, tmp_path / "bounded.sqlite", content, **identity)
    with running_server(bounded["store"]) as server:
        status, receipt = http_json(server.url + "/dispatch", bounded["candidate"])
        assert status == 200
        route = server.url + f"/tickets/{bounded['request'].tenant_id}/{bounded['store'].ticket_id}"
        status, native = http_json(route)
        assert status == 200
        assert consume(bounded, receipt, native)["status"] == "verified"
        assert native["contentHex"] == content.hex()
        assert len(canonical(native)) == response_overhead + 2 * size
        assert MAX_BODY - max(len(canonical(native)), len(canonical(bounded["candidate"]))) <= 1
        assert http_json(server.url + "/dispatch", bounded["candidate"]) == (200, receipt)
        assert http_json(route) == (200, native)
        bounded["store"].revoke()
        status, revoked = http_json(route)
        assert status == 200
        assert len(canonical(revoked)) == len(canonical(native)) - 1
        assert revoked["contentHex"] == content.hex()
        assert revoked["revision"] == 1
        with pytest.raises(VerificationError, match="unrevoked"):
            consume(bounded, receipt, revoked)
        assert http_json(server.url + "/dispatch", bounded["candidate"])[0] == 409
    overflow = payload_case(case, tmp_path / "overflow.sqlite", content + b"x", **identity)
    with running_server(overflow["store"]) as server:
        raw = canonical(overflow["candidate"])
        if len(raw) <= MAX_BODY:
            assert http_json(server.url + "/dispatch", overflow["candidate"])[0] == 409
        else:
            with pytest.raises(VerificationError, match="HTTP request exceeds"):
                http_json(server.url + "/dispatch", overflow["candidate"])
            with socket.create_connection(server.server_address, timeout=5) as connection:
                connection.sendall(b"POST /dispatch HTTP/1.0\r\nContent-Length: " + str(len(raw)).encode() + b"\r\n\r\n" + raw)
                assert b"409" in connection.recv(1024)
        assert overflow["store"].readback() == overflow["initial"]
    with pytest.raises(VerificationError, match="finite limit"):
        overflow["store"].dispatch(overflow["candidate"])
    assert overflow["store"].readback() == overflow["initial"]


def test_http_body_fits_but_readback_does_not(case: dict[str, Any], tmp_path: Path) -> None:
    """A formerly accepted POST must refuse before recording an unreadable effect."""
    overhead = len(canonical(case["candidate"])) - len(case["candidate"]["contentHex"])
    content = b"x" * ((MAX_BODY - overhead) // 2)
    oversized = payload_case(case, tmp_path / "readback-overflow.sqlite", content)
    assert MAX_BODY - len(canonical(oversized["candidate"])) <= 1
    with running_server(oversized["store"]) as server:
        assert http_json(server.url + "/dispatch", oversized["candidate"])[0] == 409
        assert http_json(read_url(server))[1] == oversized["initial"]
    with pytest.raises(VerificationError, match="native read-back exceeds"):
        oversized["store"].dispatch(oversized["candidate"])
    assert oversized["store"].readback() == oversized["initial"]


def test_retained_unreadable_completion_refuses_without_mutation(case: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Old admission can leave valid native state that cannot fit the GET budget."""
    overhead = len(canonical(case["candidate"])) - len(case["candidate"]["contentHex"])
    content = b"x" * ((MAX_BODY - overhead) // 2)
    retained = payload_case(case, tmp_path / "retained-overflow.sqlite", content)
    # Reproduce the previous admission rule while retaining real signatures,
    # intent/effect history and SQLite bytes. Restore the current rule before
    # reopening the retained store and exercising its supported interfaces.
    with monkeypatch.context() as previous:
        previous.setattr(retained["store"], "_require_readable_readback", lambda *args: None)
        receipt = retained["store"].dispatch(retained["candidate"])
        assert len(canonical(retained["store"].readback())) > MAX_BODY
    assert receipt["payload"]["phase"] == "completed"
    before = retained["store"].path.read_bytes()
    restored = reopen(retained, retained_head=receipt)
    with pytest.raises(VerificationError, match="native read-back exceeds"):
        restored.readback()
    with pytest.raises(VerificationError, match="native read-back exceeds"):
        restored.dispatch(retained["candidate"])
    with running_server(restored) as server:
        for status, refusal in [http_json(server.url + "/dispatch", retained["candidate"]), http_json(read_url(server))]:
            assert status == 409
            assert refusal["status"] == "refused"
    assert restored.path.read_bytes() == before
    with sqlite3.connect(restored.path) as db:
        assert db.execute("SELECT content,revision FROM tickets").fetchall() == [(content, 1)]
        assert db.execute("SELECT COUNT(*) FROM events").fetchone() == (3,)


def test_non_ascii_request_refuses_before_intent(case: dict[str, Any]) -> None:
    """Native UTF-8 content remains separate from restricted signed JSON identity."""
    candidate = copy.deepcopy(case["candidate"])
    candidate["request"]["principal_id"] = "\u00e9"
    with pytest.raises(VerificationError, match="non-ASCII"):
        case["store"].dispatch(candidate)
    with running_server(case["store"]) as server:
        raw = b'{"principal_id":"\xc3\xa9"}'
        with socket.create_connection(server.server_address, timeout=5) as connection:
            connection.sendall(b"POST /dispatch HTTP/1.0\r\nContent-Length: " + str(len(raw)).encode() + b"\r\n\r\n" + raw)
            assert b"409" in connection.recv(1024)
    assert case["store"].readback() == case["initial"]


def test_server_refuses_oversized_readback(case: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    """An oversized native response cannot bypass the server's actual byte bound."""
    original = case["store"].readback
    monkeypatch.setattr(case["store"], "readback", lambda: {"unexpected": "x" * MAX_BODY})
    with running_server(case["store"]) as server:
        status, refusal = http_json(read_url(server))
        assert status == 409
        assert refusal["status"] == "refused"
    assert original() == case["initial"]


def test_client_bounds_oversized_get_response() -> None:
    """A real external HTTP response cannot enlarge the client's read budget."""
    class OversizedHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            pass

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", str(MAX_BODY + 1))
            self.end_headers()
            self.wfile.write(b"x" * (MAX_BODY + 1))

    with ThreadingHTTPServer(("127.0.0.1", 0), OversizedHandler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with pytest.raises(VerificationError, match="HTTP response exceeds"):
                http_json(f"http://127.0.0.1:{server.server_address[1]}/readback")
        finally:
            server.shutdown()
            thread.join(timeout=5)


def test_real_http_write_and_restart(case: dict[str, Any]) -> None:
    """A completed native ticket survives server restart without a second write."""
    with running_server(case["store"]) as server:
        status, receipt = http_json(server.url + "/dispatch", case["candidate"])
        assert status == 200
        status, native = http_json(read_url(server))
        assert status == 200
        result = consume(case, receipt, native)
        assert result["status"] == "verified"
        assert len({result["requestId"], result["attemptId"], result["effectId"]}) == 3
        assert native["revision"] == 1
    with running_server(reopen(case, retained_head=receipt)) as server:
        assert http_json(server.url + "/dispatch", case["candidate"]) == (200, receipt)
        assert http_json(read_url(server))[1] == native


@pytest.mark.parametrize("field,value", [("tenant_id", "tenant-2"), ("principal_id", "principal-2"), ("tool_id", "wrong-tool"), ("target_path", "/work/tickets/ticket-2"), ("request_id", "request-other"), ("attempt_id", "attempt-other"), ("run_id", "run-other")])
def test_request_substitution_refused(case: dict[str, Any], field: str, value: str) -> None:
    """Changed tenant, action, principal and invocation identity never mutate state."""
    candidate = copy.deepcopy(case["candidate"])
    candidate["request"][field] = value
    with running_server(case["store"]) as server:
        assert http_json(server.url + "/dispatch", candidate)[0] == 409
        assert http_json(read_url(server))[1]["revision"] == 0


@pytest.mark.parametrize("kind", ["content", "issuer", "expired", "grant-replacement"])
def test_authority_and_content_controls(case: dict[str, Any], kind: str) -> None:
    """Native gate refuses changed bytes, issuer, expiry and grant cache reuse."""
    candidate = copy.deepcopy(case["candidate"])
    store = case["store"]
    if kind == "content":
        candidate["contentHex"] = b"different".hex()
    elif kind == "issuer":
        other = SigningKey.generate()
        candidate["grant"] = issue_grant(case["request"], other, issued_at=case["now"], expires_at=case["now"] + timedelta(seconds=60))
    elif kind == "expired":
        store = reopen(case, clock=lambda: case["now"] + timedelta(seconds=120))
    else:
        store.dispatch(candidate)
        candidate["grant"] = issue_grant(case["request"], case["issuer"], issued_at=case["now"], expires_at=case["now"] + timedelta(seconds=60))
    with running_server(store) as server:
        assert http_json(server.url + "/dispatch", candidate)[0] == 409
        assert http_json(read_url(server))[1]["revision"] == (1 if kind == "grant-replacement" else 0)


@pytest.mark.parametrize("after_effect", [False, True])
def test_revocation_on_fresh_and_cached_actions(case: dict[str, Any], after_effect: bool) -> None:
    """Revocation refuses cached retry while retaining the already completed effect."""
    if after_effect:
        receipt = case["store"].dispatch(case["candidate"])
    case["store"].revoke()
    with running_server(reopen(case)) as server:
        assert http_json(server.url + "/dispatch", case["candidate"])[0] == 409
        native = http_json(read_url(server))[1]
        assert native["revision"] == int(after_effect)
        assert native["receipt"]["payload"]["revoked"] is True
        if after_effect:
            with pytest.raises(VerificationError):
                consume(case, receipt, native)


def test_revocation_between_intent_and_effect(case: dict[str, Any]) -> None:
    """A revoke committed in the two-transaction gap prevents native mutation."""
    def hook(point: str) -> None:
        if point == "after-intent":
            reopen(case).revoke()
    store = reopen(case, crash_hook=hook)
    with pytest.raises(VerificationError, match="pending authority"):
        store.dispatch(case["candidate"])
    native = store.readback()
    assert native["revision"] == 0
    assert store.recover()["payload"]["phase"] == "incomplete"


def test_revocation_waits_for_native_transaction(case: dict[str, Any]) -> None:
    """A racing revoke shares SQLite's lock and cannot erase a committed effect."""
    started, requested, finished = threading.Event(), threading.Event(), threading.Event()
    def revoke() -> None:
        requested.set()
        reopen(case).revoke()
        finished.set()
    worker: threading.Thread | None = None
    def hook(point: str) -> None:
        nonlocal worker
        if point == "inside-effect-transaction":
            started.set()
            worker = threading.Thread(target=revoke)
            worker.start()
            assert requested.wait(2)
            assert not finished.wait(0.05)
    store = reopen(case, crash_hook=hook)
    store.dispatch(case["candidate"])
    assert started.is_set() and worker is not None
    worker.join(5)
    assert finished.is_set()
    assert store.readback()["revision"] == 1
    with pytest.raises(VerificationError, match="revoked"):
        store.dispatch(case["candidate"])


def _crash_server(case: dict[str, Any], point: str, port_pipe: Any) -> None:
    """Crash a real server process at a selected durable transaction boundary."""
    def crash(selected: str) -> None:
        if selected == point:
            os._exit(73)
    with TicketHTTPServer(reopen(case, crash_hook=crash)) as server:
        port_pipe.send(server.server_address[1])
        port_pipe.close()
        server.serve_forever()


@pytest.mark.parametrize("point,revision,phase", [("after-intent", 0, "incomplete"), ("inside-effect-transaction", 0, "incomplete"), ("after-effect", 1, "completed")])
def test_actual_process_crash_recovery(case: dict[str, Any], point: str, revision: int, phase: str) -> None:
    """Hard process exit preserves intent and SQLite commits without automatic replay."""
    context = multiprocessing.get_context("fork")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=_crash_server, args=(case, point, send))
    process.start()
    send.close()
    assert receive.poll(5)
    port = receive.recv()
    receive.close()
    try:
        with pytest.raises((OSError, ConnectionError)):
            http_json(f"http://127.0.0.1:{port}/dispatch", case["candidate"])
    finally:
        process.join(5)
        if process.is_alive():
            process.terminate()
            process.join(5)
    assert process.exitcode == 73
    store = reopen(case)
    receipt = store.recover()
    assert receipt["payload"]["phase"] == phase
    assert store.readback()["revision"] == revision
    if revision:
        assert store.dispatch(case["candidate"])["payload"]["revision"] == 1
    else:
        with pytest.raises(VerificationError, match="incomplete"):
            store.dispatch(case["candidate"])


@pytest.mark.parametrize("bypass", ["native-bytes", "native-extra-row", "native-revision", "native-content-type", "history-delete", "state-delete"])
def test_persistent_bypass_controls(case: dict[str, Any], bypass: str) -> None:
    """Unrecorded native table changes and missing service history refuse read-back."""
    case["store"].dispatch(case["candidate"])
    with sqlite3.connect(case["store"].path) as db:
        if bypass == "native-bytes":
            db.execute("UPDATE tickets SET content=?", (b"bypassed",))
        elif bypass == "native-extra-row":
            db.execute("INSERT INTO tickets VALUES('other','ticket',?,1,'other')", (b"bypass",))
        elif bypass == "native-revision":
            db.execute("UPDATE tickets SET revision=2")
        elif bypass == "native-content-type":
            db.execute("UPDATE tickets SET content='changed native SQL type'")
        elif bypass == "history-delete":
            db.execute("DELETE FROM events WHERE sequence=2")
        else:
            db.execute("DELETE FROM state")
    with running_server(reopen(case)) as server:
        assert http_json(read_url(server))[0] == 409
        assert http_json(server.url + "/dispatch", case["candidate"])[0] == 409


def test_whole_store_rollback_requires_retained_head(case: dict[str, Any], tmp_path: Path) -> None:
    """An external retained head detects a coherent older database restoration."""
    backup = tmp_path / "old.sqlite"
    backup.write_bytes(case["store"].path.read_bytes())
    receipt = case["store"].dispatch(case["candidate"])
    case["store"].path.write_bytes(backup.read_bytes())
    with pytest.raises(VerificationError, match="predates"):
        reopen(case, retained_head=receipt).readback()
    # Without an externally retained head, a coherent older local store is valid.
    assert reopen(case).readback()["revision"] == 0


def test_missing_store_never_reinitialized(case: dict[str, Any]) -> None:
    """Restart read-back and dispatch refuse missing native state."""
    case["store"].path.unlink()
    with pytest.raises(VerificationError, match="missing"):
        reopen(case).readback()
    with pytest.raises(VerificationError, match="missing"):
        reopen(case).dispatch(case["candidate"])
    assert not case["store"].path.exists()


@pytest.mark.parametrize("mutation", ["readback-bytes", "readback-tenant", "readback-effect", "receipt-signature", "wrong-key", "changed-request"])
def test_consumer_mutations(case: dict[str, Any], mutation: str) -> None:
    """Separate consumer refuses fabricated read-back and substituted trust pins."""
    receipt = case["store"].dispatch(case["candidate"])
    native = case["store"].readback()
    if mutation == "readback-bytes":
        native["contentHex"] = b"forged".hex()
    elif mutation == "readback-tenant":
        native["tenantId"] = "other"
    elif mutation == "readback-effect":
        native["effectId"] = "other"
    elif mutation == "receipt-signature":
        receipt["payload"]["revision"] = 2
    elif mutation == "wrong-key":
        case["key"] = SigningKey.generate()
    else:
        case["request"] = replace(case["request"], principal_id="other")
    with pytest.raises(VerificationError):
        consume(case, receipt, native)


def test_http_framing_and_route_controls(case: dict[str, Any]) -> None:
    """Unknown routes, duplicate members and oversized framing cannot write."""
    with running_server(case["store"]) as server:
        assert http_json(server.url + "/revoke", case["candidate"])[0] == 409
        assert http_json(server.url + "/tickets/tenant-2/ticket-1")[0] == 404
        bodies = [(b'{"request":{},"request":{}}', "25"), (b"", "999999")]
        for body, length in bodies:
            with socket.create_connection(server.server_address, timeout=5) as connection:
                connection.sendall(b"POST /dispatch HTTP/1.0\r\nContent-Length: " + length.encode() + b"\r\n\r\n" + body)
                assert b"409" in connection.recv(1024)
        assert case["store"].readback()["revision"] == 0


def test_wrong_restart_configuration(case: dict[str, Any]) -> None:
    """A different tenant-selected request cannot reopen an existing action store."""
    store = TicketStore(case["store"].path, replace(case["request"], tenant_id="other"), case["policy"], case["key"])
    with pytest.raises(VerificationError, match="configuration"):
        store.readback()


@pytest.mark.parametrize("field,value", [("revision", True), ("eventCount", True), ("revoked", 0), ("phase", []), ("effectTime", "2000-01-01T00:00:00Z"), ("intentTime", "2000-01-01T00:00:00Z"), ("effectTime", "2035-01-01T00:00:00Z"), ("unknown", "extra")])
def test_genuinely_signed_malformed_receipt(case: dict[str, Any], field: str, value: Any) -> None:
    """A valid service signature cannot erase strict types or historical grant limits."""
    receipt = case["store"].dispatch(case["candidate"])
    native = case["store"].readback()
    receipt["payload"][field] = value
    receipt["signature"] = case["key"].sign(DOMAIN, receipt["payload"])
    native["receipt"] = copy.deepcopy(receipt)
    with pytest.raises(VerificationError):
        consume(case, receipt, native)


@pytest.mark.parametrize("corruption", ["invalid-bytes", "missing-table"])
def test_corrupt_native_store_refuses_http(case: dict[str, Any], corruption: str) -> None:
    """Malformed SQLite and missing tables return finite refusal without fresh state."""
    if corruption == "invalid-bytes":
        case["store"].path.write_bytes(b"this is not SQLite")
    else:
        with sqlite3.connect(case["store"].path) as db:
            db.execute("DROP TABLE tickets")
    with running_server(reopen(case)) as server:
        assert http_json(read_url(server))[0] == 409
        assert http_json(server.url + "/dispatch", case["candidate"])[0] == 409


def test_grant_expiry_between_intent_and_effect(case: dict[str, Any]) -> None:
    """Expiry after durable intent aborts mutation and retains an incomplete effect."""
    times = iter((case["now"], case["now"] + timedelta(seconds=120)))
    store = reopen(case, clock=lambda: next(times))
    with pytest.raises(VerificationError, match="not valid"):
        store.dispatch(case["candidate"])
    assert store.readback()["revision"] == 0
    assert store.recover()["payload"]["phase"] == "incomplete"


def test_expired_cached_retry(case: dict[str, Any]) -> None:
    """A completed effect remains recorded when its grant expires before retry."""
    case["store"].dispatch(case["candidate"])
    store = reopen(case, clock=lambda: case["now"] + timedelta(seconds=120))
    with pytest.raises(VerificationError, match="not valid"):
        store.dispatch(case["candidate"])
    assert store.readback()["revision"] == 1


def test_backwards_clock_before_effect(case: dict[str, Any]) -> None:
    """A still-valid grant does not excuse reversing the observed event clock."""
    times = iter((case["now"], case["now"] - timedelta(seconds=1)))
    store = reopen(case, clock=lambda: next(times))
    with pytest.raises(VerificationError, match="backwards"):
        store.dispatch(case["candidate"])
    assert store.readback()["revision"] == 0


def test_backwards_cached_retry_clock(case: dict[str, Any]) -> None:
    """A valid grant cannot admit cached completion before its recorded effect time."""
    case["store"].dispatch(case["candidate"])
    store = reopen(case, clock=lambda: case["now"] - timedelta(seconds=1))
    with pytest.raises(VerificationError, match="predates cached"):
        store.dispatch(case["candidate"])
    assert store.readback()["revision"] == 1


def test_backwards_consumer_clock(case: dict[str, Any]) -> None:
    """An otherwise valid grant cannot place completed effect in the reader's future."""
    receipt = case["store"].dispatch(case["candidate"])
    native = case["store"].readback()
    with pytest.raises(VerificationError, match="predates completed"):
        verify_ticket_result(receipt, native, case["request"], case["policy"], case["key"].public_hex, case["grant"], now=case["now"] - timedelta(seconds=1))


@pytest.mark.parametrize("kind", ["duplicate-length", "transfer-encoding", "excessive-nesting"])
def test_ambiguous_http_framing(case: dict[str, Any], kind: str) -> None:
    """Duplicate length, chunk framing and parser-depth attacks retain no effect."""
    body = b"{}"
    if kind == "duplicate-length":
        headers = b"Content-Length: 2\r\nContent-Length: 2\r\n"
    elif kind == "transfer-encoding":
        headers = b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n"
    else:
        body = b"[" * 1200 + b"]" * 1200
        headers = b"Content-Length: " + str(len(body)).encode() + b"\r\n"
    with running_server(case["store"]) as server:
        with socket.create_connection(server.server_address, timeout=5) as connection:
            connection.sendall(b"POST /dispatch HTTP/1.0\r\n" + headers + b"\r\n" + body)
            assert b"409" in connection.recv(1024)
    assert case["store"].readback()["revision"] == 0


def test_concurrent_http_retries_do_not_duplicate_effect(case: dict[str, Any]) -> None:
    """Two HTTP callers share native locks and create at most one ticket mutation."""
    barrier = threading.Barrier(2)
    statuses: list[int] = []
    with running_server(case["store"]) as server:
        def invoke() -> None:
            barrier.wait(timeout=5)
            statuses.append(http_json(server.url + "/dispatch", case["candidate"])[0])
        workers = [threading.Thread(target=invoke) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=5)
        assert len(statuses) == 2 and 200 in statuses and set(statuses) <= {200, 409}
        assert http_json(read_url(server))[1]["revision"] == 1
        with sqlite3.connect(case["store"].path) as db:
            assert db.execute("SELECT COUNT(*) FROM tickets").fetchone()[0] == 1
            assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 3
