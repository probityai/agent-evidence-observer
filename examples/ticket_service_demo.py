"""Run nine finite HTTP/native-state controls and retain every bounded result."""

from __future__ import annotations

import argparse
import hashlib
import multiprocessing
import os
import sqlite3
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path
from typing import Any

from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant, utc_clock
from probity_observer.crypto import SigningKey, canonical
from probity_observer.ticket_service import TicketHTTPServer, TicketStore, http_json, running_server, verify_ticket_result


def setup(directory: Path, name: str) -> dict[str, Any]:
    """Select public test bytes, an exact request and ephemeral local role keys."""
    directory.mkdir()
    issuer, service = SigningKey.generate(), SigningKey.generate()
    content = b'{"summary":"public local service demo","status":"approved"}'
    now = utc_clock()
    request = ActionRequest("run-" + name, "attempt-" + name, "request-" + name, "tenant-demo", "principal-demo", "ticket-update", "/work/tickets/ticket-demo", hashlib.sha256(content).hexdigest())
    policy = GrantPolicy(issuer.public_hex)
    grant = issue_grant(request, issuer, issued_at=now, expires_at=now + timedelta(seconds=240))
    store = TicketStore(directory / "service.sqlite", request, policy, service)
    initial = store.initialize()
    candidate = {"request": asdict(request), "grant": grant, "contentHex": content.hex()}
    (directory / "inputs.json").write_bytes(canonical({"request": asdict(request), "policy": asdict(policy), "serviceKey": service.public_hex, "candidate": candidate, "initial": initial}))
    return {"store": store, "request": request, "policy": policy, "key": service, "candidate": candidate, "grant": grant, "directory": directory}


def reopen(case: dict[str, Any]) -> TicketStore:
    """Reopen the server with keys and configuration retained by its local host."""
    return TicketStore(case["store"].path, case["request"], case["policy"], case["key"])


def route(server: TicketHTTPServer) -> str:
    """Name the independently called native read-back endpoint."""
    return server.url + "/tickets/tenant-demo/ticket-demo"


def retain(case: dict[str, Any], name: str, value: dict[str, Any]) -> None:
    """Write a finite raw control result containing only public demo inputs."""
    (case["directory"] / (name + ".json")).write_bytes(canonical(value))


def crash_worker(case: dict[str, Any], point: str, pipe: Any) -> None:
    """Hard-exit an actual HTTP server process at a native persistence boundary."""
    def fault(current: str) -> None:
        if point == current:
            os._exit(73)
    store = TicketStore(case["store"].path, case["request"], case["policy"], case["key"], crash_hook=fault)
    with TicketHTTPServer(store) as server:
        pipe.send(server.server_address[1])
        pipe.close()
        server.serve_forever()


def run(output: Path) -> dict[str, Any]:
    """Execute nine declared controls over eight separately initialized stores."""
    output.mkdir(parents=True, exist_ok=False)
    outcomes: list[dict[str, Any]] = []
    happy = setup(output / "completion-restart", "completion")
    with running_server(happy["store"]) as server:
        post_status, receipt = http_json(server.url + "/dispatch", happy["candidate"])
        read_status, native = http_json(route(server))
        admitted = verify_ticket_result(receipt, native, happy["request"], happy["policy"], happy["key"].public_hex, happy["grant"], now=utc_clock())
        assert post_status == read_status == 200 and admitted["status"] == "verified"
        retain(happy, "completion", {"postStatus": post_status, "receipt": receipt, "readStatus": read_status, "native": native, "consumer": admitted})
        outcomes.append({"control": "completion", "outcome": "allow-and-native-effect", "passed": True})
    with running_server(reopen(happy)) as server:
        post_status, cached = http_json(server.url + "/dispatch", happy["candidate"])
        read_status, native = http_json(route(server))
        assert post_status == read_status == 200 and cached == receipt and native["revision"] == 1
        retain(happy, "restart", {"postStatus": post_status, "receipt": cached, "native": native})
        outcomes.append({"control": "restart", "outcome": "cached-effect-no-second-mutation", "passed": True})
    changed = setup(output / "changed-content", "changed")
    candidate = {**changed["candidate"], "contentHex": b"changed after grant".hex()}
    with running_server(changed["store"]) as server:
        post_status, refusal = http_json(server.url + "/dispatch", candidate)
        read_status, native = http_json(route(server))
        assert post_status == 409 and read_status == 200 and native["revision"] == 0
        retain(changed, "result", {"candidate": candidate, "postStatus": post_status, "refusal": refusal, "native": native})
        outcomes.append({"control": "changed-content", "outcome": "deny-and-no-native-effect", "passed": True})
    for after in (False, True):
        name = "revoked-after" if after else "revoked-before"
        case = setup(output / name, name)
        if after:
            with running_server(case["store"]) as server:
                assert http_json(server.url + "/dispatch", case["candidate"])[0] == 200
        revocation = case["store"].revoke()
        with running_server(reopen(case)) as server:
            post_status, refusal = http_json(server.url + "/dispatch", case["candidate"])
            read_status, native = http_json(route(server))
            assert post_status == 409 and read_status == 200 and native["revision"] == int(after)
            retain(case, "result", {"revocation": revocation, "postStatus": post_status, "refusal": refusal, "native": native})
            outcomes.append({"control": name, "outcome": "deny-with-retained-earlier-effect" if after else "deny-and-no-native-effect", "passed": True})
    bypass = setup(output / "native-bypass", "bypass")
    with running_server(bypass["store"]) as server:
        assert http_json(server.url + "/dispatch", bypass["candidate"])[0] == 200
        with sqlite3.connect(bypass["store"].path) as db:
            db.execute("UPDATE tickets SET content=?", (b"unrecorded native bytes",))
        post_status, refusal = http_json(server.url + "/dispatch", bypass["candidate"])
        read_status, read_refusal = http_json(route(server))
        assert post_status == read_status == 409
        retain(bypass, "result", {"postStatus": post_status, "refusal": refusal, "readStatus": read_status, "readRefusal": read_refusal})
        outcomes.append({"control": "native-bypass", "outcome": "persistent-bypass-detected", "passed": True})
    context = multiprocessing.get_context("fork")
    for point in ("after-intent", "inside-effect-transaction", "after-effect"):
        case = setup(output / point, point)
        receive, send = context.Pipe(duplex=False)
        process = context.Process(target=crash_worker, args=(case, point, send))
        process.start()
        send.close()
        assert receive.poll(5), "server failed to open its HTTP endpoint"
        port = receive.recv()
        receive.close()
        interrupted = False
        try:
            http_json(f"http://127.0.0.1:{port}/dispatch", case["candidate"])
        except (OSError, ConnectionError):
            interrupted = True
        finally:
            process.join(5)
            if process.is_alive():
                process.terminate()
                process.join(5)
        assert interrupted and process.exitcode == 73
        store = reopen(case)
        recovered = store.recover()
        with running_server(store) as server:
            post_status, retry = http_json(server.url + "/dispatch", case["candidate"])
            read_status, native = http_json(route(server))
            completed = point == "after-effect"
            assert read_status == 200 and native["revision"] == int(completed)
            assert post_status == (200 if completed else 409)
            assert recovered["payload"]["phase"] == ("completed" if completed else "incomplete")
            retain(case, "result", {"processExit": process.exitcode, "responseInterrupted": interrupted, "recovered": recovered, "retryStatus": post_status, "retry": retry, "native": native})
            outcomes.append({"control": point, "outcome": "committed-effect-recovered" if completed else "incomplete-and-no-automatic-replay", "passed": True})
    assert len(outcomes) == 9
    report = {"format": "probity-http-ticket-demo-v0", "status": "passed", "declaredControls": 9, "passedControls": 9, "stores": 8, "witnessScope": "PEER", "evidenceVantage": "artifact", "outcomes": outcomes, "coverage": "fixed-local-http-ticket-controls", "doesNotAssert": ["independent-custody", "remote-principal-identity", "general-containment", "complete-agent-effects", "production-deployment"]}
    (output / "report.json").write_bytes(canonical(report))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new directory for retained public demo evidence")
    args = parser.parse_args()
    print(canonical(run(args.output)).decode("ascii"))
