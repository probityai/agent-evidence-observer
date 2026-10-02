"""Retain unsigned native AAE decisions joined to actual HTTP ticket controls."""
from __future__ import annotations
import argparse
import copy
import hashlib
import multiprocessing
import os
import shutil
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path
from typing import Any
from probity_observer.aae_enforce import enforce_check, native_digest
from probity_observer.aae_ticket import AaeTicketStore, ticket_transaction, verify_aae_ticket_result
from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant, utc_clock
from probity_observer.crypto import SigningKey, VerificationError, canonical
from probity_observer.ticket_service import TicketHTTPServer, http_json, running_server, verify_ticket_result


def setup(directory: Path, name: str, *, denied: bool = False) -> dict[str, Any]:
    """Create public native input bytes with separately generated local role keys."""
    directory.mkdir()
    issuer, key = SigningKey.generate(), SigningKey.generate()
    content = b'{"status":"native AAE ticket update"}'
    now = utc_clock()
    request = ActionRequest("run-" + name, "attempt-" + name, "request-" + name, "tenant", "principal", "ticket-update", "/work/tickets/ticket", hashlib.sha256(content).hexdigest())
    transaction = ticket_transaction(request)
    mandate = {"grants": [{"action_binding": native_digest("action", transaction["action"]), "type_fields": ["verb", "targetKind"], "disposition": "forbid" if denied else "allow", "constraints": [{"type": "exact", "field": field, "value": value} for field, value in transaction.items() if field != "action"]}]}
    decision = dict(mandate=mandate, transaction=transaction, record=enforce_check(mandate, transaction), pinned_mandate_digest=native_digest("mandate", mandate))
    policy = GrantPolicy(issuer.public_hex)
    grant = issue_grant(request, issuer, issued_at=now, expires_at=now + timedelta(seconds=240))
    host = dict(path=directory / "store.sqlite", request=request, policy=policy, key=key)
    store = AaeTicketStore(**host, **decision)
    configuration = copy.deepcopy(store.configuration)
    initial = store.initialize()
    candidate = dict(request=asdict(request), grant=grant, contentHex=content.hex())
    (directory / "decision.json").write_bytes(canonical(decision))
    (directory / "consumer-pins.json").write_bytes(canonical({"mandateDigest": decision["pinned_mandate_digest"], "request": asdict(request), "policy": asdict(policy), "serviceKey": key.public_hex}))
    (directory / "pre-effect-configuration.json").write_bytes(canonical({"configuration": configuration, "initial": initial}))
    (directory / "http-input.json").write_bytes(canonical(candidate))
    return dict(directory=directory, host=host, decision=decision, grant=grant, candidate=candidate, store=store)


def reopen(case: dict[str, Any], **changes: Any) -> AaeTicketStore:
    """Reopen native state using host-retained configuration rather than responses."""
    return AaeTicketStore(**case["host"], **case["decision"], **changes)


def retain(case: dict[str, Any], name: str, value: Any) -> None:
    """Write raw control bytes before composing the overall report."""
    (case["directory"] / (name + ".json")).write_bytes(canonical(value))


def consume(case: dict[str, Any], receipt: Any, readback: Any, **changes: Any) -> dict[str, Any]:
    """Select native pin, grant, request and key from outside candidate output."""
    host = case["host"]
    return verify_aae_ticket_result(**{**case["decision"], **changes}, receipt=receipt, readback=readback, request=host["request"], policy=host["policy"], service_key=host["key"].public_hex, grant=case["grant"], now=utc_clock())


def crash_worker(case: dict[str, Any], point: str, pipe: Any) -> None:
    """Hard-kill the actual HTTP service at a durable native boundary."""
    def fault(current: str) -> None:
        if current == point:
            os._exit(73)
    with TicketHTTPServer(reopen(case, crash_hook=fault)) as server:
        pipe.send(server.server_address[1])
        pipe.close()
        server.serve_forever()


def run(output: Path, source_revision: str = "working-tree") -> dict[str, Any]:
    """Run twelve bounded controls and retain native state and read-back bytes."""
    output.mkdir(parents=True, exist_ok=False)
    outcomes = []
    def passed(name: str, result: str) -> None:
        outcomes.append({"control": name, "passed": True, "outcome": result})
    happy = setup(output / "completion", "completion")
    with running_server(happy["store"]) as server:
        status, receipt = http_json(server.url + "/dispatch", happy["candidate"])
        read_status, native = http_json(server.url + "/tickets/tenant/ticket")
        assert status == read_status == 200
        result = consume(happy, receipt, native)
        retain(happy, "completion", {"postStatus": status, "receipt": receipt, "readStatus": read_status, "native": native, "consumer": result})
        passed("completion", "native-PERMIT-and-native-ticket-effect")
    with running_server(reopen(happy, retained_head=receipt)) as server:
        retry_status, retry = http_json(server.url + "/dispatch", happy["candidate"])
        assert retry_status == 200 and retry == receipt
        assert http_json(server.url + "/tickets/tenant/ticket")[1]["revision"] == 1
        retain(happy, "restart", {"postStatus": retry_status, "receipt": retry})
        passed("restart", "one-native-revision-cached-receipt")
    for name, changed in (("wrong-mandate-pin", {"pinned_mandate_digest": "sha256:" + "0" * 64}), ("rehashed-core", {})):
        if name == "rehashed-core":
            record = copy.deepcopy(happy["decision"]["record"])
            record["core"]["transaction_digest"] = "sha256:" + "0" * 64
            record["core_digest"] = native_digest("core", record["core"])
            changed = {"record": record}
        refused = False
        try:
            consume(happy, receipt, native, **changed)
        except VerificationError as error:
            refused = True
            retain(happy, name, {"candidateChanges": changed, "refusal": str(error)})
        assert refused
        passed(name, "consumer-refused-native-substitution")
    host = happy["host"]
    try:
        verify_ticket_result(receipt, native, host["request"], host["policy"], host["key"].public_hex, happy["grant"], now=utc_clock())
    except VerificationError as error:
        retain(happy, "plain-reader", {"refusal": str(error)})
    else:
        raise RuntimeError("plain reader silently dropped native decision join")
    passed("plain-reader", "joined-record-not-downgraded")
    denied = setup(output / "native-deny", "deny", denied=True)
    with running_server(denied["store"]) as server:
        status, refusal = http_json(server.url + "/dispatch", denied["candidate"])
        read_status, native = http_json(server.url + "/tickets/tenant/ticket")
        assert status == 409 and read_status == 200 and native["revision"] == 0
        retain(denied, "result", {"postStatus": status, "refusal": refusal, "readStatus": read_status, "native": native})
        passed("native-deny", "native-DENY-and-no-ticket-effect")
    changed = setup(output / "changed-request", "changed-request")
    candidate = copy.deepcopy(changed["candidate"])
    candidate["request"]["request_id"] = "changed-after-decision"
    with running_server(changed["store"]) as server:
        status, refusal = http_json(server.url + "/dispatch", candidate)
        read_status, native = http_json(server.url + "/tickets/tenant/ticket")
        assert status == 409 and read_status == 200 and native["revision"] == 0
        retain(changed, "result", {"candidate": candidate, "postStatus": status, "refusal": refusal, "native": native})
        passed("changed-request", "deny-and-no-ticket-effect")
    for after in (False, True):
        name = "revoked-after" if after else "revoked-before"
        case = setup(output / name, name)
        if after:
            case["store"].dispatch(case["candidate"])
        revocation = case["store"].revoke()
        with running_server(reopen(case)) as server:
            status, refusal = http_json(server.url + "/dispatch", case["candidate"])
            read_status, native = http_json(server.url + "/tickets/tenant/ticket")
            assert status == 409 and read_status == 200 and native["revision"] == int(after)
            retain(case, "result", {"revocation": revocation, "postStatus": status, "refusal": refusal, "native": native})
            passed(name, "cached-retry-refused-existing-effect-retained" if after else "deny-and-no-ticket-effect")
    context = multiprocessing.get_context("fork")
    for point in ("after-intent", "inside-effect-transaction", "after-effect"):
        case = setup(output / point, point)
        receive, send = context.Pipe(duplex=False)
        process = context.Process(target=crash_worker, args=(case, point, send))
        process.start()
        send.close()
        assert receive.poll(5), "HTTP service failed to start"
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
            status, retry = http_json(server.url + "/dispatch", case["candidate"])
            read_status, native = http_json(server.url + "/tickets/tenant/ticket")
            completed = point == "after-effect"
            assert status == (200 if completed else 409) and read_status == 200
            assert native["revision"] == int(completed)
            assert recovered["payload"]["phase"] == ("completed" if completed else "incomplete")
            retain(case, "result", {"processExit": process.exitcode, "responseInterrupted": interrupted, "recovered": recovered, "retryStatus": status, "retry": retry, "native": native})
            passed(point, "committed-effect-recovered" if completed else "incomplete-with-no-automatic-replay")
    assert len(outcomes) == 12
    source = Path(__file__).resolve().parents[1]
    shutil.copyfile(source / "tests/fixtures/aae-enforce/source-manifest.json", output / "native-source-manifest.json")
    paths = ["src/probity_observer/aae_ticket.py", "src/probity_observer/aae_enforce.py", "src/probity_observer/ticket_service.py", "examples/aae_ticket_demo.py"]
    (output / "implementation-pins.json").write_bytes(canonical({"sourceRevision": source_revision, "sha256": {name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in paths}}))
    report = {"format": "probity-aae-http-ticket-demo-v0", "status": "passed", "declaredControls": 12, "passedControls": 12, "outcomes": outcomes, "witnessScope": "PEER", "evidenceVantage": "artifact", "issuerAuthentication": "not-established", "coverage": "fixed-native-kernel-and-one-local-ticket-row", "doesNotAssert": ["native-JWS-verification", "AAE-issuer-identity", "EVM-effects", "independent-custody", "remote-caller-identity", "production-adoption"]}
    (output / "report.json").write_bytes(canonical(report))
    (output / "retained-sha256.json").write_bytes(canonical({str(path.relative_to(output)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(output.rglob("*")) if path.is_file()}))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new retained-evidence directory")
    parser.add_argument("--source-revision", default="working-tree", help="exact checkout commit when available")
    args = parser.parse_args()
    print(canonical(run(args.output, args.source_revision)).decode("ascii"))
