"""Installed offline reader for selected joint native recovery originals.

The reader authenticates historical effects separately from permission to
release a cached result. It receives no signing key, imports no LangGraph and
opens retained SQLite snapshots read-only. All selection pins are caller input.
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from probity_observer.authorization import ActionRequest, GrantPolicy, verify_grant
from probity_observer.crypto import VerificationError, canonical, strict_loads
from probity_observer.ticket_service import TicketStore, _checked, _state_schema, verify_ticket_result

from joint_common import CASES, HOST_POLICY, NONCLAIMS, PROFILE, authority, child_environment, expected_authority, expected_revision, load, phases, read, require, same, sha


def selections(root: Path, pins: dict[str, Any]) -> dict[str, Any]:
    """Require exact externally selected manifest and finite host policy.

    Parameters
    ----------
    root : pathlib.Path
        Relying-party-selected retained public packet.
    pins : dict
        Exact plan/artifact SHA256 values and evaluation clock chosen outside
        the candidate. Pins carried inside a packet do not select themselves.

    Returns
    -------
    dict
        Original plan after bounded identity, source and population checks.
    """
    same(sorted(pins), sorted(["profile", "planSha256", "artifactManifestSha256", "evaluationTime"]), "consumer-pin-fields")
    same(pins["profile"], PROFILE, "consumer-profile")
    for name, field in (("plan-before-run.json", "planSha256"), ("artifact-manifest.json", "artifactManifestSha256")):
        require(sha(read(root, name)) == pins[field], "consumer-" + field)
    plan = load(root, "plan-before-run.json")
    same(plan["profile"], PROFILE, "profile")
    same(plan["witnessScope"], "PEER", "witness-scope")
    same(plan["doesNotAssert"], NONCLAIMS, "nonclaims")
    same(plan["hostPolicy"], HOST_POLICY, "host-policy")
    same([case["id"] for case in plan["cases"]], list(CASES), "planned-population")
    require(isinstance(plan["sourceRevision"], str) and len(plan["sourceRevision"]) == 40, "source-revision")
    same([plan["environment"]["packages"][name] for name in ("langgraph", "langgraph-checkpoint-sqlite")], ["1.0.10", "3.1.1"], "framework-selection")
    require(datetime.fromisoformat(pins["evaluationTime"]) >= datetime.fromisoformat(plan["selectedTime"]), "evaluation-time")
    manifest(root, plan)
    return plan


def manifest(root: Path, plan: dict[str, Any]) -> None:
    """Authenticate every original member and refuse added/private source files."""
    selected = load(root, "artifact-manifest.json")
    actual = {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()} - {"artifact-manifest.json", "consumer-pins.json", "report.json"}
    same(sorted(selected), sorted(actual), "artifact-population")
    for name, digest in selected.items():
        require(sha(read(root, name)) == digest, "artifact-pin")
    source_names = {"sources/joint/" + name for name in ("joint_common.py", "joint_run.py", "joint_worker.py", "joint_target.py", "joint_reader.py", "joint_host_gate.py")} | {"sources/authority/" + name for name in ("authority_common.py", "authority_worker.py")} | {"sources/langgraph/" + name for name in ("lg_common.py", "lg_run.py", "durable_worker.py")} | {"sources/target/" + name for name in ("target_common.py", "target_run.py")} | {"sources/observer/" + name for name in ("authorization.py", "crypto.py", "ticket_service.py")}
    same(sorted(plan["sources"]), sorted(source_names), "source-population")
    for name, digest in plan["sources"].items():
        require(sha(read(root, name)) == digest, "source-pin")


def signed_state(value: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    """Authenticate original state using the frozen external service-key choice.

    Authentication does not imply current dispatch authority or independent key
    custody. The exact native content relation is checked before any result is
    classified as an authentic prior effect.
    """
    same(sorted(value), sorted(["tenantId", "ticketId", "contentHex", "revision", "effectId", "receipt"]), "readback-fields")
    payload = _checked(value["receipt"], case["serviceKey"])
    _state_schema(payload, receipt=True)
    same(payload["request"], case["request"], "readback-request")
    same(payload["authorityKey"], case["policy"]["issuer_key"], "readback-authority")
    same([payload["witnessScope"], payload["coverage"]], ["PEER", "one-native-ticket-row-and-service-events"], "readback-scope")
    same([value["tenantId"], value["ticketId"], value["revision"], value["effectId"]], ["tenant", case["id"], payload["revision"], payload["effectId"]], "readback-identity")
    same(value["contentHex"], case["contentHex"] if payload["revision"] else None, "readback-content")
    if payload["revision"] == 1:
        verify_grant(case["grant"], ActionRequest(**case["request"]), GrantPolicy(**case["policy"]), now=datetime.strptime(payload["effectTime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc))
    return payload


def process_records(value: dict[str, Any], case: dict[str, Any]) -> None:
    """Require actual fresh worker/target identities and bounded process outcomes."""
    name = case["id"]
    targets, workers = value["targets"], value["workers"]
    same(len(targets), 2, "target-process-population")
    same([item["phase"] for item in workers], list(phases(name)), "worker-process-population")
    pids = [target["pid"] for target in targets] + [worker["record"]["pid"] for worker in workers]
    require(all(type(pid) is int and pid > 0 for pid in pids) and len(pids) == len(set(pids)), "distinct-processes")
    for index, target in enumerate(targets, 1):
        selected_service_key(case, target, index)
        same(target["environment"], child_environment(), "target-process-environment")
        same([target["ordinal"], target["result"]["pid"]], [index, target["pid"]], "target-process-identity")
        expected = {"pending-intent-after": 74, "pending-transaction-after": 75}.get(name, -15) if index == 1 else 78 if name in {"target-key-after", "target-store-after", "target-rollback-after"} else -15
        same(target["returncode"], expected, "target-process-exit")
        same([target["stdoutHex"], target["stderrHex"]], ["", ""], "target-process-streams")
    for worker in workers:
        item = worker["process"]
        same([item["pid"], item["timedOut"]], [worker["record"]["pid"], False], "worker-parent-process-identity")
        same(item["environment"], child_environment(), "worker-process-environment")
        same(item["exitCode"], 73 if worker["phase"] == "first" else 0, "worker-process-exit")
        require(type(item["elapsedNs"]) is int and 0 < item["elapsedNs"] <= 30_000_000_000, "worker-resource")
        expected_stderr = b"protected action refused: grant is not valid at the reference time\n".hex() if name == "grant-expired-after" and worker["phase"] == "second" else ""
        same([item["stdoutHex"], item["stderrHex"]], ["", expected_stderr], "worker-process-streams")


def current_record(case: dict[str, Any], worker: dict[str, Any], startup: bool, target_key: str) -> str:
    """Rebuild the declared current selection and durable-clock disposition."""
    name, phase, record = case["id"], worker["phase"], worker["record"]
    status = expected_authority(name, phase)
    mode = name.rsplit("-", 1)[0] if phase == "second" else "valid"
    selected = {"grantSha256": sha(canonical(case["grant"])), "issuerPolicy": case["policy"], "serviceKey": case["serviceKey"], "storeIdentity": case["storeIdentity"]}
    changes = {"grant-mismatch": ("grantSha256", "0" * 64), "authority-key": ("issuerPolicy", {**case["policy"], "issuer_key": "0" * 64}), "target-key": ("serviceKey", target_key), "target-store": ("storeIdentity", "0" * 32)}
    if mode in changes:
        field, replacement = changes[mode]
        selected = {**selected, field: replacement}
    clock = datetime.fromisoformat(case["clockTime"])
    if mode == "grant-expired":
        from datetime import timedelta
        clock += timedelta(seconds=3600)
    same(record["current"], {"authority": authority(case, mode), "selection": selected, "clockTime": clock.isoformat(), "targetReady": not startup if phase != "first" else True}, "current-selection")
    expected = {"current": authority(case, mode), "priorClock": 0 if phase == "first" else 100, "status": status}
    if status == "refused-current-grant":
        expected["grantReason"] = "grant is not valid at the reference time"
    if status in {"refused-current-selection", "refused-target-startup", "refused-current-grant"}:
        expected["selectionDenialAnchor"] = {"current": {**authority(case, mode), "revoked": True}, "priorClock": 100, "status": "refused-revoked"}
    same(record["authority"], expected, "current-authority")
    return status


def selected_service_key(case: dict[str, Any], target: dict[str, Any], ordinal: int) -> None:
    """Bind current selection to the actual native launch's retained public key."""
    key = target["selectedServiceKey"]
    if ordinal == 2 and case["id"] == "target-key-after":
        require(isinstance(key, str) and len(key) == 64 and all(character in "0123456789abcdef" for character in key) and key != case["serviceKey"], "target-launch-key")
        return
    same(key, case["serviceKey"], "target-launch-key")


def native_records(case: dict[str, Any], value: dict[str, Any]) -> None:
    """Bind the new worker to original native snapshots and parent history.

    Original SQLite checkpoint files and native projections are both retained.
    These are author-operated native captures, authenticated by selected byte
    pins; checkpoint snapshots are not separately signed by an outside operator.
    """
    first = value["workers"][0]["record"]
    same([first["status"], first["releasedResult"], first["loaded"]["values"], first["loaded"]["next"]], ["interrupted", False, {}, []], "first-native-state")
    history = list(reversed(first["history"]))
    same(len(history), 2, "native-history-population")
    same(history[-1], first["snapshot"], "native-before-exit-snapshot")
    same([history[0]["parent_config"], history[1]["parent_config"]], [None, history[0]["config"]], "native-history-parent")
    for snapshot in history:
        same(snapshot["config"]["configurable"]["thread_id"], case["request"]["run_id"] + "/" + case["id"], "native-thread")
    same(first["snapshot"]["values"], {"contentHex": case["contentHex"], "result": {}}, "native-input")
    same(first["snapshot"]["next"], ["dispatch"], "native-pending-node")
    interrupt = {"point": "before-dispatch" if case["id"].endswith("before") else "after-dispatch", "caseId": case["id"]}
    if first["http"]:
        interrupt["httpSha256"] = sha(canonical(first["http"][0]))
    same(first["snapshot"]["interrupts"][0]["value"], interrupt, "native-interrupt")
    for worker in value["workers"][1:]:
        same(worker["record"]["loaded"], first["snapshot"], "native-reopened-checkpoint")


def http_record(item: dict[str, Any], case: dict[str, Any], endpoint: str, post: bool) -> Any:
    """Bind literal HTTP bytes and monotonic intervals to the selected process."""
    same(item["url"], endpoint + ("/dispatch" if post else "/tickets/tenant/" + case["id"]), "http-endpoint")
    same(item["requestHex"], canonical({key: case[key] for key in ("request", "grant", "contentHex")}).hex() if post else None, "http-request")
    require(type(item["startedNs"]) is int and type(item["endedNs"]) is int and 0 < item["startedNs"] < item["endedNs"], "http-interval")
    if item["status"] is None:
        require(post and case["id"].startswith("pending-"), "http-unexpected-incomplete")
        same(item["responseHex"], None, "http-crash-response")
        require(item["error"] in {"RemoteDisconnected", "ConnectionResetError"}, "http-crash-error")
        return None
    require(type(item["status"]) is int and item["error"] is None, "http-status")
    raw = bytes.fromhex(item["responseHex"])
    decoded = strict_loads(raw)
    same(raw.hex(), canonical(decoded).hex(), "http-literal-bytes")
    return decoded


def worker_http(case: dict[str, Any], value: dict[str, Any]) -> None:
    """Authenticate effects while refusing completion under invalid authority."""
    startup = case["id"] in {"target-key-after", "target-store-after", "target-rollback-after"}
    for worker in value["workers"]:
        phase, record = worker["phase"], worker["record"]
        status = current_record(case, worker, startup, value["targets"][0 if phase == "first" else 1]["selectedServiceKey"])
        expected_calls = int(case["id"].endswith("after")) if phase == "first" else int(status == "authorized")
        same(len(record["http"]), expected_calls, "worker-dispatch-population")
        check_worker_disposition(case, record, phase, status)
        for item in record["http"]:
            endpoint = value["targets"][0 if phase == "first" else 1]["result"]["url"]
            response = http_record(item["post"], case, endpoint, True)
            if response is not None:
                readback = http_record(item["get"], case, endpoint, False)
                same(item["get"]["status"], 200, "worker-readback-status")
                signed_state(readback, case)
                authenticate_dispatch(case, item, response, readback)
            else:
                same(item["get"], None, "worker-crash-readback")


def authenticate_dispatch(case: dict[str, Any], item: dict[str, Any], response: Any, readback: dict[str, Any]) -> None:
    """Verify signed completed receipts or exact pending replay refusals."""
    if item["post"]["status"] == 200:
        verify_ticket_result(response, readback, ActionRequest(**case["request"]), GrantPolicy(**case["policy"]), case["serviceKey"], case["grant"], now=datetime.fromisoformat(case["clockTime"]))
        return
    same(item["post"]["status"], 409, "dispatch-refusal-status")
    require(case["id"].startswith("pending-"), "dispatch-unplanned-refusal")
    same(response, {"status": "refused", "reason": "ticket request, authority, state or framing differs"}, "pending-refusal-response")


def check_worker_disposition(case: dict[str, Any], record: dict[str, Any], phase: str, status: str) -> None:
    """Require no released result for first, denied or incomplete execution."""
    released = phase != "first" and status == "authorized" and not case["id"].startswith("pending-")
    expected = "interrupted" if phase == "first" else status if status != "authorized" else "completed" if released else "refused-pending-effect"
    same([record["status"], record["releasedResult"]], [expected, released], "worker-result-release")
    if status != "authorized":
        same(sorted(record), sorted(["pid", "loaded", "authority", "current", "http", "status", "releasedResult"]), "denied-no-result")
        return
    same(record["result"]["contentHex"], case["contentHex"], "completed-native-content")
    if phase != "first":
        item = record["http"][0]
        same(record["result"]["result"], {"httpSha256": sha(canonical(item)), "postStatus": item["post"]["status"]}, "completed-native-result")
        same(record["snapshot"]["values"], record["result"], "completed-native-snapshot")
        same(record["snapshot"]["next"], [], "completed-native-next")


def native_store(root: Path, case: dict[str, Any], value: dict[str, Any]) -> None:
    """Replay service-signed native rows read-only against the retained prefix."""
    name = case["id"]
    same(value["checkpointSnapshot"], "native/" + name + "-checkpoints.sqlite", "checkpoint-snapshot-name")
    require(read(root, value["checkpointSnapshot"]).startswith(b"SQLite format 3\x00"), "checkpoint-snapshot-format")
    native_clock(root, case, value)
    if name == "target-store-after":
        same(value["targetSnapshot"], None, "missing-store-snapshot")
        return
    same(value["targetSnapshot"], "native/" + name + "-target.sqlite", "target-snapshot-name")
    path = root / value["targetSnapshot"]
    require(read(root, value["targetSnapshot"]).startswith(b"SQLite format 3\x00"), "target-snapshot-format")
    store = TicketStore(path, ActionRequest(**case["request"]), GrantPolicy(**case["policy"]), SimpleNamespace(public_hex=case["serviceKey"]), retained_head=value["prior"]["receipt"])
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)) as connection:
        if name == "target-rollback-after":
            try:
                store._load(connection)
            except VerificationError as error:
                same(str(error), "ticket history predates retained head", "rollback-snapshot-refusal")
                return
            require(False, "rollback-snapshot-admitted")
        state, content = store._load(connection)
    payload = signed_state(value["final"], case)
    same(state, {key: payload[key] for key in state}, "native-target-state")
    same(None if content is None else content.hex(), value["final"]["contentHex"], "native-target-content")


def native_clock(root: Path, case: dict[str, Any], value: dict[str, Any]) -> None:
    """Check retained durable high-water/denial and native checkpoint population.

    Only read-only standard-library SQLite is used. Native binary checkpoint
    payloads remain retained rather than being interpreted by an installed
    framework; public native snapshots supply the checked graph projection.
    """
    path = root / value["checkpointSnapshot"]
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)) as connection:
        rows = connection.execute("SELECT binding,clock,denied FROM recovery_clock").fetchall()
        checkpoints = connection.execute("SELECT thread_id,COUNT(*) FROM checkpoints GROUP BY thread_id").fetchall()
    status = value["workers"][-1]["record"]["authority"]["status"]
    denied = int(status not in {"authorized", "refused-clock-rollback"})
    clock = 200 if case["id"].startswith("expired-") else 100
    same([list(row) for row in rows], [[authority(case)["actionSha256"], clock, denied]], "native-clock-anchor")
    same([list(row) for row in checkpoints], [[case["request"]["run_id"] + "/" + case["id"], 3 if status == "authorized" else 2]], "native-checkpoint-population")


def target_state(root: Path, case: dict[str, Any], value: dict[str, Any]) -> dict[str, Any]:
    """Preserve prior authentic effects, pending refusal and final target identity."""
    name = case["id"]
    prior = signed_state(value["prior"], case)
    final = signed_state(value["final"], case)
    same(final["revision"], expected_revision(name), "final-native-revision")
    same(prior["revision"], int(name.endswith("after") and not name.startswith("pending-")), "prior-native-revision")
    if name.startswith("pending-"):
        same([prior["phase"], final["phase"]], ["pending", "incomplete"], "pending-effect-preserved")
        require(isinstance(value["pendingRecovery"], dict), "pending-terminal-recovery")
        same(value["pendingRecovery"]["payload"], final, "pending-terminal-recovery")
    else:
        same(value["pendingRecovery"], None, "unplanned-pending-recovery")
    startup = name in {"target-key-after", "target-store-after", "target-rollback-after"}
    check_target_startup(case, value, startup)
    if not startup:
        endpoint = value["targets"][1]["result"]["url"]
        response = http_record(value["finalHttp"], case, endpoint, False)
        same(value["finalHttp"]["status"], 200, "final-http-status")
        same(response, value["final"] if not name.startswith("pending-") else value["intermediate"], "final-http-readback")
    if prior["revision"]:
        same([final[field] for field in ("effectId", "contentDigest", "effectTime", "grantDigest")], [prior[field] for field in ("effectId", "contentDigest", "effectTime", "grantDigest")], "prior-committed-effect-preserved")
    native_store(root, case, value)
    return {"id": name, "workerProcesses": len(value["workers"]), "targetProcesses": 2, "currentAuthority": value["workers"][-1]["record"]["authority"]["status"], "releasedResult": value["workers"][-1]["record"]["releasedResult"], "priorAuthenticEffect": bool(prior["revision"]), "nativeRevision": final["revision"], "nativePhase": final["phase"], "targetStartup": "refused" if startup else "reopened", "recoveryDispatches": sum(len(worker["record"]["http"]) for worker in value["workers"][1:])}


def check_target_startup(case: dict[str, Any], value: dict[str, Any], refused: bool) -> None:
    """Distinguish native startup refusal from an authenticated prior completion."""
    result = value["targets"][1]["result"]
    reasons = {"target-key-after": "ticket key differs from consumer pin", "target-store-after": "ticket store is missing; initialization required", "target-rollback-after": "ticket history predates retained head"}
    if refused:
        same(result, {"status": "refused", "reason": reasons[case["id"]], "pid": value["targets"][1]["pid"]}, "target-startup-refusal")
        same(value["finalHttp"], None, "startup-no-http")
        same(value["final"], value["prior"], "startup-prior-effect-preserved")
        return
    signed_state(result["initial"], case)
    same(result["initial"], value["intermediate"], "target-reopened-state")


def concurrency(case: dict[str, Any], value: dict[str, Any]) -> None:
    """Require actual overlapping callers and one native completed revision."""
    calls = value["concurrentProbes"]
    same(len(calls), 8 if case["id"] == "concurrent-before" else 0, "concurrent-population")
    if not calls:
        return
    statuses = []
    for call in calls:
        response = http_record(call, case, value["targets"][1]["result"]["url"], True)
        statuses.append(call["status"])
        if call["status"] == 200:
            same(response, value["final"]["receipt"], "concurrent-completion")
        else:
            same([call["status"], response], [409, {"status": "refused", "reason": "ticket request, authority, state or framing differs"}], "concurrent-refusal")
    require(200 in statuses and 409 in statuses, "concurrent-mixed-outcomes")
    require(max(call["startedNs"] for call in calls) < min(call["endedNs"] for call in calls), "concurrent-overlap")


def original_records(root: Path, plan: dict[str, Any], case: dict[str, Any], value: dict[str, Any]) -> None:
    """Join duplicate projections to actual retained process and worker originals.

    Hash reselection cannot substitute a contradictory attempt projection for
    the captured worker/current/HTTP/process member. Every selected phase and
    argument must bind the actual launch, output member and target endpoint.
    """
    for phase, target in zip(("first", "second"), value["targets"], strict=True):
        same(load(root, "targets/" + case["id"] + "/" + phase + ".json"), target, "target-original-binding")
        target_argv(plan, case, target)
    for worker in value["workers"]:
        worker_original(root, case, worker)
        worker_argv(plan, case, value, worker)


def worker_original(root: Path, case: dict[str, Any], worker: dict[str, Any]) -> None:
    """Bind original worker/process/current/HTTP bytes to one phase projection."""
    phase, record = worker["phase"], worker["record"]
    folder = "workers/" + case["id"] + "/"
    same(load(root, folder + phase + ".json"), record, "worker-original-binding")
    same(load(root, folder + phase + ".process.json"), worker["process"], "worker-process-original-binding")
    same(load(root, folder + phase + "-current.json"), record["current"], "worker-current-original-binding")
    http_path = folder + phase + "-http.json"
    if record["http"]:
        same(load(root, http_path), record["http"], "worker-http-original-binding")
        return
    require(not (root / http_path).exists(), "worker-unexpected-http-original")


def worker_argv(plan: dict[str, Any], case: dict[str, Any], value: dict[str, Any], worker: dict[str, Any]) -> None:
    """Require exact case, target URL, phase, database, output and policy argv."""
    phase = worker["phase"]
    target = value["targets"][0 if phase == "first" else 1]
    endpoint = target["result"].get("url", value["targets"][0]["result"]["url"])
    capture = Path(plan["captureRoot"])
    folder = capture / "workers" / case["id"]
    expected = [plan["pythonExecutable"], str(Path(plan["adapterRoot"]) / "joint_worker.py"), str(capture / "cases" / (case["id"] + ".json")), endpoint, str(Path(plan["hostPrivateRoot"]) / case["id"] / "checkpoints.sqlite"), phase, str(folder / (phase + ".json")), str(folder / (phase + "-current.json"))]
    same(worker["process"]["command"], expected, "worker-launch-argv")


def target_argv(plan: dict[str, Any], case: dict[str, Any], target: dict[str, Any]) -> None:
    """Require the retained native target fault and exact selected launch argv."""
    ordinal = target["ordinal"]
    first = {"pending-intent-after": "after-intent", "pending-transaction-after": "inside-effect-transaction"}.get(case["id"], "none")
    fault = first if ordinal == 1 else "concurrent-window" if case["id"] == "concurrent-before" else "none"
    same(target["fault"], fault, "target-selected-fault")
    expected = [plan["pythonExecutable"], str(Path(plan["adapterRoot"]) / "joint_target.py"), str(Path(plan["hostPrivateRoot"]) / case["id"] / f"target-{ordinal}-private.json"), "--fault", fault]
    same(target["command"], expected, "target-launch-argv")


def verify_saved(root: Path, pins: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct originals without native framework, network or signing key.

    Parameters
    ----------
    root : pathlib.Path
        Retained original packet selected by the host.
    pins : dict
        Explicit external source/artifact/evaluation selections.

    Returns
    -------
    dict
        Complete selected-population report. Evidence publication can admit a
        report containing refusals; dispatch/release permission stays separate.

    Raises
    ------
    VerificationError
        If a byte pin, signature, native relation, process identity, authority,
        population, result-release boundary or explicit nonclaim differs.
    """
    require(not root.is_symlink() and not any(path.is_symlink() for path in root.rglob("*")), "packet-symlink")
    plan = selections(root, pins)
    records = []
    pids = []
    for case in plan["cases"]:
        same(load(root, "cases/" + case["id"] + ".json"), case, "case-plan-binding")
        value = load(root, "attempts/" + case["id"] + ".json")
        original_records(root, plan, case, value)
        pids.extend([item["pid"] for item in value["targets"]] + [item["process"]["pid"] for item in value["workers"]])
        records.append(verify_attempt(root, case, value))
    require(len(pids) == len(set(pids)), "within-run-pid-reuse")
    return {"profile": PROFILE, "status": "verified", "plannedAttempts": len(CASES), "workerProcesses": sum(row["workerProcesses"] for row in records), "targetProcesses": 2 * len(CASES), "releasedResults": sum(row["releasedResult"] for row in records), "priorAuthenticEffects": sum(row["priorAuthenticEffect"] for row in records), "pendingRefusals": 2, "startupRefusals": 3, "concurrentCallers": 8, "records": records, "witnessScope": "PEER", "doesNotAssert": NONCLAIMS, "authorityScope": HOST_POLICY["authorityBoundary"], "clockScope": HOST_POLICY["clockScope"], "nativeCheckpointScope": "distinct-hard-exiting-workers-native-SqliteSaver", "effectScope": "distinct-restarted-loopback-target-local-SQLite-row", "independentCustody": "not-established", "issuerAuthentication": "host-selected-local-key", "providerCalls": 0}


def verify_attempt(root: Path, case: dict[str, Any], value: dict[str, Any]) -> dict[str, Any]:
    """Log a bounded native refusal while preserving its exact verifier reason."""
    try:
        process_records(value, case)
        native_records(case, value)
        worker_http(case, value)
        concurrency(case, value)
        return target_state(root, case, value)
    except VerificationError as error:
        require(False, str(error))
        raise


def main() -> None:
    """Read a host-selected packet through the normally installed console script."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--pins-file", type=Path, required=True)
    args = parser.parse_args()
    sys.stdout.buffer.write(canonical(verify_saved(args.packet, load(args.pins_file.parent, args.pins_file.name))))


if __name__ == "__main__":
    main()
