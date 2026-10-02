"""Offline consumer of selected LangGraph snapshots and signed HTTP effects.

This module imports neither LangGraph nor a network client at execution time.
The consumer must select plan/artifact pins separately from the packet. A pin
copied by the author is local selection, not an independent witness.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from lg_common import CASES, PROFILE, VERSION, decode, encode, read, require, sha
from probity_observer.aae_enforce import enforce_check, native_digest
from probity_observer.aae_ticket import _decision_commitment, ticket_transaction, verify_aae_ticket_result
from probity_observer.authorization import ActionRequest, GrantPolicy, verify_grant
from probity_observer.crypto import canonical, digest
from probity_observer.ticket_service import DOMAIN, _checked, _state_schema, _time


def same(actual: Any, expected: Any, reason: str) -> None:
    """Compare literal JSON types as well as values, refusing bool/int coercion."""
    require(encode(actual) == encode(expected), reason)


def selection(case: dict[str, Any], run_id: str, now: datetime) -> None:
    """Recompute frozen native mandate, exact action and committed configuration."""
    request, policy = ActionRequest(**case["request"]), GrantPolicy(**case["policy"])
    name = case["id"]
    require(request.run_id == run_id and request.attempt_id == name and request.request_id == "request-" + name, "selected-request-identity")
    require(request.tool_id == "ticket-update" and request.target_path == "/work/tickets/" + name and request.tenant_id == "tenant" and request.principal_id == "principal", "selected-request-target")
    require(case["contentHex"] == b'{"status":"DONE"}'.hex() and sha(bytes.fromhex(case["contentHex"])) == request.content_sha256, "selected-content")
    expected = b'{"status":"CHANGED"}'.hex() if name == "altered-argument" else case["contentHex"]
    require(case["graphInputHex"] == expected, "selected-graph-input")
    decision = case["decision"]
    same(decision["transaction"], ticket_transaction(request), "selected-transaction")
    actual = enforce_check(decision["mandate"], decision["transaction"])
    same(decision["record"], actual, "selected-native-decision")
    require(actual["verdict"] == ("DENY" if name == "deny" else "PERMIT"), "selected-native-verdict")
    require(native_digest("mandate", decision["mandate"]) == decision["pinned_mandate_digest"], "selected-mandate-pin")
    commitment = _decision_commitment(**decision, request=request, require_permit=False)
    same(case["configuration"], {"request": case["request"], "policy": case["policy"], "serviceKey": case["serviceKey"], "decisionDigest": commitment}, "selected-configuration")
    verify_grant(case["grant"], request, policy, now=now)


def snapshot_state(case: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    """Authenticate service state using the separately selected key and request."""
    require(set(snapshot) == {"tenantId", "ticketId", "contentHex", "revision", "effectId", "receipt"}, "readback-fields")
    state = _checked(snapshot["receipt"], case["serviceKey"])
    _state_schema(state, receipt=True)
    require(state["configuration"] == digest(DOMAIN + "-configuration", case["configuration"]), "readback-configuration")
    same(state["request"], case["request"], "readback-request")
    require(state["authorityKey"] == case["policy"]["issuer_key"] and not state["revoked"], "readback-authority")
    require(snapshot["tenantId"] == "tenant" and snapshot["ticketId"] == case["id"], "readback-identity")
    same(snapshot["revision"], state["revision"], "readback-revision")
    require(snapshot["effectId"] == state["effectId"], "readback-effect")
    require(state["witnessScope"] == "PEER" and state["coverage"] == "one-native-ticket-row-and-service-events", "readback-scope")
    return state


def aware_time(value: Any, reason: str) -> datetime:
    """Parse an aware ISO timestamp or refuse with one stable consumer reason.

    Parameters
    ----------
    value : object
        Retained timestamp; valid timezone offsets identify absolute instants.
    reason : str
        Error code for missing, malformed or timezone-naive timestamps.

    Returns
    -------
    datetime.datetime
        A timezone-aware instant. No local timezone or naive fallback is used.
    """
    require(isinstance(value, str), reason)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        require(False, reason)
    require(parsed.tzinfo is not None and parsed.utcoffset() is not None, reason)
    return parsed


def checkpoint_identity(snapshot: dict[str, Any], thread_id: str, step: int, selected_time: datetime, evaluation_time: datetime) -> str:
    """Check one native public snapshot identity and bounded step metadata."""
    created = aware_time(snapshot.get("created_at"), "native-checkpoint-time")
    require(selected_time <= created <= evaluation_time, "native-checkpoint-window")
    require(set(snapshot) == {"values", "next", "config", "metadata", "created_at", "parent_config", "tasks", "interrupts"}, "native-snapshot-fields")
    require(set(snapshot["config"]) == {"configurable"}, "native-snapshot-config")
    selected = snapshot["config"]["configurable"]
    require(set(selected) == {"thread_id", "checkpoint_ns", "checkpoint_id"}, "native-checkpoint-config")
    require(selected["thread_id"] == thread_id and selected["checkpoint_ns"] == "", "native-thread")
    require(isinstance(selected["checkpoint_id"], str) and bool(selected["checkpoint_id"]), "native-checkpoint-id")
    same(snapshot["metadata"]["step"], step, "native-step")
    same(snapshot["metadata"], {"source": "input" if step == -1 else "loop", "step": step, "parents": {}}, "native-metadata")
    require(all(task["error"] is None for task in snapshot["tasks"]), "native-task-error")
    return selected["checkpoint_id"]


def history(case: dict[str, Any], attempt: dict[str, Any], selected_time: datetime, evaluation_time: datetime) -> None:
    """Reconstruct complete one-node history, checkpoint links and exact channels."""
    thread_id = case["request"]["run_id"] + "/" + case["id"]
    same(attempt["config"], {"configurable": {"thread_id": thread_id}, "recursion_limit": 4}, "native-config")
    snapshots = list(reversed(attempt["history"]))
    require(len(snapshots) == 3, "native-history-population")
    ids = [checkpoint_identity(item, thread_id, step, selected_time, evaluation_time) for item, step in zip(snapshots, (-1, 0, 1), strict=True)]
    require(len(set(ids)) == 3 and snapshots[0]["parent_config"] is None, "native-history-root")
    for index in (1, 2):
        same(snapshots[index]["parent_config"], snapshots[index - 1]["config"], "native-history-parent")
        require(datetime.fromisoformat(snapshots[index]["created_at"]) >= datetime.fromisoformat(snapshots[index - 1]["created_at"]), "native-history-time")
    same(snapshots[0]["values"], {}, "native-root-values")
    same(snapshots[0]["next"], ["__start__"], "native-root-next")
    same(snapshots[1]["values"], {"contentHex": case["graphInputHex"], "result": {}}, "native-input-values")
    same(snapshots[1]["next"], ["dispatch"], "native-input-next")
    require(len(snapshots[1]["tasks"]) == 1 and snapshots[1]["tasks"][0]["name"] == "dispatch", "native-dispatch-task")
    same(snapshots[2]["next"], [], "native-final-next")
    same(snapshots[2]["tasks"], [], "native-final-tasks")
    require(not snapshots[0]["interrupts"] and not snapshots[2]["interrupts"], "native-terminal-interrupt")
    task_identity(snapshots[0]["tasks"], "__start__")
    task_identity(snapshots[1]["tasks"], "dispatch")
    same(snapshots[0]["tasks"][0]["result"], snapshots[1]["values"], "native-input-task-result")
    packet = attempt["http"][-1]
    result = {"httpSha256": sha(encode(packet)), "postStatus": packet["postStatus"], "revision": packet["readback"]["revision"]}
    same(snapshots[2]["values"], {"contentHex": case["graphInputHex"], "result": result}, "native-http-join")
    same(snapshots[1]["tasks"][0]["result"], {"result": result}, "native-task-result")
    boundaries(case, attempt, snapshots, selected_time, evaluation_time)


def task_identity(tasks: list[dict[str, Any]], name: str) -> None:
    """Require one original native task with exact public fields and path."""
    require(len(tasks) == 1, "native-task-population")
    task = tasks[0]
    require(set(task) == {"id", "name", "path", "error", "interrupts", "state", "result"}, "native-task-fields")
    require(isinstance(task["id"], str) and bool(task["id"]) and task["name"] == name, "native-task-identity")
    same(task["path"], ["__pregel_pull", name], "native-task-path")
    require(task["state"] is None and task["error"] is None, "native-task-state")


def boundaries(case: dict[str, Any], attempt: dict[str, Any], snapshots: list[dict[str, Any]], selected_time: datetime, evaluation_time: datetime) -> None:
    """Join original interruption snapshots to resume and resulting checkpoint."""
    interrupted = case["id"] in {"interrupt-before", "resume-after-effect"}
    records = attempt["boundaries"]
    require(len(records) == (2 if interrupted else 1), "native-boundary-population")
    require(records[0]["operation"] == "invoke", "native-initial-operation")
    for record in records:
        step = 0 if record["snapshot"]["next"] else 1
        checkpoint_identity(record["snapshot"], attempt["config"]["configurable"]["thread_id"], step, selected_time, evaluation_time)
    final = records[-1]
    same(final["snapshot"], snapshots[2], "native-final-boundary")
    same(final["result"], snapshots[2]["values"], "native-final-result")
    same(final["httpCalls"], 2 if case["id"] == "resume-after-effect" else 1, "native-http-call-count")
    if not interrupted:
        require(not snapshots[1]["interrupts"], "native-unplanned-interrupt")
        return
    require(final["operation"] == "resume", "native-resume-operation")
    first = records[0]
    expected_calls = 1 if case["id"] == "resume-after-effect" else 0
    same(first["httpCalls"], expected_calls, "native-interrupt-call-count")
    checkpoint_identity(first["snapshot"], attempt["config"]["configurable"]["thread_id"], 0, selected_time, evaluation_time)
    same(first["snapshot"]["config"], snapshots[1]["config"], "native-interrupt-checkpoint")
    same(first["snapshot"]["values"], snapshots[1]["values"], "native-interrupt-values")
    interrupts = first["snapshot"]["interrupts"]
    require(len(interrupts) == 1 and isinstance(interrupts[0]["id"], str), "native-interrupt-population")
    value = {"point": "after-effect" if expected_calls else "before-dispatch", "caseId": case["id"]}
    if expected_calls:
        value["httpSha256"] = sha(encode(attempt["http"][0]))
    same(interrupts[0]["value"], value, "native-interrupt-http-join")
    same(first["result"], {**snapshots[1]["values"], "__interrupt__": interrupts}, "native-interrupt-result")
    same(first["snapshot"]["tasks"][0]["interrupts"], interrupts, "native-task-interrupt")
    same(snapshots[1]["interrupts"], interrupts, "native-history-interrupt")
    expected = {**snapshots[1], "tasks": [{**snapshots[1]["tasks"][0], "result": None}]}
    same(first["snapshot"], expected, "native-interrupted-snapshot")


def http_effect(case: dict[str, Any], attempt: dict[str, Any], now: datetime) -> str:
    """Replay admission, authenticate each HTTP readback and retain incomplete effects."""
    name = case["id"]
    expected_count = 2 if name == "resume-after-effect" else 1
    require(len(attempt["http"]) == expected_count, "http-population")
    initial = snapshot_state(case, case["initial"])
    require(initial["phase"] == "ready" and initial["eventCount"] == 1 and case["initial"]["contentHex"] is None, "initial-state")
    for packet in attempt["http"]:
        same(packet["candidate"], {"request": case["request"], "grant": case["grant"], "contentHex": case["graphInputHex"]}, "http-argument-binding")
        require(packet["endpoint"].startswith("http://127.0.0.1:") and packet["endpoint"].removeprefix("http://127.0.0.1:").isdigit(), "http-loopback")
        same(packet["getStatus"], 200, "http-readback-status")
        require(bytes.fromhex(packet["postRequestHex"]) == canonical(packet["candidate"]), "http-request-bytes")
        require(bytes.fromhex(packet["postResponseHex"]) == canonical(packet["response"]), "http-response-bytes")
        require(bytes.fromhex(packet["getResponseHex"]) == canonical(packet["readback"]), "http-readback-bytes")
        effect_packet(case, packet, now)
    same(attempt["finalStatus"], 200, "http-final-status")
    require(bytes.fromhex(attempt["finalReadbackHex"]) == canonical(attempt["finalReadback"]), "http-final-bytes")
    same(attempt["finalReadback"], attempt["http"][-1]["readback"], "http-final-readback")
    if name == "resume-after-effect":
        same(attempt["http"][0], attempt["http"][1], "cached-resume-effect")
    return {"deny": "refused-no-local-row", "altered-argument": "refused-no-local-row", "pending-intent": "incomplete-no-automatic-replay"}.get(name, "verified-local-ticket-update")


def effect_packet(case: dict[str, Any], packet: dict[str, Any], now: datetime) -> None:
    """Require either selected completion, exact initial refusal or signed pending intent."""
    request, policy = ActionRequest(**case["request"]), GrantPolicy(**case["policy"])
    state = snapshot_state(case, packet["readback"])
    if case["id"] in {"deny", "altered-argument"}:
        same(packet["postStatus"], 409, "http-refusal-status")
        require(packet["response"].get("status") == "refused", "http-refusal-response")
        same(packet["readback"], case["initial"], "refusal-native-state")
        return
    if case["id"] == "pending-intent":
        same(packet["postStatus"], 409, "pending-response-status")
        require(packet["response"].get("status") == "refused" and state["phase"] == "pending" and state["eventCount"] == 2, "pending-state")
        same(state["revision"], 0, "pending-revision")
        require(packet["readback"]["contentHex"] is None, "pending-native-content")
        authorized = verify_grant(case["grant"], request, policy, now=_time(state["intentTime"]))
        require(now >= _time(state["intentTime"]) and state["grantDigest"] == authorized.grant_digest, "pending-grant")
        expected = digest(DOMAIN + "-effect", {"configuration": state["configuration"], "requestId": request.request_id, "grantDigest": authorized.grant_digest})
        require(state["effectId"] == expected, "pending-effect-identity")
        return
    same(packet["postStatus"], 200, "completion-response-status")
    verify_aae_ticket_result(**case["decision"], receipt=packet["response"], readback=packet["readback"], request=request, policy=policy, service_key=case["serviceKey"], grant=case["grant"], now=now)


def verify_saved(root: Path, pins: dict[str, Any]) -> dict[str, Any]:
    """Recompute finite graph and effect verdicts from separately selected pins.

    Parameters
    ----------
    root : pathlib.Path
        Packet directory containing original public native snapshots and HTTP
        results. Reading does not execute LangGraph or issue any HTTP request.
    pins : dict
        Consumer-selected plan and artifact-manifest SHA-256 values, plus an
        aware evaluation timestamp within the signed grant validity interval.

    Returns
    -------
    dict
        Per-attempt execution/effect classifications and explicit scope limits.
    """
    require(not root.is_symlink() and not any(p.is_symlink() for p in root.rglob("*")), "packet-symlink")
    require(set(pins) == {"planSha256", "artifactManifestSha256", "evaluationTime"}, "consumer-pin-fields")
    plan_raw, manifest_raw = read(root, "plan-before-run.json"), read(root, "artifact-manifest.json")
    require(sha(plan_raw) == pins["planSha256"], "consumer-plan-pin")
    require(sha(manifest_raw) == pins["artifactManifestSha256"], "consumer-artifact-pin")
    plan, manifest = decode(plan_raw), decode(manifest_raw)
    require(plan["profile"] == PROFILE and plan["frameworkVersion"] == VERSION, "plan-profile")
    same(plan["graph"], {"nodes": ["dispatch"], "edges": [["__start__", "dispatch"], ["dispatch", "__end__"]], "checkpointer": "InMemorySaver", "recursionLimit": 4, "providerCalls": 0}, "plan-graph")
    same([case["id"] for case in plan["cases"]], list(CASES), "plan-population")
    require(set(manifest) == {name + ".json" for name in CASES}, "artifact-population")
    require({p.name for p in (root / "attempts").iterdir()} == set(manifest), "artifact-file-population")
    verify_sources(root, plan)
    now = aware_time(pins["evaluationTime"], "consumer-time")
    selected_time = aware_time(plan.get("selectedTime"), "selected-time")
    require(now >= selected_time, "consumer-time")
    records = []
    for case in plan["cases"]:
        selection(case, plan["runId"], now)
        raw = read(root / "attempts", case["id"] + ".json")
        require(sha(raw) == manifest[case["id"] + ".json"], "native-artifact-pin")
        attempt = decode(raw)
        require(type(attempt["elapsedNs"]) is int and attempt["elapsedNs"] >= 0, "resource-elapsed")
        effect = http_effect(case, attempt, now)
        history(case, attempt, selected_time, now)
        records.append({"attemptId": case["id"], "status": "complete", "taskOutcome": "controlled-scenario-matched", "kernelVerdict": case["decision"]["record"]["verdict"], "effectOutcome": effect, "httpCalls": len(attempt["http"]), "nativeRevision": attempt["finalReadback"]["revision"], "elapsedNs": attempt["elapsedNs"]})
    return {"profile": PROFILE, "status": "verified", "plannedAttempts": 6, "records": records, "providerCalls": 0, "inputTokens": 0, "outputTokens": 0, "taskScope": "deterministic-real-framework-integration-control", "checkpointScope": "in-memory-same-process-native-snapshots", "effectScope": "selected-loopback-service-local-SQLite-row", "independentCustody": "not-established", "issuerAuthentication": "not-established", "exactlyOnce": "not-established", "priorSelection": "author-local-plan-consumer-must-select-pins", "peakMemoryBytes": None}


def verify_sources(root: Path, plan: dict[str, Any]) -> None:
    """Check the retained literal source population and installed runtime manifest."""
    raw = read(root, "sources-before-run.json")
    require(sha(raw) == plan["sourcesSha256"], "source-manifest-pin")
    sources = decode(raw)
    expected = {"adapter/" + name for name in ("lg_common.py", "lg_reader.py", "lg_run.py")} | {"observer/" + name for name in ("aae_ticket.py", "aae_enforce.py", "authorization.py", "crypto.py", "ticket_service.py")}
    require(set(sources) == expected, "source-population")
    require({str(p.relative_to(root / "sources")) for p in (root / "sources").rglob("*") if p.is_file()} == expected, "source-file-population")
    for name, pin in sources.items():
        require(sha(read(root / "sources", name)) == pin, "source-file-pin")
    env_raw = read(root, "environment-before-run.json")
    require(sha(env_raw) == plan["environmentSha256"], "environment-pin")
    environment = decode(env_raw)
    require(environment["packages"]["langgraph"]["version"] == VERSION, "environment-framework")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--pins-file", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify_saved(args.output, decode(args.pins_file.read_bytes())), indent=2))
