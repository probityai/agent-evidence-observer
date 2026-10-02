"""Offline semantic reader of exact durable restart selections and native outputs."""
from __future__ import annotations

import argparse
import json
from datetime import timezone
from pathlib import Path
from typing import Any

from lg_common import decode, encode, read, require, sha
from lg_reader import aware_time, checkpoint_identity, effect_packet, same, selection, snapshot_state, task_identity
from probity_observer.authorization import ActionRequest, GrantPolicy, verify_grant
from probity_observer.crypto import canonical, digest
from probity_observer.ticket_service import DOMAIN, _time

PROFILE = "probity-langgraph-durable-restart-v0"
CASES = ("restart-before", "restart-after", "crash-after-effect", "restart-pending", "missing-checkpoint", "wrong-thread")
REFUSALS = {"missing-checkpoint", "wrong-thread"}
BEFORE = {"restart-before", *REFUSALS}


def pending(case: dict, item: dict, now: Any) -> None:
    """Authenticate durable intent while refusing to classify it as completion."""
    state = snapshot_state(case, item["readback"])
    same(item["postStatus"], 409, "pending-response-status")
    require(item["response"].get("status") == "refused" and state["phase"] == "pending" and state["eventCount"] == 2, "pending-state")
    same(state["revision"], 0, "pending-revision")
    require(item["readback"]["contentHex"] is None, "pending-native-content")
    request, policy = ActionRequest(**case["request"]), GrantPolicy(**case["policy"])
    authorized = verify_grant(case["grant"], request, policy, now=_time(state["intentTime"]))
    require(now >= _time(state["intentTime"]) and state["grantDigest"] == authorized.grant_digest, "pending-grant")
    expected = digest(DOMAIN + "-effect", {"configuration": state["configuration"], "requestId": request.request_id, "grantDigest": authorized.grant_digest})
    require(state["effectId"] == expected, "pending-effect-identity")


def packet(case: dict, item: dict, now: Any) -> None:
    """Require literal HTTP joins and selected signed native completion/pending state."""
    same(item["candidate"], {"request": case["request"], "grant": case["grant"], "contentHex": case["graphInputHex"]}, "http-argument-binding")
    require(item["endpoint"].startswith("http://127.0.0.1:") and item["endpoint"].removeprefix("http://127.0.0.1:").isdigit(), "http-loopback")
    same(item["getStatus"], 200, "http-readback-status")
    for field, value in (("postRequestHex", item["candidate"]), ("postResponseHex", item["response"]), ("getResponseHex", item["readback"])):
        require(bytes.fromhex(item[field]) == canonical(value), "http-literal-bytes")
    if case["id"] == "restart-pending":
        pending(case, item, now)
    else:
        effect_packet(case, item, now)


def identity(case: dict, snapshot: dict, step: int, selected: Any, now: Any) -> None:
    """Validate native checkpoint identity, channels and task structure."""
    thread = case["request"]["run_id"] + "/" + case["id"]
    checkpoint_identity(snapshot, thread, step, selected, now)
    if step == -1:
        same(snapshot["values"], {}, "native-root-values")
        same(snapshot["next"], ["__start__"], "native-root-next")
        task_identity(snapshot["tasks"], "__start__")
    if step == 0:
        same(snapshot["values"], {"contentHex": case["graphInputHex"], "result": {}}, "native-input-values")
        same(snapshot["next"], ["dispatch"], "native-input-next")
        task_identity(snapshot["tasks"], "dispatch")
    if step == 1:
        same(snapshot["next"], [], "native-final-next")
        same(snapshot["tasks"], [], "native-final-tasks")
        same(snapshot["interrupts"], [], "native-final-interrupts")


def interrupted(case: dict, record: dict, calls: list, selected: Any, now: Any) -> None:
    """Bind native interrupt identity to exactly retained pre-exit HTTP bytes."""
    identity(case, record["snapshot"], 0, selected, now)
    value = {"caseId": case["id"], "point": "before-dispatch" if case["id"] in BEFORE else "after-effect"}
    if calls:
        value["httpSha256"] = sha(encode(calls[0]))
    interrupts = record["snapshot"]["interrupts"]
    require(len(interrupts) == 1 and isinstance(interrupts[0]["id"], str) and bool(interrupts[0]["id"]), "native-interrupt-population")
    same(interrupts[0]["value"], value, "native-interrupt-http-join")
    same(record["result"], {**record["snapshot"]["values"], "__interrupt__": interrupts}, "native-interrupt-result")
    same(record["snapshot"]["tasks"][0]["interrupts"], interrupts, "native-task-interrupt")
    same(record["snapshot"]["tasks"][0]["result"], None, "native-interrupted-task-result")
    same(record["http"], calls, "native-interrupt-calls")
    saved = list(reversed(record["history"]))
    require(len(saved) == 2, "native-pre-exit-history")
    identity(case, saved[0], -1, selected, now)
    same(saved[0]["parent_config"], None, "native-pre-exit-root")
    same(saved[1], record["snapshot"], "native-pre-exit-snapshot")
    same(saved[1]["parent_config"], saved[0]["config"], "native-pre-exit-parent")
    same(saved[0]["tasks"][0]["result"], saved[1]["values"], "native-pre-exit-input")


def completed_history(case: dict, record: dict, selected: Any, now: Any) -> None:
    """Reconstruct durable native checkpoint parents and exact graph result joins."""
    snapshots = list(reversed(record["history"]))
    require(len(snapshots) == 3, "native-history-population")
    for snapshot, step in zip(snapshots, (-1, 0, 1), strict=True):
        identity(case, snapshot, step, selected, now)
    require(snapshots[0]["parent_config"] is None, "native-history-root")
    ids = [s["config"]["configurable"]["checkpoint_id"] for s in snapshots]
    require(len(set(ids)) == 3, "native-history-identity")
    for index in (1, 2):
        same(snapshots[index]["parent_config"], snapshots[index - 1]["config"], "native-history-parent")
        require(aware_time(snapshots[index]["created_at"], "native-checkpoint-time") >= aware_time(snapshots[index - 1]["created_at"], "native-checkpoint-time"), "native-history-time")
    same(snapshots[0]["tasks"][0]["result"], snapshots[1]["values"], "native-input-task-result")
    item = record["http"][-1]
    result = {"httpSha256": sha(encode(item)), "postStatus": item["postStatus"], "revision": item["readback"]["revision"]}
    same(snapshots[2]["values"], {"contentHex": case["graphInputHex"], "result": result}, "native-http-join")
    same(snapshots[1]["tasks"][0]["result"], {"result": result}, "native-task-result")
    same(record["snapshot"], snapshots[2], "native-final-boundary")
    same(record["result"], snapshots[2]["values"], "native-final-result")
    same(record["loaded"]["config"], snapshots[1]["config"], "native-recovered-checkpoint")
    same(record["loaded"]["values"], snapshots[1]["values"], "native-recovered-values")
    same(record["loaded"]["interrupts"], snapshots[1]["interrupts"], "native-recovered-interrupts")


def process_records(name: str, value: dict) -> None:
    """Require hard exit, successful next worker and distinct process identities."""
    for process in (value["firstProcess"], value["secondProcess"]):
        require(type(process["elapsedNs"]) is int and process["elapsedNs"] >= 0, "resource-elapsed")
    same(value["firstProcess"]["exitCode"], 74 if name == "crash-after-effect" else 73, "first-hard-exit")
    same(value["secondProcess"]["exitCode"], 0, "second-worker-exit")
    first_pid, second_pid = value["firstLoaded"]["pid"], value["second"]["pid"]
    require(type(first_pid) is int and type(second_pid) is int and first_pid > 0 and second_pid > 0 and first_pid != second_pid, "distinct-processes")
    same(value["firstLoaded"]["snapshot"]["values"], {}, "initial-empty-checkpoint")
    same(value["firstLoaded"]["snapshot"]["next"], [], "initial-empty-checkpoint")


def http_records(case: dict, value: dict, now: Any) -> tuple[int, int]:
    """Check complete call populations and unchanged protected rows on replay."""
    name, second = case["id"], value["second"]
    initial = snapshot_state(case, case["initial"])
    require(initial["phase"] == "ready" and initial["eventCount"] == 1 and case["initial"]["contentHex"] is None, "initial-state")
    first_count, second_count = (0 if name in BEFORE else 1), (0 if name in REFUSALS else 1)
    require(len(value["firstHttp"]) == first_count and len(second["http"]) == second_count, "http-population")
    for item in [*value["firstHttp"], *second["http"]]:
        packet(case, item, now)
    for prefix in ("before", "final"):
        same(value[prefix + "Status"], 200, "http-final-status")
        require(bytes.fromhex(value[prefix + "ReadbackHex"]) == canonical(value[prefix + "Readback"]), "http-final-bytes")
        snapshot_state(case, value[prefix + "Readback"])
    same(value["beforeReadback"], value["firstHttp"][-1]["readback"] if first_count else case["initial"], "pre-restart-effect")
    same(value["finalReadback"], second["http"][-1]["readback"] if second_count else case["initial"], "final-restart-effect")
    if first_count:
        same(value["finalReadback"], value["beforeReadback"], "replayed-effect-unchanged")
        same(value["firstHttp"][0], second["http"][0], "cached-restart-response")
    return first_count, second_count


def recovery(case: dict, value: dict, selected: Any, now: Any) -> str:
    """Refuse absent state, otherwise bind durable reload to original checkpoint."""
    name, first, second = case["id"], value["first"], value["second"]
    if name != "crash-after-effect":
        require(first is not None and first["status"] == "interrupted", "first-interrupted-status")
        same(first["pid"], value["firstLoaded"]["pid"], "first-process-identity")
        interrupted(case, first, value["firstHttp"], selected, now)
    else:
        require(first is None, "hard-crash-no-return")
    if name in REFUSALS:
        same(second["status"], "refused-missing-checkpoint", "recovery-refusal")
        same(second["loaded"]["next"], [], "missing-checkpoint-no-task")
        same(second["loaded"]["values"], {}, "missing-checkpoint-no-values")
        return "refused-no-local-row"
    same(second["status"], "completed", "second-completed-status")
    identity(case, second["loaded"], 0, selected, now)
    if first is not None:
        same(second["loaded"], first["snapshot"], "durable-restart-snapshot")
    else:
        same(second["loaded"]["interrupts"], [], "crash-no-interrupt")
    completed_history(case, second, selected, now)
    return "incomplete-no-automatic-replay" if name == "restart-pending" else "verified-local-ticket-update"


def source_records(root: Path, plan: dict) -> None:
    """Verify the exact old/new adapter source population and dependency manifest."""
    raw = read(root, "sources-before-run.json")
    require(sha(raw) == plan["sourcesSha256"], "source-manifest-pin")
    sources = decode(raw)
    expected = {"adapter/" + name for name in ("lg_common.py", "lg_reader.py", "lg_run.py", "durable_run.py", "durable_reader.py", "durable_worker.py")} | {"observer/" + name for name in ("aae_ticket.py", "aae_enforce.py", "authorization.py", "crypto.py", "ticket_service.py")}
    require(set(sources) == expected, "source-population")
    require({str(p.relative_to(root / "sources")) for p in (root / "sources").rglob("*") if p.is_file()} == expected, "source-file-population")
    for name, pin in sources.items():
        require(sha(read(root / "sources", name)) == pin, "source-file-pin")
    env_raw = read(root, "environment-before-run.json")
    require(sha(env_raw) == plan["environmentSha256"], "environment-pin")
    environment = decode(env_raw)
    require(environment["packages"]["langgraph"]["version"] == "1.0.10" and environment["packages"]["langgraph-checkpoint-sqlite"]["version"] == "3.1.1", "environment-framework")


def verify_saved(root: Path, pins: dict[str, Any]) -> dict[str, Any]:
    """Read bounded selected files without framework, network or SQLite execution."""
    require(not root.is_symlink() and not any(p.is_symlink() for p in root.rglob("*")), "packet-symlink")
    require(set(pins) == {"planSha256", "artifactManifestSha256", "evaluationTime"}, "consumer-pin-fields")
    plan_raw, manifest_raw = read(root, "plan-before-run.json"), read(root, "artifact-manifest.json")
    require(sha(plan_raw) == pins["planSha256"], "consumer-plan-pin")
    require(sha(manifest_raw) == pins["artifactManifestSha256"], "consumer-artifact-pin")
    plan, manifest = decode(plan_raw), decode(manifest_raw)
    require(plan["profile"] == PROFILE and plan["frameworkVersion"] == "1.0.10" and plan["sqliteVersion"] == "3.1.1", "plan-profile")
    same(plan["graph"], {"checkpointer": "SqliteSaver", "durability": "sync", "nodes": ["dispatch"], "recursionLimit": 4, "workerTimeoutSeconds": 30, "providerCalls": 0}, "plan-graph")
    same([case["id"] for case in plan["cases"]], list(CASES), "plan-population")
    require(set(manifest) == {name + ".json" for name in CASES}, "artifact-population")
    require({p.name for p in (root / "attempts").iterdir()} == set(manifest), "artifact-file-population")
    source_records(root, plan)
    selected, now = aware_time(plan["selectedTime"], "selected-time"), aware_time(pins["evaluationTime"], "consumer-time")
    require(now >= selected, "consumer-time")
    records = [verify_attempt(root, plan, manifest, case, selected, now) for case in plan["cases"]]
    return {"profile": PROFILE, "status": "verified", "plannedAttempts": 6, "records": records, "checkpointScope": "native-SqliteSaver-distinct-process-sync-hard-exit-reopen", "effectScope": "selected-loopback-service-local-SQLite-row", "targetProcessRestart": "not-exercised", "powerLoss": "not-exercised", "independentCustody": "not-established", "issuerAuthentication": "not-established", "exactlyOnce": "not-established", "providerCalls": 0, "inputTokens": 0, "outputTokens": 0, "taskScope": "deterministic-real-framework-integration-control"}


def verify_attempt(root: Path, plan: dict, manifest: dict, case: dict, selected: Any, now: Any) -> dict:
    """Join one original attempt to authority, native recovery and observed effects."""
    selection(case, plan["runId"], now.astimezone(timezone.utc).replace(microsecond=0))
    raw = read(root / "attempts", case["id"] + ".json")
    require(sha(raw) == manifest[case["id"] + ".json"], "native-artifact-pin")
    value = decode(raw)
    process_records(case["id"], value)
    first_count, second_count = http_records(case, value, now.astimezone(timezone.utc).replace(microsecond=0))
    effect = recovery(case, value, selected, now)
    return {"attemptId": case["id"], "recoveryOutcome": "refused-missing-checkpoint" if case["id"] in REFUSALS else "recovered-durable-checkpoint", "effectOutcome": effect, "httpCalls": first_count + second_count, "nativeRevision": value["finalReadback"]["revision"], "workerExitCodes": [value["firstProcess"]["exitCode"], value["secondProcess"]["exitCode"]]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--pins-file", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify_saved(args.output, decode(args.pins_file.read_bytes())), indent=2))
