"""Framework-free reader joining recovery authority, native state and signed effect."""
from __future__ import annotations

import argparse
import json
from datetime import timezone
from pathlib import Path

from authority_common import CASES, PROFILE, authority, decode, encode, read, require, sha, validate
from lg_reader import aware_time, checkpoint_identity, effect_packet, same, selection, snapshot_state
from probity_observer.crypto import canonical


def process(value):
    """Refuse nonnative process outcomes and mixed first/recovery identities."""
    same(value["firstProcess"]["exitCode"], 73, "first-hard-exit")
    same(value["secondProcess"]["exitCode"], 0, "second-worker-exit")
    first, second = value["first"]["pid"], value["second"]["pid"]
    require(type(first) is int and type(second) is int and first > 0 and second > 0 and first != second, "distinct-processes")
    for item in (value["firstProcess"], value["secondProcess"]):
        require(type(item["elapsedNs"]) is int and 0 <= item["elapsedNs"] <= 30_000_000_000, "resource-elapsed")
        same([item["stdoutHex"], item["stderrHex"]], ["", ""], "worker-unexpected-output")


def native(case, value, selected, now):
    """Pin recovered snapshot to literal pre-exit native checkpoint and parents."""
    first, second = value["first"], value["second"]
    same(first["status"], "interrupted", "first-interrupted")
    same(first["loaded"]["values"], {}, "first-empty-values")
    same(first["loaded"]["next"], [], "first-empty-next")
    same(second["loaded"], first["snapshot"], "reopened-checkpoint")
    history = list(reversed(first["history"]))
    require(len(history) == 2, "native-history-population")
    thread = case["request"]["run_id"] + "/" + case["id"]
    for snapshot, step in zip(history, (-1, 0), strict=True):
        checkpoint_identity(snapshot, thread, step, selected, now)
    same(history[0]["parent_config"], None, "native-root-parent")
    same(history[1]["parent_config"], history[0]["config"], "native-history-parent")
    same(history[1], first["snapshot"], "native-pre-exit-snapshot")
    same(history[1]["values"], {"contentHex": case["graphInputHex"], "result": {}}, "native-input-values")
    same(history[1]["next"], ["dispatch"], "native-pending-dispatch")
    interrupt = {"point": "before-dispatch" if case["id"].endswith("before") else "after-effect", "caseId": case["id"]}
    if first["http"]:
        interrupt["httpSha256"] = sha(encode(first["http"][0]))
    require(len(first["snapshot"]["interrupts"]) == 1, "native-interrupt-population")
    same(first["snapshot"]["interrupts"][0]["value"], interrupt, "native-interrupt-binding")


def http(case, value, now, status):
    """Authenticate every retained effect independently of current recovery right."""
    first, second = value["first"], value["second"]
    before_count = 1 if case["id"].endswith("after") else 0
    same([len(first["http"]), len(second["http"])], [before_count, 1 if status == "authorized" else 0], "dispatch-population")
    for item in [*first["http"], *second["http"]]:
        require(item["endpoint"].startswith("http://127.0.0.1:") and item["endpoint"].removeprefix("http://127.0.0.1:").isdigit(), "http-loopback")
        effect_packet(case, item, now)
        for field, parsed in (("postRequestHex", item["candidate"]), ("postResponseHex", item["response"]), ("getResponseHex", item["readback"])):
            require(bytes.fromhex(item[field]) == canonical(parsed), "http-literal-bytes")
    for prefix in ("before", "final"):
        same(value[prefix + "Status"], 200, "readback-status")
        require(bytes.fromhex(value[prefix + "ReadbackHex"]) == canonical(value[prefix + "Readback"]), "readback-literal-bytes")
        snapshot_state(case, value[prefix + "Readback"])
    same(value["beforeReadback"], first["http"][-1]["readback"] if before_count else case["initial"], "before-effect")
    same(value["finalReadback"], second["http"][-1]["readback"] if second["http"] else value["beforeReadback"], "final-effect")
    if before_count:
        same(value["beforeReadback"], value["finalReadback"], "committed-effect-preserved")


def attempt(root, plan, manifest, case, selected, now):
    """Reconstruct current host authority using independently selected policy."""
    selection(case, plan["runId"], now.astimezone(timezone.utc).replace(microsecond=0))
    raw = read(root / "attempts", case["id"] + ".json")
    require(sha(raw) == manifest[case["id"] + ".json"], "artifact-pin")
    value = decode(raw)
    process(value)
    first, second = value["first"], value["second"]
    same(first["authority"], {"current": authority(case), "priorClock": 0, "status": "authorized"}, "first-authority")
    current = authority(case, case["id"].split("-")[0])
    status = validate(current, authority(case)["actionSha256"], 100)
    same(second["authority"], {"current": current, "priorClock": 100, "status": status}, "recovery-authority")
    same(second["status"], "completed" if status == "authorized" else status, "recovery-disposition")
    native(case, value, selected, now)
    http(case, value, now.astimezone(timezone.utc).replace(microsecond=0), status)
    completed(case, value, selected, now, status)
    return {"attemptId": case["id"], "recoveryAuthority": status, "freshRecoveryDispatches": len(second["http"]), "retainedNativeRevision": value["finalReadback"]["revision"], "existingCommit": "preserved" if case["id"].endswith("after") else "absent-before-recovery", "workerExitCodes": [73, 0]}


def completed(case, value, selected, now, status):
    """Refusals return no graph completion; permitted resumes retain native result."""
    second = value["second"]
    if status != "authorized":
        require(set(second) == {"pid", "loaded", "authority", "http", "status"}, "refused-no-result")
        return
    history = list(reversed(second["history"]))
    require(len(history) == 3, "completed-history-population")
    thread = case["request"]["run_id"] + "/" + case["id"]
    for snapshot, step in zip(history, (-1, 0, 1), strict=True):
        checkpoint_identity(snapshot, thread, step, selected, now)
    for index in (1, 2):
        same(history[index]["parent_config"], history[index - 1]["config"], "completed-history-parent")
    item = second["http"][0]
    expected = {"contentHex": case["graphInputHex"], "result": {"httpSha256": sha(encode(item)), "postStatus": item["postStatus"], "revision": item["readback"]["revision"]}}
    same(second["result"], expected, "completed-result")
    same(second["snapshot"], history[-1], "completed-snapshot")
    same(history[-1]["values"], expected, "completed-native-result")
    same(history[-1]["next"], [], "completed-next")


def selections(root, pins):
    """Require caller's literal plan/artifact/policy pins and exact finite profile."""
    require(set(pins) == {"planSha256", "artifactManifestSha256", "policySha256", "evaluationTime"}, "consumer-pin-fields")
    records = []
    for name, pin in (("plan-before-run.json", "planSha256"), ("artifact-manifest.json", "artifactManifestSha256"), ("host-policy-before-run.json", "policySha256")):
        raw = read(root, name)
        require(sha(raw) == pins[pin], "consumer-" + pin)
        records.append(decode(raw))
    plan, manifest, policy = records
    same(policy, {"profile": PROFILE, "plannedAttempts": 8, "clockScope": "host-selected-deterministic-integer-clock", "maximumWorkerSeconds": 30, "authorityBoundary": "reopen-before-native-resume", "refusalOrder": ["clock-rollback", "revoked", "expired"], "allowCachedEffectWithInvalidAuthority": False}, "host-policy")
    same(plan["profile"], PROFILE, "profile")
    same(plan["policySha256"], pins["policySha256"], "policy-plan-binding")
    same([case["id"] for case in plan["cases"]], list(CASES), "planned-population")
    require(set(manifest) == {name + ".json" for name in CASES}, "artifact-population")
    require({path.name for path in (root / "attempts").iterdir()} == set(manifest), "artifact-file-population")
    return plan, manifest


def sources(root, plan):
    """Check literal adapter/base source and installed framework selections."""
    raw = read(root, "sources-before-run.json")
    require(sha(raw) == plan["sourcesSha256"], "source-manifest")
    source = decode(raw)
    expected = {"adapter/" + name for name in ("lg_common.py", "lg_run.py", "lg_reader.py", "durable_worker.py", "authority_common.py", "authority_worker.py", "authority_run.py", "authority_reader.py")} | {"observer/" + name for name in ("aae_ticket.py", "aae_enforce.py", "authorization.py", "crypto.py", "ticket_service.py")}
    require(set(source) == expected, "source-population")
    require({str(p.relative_to(root / "sources")) for p in (root / "sources").rglob("*") if p.is_file()} == expected, "source-file-population")
    for name, digest in source.items():
        require(sha(read(root / "sources", name)) == digest, "source-pin")
    environment = read(root, "environment-before-run.json")
    require(sha(environment) == plan["environmentSha256"], "environment-pin")
    packages = decode(environment)["packages"]
    same([packages["langgraph"]["version"], packages["langgraph-checkpoint-sqlite"]["version"]], ["1.0.10", "3.1.1"], "framework-selection")


def verify_saved(root: Path, pins: dict):
    """No framework, SQLite or network operations while reading bounded originals."""
    require(not root.is_symlink() and not any(p.is_symlink() for p in root.rglob("*")), "packet-symlink")
    plan, manifest = selections(root, pins)
    sources(root, plan)
    selected = aware_time(plan["selectedTime"], "selected-time")
    now = aware_time(pins["evaluationTime"], "evaluation-time")
    require(now >= selected, "evaluation-time")
    records = [attempt(root, plan, manifest, case, selected, now) for case in plan["cases"]]
    return {"profile": PROFILE, "status": "verified", "plannedAttempts": 8, "records": records, "clockScope": "host-selected-deterministic-integer-clock", "authorityScope": "host-selected-action-bound-recovery-policy-before-resume", "checkpointScope": "native-SqliteSaver-distinct-hard-exiting-workers", "effectScope": "selected-loopback-service-local-SQLite-row", "targetProcessRestart": "not-exercised", "powerLoss": "not-exercised", "independentCustody": "not-established", "issuerAuthentication": "not-established", "exactlyOnce": "not-established", "providerCalls": 0, "inputTokens": 0, "outputTokens": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--pins-file", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify_saved(args.output, decode(args.pins_file.read_bytes())), indent=2))
