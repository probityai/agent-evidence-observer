"""Framework-free reconstruction of native history, effects and admission."""
from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path
from typing import Any

from probity_observer.authorization import ActionRequest, GrantPolicy
from probity_observer.crypto import (
    VerificationError,
    canonical,
    strict_loads,
    verify_signature,
)
from probity_observer.ticket_service import DOMAIN, verify_ticket_result

from probity_pydantic_recovery.common import (
    CASES,
    NONCLAIMS,
    PROFILE,
    deferred,
    load,
    messages,
    read,
    require,
    sha,
)
from probity_pydantic_recovery.gate import admit


def population(root: Path, selected: dict[str, Any]) -> dict[str, Any]:
    """Admit the exact externally selected finite file/source population."""
    require(root.is_dir() and not root.is_symlink(), "packet-directory")
    require(not any(path.is_symlink() for path in root.rglob("*")), "packet-symlink")
    require(selected["profile"] == PROFILE, "selected-profile")
    require(selected["planSha256"] == sha(read(root / "plan-before-run.json")), "selected-plan")
    require(selected["artifactManifestSha256"] == sha(read(root / "artifact-manifest.json")), "selected-manifest")
    manifest = load(root / "artifact-manifest.json")
    actual = {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()}
    require(actual - {"artifact-manifest.json", "consumer-pins.json", "report.json"} == set(manifest), "artifact-population")
    require(len(manifest) < 3000, "file-population-bound")
    total = 0
    for name, digest in manifest.items():
        path = Path(name)
        require(not path.is_absolute() and ".." not in path.parts, "artifact-path")
        raw = read(root / path)
        total += len(raw)
        require(sha(raw) == digest, "artifact-hash")
    require(total < 128 * 1024 * 1024, "packet-byte-bound")
    plan = load(root / "plan-before-run.json")
    require(plan["profile"] == PROFILE and plan["framework"] == "pydantic-ai-slim==1.68.0" and plan["model"] == "scripted-FunctionModel", "plan-profile")
    require(plan["witnessScope"] == "PEER" and plan["doesNotAssert"] == NONCLAIMS, "claim-scope")
    require([case["id"] for case in plan["cases"]] == list(CASES), "case-population")
    require(all(manifest[name] == digest for name, digest in plan["sources"].items()), "source-manifest")
    return plan


def processes(record: dict[str, Any], case: dict[str, Any]) -> list[int]:
    """Check parent-recorded exits and their separately captured child identities."""
    workers, targets = record["workers"], record["targets"]
    require(len(workers) == len(targets) == 2, "process-population")
    require([p["returncode"] for p in workers] == [74, 0], "worker-exits")
    require([p["argv"][2] for p in workers] == ["first", "second"], "worker-phases")
    require(all(Path(p["argv"][3]).parent.name == case["id"] and Path(p["argv"][3]).name == "case.json" for p in workers), "worker-case-argv")
    require(all(p["environment"].get("OTEL_SDK_DISABLED") == "true" for p in workers + targets), "child-tracing")
    require(all(set(p["environment"]) <= {"PATH", "VIRTUAL_ENV", "PYTHONPATH", "LANG", "LC_ALL", "SYSTEMROOT", "OTEL_SDK_DISABLED", "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE"} for p in workers + targets), "child-environment-population")
    require(all(p["pid"] == p["startup"]["pid"] for p in targets), "target-pid-join")
    expected = 78 if case["id"] in {"target-key", "missing-store", "rollback-store"} else -15
    require([p["returncode"] for p in targets] == [-15, expected], "target-exits")
    ids = [p["pid"] for p in workers + targets]
    require(len(set(ids)) == 4 and all(type(i) is int and i > 0 for i in ids), "distinct-processes")
    return ids


def historical(root: Path, case: dict[str, Any]) -> dict[str, Any]:
    """Re-check the committed native store and signed retained prior effect."""
    from datetime import datetime
    prior = load(root / "parent-prior-readback.json")
    verified = verify_ticket_result(prior["receipt"], prior, ActionRequest(**case["request"]), GrantPolicy(**case["policy"]), case["serviceKey"], case["grant"], now=datetime.fromisoformat(case["historicalTime"]))
    database = root / "committed.sqlite"
    with sqlite3.connect(database.resolve().as_uri() + "?mode=ro&immutable=1", uri=True) as connection:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.set_progress_handler(lambda: 1, 10000)
        tables = connection.execute("SELECT name,type FROM sqlite_schema WHERE name IN ('tickets','state') ORDER BY name").fetchall()
        require(tables == [("state", "table"), ("tickets", "table")], "native-sqlite-schema")
        rows = connection.execute("SELECT tenant,ticket,content,revision,effect FROM tickets LIMIT 2").fetchall()
        state = strict_loads(connection.execute("SELECT record FROM state WHERE singleton=1").fetchone()[0])
    require(rows == [("tenant", case["id"], b"DONE", 1, prior["effectId"])], "native-committed-row")
    verify_signature(case["serviceKey"], DOMAIN, state["payload"], state["signature"])
    require(state["keyid"] == case["serviceKey"], "native-state-key")
    expected = {key: value for key, value in prior["receipt"]["payload"].items() if key not in {"request", "authorityKey", "witnessScope", "coverage"}}
    require(state["payload"] == expected, "native-committed-state")
    return verified


def resumed(root: Path, case: dict[str, Any], accepted: dict[str, Any], recovery: dict[str, Any]) -> None:
    """Bind new native tool return to the only accepted prior-result receipt."""
    initial = messages(read(root / "history.json"))
    history = messages(read(root / "resumed-history.json"))
    require(len(history) == 4 and history[:2] == initial, "native-continuation-history")
    part = history[2]["parts"]
    require(len(part) == 1 and part[0]["part_kind"] == "tool-return", "native-result-population")
    require(part[0]["tool_name"] == "dispatch_ticket" and part[0]["tool_call_id"] == accepted["toolCallId"] and part[0]["content"] == accepted["result"], "native-result-binding")
    require(len(history[3]["parts"]) == 1 and history[3]["parts"][0]["part_kind"] == "text" and history[3]["parts"][0]["content"] == "complete", "native-final-output")
    require(recovery["nativeModelRequests"] == 1 and recovery["output"] == "complete" and recovery["providerCalls"] == 0, "native-continuation-terminal")


def recovery_case(root: Path, case: dict[str, Any], process: dict[str, Any]) -> dict[str, Any]:
    """Recompute result admission or exact refusal without importing the SDK."""
    history = read(root / "history.json")
    call = deferred(history, case)
    require(load(root / "deferred.json") == {"calls": [{"toolCallId": call["tool_call_id"], "toolName": "dispatch_ticket", "arguments": {"content": "DONE"}}]}, "deferred-request-binding")
    verified = historical(root, case)
    current, recovery = load(root / "current-host-selection.json"), load(root / "recovery.json")
    require(recovery["pid"] == process["workers"][1]["pid"], "recovery-worker-pid")
    require(recovery["recoveryPosts"] == 0, "recovery-must-not-dispatch")
    target_requests(root, case, process)
    expected = decision(root, case, current, recovery)
    if expected is None:
        require(case["id"] != "permit", "permit-must-resume")
        require(recovery["status"] == "refused" and recovery["releasedResult"] is False and recovery["nativeModelRequests"] == 0, "refusal-must-not-resume")
        require(not (root / "accepted-host-receipt.json").exists() and not (root / "resumed-history.json").exists(), "refusal-artifact-population")
    else:
        require(case["id"] == "permit", "denied-case-must-not-resume")
        require(load(root / "accepted-host-receipt.json") == expected and expected["dispatchPermitted"] is False, "accepted-host-receipt-binding")
        require(recovery["status"] == "completed" and recovery["releasedResult"] is True, "resume-terminal")
        resumed(root, case, expected, recovery)
    final_readback(root, case)
    return {"id": case["id"], "priorEffect": verified, "firstExecution": "hard-exit-74", "recovery": recovery["status"], "releasedResult": recovery["releasedResult"], "recoveryPosts": 0, "nativeModelRequests": recovery["nativeModelRequests"]}


def target_requests(root: Path, case: dict[str, Any], process: dict[str, Any]) -> None:
    """Check target-owned HTTP events rather than only a worker zero counter."""
    first = load(root / "first-target-http-events.json")
    second = load(root / "second-target-http-events.json")
    expected_first = [{"method": "POST", "path": "/dispatch", "pid": process["targets"][0]["pid"]}, {"method": "GET", "path": "/tickets/tenant/" + case["id"], "pid": process["targets"][0]["pid"]}]
    require(sorted(first, key=lambda event: event["method"]) == sorted(expected_first, key=lambda event: event["method"]), "first-target-http-population")
    early_refusals = {"target-key", "missing-store", "rollback-store", "crash-window"}
    expected_second = [] if case["id"] in early_refusals else [{"method": "GET", "path": "/tickets/tenant/" + case["id"], "pid": process["targets"][1]["pid"]}]
    require(second == expected_second, "recovery-target-http-population")


def final_readback(root: Path, case: dict[str, Any]) -> None:
    """Authenticate required final state, allowing only declared host revocation."""
    path = root / "final-parent-readback.json"
    expected_presence = case["id"] not in {"target-key", "missing-store", "rollback-store"}
    require(path.is_file() == expected_presence, "final-readback-population")
    if not expected_presence:
        return
    prior, final = load(root / "parent-prior-readback.json"), load(path)
    require(set(final) == set(prior), "final-readback-schema")
    require({key: value for key, value in final.items() if key != "receipt"} == {key: value for key, value in prior.items() if key != "receipt"}, "final-native-effect-binding")
    receipt = final["receipt"]
    require(set(receipt) == {"payload", "keyid", "signature"} and receipt["keyid"] == case["serviceKey"], "final-receipt-envelope")
    verify_signature(case["serviceKey"], DOMAIN, receipt["payload"], receipt["signature"])
    final_payload(prior["receipt"]["payload"], receipt["payload"], case["id"])


def final_payload(prior: dict[str, Any], final: dict[str, Any], case_id: str) -> None:
    """Preserve effect identity and authority binding through the final readback."""
    if case_id != "revoked":
        require(final == prior, "final-receipt-effect-binding")
        return
    permitted = {"revoked", "eventCount", "eventHead"}
    require(set(final) == set(prior), "final-receipt-schema")
    require({key: value for key, value in final.items() if key not in permitted} == {key: value for key, value in prior.items() if key not in permitted}, "revoked-final-effect-binding")
    require(final["revoked"] is True and type(final["eventCount"]) is int and final["eventCount"] == prior["eventCount"] + 1, "final-revocation-state")
    require(type(final["eventHead"]) is str and len(final["eventHead"]) == 64 and all(c in "0123456789abcdef" for c in final["eventHead"]) and final["eventHead"] != prior["eventHead"], "final-revocation-history")


def decision(root: Path, case: dict[str, Any], current: dict[str, Any], recovery: dict[str, Any]) -> dict[str, Any] | None:
    """Reproduce the exact gate order and retain its truthful refusal reason."""
    try:
        require(current["targetReady"] is True, "current-target-not-ready")
        require((root / "prior-http.json").is_file(), "historical-http-journal-missing")
        return admit(case, read(root / "recovery-history.json"), load(root / "prior-http.json"), recovery["live"], current)
    except VerificationError as error:
        require(recovery.get("reason") == str(error), "refusal-reason-binding")
        return None


def reconstruct(root: Path, selected: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct the bounded author-operated profile from external byte pins."""
    plan = population(root, selected)
    records, identities = [], []
    for case in plan["cases"]:
        folder = root / case["id"]
        require(load(folder / "case.json") == case, "case-plan-join")
        process = load(folder / "processes.json")
        identities.extend(processes(process, case))
        records.append(recovery_case(folder, case, process))
    require(len(set(identities)) == len(identities), "global-process-identities")
    return {"profile": PROFILE, "status": "verified", "plannedAttempts": len(CASES), "freshWorkers": 18, "freshTargets": 18, "providerCalls": 0, "model": "scripted-FunctionModel", "records": records, "witnessScope": "PEER", "doesNotAssert": NONCLAIMS}


def verify_saved(root: Path, selected: dict[str, Any]) -> dict[str, Any]:
    """Convert malformed candidate representations to one bounded refusal."""
    try:
        return reconstruct(root, selected)
    except (KeyError, TypeError, IndexError, AttributeError, sqlite3.Error, RecursionError) as error:
        raise VerificationError("malformed-selected-packet") from error


def main() -> None:
    """Read a selected packet without importing the agent framework."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--pins-file", type=Path, required=True)
    args = parser.parse_args()
    print(canonical(verify_saved(args.packet, load(args.pins_file))).decode())


if __name__ == "__main__":
    main()
