"""Execute all eight selected authority transitions with real native workers."""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

from authority_common import BASE, CASES, PROFILE, authority, decode, encode, require, sha, write
from lg_run import environment, evidence_clock, exchange, retain_sources, select_case
from probity_observer.ticket_service import running_server


def child(case_file, endpoint, database, phase, output, current):
    """Keep complete stdout/stderr and bounded elapsed process receipts."""
    command = [sys.executable, str(Path(__file__).with_name("authority_worker.py")), str(case_file), endpoint, str(database), phase, str(output), str(current)]
    start = time.perf_counter_ns()
    result = subprocess.run(command, capture_output=True, timeout=30, check=False)
    receipt = {"command": command, "exitCode": result.returncode, "elapsedNs": time.perf_counter_ns() - start, "stdoutHex": result.stdout.hex(), "stderrHex": result.stderr.hex()}
    write(output.with_suffix(".process.json"), receipt)
    require(not result.stdout and not result.stderr, "worker-unexpected-output")
    return receipt


def execute(root, case, store):
    """Host selects replacement authority after first worker has actually exited."""
    folder = root / "workers" / case["id"]
    folder.mkdir(parents=True)
    database = folder / "checkpoints.sqlite"
    first_authority = folder / "first-authority.json"
    second_authority = folder / "second-authority.json"
    write(first_authority, authority(case))
    with running_server(store) as server:
        first_process = child(root / "cases" / (case["id"] + ".json"), server.url, database, "first", folder / "first.json", first_authority)
        require(first_process["exitCode"] == 73, "first-hard-exit")
        before_status, before, before_hex = exchange(server.url + "/tickets/tenant/" + case["id"])
        write(second_authority, authority(case, case["id"].split("-")[0]))
        second_process = child(root / "cases" / (case["id"] + ".json"), server.url, database, "second", folder / "second.json", second_authority)
        require(second_process["exitCode"] == 0, "second-worker-exit")
        final_status, final, final_hex = exchange(server.url + "/tickets/tenant/" + case["id"])
    return {"firstProcess": first_process, "secondProcess": second_process, "first": decode((folder / "first.json").read_bytes()), "second": decode((folder / "second.json").read_bytes()), "beforeStatus": before_status, "beforeReadback": before, "beforeReadbackHex": before_hex, "finalStatus": final_status, "finalReadback": final, "finalReadbackHex": final_hex}


def run(root: Path, revision: str):
    """Freeze policy/population/source selection before any worker executes."""
    from authority_reader import verify_saved
    require(importlib.metadata.version("langgraph") == "1.0.10" and importlib.metadata.version("langgraph-checkpoint-sqlite") == "3.1.1", "framework-version")
    root.mkdir(parents=True, exist_ok=False)
    run_id = "authority-" + uuid.uuid4().hex
    selections = [select_case(root, run_id, name) for name in CASES]
    sources = retain_sources(root)
    paths = [BASE / "durable_worker.py", *Path(__file__).parent.glob("authority_*.py")]
    for path in sorted(paths):
        raw = path.read_bytes()
        name = "adapter/" + path.name
        (root / "sources" / name).write_bytes(raw)
        sources[name] = sha(raw)
    write(root / "sources-before-run.json", sources)
    write(root / "environment-before-run.json", environment())
    policy = {"profile": PROFILE, "plannedAttempts": 8, "clockScope": "host-selected-deterministic-integer-clock", "maximumWorkerSeconds": 30, "authorityBoundary": "reopen-before-native-resume", "refusalOrder": ["clock-rollback", "revoked", "expired"], "allowCachedEffectWithInvalidAuthority": False}
    write(root / "host-policy-before-run.json", policy)
    plan = {"profile": PROFILE, "runId": run_id, "sourceRevision": revision, "selectedTime": evidence_clock().isoformat(), "cases": [case for case, _ in selections], "sourcesSha256": sha(encode(sources)), "environmentSha256": sha((root / "environment-before-run.json").read_bytes()), "policySha256": sha(encode(policy))}
    write(root / "plan-before-run.json", plan)
    for case, store in selections:
        write(root / "cases" / (case["id"] + ".json"), case)
        write(root / "attempts" / (case["id"] + ".json"), execute(root, case, store))
    manifest = {path.name: sha(path.read_bytes()) for path in sorted((root / "attempts").iterdir())}
    write(root / "artifact-manifest.json", manifest)
    pins = {"planSha256": sha(encode(plan)), "artifactManifestSha256": sha(encode(manifest)), "policySha256": sha(encode(policy)), "evaluationTime": evidence_clock().isoformat()}
    write(root / "consumer-pins.json", pins)
    report = verify_saved(root, pins)
    write(root / "report.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.output, args.source_revision), indent=2))
