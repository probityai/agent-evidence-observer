"""Execute a preregistered finite durable restart/recovery matrix."""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import sqlite3
import subprocess
import sys
import time
import uuid
from contextlib import closing
from pathlib import Path
from typing import Any

from lg_common import VERSION, decode, encode, require, sha, write
from lg_run import environment, evidence_clock, exchange, retain_sources, select_case
from probity_observer.crypto import VerificationError
from probity_observer.ticket_service import running_server

PROFILE = "probity-langgraph-durable-restart-v0"
CASES = ("restart-before", "restart-after", "crash-after-effect", "restart-pending", "missing-checkpoint", "wrong-thread")
SQLITE_VERSION = "3.1.1"


def child(case_file: Path, endpoint: str, database: Path, phase: str, output: Path) -> dict[str, Any]:
    """Start and wait for an actual separate worker with a finite timeout."""
    command = [sys.executable, str(Path(__file__).with_name("durable_worker.py")), str(case_file), endpoint, str(database), phase, str(output)]
    started = time.perf_counter_ns()
    result = subprocess.run(command, capture_output=True, timeout=30, check=False)
    require(not result.stdout and not result.stderr, "worker-unexpected-output")
    return {"exitCode": result.returncode, "elapsedNs": time.perf_counter_ns() - started}


def execute(output: Path, case: dict[str, Any], store: Any) -> dict[str, Any]:
    """Hard-exit graph workers, reopen durable state and retain refusal controls."""
    name = case["id"]
    directory = output / "workers" / name
    directory.mkdir(parents=True)
    case_file = output / "cases" / (name + ".json")
    database = directory / "checkpoints.sqlite"
    if name == "restart-pending":
        def fault(point: str) -> None:
            if point == "after-intent":
                raise VerificationError("selected interruption after durable intent")
        store.crash_hook = fault
    with running_server(store) as server:
        first = child(case_file, server.url, database, "first", directory / "first.json")
        require(first["exitCode"] == (74 if name == "crash-after-effect" else 73), "first-hard-exit")
        pre_status, before, before_hex = exchange(server.url + "/tickets/tenant/" + name)
        with closing(sqlite3.connect(database)) as source, closing(sqlite3.connect(directory / "before-restart.sqlite")) as target:
            source.backup(target)
        if name == "missing-checkpoint":
            database.unlink()
        store.crash_hook = None
        second = child(case_file, server.url, database, "second", directory / "second.json")
        require(second["exitCode"] == 0, "second-worker-exit")
        final_status, final, final_hex = exchange(server.url + "/tickets/tenant/" + name)
    first_record = decode((directory / "first.json").read_bytes()) if (directory / "first.json").exists() else None
    first_http = decode((directory / "first-http.json").read_bytes()) if (directory / "first-http.json").exists() else []
    return {"firstProcess": first, "secondProcess": second, "firstLoaded": decode((directory / "first-loaded.json").read_bytes()), "first": first_record, "firstHttp": first_http, "second": decode((directory / "second.json").read_bytes()), "beforeStatus": pre_status, "beforeReadback": before, "beforeReadbackHex": before_hex, "finalStatus": final_status, "finalReadback": final, "finalReadbackHex": final_hex}


def run(output: Path, revision: str) -> dict[str, Any]:
    """Write selection before execution and independently replay original bytes."""
    from durable_reader import verify_saved
    require(importlib.metadata.version("langgraph") == VERSION, "framework-version")
    require(importlib.metadata.version("langgraph-checkpoint-sqlite") == SQLITE_VERSION, "sqlite-version")
    output.mkdir(parents=True, exist_ok=False)
    run_id = "durable-" + uuid.uuid4().hex
    selections = [select_case(output, run_id, name) for name in CASES]
    sources = retain_sources(output)
    for name in ("durable_run.py", "durable_reader.py", "durable_worker.py"):
        raw = Path(__file__).with_name(name).read_bytes()
        (output / "sources" / "adapter" / name).write_bytes(raw)
        sources["adapter/" + name] = sha(raw)
    write(output / "sources-before-run.json", sources)
    write(output / "environment-before-run.json", environment())
    plan = {"profile": PROFILE, "frameworkVersion": VERSION, "sqliteVersion": SQLITE_VERSION, "runId": run_id, "sourceRevision": revision, "selectedTime": evidence_clock().isoformat(), "cases": [case for case, _ in selections], "sourcesSha256": sha(encode(sources)), "environmentSha256": sha((output / "environment-before-run.json").read_bytes()), "graph": {"checkpointer": "SqliteSaver", "durability": "sync", "nodes": ["dispatch"], "recursionLimit": 4, "workerTimeoutSeconds": 30, "providerCalls": 0}}
    write(output / "plan-before-run.json", plan)
    for case, store in selections:
        write(output / "cases" / (case["id"] + ".json"), case)
        write(output / "attempts" / (case["id"] + ".json"), execute(output, case, store))
    manifest = {p.name: sha(p.read_bytes()) for p in sorted((output / "attempts").iterdir())}
    write(output / "artifact-manifest.json", manifest)
    pins = {"planSha256": sha(encode(plan)), "artifactManifestSha256": sha(encode(manifest)), "evaluationTime": evidence_clock().isoformat()}
    write(output / "consumer-pins.json", pins)
    report = verify_saved(output, pins)
    write(output / "report.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.output, args.source_revision), indent=2))
