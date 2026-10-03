"""Freeze and run four native effect/checkpoint-gap and target-restart cases."""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "joint-recovery-2026-10-02"))
from joint_run import selected, current, start_target, stop_target, retain_sources, retain_native, communicate_worker  # noqa: E402
from crash_common import CASES, NONCLAIMS, POLICY, PROFILE, child_environment, load, require, sha, write  # noqa: E402
from probity_observer.crypto import canonical  # noqa: E402


def child(root, case, endpoint, database, phase, folder, selection):
    """Record literal argv, PID, streams and hard-exit status of a real child."""
    output = folder / (phase + ".json")
    command = [sys.executable, str(Path(__file__).with_name("crash_worker.py")),
               str(root / "cases" / (case["id"] + ".json")), endpoint, str(database), phase,
               str(output), str(selection)]
    started = time.monotonic_ns()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True, env=child_environment())
    stdout, stderr, timed_out = communicate_worker(process)
    receipt = {"command": command, "environment": child_environment(), "pid": process.pid,
               "timedOut": timed_out, "exitCode": process.returncode,
               "elapsedNs": time.monotonic_ns() - started, "stdoutHex": stdout.hex(), "stderrHex": stderr.hex()}
    write(folder / (phase + ".process.json"), receipt)
    require(not timed_out, "crash-window-worker-timeout")
    require(process.returncode == (74 if phase == "first" else 0), "crash-window-worker-exit")
    return {"phase": phase, "process": receipt, "record": load(folder, output.name)}


def snapshot(database, output):
    """Retain committed WAL state through SQLite's consistent backup API."""
    with closing(sqlite3.connect(database)) as source, closing(sqlite3.connect(output)) as target:
        source.backup(target)


def execute(root, private, case, store):
    """Restart both processes across a committed effect and unfinished node."""
    folder = root / "workers" / case["id"]
    folder.mkdir(parents=True)
    database = private / "checkpoints.sqlite"
    targets, workers = [], []
    head = case["initial"]["receipt"]
    for ordinal, phase in enumerate(("first", "second"), 1):
        process, target = start_target(private, case, store, ordinal, head, "none")
        targets.append(target)
        selection = folder / (phase + "-current.json")
        write(selection, current(case, phase, True, target["selectedServiceKey"]))
        try:
            workers.append(child(root, case, target["result"]["url"], database, phase, folder, selection))
        finally:
            stop_target(process, target)
            write(root / "targets" / case["id"] / (phase + ".json"), target)
        head = store.readback()["receipt"]
        if ordinal == 1:
            prior = store.readback()
            checkpoint = root / "native" / (case["id"] + "-before-recovery.sqlite")
            checkpoint.parent.mkdir(exist_ok=True)
            snapshot(database, checkpoint)
    for config in private.glob("target-*-private.json"):
        config.unlink()
    return {"targets": targets, "workers": workers, "prior": prior, "final": store.readback(),
            "beforeRecoverySnapshot": str(checkpoint.relative_to(root)),
            **retain_native(root, private, case, store, database)}


def run(root, revision):
    """Select the complete population and exact source/dependency bytes first."""
    from crash_reader import verify_saved
    require(importlib.metadata.version("langgraph") == "1.0.10" and importlib.metadata.version("langgraph-checkpoint-sqlite") == "3.1.1", "crash-window-framework-version")
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=False)
    private = root.parent / (root.name + "-host-private")
    private.mkdir(mode=0o700)
    run_id = "crash-window-" + uuid.uuid4().hex
    choices = []
    for name in CASES:
        folder = private / name
        folder.mkdir(mode=0o700)
        choices.append((selected(folder, run_id, name), folder))
    sources = retain_sources(root)
    for name in ("crash_common.py", "crash_worker.py", "crash_run.py", "crash_reader.py"):
        path = Path(__file__).with_name(name)
        destination = root / "sources" / "crash" / name
        destination.parent.mkdir(exist_ok=True)
        shutil.copyfile(path, destination)
        sources[str(destination.relative_to(root))] = sha(path.read_bytes())
    plan = {"profile": PROFILE, "runId": run_id, "sourceRevision": revision,
            "selectedTime": datetime.now(timezone.utc).isoformat(), "cases": [pair[0] for pair, _ in choices],
            "sources": sources, "environment": {"python": sys.version, "packages": {name: importlib.metadata.version(name) for name in ("langgraph", "langgraph-checkpoint-sqlite", "agent-evidence-observer", "cryptography")}},
            "witnessScope": "PEER", "doesNotAssert": NONCLAIMS, "hostPolicy": POLICY,
            "captureRoot": str(root), "hostPrivateRoot": str(private),
            "adapterRoot": str(Path(__file__).resolve().parent), "pythonExecutable": sys.executable}
    write(root / "plan-before-run.json", plan)
    for (case, store), folder in choices:
        write(root / "cases" / (case["id"] + ".json"), case)
        write(root / "attempts" / (case["id"] + ".json"), execute(root, folder, case, store))
    manifest = {str(path.relative_to(root)): sha(path.read_bytes()) for path in sorted(root.rglob("*")) if path.is_file()}
    write(root / "artifact-manifest.json", manifest)
    pins = {"profile": PROFILE, "planSha256": sha(canonical(plan)), "artifactManifestSha256": sha(canonical(manifest))}
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
