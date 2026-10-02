"""Execute the frozen joint worker/target/current-authority population."""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
import probity_observer
from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant, utc_clock
from probity_observer.crypto import SigningKey, canonical
from probity_observer.ticket_service import TicketStore

from joint_common import CASES, HOST_POLICY, NONCLAIMS, PROFILE, authority, child_environment, load, phases, require, sha, write

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "target-recovery-2026-10-02"))
from target_run import concurrent_dispatch, exchange  # noqa: E402


def selected(private: Path, run_id: str, name: str) -> tuple[dict[str, Any], TicketStore]:
    """Create one host-owned action and its distinct native signing identities.

    Parameters
    ----------
    private : pathlib.Path
        Private case directory, outside the public packet.
    run_id : str
        Frozen run identity shared by this selected population.
    name : str
        Literal selected case from :data:`joint_common.CASES`.

    Returns
    -------
    case : dict
        Public request, grant, policy, service key, initial receipt and opaque
        store identity. No private key or store path is returned in this record.
    store : TicketStore
        Existing merged native backend. Only this host creates it once.
    """
    issuer, service = SigningKey.generate(), SigningKey.generate()
    content = b'{"status":"DONE"}'
    request = ActionRequest(run_id, name, "request-" + name, "tenant", "principal", "ticket-update", "/work/tickets/" + name, sha(content))
    policy = GrantPolicy(issuer.public_hex, max_validity_seconds=3600)
    now = utc_clock()
    grant = issue_grant(request, issuer, issued_at=now, expires_at=now + timedelta(seconds=3600))
    store = TicketStore(private / "target.sqlite", request, policy, service, clock=lambda: now)
    initial = store.initialize()
    shutil.copyfile(store.path, private / "ready-backup.sqlite")
    return {"id": name, "request": asdict(request), "policy": asdict(policy), "serviceKey": service.public_hex, "grant": grant, "contentHex": content.hex(), "initial": initial, "storeIdentity": uuid.uuid4().hex, "clockTime": now.isoformat()}, store


def current(case: dict[str, Any], phase: str, target_ready: bool, selected_service_key: str | None = None) -> dict[str, Any]:
    """Supply a fresh host selection only after the preceding process exits.

    Exact original grant/key/store identity is required. Grant expiry uses the
    signed grant's precise exclusive boundary on the selected UTC clock; integer
    expiry and rollback independently exercise the merged durable clock gate.
    """
    name = case["id"]
    mode = name.rsplit("-", 1)[0] if phase == "second" else "valid"
    selection = {"grantSha256": sha(canonical(case["grant"])), "issuerPolicy": case["policy"], "serviceKey": case["serviceKey"], "storeIdentity": case["storeIdentity"]}
    changes = {
        "grant-mismatch": ("grantSha256", "0" * 64),
        "authority-key": ("issuerPolicy", {**case["policy"], "issuer_key": "0" * 64}),
        "target-key": ("serviceKey", selected_service_key or "0" * 64),
        "target-store": ("storeIdentity", "0" * 32),
    }
    if mode in changes:
        field, replacement = changes[mode]
        selection = {**selection, field: replacement}
    clock_time = datetime.fromisoformat(case["clockTime"])
    if mode == "grant-expired":
        clock_time += timedelta(seconds=3600)
    return {"authority": authority(case, mode), "selection": selection, "clockTime": clock_time.isoformat(), "targetReady": target_ready}


def target_config(private: Path, case: dict[str, Any], store: TicketStore, ordinal: int, head: dict[str, Any]) -> Path:
    """Write a mode-0600 launch selection, separate from retained public bytes."""
    path = private / f"target-{ordinal}-private.json"
    key = SigningKey.generate() if ordinal == 2 and case["id"] == "target-key-after" else store.key
    secret = key.private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
    clock_time = datetime.fromisoformat(case["clockTime"])
    if ordinal == 2 and case["id"].startswith(("expired-", "grant-expired-")):
        clock_time += timedelta(seconds=3600)
    write(path, {"store": str(store.path.resolve()), "request": case["request"], "policy": case["policy"], "servicePrivateHex": secret, "servicePublicHex": key.public_hex, "retainedHead": head, "clockTime": clock_time.isoformat(), "readyFile": str((private / f"ready-{ordinal}.json").resolve()), "refusalFile": str((private / f"refusal-{ordinal}.json").resolve())})
    path.chmod(0o600)
    return path


def start_target(private: Path, case: dict[str, Any], store: TicketStore, ordinal: int, head: dict[str, Any], fault: str) -> tuple[subprocess.Popen[bytes], dict[str, Any]]:
    """Launch a distinct HTTP OS process and wait for concrete readiness.

    Every process is bounded by the frozen startup budget. An exception during
    readiness stops and reaps the process immediately through :func:`stop_target`.
    """
    config = target_config(private, case, store, ordinal, head)
    command = [sys.executable, str(Path(__file__).with_name("joint_target.py")), str(config), "--fault", fault]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, env=child_environment())
    record: dict[str, Any] = {"ordinal": ordinal, "pid": process.pid, "fault": fault, "command": command, "environment": child_environment(), "selectedServiceKey": load(private, config.name)["servicePublicHex"]}
    deadline = time.monotonic() + HOST_POLICY["maximumTargetStartupSeconds"]
    ready, refusal = private / f"ready-{ordinal}.json", private / f"refusal-{ordinal}.json"
    try:
        while not ready.exists() and not refusal.exists() and process.poll() is None:
            require(time.monotonic() < deadline, "target-startup-timeout")
            time.sleep(0.02)
        record["result"] = load(private, ready.name if ready.exists() else refusal.name)
    except BaseException:
        stop_target(process, record)
        write(private / f"startup-cleanup-{ordinal}.json", record)
        raise
    return process, record


def stop_target(process: subprocess.Popen[bytes], record: dict[str, Any]) -> None:
    """Stop and reap an owned target, preserving original output and actual exit."""
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
    try:
        stdout, stderr = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=5)
    record.update(returncode=process.returncode, stdoutHex=stdout.hex(), stderrHex=stderr.hex())


def child(case_file: Path, endpoint: str, database: Path, phase: str, output: Path, selection: Path) -> dict[str, Any]:
    """Execute a bounded fresh graph worker and retain its literal process streams."""
    command = [sys.executable, str(Path(__file__).with_name("joint_worker.py")), str(case_file), endpoint, str(database), phase, str(output), str(selection)]
    started = time.monotonic_ns()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, env=child_environment())
    stdout, stderr, timed_out = communicate_worker(process)
    receipt = {"command": command, "environment": child_environment(), "pid": process.pid, "timedOut": timed_out, "exitCode": process.returncode, "elapsedNs": time.monotonic_ns() - started, "stdoutHex": stdout.hex(), "stderrHex": stderr.hex()}
    write(output.with_suffix(".process.json"), receipt)
    require(not timed_out, "worker-timeout")
    require(process.returncode == (73 if phase == "first" else 0), "worker-exit")
    return receipt


def communicate_worker(process: subprocess.Popen[bytes]) -> tuple[bytes, bytes, bool]:
    """Reap a bounded owned group even on timeout, retaining its actual streams."""
    try:
        stdout, stderr = process.communicate(timeout=HOST_POLICY["maximumWorkerSeconds"])
        return stdout, stderr, False
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=5)
        return stdout, stderr, True


def after_exit(case: dict[str, Any], store: TicketStore, private: Path) -> dict[str, Any]:
    """Retain prior state before host-only revocation or target identity controls."""
    prior = store.readback()
    if case["id"].startswith("revoked-"):
        store.revoke()
    if case["id"] == "target-store-after":
        store.path.unlink()
    if case["id"] == "target-rollback-after":
        shutil.copyfile(private / "ready-backup.sqlite", store.path)
    return prior


def first_fault(name: str) -> str:
    """Select only the two declared real target hard-exit transaction boundaries."""
    return {"pending-intent-after": "after-intent", "pending-transaction-after": "inside-effect-transaction"}.get(name, "none")


def retain_native(root: Path, private: Path, case: dict[str, Any], store: TicketStore, database: Path) -> dict[str, Any]:
    """Retain exact native files after all owned processes have exited.

    For startup identity refusals, the original authenticated before-exit state
    remains available separately. The missing/rolled-back target is never reset.
    """
    target = root / "native" / (case["id"] + "-target.sqlite")
    target.parent.mkdir(exist_ok=True)
    exists = store.path.exists()
    if exists:
        shutil.copyfile(store.path, target)
    checkpoint = root / "native" / (case["id"] + "-checkpoints.sqlite")
    shutil.copyfile(database, checkpoint)
    return {"targetSnapshot": str(target.relative_to(root)) if exists else None, "checkpointSnapshot": str(checkpoint.relative_to(root))}


def execute(root: Path, private: Path, case: dict[str, Any], store: TicketStore) -> dict[str, Any]:
    """Join actual worker exit, target exit, host reselection and native recovery.

    Parameters
    ----------
    root, private : pathlib.Path
        Public packet and separate private host directories respectively.
    case : dict
        Frozen action and scenario selection.
    store : TicketStore
        Native backend initialized exactly once by :func:`selected`.

    Returns
    -------
    dict
        Complete process identities, native snapshots, authority selections,
        literal HTTP responses, preserved prior state and concurrent probes.
    """
    folder = root / "workers" / case["id"]
    folder.mkdir(parents=True)
    database = private / "checkpoints.sqlite"
    process, target = start_target(private, case, store, 1, case["initial"]["receipt"], first_fault(case["id"]))
    targets, workers = [target], []
    try:
        write(folder / "first-current.json", current(case, "first", True))
        receipt = child(root / "cases" / (case["id"] + ".json"), target["result"]["url"], database, "first", folder / "first.json", folder / "first-current.json")
        workers.append({"phase": "first", "process": receipt, "record": load(folder, "first.json")})
    finally:
        stop_target(process, target)
        write(root / "targets" / case["id"] / "first.json", target)
    prior = after_exit(case, store, private)
    intermediate = store.readback() if case["id"] not in {"target-store-after", "target-rollback-after"} else prior
    process, target = start_target(private, case, store, 2, prior["receipt"], "concurrent-window" if case["id"] == "concurrent-before" else "none")
    targets.append(target)
    ready = target["result"].get("status") != "refused"
    endpoint = target["result"].get("url", targets[0]["result"]["url"])
    probes: list[dict[str, Any]] = []
    try:
        if case["id"] == "concurrent-before":
            probes = concurrent_dispatch(endpoint, {key: case[key] for key in ("request", "grant", "contentHex")})
        for phase in phases(case["id"])[1:]:
            write(folder / (phase + "-current.json"), current(case, phase, ready, target["selectedServiceKey"]))
            receipt = child(root / "cases" / (case["id"] + ".json"), endpoint, database, phase, folder / (phase + ".json"), folder / (phase + "-current.json"))
            workers.append({"phase": phase, "process": receipt, "record": load(folder, phase + ".json")})
        final_http = exchange(endpoint + "/tickets/tenant/" + case["id"]) if ready else None
    finally:
        stop_target(process, target)
        write(root / "targets" / case["id"] / "second.json", target)
        for config in private.glob("target-*-private.json"):
            config.unlink()
    recovery = store.recover() if case["id"].startswith("pending-") else None
    final = store.readback() if ready else prior
    return {"targets": targets, "workers": workers, "prior": prior, "intermediate": intermediate, "final": final, "finalHttp": final_http, "pendingRecovery": recovery, "concurrentProbes": probes, **retain_native(root, private, case, store, database)}


def retain_sources(root: Path) -> dict[str, str]:
    """Retain exact new adapter and reused merged backend/gate source bytes."""
    observer = Path(probity_observer.__file__).parent
    own = Path(__file__).parent
    groups = {
        "joint": [own / name for name in ("joint_common.py", "joint_run.py", "joint_worker.py", "joint_target.py", "joint_reader.py", "joint_host_gate.py")],
        "authority": [BASE / "langgraph-recovery-authority-2026-10-02" / name for name in ("authority_worker.py", "authority_common.py")],
        "langgraph": [BASE / "langgraph-ticket-2026-10-02" / name for name in ("lg_common.py", "lg_run.py", "durable_worker.py")],
        "target": [BASE / "target-recovery-2026-10-02" / name for name in ("target_common.py", "target_run.py")],
        "observer": [observer / name for name in ("authorization.py", "crypto.py", "ticket_service.py")],
    }
    manifest = {}
    for group, paths in groups.items():
        for path in paths:
            destination = root / "sources" / group / path.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(path.read_bytes())
            manifest[str(destination.relative_to(root))] = sha(path.read_bytes())
    return manifest


def run(root: Path, revision: str) -> dict[str, Any]:
    """Freeze source, host policy and finite population before any child launch.

    The original streams and databases remain outside Git. This function does
    not declare independent custody, remote caller identity or power-loss safety.
    """
    from joint_reader import verify_saved
    root = root.resolve()
    require(importlib.metadata.version("langgraph") == "1.0.10" and importlib.metadata.version("langgraph-checkpoint-sqlite") == "3.1.1", "framework-version")
    root.mkdir(parents=True, exist_ok=False)
    private = root.parent / (root.name + "-host-private")
    private.mkdir(mode=0o700)
    run_id = "joint-" + uuid.uuid4().hex
    selections = []
    for name in CASES:
        folder = private / name
        folder.mkdir(mode=0o700)
        selections.append((selected(folder, run_id, name), folder))
    sources = retain_sources(root)
    environment = {"python": sys.version, "packages": {name: importlib.metadata.version(name) for name in ("langgraph", "langgraph-checkpoint-sqlite", "agent-evidence-observer", "cryptography")}}
    plan = {"profile": PROFILE, "runId": run_id, "sourceRevision": revision, "selectedTime": datetime.now(timezone.utc).isoformat(), "cases": [pair[0] for pair, _ in selections], "sources": sources, "environment": environment, "witnessScope": "PEER", "doesNotAssert": NONCLAIMS, "hostPolicy": HOST_POLICY, "captureRoot": str(root.resolve()), "hostPrivateRoot": str(private.resolve()), "adapterRoot": str(Path(__file__).resolve().parent), "pythonExecutable": sys.executable}
    write(root / "plan-before-run.json", plan)
    for (case, store), folder in selections:
        write(root / "cases" / (case["id"] + ".json"), case)
        write(root / "attempts" / (case["id"] + ".json"), execute(root, folder, case, store))
    manifest = {str(path.relative_to(root)): sha(path.read_bytes()) for path in sorted(root.rglob("*")) if path.is_file()}
    write(root / "artifact-manifest.json", manifest)
    pins = {"profile": PROFILE, "planSha256": sha(canonical(plan)), "artifactManifestSha256": sha(canonical(manifest)), "evaluationTime": datetime.now(timezone.utc).isoformat()}
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
