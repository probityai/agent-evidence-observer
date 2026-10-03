"""Finite native Pydantic hard-exit/reopen population with retained originals."""
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
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant
from probity_observer.crypto import SigningKey, canonical
from probity_observer.ticket_service import TicketStore

from probity_pydantic_recovery.common import (
    CASES,
    NONCLAIMS,
    PROFILE,
    child_environment,
    load,
    messages,
    require,
    sha,
    write,
)

ACTIVE: list[subprocess.Popen[bytes]] = []


def interrupted(signum: int, frame: Any) -> None:
    """Unwind the owned run on SIGTERM so its finally block can reap children."""
    raise SystemExit(128 + signum)


def cleanup() -> None:
    """Reap every owned process, including after a failed assertion."""
    for process in ACTIVE:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=3)
    ACTIVE.clear()


def launch(command: list[str]) -> subprocess.Popen[bytes]:
    """Launch an isolated owned process with the recorded environment allowlist."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, env=child_environment())
    ACTIVE.append(process)
    return process


def complete(process: subprocess.Popen[bytes], command: list[str], expected: int) -> dict[str, Any]:
    """Join the actual exit, PID and original process output."""
    stdout, stderr = process.communicate(timeout=30)
    require(process.returncode == expected, "process-exit:" + str(process.returncode) + ":" + stderr.decode(errors="replace")[-1000:])
    return {"pid": process.pid, "argv": command, "returncode": process.returncode, "stdoutHex": stdout.hex(), "stderrHex": stderr.hex(), "environment": child_environment()}


def target(private: Path, store: TicketStore, head: dict[str, Any], phase: str, clock: str | None, changed_key: bool = False) -> tuple[subprocess.Popen[bytes], list[str], dict[str, Any]]:
    """Wait for actual native readiness or an explicit authenticated-store refusal."""
    config, ready, refusal = (private / (phase + suffix) for suffix in ("-config.json", "-ready.json", "-refusal.json"))
    key = SigningKey.generate() if changed_key else store.key
    secret = key.private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
    write(config, {"store": str(store.path), "request": asdict(store.request), "policy": asdict(store.policy), "privateHex": secret, "retainedHead": head, "clockTime": clock, "ready": str(ready), "refusal": str(refusal), "auditDirectory": str(private / (phase + "-http-events"))})
    config.chmod(0o600)
    command = [sys.executable, str(Path(__file__).with_name("recovery_target.py")), str(config)]
    process = launch(command)
    deadline = time.monotonic() + 10
    while not ready.exists() and not refusal.exists() and process.poll() is None:
        require(time.monotonic() < deadline, "target-startup-timeout")
        time.sleep(0.02)
    result = load(ready if ready.exists() else refusal)
    require(result["pid"] == process.pid, "target-pid")
    return process, command, result


def stop_target(process: subprocess.Popen[bytes], command: list[str], ready: dict[str, Any]) -> dict[str, Any]:
    """Retain the target's exit and startup result."""
    expected = 78 if ready.get("status") == "refused" else -signal.SIGTERM
    if expected != 78:
        process.send_signal(signal.SIGTERM)
    return {**complete(process, command, expected), "startup": ready}


def selection(private: Path, run_id: str, name: str, now: datetime) -> tuple[dict[str, Any], TicketStore]:
    """Initialize one target and separate issuer/service keys before native execution."""
    issuer, service = SigningKey.generate(), SigningKey.generate()
    request = ActionRequest(run_id, name, "request-" + name, "tenant", "principal", "ticket-update", "/work/tickets/" + name, sha(b"DONE"))
    policy = GrantPolicy(issuer.public_hex)
    grant = issue_grant(request, issuer, issued_at=now, expires_at=now + timedelta(seconds=240))
    store = TicketStore(private / "target.sqlite", request, policy, service, clock=lambda: now)
    initial = store.initialize()
    shutil.copyfile(store.path, private / "initial.sqlite")
    return {"id": name, "request": asdict(request), "policy": asdict(policy), "serviceKey": service.public_hex, "grant": grant, "contentHex": b"DONE".hex(), "historicalTime": now.isoformat(), "initial": initial}, store


def worker(case: dict[str, Any], root: Path, endpoint: str, phase: str, current: Path | None = None) -> dict[str, Any]:
    """Capture a real native Pydantic worker's distinct OS process and terminal."""
    command = [sys.executable, str(Path(__file__).with_name("recovery_worker.py")), phase, str(root / "case.json"), endpoint, str(root)]
    if current is not None:
        command += ["--current", str(current)]
    return complete(launch(command), command, 74 if phase == "first" else 0)


def change_target(case: dict[str, Any], store: TicketStore, private: Path, retained: dict[str, Any]) -> dict[str, Any]:
    """Apply declared host changes only after the first worker and target exit."""
    if case["id"] == "revoked":
        store.revoke()
        retained = store.readback()["receipt"]
    elif case["id"] == "missing-store":
        store.path.unlink()
    elif case["id"] == "rollback-store":
        shutil.copyfile(private / "initial.sqlite", store.path)
    return retained


def current_selection(case: dict[str, Any], root: Path, ready: dict[str, Any], live: dict[str, Any] | None) -> dict[str, Any]:
    """Select recovery time and exact live target receipt outside native workers."""
    history = (root / "history.json").read_bytes()
    if case["id"] == "changed-arguments":
        altered = messages(history)
        altered[1]["parts"][0]["args"] = {"content": "CHANGED"}
        history = json.dumps(altered, separators=(",", ":")).encode()
    write(root / "recovery-history.json", history, raw=True)
    grant = dict(case["grant"])
    if case["id"] == "changed-grant":
        grant["signature"] = "0" * len(grant["signature"])
    clock = case["grant"]["expiresAt"].replace("Z", "+00:00") if case["id"] == "expired" else datetime.now(UTC).replace(microsecond=0).isoformat()
    source = "fixture-exact-expiry" if case["id"] == "expired" else "host-system-utc"
    require(ready.get("initial") == live, "parent-live-startup-join")
    write(root / "parent-current-readback.json", live)
    return {"historySha256": sha(history), "grant": grant, "serviceKey": case["serviceKey"], "policy": case["policy"], "liveSha256": sha(canonical(live)), "clockTime": clock, "clockSource": source, "targetReady": ready.get("status") != "refused"}


def execute(root: Path, private: Path, case: dict[str, Any], store: TicketStore) -> None:
    """Join actual first-worker death, target reopen and current result admission."""
    root.mkdir()
    write(root / "case.json", case)
    process, command, ready = target(private, store, case["initial"]["receipt"], "first", case["historicalTime"])
    first = worker(case, root, ready["url"], "first")
    first_target = stop_target(process, command, ready)
    prior = store.readback()
    write(root / "parent-prior-readback.json", prior)
    shutil.copyfile(store.path, root / "committed.sqlite")
    required_head = change_target(case, store, private, prior["receipt"])
    write(root / "required-target-head.json", required_head)
    process, command, ready = target(private, store, required_head, "second", None, case["id"] == "target-key")
    live = None if ready.get("status") == "refused" else store.readback()
    current = current_selection(case, root, ready, live)
    selected = private / "current-host-selection.json"
    write(selected, current)
    second = worker(case, root, ready.get("url", "refused-target"), "second", selected)
    second_target = stop_target(process, command, ready)
    write(root / "current-host-selection.json", current)
    write(root / "processes.json", {"workers": [first, second], "targets": [first_target, second_target]})
    for phase in ("first", "second"):
        write(root / (phase + "-target-http-events.json"), [load(path) for path in sorted((private / (phase + "-http-events")).glob("*.json"))])
    if store.path.exists() and case["id"] not in {"rollback-store", "target-key"}:
        write(root / "final-parent-readback.json", store.readback())


def capture_sources(root: Path) -> dict[str, str]:
    """Retain the selected native source and dependency closure before all cases."""
    import probity_observer
    import pydantic_ai
    paths = list(Path(__file__).parent.glob("recovery_*.py"))
    paths += list((Path(__file__).parent / "probity_pydantic_recovery").glob("*.py"))
    paths += list(Path(probity_observer.__file__).parent.glob("*.py"))
    paths += list(Path(pydantic_ai.__file__).parent.rglob("*.py"))
    paths += [Path(__file__).with_name("requirements.lock")]
    result = {}
    for ordinal, path in enumerate(sorted(paths)):
        name = "sources/" + str(ordinal) + "-" + path.name
        write(root / name, path.read_bytes(), raw=True)
        result[name] = sha(path.read_bytes())
    return result


def prepare_and_execute(root: Path, private: Path, revision: str) -> None:
    """Freeze native sources and selections before the first protected effect."""
    require(importlib.metadata.version("pydantic-ai-slim") == "1.68.0", "framework-version")
    now = datetime.now(UTC).replace(microsecond=0)
    run_id = "pydantic-recovery-" + uuid.uuid4().hex
    selections = []
    for name in CASES:
        directory = private / name
        directory.mkdir(mode=0o700)
        selections.append((directory, *selection(directory, run_id, name, now)))
    plan = {"profile": PROFILE, "sourceRevision": revision, "framework": "pydantic-ai-slim==1.68.0", "model": "scripted-FunctionModel", "cases": [case for _, case, _ in selections], "sources": capture_sources(root), "witnessScope": "PEER", "doesNotAssert": NONCLAIMS}
    write(root / "plan-before-run.json", plan)
    for directory, case, store in selections:
        execute(root / case["id"], directory, case, store)


def run(root: Path, revision: str) -> dict[str, Any]:
    """Clean private keys and owned processes even when preparation fails."""
    from probity_pydantic_recovery.reader import verify_saved
    root.mkdir(parents=True, exist_ok=False)
    private = root.parent / (root.name + "-private")
    private.mkdir(mode=0o700)
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        prepare_and_execute(root, private, revision)
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            cleanup()
        finally:
            try:
                shutil.rmtree(private)
            finally:
                signal.signal(signal.SIGTERM, previous)
    manifest = {str(path.relative_to(root)): sha(path.read_bytes()) for path in sorted(root.rglob("*")) if path.is_file()}
    write(root / "artifact-manifest.json", manifest)
    pins = {"profile": PROFILE, "planSha256": sha((root / "plan-before-run.json").read_bytes()), "artifactManifestSha256": sha(canonical(manifest))}
    write(root / "consumer-pins.json", pins)
    report = verify_saved(root, pins)
    write(root / "report.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    print(canonical(run(args.output, args.source_revision)).decode())
