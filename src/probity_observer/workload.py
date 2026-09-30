"""Run one Python workload behind the bounded host write broker."""

from __future__ import annotations

import hashlib
import os
import selectors
import shutil
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Sequence

from .broker import Broker, CoverageError, recover_interrupted, tree_root
from .crypto import SigningKey, VerificationError, canonical, digest, strict_loads, verify_signature
from .history import Witness, read_history, unresolved_intents
from .isolation import _WriteServer, observer_build_digest, sha256
from .verify import verify_incomplete, verify_packet

MAX_OUTPUT = 1_048_576
DEADLINE = 15


def workload_command(bwrap: Path, socket_dir: Path, interpreter: Path, script: Path, args: Sequence[str]) -> list[str]:
    """Mount the broker socket and script, but not the host work tree."""
    mounts = [item for item in ("/usr", "/bin", "/lib", "/lib64") if Path(item).is_dir()]
    command = [str(bwrap), "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv"]
    for mount in mounts:
        command += ["--ro-bind", mount, mount]
    return command + [
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/agent", "--dir", "/broker",
        "--ro-bind", str(socket_dir), "/broker", "--ro-bind", str(script), "/agent/workload.py",
        "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "PYTHONNOUSERSITE", "1", "--chdir", "/",
        "--", str(interpreter), "-I", "/agent/workload.py", *args,
    ]


def _run_workload_child(command: list[str], server: _WriteServer) -> tuple[int, bytes, bytes]:
    """Drain child output with a byte cap while the broker serves requests."""
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    stdout = bytearray()
    stderr = bytearray()
    child: subprocess.Popen[bytes] | None = None
    try:
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert child.stdout is not None and child.stderr is not None
        streams = selectors.DefaultSelector()
        streams.register(child.stdout, selectors.EVENT_READ, stdout)
        streams.register(child.stderr, selectors.EVENT_READ, stderr)
        deadline = time.monotonic() + DEADLINE
        failed = False
        while streams.get_map():
            if not failed and time.monotonic() >= deadline:
                failed = True
                stderr.extend(b"workload deadline exceeded\n")
                if child.poll() is None:
                    child.kill()
            for key, _ in streams.select(timeout=0.1):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    streams.unregister(key.fileobj)
                    continue
                target: bytearray = key.data
                capacity = MAX_OUTPUT - len(target)
                target.extend(chunk[:capacity])
                if len(chunk) > capacity and not failed:
                    failed = True
                    stderr.extend(b"workload output limit exceeded\n")
                    if child.poll() is None:
                        child.kill()
        streams.close()
        try:
            code = child.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
            failed = True
            stderr.extend(b"workload deadline exceeded\n")
            code = -1
        return (-1 if failed else code), bytes(stdout), bytes(stderr[:MAX_OUTPUT])
    except OSError as exc:
        return -1, bytes(stdout), str(exc).encode("ascii", errors="backslashreplace")
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait()
        server.shutdown()
        thread.join(timeout=2)


def _counts(history: Path) -> dict[str, int]:
    kinds = [entry["event"]["kind"] for entry in read_history(history)]
    return {
        "accepted": kinds.count("write"),
        "replayed": kinds.count("retry"),
        "denied": kinds.count("denied"),
        "knownGaps": kinds.count("gap"),
    }


def verify_workload_bundle(output: Path, observer_key: str, witness_key: str) -> dict[str, Any]:
    """Check retained bytes against separately pinned observer and witness keys."""
    report = strict_loads((output / "workload-report.json").read_bytes())
    authority = strict_loads((output / "authority.json").read_bytes())
    launch = strict_loads((output / "launch-policy.json").read_bytes())
    attestation = strict_loads((output / "workload-attestation.json").read_bytes())
    if report["witnessScope"] != "PEER" or report["evidence_vantage"] != "artifact":
        raise VerificationError("workload report claims an unsupported vantage")
    if sha256(output / "workload.py") != authority["workloadSha256"]:
        raise VerificationError("workload bytes differ from authority")
    if digest("probity-launch-policy-v0", launch) != authority["launchPolicySha256"]:
        raise VerificationError("launch policy differs from authority")
    for name in ("stdout", "stderr"):
        if sha256(output / f"workload-{name}.bin") != report[f"{name}Sha256"]:
            raise VerificationError("raw workload output differs from report")
    history = output / "history.jsonl"
    entries = read_history(history)
    if report["channelCounts"] != _counts(history):
        raise VerificationError("channel counts differ from broker history")
    payload = {
        "reportDigest": digest("probity-workload-report-v0", report),
        "authorityDigest": digest("probity-authority-v0", authority),
        "historyHead": entries[-1]["hash"],
    }
    if attestation["keyid"] != observer_key or attestation["payload"] != payload:
        raise VerificationError("workload attestation differs from pinned result")
    verify_signature(observer_key, "probity-workload-result-v0", payload, attestation["signature"])
    if entries[0]["event"]["commitment"]["preimage"]["authorityDigest"] != payload["authorityDigest"]:
        raise VerificationError("history commitment differs from authority")
    if report["status"] == "completed":
        packet = strict_loads((output / "packet.json").read_bytes())
        if packet["authority"] != authority:
            raise VerificationError("packet authority differs from workload authority")
        claim = verify_packet(packet, history, observer_key, witness_key, output / "workspace")
        if report["exitCode"] != 0 or report["channelCounts"]["accepted"] < 1 or not claim["coverage"]["noDetectedGap"]:
            raise VerificationError("completed workload has no covered broker effect")
    elif report["status"] == "incomplete":
        incomplete = strict_loads((output / "incomplete.json").read_bytes())
        terminal = verify_incomplete(history, incomplete["startCheckpoint"], incomplete["checkpoint"], observer_key, witness_key)
        if terminal["reason"] != report["reason"] or (output / "packet.json").exists():
            raise VerificationError("incomplete workload differs from history")
    else:
        raise VerificationError("workload report has an unknown status")
    return report


def run_workload(
    output: Path, source: Path, *, args: Sequence[str] = (), bwrap: Path | None = None,
    interpreter: Path = Path("/usr/bin/python3"),
) -> dict[str, Any]:
    """Run a pinned script and keep the host journal as the effect record."""
    script_bytes = source.read_bytes()
    canonical(list(args))
    output.mkdir(parents=True, exist_ok=True)
    output = output.resolve(strict=True)
    if any(output.iterdir()):
        raise ValueError("workload output directory must be empty")
    workspace = output / "workspace"
    workspace.mkdir()
    socket_dir = output / "socket"
    socket_dir.mkdir()
    script = output / "workload.py"
    script.write_bytes(script_bytes)
    bwrap = bwrap or Path(shutil.which("bwrap") or "/usr/bin/bwrap")
    command = workload_command(bwrap, socket_dir, interpreter, script, args)
    launch = {"argv": command, "workload": str(script), "interpreter": str(interpreter)}
    (output / "launch-policy.json").write_bytes(canonical(launch))
    authority = {
        "intervalId": "workload-1", "scope": "/work", "operation": "write-file",
        "workloadSha256": hashlib.sha256(script_bytes).hexdigest(),
        "interpreterSha256": sha256(interpreter),
        "bwrapSha256": sha256(bwrap) if bwrap.is_file() else "0" * 64,
        "launchPolicySha256": digest("probity-launch-policy-v0", launch),
        "observerBuildDigest": observer_build_digest(), "beforeRoot": tree_root(workspace),
        "expiresAt": (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    (output / "authority.json").write_bytes(canonical(authority))
    observer_key = SigningKey.generate()
    witness_key = SigningKey.generate()
    witness = Witness(output / "witness-state.json", witness_key)
    keys = {"observer": observer_key.public_hex, "witness": witness_key.public_hex}
    (output / "trusted-keys.json").write_bytes(canonical(keys))
    history = output / "history.jsonl"
    broker = Broker(workspace, history, authority, observer_key, witness)
    broker.begin()
    stdout = b""
    stderr = b""
    returncode = -1
    try:
        with _WriteServer(socket_dir / "write.sock", broker) as server:
            os.chmod(socket_dir / "write.sock", 0o666)
            returncode, stdout, stderr = _run_workload_child(command, server)
    except OSError as exc:
        stderr = str(exc).encode("ascii", errors="backslashreplace")
    (socket_dir / "write.sock").unlink(missing_ok=True)
    pending = unresolved_intents(read_history(history))
    if not pending:
        try:
            broker._check_unchanged()
        except CoverageError as exc:
            broker._record_gap(str(exc))
        except OSError:
            broker._record_gap("workspace snapshot failed")
    counts = _counts(history)
    report: dict[str, Any] = {
        "status": "incomplete", "witnessScope": "PEER", "evidence_vantage": "artifact",
        "exitCode": returncode, "channelCounts": counts,
        "stdoutSha256": hashlib.sha256(stdout).hexdigest(), "stderrSha256": hashlib.sha256(stderr).hexdigest(),
    }
    (output / "workload-stdout.bin").write_bytes(stdout)
    (output / "workload-stderr.bin").write_bytes(stderr)
    if pending:
        incomplete = recover_interrupted(history, workspace, witness)
        report["reason"] = "write outcome unresolved after interruption"
    elif returncode == 0 and counts["accepted"] > 0 and counts["knownGaps"] == 0:
        packet = broker.seal()
        (output / "packet.json").write_bytes(canonical(packet))
        report["status"] = "completed"
    else:
        report["reason"] = "workload failed" if returncode != 0 else "broker channel incomplete"
        incomplete = broker.abort(report["reason"])
    if report["status"] == "incomplete":
        (output / "incomplete.json").write_bytes(canonical(incomplete))
    (output / "workload-report.json").write_bytes(canonical(report))
    payload = {
        "reportDigest": digest("probity-workload-report-v0", report),
        "authorityDigest": digest("probity-authority-v0", authority),
        "historyHead": read_history(history)[-1]["hash"],
    }
    attestation = {"payload": payload, "keyid": keys["observer"], "signature": observer_key.sign("probity-workload-result-v0", payload)}
    (output / "workload-attestation.json").write_bytes(canonical(attestation))
    verify_workload_bundle(output, keys["observer"], keys["witness"])
    return report
