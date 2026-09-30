"""A fail-closed Linux boundary gate for the bounded write broker."""

from __future__ import annotations

import hashlib
import os
import shutil
import socketserver
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .broker import Broker, recover_interrupted, tree_root
from .crypto import SigningKey, VerificationError, canonical, digest, strict_loads, verify_signature
from .history import CheckpointWitness, Witness, read_history, unresolved_intents
from .ledger import verify_ledger_receipts
from .remote_witness import RemoteLedgerWitness, export_ledger
from .verify import verify_incomplete, verify_packet

PROBE = Path(__file__).with_name("probe_agent.py")
EXPECTED = frozenset({
    "directWriteRefused", "keyReadRefused", "processSignalRefused", "networkRefused",
    "brokerWrite", "retryReplayed", "changedRetryDenied", "traversalDenied",
})
MAX_REQUEST = 65536


def sha256(path: Path) -> str:
    """Hash the exact file bytes used for this run."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def observer_build_digest() -> str:
    """Bind the observer source files that take part in this test run."""
    source = Path(__file__).parent
    files = {path.name: sha256(path) for path in source.glob("*.py")}
    return digest("probity-observer-source-v0", files)


def launch_command(bwrap: Path, socket_dir: Path, interpreter: Path, host_pid: int, probe: Path = PROBE) -> list[str]:
    """Expose a broker socket and read-only runtime, with no watched-tree mount."""
    mounts = [item for item in ("/usr", "/bin", "/lib", "/lib64") if Path(item).is_dir()]
    args = [str(bwrap), "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv"]
    for mount in mounts:
        args += ["--ro-bind", mount, mount]
    return args + [
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/agent", "--dir", "/broker",
        "--ro-bind", str(socket_dir), "/broker", "--ro-bind", str(probe), "/agent/probe.py",
        "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "PYTHONNOUSERSITE", "1", "--chdir", "/",
        "--", str(interpreter), "-I", "/agent/probe.py", str(host_pid),
    ]


class _WriteHandler(socketserver.StreamRequestHandler):
    """Serve one bounded request per connection; the host owns the broker."""

    def handle(self) -> None:
        broker: Broker = self.server.broker  # type: ignore[attr-defined]
        raw = self.rfile.readline(MAX_REQUEST + 1)
        try:
            if len(raw) > MAX_REQUEST or not raw.endswith(b"\n"):
                broker._record_gap("broker request missing or oversized")
                raise ValueError("broker request missing or oversized")
            payload = strict_loads(raw[:-1])
            if not isinstance(payload, dict) or set(payload) != {"requestId", "path", "contentHex"}:
                raise ValueError("broker request has unexpected fields")
            if not all(isinstance(value, str) for value in payload.values()):
                raise ValueError("broker request fields must be strings")
            content = bytes.fromhex(payload["contentHex"])
            result = broker.write(payload["requestId"], payload["path"], content)
            response: dict[str, Any] = {"ok": True, "replayed": result.replayed, "afterRoot": result.after_root}
        except (ValueError, OSError) as exc:
            response = {"ok": False, "error": str(exc)}
        self.wfile.write(canonical(response) + b"\n")


class _WriteServer(socketserver.UnixStreamServer):
    """Serially handle writes so broker history has one owner."""

    def __init__(self, path: Path, broker: Broker) -> None:
        self.broker = broker
        super().__init__(str(path), _WriteHandler)


def _run_child(command: list[str], server: _WriteServer) -> tuple[int, bytes, bytes]:
    """Serve the socket while the sandboxed child runs with a deadline."""
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        completed = subprocess.run(command, capture_output=True, timeout=15, check=False)
        return completed.returncode, completed.stdout, completed.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, b"", str(exc).encode("ascii", errors="backslashreplace")
    finally:
        server.shutdown()
        thread.join(timeout=2)


def _report(output: Path, report: dict[str, Any], stdout: bytes, stderr: bytes) -> dict[str, Any]:
    """Keep raw child results next to a small, canonical gate decision."""
    (output / "probe-stdout.bin").write_bytes(stdout)
    (output / "probe-stderr.bin").write_bytes(stderr)
    report["stdoutSha256"] = hashlib.sha256(stdout).hexdigest()
    report["stderrSha256"] = hashlib.sha256(stderr).hexdigest()
    (output / "boundary-report.json").write_bytes(canonical(report))
    return report


def _sign_report(output: Path, report: dict[str, Any], authority: dict[str, str], history: Path, key: SigningKey) -> None:
    """Bind the raw-result digests and final history head under the observer key."""
    payload = {
        "reportDigest": digest("probity-boundary-report-v0", report),
        "authorityDigest": digest("probity-authority-v0", authority),
        "historyHead": read_history(history)[-1]["hash"],
    }
    signed = {"payload": payload, "keyid": key.public_hex, "signature": key.sign("probity-boundary-result-v0", payload)}
    (output / "boundary-attestation.json").write_bytes(canonical(signed))


def verify_boundary_bundle(output: Path, observer_key: str, witness_key: str) -> dict[str, Any]:
    """Check a retained gate result with public keys pinned outside the bundle."""
    report = strict_loads((output / "boundary-report.json").read_bytes())
    authority = strict_loads((output / "authority.json").read_bytes())
    launch = strict_loads((output / "launch-policy.json").read_bytes())
    attestation = strict_loads((output / "boundary-attestation.json").read_bytes())
    if report["witnessScope"] != "PEER" or report["evidence_vantage"] != "artifact":
        raise VerificationError("boundary report claims an unsupported vantage")
    if report["probeSha256"] != authority["probeSha256"] or sha256(output / "agent-probe.py") != authority["probeSha256"]:
        raise VerificationError("probe bytes differ from the committed authority")
    if digest("probity-launch-policy-v0", launch) != authority["launchPolicySha256"]:
        raise VerificationError("launch policy differs from the committed authority")
    for name in ("stdout", "stderr"):
        if sha256(output / f"probe-{name}.bin") != report[f"{name}Sha256"]:
            raise VerificationError("raw probe output differs from the report")
    entries = read_history(output / "history.jsonl")
    payload = {
        "reportDigest": digest("probity-boundary-report-v0", report),
        "authorityDigest": digest("probity-authority-v0", authority),
        "historyHead": entries[-1]["hash"],
    }
    if attestation["keyid"] != observer_key or attestation["payload"] != payload:
        raise VerificationError("boundary attestation differs from the pinned result")
    verify_signature(observer_key, "probity-boundary-result-v0", payload, attestation["signature"])
    history = output / "history.jsonl"
    if report["status"] == "probe-passed":
        packet = strict_loads((output / "packet.json").read_bytes())
        if packet["authority"] != authority:
            raise VerificationError("packet authority differs from the launch authority")
        verify_packet(packet, history, observer_key, witness_key, output / "workspace")
    elif report["status"] == "incomplete":
        incomplete = strict_loads((output / "incomplete.json").read_bytes())
        terminal = verify_incomplete(history, incomplete["startCheckpoint"], incomplete["checkpoint"], observer_key, witness_key)
        if terminal["reason"] != report["reason"] or (output / "packet.json").exists():
            raise VerificationError("incomplete result differs from the history")
    else:
        raise VerificationError("boundary report has an unknown status")
    committed = entries[0]["event"]["commitment"]["preimage"]["authorityDigest"]
    if committed != payload["authorityDigest"]:
        raise VerificationError("history commitment differs from the launch authority")
    start = packet["startCheckpoint"] if report["status"] == "probe-passed" else incomplete["startCheckpoint"]
    terminal_checkpoint = packet["checkpoint"] if report["status"] == "probe-passed" else incomplete["checkpoint"]
    if "ledgerReceipt" in start or "ledgerReceipt" in terminal_checkpoint:
        if "ledgerReceipt" not in start or "ledgerReceipt" not in terminal_checkpoint:
            raise VerificationError("witness ledger receipt is missing")
        verify_ledger_receipts(output / "witness-ledger.jsonl", start, terminal_checkpoint, witness_key)
    return report


def _broker_events_match(history: Path) -> bool:
    """Check the durable broker side of the fixed probe sequence."""
    events = [item["event"] for item in read_history(history)]
    if [item["kind"] for item in events] != ["begin", "write-intent", "write", "retry", "denied", "denied"]:
        return False
    return (
        events[2]["requestId"] == events[3]["requestId"] == "write-1"
        and events[4]["reason"] == "idempotency key reused with different request"
        and events[5]["reason"] == "write path is not normalized"
    )


def run_boundary_probe(
    output: Path, *, bwrap: Path | None = None, interpreter: Path = Path("/usr/bin/python3"),
    observer_key: SigningKey | None = None, witness: CheckpointWitness | None = None,
) -> dict[str, Any]:
    """Commit first, run the fixed attack probe, and retain either outcome.

    A passing probe documents one launch configuration. Its packet remains
    PEER because the witness is local and this is not an independent audit.
    """
    output.mkdir(parents=True, exist_ok=True)
    output = output.resolve(strict=True)
    if any(output.iterdir()):
        raise ValueError("boundary output directory must be empty")
    workspace = output / "workspace"
    workspace.mkdir()
    socket_dir = output / "socket"
    socket_dir.mkdir()
    probe = output / "agent-probe.py"
    probe.write_bytes(PROBE.read_bytes())
    bwrap = bwrap or Path(shutil.which("bwrap") or "/usr/bin/bwrap")
    command = launch_command(bwrap, socket_dir, interpreter, os.getpid(), probe)
    launch = {"argv": command, "probe": str(probe), "interpreter": str(interpreter)}
    (output / "launch-policy.json").write_bytes(canonical(launch))
    authority = {
        "intervalId": "boundary-probe-1", "scope": "/work", "operation": "write-file",
        "probeSha256": sha256(probe), "interpreterSha256": sha256(interpreter),
        "bwrapSha256": sha256(bwrap) if bwrap.is_file() else "0" * 64,
        "launchPolicySha256": digest("probity-launch-policy-v0", launch),
        "observerBuildDigest": observer_build_digest(), "beforeRoot": tree_root(workspace),
        "expiresAt": (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    (output / "authority.json").write_bytes(canonical(authority))
    observer_key = observer_key or SigningKey.generate()
    witness = witness or Witness(output / "witness-state.json", SigningKey.generate())
    keys = {"observer": observer_key.public_hex, "witness": witness.public_key}
    (output / "trusted-keys.json").write_bytes(canonical(keys))
    history = output / "history.jsonl"
    broker = Broker(workspace, history, authority, observer_key, witness)
    broker.begin()
    report: dict[str, Any] = {"evidence_vantage": "artifact", "witnessScope": "PEER", "probeSha256": authority["probeSha256"]}
    stdout = b""
    stderr = b""
    returncode = -1
    try:
        with _WriteServer(socket_dir / "write.sock", broker) as server:
            os.chmod(socket_dir / "write.sock", 0o666)
            returncode, stdout, stderr = _run_child(command, server)
    except OSError as exc:
        stderr = str(exc).encode("ascii", errors="backslashreplace")
    (socket_dir / "write.sock").unlink(missing_ok=True)
    report["exitCode"] = returncode
    try:
        results = strict_loads(stdout.strip(b"\n")) if returncode == 0 else None
    except ValueError:
        results = None
    report["attempts"] = results if isinstance(results, dict) else None
    passed = returncode == 0 and isinstance(results, dict) and set(results) == EXPECTED and all(value is True for value in results.values())
    target = workspace / "effect.txt"
    passed = passed and target.is_file() and target.read_bytes() == b"observed effect\n" and _broker_events_match(history)
    if passed:
        packet = broker.seal()
        (output / "packet.json").write_bytes(canonical(packet))
        verify_packet(packet, history, keys["observer"], keys["witness"], workspace)
        report["status"] = "probe-passed"
    else:
        entries = read_history(history)
        if unresolved_intents(entries):
            incomplete = recover_interrupted(history, workspace, witness)
            reason = "write outcome unresolved after interruption"
        else:
            reason = "isolation setup failed" if returncode != 0 and len(entries) == 1 else "boundary probes failed"
            incomplete = broker.abort(reason)
        (output / "incomplete.json").write_bytes(canonical(incomplete))
        verify_incomplete(history, incomplete["startCheckpoint"], incomplete["checkpoint"], keys["observer"], keys["witness"])
        report["status"] = "incomplete"
        report["reason"] = reason
    result = _report(output, report, stdout, stderr)
    _sign_report(output, result, authority, history, observer_key)
    if isinstance(witness, RemoteLedgerWitness):
        export_ledger(witness.socket_path, output / "witness-ledger.jsonl", witness.public_key)
    verify_boundary_bundle(output, keys["observer"], keys["witness"])
    return result
