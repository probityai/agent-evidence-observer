"""Actual installed Linux IPC, different-UID and process-fault acceptance run."""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from probity_observer import Broker, LedgerWitness, SigningKey
from probity_observer.crypto import canonical, strict_loads

from .protocol import FORMAT, receive, require, sha
from .reader import CASES
from .retention import retain_head
from .server import OperatorServer, remove_stale_socket
from .sources import retain_sources
from .store import Configuration, OperatorStore, generate_key, initialize, load_key, write_private
from .worker import CONTENT

PRODUCER_UID = 65534
PROCESS_LOG: Path | None = None


def _key_bytes(key: SigningKey) -> bytes:
    """Export only a host-selected producer key into its private runtime."""
    return key.private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def _drop_uid() -> None:
    """Run the native producer without the operator's UID or groups."""
    os.setgroups([])
    os.setgid(PRODUCER_UID)
    os.setuid(PRODUCER_UID)


def _wait(path: Path, process: subprocess.Popen[bytes]) -> None:
    """Bound native startup and fault barriers to 15 seconds."""
    end = time.monotonic() + 15
    while not path.exists():
        require(process.poll() is None, "native process exited before barrier")
        require(time.monotonic() < end, "native process barrier timed out")
        time.sleep(0.01)


def _stop(process: subprocess.Popen[bytes]) -> None:
    """Terminate only the exact child created by this harness."""
    if process.poll() is None:
        process.kill()
    stdout, stderr = process.communicate(timeout=10)
    _process_log(process, stdout, stderr)


def _process_log(process: subprocess.Popen[bytes], stdout: bytes, stderr: bytes) -> None:
    """Retain exact native process stdout/stderr before interpreting results."""
    if PROCESS_LOG is not None:
        value = {"argv": process.args, "pid": process.pid, "returncode": process.returncode,
                 "stdoutHex": stdout.hex(), "stderrHex": stderr.hex()}
        with PROCESS_LOG.open("ab") as stream:
            stream.write(canonical(value) + b"\n")


@dataclass
class NativeCase:
    """Keep private operator state outside the retained public packet."""

    name: str
    directory: Path
    producer: Path
    configuration: Configuration
    config_path: Path
    retained_path: Path
    worker_config: Path
    initial_head: dict[str, Any]
    observer: SigningKey
    issuer: SigningKey

    def operator_args(self) -> list[str]:
        """Select exact host config and external retained-head bytes."""
        return ["--config", str(self.config_path), "--config-sha256", self.configuration.digest,
                "--retained-head", str(self.retained_path), "--retained-sha256", sha(self.retained_path.read_bytes())]

    def store(self) -> OperatorStore:
        """Reopen the selected store without generating or resetting anything."""
        return OperatorStore(self.configuration, self.retained_path, sha(self.retained_path.read_bytes()))


def _producer_key(path: Path, key: SigningKey) -> None:
    """Create a producer key under only the producer UID's permissions."""
    write_private(path, _key_bytes(key))
    os.chown(path, PRODUCER_UID, PRODUCER_UID)


def create_case(name: str, packet: Path, private: Path, socket_root: Path) -> NativeCase:
    """Select host keys, state, peer UID and initial head before producer launch."""
    directory = packet / name
    directory.mkdir()
    runtime = private / name
    runtime.mkdir()
    operator = runtime / "operator"
    operator.mkdir(mode=0o700)
    producer = runtime / "producer"
    producer.mkdir(mode=0o700)
    os.chown(producer, PRODUCER_UID, PRODUCER_UID)
    observer, issuer = SigningKey.generate(), SigningKey.generate()
    witness_key = generate_key(operator / "key.raw")
    _producer_key(producer / "observer.raw", observer)
    _producer_key(producer / "issuer.raw", issuer)
    value = {"format": FORMAT, "keyPath": str(operator / "key.raw"), "storePath": str(operator / "state"),
             "socketPath": str(socket_root / (name + ".sock")), "observerKey": observer.public_hex,
             "witnessKey": witness_key, "clientUid": PRODUCER_UID}
    config_path = operator / "host.json"
    config_path.write_bytes(canonical(value))
    configuration = Configuration.read(config_path, sha(config_path.read_bytes()))
    initial = initialize(configuration)
    retained_directory = runtime / "retained"
    retained_directory.mkdir(mode=0o700)
    retained = retained_directory / "head.json"
    candidate = retained_directory / "candidate.json"
    candidate.write_bytes(canonical(initial))
    retain_head(configuration.store_path / "ledger.jsonl", candidate, retained, witness_key=witness_key,
                ledger_sha256=sha(b""), candidate_sha256=sha(candidate.read_bytes()), previous_sha256=None)
    worker = {"case": name, "socketPath": value["socketPath"], "witnessKey": witness_key,
              "observerKey": observer.public_hex, "observerKeyPath": str(producer / "observer.raw"),
              "issuerKey": issuer.public_hex, "issuerKeyPath": str(producer / "issuer.raw"),
              "operatorKeyPath": value["keyPath"], "operatorLedgerPath": str(configuration.store_path / "ledger.jsonl"),
              "serverUid": os.getuid(), "retainedHead": initial}
    worker_config = producer / "host-input.json"
    worker_config.write_bytes(canonical(worker))
    os.chown(worker_config, PRODUCER_UID, PRODUCER_UID)
    return NativeCase(name, directory, producer, configuration, config_path, retained, worker_config, initial, observer, issuer)


def _worker(case: NativeCase, python: str, operation: str = "produce") -> subprocess.Popen[bytes]:
    """Launch a separately installed producer with kernel UID separation."""
    return subprocess.Popen([python, "-I", "-B", "-m", "probity_witness_operator.worker", operation,
                             str(case.worker_config), str(case.producer)], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, preexec_fn=_drop_uid)


def _operator(case: NativeCase, fault: bool = False) -> subprocess.Popen[bytes]:
    """Launch the installed operator or its host-only fault worker."""
    if fault:
        command = [sys.executable, "-I", "-B", "-m", "probity_witness_operator.native", "fault-server", str(case.config_path), str(case.retained_path)]
    else:
        command = [sys.executable, "-I", "-B", "-m", "probity_witness_operator.cli", "serve", *case.operator_args()]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _wait(case.configuration.socket_path, process)
    return process


def _capture(process: subprocess.Popen[bytes]) -> dict[str, Any]:
    """Retain the actual child exit and exact stdout/stderr bytes."""
    stdout, stderr = process.communicate(timeout=20)
    _process_log(process, stdout, stderr)
    return {"returncode": process.returncode, "stdoutHex": stdout.hex(), "stderrHex": stderr.hex(), "retryReturncode": None}


def _normal_case(case: NativeCase, python: str) -> dict[str, Any]:
    """Run a permitted or deliberately failed producer through actual IPC."""
    server = _operator(case)
    try:
        return _capture(_worker(case, python))
    finally:
        _stop(server)


def _unavailable_before(case: NativeCase, python: str) -> dict[str, Any]:
    """No witness acknowledgment means no broker effect can start."""
    return _capture(_worker(case, python))


def _unavailable_after(case: NativeCase, python: str) -> dict[str, Any]:
    """Kill the witness after an actual target write, then attempt terminal closure."""
    server = _operator(case)
    worker = _worker(case, python)
    try:
        _wait(case.producer / "after-write.ready", worker)
        _stop(server)
        (case.producer / "continue").write_bytes(b"continue")
        return _capture(worker)
    finally:
        _stop(server)
        _stop(worker)


def _retain_current(case: NativeCase) -> None:
    """Acquire and retain an authenticated head through the host operator seam."""
    exported = case.store().export()
    candidate = case.retained_path.parent / "candidate.json"
    candidate.write_bytes(canonical(exported["head"]))
    retain_head(case.configuration.store_path / "ledger.jsonl", candidate, case.retained_path,
                witness_key=case.configuration.witness_key, ledger_sha256=sha(bytes.fromhex(exported["ledgerHex"])),
                candidate_sha256=sha(candidate.read_bytes()), previous_sha256=sha(case.retained_path.read_bytes()))
    value = strict_loads(case.worker_config.read_bytes())
    value["retainedHead"] = exported["head"]
    case.worker_config.write_bytes(canonical(value))


def _lost_ack(case: NativeCase, python: str) -> dict[str, Any]:
    """Kill after durable receipt, restart, and retry exact bytes once."""
    server = _operator(case, fault=True)
    result = _capture(_worker(case, python))
    _stop(server)
    require(server.returncode == 73, "native post-commit crash did not run")
    _retain_current(case)
    remove_stale_socket(case.configuration.socket_path)
    restarted = _operator(case)
    try:
        retry = _capture(_worker(case, python, "retry"))
        result["retryReturncode"] = retry["returncode"]
        require(retry["returncode"] == 0, "native retry failed")
        return result
    finally:
        _stop(restarted)


def _retain_case(case: NativeCase, result: dict[str, Any]) -> dict[str, Any]:
    """Retain only selected public native files, never private keys or runtime state."""
    exported = case.store().export()
    selected = ("worker.json", "history.jsonl", "packet.json", "authorization.json", "retry-checkpoint.json")
    for name in selected:
        source = case.producer / name
        if source.exists():
            shutil.copyfile(source, case.directory / name)
    target = case.producer / "work/result.txt"
    if target.exists():
        work = case.directory / "work"
        work.mkdir()
        shutil.copyfile(target, work / "result.txt")
    (case.directory / "process.json").write_bytes(canonical(result))
    (case.directory / "ledger.jsonl").write_bytes(bytes.fromhex(exported["ledgerHex"]))
    (case.directory / "head.json").write_bytes(canonical(exported["head"]))
    return _case_policy(case)


def _case_policy(case: NativeCase) -> dict[str, Any]:
    """Select the finite expected native result and exact retained file population."""
    expected = {"permit": (0, 2, 1, True), "failed-after": (7, 2, 1, True),
                "unavailable-before": (2, 0, 0, False), "unavailable-after": (2, 1, 1, False), "lost-ack": (2, 1, 0, False)}[case.name]
    exit_code, count, writes, terminal = expected
    request = {"run_id": case.name, "attempt_id": "attempt-1", "request_id": "write-1", "tenant_id": "tenant",
               "principal_id": "principal", "tool_id": "file-write", "target_path": "/work/result.txt", "content_sha256": sha(CONTENT)}
    return {"witnessKey": case.configuration.witness_key, "observerKey": case.observer.public_hex,
            "issuerKey": case.issuer.public_hex, "producerUid": PRODUCER_UID, "initialHead": case.initial_head,
            "expectedExit": exit_code, "expectedState": "COMPLETED" if exit_code == 0 else "FAILED",
            "expectedLedgerCount": count, "expectedWrites": writes, "signedTerminal": terminal, "request": request,
            "files": {str(path.relative_to(case.directory)): sha(path.read_bytes()) for path in case.directory.rglob("*") if path.is_file()}}


def _command_refused(case: NativeCase) -> bool:
    """A native restart/head refusal must emit no successful JSON output."""
    result = subprocess.run([sys.executable, "-I", "-B", "-m", "probity_witness_operator.cli", "head", *case.operator_args()], capture_output=True, timeout=10)
    value = {"argv": result.args, "returncode": result.returncode, "stdoutHex": result.stdout.hex(), "stderrHex": result.stderr.hex()}
    with (case.directory.parent.parent / "fault-command-results.jsonl").open("ab") as stream:
        stream.write(canonical(value) + b"\n")
    return (result.returncode, result.stdout) == (2, b"") and result.stderr.endswith(b"witness command refused\n")


def _restore_control(case: NativeCase, replacement: bytes) -> dict[str, bool]:
    """Try a coherent restored log, prove refusal leaves it unchanged, then restore."""
    path = case.configuration.store_path / "ledger.jsonl"
    saved = path.read_bytes()
    path.write_bytes(replacement)
    try:
        return {"refused": _command_refused(case), "stateUnchanged": path.read_bytes() == replacement}
    finally:
        path.write_bytes(saved)


def _fork(case: NativeCase, private: Path) -> bytes:
    """Let the same operator sign a real alternate history to test a retained head."""
    directory = private / "fork"
    directory.mkdir()
    workspace = directory / "work"
    workspace.mkdir()
    witness = LedgerWitness(directory / "fork.jsonl", load_key(case.configuration), case.observer.public_hex)
    broker = Broker(workspace, directory / "history.jsonl", {"intervalId": "alternate", "scope": "/work", "operation": "write-file"}, case.observer, witness)
    broker.begin()
    ledger = witness.state_path.read_bytes()
    (case.directory / "fork-ledger.jsonl").write_bytes(ledger)
    (case.directory / "fork-head.json").write_bytes(canonical(witness.signed_head()))
    return ledger


def _missing(case: NativeCase) -> dict[str, bool]:
    """Missing restart state must remain missing, with no fresh genesis reset."""
    path = case.configuration.store_path / "ledger.jsonl"
    saved = path.read_bytes()
    path.unlink()
    try:
        return {"refused": _command_refused(case), "stateUnchanged": not path.exists()}
    finally:
        write_private(path, saved)


def _wrong_key(case: NativeCase) -> dict[str, bool]:
    """A replacement private key cannot silently re-key the configured store."""
    path = case.configuration.key_path
    saved = path.read_bytes()
    path.write_bytes(b"\0" * 32)
    try:
        return {"refused": _command_refused(case), "stateUnchanged": path.read_bytes() == b"\0" * 32}
    finally:
        path.write_bytes(saved)


def _wrong_peer(case: NativeCase) -> dict[str, bool]:
    """A real root connection is refused when the host selected the producer UID."""
    server = _operator(case)
    path = case.configuration.store_path / "ledger.jsonl"
    saved = path.read_bytes()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.connect(str(case.configuration.socket_path))
            reply = strict_loads(receive(stream))
        return {"refused": reply == {"status": "refused", "reason": "witness peer, framing, history or state differs"},
                "stateUnchanged": path.read_bytes() == saved}
    finally:
        _stop(server)
        remove_stale_socket(case.configuration.socket_path)


def _fault_controls(case: NativeCase, private: Path) -> dict[str, Any]:
    """Run actual installed CLI controls against the persisted lost-ack interval."""
    _retain_current(case)
    return {"rollback": _restore_control(case, b""), "fork": _restore_control(case, _fork(case, private)),
            "missing-ledger": _missing(case), "wrong-key": _wrong_key(case), "wrong-peer": _wrong_peer(case)}


def _other_map(python: str) -> dict[str, str]:
    """Compare selected source bytes in each separate installed environment."""
    result = subprocess.run([python, "-I", "-B", "-c", "from probity_witness_operator.sources import installed_map; from probity_observer.crypto import canonical; import sys; sys.stdout.buffer.write(canonical(installed_map()))"], check=True, capture_output=True, timeout=10)
    return strict_loads(result.stdout)


def run(directory: Path, private: Path, producer_python: str, reader_python: str) -> None:
    """Retain an actual different-UID IPC run and all finite fault controls.

    Parameters
    ----------
    directory : Path
        New public retained packet directory.
    private : Path
        Separate host runtime directory, excluded from uploaded artifacts.
    producer_python, reader_python : str
        Separately installed producer and reader Python executables.
    """
    global PROCESS_LOG
    require(os.getuid() == 0, "native UID controls require root harness")
    directory.mkdir()
    PROCESS_LOG = directory / "native-process-results.jsonl"
    private.mkdir(mode=0o755)
    packet = directory / "packet"
    packet.mkdir()
    source = retain_sources(packet / "source")
    require(source == _other_map(producer_python), "producer installed source bytes differ")
    require(source == _other_map(reader_python), "reader installed source bytes differ")
    with tempfile.TemporaryDirectory(prefix="witness-ipc-") as sockets:
        socket_root = Path(sockets)
        socket_root.chmod(0o755)
        policies, lost = _cases(packet, private, socket_root, producer_python)
        controls = _fault_controls(lost, private)
        policies[lost.name] = _case_policy(lost)
    faults = packet / "fault-controls.json"
    faults.write_bytes(canonical(controls))
    policy = {"format": FORMAT, "cases": policies, "source": source, "faultControls": sha(faults.read_bytes())}
    (directory / "host-policy.json").write_bytes(canonical(policy))
    require(all(value["refused"] and value["stateUnchanged"] for value in controls.values()), "native fault control failed")


def _cases(packet: Path, private: Path, sockets: Path, python: str) -> tuple[dict[str, Any], NativeCase]:
    """Produce each preselected case once under separate installed processes."""
    policies: dict[str, Any] = {}
    handlers = {"permit": _normal_case, "failed-after": _normal_case, "unavailable-before": _unavailable_before,
                "unavailable-after": _unavailable_after, "lost-ack": _lost_ack}
    cases: dict[str, NativeCase] = {}
    for name in CASES:
        case = create_case(name, packet, private, sockets)
        cases[name] = case
        result = handlers[name](case, python)
        require(result["returncode"] == {"permit": 0, "failed-after": 7}.get(name, 2), "native producer process result differs")
        policies[name] = _retain_case(case, result)
        _cleanup_socket(case.configuration.socket_path)
    return policies, cases["lost-ack"]


def _cleanup_socket(path: Path) -> None:
    """Remove a dead child endpoint only after checking its actual socket state."""
    if path.exists():
        remove_stale_socket(path)


def fault_server(configuration_path: Path, retained_path: Path) -> None:
    """Crash the real operator after durable append but before sending its reply."""
    configuration = Configuration.read(configuration_path, sha(configuration_path.read_bytes()))
    store = OperatorStore(configuration, retained_path, sha(retained_path.read_bytes()), after_commit=lambda: os._exit(73))
    with OperatorServer(store) as server:
        server.serve_forever(poll_interval=0.05)


def main() -> None:
    """Dispatch only explicit host-side native run or process-fault commands."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    native = commands.add_parser("run")
    native.add_argument("directory", type=Path)
    native.add_argument("--private-state", type=Path, required=True)
    native.add_argument("--producer-python", required=True)
    native.add_argument("--reader-python", required=True)
    fault = commands.add_parser("fault-server")
    fault.add_argument("configuration", type=Path)
    fault.add_argument("retained", type=Path)
    arguments = parser.parse_args()
    if arguments.operation == "run":
        run(arguments.directory, arguments.private_state, arguments.producer_python, arguments.reader_python)
    else:
        fault_server(arguments.configuration, arguments.retained)


if __name__ == "__main__":
    main()
