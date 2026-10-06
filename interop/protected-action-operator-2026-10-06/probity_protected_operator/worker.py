"""Installed role processes for a job-owned, separate-store operator run."""

from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import tempfile
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from probity_observer import broker as native_broker
from probity_observer.admission import AdmissionPolicy, AdmissionStore
from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant, utc_clock
from probity_observer.crypto import SigningKey, VerificationError, canonical, digest, strict_loads
from probity_observer.history import read_history, verify_checkpoint
from probity_observer.ledger import RECEIPT_DOMAIN, read_ledger, verify_ledger_head
from probity_observer.protected_dispatch import CONFIG_DOMAIN, ProtectedDispatcher, ProtectedWriteServer, _locked, _save, verify_dispatch_bundle
from probity_observer.witness_port import DispatchWitnessPorts
from probity_witness_operator.client import WitnessClient
from probity_witness_operator.protocol import exchange, require, sha
from probity_witness_operator.server import OperatorServer, remove_stale_socket
from probity_witness_operator.store import Configuration, OperatorStore, secure_file, write_private

from .client import AuthorizationClient
from .protocol import checkpoint_prefix, journal_entries
from .store import AuthorizationConfiguration, AuthorizationStore

BUNDLE_FILES = ("dispatch-state.json", "authorization.jsonl", "history.jsonl", "witness-ledger.jsonl", "packet.json")
OPERATIONS = {
    "issuer": {"run"},
    "gateway": {"init", "serve"},
    "native-witness": {"serve"},
    "authorization-witness": {"serve"},
    "workload": {"run", "lost-ack"},
    "consumer": {"init", "retain", "admit"},
    "probe": {"run"},
    "peer-probe": {"run"},
    "fork": {"run"},
    "check-fork": {"run"},
}


def _key(path: str, public: str) -> SigningKey:
    """Load a role's existing private key with owner and exact public pin checks."""
    raw = secure_file(Path(path))
    require(len(raw) == 32, "role key length differs")
    key = SigningKey(Ed25519PrivateKey.from_private_bytes(raw))
    require(key.public_hex == public, "role key pin differs")
    return key


def _probe(config: dict[str, Any]) -> dict[str, Any]:
    """Perform actual key/store reads, recording denial without secret bytes."""
    denials = []
    for name, value in config["deniedPaths"].items():
        try:
            Path(value).read_bytes()
        except PermissionError as error:
            denials.append({"resource": name, "denied": True, "errno": error.errno})
        else:
            raise VerificationError("role read an unauthorized private resource")
    return {"uid": os.getuid(), "gid": os.getgid(), "groups": os.getgroups(), "denials": denials}


def _issuer(config: dict[str, Any]) -> dict[str, Any]:
    """Issue a finite grant from the issuer process; no other role gets its key."""
    key = _key(config["keyPath"], config["issuerKey"])
    request = ActionRequest(**config["request"])
    now = utc_clock()
    return {"grant": issue_grant(request, key, issued_at=now - timedelta(seconds=1), expires_at=now + timedelta(seconds=config.get("validitySeconds", 240)))}


def _gateway(config: dict[str, Any], operation: str) -> dict[str, Any] | None:
    """Use one existing dispatcher implementation through the public witness ports."""
    selected = config["dispatchConfiguration"]
    observer = _key(config["observerKeyPath"], selected["observerKey"])
    authorization = AuthorizationClient(Path(config["authorizationSocket"]), selected["witnessKey"], config["witnessUid"], digest(CONFIG_DOMAIN, selected), config["authorizationCheckpoint"])
    native = WitnessClient(Path(config["nativeSocket"]), selected["witnessKey"], selected["observerKey"], config["witnessUid"], config["nativeHead"])
    ports = DispatchWitnessPorts(selected["witnessKey"], authorization, native)
    retained = None if operation == "init" else config["authorizationCheckpoint"]
    if operation != "init":
        require(retained["count"] >= 1, "gateway restart requires initialized external authorization checkpoint")
    dispatcher = ProtectedDispatcher(Path(config["workspace"]), Path(config["stateDir"]), ActionRequest(**selected["request"]), GrantPolicy(**selected["policy"]), observer, ports, retained_authorization_head=retained, execution_digest=selected["executionDigest"], decision_digest=selected.get("decisionDigest"))
    if operation == "init":
        return {"authorizationCheckpoint": dispatcher.initialize()}
    _target_fault(config.get("fault"))
    if config.get("removeStaleSocket"):
        remove_stale_socket(Path(config["gatewaySocket"]))
    with GatewayServer(Path(config["gatewaySocket"]), dispatcher, config["workloadUid"]) as server:
        server.socket_path.chmod(0o666)
        _ready(config, server.socket_path)
        server.serve_forever(poll_interval=0.05)
    return None


class GatewayServer(ProtectedWriteServer):
    """Apply host-selected kernel peer policy before the existing exact action API."""

    def __init__(self, path: Path, dispatcher: ProtectedDispatcher, client_uid: int) -> None:
        """Bind the existing dispatcher under one host-selected local peer policy."""
        require(type(client_uid) is int and 0 <= client_uid < 2**32, "gateway peer UID differs")
        self.client_uid, self.socket_path = client_uid, path
        super().__init__(path, dispatcher)

    def verify_request(self, request: socket.socket, client_address: Any) -> bool:
        """Reject the wrong kernel peer before consuming its action request."""
        uid = struct.unpack("3i", request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
        return uid == self.client_uid


def _target_fault(fault: str | None) -> None:
    """A host-only control exits the real gateway process around durable replacement."""
    require(fault in {None, "before-target", "after-target"}, "gateway fault selection differs")
    if fault is None:
        return
    original = native_broker._atomic_write
    def interrupted(target: Path, content: bytes) -> None:
        """Keep the original durable write and exit at the selected boundary."""
        if fault == "before-target":
            os._exit(74)
        original(target, content)
        os._exit(74)
    native_broker._atomic_write = interrupted


def _witness(config: dict[str, Any], kind: str) -> None:
    """Run a real private witness process with an optional host-only lost acknowledgment."""
    configuration_path = Path(config["configurationPath"])
    retained_path = Path(config["retainedPath"])
    if kind == "authorization":
        configuration = AuthorizationConfiguration.read(configuration_path, config["configurationSha256"])
        store = AuthorizationStore(configuration, retained_path, config["retainedSha256"])
        if config.get("faultCount") is not None:
            store.after_commit = lambda count: os._exit(73) if count == config["faultCount"] else None
    else:
        configuration = Configuration.read(configuration_path, config["configurationSha256"])
        store = OperatorStore(configuration, retained_path, config["retainedSha256"])
        if config.get("faultCount") is not None:
            store.after_commit = lambda: os._exit(73) if store.witness.signed_head()["count"] == config["faultCount"] else None
    if config.get("removeStaleSocket"):
        remove_stale_socket(configuration.socket_path)
    with OperatorServer(store) as server:
        _ready(config, configuration.socket_path)
        server.serve_forever(poll_interval=0.05)


def _ready(config: dict[str, Any], socket_path: Path) -> None:
    """Retain a fresh host-only bind acknowledgment before a workload starts."""
    write_private(Path(config["readyPath"]), canonical({"pid": os.getpid(), "uid": os.getuid(), "socketPath": str(socket_path), "socketInode": socket_path.lstat().st_ino}))


def _workload(config: dict[str, Any], lost_ack: bool) -> dict[str, Any]:
    """Submit only public action inputs; record a lost reply without guessing its effect."""
    response = None
    transport = None
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(15)
        try:
            stream.connect(config["gatewaySocket"])
            stream.sendall(canonical(config["candidate"]) + b"\n")
            if lost_ack:
                return {"acknowledged": False, "requestedLostAcknowledgment": True}
            received = bytearray()
            while not received.endswith(b"\n"):
                part = stream.recv(65536 - len(received))
                if not part:
                    break
                received.extend(part)
                require(len(received) < 65536 or received.endswith(b"\n"), "gateway reply exceeds finite limit")
            if received:
                response = strict_loads(bytes(received))
        except OSError as error:
            transport = type(error).__name__
    return {"response": response, "acknowledged": response is not None, "transportError": transport}


def _peer_probe(config: dict[str, Any]) -> dict[str, Any]:
    """Send a valid public witness request from an explicitly unauthorized UID."""
    reply = exchange(Path(config["socketPath"]), config["serverUid"], 5, bytes.fromhex(config["requestHex"]))
    value = strict_loads(reply)
    require(value.get("status") == "refused", "wrong witness peer was accepted")
    return {"refused": True, "response": value}


def _consumer_initialize(config: dict[str, Any]) -> dict[str, Any]:
    """Create one protected consumer store explicitly from separately selected pins."""
    selected = config["dispatchConfiguration"]
    AdmissionStore(Path(config["statePath"])).initialize(selected["observerKey"], selected["witnessKey"])
    path = Path(config["retentionPath"])
    require(not path.exists(), "consumer retention already exists")
    _save(path, {"authorization": config["authorizationCheckpoint"], "native": config["nativeHead"]})
    return {"initialized": True}


def _consumer(config: dict[str, Any], operation: str) -> dict[str, Any]:
    """Capture one candidate, verify approval and native history, then retain or admit."""
    selected = config["dispatchConfiguration"]
    key = selected["witnessKey"]
    retention_path = Path(config["retentionPath"])
    with _locked(retention_path.with_name(retention_path.name + ".lock")):
        retained = strict_loads(secure_file(retention_path))
        with tempfile.TemporaryDirectory(dir=retention_path.parent) as directory:
            snapshot = Path(directory)
            for name in BUNDLE_FILES:
                (snapshot / name).write_bytes((Path(config["bundle"]) / name).read_bytes())
            entries = journal_entries((snapshot / "authorization.jsonl").read_bytes(), selected, config["beforeRoot"])
            checkpoint_prefix(entries, retained["authorization"], key)
            ledger = snapshot / "witness-ledger.jsonl"
            verify_ledger_head(ledger, retained["native"], key)
            if operation == "retain":
                candidate = strict_loads(Path(config["candidateHeads"]).read_bytes())
                verify_checkpoint(entries, candidate["authorization"], key)
                current = verify_ledger_head(ledger, candidate["native"], key)
                require(current["count"] == candidate["native"]["count"], "consumer candidate native head is not current")
                _save(retention_path, candidate)
                return {"retained": candidate}
            verified = verify_dispatch_bundle(snapshot, ActionRequest(**selected["request"]), GrantPolicy(**selected["policy"]), selected["observerKey"], key, retained["authorization"], execution_digest=selected["executionDigest"], decision_digest=selected.get("decisionDigest"))
            authority = {"intervalId": selected["request"]["run_id"], "scope": "/work", "operation": "write-file"}
            policy = AdmissionPolicy(selected["request"]["run_id"], digest("probity-authority-v0", authority), selected["observerKey"], key, retained["native"])
            decision = AdmissionStore(Path(config["statePath"])).admit(strict_loads((snapshot / "packet.json").read_bytes()), snapshot / "history.jsonl", ledger, policy)
            return {"decision": decision, "witnessScope": verified["witnessScope"], "evidenceVantage": verified["evidence_vantage"]}


def _fork(config: dict[str, Any]) -> dict[str, Any]:
    """Sign an alternate public receipt branch with this witness's own private key."""
    key = _key(config["keyPath"], config["witnessKey"])
    receipts = read_ledger(Path(config["ledgerPath"]), config["witnessKey"])
    require(len(receipts) == 2, "fork control needs one complete native interval")
    receipt = receipts[-1]
    payload = {"count": receipt["checkpoint"]["count"], "head": "f" * 64}
    checkpoint = {**payload, "keyid": key.public_hex, "signature": key.sign("probity-checkpoint-v0", payload)}
    body = {field: receipt[field] for field in ("sequence", "previous", "intervalId", "authorityDigest", "observerKey", "phase")}
    body["checkpoint"] = checkpoint
    alternate = {**body, "hash": digest(RECEIPT_DOMAIN, body), "keyid": key.public_hex, "signature": key.sign(RECEIPT_DOMAIN, body)}
    return {"ledgerHex": (canonical(receipts[0]) + b"\n" + canonical(alternate) + b"\n").hex()}


def _check_fork(config: dict[str, Any]) -> dict[str, Any]:
    """Separate signature validity from the refusal against a held consumer prefix."""
    path = Path(config["forkPath"])
    receipts = read_ledger(path, config["witnessKey"])
    retained = strict_loads(secure_file(Path(config["retentionPath"])))
    try:
        verify_ledger_head(path, retained["native"], config["witnessKey"])
    except VerificationError as error:
        return {"signedReceiptsValid": len(receipts) == 2, "retainedPrefixRefused": True, "reason": str(error)}
    raise VerificationError("signed fork was accepted against retained consumer prefix")


def main() -> int:
    """Run exactly one installed role action under a separately pinned input file."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("issuer", "gateway", "native-witness", "authorization-witness", "workload", "consumer", "probe", "peer-probe", "fork", "check-fork"))
    parser.add_argument("--operation", required=True, choices=("run", "init", "serve", "retain", "admit", "lost-ack"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--config-sha256", required=True)
    arguments = parser.parse_args()
    try:
        require(arguments.operation in OPERATIONS[arguments.role], "role operation differs")
        raw = arguments.config.read_bytes()
        require(sha(raw) == arguments.config_sha256, "role configuration pin differs")
        config = strict_loads(raw)
        if arguments.role == "issuer":
            result = _issuer(config)
        elif arguments.role == "gateway":
            result = _gateway(config, arguments.operation)
        elif arguments.role in {"native-witness", "authorization-witness"}:
            _witness(config, "native" if arguments.role == "native-witness" else "authorization")
            result = None
        elif arguments.role == "workload":
            result = _workload(config, arguments.operation == "lost-ack")
        elif arguments.role == "probe":
            result = _probe(config)
        elif arguments.role == "peer-probe":
            result = _peer_probe(config)
        elif arguments.role == "fork":
            result = _fork(config)
        elif arguments.role == "check-fork":
            result = _check_fork(config)
        elif arguments.operation == "init":
            result = _consumer_initialize(config)
        else:
            result = _consumer(config, arguments.operation)
        if result is not None:
            sys.stdout.buffer.write(canonical({"role": arguments.role, "pid": os.getpid(), "uid": os.getuid(), **result}))
        return 0
    except (VerificationError, ValueError, KeyError, TypeError, OSError) as error:
        print("operator role refused: " + (str(error) if isinstance(error, VerificationError) else type(error).__name__), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
