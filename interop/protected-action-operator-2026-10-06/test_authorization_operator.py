"""Finite service and public-port integration controls; no outside custody claim."""

from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import sys
import threading
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant, utc_clock
from probity_observer.broker import tree_root
from probity_observer.crypto import SigningKey, VerificationError, canonical, digest, strict_loads
from probity_observer.history import append_history
from probity_observer.protected_dispatch import CONFIG_DOMAIN, ProtectedDispatcher, verify_dispatch_bundle
from probity_observer.witness_port import DispatchWitnessPorts
from probity_witness_operator.client import WitnessClient
from probity_witness_operator.protocol import FORMAT as NATIVE_FORMAT, sha
from probity_witness_operator.server import OperatorServer
from probity_witness_operator.store import Configuration, OperatorStore, initialize as initialize_native, write_private

from probity_protected_operator.client import AuthorizationClient
from probity_protected_operator.protocol import FORMAT, checkpoint_prefix, request_bytes
from probity_protected_operator.store import AuthorizationConfiguration, AuthorizationStore, initialize
from probity_protected_operator.worker import _workload


@pytest.fixture
def case(tmp_path: Path) -> dict[str, Any]:
    issuer, observer, witness = (SigningKey.generate() for _ in range(3))
    content = b"operator service effect\n"
    request = ActionRequest("run-operator", "attempt", "request", "tenant", "principal", "file-write", "/work/result.txt", hashlib.sha256(content).hexdigest())
    policy = GrantPolicy(issuer.public_hex)
    work = tmp_path / "work"
    work.mkdir()
    raw_key = witness.private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    write_private(tmp_path / "witness.raw", raw_key)
    dispatch = {"request": asdict(request), "policy": asdict(policy), "observerKey": observer.public_hex, "witnessKey": witness.public_hex, "executionDigest": None}
    config_path = tmp_path / "authorization-config.json"
    config_path.write_bytes(canonical({"format": FORMAT, "keyPath": str(tmp_path / "witness.raw"), "storePath": str(tmp_path / "authorization-private"), "socketPath": str(tmp_path / "authorization.sock"), "clientUid": os.getuid(), "dispatchConfiguration": dispatch, "beforeRoot": tree_root(work)}))
    config = AuthorizationConfiguration.read(config_path, sha(config_path.read_bytes()))
    initial = initialize(config)
    retained = tmp_path / "authorization-retained.json"
    retained.write_bytes(canonical(initial))
    store = AuthorizationStore(config, retained, sha(retained.read_bytes()))
    journal = tmp_path / "journal.jsonl"
    append_history(journal, {"kind": "dispatch-created", "configurationDigest": digest(CONFIG_DOMAIN, dispatch), "beforeRoot": tree_root(work)})
    return dict(root=tmp_path, issuer=issuer, observer=observer, witness=witness, content=content, request=request, policy=policy, work=work, dispatch=dispatch, config_path=config_path, config=config, initial=initial, retained=retained, store=store, journal=journal)


def test_exact_checkpoint_retry_and_restart(case: dict[str, Any]) -> None:
    raw = request_bytes("checkpoint", case["journal"].read_bytes())
    reply = case["store"].handle(raw)
    saved = (case["config"].store_path / "state.json").read_bytes()
    assert case["store"].handle(raw) == reply
    assert (case["config"].store_path / "state.json").read_bytes() == saved
    reopened = AuthorizationStore(case["config"], case["retained"], sha(case["retained"].read_bytes()))
    assert reopened.export()["checkpoint"]["count"] == 1


@pytest.mark.parametrize("change", ["missing", "truncated", "empty", "wrong-key"])
def test_restart_never_resets_state(case: dict[str, Any], change: str) -> None:
    path = case["config"].store_path / "state.json"
    if change == "missing":
        path.unlink()
    elif change == "truncated":
        path.write_bytes(path.read_bytes()[:-1])
    elif change == "empty":
        path.write_bytes(b"")
    else:
        case["config"].key_path.write_bytes(b"0" * 32)
    with pytest.raises((VerificationError, ValueError, OSError)):
        AuthorizationStore(case["config"], case["retained"], sha(case["retained"].read_bytes()))


@pytest.mark.parametrize("field", ["beforeRoot", "configurationDigest", "kind"])
def test_wrong_initial_relation_refused(case: dict[str, Any], field: str) -> None:
    path = case["root"] / "wrong-journal.jsonl"
    event = {"kind": "dispatch-created", "configurationDigest": digest(CONFIG_DOMAIN, case["dispatch"]), "beforeRoot": tree_root(case["work"])}
    event[field] = "different" if field == "kind" else "0" * 64
    append_history(path, event)
    before = case["store"].export()
    with pytest.raises(VerificationError):
        case["store"].handle(request_bytes("checkpoint", path.read_bytes()))
    assert case["store"].export() == before


def test_live_store_rollback_refused(case: dict[str, Any]) -> None:
    state = case["config"].store_path / "state.json"
    bootstrap = state.read_bytes()
    case["store"].handle(request_bytes("checkpoint", case["journal"].read_bytes()))
    checkpoint = case["store"].export()["checkpoint"]
    case["retained"].write_bytes(canonical(checkpoint))
    state.write_bytes(bootstrap)
    with pytest.raises(VerificationError):
        case["store"].export()
    with pytest.raises(VerificationError):
        AuthorizationStore(case["config"], case["retained"], sha(case["retained"].read_bytes()))


def test_remote_ports_complete_replay_and_offline_reader(case: dict[str, Any]) -> None:
    root = case["root"]
    native_path = root / "native-config.json"
    native_path.write_bytes(canonical({"format": NATIVE_FORMAT, "keyPath": str(root / "witness.raw"), "storePath": str(root / "native-private"), "socketPath": str(root / "native.sock"), "observerKey": case["observer"].public_hex, "witnessKey": case["witness"].public_hex, "clientUid": os.getuid()}))
    native_config = Configuration.read(native_path, sha(native_path.read_bytes()))
    native_initial = initialize_native(native_config)
    native_retained = root / "native-retained.json"
    native_retained.write_bytes(canonical(native_initial))
    stores = (case["store"], OperatorStore(native_config, native_retained, sha(native_retained.read_bytes())))
    servers = [OperatorServer(store) for store in stores]
    threads = [threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}) for server in servers]
    for thread in threads:
        thread.start()
    try:
        authorization = AuthorizationClient(root / "authorization.sock", case["witness"].public_hex, os.getuid(), digest(CONFIG_DOMAIN, case["dispatch"]), case["initial"])
        native = WitnessClient(root / "native.sock", case["witness"].public_hex, case["observer"].public_hex, os.getuid(), native_initial)
        ports = DispatchWitnessPorts(case["witness"].public_hex, authorization, native)
        gateway = ProtectedDispatcher(case["work"], root / "gateway", case["request"], case["policy"], case["observer"], ports)
        initial = gateway.initialize()
        now = utc_clock()
        grant = issue_grant(case["request"], case["issuer"], issued_at=now - timedelta(seconds=1), expires_at=now + timedelta(seconds=120))
        assert gateway.write(case["request"], grant, case["content"]).replayed is False
        before = (case["work"] / "result.txt").stat().st_ino
        assert gateway.write(case["request"], grant, case["content"]).replayed is True
        assert (case["work"] / "result.txt").stat().st_ino == before
        assert case["store"].export()["checkpoint"]["count"] == 3
        assert not (root / "gateway" / "authorization-witness.json").exists()
        result = verify_dispatch_bundle(root / "gateway", case["request"], case["policy"], case["observer"].public_hex, case["witness"].public_hex, initial, workspace=case["work"])
        assert result["witnessScope"] == "PEER"
        state = strict_loads((root / "gateway" / "dispatch-state.json").read_bytes())
        checkpoint_prefix([], case["initial"], case["witness"].public_hex)
        assert state["payload"]["checkpoint"] == authorization.retained_checkpoint
    finally:
        for server, thread in zip(servers, threads, strict=True):
            server.shutdown()
            thread.join()
            server.server_close()


@pytest.mark.parametrize("role,operation", [("issuer", "serve"), ("gateway", "run"), ("consumer", "serve"), ("native-witness", "admit")])
def test_wrong_role_operation_refused_without_bootstrap(tmp_path: Path, role: str, operation: str) -> None:
    """An unsupported operation cannot become a hidden key/store or service action."""
    path = tmp_path / "host.json"
    path.write_bytes(b"{}")
    result = subprocess.run([sys.executable, "-I", "-B", "-m", "probity_protected_operator.worker", role, "--operation", operation, "--config", str(path), "--config-sha256", sha(path.read_bytes())], capture_output=True, timeout=10)
    assert result.returncode == 2
    assert result.stdout == b""
    assert b"role operation differs" in result.stderr
    assert set(item.name for item in tmp_path.iterdir()) == {"host.json"}


@pytest.mark.parametrize("reply,accepted,error", [
    (b'{"ok":false}\n', False, None),
    (b'{"ok":true}\n', True, None),
    (b'{"ok": false}\n', None, "JSON document is not canonical"),
    (b'{"ok":false}', None, "gateway reply lacks its LF frame byte"),
    (b'{"ok":"yes"}\n', None, "gateway reply result differs"),
    (b'{"ok":false}\n\n', None, "JSON document is not canonical"),
])
def test_workload_accepts_exact_canonical_lf_frame(tmp_path: Path, reply: bytes, accepted: bool | None, error: str | None) -> None:
    """An actual socket reply removes one frame byte and retains every received byte."""
    endpoint = tmp_path / "action.sock"
    candidate = {"public": "action"}
    request = bytearray()
    failures = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(endpoint))
        server.listen(1)
        server.settimeout(5)

        def answer() -> None:
            try:
                with server.accept()[0] as stream:
                    stream.settimeout(5)
                    while not request.endswith(b"\n"):
                        part = stream.recv(65536)
                        if not part:
                            return
                        request.extend(part)
                    stream.sendall(reply)
            except BaseException as failure:
                failures.append(failure)

        thread = threading.Thread(target=answer)
        thread.start()
        try:
            result = _workload({"gatewaySocket": str(endpoint), "candidate": candidate}, False)
        finally:
            thread.join(timeout=10)
        assert not thread.is_alive()
    assert failures == []
    assert request == canonical(candidate) + b"\n"
    assert result["replyHex"] == reply.hex()
    assert result["transportError"] is None
    assert result["protocolError"] == error
    assert result["acknowledged"] is (error is None)
    assert result["response"] == ({"ok": accepted} if error is None else None)
