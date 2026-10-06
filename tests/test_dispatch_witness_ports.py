"""Check selected public ports before effects; these are local unit controls."""

from dataclasses import asdict
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant, utc_clock
from probity_observer.broker import Broker, CoverageError
from probity_observer.crypto import SigningKey, VerificationError, digest, strict_loads
from probity_observer.history import Witness
from probity_observer.ledger import LedgerWitness
from probity_observer.protected_dispatch import CONFIG_DOMAIN, ProtectedDispatcher, verify_dispatch_bundle
from probity_observer.witness_port import DispatchWitnessPorts


@pytest.fixture
def ports_case(tmp_path: Path) -> dict[str, Any]:
    """Select an exact action and witness stores outside the gateway store."""
    issuer, observer, witness = (SigningKey.generate() for _ in range(3))
    content = b"separate-port effect\n"
    import hashlib
    request = ActionRequest("run", "attempt", "request", "tenant", "principal", "file-write", "/work/result.txt", hashlib.sha256(content).hexdigest())
    policy = GrantPolicy(issuer.public_hex)
    now = utc_clock()
    grant = issue_grant(request, issuer, issued_at=now - timedelta(seconds=1), expires_at=now + timedelta(seconds=120))
    workspace = tmp_path / "work"
    workspace.mkdir()
    authorization = Witness(tmp_path / "authorization-private.json", witness)
    native = LedgerWitness(tmp_path / "native-private.jsonl", witness, observer.public_hex)
    ports = DispatchWitnessPorts(witness.public_hex, authorization, native)
    dispatcher = ProtectedDispatcher(workspace, tmp_path / "gateway", request, policy, observer, ports)
    initial = dispatcher.initialize()
    return dict(issuer=issuer, observer=observer, witness=witness, content=content, request=request, policy=policy, grant=grant, workspace=workspace, authorization=authorization, native=native, ports=ports, dispatcher=dispatcher, initial=initial)


def test_selected_ports_complete_reopen_and_verify(ports_case: dict[str, Any]) -> None:
    case = ports_case
    dispatcher = case["dispatcher"]
    result = dispatcher.write(case["request"], case["grant"], case["content"])
    assert result.replayed is False
    assert (case["workspace"] / "result.txt").read_bytes() == case["content"]
    directory = dispatcher.state_dir
    assert not (directory / "authorization-witness.json").exists()
    assert (directory / "witness-ledger.jsonl").read_bytes() == case["native"].state_path.read_bytes()
    reopened = ProtectedDispatcher(case["workspace"], directory, case["request"], case["policy"], case["observer"], case["ports"], retained_authorization_head=case["initial"])
    inode = (case["workspace"] / "result.txt").stat().st_ino
    assert reopened.write(case["request"], case["grant"], case["content"]).replayed is True
    assert (case["workspace"] / "result.txt").stat().st_ino == inode
    verified = verify_dispatch_bundle(directory, case["request"], case["policy"], case["observer"].public_hex, case["witness"].public_hex, case["initial"], workspace=case["workspace"])
    assert verified["witnessScope"] == "PEER"
    configuration = {"request": asdict(case["request"]), "policy": asdict(case["policy"]), "observerKey": case["observer"].public_hex, "witnessKey": case["witness"].public_hex, "executionDigest": None}
    assert strict_loads((directory / "authorization.jsonl").read_bytes().splitlines()[0])["event"]["configurationDigest"] == digest(CONFIG_DOMAIN, configuration)


@pytest.mark.parametrize("role", ["authorization", "native"])
def test_wrong_selected_port_key_refused(ports_case: dict[str, Any], role: str) -> None:
    case = ports_case
    wrong = SigningKey.generate()
    port = Witness(case["workspace"].parent / "wrong.json", wrong) if role == "authorization" else LedgerWitness(case["workspace"].parent / "wrong.jsonl", wrong, case["observer"].public_hex)
    with pytest.raises(VerificationError, match="selected key"):
        DispatchWitnessPorts(case["witness"].public_hex, port if role == "authorization" else case["authorization"], port if role == "native" else case["native"])
    assert not (case["workspace"] / "result.txt").exists()


@pytest.mark.parametrize("role", ["authorization", "native"])
def test_mutated_port_key_refused_before_effect(ports_case: dict[str, Any], role: str) -> None:
    case = ports_case
    case[role].signing_key = SigningKey.generate()
    with pytest.raises(VerificationError, match="selected key"):
        case["dispatcher"].write(case["request"], case["grant"], case["content"])
    assert not (case["workspace"] / "result.txt").exists()


@pytest.mark.parametrize("role", ["authorization", "native"])
def test_unbound_checkpoint_refused_before_effect(ports_case: dict[str, Any], role: str, monkeypatch: pytest.MonkeyPatch) -> None:
    case = ports_case
    original = case[role].checkpoint
    def wrong(path: Path) -> dict[str, Any]:
        checkpoint = original(path)
        return {**checkpoint, "head": "0" * 64}
    monkeypatch.setattr(case[role], "checkpoint", wrong)
    with pytest.raises(VerificationError, match="bind"):
        case["dispatcher"].write(case["request"], case["grant"], case["content"])
    assert not (case["workspace"] / "result.txt").exists()


def test_receipt_proof_missing_current_history_refused(ports_case: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    case = ports_case
    monkeypatch.setattr(case["native"], "receipt_log", lambda _: b"")
    with pytest.raises(VerificationError, match="finite limit"):
        case["dispatcher"].write(case["request"], case["grant"], case["content"])
    assert not (case["workspace"] / "result.txt").exists()


@pytest.mark.parametrize("mutation", ["count", "head", "keyid", "signature"])
def test_native_broker_rejects_unbound_begin_before_effect(ports_case: dict[str, Any], monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    """A malformed public port must not open any native write interval."""
    case = ports_case
    original = case["native"].checkpoint
    def wrong(path: Path) -> dict[str, Any]:
        checkpoint = original(path)
        checkpoint[mutation] = 2 if mutation == "count" else "0" * (128 if mutation == "signature" else 64)
        return checkpoint
    monkeypatch.setattr(case["native"], "checkpoint", wrong)
    broker = Broker(case["workspace"], case["workspace"].parent / "broker-history.jsonl", {"intervalId": "broker-run", "scope": "/work", "operation": "write-file"}, case["observer"], case["native"])
    with pytest.raises(VerificationError):
        broker.begin()
    with pytest.raises(CoverageError, match="open"):
        broker.write("write", "/work/result.txt", case["content"])
    assert not (case["workspace"] / "result.txt").exists()


def test_native_broker_refuses_role_key_change_before_effect(ports_case: dict[str, Any]) -> None:
    case = ports_case
    broker = Broker(case["workspace"], case["workspace"].parent / "broker-history.jsonl", {"intervalId": "broker-run", "scope": "/work", "operation": "write-file"}, case["observer"], case["native"])
    broker.begin()
    case["native"].signing_key = SigningKey.generate()
    with pytest.raises(VerificationError, match="selected role"):
        broker.write("write", "/work/result.txt", case["content"])
    assert not (case["workspace"] / "result.txt").exists()
