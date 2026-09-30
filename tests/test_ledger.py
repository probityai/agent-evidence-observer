"""Witness ledger checks across broker intervals."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from probity_observer import Broker, LedgerWitness, SigningKey, VerificationError, verify_ledger_receipts, verify_packet
from probity_observer.broker import recover_interrupted
from probity_observer.history import append_history
from probity_observer.ledger import read_ledger


def broker_for(root: Path, interval: str, observer_key: SigningKey, witness: LedgerWitness) -> tuple[Broker, Path]:
    workspace = root / interval / "workspace"
    workspace.mkdir(parents=True)
    history = root / interval / "history.jsonl"
    broker = Broker(workspace, history, {"intervalId": interval, "scope": "/work", "operation": "write-file"}, observer_key, witness)
    return broker, history


def test_two_intervals_share_one_checkable_history(tmp_path: Path) -> None:
    observer_key = SigningKey.generate()
    witness_key = SigningKey.generate()
    ledger_path = tmp_path / "witness" / "ledger.jsonl"
    witness = LedgerWitness(ledger_path, witness_key, observer_key.public_hex)
    broker_a, history_a = broker_for(tmp_path, "a", observer_key, witness)
    broker_a.begin()
    broker_a.write("first", "/work/x", b"one")
    packet_a = broker_a.seal()
    first_head = packet_a["checkpoint"]["ledgerReceipt"]["hash"]
    broker_b, history_b = broker_for(tmp_path, "b", observer_key, witness)
    broker_b.begin()
    broker_b.write("second", "/work/y", b"two")
    packet_b = broker_b.seal()

    assert verify_packet(packet_a, history_a, observer_key.public_hex, witness_key.public_hex)["witnessScope"] == "PEER"
    assert verify_packet(packet_b, history_b, observer_key.public_hex, witness_key.public_hex)["witnessScope"] == "PEER"
    assert verify_ledger_receipts(ledger_path, packet_a["startCheckpoint"], packet_a["checkpoint"], witness_key.public_hex) == {
        "count": 4, "head": packet_b["checkpoint"]["ledgerReceipt"]["hash"],
    }
    assert verify_ledger_receipts(ledger_path, packet_b["startCheckpoint"], packet_b["checkpoint"], witness_key.public_hex, first_head)["count"] == 4


def test_concurrent_intervals_share_one_serial_ledger(tmp_path: Path) -> None:
    observer_key = SigningKey.generate()
    witness_key = SigningKey.generate()
    ledger_path = tmp_path / "ledger.jsonl"

    def run(index: int) -> None:
        witness = LedgerWitness(ledger_path, witness_key, observer_key.public_hex)
        broker, history = broker_for(tmp_path, f"interval-{index}", observer_key, witness)
        broker.begin()
        packet = broker.seal()
        verify_packet(packet, history, observer_key.public_hex, witness_key.public_hex)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(run, range(8)))
    receipts = read_ledger(ledger_path, witness_key.public_hex)
    assert len(receipts) == 16
    assert {r["intervalId"] for r in receipts} == {f"interval-{i}" for i in range(8)}


def test_repeated_interval_and_terminal_fork_are_refused(tmp_path: Path) -> None:
    observer_key = SigningKey.generate()
    witness = LedgerWitness(tmp_path / "ledger.jsonl", SigningKey.generate(), observer_key.public_hex)
    broker, history = broker_for(tmp_path, "one", observer_key, witness)
    broker.begin()
    fork = tmp_path / "fork.jsonl"
    fork.write_bytes(history.read_bytes())
    append_history(fork, {"kind": "denied", "requestId": "x", "path": "/work/x", "reason": "test"})
    append_history(fork, {"kind": "seal", "claimDigest": "0" * 64})
    broker.write("one", "/work/x", b"real")
    broker.seal()
    with pytest.raises(VerificationError, match="already has a terminal head"):
        witness.checkpoint(fork)
    again, _ = broker_for(tmp_path / "alternate", "one", observer_key, witness)
    with pytest.raises(VerificationError, match="terminal head"):
        again.begin()


def test_truncation_and_wrong_receipt_fail_against_pinned_head(tmp_path: Path) -> None:
    observer_key = SigningKey.generate()
    witness_key = SigningKey.generate()
    ledger_path = tmp_path / "ledger.jsonl"
    witness = LedgerWitness(ledger_path, witness_key, observer_key.public_hex)
    broker, _ = broker_for(tmp_path, "one", observer_key, witness)
    broker.begin()
    packet = broker.seal()
    published_head = packet["checkpoint"]["ledgerReceipt"]["hash"]
    original = ledger_path.read_bytes()
    ledger_path.write_bytes(original.splitlines()[0] + b"\n")
    with pytest.raises(VerificationError, match="absent from the ledger"):
        verify_ledger_receipts(ledger_path, packet["startCheckpoint"], packet["checkpoint"], witness_key.public_hex)
    with pytest.raises(VerificationError, match="pinned head"):
        verify_ledger_receipts(ledger_path, packet["startCheckpoint"], packet["startCheckpoint"], witness_key.public_hex, published_head)
    ledger_path.write_bytes(original.replace(b'"phase":"terminal"', b'"phase":"begin"', 1))
    with pytest.raises(VerificationError, match="digest differs"):
        read_ledger(ledger_path, witness_key.public_hex)


def test_interrupted_write_retains_ledger_receipts(tmp_path: Path) -> None:
    observer_key = SigningKey.generate()
    witness_key = SigningKey.generate()
    ledger_path = tmp_path / "ledger.jsonl"
    witness = LedgerWitness(ledger_path, witness_key, observer_key.public_hex)
    broker, history = broker_for(tmp_path, "crash", observer_key, witness)
    broker.begin()
    append_history(history, {"kind": "write-intent", "requestId": "x", "path": "/work/x", "contentDigest": "0" * 64, "beforeRoot": broker._expected_root})
    recovered = recover_interrupted(history, broker.workspace, witness)
    assert recovered["status"] == "incomplete"
    assert verify_ledger_receipts(ledger_path, recovered["startCheckpoint"], recovered["checkpoint"], witness_key.public_hex)["count"] == 2
