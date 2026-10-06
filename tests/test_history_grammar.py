"""A valid signature or digest cannot turn a Boolean into a record position."""
from pathlib import Path

import pytest

from probity_observer.broker import Broker
from probity_observer.crypto import SigningKey, VerificationError, canonical, digest
from probity_observer.history import GENESIS, read_history, verify_checkpoint
from probity_observer.ledger import LedgerWitness


@pytest.mark.parametrize("entries,count", [([], False), ([{"hash": "1" * 64}], True)])
def test_signed_boolean_checkpoint_refused(entries, count) -> None:
    key = SigningKey.generate()
    payload = {"count": count, "head": entries[-1]["hash"] if entries else GENESIS}
    checkpoint = {**payload, "keyid": key.public_hex, "signature": key.sign("probity-checkpoint-v0", payload)}
    with pytest.raises(VerificationError, match="invalid fields or count"):
        verify_checkpoint(entries, checkpoint, key.public_hex)


@pytest.mark.parametrize("entries", [[], [{"hash": "1" * 64}]])
def test_float_checkpoint_substitution_refused(entries) -> None:
    key = SigningKey.generate()
    payload = {"count": len(entries), "head": entries[-1]["hash"] if entries else GENESIS}
    checkpoint = {**payload, "keyid": key.public_hex, "signature": key.sign("probity-checkpoint-v0", payload)}
    checkpoint["count"] = float(len(entries))
    with pytest.raises(VerificationError, match="invalid fields or count"):
        verify_checkpoint(entries, checkpoint, key.public_hex)


@pytest.mark.parametrize("entries", [[], [{"hash": "1" * 64}]])
def test_integer_checkpoint_remains_valid(entries) -> None:
    key = SigningKey.generate()
    payload = {"count": len(entries), "head": entries[-1]["hash"] if entries else GENESIS}
    checkpoint = {**payload, "keyid": key.public_hex, "signature": key.sign("probity-checkpoint-v0", payload)}
    verify_checkpoint(entries, checkpoint, key.public_hex)
    with pytest.raises(VerificationError, match="invalid fields or count"):
        verify_checkpoint(entries, {**checkpoint, "unsignedExtension": "ignored"}, key.public_hex)


def test_real_native_receipt_extension_remains_valid(tmp_path: Path) -> None:
    workspace = tmp_path / "work"
    workspace.mkdir()
    observer, key = SigningKey.generate(), SigningKey.generate()
    witness = LedgerWitness(tmp_path / "ledger.jsonl", key, observer.public_hex)
    history = tmp_path / "history.jsonl"
    broker = Broker(workspace, history, {"intervalId": "type-control", "scope": "/work", "operation": "write-file"}, observer, witness)
    checkpoint = broker.begin()["checkpoint"]
    assert checkpoint["ledgerReceipt"]["checkpoint"]["count"] == 1
    verify_checkpoint(read_history(history), checkpoint, key.public_hex)


def test_hash_valid_boolean_history_position_refused(tmp_path: Path) -> None:
    body = {"sequence": True, "previous": GENESIS, "event": {"kind": "control"}}
    entry = {**body, "hash": digest("probity-history-entry-v0", body)}
    path = tmp_path / "history.jsonl"
    path.write_bytes(canonical(entry) + b"\n")
    with pytest.raises(VerificationError, match="sequence is not an integer"):
        read_history(path)


def test_history_refuses_unbound_extra_fields(tmp_path: Path) -> None:
    body = {"sequence": 1, "previous": GENESIS, "event": {"kind": "control"}}
    entry = {**body, "hash": digest("probity-history-entry-v0", body)}
    path = tmp_path / "history.jsonl"
    path.write_bytes(canonical(entry) + b"\n")
    assert read_history(path) == [entry]
    path.write_bytes(canonical({**entry, "unsignedExtension": "ignored"}) + b"\n")
    with pytest.raises(VerificationError, match="shape is unsupported"):
        read_history(path)
