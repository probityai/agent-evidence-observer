"""A separately run witness with a signed request and durable receipt log."""

from __future__ import annotations

import hashlib
import os
import socket
import socketserver
import stat
import tempfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import SigningKey, VerificationError, canonical, digest, strict_loads, verify_signature
from .history import read_history, verify_checkpoint
from .ledger import LedgerWitness, RECEIPT_DOMAIN, _begin_identity, read_ledger

SUBMIT_DOMAIN = "probity-witness-submit-v0"
MAX_HISTORY = 256 * 1024
MAX_WIRE = 1024 * 1024


def save_key(path: Path, key: SigningKey) -> None:
    """Create a private witness or observer key readable only by its owner."""
    from cryptography.hazmat.primitives import serialization

    path.parent.mkdir(parents=True, exist_ok=True)
    raw = key.private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        parent = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)


def load_key(path: Path) -> SigningKey:
    """Refuse a private key with group or world access."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise VerificationError("private key permissions must be 0600")
        raw = stream.read(33)
    if len(raw) != 32:
        raise VerificationError("private key must contain 32 raw bytes")
    return SigningKey(Ed25519PrivateKey.from_private_bytes(raw))


def _send(socket_path: Path, request: dict[str, Any]) -> dict[str, Any]:
    wire = canonical(request) + b"\n"
    if len(wire) > MAX_WIRE:
        raise VerificationError("witness request exceeds the size limit")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(3)
            client.connect(str(socket_path))
            client.sendall(wire)
            with client.makefile("rb") as stream:
                answer = stream.readline(MAX_WIRE + 1)
    except (OSError, TimeoutError) as exc:
        raise VerificationError("witness unavailable") from exc
    if not answer.endswith(b"\n") or len(answer) > MAX_WIRE:
        raise VerificationError("witness response is missing or oversized")
    response = strict_loads(answer[:-1])
    if not isinstance(response, dict):
        raise VerificationError("witness response is not an object")
    if response.get("ok") is not True:
        raise VerificationError("witness rejected request: " + str(response.get("error", "invalid response")))
    return response


def _receipt_matches(receipt: dict[str, Any], checkpoint: dict[str, Any], observer_key: str, entries: list[dict[str, Any]]) -> None:
    body = {key: receipt[key] for key in (
        "sequence", "previous", "intervalId", "authorityDigest", "observerKey", "phase", "checkpoint",
    )}
    interval, authority = _begin_identity(entries, observer_key)
    phase = "begin" if len(entries) == 1 else "terminal"
    if (receipt["intervalId"], receipt["authorityDigest"], receipt["observerKey"], receipt["phase"]) != (
        interval, authority, observer_key, phase,
    ) or receipt["checkpoint"] != {k: v for k, v in checkpoint.items() if k != "ledgerReceipt"}:
        raise VerificationError("witness receipt differs from the submitted history")
    if receipt["hash"] != digest(RECEIPT_DOMAIN, body) or receipt["keyid"] != checkpoint["keyid"]:
        raise VerificationError("witness receipt digest or key differs")
    verify_signature(receipt["keyid"], RECEIPT_DOMAIN, body, receipt["signature"])


class RemoteLedgerWitness:
    """Submit history bytes over a Unix socket; never hold the witness key."""

    state_path: None = None

    def __init__(self, socket_path: Path, observer_key: SigningKey, pinned_witness_key: str) -> None:
        if pinned_witness_key == observer_key.public_hex:
            raise VerificationError("observer and witness keys must differ")
        self.socket_path = socket_path
        self.observer_key = observer_key
        self.public_key = pinned_witness_key

    def _request(self, action: str, history_path: Path) -> dict[str, Any]:
        raw = history_path.read_bytes()
        if len(raw) > MAX_HISTORY:
            raise VerificationError("history exceeds the witness size limit")
        fields = {"action": action, "historySha256": hashlib.sha256(raw).hexdigest()}
        request = {
            **fields, "historyHex": raw.hex(),
            "signature": self.observer_key.sign(SUBMIT_DOMAIN, fields),
        }
        response = _send(self.socket_path, request)
        if set(response) != {"ok", "checkpoint"}:
            raise VerificationError("witness response has unexpected fields")
        checkpoint = response["checkpoint"]
        entries = read_history(history_path)
        checked_entries = entries[:1] if action == "latest" else entries
        verify_checkpoint(checked_entries, checkpoint, self.public_key)
        receipt = checkpoint.get("ledgerReceipt")
        if not isinstance(receipt, dict):
            raise VerificationError("witness receipt is missing")
        _receipt_matches(receipt, checkpoint, self.observer_key.public_hex, checked_entries)
        return checkpoint

    def checkpoint(self, history_path: Path) -> dict[str, Any]:
        return self._request("checkpoint", history_path)

    def latest_checkpoint(self, history_path: Path) -> dict[str, Any]:
        return self._request("latest", history_path)


def export_ledger(socket_path: Path, output: Path, pinned_witness_key: str, pinned_head: str | None = None) -> dict[str, Any]:
    """Retain a checked copy; a pinned head detects rollback, not later omission."""
    response = _send(socket_path, {"action": "export"})
    if set(response) != {"ok", "ledgerHex"}:
        raise VerificationError("witness export has unexpected fields")
    try:
        raw = bytes.fromhex(response["ledgerHex"])
    except (TypeError, ValueError) as exc:
        raise VerificationError("witness export is not hex") from exc
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=output.parent, delete=False) as temporary:
        staged = Path(temporary.name)
        temporary.write(raw)
        temporary.flush()
        os.fsync(temporary.fileno())
    try:
        receipts = read_ledger(staged, pinned_witness_key)
        if pinned_head is not None and not any(item["hash"] == pinned_head for item in receipts):
            raise VerificationError("witness export does not extend the pinned head")
        os.replace(staged, output)
        parent = os.open(output.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        staged.unlink(missing_ok=True)
    return {"count": len(receipts), "head": receipts[-1]["hash"] if receipts else "0" * 64}


class WitnessService:
    """Hold the signer and ledger outside the observer's process and run tree."""

    def __init__(self, ledger_path: Path, signing_key: SigningKey, observer_key: str) -> None:
        if signing_key.public_hex == observer_key:
            raise VerificationError("observer and witness keys must differ")
        self.ledger_path = ledger_path
        self.signing_key = signing_key
        self.observer_key = observer_key

    def process(self, request: dict[str, Any]) -> dict[str, Any]:
        if request == {"action": "export"}:
            read_ledger(self.ledger_path, self.signing_key.public_hex)
            raw = self.ledger_path.read_bytes() if self.ledger_path.exists() else b""
            if len(raw) > MAX_HISTORY:
                raise VerificationError("witness ledger exceeds the export limit")
            return {"ok": True, "ledgerHex": raw.hex()}
        if not isinstance(request, dict) or set(request) != {"action", "historyHex", "historySha256", "signature"}:
            raise VerificationError("witness request has unexpected fields")
        action = request["action"]
        if action not in {"checkpoint", "latest"}:
            raise VerificationError("witness request has an unknown action")
        fields = {"action": action, "historySha256": request["historySha256"]}
        verify_signature(self.observer_key, SUBMIT_DOMAIN, fields, request["signature"])
        try:
            raw = bytes.fromhex(request["historyHex"])
        except (TypeError, ValueError) as exc:
            raise VerificationError("witness history is not hex") from exc
        if len(raw) > MAX_HISTORY or hashlib.sha256(raw).hexdigest() != request["historySha256"]:
            raise VerificationError("witness history exceeds the limit or differs from its signature")
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=self.ledger_path.parent) as temporary:
            temporary.write(raw)
            temporary.flush()
            history = Path(temporary.name)
            entries = read_history(history)
            witness = LedgerWitness(self.ledger_path, self.signing_key, self.observer_key)
            if action == "latest":
                checkpoint = witness.latest_checkpoint(history)
            else:
                interval, authority = _begin_identity(entries, self.observer_key)
                phase = "begin" if len(entries) == 1 else "terminal"
                receipts = read_ledger(self.ledger_path, self.signing_key.public_hex)
                matches = [receipt for receipt in receipts if (
                    receipt["intervalId"], receipt["authorityDigest"], receipt["phase"],
                    receipt["checkpoint"]["count"], receipt["checkpoint"]["head"],
                ) == (interval, authority, phase, len(entries), entries[-1]["hash"])]
                if matches:
                    checkpoint = {**matches[0]["checkpoint"], "ledgerReceipt": matches[0]}
                else:
                    checkpoint = witness.checkpoint(history)
        return {"ok": True, "checkpoint": checkpoint}


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        raw = self.rfile.readline(MAX_WIRE + 1)
        try:
            if len(raw) > MAX_WIRE or not raw.endswith(b"\n"):
                raise VerificationError("witness request is missing or oversized")
            response = self.server.service.process(strict_loads(raw[:-1]))  # type: ignore[attr-defined]
        except (ValueError, TypeError, KeyError, OSError) as exc:
            response = {"ok": False, "error": str(exc)}
        self.wfile.write(canonical(response) + b"\n")


class _Server(socketserver.UnixStreamServer):
    def __init__(self, path: Path, service: WitnessService) -> None:
        self.service = service
        super().__init__(str(path), _Handler)


def serve(socket_path: Path, ledger_path: Path, key_path: Path, observer_key: str, socket_mode: int = 0o600) -> None:
    """Serve until stopped; the operator owns the key, socket, and ledger."""
    if socket_path.exists() or socket_path.is_symlink():
        raise FileExistsError("witness socket already exists")
    if socket_path.resolve().is_relative_to(ledger_path.resolve().parent):
        raise VerificationError("witness socket must be outside private ledger storage")
    if socket_mode not in {0o600, 0o660}:
        raise VerificationError("witness socket mode must be 0600 or 0660")
    service = WitnessService(ledger_path, load_key(key_path), observer_key)
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    with _Server(socket_path, service) as server:
        try:
            os.chmod(socket_path, socket_mode)
            server.serve_forever(poll_interval=0.05)
        finally:
            socket_path.unlink(missing_ok=True)
