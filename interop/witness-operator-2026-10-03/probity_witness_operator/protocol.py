"""Bounded exact history and signed IPC response formats."""

from __future__ import annotations

import hashlib
import re
import socket
import struct
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from probity_observer.crypto import VerificationError, canonical, digest, strict_loads, verify_signature
from probity_observer.history import read_history, verify_checkpoint
from probity_observer.ledger import _begin_identity, read_ledger, verify_ledger_head

FORMAT = "probity-witness-operator-v0"
REPLY_DOMAIN = FORMAT + "-reply"
MAX_HISTORY = 262144
MAX_FRAME = 2097152
MAX_ENTRIES = 512
INTERVAL_ID = re.compile(r"[\x21-\x7e]{1,128}\Z")
HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def require(condition: bool, reason: str) -> None:
    """Raise the shared finite refusal when a relation differs."""
    if not condition:
        raise VerificationError(reason)


def sha(raw: bytes) -> str:
    """Return SHA-256 of exact supplied bytes."""
    return hashlib.sha256(raw).hexdigest()


def exact_fields(value: Any, fields: set[str], reason: str) -> None:
    """Require an object with exactly the selected field population."""
    require(isinstance(value, dict), reason)
    require(set(value) == fields, reason)


def history_entries(raw: bytes) -> list[dict[str, Any]]:
    """Check canonical exact history bytes before checkpoint submission.

    Parameters
    ----------
    raw : bytes
        Full broker JSONL history, limited to 256 KiB and 512 entries.

    Returns
    -------
    list of dict
        Chain-verified entries with an exact fixed entry schema.
    """
    require(0 < len(raw) <= MAX_HISTORY, "history exceeds finite limit")
    require(raw.endswith(b"\n"), "history lacks complete closure")
    lines = raw.splitlines()
    require(len(lines) <= MAX_ENTRIES, "history entry population exceeds finite limit")
    for line in lines:
        entry = strict_loads(line)
        exact_fields(entry, {"sequence", "previous", "event", "hash"}, "history entry fields differ")
        require(type(entry["sequence"]) is int, "history sequence type differs")
        require(canonical(entry) == line, "history bytes are noncanonical")
    with TemporaryDirectory() as directory:
        path = Path(directory) / "history.jsonl"
        path.write_bytes(raw)
        return read_history(path)


def decode_request(raw: bytes) -> tuple[str, bytes]:
    """Decode a fixed request without accepting operator paths or key changes."""
    value = strict_loads(raw)
    exact_fields(value, {"format", "operation", "historyHex", "historySha256"}, "request fields differ")
    require(canonical(value) == raw, "request bytes are noncanonical")
    require(value["format"] == FORMAT, "request format differs")
    require(value["operation"] in {"checkpoint", "latest"}, "request operation differs")
    history = bytes.fromhex(value["historyHex"])
    require(history.hex() == value["historyHex"], "history encoding differs")
    require(sha(history) == value["historySha256"], "request history digest differs")
    history_entries(history)
    return value["operation"], history


def request_bytes(operation: str, raw: bytes) -> bytes:
    """Bind the operation to exact history bytes, not a server-side pathname."""
    history_entries(raw)
    return canonical({"format": FORMAT, "operation": operation, "historyHex": raw.hex(), "historySha256": sha(raw)})


def checked_identity(entries: list[dict[str, Any]], observer_key: str) -> tuple[str, str]:
    """Authenticate the host observer and admit only finite typed identities."""
    interval, authority = _begin_identity(entries, observer_key)
    require(isinstance(interval, str), "operator interval ID type differs")
    require(INTERVAL_ID.fullmatch(interval) is not None, "operator interval ID differs")
    require(isinstance(authority, str), "operator authority digest type differs")
    require(HEX_DIGEST.fullmatch(authority) is not None, "operator authority digest differs")
    return interval, authority


def read_exact(stream: socket.socket, length: int) -> bytes:
    """Read one finite frame segment or refuse interrupted closure."""
    chunks = bytearray()
    while len(chunks) < length:
        part = stream.recv(length - len(chunks))
        require(bool(part), "IPC frame is incomplete")
        chunks.extend(part)
    return bytes(chunks)


def receive(stream: socket.socket) -> bytes:
    """Read one length-prefixed frame with a bounded allocation."""
    length = struct.unpack("!I", read_exact(stream, 4))[0]
    require(0 < length <= MAX_FRAME, "IPC frame exceeds finite limit")
    return read_exact(stream, length)


def send(stream: socket.socket, raw: bytes) -> None:
    """Write one bounded length-prefixed frame."""
    require(0 < len(raw) <= MAX_FRAME, "IPC reply exceeds finite limit")
    stream.sendall(struct.pack("!I", len(raw)) + raw)


def peer_uid(stream: socket.socket) -> int:
    """Return Linux kernel peer credentials for the connected Unix socket."""
    return struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


def _checked_payload(reply: Any, public_key: str) -> dict[str, Any]:
    """Authenticate the exact response envelope under the host-selected key."""
    exact_fields(reply, {"payload", "keyid", "signature"}, "reply envelope differs")
    require(reply["keyid"] == public_key, "reply witness pin differs")
    payload = reply["payload"]
    verify_signature(public_key, REPLY_DOMAIN, payload, reply["signature"])
    exact_fields(payload, {"format", "operation", "historySha256", "checkpoint", "ledgerHead", "ledgerHex"}, "reply fields differ")
    require(payload["format"] == FORMAT, "reply format differs")
    return payload


def _checked_ledger(payload: dict[str, Any], retained: dict[str, Any], public_key: str) -> list[dict[str, Any]]:
    """Verify both externally retained and returned heads against full bytes."""
    raw = bytes.fromhex(payload["ledgerHex"])
    require(raw.hex() == payload["ledgerHex"], "ledger encoding differs")
    require(len(raw) <= MAX_HISTORY, "ledger exceeds finite limit")
    with TemporaryDirectory() as directory:
        path = Path(directory) / "ledger.jsonl"
        path.write_bytes(raw)
        verify_ledger_head(path, retained, public_key)
        current = verify_ledger_head(path, payload["ledgerHead"], public_key)
        require(current["count"] == payload["ledgerHead"]["count"], "reply head is not current")
        return read_ledger(path, public_key)


def _checked_receipt(checkpoint: Any, receipts: list[dict[str, Any]], entries: list[dict[str, Any]], observer_key: str) -> None:
    """Bind the returned persisted receipt to interval, observer and checkpoint."""
    exact_fields(checkpoint, {"count", "head", "keyid", "signature", "ledgerReceipt"}, "reply checkpoint fields differ")
    receipt = checkpoint["ledgerReceipt"]
    require(receipt in receipts, "reply checkpoint is absent from ledger")
    require(receipt["checkpoint"] == {k: v for k, v in checkpoint.items() if k != "ledgerReceipt"}, "reply checkpoint receipt differs")
    commitment = entries[0]["event"]["commitment"]
    require(receipt["observerKey"] == observer_key, "reply observer pin differs")
    require(receipt["intervalId"] == commitment["preimage"]["intervalId"], "reply interval differs")
    require(receipt["authorityDigest"] == commitment["preimage"]["authorityDigest"], "reply authority differs")


def verify_reply(raw_reply: bytes, operation: str, history: bytes, public_key: str, observer_key: str, retained: dict[str, Any]) -> dict[str, Any]:
    """Verify a persisted response and advance only a host-selected prefix.

    Parameters
    ----------
    raw_reply : bytes
        Canonical signed operator response, including its full receipt log.
    operation : str
        Requested checkpoint or latest operation.
    history : bytes
        Exact bytes sent to the operator.
    public_key, observer_key : str
        Host-selected witness and observer pins.
    retained : dict
        Signed head previously retained through the host's trusted channel.

    Returns
    -------
    dict
        Authenticated response payload with verified checkpoint and head.
    """
    reply = strict_loads(raw_reply)
    require(canonical(reply) == raw_reply, "reply bytes are noncanonical")
    payload = _checked_payload(reply, public_key)
    require(payload["operation"] == operation, "reply operation differs")
    require(payload["historySha256"] == sha(history), "reply history digest differs")
    entries = history_entries(history)
    checked_identity(entries, observer_key)
    checkpoint_entries = entries[:1] if operation == "latest" else entries
    verify_checkpoint(checkpoint_entries, payload["checkpoint"], public_key)
    receipts = _checked_ledger(payload, retained, public_key)
    _checked_receipt(payload["checkpoint"], receipts, entries, observer_key)
    return payload
