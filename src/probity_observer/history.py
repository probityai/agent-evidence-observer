"""Durable hash-chain history and a separately keyed checkpoint witness.

The witness checks append-only extension before signing a new head. It must be
deployed under a separate operator to make that separation a trust claim; two
keys generated on one laptop are only a protocol demonstration.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .crypto import SigningKey, VerificationError, canonical, digest, strict_loads, verify_signature

GENESIS = "0" * 64


def read_history(path: Path) -> list[dict[str, Any]]:
    """Verify and return every entry in an append-only JSONL history.

    Parameters
    ----------
    path : Path
        History file. A missing file represents an empty history.

    Returns
    -------
    list[dict[str, Any]]
        Entries whose sequence, predecessor, hash, and canonical bytes agree.

    Raises
    ------
    VerificationError
        If a line was changed, removed from the middle, or reordered.
    """
    if not path.exists():
        return []
    raw = path.read_bytes()
    if raw and not raw.endswith(b"\n"):
        raise VerificationError("history ends with an incomplete line")
    entries: list[dict[str, Any]] = []
    for line in raw.splitlines():
        entry = strict_loads(line)
        expected_prev = entries[-1]["hash"] if entries else GENESIS
        if entry["sequence"] != len(entries) + 1 or entry["previous"] != expected_prev:
            raise VerificationError("history sequence or predecessor differs")
        body = {key: entry[key] for key in ("sequence", "previous", "event")}
        if entry["hash"] != digest("probity-history-entry-v0", body):
            raise VerificationError("history entry digest differs")
        entries.append(entry)
    return entries


def unresolved_intents(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Find writes whose durable intent has no matching effect event."""
    pending: dict[str, Any] | None = None
    seen: set[str] = set()
    for entry in entries:
        event = entry["event"]
        kind = event["kind"]
        if pending is not None and kind not in {"write", "incomplete", "seal"}:
            raise VerificationError("history has an event inside an unresolved write")
        if kind == "write-intent":
            request_id = event["requestId"]
            if pending is not None or request_id in seen:
                raise VerificationError("history has overlapping or repeated write intents")
            pending = event
            seen.add(request_id)
        elif kind == "write":
            if pending is None:
                raise VerificationError("history write has no durable intent")
            if any(event[field] != pending[field] for field in ("requestId", "path", "contentDigest", "beforeRoot")):
                raise VerificationError("history write differs from its durable intent")
            pending = None
    return [pending] if pending is not None else []


def append_history(path: Path, event: dict[str, Any]) -> dict[str, Any]:
    """Append one event, flush it durably, and return its hash-chain entry.

    The prototype permits one writer per file. A production service needs an
    operating-system lock or transactional storage before concurrent writers.
    """
    entries = read_history(path)
    body = {
        "sequence": len(entries) + 1,
        "previous": entries[-1]["hash"] if entries else GENESIS,
        "event": event,
    }
    entry = {**body, "hash": digest("probity-history-entry-v0", body)}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as stream:
        stream.write(canonical(entry) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return entry


class Witness:
    """A monotonic checkpoint signer with its own retained latest head.

    Parameters
    ----------
    state_path : Path
        The witness's private state file, outside the observed workload's tree.
    signing_key : SigningKey
        Key pinned separately from the observer key by an offline consumer.

    Notes
    -----
    This signer checks a proposed history extends its last witnessed prefix.
    It cannot prove it is controlled by an independent organization. The caller
    must establish that custody and publish checkpoints to detect equivocation.
    """

    def __init__(self, state_path: Path, signing_key: SigningKey) -> None:
        self.state_path = state_path
        self.signing_key = signing_key

    def checkpoint(self, history_path: Path) -> dict[str, Any]:
        """Sign the current head after verifying prefix consistency.

        Raises
        ------
        VerificationError
            If the history diverges from a head this witness signed earlier.
        """
        entries = read_history(history_path)
        old = self._previous()
        if old is not None:
            count = old["count"]
            prefix_head = entries[count - 1]["hash"] if count <= len(entries) and count else GENESIS
            if count > len(entries) or prefix_head != old["head"]:
                raise VerificationError("history does not extend the witnessed head")
        payload = {"count": len(entries), "head": entries[-1]["hash"] if entries else GENESIS}
        checkpoint = {
            **payload,
            "keyid": self.signing_key.public_hex,
            "signature": self.signing_key.sign("probity-checkpoint-v0", payload),
        }
        self._persist(checkpoint)
        return checkpoint

    def _previous(self) -> dict[str, Any] | None:
        if not self.state_path.exists():
            return None
        previous = strict_loads(self.state_path.read_bytes())
        if previous["keyid"] != self.signing_key.public_hex:
            raise VerificationError("witness state key differs from its signer")
        payload = {key: previous[key] for key in ("count", "head")}
        verify_signature(previous["keyid"], "probity-checkpoint-v0", payload, previous["signature"])
        return previous

    def _persist(self, checkpoint: dict[str, Any]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(".tmp")
        with temporary.open("wb") as stream:
            stream.write(canonical(checkpoint))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.state_path)
        parent = os.open(self.state_path.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)


def verify_checkpoint(entries: list[dict[str, Any]], checkpoint: dict[str, Any], pinned_key: str) -> None:
    """Verify a checkpoint binds exactly the supplied history under a pinned key."""
    if checkpoint["keyid"] != pinned_key:
        raise VerificationError("checkpoint key is not the pinned witness key")
    expected_head = entries[-1]["hash"] if entries else GENESIS
    if checkpoint["count"] != len(entries) or checkpoint["head"] != expected_head:
        raise VerificationError("checkpoint does not bind the supplied history")
    payload = {key: checkpoint[key] for key in ("count", "head")}
    verify_signature(pinned_key, "probity-checkpoint-v0", payload, checkpoint["signature"])
