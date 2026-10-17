"""Byte forms, payload types and keys shared by every done record.

Every record is RFC 8785 bytes (through ``probityai.jcs``), so a record's digest is the
digest of one canonical spelling. Records are signed as DSSE envelopes whose payload type
names the record format. The in-toto Statements that carry the ``done-contract`` and
``done-receipt`` predicate types are written beside the envelopes but left unsigned: no signed
statement may carry those URIs before their Pages documents are live.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from probityai import dsse

from ..witness.checkpoint import canonical, signer, verifier

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_BASE = "https://probityai.github.io/probity/predicate/v1/"
CONTRACT_PREDICATE = PREDICATE_BASE + "done-contract"
RECEIPT_PREDICATE = PREDICATE_BASE + "done-receipt"

PAYLOAD_TYPES = {
    "probity-done-contract/v1": "application/vnd.probity.done-contract.v1+json",
    "probity-tree/v1": "application/vnd.probity.tree.v1+json",
    "probity-observation/v2": "application/vnd.probity.observation.v2+json",
    "probity-capabilities/v1": "application/vnd.probity.capabilities.v1+json",
    "probity-acceptance-grade/v1": "application/vnd.probity.acceptance-grade.v1+json",
    "probity-tool-claims/v1": "application/vnd.probity.tool-claims.v1+json",
    "probity-done-receipt/v1": "application/vnd.probity.done-receipt.v1+json",
}


class DoneError(ValueError):
    """A done record, bundle or input cannot be used."""


def encode(value: Any) -> bytes:
    """The RFC 8785 bytes a record is pinned and signed by."""
    return canonical(value)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def payload_type(record: dict[str, Any]) -> str:
    """The DSSE payload type of a record, from its ``schema_version``."""
    try:
        return PAYLOAD_TYPES[record["schema_version"]]
    except KeyError as exc:
        raise DoneError(f"no payload type for record {record.get('schema_version')!r}") from exc


def sign_record(record: dict[str, Any], key: dsse.Ed25519Signer) -> tuple[bytes, bytes]:
    """Return the record's bytes and a DSSE envelope over them."""
    data = encode(record)
    return data, dsse.sign(payload_type(record), data, key)


def open_record(envelope: bytes, public_key: str, expected_schema: str) -> bytes:
    """Verify one envelope under a pinned key and return its payload bytes.

    The payload must be RFC 8785 bytes of a record of the expected format.
    """
    try:
        verified = dsse.verify(envelope, verifier(public_key))
    except dsse.DsseError as exc:
        raise DoneError(f"{expected_schema}: signature does not verify: {exc.variant}") from exc
    if verified.payload_type != PAYLOAD_TYPES[expected_schema]:
        raise DoneError(f"{expected_schema}: unexpected payload type {verified.payload_type}")
    payload = verified.payload
    record = json.loads(payload)
    if encode(record) != payload or record.get("schema_version") != expected_schema:
        raise DoneError(f"{expected_schema}: payload is not the canonical record")
    return payload


def statement(predicate_type: str, subject_name: str, subject_sha256: str,
              predicate: dict[str, Any]) -> dict[str, Any]:
    """An unsigned in-toto Statement v1 carrying one predicate."""
    return {"_type": STATEMENT_TYPE,
            "subject": [{"name": subject_name, "digest": {"sha256": subject_sha256}}],
            "predicateType": predicate_type, "predicate": predicate}


def new_seed(path: Path) -> str:
    """Write a fresh 32-byte Ed25519 seed as hex (mode 0600) and return its public key."""
    seed = os.urandom(32)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(seed.hex() + "\n")
    return signer(seed).public_key.hex()


def load_signer(path: Path) -> dsse.Ed25519Signer:
    """Read a hex seed file written by :func:`new_seed`."""
    text = Path(path).read_text().strip()
    try:
        seed = bytes.fromhex(text)
    except ValueError as exc:
        raise DoneError(f"{path}: not a hex seed") from exc
    if len(seed) != 32:
        raise DoneError(f"{path}: a seed is 32 bytes")
    return signer(seed)


def public_key(key: dsse.Ed25519Signer) -> str:
    return key.public_key.hex()
