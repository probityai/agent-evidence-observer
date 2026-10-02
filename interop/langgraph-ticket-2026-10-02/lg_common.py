"""Finite packet utilities shared by the real runner and offline reader."""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)
PROFILE = "probity-langgraph-aae-ticket-v0"
VERSION = "1.0.10"
CASES = ("permit", "deny", "altered-argument", "interrupt-before", "resume-after-effect", "pending-intent")
LIMIT = 8 * 1024 * 1024


class PacketError(ValueError):
    """A selected native packet fails a bounded consumer invariant."""


def require(condition: bool, reason: str) -> None:
    """Log a bounded reason and refuse an invariant without dumping evidence.

    Parameters
    ----------
    condition : bool
        Exact consumer invariant being checked.
    reason : str
        Stable error code used by mutation tests and CI consumers.
    """
    if not condition:
        LOGGER.warning("LangGraph packet refused: %s", reason)
        raise PacketError(reason)


def encode(value: Any) -> bytes:
    """Encode a deterministic retained JSON projection; this is not JCS."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def decode(raw: bytes) -> Any:
    """Reject duplicate JSON names before interpreting retained packet bytes."""
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for name, value in pairs:
            require(name not in result, "duplicate-json-name")
            result[name] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def sha(raw: bytes) -> str:
    """Return the SHA-256 digest of literal retained bytes."""
    return hashlib.sha256(raw).hexdigest()


def read(root: Path, name: str) -> bytes:
    """Read one bounded file below a selected directory, refusing symlinks.

    This path guard is reused by :func:`lg_reader.verify_saved`; it does not
    authenticate an operator or protect against concurrent filesystem mutation.
    """
    path = root / name
    require(path.resolve().is_relative_to(root.resolve()), "packet-path")
    require(not any(p.is_symlink() for p in (path, *path.parents)), "packet-symlink")
    with path.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    require(len(raw) <= LIMIT, "packet-size")
    return raw


def write(path: Path, value: Any) -> None:
    """Exclusively create retained evidence; never overwrite a previous run."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(encode(value))


def project(value: Any) -> Any:
    """Retain every public snapshot field without inventing framework events.

    Named tuples and dataclasses are projected with their public field names;
    tuples become JSON arrays. All other values must already be JSON values.
    """
    if hasattr(value, "_asdict"):
        return project(value._asdict())
    if is_dataclass(value) and not isinstance(value, type):
        return project(asdict(value))
    if isinstance(value, dict):
        return {key: project(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [project(item) for item in value]
    return value
