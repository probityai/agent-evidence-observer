"""Finite reference profile; no framework or provider import."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from probity_observer.crypto import VerificationError

PROFILE = "probity-openai-agents-ticket-v0"
VERSION = "0.23.1"
CASES = (
    "permit",
    "deny",
    "changed-arguments",
    "producer-error",
    "committed-effect-error",
    "turns-exhausted",
)
CONTENT = "DONE"
PROMPT = "Execute the selected synthetic ticket update."
BEFORE_ERROR = "selected producer failure before HTTP dispatch"
AFTER_ERROR = "selected producer failure after committed HTTP effect"
LIMIT = 8 * 1024 * 1024


def require(condition: bool, reason: str) -> None:
    """Refuse without logging candidate contents or exception payloads."""
    if not condition:
        raise VerificationError(reason)


def sha(raw: bytes) -> str:
    """Digest exact bytes."""
    return hashlib.sha256(raw).hexdigest()


def encode(value: Any) -> bytes:
    """Serialize the profile's deterministic projection, without a JCS claim."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse duplicate names in original native exports."""
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate-json-name")
        result[key] = value
    return result


def invalid(value: str) -> None:
    """Refuse nonfinite non-JSON numeric values."""
    require(False, "nonfinite-json-number")


def decode(raw: bytes) -> Any:
    """Decode exact native JSON without collapsing duplicate fields."""
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def same(actual: Any, expected: Any, reason: str) -> None:
    """Compare typed JSON encodings, so boolean counters cannot equal integers."""
    require(encode(actual) == encode(expected), reason)


def read(root: Path, name: str) -> bytes:
    """Read bounded relative evidence and refuse every symlink ancestor."""
    path = root / name
    require(path.resolve().is_relative_to(root.resolve()), "packet-path")
    require(not any(p.is_symlink() for p in (path, *path.parents)), "packet-symlink")
    with path.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    require(len(raw) <= LIMIT, "packet-size")
    return raw


def write(path: Path, raw: bytes) -> None:
    """Retain exact evidence once without replacing an existing artifact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)


def arguments(case: str) -> dict[str, str]:
    """Select the frozen synthetic call arguments."""
    return {"content": "CHANGED" if case == "changed-arguments" else CONTENT}
