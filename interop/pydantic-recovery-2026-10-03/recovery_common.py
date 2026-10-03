"""Closed deferred-result profile and durable, bounded byte operations."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from probity_observer.crypto import VerificationError, canonical, strict_loads

PROFILE = "probity-pydantic-deferred-worker-recovery-v1"
CASES = ("permit", "revoked", "expired", "changed-grant", "changed-arguments", "target-key", "missing-store", "rollback-store", "crash-window")
NONCLAIMS = ["independent-custody", "caller-identity", "provider-model-quality", "power-loss", "general-exactly-once", "outside-adoption"]
MAX_FILE = 2 * 1024 * 1024


def require(condition: bool, reason: str) -> None:
    """Refuse a bounded relation without including candidate secrets."""
    if not condition:
        raise VerificationError(reason)


def sha(raw: bytes) -> str:
    """Hash the exact original bytes."""
    return hashlib.sha256(raw).hexdigest()


def read(path: Path) -> bytes:
    """Read one bounded regular file without following a symlink."""
    require(path.is_file() and not path.is_symlink(), "missing-or-linked-file")
    with path.open("rb") as handle:
        raw = handle.read(MAX_FILE + 1)
    require(len(raw) <= MAX_FILE, "file-bound")
    return raw


def load(path: Path) -> Any:
    """Parse the closed canonical JSON profile."""
    return strict_loads(read(path))


def write(path: Path, value: Any, *, raw: bool = False) -> None:
    """Create and fsync exact bytes, then fsync their parent directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(value if raw else canonical(value))
        handle.flush()
        os.fsync(handle.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse duplicate members in the native serializer's ordinary JSON."""
    result: dict[str, Any] = {}
    for name, value in pairs:
        require(name not in result, "native-duplicate-member")
        result[name] = value
    return result


def messages(raw: bytes) -> list[dict[str, Any]]:
    """Parse native message bytes without importing Pydantic AI."""
    result = json.loads(raw, object_pairs_hook=unique)
    require(type(result) is list, "native-history-type")
    return result


def deferred(raw: bytes, case: dict[str, Any]) -> dict[str, Any]:
    """Bind the only native deferred call to the frozen typed action."""
    history = messages(raw)
    require(len(history) == 2, "deferred-history-population")
    require(history[0]["kind"] == "request" and history[1]["kind"] == "response", "deferred-message-kinds")
    require(len(history[1]["parts"]) == 1, "deferred-call-population")
    call = history[1]["parts"][0]
    expected = {"part_kind": "tool-call", "tool_name": "dispatch_ticket", "args": {"content": "DONE"}, "tool_call_id": case["id"] + "-call"}
    require(all(call.get(key) == value for key, value in expected.items()), "deferred-call-binding")
    return call


def child_environment() -> dict[str, str]:
    """Supply only explicit local process settings, with tracing disabled."""
    selected = {key: os.environ[key] for key in ("PATH", "VIRTUAL_ENV", "PYTHONPATH", "LANG", "LC_ALL", "SYSTEMROOT") if key in os.environ}
    return {**selected, "OTEL_SDK_DISABLED": "true", "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"}
