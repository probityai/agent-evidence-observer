"""Closed deferred-result profile and durable, bounded byte operations."""
from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from pathlib import Path
from typing import Any

from probity_observer.crypto import VerificationError, canonical, strict_loads

PROFILE = "probity-pydantic-deferred-worker-recovery-v1"
CASES = ("permit", "revoked", "expired", "changed-grant", "changed-arguments", "target-key", "missing-store", "rollback-store", "crash-window")
NONCLAIMS = ["independent-custody", "caller-identity", "provider-model-quality", "power-loss", "general-exactly-once", "outside-adoption"]
MAX_FILE = 2 * 1024 * 1024
TARGET_REFUSALS = {"target-key": "ticket key differs from consumer pin", "missing-store": "ticket store is missing; initialization required", "rollback-store": "ticket history predates retained head"}
RECOVERY_REFUSALS = {"revoked": "ticket consumer requires unrevoked bounded completion", "expired": "grant is not valid at the reference time", "changed-grant": "grant signature does not verify under the pinned issuer key", "changed-arguments": "deferred-call-binding", "target-key": "current-target-not-ready", "missing-store": "current-target-not-ready", "rollback-store": "current-target-not-ready", "crash-window": "historical-http-journal-missing"}


def require(condition: bool, reason: str) -> None:
    """Refuse a bounded relation without including candidate secrets."""
    if not condition:
        raise VerificationError(reason)


def sha(raw: bytes) -> str:
    """Hash the exact original bytes."""
    return hashlib.sha256(raw).hexdigest()


def read(path: Path) -> bytes:
    """Open one bounded regular file without following its final symlink."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise VerificationError("missing-or-linked-file") from error
    try:
        require(stat.S_ISREG(os.fstat(descriptor).st_mode), "nonregular-file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_FILE + 1)
    finally:
        os.close(descriptor)
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
    try:
        result = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    except (ValueError, RecursionError) as error:
        raise VerificationError("native-json-refused") from error
    bounded_json(result)
    require(type(result) is list, "native-history-type")
    return result


def bounded_json(result: Any) -> None:
    """Bound finite native metadata without recursion or executing candidate code."""
    pending = [(result, 0)]
    while pending:
        value, depth = pending.pop()
        require(depth <= 32, "native-json-depth")
        require(not isinstance(value, float) or math.isfinite(value), "native-nonfinite-number")
        if isinstance(value, (dict, list)):
            children = value.values() if isinstance(value, dict) else value
            pending.extend((child, depth + 1) for child in children)


def invalid_constant(value: str) -> None:
    """Refuse nonfinite native JSON numbers rather than accepting parser defaults."""
    raise VerificationError("native-nonfinite-number")


def deferred(raw: bytes, case: dict[str, Any]) -> dict[str, Any]:
    """Bind the only native deferred call to the frozen typed action."""
    history = messages(raw)
    require(len(history) == 2, "deferred-history-population")
    require(history[0]["kind"] == "request" and history[1]["kind"] == "response", "deferred-message-kinds")
    prompt = history[0]["parts"]
    require(len(prompt) == 1 and prompt[0].get("part_kind") == "user-prompt" and prompt[0].get("content") == "Execute the selected ticket update.", "deferred-prompt-binding")
    require(len(history[1]["parts"]) == 1, "deferred-call-population")
    call = history[1]["parts"][0]
    expected = {"part_kind": "tool-call", "tool_name": "dispatch_ticket", "args": {"content": "DONE"}, "tool_call_id": case["id"] + "-call"}
    require(all(call.get(key) == value for key, value in expected.items()), "deferred-call-binding")
    return call


def child_environment() -> dict[str, str]:
    """Supply only explicit local process settings, with tracing disabled."""
    selected = {key: os.environ[key] for key in ("PATH", "VIRTUAL_ENV", "PYTHONPATH", "LANG", "LC_ALL", "SYSTEMROOT") if key in os.environ}
    return {**selected, "OTEL_SDK_DISABLED": "true", "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"}
