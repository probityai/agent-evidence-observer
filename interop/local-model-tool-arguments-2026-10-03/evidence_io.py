"""Bounded original-byte operations for the authored tool-argument study.

These operations retain observations; they do not witness an independent host
or authorize a model-proposed tool effect. Candidate code is never imported.
"""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import logging
import math
import os
from pathlib import Path
import stat
from typing import Any

LOGGER = logging.getLogger(__name__)
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_PACKET_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 1024
MAX_DEPTH = 32
MAX_JSON_NODES = 50000


def require(condition: bool, message: str) -> None:
    """Refuse a failed evidence relation using its stable logged message."""
    if not condition:
        LOGGER.error("%s", message)
        raise ValueError(message)


def digest(raw: bytes) -> str:
    """Commit to one unmodified byte buffer with SHA-256."""
    return hashlib.sha256(raw).hexdigest()


def encode(value: Any) -> bytes:
    """Serialize finite JSON with deterministic members and one final newline."""
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate object members rather than silently selecting the last."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON member")
        result[key] = value
    return result


def invalid_constant(_: str) -> None:
    """Refuse nonfinite JSON constants with a stable message."""
    require(False, "nonfinite JSON")


def bounded_json(value: Any) -> None:
    """Require finite JSON within selected depth and population limits.

    Traversal is iterative. Depth applies to every child, including scalar
    leaves; at most fifty thousand values may be assessed in one document.
    """
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        require(depth <= MAX_DEPTH and count <= MAX_JSON_NODES, "JSON population or depth exceeds selection")
        require(not isinstance(item, float) or math.isfinite(item), "nonfinite JSON")
        if isinstance(item, (dict, list)):
            children = item.values() if isinstance(item, dict) else item
            pending.extend((child, depth + 1) for child in children)


def strict_json(raw: bytes | str) -> Any:
    """Read finite, duplicate-free JSON and check its bounded value population.

    Parameters
    ----------
    raw : bytes or str
        A selected byte buffer or native response text. File size is checked
        separately by :func:`read_regular` before candidate file consumption.

    Returns
    -------
    object
        Standard Python JSON values without coercion or member replacement.

    Raises
    ------
    ValueError
        For malformed, duplicate, nonfinite, overpopulated or too deep JSON.
    """
    try:
        result = json.loads(raw, object_pairs_hook=unique_members, parse_constant=invalid_constant)
        bounded_json(result)
        return result
    except RecursionError as error:
        raise ValueError("JSON population or depth exceeds selection") from error


def read_regular(path: Path, maximum: int = MAX_FILE_BYTES) -> bytes:
    """Read a bounded regular original without blocking on FIFO or final link.

    The caller's host filesystem must prevent concurrent replacement of
    ancestor directories. :func:`packet_buffers` refuses linked descendants
    and assesses the exact buffers returned by this function.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise ValueError("selected artifact is absent or linked") from error
    try:
        require(stat.S_ISREG(os.fstat(descriptor).st_mode), "selected artifact must be a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
    finally:
        os.close(descriptor)
    require(len(raw) <= maximum, "selected artifact exceeds file budget")
    return raw


def packet_buffers(root: Path) -> dict[str, bytes]:
    """Snapshot one finite original packet into bounded selected byte buffers.

    No candidate module or binary is executed. Links and special files refuse,
    including directories. The complete packet allows at most1024entries,
    depth32 and64MiB. Candidate traversal is iterative and does not follow
    symlinks. Every later relation uses these exact buffers.
    """
    require(root.is_dir() and not root.is_symlink(), "packet root must be a selected directory")
    pending = [(root, 0)]
    entries, total = 0, 0
    result: dict[str, bytes] = {}
    while pending:
        directory, depth = pending.pop()
        require(depth <= MAX_DEPTH, "packet depth exceeds selection")
        with os.scandir(directory) as children:
            for child in children:
                entries += 1
                require(entries <= MAX_ENTRIES and not child.is_symlink(), "packet contains links or exceeds entry selection")
                path = Path(child.path)
                if child.is_dir(follow_symlinks=False):
                    pending.append((path, depth + 1))
                    continue
                raw = read_regular(path)
                total += len(raw)
                require(total <= MAX_PACKET_BYTES, "packet exceeds byte selection")
                result[path.relative_to(root).as_posix()] = raw
    return result


def write(path: Path, value: Any) -> None:
    """Exclusively retain complete bytes or deterministic JSON and fsync them."""
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = value if isinstance(value, bytes) else encode(value)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def now() -> str:
    """Return the operator's current UTC timestamp for ordered observations."""
    return datetime.now(UTC).isoformat()


def timestamp(value: str) -> datetime:
    """Parse a timezone-bearing observation time without assuming local time."""
    result = datetime.fromisoformat(value)
    require(result.utcoffset() is not None, "timestamp requires timezone")
    return result
