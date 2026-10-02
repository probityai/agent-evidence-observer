"""Shared finite plan and byte framing; no framework or network import."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

from probity_observer.crypto import VerificationError, canonical, strict_loads

LOGGER = logging.getLogger(__name__)
PROFILE = "probity-pydantic-ai-ticket-v0"
VERSION = "1.68.0"
PROMPT = "Execute the selected ticket update."
CONTENT = "DONE"
RETRY = "selected transient pre-dispatch retry"
ERROR = "selected producer failure before HTTP dispatch"
CASES = ("permit", "deny", "changed-arguments", "retry", "producer-error")
MAX_FILE = 2 * 1024 * 1024


def require(condition: bool, reason: str) -> None:
    """Raise and log one bounded refusal without including candidate content.

    Parameters
    ----------
    condition : bool
        Relation that must hold before consumer admission continues.
    reason : str
        Stable public reason used in tests and the CLI's refusal result.

    Raises
    ------
    VerificationError
        If ``condition`` is false. See :func:`read` for byte-level checks.
    """
    if not condition:
        LOGGER.warning("pydantic consumer refused: %s", reason)
        raise VerificationError(reason)


def sha(raw: bytes) -> str:
    """Return the SHA-256 of exact bytes, without JSON normalization."""
    return hashlib.sha256(raw).hexdigest()


def decode(raw: bytes) -> Any:
    """Decode Observer's duplicate-refusing restricted JSON representation."""
    return strict_loads(raw)


def encode(value: Any) -> bytes:
    """Encode profile JSON in Observer's unchanged canonical byte format."""
    return canonical(value)


def read(root: Path, name: str) -> bytes:
    """Read a bounded literal file from an already selected packet directory.

    Parameters
    ----------
    root : Path
        Selected packet directory. Symlinks are refused by the outer reader.
    name : str
        Profile-owned relative path; never a candidate-selected arbitrary path.

    Returns
    -------
    bytes
        Exact file content, limited to :data:`MAX_FILE` bytes.
    """
    path = root / name
    require(path.is_file() and not path.is_symlink(), "packet file missing or linked")
    with path.open("rb") as handle:
        raw = handle.read(MAX_FILE + 1)
    require(len(raw) <= MAX_FILE, "packet file exceeds bound")
    return raw


def write(path: Path, raw: bytes) -> None:
    """Create exact retained bytes once, refusing an existing artifact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(raw)


def script(case: str) -> list[str]:
    """Return the frozen native tool argument sequence for one declared case."""
    require(case in CASES, "unknown declared case")
    if case == "retry":
        return [CONTENT, CONTENT]
    return ["CHANGED" if case == "changed-arguments" else CONTENT]


def expected_outcome(case: str, index: int) -> str:
    """Select the frozen dispatch outcome; a trace cannot choose its own branch."""
    if case == "producer-error":
        return "error"
    if case == "retry" and index == 0:
        return "retry"
    return "return"
