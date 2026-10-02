"""Bounded identities and immutable packet utilities for joint recovery.

The host selects recovery authority separately from the original signed action
grant. These utilities are shared with the installed offline reader; they import
neither LangGraph nor the native process launcher.
"""
from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import Any

from probity_observer.crypto import VerificationError, canonical, strict_loads

LOGGER = logging.getLogger(__name__)
PROFILE = "probity-joint-process-authority-recovery-v1"
CASES = tuple(f"{mode}-{point}" for mode in ("valid", "revoked", "expired", "rollback", "sticky") for point in ("before", "after")) + (
    "grant-expired-after", "grant-mismatch-after", "authority-key-after",
    "target-key-after", "target-store-after", "target-rollback-after",
    "pending-intent-after", "pending-transaction-after", "concurrent-before",
)
NONCLAIMS = ["power-loss", "general-exactly-once", "remote-identity", "independent-custody", "production-containment"]
LIMIT = 16 * 1024 * 1024
HOST_POLICY = {
    "profile": PROFILE, "plannedAttempts": len(CASES), "maximumWorkerSeconds": 30,
    "maximumTargetStartupSeconds": 10, "parallelCallers": 8,
    "clockScope": "host-selected-integer-high-water-and-fixed-UTC-reference",
    "currentSelection": ["action", "signedGrant", "issuerPolicy", "serviceKey", "storeIdentity", "clock"],
    "authorityBoundary": "before-native-resume-and-cached-result-release",
    "allowCachedEffectWithInvalidAuthority": False, "automaticPendingReplay": False,
    "childEnvironment": "credential-free-allowlist-tracing-disabled",
}


def require(condition: bool, reason: str) -> None:
    """Log a stable bounded refusal without displaying retained evidence.

    Parameters
    ----------
    condition : bool
        Exact invariant; callers must preserve JSON types where relevant.
    reason : str
        Stable reason checked by semantic mutation controls.

    Raises
    ------
    VerificationError
        If ``condition`` is false. The same reason is written to the logger.
    """
    if not condition:
        LOGGER.warning("Joint recovery refused: %s", reason)
        raise VerificationError(reason)


def sha(raw: bytes) -> str:
    """Return the SHA-256 identity of literal bytes, without JSON rewriting."""
    return hashlib.sha256(raw).hexdigest()


def same(value: Any, expected: Any, reason: str) -> None:
    """Compare canonical bytes so boolean values cannot substitute for counters."""
    require(canonical(value) == canonical(expected), reason)


def read(root: Path, name: str) -> bytes:
    """Read one bounded selected file, refusing traversal and symbolic links.

    Parameters
    ----------
    root : pathlib.Path
        Relying-party-selected packet directory.
    name : str
        Relative member name beneath ``root``.

    Returns
    -------
    bytes
        Original member bytes, limited to :data:`LIMIT`.
    """
    path = root / name
    require(path.resolve().is_relative_to(root.resolve()), "packet-path")
    require(not any(item.is_symlink() for item in (path, *path.parents)), "packet-symlink")
    with path.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    require(len(raw) <= LIMIT, "packet-size")
    return raw


def load(root: Path, name: str) -> Any:
    """Parse a bounded original using the Observer duplicate-name refusal."""
    try:
        return strict_loads(read(root, name))
    except VerificationError as error:
        LOGGER.warning("Joint recovery refused: %s", error)
        raise


def write(path: Path, value: Any) -> None:
    """Exclusively create a canonical member; existing originals remain intact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical(value))


def authority(case: dict[str, Any], mode: str = "valid") -> dict[str, Any]:
    """Select deterministic recovery authority bound to the original action.

    The integer clock is a host policy reference, not a claim of trusted wall
    time. The existing merged authority gate persists its high-water mark.
    """
    return {
        "actionSha256": sha(canonical({"request": case["request"], "grant": case["grant"]})),
        "clock": 99 if mode == "rollback" else 200 if mode == "expired" else 100,
        "expires": 200, "revoked": mode in {"revoked", "sticky"},
    }


def expected_authority(name: str, phase: str) -> str:
    """Return the declared finite disposition for one native worker phase."""
    if phase == "first":
        return "authorized"
    if phase == "third":
        return "refused-stale-authority"
    return {
        "revoked": "refused-revoked", "sticky": "refused-revoked",
        "expired": "refused-expired", "rollback": "refused-clock-rollback",
        "grant-expired": "refused-current-grant", "grant-mismatch": "refused-current-selection",
        "authority-key": "refused-current-selection", "target-key": "refused-current-selection",
        "target-store": "refused-current-selection", "target-rollback": "refused-target-startup",
    }.get(name.rsplit("-", 1)[0], "authorized")


def expected_revision(name: str) -> int:
    """Declare retained target revision after the selected finite exercise."""
    return 0 if name.endswith("before") and not name.startswith(("valid", "concurrent")) or name.startswith("pending-") else 1


def phases(name: str) -> tuple[str, ...]:
    """Include a third fresh worker only for equal-clock denial resurrection."""
    return ("first", "second", "third") if name.startswith("sticky-") else ("first", "second")


def child_environment() -> dict[str, str]:
    """Select credential-free native/reader process variables with tracing off.

    No API key, provider credential, user-site path or inherited tracing setting
    reaches an owned child. All interpreter and reader executable paths are
    absolute, so the standard system PATH is sufficient for this finite run.
    """
    return {"PATH": os.defpath, "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1", "LANGSMITH_TRACING": "false", "LANGCHAIN_TRACING_V2": "false"}
