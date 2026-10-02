"""Explicitly selected host recovery authority, separate from signed effect grant."""
from __future__ import annotations

import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent / "langgraph-ticket-2026-10-02"
sys.path.insert(0, str(BASE))
from lg_common import decode, encode, read, require, sha, write  # noqa: E402,F401

PROFILE = "probity-langgraph-recovery-authority-v0"
CASES = tuple(f"{state}-{point}" for state in ("valid", "revoked", "expired", "rollback") for point in ("before", "after"))
FIELDS = {"actionSha256", "clock", "expires", "revoked"}


def authority(case: dict, state: str = "valid") -> dict:
    """Declare deterministic host-clock selections; no trusted wall-clock claim."""
    return {"actionSha256": sha(encode({"request": case["request"], "grant": case["grant"]})), "clock": 99 if state == "rollback" else 200 if state == "expired" else 100, "expires": 200, "revoked": state == "revoked"}


def validate(value: dict, binding: str, prior: int) -> str:
    """Fail closed on schema, action, rollback, revocation or exact expiry boundary."""
    require(set(value) == FIELDS, "authority-fields")
    require(type(value["clock"]) is int and type(value["expires"]) is int and type(value["revoked"]) is bool, "authority-types")
    require(value["actionSha256"] == binding, "authority-action")
    return disposition(value, prior)


def disposition(value: dict, prior: int) -> str:
    """Selected refusal order is explicit and independently reconstructed."""
    if value["clock"] < prior:
        return "refused-clock-rollback"
    if value["revoked"]:
        return "refused-revoked"
    if value["clock"] >= value["expires"]:
        return "refused-expired"
    return "authorized"
