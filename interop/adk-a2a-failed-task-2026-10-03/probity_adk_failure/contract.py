"""Literal native task/effect cases and strict unsigned JSON utilities."""
from __future__ import annotations

import hashlib
import json
import logging
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)
PROFILE = "probity-adk-a2a-failed-task-v0"
SDK_VERSION = "2.11.0"
A2A_VERSION = "1.2.1"
A2A_SOURCE = "041c17bbe8d5ced7a8f6c48761152ce01ffbfc14"
REVISIONS = {
    "baseline": "63aed55113d4fe78245d3d6667b6e87569888bf5",
    "proposed-fix": "23d253f2587ac090412394fe1a71ef5694fe2eda",
}
CONTENT = "native A2A authorized effect\n"
FAILURE = "controlled remote failure"
BARE_FAILURE = "Remote A2A task failed"
ARTIFACTS = ("grant.json", "history.jsonl", "native.json", "packet.json", "wire.json")


@dataclass(frozen=True)
class Case:
    """Host-selected terminal and effect population for one native request.

    Parameters
    ----------
    effects : int
        Durable writes required by the signed Observer packet.
    state : str
        Expected native remote task state, without the TASK_STATE_ prefix.
    text : str | None
        Terminal remote message text. ``None`` exercises a bare failure.
    complete : bool
        Whether the ADK caller retains terminal closure. A dropped-closure
        caller stops after the working event, although the wire still records
        the remote server's final failure.
    """
    effects: int
    state: str
    text: str | None
    complete: bool = True


CASES = {
    "permit": Case(1, "COMPLETED", "done"),
    "failed-before": Case(0, "FAILED", FAILURE),
    "failed-after": Case(1, "FAILED", FAILURE),
    "failed-after-bare": Case(1, "FAILED", None),
    "status-after-content": Case(1, "FAILED", FAILURE),
    "dropped-closure": Case(1, "WORKING", "done", False),
}


def encode(value: Any) -> bytes:
    """Serialize finite unsigned JSON with stable UTF-8 field ordering."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha(raw: bytes) -> str:
    """Return the SHA-256 of exact selected bytes."""
    return hashlib.sha256(raw).hexdigest()


def require(condition: bool, reason: str) -> None:
    """Log and refuse an unmet contract condition with the exact reason."""
    if not condition:
        LOGGER.warning(reason)
        raise ValueError(reason)


def exact(actual: Any, expected: Any, reason: str) -> None:
    """Compare encoded values so booleans cannot substitute for counts."""
    require(encode(actual) == encode(expected), reason)


def decode(raw: bytes | str) -> Any:
    """Parse JSON while refusing duplicate members and non-finite numbers.

    Parameters
    ----------
    raw : bytes or str
        Exact selected JSON bytes, including native JSONRPC/SSE payloads.

    Returns
    -------
    Any
        Parsed JSON value. Shape and semantics remain the caller's obligation.

    Raises
    ------
    ValueError
        When duplicate members or non-finite numeric values occur.
    """
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON member")
            result[key] = value
        return result

    def finite(value: str) -> None:
        require(False, "non-finite JSON number")

    def finite_float(value: str) -> float:
        parsed = float(value)
        require(math.isfinite(parsed), "non-finite JSON number")
        return parsed

    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=finite, parse_float=finite_float)


def load(path: Path) -> Any:
    """Read selected bytes and apply :func:`decode` without weakening checks."""
    return decode(path.read_bytes())


def population() -> list[tuple[str, bool]]:
    """Return ten complete cases and one streamed dropped-closure control."""
    return [(case, streaming) for case in CASES for streaming in (True, False)
            if CASES[case].complete or streaming]


def identity(case: str, streaming: bool) -> str:
    """Return an unambiguous case identity for a native transport mode."""
    return f"{case}-{'streamed' if streaming else 'nonstreamed'}"


def state_label(value: Any) -> str | None:
    """Normalize only native string/enum labels, preserving unknown states."""
    if value is None:
        return None
    return str(value).removeprefix("TASK_STATE_").upper()
