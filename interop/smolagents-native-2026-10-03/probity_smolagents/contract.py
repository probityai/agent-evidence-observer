"""Literal eight-case contract for scripted native smolagents execution."""
from __future__ import annotations

import hashlib
import json
import logging
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)
PROFILE = "probity-smolagents-native-v0"
SDK_SOURCE = "c30b115286e000e98711fae5e85993547b73d826"
SDK_VERSION = "1.27.0.dev0"
CONTENT = "native smolagents authorized effect\n"
FALLBACK = "fallback after max steps"


@dataclass(frozen=True)
class Case:
    """Expected native population, separate from authorized durable effects.

    Parameters
    ----------
    models, tools, effects : int
        Model attempts, custom tool forwards and signed durable writes.
    state : str
        Native run state; success can coexist with a handled tool error.
    action_errors : tuple[str | None, ...]
        Error classes on native ActionStep callbacks, in their exact order.
    final_callbacks : int
        FinalAnswerStep callbacks. A final callback is not in agent memory.
    """
    models: int
    tools: int
    effects: int
    state: str
    action_errors: tuple[str | None, ...]
    final_callbacks: int = 1


CASES = {
    "permit": Case(2, 1, 1, "success", (None, None)),
    "wrong-content": Case(2, 1, 0, "success", ("AgentToolExecutionError", None)),
    "error-before": Case(2, 1, 0, "success", ("AgentToolExecutionError", None)),
    "error-after": Case(2, 1, 1, "success", ("AgentToolExecutionError", None)),
    "max-steps": Case(2, 1, 1, "max_steps_error", (None, "AgentMaxStepsError")),
    "model-error-after": Case(2, 1, 1, "raised", (None, None), 0),
    "incomplete-after": Case(1, 1, 1, "incomplete", (None,), 0),
    "final-without-effect": Case(1, 0, 0, "success", (None,)),
}


def encode(value: Any) -> bytes:
    """Encode unambiguous unsigned UTF-8 JSON with finite numbers only."""
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def sha(raw: bytes) -> str:
    """Return the SHA-256 of exact selected bytes."""
    return hashlib.sha256(raw).hexdigest()


def require(condition: bool, reason: str) -> None:
    """Log and refuse a failed contract condition with an exact reason."""
    if not condition:
        LOGGER.warning(reason)
        raise ValueError(reason)


def exact(actual: Any, expected: Any, reason: str) -> None:
    """Compare encoded values so a boolean never substitutes for an integer."""
    require(encode(actual) == encode(expected), reason)


def load(path: Path) -> Any:
    """Read JSON while refusing duplicates and non-finite scalar values."""
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

    return json.loads(
        path.read_bytes(), object_pairs_hook=unique,
        parse_constant=finite, parse_float=finite_float,
    )


def reply(index: int, case: str) -> dict[str, Any] | None:
    """Return the literal scripted reply, including a failed model attempt."""
    if case == "model-error-after" and index == 1:
        return None
    if case == "max-steps" and index == 1:
        return {
            "role": "assistant", "content": FALLBACK, "tool_calls": None,
            "raw": None, "token_usage": None,
        }
    final = index > 0 or case == "final-without-effect"
    arguments = {"answer": "done"} if final else {
        "content": "wrong bytes" if case == "wrong-content" else CONTENT
    }
    return {
        "role": "assistant", "content": None, "raw": None, "token_usage": None,
        "tool_calls": [{
            "id": f"call-{index + 1}", "type": "function",
            "function": {
                "name": "final_answer" if final else "write_result",
                "arguments": arguments, "description": None,
            },
        }],
    }
