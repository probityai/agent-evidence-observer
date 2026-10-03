"""Public finite fault population and exact byte contract."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

PROFILE = "probity-haystack-native-v0"
SDK_VERSION = "3.3.0"
SDK_SOURCE = "daa2d1ffacd083dcb1fc9a455adf541360a9e09c"
CONTENT = "native Haystack authorized effect\n"
# (model calls, tool calls, durable writes, exit reason, raised exception, tool errors)
CASES = {
    "permit": (2, 1, 1, "text", False, 0),
    "wrong-content": (2, 1, 0, "text", False, 1),
    "error-before": (2, 1, 0, "text", False, 1),
    "handled-after": (2, 1, 1, "text", False, 1),
    "unhandled-after": (1, 1, 1, None, True, 0),
    "max-steps": (1, 1, 1, "max_agent_steps", False, 0),
    "length": (1, 0, 0, "length", False, 0),
}


def encode(value: Any) -> bytes:
    """Return unambiguous UTF-8 JSON bytes for this unsigned artifact profile."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(value: bytes) -> str:
    """Hash the exact selected bytes."""
    return hashlib.sha256(value).hexdigest()


def load(path: Path) -> Any:
    """Read strict JSON without duplicate member names or non-finite values."""
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result
    def refuse(value: str) -> None:
        raise ValueError("non-finite JSON number")
    return json.loads(path.read_bytes(), object_pairs_hook=unique, parse_constant=refuse)
