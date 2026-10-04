"""Byte records and fixed author-operated population for this reference."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

PROFILE = "probity-adk-user-response-routing-v1"
SOURCE = "86a47f6974bae349a5c9ea15a74a4b450614ae42"
OBSERVER = "8c074d7b8f380dd01fd55277b68a37ad8217c8cb"
CASES = ("approval-granted", "approval-denied", "long-running-completed")
FINAL_TEXT = "Issuer handled the supplied response"
ROOT_TEXT = "Root handled the later plain text"
CONTENT = b"one retained finite effect\n"


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def encode(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode()


def decode(raw: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "duplicate-json-member")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, "nonfinite-json"))


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def store(path: Path, value: Any) -> None:
    path.write_bytes(encode(value))


def native(value: Any) -> dict[str, Any]:
    raw = value.model_dump_json().encode()
    return {"jsonHex": raw.hex(), "value": decode(raw)}


def original(record: dict[str, Any]) -> dict[str, Any]:
    value = decode(bytes.fromhex(record["jsonHex"]))
    require(value == record["value"], "native-original-byte-mismatch")
    return value


def plan(run_id: str) -> dict[str, Any]:
    return {
        "profile": PROFILE, "runId": run_id, "sourceRevision": SOURCE,
        "observerRevision": OBSERVER, "cases": list(CASES),
        "resumability": False, "issuer": "issuer", "root": "root",
        "model": "fixed-public-script", "providerRequests": 0,
        "modelQuality": "not-evaluated", "operator": "author-operated",
        "witnessScope": "PEER", "prospectiveEightTaskRun": "not-started",
        "budget": {"cases": 3, "turnsPerCase": 3, "modelCalls": 12,
                   "toolBodyCalls": 2, "elapsedSeconds": 120},
    }
