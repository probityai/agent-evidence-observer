"""Public finite population, raw JSON preservation and selected scope."""

import hashlib
import json
from pathlib import Path

from probity_observer.crypto import strict_loads

PROFILE = "probity-ag2-push-authority-v1"
SOURCE = "fd789e3ca8a77d14c8e3e89923665fe62c00cb9a"
SDK = "e649325e041e44c0b0fe57e3eef0699cad164a1e"
TRANSPORTS = ("jsonrpc", "rest", "grpc")
VARIANTS = ("accepted", "registration-denied", "dispatch-denied", "target-denied",
            "legacy-config-only", "sdk-policy-denied")
CASES = tuple(f"{t}/{v}" for t in TRANSPORTS for v in VARIANTS)
TARGET = "https://callback.example.test/receipt"
UNSAFE = ("http://127.0.0.1/private", "http://169.254.169.254/latest", "file:///etc/passwd")
TOKEN = "public-fixture-token"
AUTH = "public-fixture-bearer"
TEXT = "AG2 finite task complete."
CONTENT = b"AG2 callback accepted.\n"
FILES = ("authority-before-run.json", "keys-before-run.json", "begin-before-run.json",
         "native-task.json", "native-agent.json", "native-callbacks.json", "url-policy.json",
         "push-operations.json", "stored-configs.json", "effect-before-dispatch.json",
         "dispatch.json", "target-callbacks.json", "target-effects.json",
         "observer-packet.json", "history.jsonl", "witness-state.json")


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, reason):
    if not value:
        raise ValueError(reason)


def store(path: Path, value):
    path.write_bytes(encode(value))


def decode(raw):
    return strict_loads(raw)


def json_original(raw: str):
    value = bytes.fromhex(raw)
    def unique(pairs):
        result = {}
        for key, item in pairs:
            require(key not in result, "duplicate-native-json-key")
            result[key] = item
        return result
    def constant(value):
        raise ValueError("non-finite-native-json")
    return json.loads(value.decode("utf-8", errors="strict"), object_pairs_hook=unique,
                      parse_constant=constant)


def plan(run_id):
    return {"profile": PROFILE, "runId": run_id, "ag2Revision": SOURCE,
            "a2aSDKRevision": SDK, "cases": list(CASES), "agentModel": "native-TestConfig-fixed-text",
            "providerRequests": 0, "modelQuality": "not-evaluated", "operator": "author-operated",
            "witnessScope": "PEER", "outsideOperator": False,
            "dispatchOperator": "same-author-host-explicit-post-completion-SDK-call",
            "callbackTransport": "native-httpx-ASGITransport-no-network-listener",
            "grpcTransport": "native-grpc-loopback-plaintext",
            "prospectiveEightTaskRun": "not-started",
            "budget": {"cases": 18, "nativeTasks": 18, "maximumDispatchCalls": 15,
                       "maximumTargetCallbacks": 6, "maximumWrites": 3, "elapsedSeconds": 120}}


def selected_files():
    return ["plan-before-run.json", "native-result.json"] + [
        f"cases/{case}/{name}" for case in CASES for name in FILES]
