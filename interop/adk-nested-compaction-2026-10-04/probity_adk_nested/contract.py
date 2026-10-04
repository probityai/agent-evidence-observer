"""Finite population, native byte admission and declared operator scope."""

import hashlib
import json

PROFILE = "probity-adk-nested-compaction-v1"
SOURCE = "81c43680d6ebe0288b77a2e9ff746f696889c75d"
CASES = ("token", "no-config", "window-only", "token-no-plugins")
PAYLOAD = "lorem ipsum dolor sit amet " * 80
FILES = ("keys-before-run.json", "authority-before-run.json", "begin-before-run.json",
         "parent-config-before.json", "parent-config-after.json", "yielded-root-events.json",
         "plugin-before-parent-close.json", "plugin-after-parent-close.json", "root-session.json",
         "model-requests.json", "tool-effects.json", "observer-packet.json", "history.jsonl",
         "witness-state.json")


def require(value, reason):
    if not value:
        raise ValueError(reason)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate-json-key")
            result[key] = value
        return result
    def constant(value):
        raise ValueError("non-finite-json")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=constant)


def original(value):
    require(set(value) == {"jsonHex", "value"}, "native-wrapper-fields")
    result = decode(bytes.fromhex(value["jsonHex"]))
    require(result == value["value"], "native-original-bytes")
    return result


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def store(path, value):
    path.write_bytes(encode(value))


def plan(run_id):
    return {"profile": PROFILE, "runId": run_id, "sourceRevision": SOURCE,
            "cases": list(CASES), "agentTree": "root -> AgentTool(middle) -> AgentTool(leaf)",
            "rootCalls": 3, "middleCalls": 4, "leafCalls": 8, "leafRuns": 2,
            "model": "fixed-public-BaseLlm-script", "providerRequests": 0,
            "operator": "author-operated", "witnessScope": "PEER", "outsideOperator": False,
            "modelQuality": "not-evaluated", "older16Rows": "unchanged",
            "prospectiveEightTaskRun": "not-started",
            "budget": {"cases": 4, "agentModelCalls": 60, "summaryModelCalls": 19,
                       "nativeToolWrites": 24, "elapsedSeconds": 120}}


def selected_files():
    return ["plan-before-run.json", "native-result.json"] + [
        f"cases/{case}/{name}" for case in CASES for name in FILES]
