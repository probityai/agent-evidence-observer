"""Finite CrewAI job population and strict admission of retained JSON bytes."""

import hashlib
import json

PROFILE = "probity-crewai-job-fences-v1"
SOURCE = "738c8e19e35c2888d8e0663bc5cc45c5acf6ac2d"
DIRECT_CASES = ("valid-stage", "foreign-owner", "missing-job", "stale-revision", "stale-attempt",
                "duplicate-sequence", "sequence-gap", "wrong-stage", "uncommitted-next-stage",
                "overwrite-input", "overwrite-lifecycle", "invalid-output-type", "nonstage-output",
                "premature-completion", "postterminal", "regressing-sequence", "strict-boolean-sequence")
CASES = ("valid-runner", "refusal-before-body", "effect-before-refusal")
PAYLOAD = "Probity public finite CrewAI job fixture.\n"
FILES = ("keys-before-run.json", "authority-before-run.json", "begin-before-run.json",
         "job-before-run.json", "native-state-before-run.json", "native-state-after-run.json",
         "manual-publication.json", "callbacks.json", "snapshots.json", "worker-events.json",
         "body-effects.json", "observer-packet.json", "history.jsonl", "witness-state.json",
         "runner-after-close.json")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode()


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "duplicate-json-key")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, "non-finite-json"))


def original(value):
    require(set(value) == {"jsonHex", "value"}, "native-wrapper-fields")
    decoded = decode(bytes.fromhex(value["jsonHex"]))
    require(decoded == value["value"], "native-original-bytes")
    return decoded


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    path.write_bytes(encode(value))


def plan(run_id):
    return {"profile": PROFILE, "runId": run_id, "sourceRevision": SOURCE,
            "directCases": list(DIRECT_CASES), "runnerCases": list(CASES),
            "model": "none-native-experimental-JobWorkFlow", "providerRequests": 0,
            "operator": "author-operated", "witnessScope": "PEER", "outsideOperator": False,
            "modelQuality": "not-evaluated", "older16Rows": "unchanged",
            "prospectiveEightTaskRun": "not-started",
            "faultOperator": "author-controlled-stale-revision-proposal-before-native-commit",
            "effectAuthority": "author-installed-Observer-write-file-broker; SDK job commit is separate",
            "publicationAuthority": "explicit-author-foreground-status-turn; no automatic job publication",
            "budget": {"directCases": 17, "runnerCases": 3, "nativeBodyWrites": 2,
                       "foregroundTurns": 3, "providerCalls": 0, "elapsedSeconds": 120}}


def selected_files():
    result = ["plan-before-run.json", "native-result.json"]
    result += [f"direct/{case}/{name}" for case in DIRECT_CASES
               for name in ("inputs-before-call.json", "native-call.json")]
    result += [f"cases/{case}/{name}" for case in CASES for name in FILES]
    result += [f"cases/{case}/workspace/result.txt" for case in CASES
               if case != "refusal-before-body"]
    return result
