"""Framework-free routing reconstruction and actual Observer packet verification."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from probity_observer.crypto import strict_loads
from probity_observer.history import read_history
from probity_observer.verify import verify_packet

from .contract import (CASES, CONTENT, FINAL_TEXT, PROFILE, ROOT_TEXT, SOURCE,
                       decode, encode, original, plan, require, sha)

FILES = ("trusted-keys-before-run.json", "authority-before-run.json",
         "begin-before-run.json", "effect-before-response.json",
         "supplied-user-response.json", "session.json", "turns.json",
         "callbacks.json", "model-requests.json", "tool-bodies.json",
         "operator-effects.json", "observer-packet.json", "history.jsonl",
         "witness-state.json")


def selected_files() -> list[str]:
    return ["plan-before-run.json", "native-result.json"] + [
        f"cases/{case}/{name}" for case in CASES for name in FILES]


def host_policy(root: Path) -> dict[str, Any]:
    """Select raw outputs in the trusted host, separately from candidate bytes.

    This host is the same author/operator as the native fixture. These pins are
    post-run byte selection, not external key custody or pre-run authority.
    """
    return {"profile": PROFILE, "sourceRevision": SOURCE,
            "files": {p: sha((root / p).read_bytes()) for p in selected_files()},
            "keys": {case: decode((root / "cases" / case /
                                   "trusted-keys-before-run.json").read_bytes())
                     for case in CASES}}


def field(value: dict[str, Any], snake: str, camel: str) -> Any:
    require(not (snake in value and camel in value), "ambiguous-native-field")
    return value.get(snake, value.get(camel))


def parts(event: dict[str, Any]) -> list[dict[str, Any]]:
    return (event.get("content") or {}).get("parts") or []


def calls(event: dict[str, Any]) -> list[dict[str, Any]]:
    return [v for p in parts(event)
            if (v := field(p, "function_call", "functionCall"))]


def responses(event: dict[str, Any]) -> list[dict[str, Any]]:
    return [v for p in parts(event)
            if (v := field(p, "function_response", "functionResponse"))]


def text(events: list[dict[str, Any]]) -> list[str]:
    return [p["text"] for e in events for p in parts(e) if p.get("text")]


def event_view(event: dict[str, Any]) -> dict[str, Any]:
    """Compare native semantics without pretending all timestamps are ordered."""
    return {"id": event.get("id"), "author": event.get("author"),
            "content": event.get("content")}


def case_read(root: Path, case: str, keys: dict[str, str]) -> dict[str, Any]:
    directory = root / "cases" / case
    get = lambda name: decode((directory / name).read_bytes())
    turns = [[original(e) for e in turn] for turn in get("turns.json")]
    require(len(turns) == 3 and all(turns), "native-turn-population")
    first, second, third = turns
    require({e["author"] for e in second} == {"issuer"}, "response-issuer")
    require(text(second) == [FINAL_TEXT], "issuer-terminal-text")
    require({e["author"] for e in third} == {"root"}, "plain-text-root")
    require(text(third) == [ROOT_TEXT] and not any(calls(e) for e in third),
            "plain-text-root-terminal")
    tool_name = "pending_work" if case == "long-running-completed" else "approved_write"
    issued = [fc for e in first if e["author"] == "issuer"
              for fc in calls(e) if fc["name"] == tool_name]
    require(len(issued) == 1 and bool(issued[0].get("id")), "original-issued-call")
    original_id = issued[0]["id"]
    if case == "long-running-completed":
        supplied_call = issued[0]
    else:
        confirmations = [fc for e in first if e["author"] == "issuer"
                         for fc in calls(e) if fc["name"] == "adk_request_confirmation"]
        require(len(confirmations) == 1, "confirmation-call-population")
        supplied_call = confirmations[0]
        original_call = supplied_call["args"]["originalFunctionCall"]
        require({k: original_call.get(k) for k in ("id", "name", "args")} ==
                {k: issued[0].get(k) for k in ("id", "name", "args")},
                "confirmation-original-call-binding")
    supplied = original(get("supplied-user-response.json"))
    supplied_responses = responses({"content": supplied})
    require(len(supplied_responses) == 1, "supplied-response-population")
    supplied_response = supplied_responses[0]
    require(supplied_response["id"] == supplied_call["id"] and
            supplied_response["name"] == supplied_call["name"],
            "supplied-response-call-binding")
    expected_response = ({"status": "completed", "requestId": original_id}
                         if case == "long-running-completed" else
                         {"confirmed": case == "approval-granted"})
    require(supplied_response["response"] == expected_response, "response-decision")
    session = original(get("session.json"))
    session_events = session["events"]
    user_responses = [fr for e in session_events if e["author"] == "user"
                      for fr in responses(e)]
    require(user_responses == supplied_responses, "session-user-response")
    native_events = [event_view(e) for turn in turns for e in turn]
    require([event_view(e) for e in session_events if e["author"] != "user"] ==
            native_events, "session-native-turn-history")

    capture = get("callbacks.json")
    require(capture["capturePayloads"] is True and capture["closed"] is True and
            capture["failures"] == 0, "capture-closed-complete")
    records = capture["records"]
    require([r["sequence"] for r in records] == list(range(len(records))),
            "callback-sequence")
    require(sum(r["callback"] == "before-run" for r in records) == 3 and
            sum(r["callback"] == "after-run" for r in records) == 3,
            "callback-turn-boundaries")
    require([r["native"]["agent"] for r in records if r["callback"] == "before-agent"] ==
            ["root", "issuer", "issuer", "root"], "callback-routed-agents")
    captured_events = [event_view(original(r["native"])) for r in records
                       if r["callback"] == "event"]
    require(captured_events == native_events, "callback-native-event-population")
    tool_callbacks = [r for r in records if r["callback"] == "before-tool" and
                      r["native"]["tool"] == tool_name]
    require(len(tool_callbacks) == (1 if case == "long-running-completed" else 2) and
            all(r["native"]["functionCallId"] == original_id for r in tool_callbacks),
            "callback-original-tool-call-binding")
    requests = get("model-requests.json")
    require(len(requests["root"]) == 2 and len(requests["issuer"]) == 2,
            "native-model-population")
    for rows in requests.values():
        for row in rows:
            original(row)
    model_callbacks = [original(r["native"]) for r in records
                       if r["callback"] == "before-model"]
    require(model_callbacks == [original(requests["root"][0]),
                                original(requests["issuer"][0]),
                                original(requests["issuer"][1]),
                                original(requests["root"][1])],
            "callback-model-request-population")

    packet = strict_loads((directory / "observer-packet.json").read_bytes())
    require(packet["authority"] == get("authority-before-run.json") ==
            {"intervalId": case, "scope": "/work", "operation": "write-file"},
            "declared-broker-authority")
    begin = get("begin-before-run.json")
    require(begin == {"commitment": packet["commitment"],
                      "checkpoint": packet["startCheckpoint"]}, "prior-commitment")
    claim = verify_packet(packet, directory / "history.jsonl", keys["observer"],
                          keys["witness"], directory / "workspace")
    require(claim["witnessScope"] == "PEER" and claim["coverage"]["noDetectedGap"] is True,
            "bounded-peer-coverage")
    require(get("effect-before-response.json") == {"files": []},
            "effect-before-supplied-response")
    writes = claim["writes"]
    bodies, operator_effects = get("tool-bodies.json"), get("operator-effects.json")
    require(len(writes) == (0 if case == "approval-denied" else 1), "observed-write-count")
    if writes:
        require(writes[0]["requestId"] == original_id and
                writes[0]["contentDigest"] == sha(CONTENT), "effect-call-and-bytes")
        require((directory / "workspace" / "result.txt").read_bytes() == CONTENT,
                "current-effect-byte-readback")
    if case == "approval-granted":
        require(len(bodies) == 1 and bodies[0]["tool"] == tool_name and
                bodies[0]["functionCallId"] == original_id and
                bodies[0]["effectOperator"] == "tool-body" and not operator_effects,
                "native-confirmed-body")
    elif case == "approval-denied":
        require(not bodies and not operator_effects and
                not list((directory / "workspace").iterdir()), "denied-no-body-or-effect")
    else:
        require(len(bodies) == 1 and bodies[0] == {
            "tool": tool_name, "functionCallId": original_id,
            "result": None, "effectOperator": None}, "native-lro-start-only")
        require(len(operator_effects) == 1 and
                operator_effects[0]["functionCallId"] == original_id and
                operator_effects[0]["effectOperator"] == "same-author-host-completion",
                "host-completion-distinct-from-tool-body")
    require(len([e for e in read_history(directory / "history.jsonl")
                 if e["event"]["kind"] == "write"]) == len(writes), "signed-write-history")
    return {"case": case, "nativeResponseAuthors": ["issuer"],
            "nativeLaterTextAuthors": ["root"], "modelCalls": 4,
            "toolBodyCalls": 0 if case == "approval-denied" else 1,
            "observedWrites": len(writes)}


def read(root: Path, policy_raw: bytes, expected_policy_sha: str) -> dict[str, Any]:
    require(sha(policy_raw) == expected_policy_sha, "unselected-host-policy")
    policy = decode(policy_raw)
    require(policy["profile"] == PROFILE and policy["sourceRevision"] == SOURCE,
            "unselected-profile-or-source")
    require(set(policy["files"]) == set(selected_files()), "selected-file-population")
    for path, expected in policy["files"].items():
        candidate = root / path
        require(not candidate.is_symlink() and candidate.is_file() and
                all(not parent.is_symlink() for parent in candidate.parents),
                "linked-or-missing-packet-input")
        require(sha(candidate.read_bytes()) == expected, "selected-original-bytes")
    selected = decode((root / "plan-before-run.json").read_bytes())
    require(selected == plan(selected["runId"]), "fixed-before-run-plan")
    require(set(policy["keys"]) == set(CASES), "selected-case-key-population")
    rows = [case_read(root, case, policy["keys"][case]) for case in CASES]
    native_result = decode((root / "native-result.json").read_bytes())
    require(native_result["rows"] == rows and native_result["runId"] == selected["runId"] and
            native_result["providerRequests"] == 0 and
            native_result["modelQuality"] == "not-evaluated" and
            native_result["publicationDecision"] is None and
            native_result["prospectiveEightTaskRun"] == "not-started", "native-result-reconstruction")
    return {"status": "verified", "profile": PROFILE, "sourceRevision": SOURCE,
            "runId": selected["runId"], "rows": rows, "witnessScope": "PEER",
            "publicationDecision": "admit-this-finite-reference-only",
            "authority": "explicit author-operated broker scope",
            "outsideOperator": False, "modelQuality": "not-evaluated",
            "doesNotAssert": ["provider-inference", "real-model-quality",
                              "outside-custody", "recurring-consumer-adoption",
                              "unmediated-effects", "general-application-traces"],
            "prospectiveEightTaskRun": "not-started"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(args.output.resolve() != args.policy.resolve() and
            not args.output.resolve().is_relative_to(args.directory.resolve()),
            "decision-path-overlaps-input")
    args.output.unlink(missing_ok=True)
    decision = encode(read(args.directory, args.policy.read_bytes(), args.policy_sha256))
    args.output.write_bytes(decision)
    print(decision.decode())
    return 0
