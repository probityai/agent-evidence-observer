"""Read the complete selected population without importing smolagents."""
from __future__ import annotations

import argparse
import math
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from probity_observer.authorization import (
    ActionRequest, GrantPolicy, verify_authorized_packet, verify_grant,
)
from probity_observer.verify import verify_packet

from .contract import (
    CASES, CONTENT, FALLBACK, PROFILE, SDK_SOURCE, SDK_VERSION,
    encode, exact, load, reply, require, sha,
)
from .source import expected_sources


def checked_file(root: Path, name: str, digest: str) -> Path:
    """Authenticate a selected artifact without following symbolic links."""
    parts = name.split("/")
    require(all(part not in {"", ".", ".."} for part in parts), "artifact path differs")
    path = root / name
    parents = [parent for parent in path.parents if parent.is_relative_to(root)]
    require(
        not root.is_symlink() and not path.is_symlink() and path.is_file()
        and all(not parent.is_symlink() for parent in parents),
        "artifact must be a regular file",
    )
    exact(sha(path.read_bytes()), digest, "artifact digest differs from host selection")
    return path


def core_check(function: Callable[[], Any], reason: str) -> Any:
    """Translate a signed-core refusal into one logged public profile reason."""
    try:
        return function()
    except (ValueError, KeyError, TypeError):
        require(False, reason)


def verify_sources(root: Path, policy: dict[str, Any]) -> None:
    """Check complete retained source against primary SDK and installed reader."""
    manifest = load(checked_file(root, "source-before-run.json", policy["sourceManifestSha256"]))
    exact(manifest, expected_sources(), "selected source population or bytes differ")
    for name, digest in manifest.items():
        checked_file(root / "source", name, digest)


def verify_models(native: dict[str, Any], case: str) -> None:
    """Keep attempted model errors and literal tool arguments in the contract."""
    spec = CASES[case]
    models = native["modelCalls"]
    exact(len(models), spec.models, "model call population differs")
    for index, row in enumerate(models):
        exact(sorted(row), ["error", "input", "output", "tools"], "model record shape differs")
        exact(row["output"], reply(index, case), "model reply differs")
        error = "RuntimeError" if case == "model-error-after" and index == 1 else None
        exact(row["error"], error, "model error differs")
        require(isinstance(row["input"], list) and bool(row["input"]), "native model input absent")
        tools = [] if case == "max-steps" and index == 1 else ["write_result", "final_answer"]
        exact(row["tools"], tools, "native selected tools differ")


def verify_tools(native: dict[str, Any], case: str, effects: int) -> None:
    """Check actual forward bytes separately from a successful final answer."""
    calls = native["toolCalls"]
    exact(len(calls), CASES[case].tools, "tool call population differs")
    expected_error = {
        "wrong-content": "VerificationError", "error-before": "RuntimeError",
        "error-after": "RuntimeError",
    }.get(case)
    for row in calls:
        require(type(row["committed"]) is bool, "tool committed type differs")
        expected = {
            "content": "wrong bytes" if case == "wrong-content" else CONTENT,
            "committed": bool(CASES[case].effects), "exception": expected_error,
        }
        exact(row, expected, "native forward or effect boundary differs")
    exact(sum(row["committed"] for row in calls), effects, "native signed-effect consistency differs")


def error_type(step: dict[str, Any]) -> str | None:
    """Extract the actual SDK error class from an ActionStep snapshot."""
    return step["error"]["type"] if step["error"] else None


def verify_action_timing(step: dict[str, Any]) -> None:
    """Require an actual finalized native action without interpreting duration."""
    timing = step["timing"]
    values = [timing["start_time"], timing["end_time"]]
    require(
        all(type(value) in (int, float) and math.isfinite(value) for value in values)
        and values[1] >= values[0],
        "native action did not close",
    )


def verify_actions(native: dict[str, Any], case: str) -> None:
    """Authenticate callback closure, error handling and native memory order."""
    callbacks = native["callbacks"]
    require(
        all(row["kind"] in {"ActionStep", "FinalAnswerStep"} for row in callbacks),
        "unexpected native callback",
    )
    actions = [row["data"] for row in callbacks if row["kind"] == "ActionStep"]
    finals = [row["data"] for row in callbacks if row["kind"] == "FinalAnswerStep"]
    exact(actions, native["memoryActions"], "native memory and callbacks differ")
    exact(len(actions), len(CASES[case].action_errors), "action callback population differs")
    exact(len(finals), CASES[case].final_callbacks, "final callback population differs")
    exact(
        [row["kind"] for row in callbacks],
        ["ActionStep"] * len(CASES[case].action_errors)
        + ["FinalAnswerStep"] * CASES[case].final_callbacks,
        "native callback order differs",
    )
    for index, step in enumerate(actions):
        exact(step["step_number"], index + 1, "native step identity differs")
        verify_action_timing(step)
        exact(error_type(step), CASES[case].action_errors[index], "native action error differs")
    verify_action_replies(actions, native["modelCalls"], case)
    verify_final(finals, native, case)


def verify_action_replies(actions: list[dict[str, Any]], models: list[dict[str, Any]], case: str) -> None:
    """Pin model replies and native processed tool-result boundaries."""
    first = actions[0]
    exact(first["model_output_message"], reply(0, case), "native action reply differs")
    exact(first["model_input_messages"], models[0]["input"], "native action input differs")
    expected_first_final = case == "final-without-effect"
    exact(first["is_final_answer"], expected_first_final, "native final-answer flag differs")
    has_error = CASES[case].action_errors[0] is not None
    first_calls = [] if has_error else [{
        "id": "call-1", "type": "function", "function": {
            "name": "final_answer" if expected_first_final else "write_result",
            "arguments": {"answer": "done"} if expected_first_final else {"content": CONTENT},
        },
    }]
    exact(first["tool_calls"], first_calls, "native processed tool population differs")
    if len(actions) == 1:
        return
    last = actions[1]
    ordinary = case not in {"max-steps", "model-error-after"}
    exact(last["model_output_message"], reply(1, case) if ordinary else None, "native terminal action reply differs")
    exact(last["is_final_answer"], ordinary, "native terminal final flag differs")
    final_calls = [{"id": "call-2", "type": "function", "function": {
        "name": "final_answer", "arguments": {"answer": "done"},
    }}] if ordinary else []
    exact(last["tool_calls"], final_calls, "native terminal processed tools differ")
    if case != "max-steps":
        exact(last["model_input_messages"], models[1]["input"], "native terminal action input differs")


def verify_final(finals: list[dict[str, Any]], native: dict[str, Any], case: str) -> None:
    """Refuse fallback, raised and incomplete states as successful publication."""
    expected_output = FALLBACK if case == "max-steps" else "done"
    expected_final = [{"output": expected_output}] if CASES[case].final_callbacks else []
    exact(finals, expected_final, "native final callback output differs")
    exception = "AgentGenerationError" if case == "model-error-after" else None
    result = (
        {"state": CASES[case].state, "output": expected_output}
        if CASES[case].final_callbacks else None
    )
    exact(
        native["terminal"],
        {"state": CASES[case].state, "exception": exception, "result": result},
        "native terminal state differs",
    )


def verify_case(root: Path, case: str, pins: dict[str, Any]) -> dict[str, Any]:
    """Verify native semantics and a signed, authorized, peer-witnessed effect."""
    exact(sorted(pins["artifacts"]), ["grant.json", "history.jsonl", "native.json", "packet.json"], "artifact population differs")
    paths = {name: checked_file(root, name, digest) for name, digest in pins["artifacts"].items()}
    native, packet, grant = (load(paths[name]) for name in ("native.json", "packet.json", "grant.json"))
    exact(
        [native["profile"], native["case"], native["sdkVersion"]],
        [PROFILE, case, SDK_VERSION], "native identity differs",
    )
    request = ActionRequest(**pins["request"])
    selected = ActionRequest(
        case, "attempt-1", "request-1", "tenant-1", "principal-1",
        "write_result", "/work/result.txt", sha(CONTENT.encode()),
    )
    exact(pins["request"], asdict(selected), "host action differs from finite profile")
    when = datetime.strptime(pins["referenceTime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    core_check(lambda: verify_grant(grant, request, GrantPolicy(pins["issuerKey"]), now=when), "grant verification refused")
    claim = core_check(
        lambda: verify_packet(packet, paths["history.jsonl"], pins["observerKey"], pins["witnessKey"], workspace=root / "work"),
        "signed effect verification refused",
    )
    exact(len(claim["writes"]), CASES[case].effects, "signed effect population differs")
    exact(claim["witnessScope"], "PEER", "witness scope differs")
    verify_models(native, case)
    verify_tools(native, case, len(claim["writes"]))
    verify_actions(native, case)
    if CASES[case].effects:
        core_check(
            lambda: verify_authorized_packet(grant, request, GrantPolicy(pins["issuerKey"]), packet, paths["history.jsonl"], pins["observerKey"], pins["witnessKey"], now=when, workspace=root / "work"),
            "authorized effect verification refused",
        )
    return {
        "case": case, "modelCalls": CASES[case].models, "toolCalls": CASES[case].tools,
        "committedEffects": CASES[case].effects, "nativeState": CASES[case].state,
        "publicationDecision": "RELEASE" if case == "permit" else "WITHHOLD",
        "witnessScope": claim["witnessScope"],
    }


def verify_saved(root: Path, policy: dict[str, Any]) -> dict[str, Any]:
    """Read a complete bounded population against an explicitly selected policy."""
    exact(sorted(policy), ["cases", "profile", "schema", "sdk", "sourceManifestSha256"], "host policy shape differs")
    exact(policy["schema"], "probity.smolagents-host-policy.v1", "host schema differs")
    exact(policy["profile"], PROFILE, "host profile differs")
    exact(policy["sdk"], {"version": SDK_VERSION, "commit": SDK_SOURCE}, "host SDK differs")
    exact(sorted(policy["cases"]), sorted(CASES), "planned population differs")
    verify_sources(root, policy)
    records = [verify_case(root / case, case, policy["cases"][case]) for case in CASES]
    return {
        "profile": PROFILE, "records": records,
        "modelCalls": sum(row["modelCalls"] for row in records),
        "toolCalls": sum(row["toolCalls"] for row in records),
        "committedEffects": sum(row["committedEffects"] for row in records),
        "modelInferenceCalls": 0, "independentCustody": False,
    }


def publish_saved(root: Path, policy: dict[str, Any], destination: Path) -> dict[str, Any]:
    """Publish only the verified permit row, leaving no output on refusal."""
    require(
        not destination.resolve().is_relative_to(root.resolve()),
        "publication destination must be outside packet",
    )
    require(not destination.exists(), "publication destination already exists")
    report = verify_saved(root, policy)
    result = {
        "profile": PROFILE,
        "records": [row for row in report["records"] if row["publicationDecision"] == "RELEASE"],
        "selectionSha256": sha(encode(policy)),
    }
    destination.mkdir()
    (destination / "published.json").write_bytes(encode(result))
    return result


def main() -> None:
    """Require an external policy and its digest at the installed reader CLI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--host-policy", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--publish", type=Path)
    args = parser.parse_args()
    require(not args.host_policy.resolve().is_relative_to(args.packet.resolve()), "host policy must be outside packet")
    exact(sha(args.host_policy.read_bytes()), args.policy_sha256, "host policy pin differs")
    policy = load(args.host_policy)
    result = publish_saved(args.packet, policy, args.publish) if args.publish else verify_saved(args.packet, policy)
    print(encode(result).decode())


if __name__ == "__main__":
    main()
