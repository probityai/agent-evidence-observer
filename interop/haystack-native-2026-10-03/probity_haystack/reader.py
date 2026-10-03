"""Read selected native bytes without importing or running Haystack."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from probity_observer.authorization import ActionRequest, GrantPolicy, verify_authorized_packet, verify_grant
from probity_observer.verify import verify_packet

from .contract import CASES, CONTENT, PROFILE, SDK_SOURCE, SDK_VERSION, encode, load, sha


def require(condition: bool, reason: str) -> None:
    """Refuse an incomplete, changed or semantically inconsistent population."""
    if not condition:
        raise ValueError(reason)


def checked_file(root: Path, name: str, expected: str) -> Path:
    """Check exact selected bytes and refuse symbolic links."""
    path = root / name
    require(not root.is_symlink() and not path.is_symlink() and path.is_file() and all(not parent.is_symlink() for parent in path.parents if parent.is_relative_to(root)), "artifact must be a regular file")
    require(sha(path.read_bytes()) == expected, "artifact digest differs from host selection")
    return path


def verify_case(root: Path, case: str, pins: dict[str, Any]) -> dict[str, Any]:
    """Check a native terminal state separately from signed durable effects."""
    require(set(pins["artifacts"]) == {"native.json", "packet.json", "grant.json", "history.jsonl"}, "artifact population differs")
    paths = {name: checked_file(root, name, value) for name, value in pins["artifacts"].items()}
    native = load(paths["native.json"])
    packet = load(paths["packet.json"])
    grant = load(paths["grant.json"])
    require(native["profile"] == PROFILE and native["case"] == case and native["sdkVersion"] == SDK_VERSION, "native identity differs")
    request = ActionRequest(**pins["request"])
    require(request == ActionRequest(case, "attempt-1", "request-1", "tenant-1", "principal-1", "write_result", "/work/result.txt", sha(CONTENT.encode())), "host action differs from finite profile")
    when = datetime.strptime(pins["referenceTime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    verify_grant(grant, request, GrantPolicy(pins["issuerKey"]), now=when)
    claim = verify_packet(packet, paths["history.jsonl"], pins["observerKey"], pins["witnessKey"], workspace=root / "work")
    models, tools, effects, reason, raised, errors = CASES[case]
    require(native["terminal"]["exception"] == ("PipelineRuntimeError" if raised else None), "native terminal exception differs")
    require(native["terminal"]["exitReason"] == reason, "native exit reason differs")
    require(len(native["modelCalls"]) == models and len(native["toolCalls"]) == tools, "call population differs")
    if not raised:
        require(type(native["terminal"]["stepCount"]) is int and native["terminal"]["stepCount"] == models, "native step count differs")
    requested = [item["tool_call"] for item in native["modelCalls"][0]["output"]["content"] if "tool_call" in item]
    require(len(requested) == tools, "native model tool-request population differs")
    if tools:
        require(requested[0] == {"tool_name": "write_result", "arguments": {"content": "wrong bytes" if case == "wrong-content" else CONTENT}, "id": "call-1", "extra": None}, "native model tool identity or arguments differ")
    require(len(claim["writes"]) == effects, "committed effect population differs")
    require(sum(row["committed"] is True for row in native["toolCalls"]) == effects, "native tool/effect consistency differs")
    for row in native["toolCalls"]:
        require(type(row["committed"]) is bool, "committed must be boolean")
        require(row["content"] == ("wrong bytes" if case == "wrong-content" else CONTENT), "invocation bytes differ")
        expected_error = "VerificationError" if case == "wrong-content" else "RuntimeError" if case in {"error-before", "handled-after", "unhandled-after"} else None
        require(row["exception"] == expected_error, "native tool exception differs")
    tool_results = [item for message in native["messages"] for item in message["content"] if "tool_call_result" in item]
    require(len(tool_results) == (0 if raised else tools), "native result population differs")
    require(sum(item["tool_call_result"]["error"] is True for item in tool_results) == errors, "native tool errors differ")
    for item in tool_results:
        result = item["tool_call_result"]
        require(type(result["error"]) is bool and result["origin"] == requested[0], "native tool-result origin or error type differs")
    spans = native["spans"]
    require(bool(spans), "native capture is empty")
    require([row["id"] for row in spans] == list(range(len(spans))), "span identity differs")
    for row in spans:
        require(row["closed"] is True, "native span did not close")
        parent = row["parent"]
        require(parent is None or type(parent) is int and 0 <= parent < row["id"], "native ancestry differs")
    require(sum(row["operation"] == "haystack.agent.run" for row in spans) == 1, "native Agent capture differs")
    require(sum(row["operation"] == "haystack.agent.step.llm" for row in spans) == models, "native model span population differs")
    require(sum(row["operation"] == "haystack.agent.step.tool" for row in spans) == tools, "native tool span population differs")
    for row in spans:
        if row["operation"] == "haystack.agent.step.tool":
            require(row["tags"]["haystack.tool.name"] == "write_result", "native tool identity differs")
            require(spans[row["parent"]]["operation"] == "haystack.agent.step", "native tool ancestry differs")
    require(any(row["operation"] == "haystack.pipeline.run" for row in spans), "native Pipeline capture absent")
    if effects:
        verify_authorized_packet(grant, request, GrantPolicy(pins["issuerKey"]), packet, paths["history.jsonl"], pins["observerKey"], pins["witnessKey"], now=when, workspace=root / "work")
    return {"case": case, "modelCalls": models, "toolCalls": tools, "committedEffects": effects,
            "nativeExitReason": reason, "publicationDecision": "RELEASE" if case == "permit" else "WITHHOLD",
            "witnessScope": claim["witnessScope"]}


def verify_saved(root: Path, policy: dict[str, Any]) -> dict[str, Any]:
    """Read a complete population against a caller-selected trusted host policy."""
    require(policy["profile"] == PROFILE and policy["sdkVersion"] == SDK_VERSION and policy["sdkSource"] == SDK_SOURCE, "host source selection differs")
    require(set(policy["cases"]) == set(CASES), "planned population differs")
    manifest_path = checked_file(root, "source-before-run.json", policy["sourceManifestSha256"])
    manifest = load(manifest_path)
    require({"probity_haystack/producer.py", "probity_haystack/reader.py", "probity_haystack/contract.py", "probity_observer/authorization.py", "haystack/components/agents/agent.py"} <= set(manifest), "selected source population is incomplete")
    for name, expected in manifest.items():
        require(name.endswith(".py") and name.startswith(("probity_haystack/", "probity_observer/", "haystack/")) and all(part not in {"", ".", ".."} for part in name.split("/")), "selected source path differs")
        checked_file(root / "source", name, expected)
    records = [verify_case(root / case, case, policy["cases"][case]) for case in CASES]
    return {"profile": PROFILE, "records": records, "modelCalls": sum(row["modelCalls"] for row in records),
            "toolCalls": sum(row["toolCalls"] for row in records), "committedEffects": sum(row["committedEffects"] for row in records),
            "modelInferenceCalls": 0, "independentCustody": False}


def publish_saved(root: Path, policy: dict[str, Any], destination: Path) -> dict[str, Any]:
    """Write only released records after the complete population passes verification."""
    report = verify_saved(root, policy)
    published = {"profile": PROFILE, "records": [row for row in report["records"] if row["publicationDecision"] == "RELEASE"],
                 "selectionSha256": sha(encode(policy))}
    destination.mkdir()
    (destination / "published.json").write_bytes(encode(published))
    return published


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("packet", type=Path)
    parser.add_argument("--host-policy", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--publish", type=Path)
    args = parser.parse_args()
    require(sha(args.host_policy.read_bytes()) == args.policy_sha256, "host policy pin differs")
    policy = load(args.host_policy)
    result = publish_saved(args.packet, policy, args.publish) if args.publish else verify_saved(args.packet, policy)
    print(encode(result).decode())


if __name__ == "__main__":
    main()
