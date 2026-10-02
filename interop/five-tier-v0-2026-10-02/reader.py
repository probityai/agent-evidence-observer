"""Reconstruct separate outcomes from externally selected retained artifacts."""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

from protocol import VERSION, digest, encode, manifest, population

LOGGER = logging.getLogger(__name__)


def require(condition: bool, reason: str) -> None:
    """Raise a stable, logged refusal reason for failed reconstruction."""
    if not condition:
        LOGGER.error("%s", reason)
        raise ValueError(reason)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_member")
        result[key] = value
    return result


def decode(raw: bytes) -> Any:
    """Read finite JSON while refusing duplicate member and nonfinite values."""
    def nonfinite(_: str) -> Any:
        require(False, "nonfinite_json")
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=nonfinite)


def read(root: Path, name: str) -> bytes:
    """Read a bounded regular artifact entirely within the selected packet."""
    path = root / name
    require(not path.is_symlink() and path.resolve().is_relative_to(root.resolve()), "artifact_path_escape")
    require(path.is_file() and path.stat().st_size <= 32 * 1024 * 1024, "artifact_size_or_absent")
    return path.read_bytes()


def _file_result(name: str, args: dict[str, Any], state: dict[str, Any]) -> str:
    """Recompute a file transition independently from the runtime tool body."""
    if name == "write_file":
        if args["content"] != "DONE":
            return "refused:content"
        state["file"] = "DONE"
    return state["file"]


def _sqlite_result(name: str, args: dict[str, Any], state: dict[str, Any]) -> str:
    """Recompute an atomic two-row transaction without opening a database."""
    if name == "transfer":
        amount = args["amount"]
        if not 1 <= amount <= 10:
            return "refused:amount"
        if amount > state["left"]:
            return "refused:insufficient-funds"
        state["left"] -= amount
        state["right"] += amount
    return f"{state['left']},{state['right']}"


def _expected(call: dict[str, Any], state: dict[str, Any]) -> str:
    """Choose only a supported predeclared finite operation."""
    name, args = call["name"], call["arguments"]
    if name == "double":
        return str(args["value"] * 2)
    if name in {"read_file", "write_file"}:
        return _file_result(name, args, state)
    return _sqlite_result(name, args, state)


def expected_tools(case: dict[str, Any]) -> tuple[list[str], dict[str, str]]:
    """Recompute finite tool semantics without invoking a framework or target."""
    state = {"file": "OPEN", "left": 10, "right": 0}
    values = [_expected(call, state) for call in case["calls"]]
    return values, {"file": state["file"], "sqlite": f"{state['left']},{state['right']}"}


def tool_join(sample: dict[str, Any], case: dict[str, Any], events: list[dict[str, Any]]) -> None:
    """Join each native call/result to the original scoped operation recorder."""
    native = [event for event in sample["events"] if event.get("event") == "tool"]
    calls = [call for message in sample["messages"] if message.get("role") == "assistant" for call in message.get("tool_calls", [])]
    replies = [message for message in sample["messages"] if message.get("role") == "tool"]
    values, _ = expected_tools(case)
    require(len(native) == len(events) == len(calls) == len(replies) <= len(values), "native_tool_population")
    if sample.get("error") is None and sample.get("completed_at") is not None:
        require(len(native) == len(values), "native_tools_missing")
    for native_event, owned, call, reply, spec, value in zip(native, events, calls, replies, case["calls"], values):
        require(call["id"] == native_event["id"] == reply["tool_call_id"], "native_tool_identity")
        require(call["function"] == native_event["function"] == owned["name"] == spec["name"], "native_tool_name")
        require(encode(call["arguments"]) == encode(native_event["arguments"]) == encode(owned["arguments"]) == encode(spec["arguments"]), "native_tool_arguments")
        require(native_event.get("error") is None and native_event["result"] == reply["content"] == owned["result"] == value, "native_tool_result")
        require(all(type(owned[key]) is int and owned[key] >= 0 for key in ("elapsed_ns", "thread_cpu_ns")), "tool_resource_value")


def native_configuration(native: dict[str, Any], case: dict[str, Any]) -> None:
    """Refuse changed native launch, model responses, scorer and solver settings."""
    evaluation = native["eval"]
    require(evaluation["packages"]["inspect_ai"] == "0.3.273", "native_framework_version")
    expected = {"epochs": 1, "retry_on_error": 0, "max_samples": 1, "message_limit": 8 if case["solver"] == "react-8" else 12, "fail_on_error": True}
    require(all(type(evaluation["config"].get(key)) is type(value) and evaluation["config"].get(key) == value for key, value in expected.items()), "native_configuration")
    require(evaluation["scorers"][0]["name"] == "match" and evaluation["scorers"][0]["options"] == {} and len(evaluation["scorers"]) == 1, "native_scorer")
    steps = native["plan"]["steps"]
    names = [step["solver"] for step in steps]
    require(names == (["use_tools", "generate"] if case["solver"] == "generate" else ["react"]), "native_solver")
    if case["solver"] != "generate":
        require(steps[0]["params"]["submit"] is False and steps[0]["params"]["attempts"] == 1, "native_agent_configuration")
    configured = evaluation["model_args"]["custom_outputs"]
    require(len(configured) == len(case["calls"]) + int(case["response"] is not None), "native_model_population")
    for index, call in enumerate(case["calls"]):
        tool_calls = configured[index]["choices"][0]["message"]["tool_calls"]
        require(len(tool_calls) == 1 and tool_calls[0]["id"] == f"call-{index}" and tool_calls[0]["function"] == call["name"] and encode(tool_calls[0]["arguments"]) == encode(call["arguments"]), "native_model_call")
    if case["response"] is not None:
        require(configured[-1]["completion"] == case["response"], "native_model_completion")


def validate_launch(launch: dict[str, Any], case: dict[str, Any]) -> None:
    """Keep declared missing starts and actual timed launches type-strict."""
    require(launch.get("status") in {"returned", "error", "not-started"}, "launch_status")
    elapsed = launch.get("elapsed_ns")
    require(elapsed is None if launch["status"] == "not-started" else type(elapsed) is int and elapsed >= 0, "launch_resource")
    require(case["launch"] or launch["status"] == "not-started", "undeclared_launch")


def verify_a2a(root: Path, summary: dict[str, Any]) -> None:
    """Recompute original SDK raw request/result and common mapping offline."""
    if summary["status"] != "complete":
        require("original_report" not in summary, "a2a_failed_launch_claimed_report")
        return
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "a2a-native-2026-10-02"))
    from a2a_verify import read_and_verify
    packet = root / "a2a-native"
    raw = read(packet, "report.json")
    original = decode(raw)
    require(summary["exit_code"] == 0 and summary["report_sha256"] == digest(raw) and summary["original_report"] == original, "a2a_launch_report_join")
    names = ("sdk-source.json", "sdk-source-pins.json", "sdk-license.txt", "local-source.json", "rubric.json", "policy.json", "runtime.json")
    # Native helper uses compact wrapper encoding, not this profile's pretty JSON.
    from evaluation_contract import encode as native_encode
    sources_pin = digest(native_encode({name: digest(read(packet / "common", name)) for name in names}))
    reconstructed = read_and_verify(packet, decode(read(packet, "selected-native-pins.json")), original["plan_sha256"], original["history_sha256"], sources_pin=sources_pin)
    require(reconstructed == original, "a2a_native_mapping_mismatch")


def derive(case: dict[str, Any], declared: dict[str, Any], artifacts: dict[str, bytes]) -> dict[str, Any]:
    """Map a declared attempt, retaining error and unknown start independently."""
    launch = decode(artifacts["launch.json"])
    validate_launch(launch, case)
    record: dict[str, Any] = {"id": case["id"], "tier": case["tier"], "family": case["family"], "configuration": case["solver"], "status": "not-started" if not case["launch"] else "start-unknown", "task_outcome": "unknown", "authority": "not-exercised", "effect": "unknown", "coverage": "declared-local-transcript-only", "judge_reliability": "not-independent", "consumer": "not-exercised", "resources": {"elapsed_ns": None, "thread_cpu_ns": None, "input_tokens": None, "output_tokens": None, "provider_dollars": 0}, "effect_capture_complete": False, "launch_status": launch["status"]}
    if "native.json" not in artifacts:
        return record
    require(case["launch"] and launch["status"] != "not-started", "native_without_declared_launch")
    native = decode(artifacts["native.json"])
    require(native["eval"]["metadata"] == {"probity_profile": VERSION, "declaration_sha256": digest(encode(declared))}, "native_declaration_binding")
    require(native["eval"]["model"] == "mockllm/model" and len(native["samples"]) == 1, "native_sample_population")
    native_configuration(native, case)
    sample = native["samples"][0]
    require(sample["id"] == case["id"] and sample["input"] == case["input"] and sample["target"] == case["target"], "native_sample_identity")
    require(sample.get("error_retries", []) == [], "native_retries")
    record["status"] = "error" if sample.get("error") is not None else "complete" if sample.get("completed_at") is not None else "incomplete"
    events = [decode(line) for line in artifacts.get("tool-events.jsonl", b"").splitlines()]
    tool_join(sample, case, events)
    record["resources"]["elapsed_ns"] = launch.get("elapsed_ns")
    record["resources"]["thread_cpu_ns"] = sum(event["thread_cpu_ns"] for event in events)
    if record["status"] == "complete" and sample.get("scores"):
        completion = sample["output"]["completion"]
        require(type(completion) is str and completion == case["response"], "native_completion_binding")
        expected = "C" if completion.strip() == case["target"].strip() else "I"
        require(sample["scores"]["match"]["value"] == expected, "native_score_recomputed")
        record["task_outcome"] = "pass" if expected == "C" else "fail"
    if "readback.json" in artifacts:
        _, expected = expected_tools({**case, "calls": case["calls"][:len(events)]})
        require(decode(artifacts["readback.json"]) == expected, "local_readback_recomputed")
        record["effect"] = "local-state-matches-declaration"
    return record


def verify(root: Path, pins: dict[str, str]) -> dict[str, Any]:
    """Reconstruct a saved report without native calls, using external pins.

    Parameters
    ----------
    root : pathlib.Path
        Retained packet directory. Symlinks, escapes and extra artifact population
        are refused. Original native bytes remain unchanged during verification.
    pins : dict of str to str
        Caller-selected declaration/index SHA-256 values. The adjacent generated
        convenience file only supports a same-operator round trip.

    Returns
    -------
    dict
        Reconstructed report, including separate tier populations and controls.

    Raises
    ------
    ValueError
        Stable refusal reason logged through :func:`require`. A changed wrapper
        is refused even when its producer recomputes adjacent convenience pins.
    """
    require(set(pins) == {"declaration_sha256", "index_sha256"}, "consumer_pin_names")
    declaration_raw, index_raw = read(root, "declaration-before-run.json"), read(root, "artifact-index.json")
    require(digest(declaration_raw) == pins["declaration_sha256"] and digest(index_raw) == pins["index_sha256"], "consumer_pin_mismatch")
    declared, index = decode(declaration_raw), decode(index_raw)
    require(declared == manifest(), "frozen_manifest_changed")
    retained = {name: read(root, name) for name in index}
    require(all(digest(raw) == index[name] for name, raw in retained.items()), "artifact_pin_mismatch")
    allowed = set(index) | {"declaration-before-run.json", "artifact-index.json", "consumer-pins.json", "report.json"}
    require({str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()} == allowed, "artifact_population")
    records = []
    for case in declared["attempts"] + declared["controls"]:
        prefix = f"cases/{case['id']}/"
        artifacts = {name[len(prefix):]: raw for name, raw in retained.items() if name.startswith(prefix)}
        records.append(derive(case, declared, artifacts))
    a2a = decode(retained["a2a-launch.json"])
    verify_a2a(root, a2a)
    result = report(declared, records, a2a)
    require(decode(read(root, "report.json")) == result, "report_mapping_mismatch")
    return result


def report(declared: dict[str, Any], records: list[dict[str, Any]], a2a: dict[str, Any]) -> dict[str, Any]:
    """Keep tier/controls populations separate and never emit an overall score."""
    return {"profile": VERSION, "classification": declared["classification"], "real_model_quality": "not-measured", "independent_custody": "not-established", "aggregate_score": None, "populations": {tier: population([record for record in records if record["tier"] == tier]) for tier in ("reasoning", "tools", "agents", "workloads", "controls")}, "records": records, "a2a": a2a, "resources_scope": "launch wall elapsed; successful owned tool body thread CPU only; mock token zeros omitted; no memory isolation accounting", "authority_scope": "not-exercised; protected authority/effect profile remains separately available", "historical_cpu_baseline": declared["historical_cpu_baseline"]}
