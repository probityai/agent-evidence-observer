"""Execute and reconstruct a bounded native Inspect tool/agent/workload packet.

This separate profile uses controlled mock outputs to exercise actual framework
execution. It neither changes the reasoning adapter nor measures model quality.
Consumer-selected declarations, original log bytes and bindings are trust inputs;
no signature, independent custody or global capture claim is supplied.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import hashlib
import math
import time
import uuid
from decimal import Decimal
from datetime import datetime
from pathlib import Path
from typing import Any

from evaluation_contract import (
    AXES,
    PROFILE,
    RESOURCES,
    ROLES,
    decode,
    digest,
    encode,
    identifier,
    object_keys,
    require,
    pinned,
    MAX_BYTES,
    validate,
)
from inspect_contract import reference

VERSION = "probity-inspect-execution-v1"
INSPECT_VERSION = "0.3.273"
POLICY = b"Native match C/I task score only; finite local mock execution; no independent judge, authority or custody claim."


def declaration() -> dict:
    """Freeze finite tasks and controlled responses before any framework call."""
    cases = []
    for name, tier, final, launch in (
        ("tool-pass", "tools", "4", True),
        ("tool-fail", "tools", "wrong", True),
        ("agent-pass", "agents", "4", True),
        ("agent-error", "agents", None, True),
        ("workload-pass", "workloads", "DONE", True),
        ("planned-unstarted", "workloads", "DONE", False),
    ):
        cases.append(
            {
                "id": name,
                "tier": tier,
                "input": "Complete the bounded local task.",
                "target": "DONE" if tier == "workloads" else "4",
                "final": final,
                "launch": launch,
            }
        )
    return {
        "profile": VERSION,
        "run_id": "native-execution-" + uuid.uuid4().hex,
        "cases": cases,
    }


def _declared(value: dict) -> None:
    object_keys(value, {"profile", "run_id", "cases"}, "execution_declaration")
    require(value["profile"] == VERSION, "execution_profile")
    identifier(value["run_id"])
    require(
        type(value["cases"]) is list and 0 < len(value["cases"]) <= 100,
        "execution_population",
    )
    ids = []
    for case in value["cases"]:
        object_keys(
            case, {"id", "tier", "input", "target", "final", "launch"}, "execution_case"
        )
        identifier(case["id"])
        require(
            len(case["id"]) <= 128
            and all(
                c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                for c in case["id"]
            ),
            "execution_case_filename",
        )
        require(
            type(case["tier"]) is str
            and case["tier"] in {"tools", "agents", "workloads"},
            "execution_tier",
        )
        require(
            type(case["launch"]) is bool
            and type(case["input"]) is str
            and type(case["target"]) is str
            and (case["final"] is None or type(case["final"]) is str),
            "execution_case_value",
        )
        require(
            case["target"] == ("DONE" if case["tier"] == "workloads" else "4")
            and case["final"] in {None, "wrong", case["target"]},
            "execution_bounded_task",
        )
        ids.append(case["id"])
    require(len(ids) == len(set(ids)), "execution_duplicate_case")


def sources(framework: Any, declared: dict) -> dict[str, bytes]:
    """Retain actual installed source bytes, including native solver and tools."""
    root = Path(framework.__file__).parent
    files = (
        "_eval/eval.py",
        "agent/_react.py",
        "agent/_as_solver.py",
        "solver/_solver.py",
        "solver/_use_tools.py",
        "tool/_tool.py",
        "model/_providers/mockllm.py",
        "scorer/_match.py",
    )
    return {
        "task.json": encode(declared),
        "harness.json": encode(
            {name: (root / name).read_text("utf-8") for name in files}
        ),
        "model.json": encode(
            {
                "identity": "mockllm/model",
                "outputs": declared["cases"],
                "token_accounting": "mock_zero_is_not_normalized",
            }
        ),
        "rubric.py": (root / "scorer/_match.py").read_bytes(),
        "policy.txt": POLICY,
        "configuration.json": encode(
            {
                name: (Path(__file__).parent / name).read_text("utf-8")
                for name in (
                    "inspect_execution.py",
                    "evaluation_contract.py",
                    "inspect_contract.py",
                )
            }
        ),
    }


def contract_plan(declared: dict, source_bytes: dict[str, bytes]) -> dict:
    _declared(declared)
    require(
        type(source_bytes) is dict
        and set(source_bytes)
        == {
            "task.json",
            "harness.json",
            "model.json",
            "rubric.py",
            "policy.txt",
            "configuration.json",
        }
        and all(type(raw) is bytes for raw in source_bytes.values()),
        "execution_sources",
    )
    require(source_bytes["policy.txt"] == POLICY, "execution_policy")
    require(
        source_bytes["model.json"]
        == encode(
            {
                "identity": "mockllm/model",
                "outputs": declared["cases"],
                "token_accounting": "mock_zero_is_not_normalized",
            }
        ),
        "execution_model_source",
    )
    require(
        source_bytes["task.json"] == encode(declared), "execution_source_declaration"
    )
    roles = {role: None for role in ROLES}
    for role in {
        "case_author",
        "implementation_author",
        "runner",
        "retention_holder",
        "policy_owner",
        "consumer",
    }:
        roles[role] = "same-demo-operator"
    mapped = {}
    for role, name in {
        "task": "task.json",
        "harness": "harness.json",
        "model": "model.json",
        "rubric": "rubric.py",
        "policy": "policy.txt",
        "configuration": "configuration.json",
    }.items():
        mapped[role] = {
            "identity": "inspect-native-" + role,
            "revision": VERSION,
            "artifact": reference(name, source_bytes[name], VERSION),
        }
    attempts = []
    for case in declared["cases"]:
        attempts.append(
            {
                "identity": {
                    "task_id": case["id"],
                    "logical_request_id": "request-"
                    + digest(encode({"run": declared["run_id"], "case": case["id"]})),
                    "attempt_id": case["id"],
                    "interval_id": declared["run_id"],
                    "catalog_authority_id": "declared-local-catalog",
                    "capability_id": "native-" + case["tier"],
                    "runtime_target_id": "mockllm/model",
                    "effect_id": None,
                    "consumer_decision_id": None,
                },
                "tier": case["tier"],
                "parent_attempt_id": None,
            }
        )
    return {
        "profile": PROFILE,
        "run_id": declared["run_id"],
        "mode": "retained-native",
        "roles": roles,
        "sources": mapped,
        "attempts": attempts,
    }


def _number(value: Any, reason: str) -> None:
    require(type(value) in {int, float} and math.isfinite(value) and value >= 0, reason)


def _timestamp(value: Any) -> datetime:
    require(type(value) is str and len(value) <= 64, "execution_timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        require(False, "execution_timestamp")
    require(
        parsed.tzinfo is not None and parsed.utcoffset() is not None,
        "execution_timestamp",
    )
    return parsed


def _sample(native: bytes, case: dict, declared: dict, selected: dict) -> dict | None:
    """Check supported native identity/profile before interpreting its sample."""
    object_keys(selected, {"sha256", "run_id", "eval_id"}, "execution_binding")
    require(digest(native) == selected["sha256"], "execution_native_pin")
    log = decode(native)
    require(
        type(log) is dict
        and log.get("version") == 2
        and type(log.get("status")) is str
        and log.get("status") in {"success", "error", "started"},
        "execution_log",
    )
    ev = log.get("eval")
    require(type(ev) is dict, "execution_eval")
    require(
        ev.get("run_id") == selected["run_id"]
        and ev.get("eval_id") == selected["eval_id"],
        "execution_native_identity",
    )
    require(
        ev.get("task") == case["id"]
        and type(ev.get("task_version")) is int
        and ev.get("task_version") == 1
        and ev.get("model") == "mockllm/model",
        "execution_task_identity",
    )
    require(type(ev.get("packages")) is dict, "execution_framework_version")
    require(
        ev.get("packages", {}).get("inspect_ai") == INSPECT_VERSION,
        "execution_framework_version",
    )
    require(
        ev.get("metadata")
        == {
            "probity_execution_profile": VERSION,
            "probity_declaration_sha256": digest(encode(declared)),
        },
        "execution_declaration_binding",
    )
    conf = ev.get("config", {})
    require(type(conf) is dict, "execution_config")
    require(
        all(
            type(conf.get(key)) is int
            for key in ("epochs", "retry_on_error", "max_samples", "message_limit")
        )
        and conf.get("message_limit") == 12
        and conf.get("epochs") == 1
        and conf.get("retry_on_error") == 0
        and conf.get("max_samples") == 1
        and conf.get("log_samples") is True
        and conf.get("score_on_error") is False,
        "execution_config",
    )
    require(type(ev.get("dataset")) is dict, "execution_dataset")
    require(
        ev.get("dataset", {}).get("sample_ids") == [case["id"]]
        and ev.get("dataset", {}).get("samples") == 1,
        "execution_dataset",
    )
    require(
        type(ev.get("scorers")) is list
        and len(ev["scorers"]) == 1
        and type(ev["scorers"][0]) is dict,
        "execution_scorer",
    )
    require(
        ev.get("scorers", [{}])[0].get("name") == "match"
        and len(ev.get("scorers", [])) == 1
        and ev["scorers"][0].get("options") == {},
        "execution_scorer",
    )
    require(type(log.get("plan")) is dict, "execution_solver")
    steps = log["plan"].get("steps")
    require(type(steps) is list, "execution_solver")
    names = [step.get("solver") for step in steps if type(step) is dict]
    require(
        names == (["use_tools", "generate"] if case["tier"] == "tools" else ["react"]),
        "execution_solver",
    )
    tool_names = (
        ["read_ticket", "write_ticket"] if case["tier"] == "workloads" else ["double"]
    )
    tool_specs = [{"type": "tool", "name": name, "params": {}} for name in tool_names]
    if case["tier"] == "tools":
        require(
            steps[0].get("params")
            == {"tools": [tool_specs], "tool_choice": "auto", "append": False}
            and steps[1].get("params") == {"tool_calls": "loop"},
            "execution_solver_options",
        )
    else:
        params = steps[0].get("params")
        require(
            type(params) is dict
            and params.get("submit") is False
            and type(params.get("attempts")) is int
            and params.get("attempts") == 1
            and params.get("tools") == tool_specs
            and params.get("truncation") == "disabled",
            "execution_agent_options",
        )
        require(
            all(
                params.get(name) is None
                for name in (
                    "model",
                    "on_continue",
                    "retry_refusals",
                    "compaction",
                    "approval",
                    "review",
                )
            ),
            "execution_agent_options",
        )
    samples = log.get("samples")
    require(type(samples) is list and len(samples) <= 1, "execution_samples")
    if not samples:
        require(log["status"] != "success", "execution_success_missing_sample")
        return None
    sample = samples[0]
    require(
        type(sample) is dict
        and sample.get("id") == case["id"]
        and type(sample.get("epoch")) is int
        and sample.get("epoch") == 1
        and sample.get("input") == case["input"]
        and sample.get("target") == case["target"],
        "execution_sample_identity",
    )
    require(sample.get("error_retries", []) == [], "execution_retries")
    start = _timestamp(sample.get("started_at"))
    if sample.get("completed_at") is not None:
        require(
            _timestamp(sample["completed_at"]) >= start, "execution_timestamp_order"
        )
    require(type(sample.get("events")) is list, "execution_events")
    return sample


def _tools(sample: dict, case: dict) -> tuple[int, int | None]:
    """Join original calls/results and recompute owned finite tool semantics.

    CPU/elapsed values bind the retained native tool receipt; arithmetic and
    local read/write values are rederived. Clock honesty is not authenticated.
    """
    events = [
        e for e in sample["events"] if type(e) is dict and e.get("event") == "tool"
    ]
    messages = sample.get("messages")
    require(type(messages) is list, "execution_messages")
    calls = []
    replies = []
    for message in messages:
        require(type(message) is dict, "execution_message")
        if message.get("role") == "assistant":
            native_calls = message.get("tool_calls", [])
            require(type(native_calls) is list, "execution_message_calls")
            calls.extend(native_calls)
        if message.get("role") == "tool":
            replies.append(message)
    require(len(events) == len(calls) == len(replies), "execution_call_result_join")
    expected = (
        [("read_ticket", {}, "OPEN"), ("write_ticket", {"content": "DONE"}, "DONE")]
        if case["tier"] == "workloads"
        else [("double", {"value": 2}, 4)]
    )
    require(len(events) <= len(expected), "execution_tool_population")
    if sample.get("error") is None and sample.get("completed_at") is not None:
        require(len(events) == len(expected), "execution_complete_tools_missing")
    cpu = 0
    ids = set()
    for event, call, reply, (name, args, value) in zip(
        events, calls, replies, expected
    ):
        require(
            type(call) is dict and type(event.get("id")) is str, "execution_tool_call"
        )
        identifier(event["id"])
        require(event["id"] not in ids, "execution_tool_call_reused")
        ids.add(event["id"])
        require(
            call.get("id") == event["id"] == reply.get("tool_call_id")
            and call.get("function")
            == event.get("function")
            == reply.get("function")
            == name
            and call.get("arguments") == event.get("arguments") == args
            and encode(call.get("arguments")) == encode(args),
            "execution_call_result_join",
        )
        require(
            event.get("error") is None and reply.get("error") is None,
            "execution_tool_error_unsupported",
        )
        require(
            type(event.get("result")) is str
            and event["result"] == reply.get("content"),
            "execution_call_result_join",
        )
        result = decode(event["result"].encode())
        object_keys(
            result,
            {"value", "elapsed_ns", "thread_cpu_ns"},
            "execution_tool_measurement",
        )
        require(
            encode(result["value"]) == encode(value), "execution_tool_result_recomputed"
        )
        require(
            all(
                type(result[key]) is int and result[key] >= 0
                for key in ("elapsed_ns", "thread_cpu_ns")
            ),
            "execution_tool_measurement",
        )
        cpu += result["thread_cpu_ns"]
    return len(events), cpu


def adapt(
    declared: dict,
    native_logs: dict[str, bytes],
    bindings: dict[str, dict],
    source_bytes: dict[str, bytes],
    readbacks: dict[str, bytes],
) -> tuple[dict, dict, dict[str, bytes]]:
    """Reconstruct all axes, measurements and population from selected originals."""
    plan = contract_plan(declared, source_bytes)
    launched = {c["id"] for c in declared["cases"] if c["launch"]}
    require(
        set(native_logs) <= launched and set(bindings) == set(native_logs),
        "execution_log_population",
    )
    require(
        set(readbacks)
        <= {
            c["id"]
            for c in declared["cases"]
            if c["tier"] == "workloads" and c["launch"]
        },
        "execution_readback_population",
    )
    artifacts = dict(source_bytes)
    records, measurements = [], []
    for spec, case in zip(plan["attempts"], declared["cases"], strict=True):
        aid = case["id"]
        sample, evidence = None, []
        if aid in native_logs:
            sample = _sample(native_logs[aid], case, declared, bindings[aid])
            name = aid + "-native.json"
            artifacts[name] = native_logs[aid]
            evidence.append(reference(name, native_logs[aid], INSPECT_VERSION))
        status = "not-started" if not case["launch"] else "start-unknown"
        resources = {key: None for key in RESOURCES}
        task_status, tool_count, cpu_ns = "unknown", None, None
        gaps = [
            "independent_custody_not_established",
            "external_effects_not_observed",
            "native_transcript_completeness_not_established",
        ]
        if not case["launch"]:
            gaps.append("unstarted_by_local_launcher_declaration")
        elif sample is None:
            gaps.append("start_evidence_missing")
        else:
            status = (
                "error"
                if sample.get("error") is not None
                else (
                    "complete"
                    if sample.get("completed_at") is not None
                    else "incomplete"
                )
            )
            if status == "incomplete":
                gaps.append("native_completion_absent")
            native_seconds = sample.get("total_time")
            if native_seconds is not None:
                _number(native_seconds, "execution_elapsed")
                resources["elapsed_ns"] = int(
                    Decimal(str(native_seconds)) * 1_000_000_000
                )
            score = sample.get("scores")
            if status == "complete" and score is not None:
                require(
                    type(score) is dict
                    and set(score) == {"match"}
                    and type(score["match"]) is dict
                    and type(score["match"].get("value")) is str
                    and score["match"].get("value") in {"C", "I"},
                    "execution_score",
                )
                require(type(sample.get("output")) is dict, "execution_mock_completion")
                completion = sample.get("output", {}).get("completion")
                require(
                    type(completion) is str and completion == case["final"],
                    "execution_mock_completion",
                )
                expected_score = "C" if case["final"] == case["target"] else "I"
                require(
                    score["match"]["value"] == expected_score,
                    "execution_bounded_score_recomputed",
                )
                task_status = "pass" if expected_score == "C" else "fail"
            tool_count, cpu_ns = _tools(sample, case)
            measurements.append(
                {
                    "attempt_id": aid,
                    "native_total_time_seconds": native_seconds,
                    "elapsed_mapping": "floor(native-total-time-seconds * 1e9)",
                    "elapsed_scope": "Inspect retained sample total_time, native rounding retained",
                    "native_tool_event_count": tool_count,
                    "tool_thread_cpu_ns": cpu_ns,
                    "cpu_scope": "sum of measured thread_time_ns deltas inside successful owned tool bodies; errors/other threads/harness excluded",
                    "native_evidence": evidence,
                }
            )
        if aid in readbacks:
            require(readbacks[aid] == b"DONE", "execution_readback_recomputed")
            require(
                sample is not None
                and sample.get("completed_at") is not None
                and sample.get("error") is None,
                "execution_readback_without_completed_native",
            )
            name = aid + "-readback.txt"
            artifacts[name] = readbacks[aid]
            evidence.append(reference(name, readbacks[aid], VERSION))
        claims = {
            axis: {
                "status": "not-exercised",
                "reason_code": "execution_profile_does_not_admit_axis",
                "native_reason": "Native task scores do not establish this separate axis",
                "profile": VERSION,
                "evidence": [],
            }
            for axis in AXES
        }
        claims["task_outcome"] = {
            "status": task_status,
            "reason_code": (
                "native_match_score"
                if task_status in {"pass", "fail"}
                else "native_task_score_unknown"
            ),
            "native_reason": "Selected native match C/I score; not independent rescoring",
            "profile": "match-C-I-v0",
            "evidence": evidence,
        }
        if aid in readbacks:
            claims["effect"] = {
                "status": "unknown",
                "reason_code": "local_readback_retained_without_effect_attestation",
                "native_reason": "Original local file bytes retained separately; no signed effect or independent observation claim",
                "profile": VERSION,
                "evidence": evidence,
            }
        record = {
            "run_id": plan["run_id"],
            **spec,
            "harness_status": status,
            "resources": resources,
            "claims": claims,
            "capture": {
                "scope": "retained-inspect-execution-transcript",
                "complete": False,
                "gaps": gaps,
                "observed_effect_count": None,
            },
        }
        name = aid + "-mapped.json"
        artifacts[name] = encode(record)
        records.append({**record, "output": reference(name, artifacts[name], VERSION)})
    artifacts["execution-measurements.json"] = encode(measurements)
    starts = [
        r["identity"]["attempt_id"]
        for r in records
        if r["harness_status"] not in {"not-started", "start-unknown"}
    ]
    artifacts["execution-start-ledger.json"] = encode(
        {"run_id": plan["run_id"], "starts": starts}
    )
    history = {
        "profile": PROFILE,
        "run_id": plan["run_id"],
        "plan_sha256": digest(encode(plan)),
        "start_ledger": starts,
        "history_head_ref": reference(
            "execution-start-ledger.json",
            artifacts["execution-start-ledger.json"],
            VERSION,
        ),
        "records": records,
    }
    return plan, history, artifacts


def verify(
    declared: dict,
    native_logs: dict[str, bytes],
    bindings: dict[str, dict],
    source_bytes: dict[str, bytes],
    readbacks: dict[str, bytes],
    *,
    plan_bytes: bytes,
    history_bytes: bytes,
    artifacts: dict[str, bytes],
    expected_plan_sha256: str,
    expected_history_sha256: str,
) -> dict:
    plan, history, retained = adapt(
        declared, native_logs, bindings, source_bytes, readbacks
    )
    require(
        encode(decode(plan_bytes)) == encode(plan), "execution_plan_mapping_mismatch"
    )
    require(
        encode(decode(history_bytes)) == encode(history),
        "execution_history_mapping_mismatch",
    )
    require(artifacts == retained, "execution_artifact_mapping_mismatch")
    return {
        **validate(
            plan_bytes,
            history_bytes,
            artifacts,
            expected_plan_sha256=expected_plan_sha256,
            expected_history_sha256=expected_history_sha256,
        ),
        "mapping": VERSION,
        "interpretation": "same-operator-native-mock-tools-agents-local-workload-not-real-model-benchmark",
        "resourceScope": "native-sample-elapsed-and-owned-tool-thread-CPU-only",
        "priorCommitment": "local-pre-run-file-not-authenticated-witness",
        "independentCustody": "not-established",
    }


SOURCE_NAMES = {
    "task.json",
    "harness.json",
    "model.json",
    "rubric.py",
    "policy.txt",
    "configuration.json",
}
PIN_NAMES = {
    "expected_declaration_sha256",
    "expected_sources_sha256",
    "expected_bindings_sha256",
    "expected_plan_sha256",
    "expected_history_sha256",
}


def _source_manifest(source_bytes: dict[str, bytes]) -> bytes:
    return encode({name: digest(raw) for name, raw in source_bytes.items()})


def _read_within(root: Path, path: Path) -> bytes:
    require(
        path.resolve().is_relative_to(root.resolve()), "execution_packet_path_escape"
    )
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "execution_packet_size")
    return raw


def verify_saved(output: Path, selected: dict) -> dict:
    """Read a saved packet using pins selected outside that packet.

    No native framework or provider is invoked. IDs are bounded file components,
    and neither named artifacts nor native URLs are followed outside this folder.
    """
    object_keys(selected, PIN_NAMES, "execution_consumer_pins")
    declaration_raw = _read_within(output, output / "declaration-before-run.json")
    pinned(declaration_raw, selected["expected_declaration_sha256"])
    declared = decode(declaration_raw)
    _declared(declared)
    source_bytes = {
        name: _read_within(output, output / "sources" / name) for name in SOURCE_NAMES
    }
    pinned(_source_manifest(source_bytes), selected["expected_sources_sha256"])
    packet = output / "packet"
    bindings_raw = _read_within(output, packet / "native-bindings.json")
    pinned(bindings_raw, selected["expected_bindings_sha256"])
    bindings = decode(bindings_raw)
    require(type(bindings) is dict, "execution_binding_population")
    allowed = {case["id"] for case in declared["cases"] if case["launch"]}
    require(set(bindings) <= allowed, "execution_binding_population")
    native_logs = {
        aid: _read_within(output, packet / (aid + "-native.json")) for aid in bindings
    }
    readbacks = {
        case["id"]: _read_within(output, packet / (case["id"] + "-readback.txt"))
        for case in declared["cases"]
        if case["tier"] == "workloads"
        and case["launch"]
        and (packet / (case["id"] + "-readback.txt")).exists()
    }
    excluded = {
        "plan.json",
        "history.json",
        "consumer-pins.json",
        "native-bindings.json",
        "report.json",
    }
    artifacts = {
        path.name: _read_within(output, path)
        for path in packet.iterdir()
        if path.is_file() and path.name not in excluded
    }
    return verify(
        declared,
        native_logs,
        bindings,
        source_bytes,
        readbacks,
        plan_bytes=_read_within(output, packet / "plan.json"),
        history_bytes=_read_within(output, packet / "history.json"),
        artifacts=artifacts,
        expected_plan_sha256=selected["expected_plan_sha256"],
        expected_history_sha256=selected["expected_history_sha256"],
    )


def _write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)


def _execute(framework: Any, declared: dict, case: dict, folder: Path) -> Path:
    from inspect_ai.agent import react
    from inspect_ai.dataset import Sample
    from inspect_ai.model import (
        ChatMessageAssistant,
        ModelOutput,
        ModelUsage,
        get_model,
    )
    from inspect_ai.scorer import match
    from inspect_ai.solver import generate, use_tools
    from inspect_ai.tool import ToolCall, tool

    target = folder / "ticket.txt"
    if case["tier"] == "workloads":
        _write(target, b"OPEN")

    def measured(function: Any) -> str:
        start, cpu = time.perf_counter_ns(), time.thread_time_ns()
        value = function()
        return encode(
            {
                "value": value,
                "elapsed_ns": time.perf_counter_ns() - start,
                "thread_cpu_ns": time.thread_time_ns() - cpu,
            }
        ).decode()

    @tool
    def double():
        async def execute(value: int) -> str:
            """Double an integer.

            Args:
                value: Integer input.
            """
            require(type(value) is int, "native_tool_input")
            return measured(lambda: value * 2)

        return execute

    @tool
    def read_ticket():
        async def execute() -> str:
            """Read the single local ticket."""
            return measured(lambda: target.read_text("utf-8"))

        return execute

    @tool
    def write_ticket():
        async def execute(content: str) -> str:
            """Write the single local ticket.

            Args:
                content: New ticket status.
            """
            require(content == "DONE", "native_ticket_value")

            def write():
                target.write_text(content, "utf-8")
                return target.read_text("utf-8")

            return measured(write)

        return execute

    calls = (
        [("read_ticket", {}), ("write_ticket", {"content": "DONE"})]
        if case["tier"] == "workloads"
        else [("double", {"value": 2})]
    )
    outputs = [
        ModelOutput.from_message(
            ChatMessageAssistant(
                content="",
                tool_calls=[ToolCall(id=f"call-{i}", function=name, arguments=args)],
            ),
            stop_reason="tool_calls",
        )
        for i, (name, args) in enumerate(calls)
    ]
    if case["final"] is not None:
        outputs.append(ModelOutput.from_content(model="mockllm", content=case["final"]))
    for output in outputs:
        output.usage = ModelUsage(input_tokens=0, output_tokens=0, total_tokens=0)
    model = get_model("mockllm/model", custom_outputs=outputs)
    tools = (
        [read_ticket(), write_ticket()] if case["tier"] == "workloads" else [double()]
    )
    solver = (
        [use_tools(tools), generate()]
        if case["tier"] == "tools"
        else react(tools=tools, submit=False)
    )
    task = framework.Task(
        dataset=[Sample(id=case["id"], input=case["input"], target=case["target"])],
        solver=solver,
        scorer=match(),
        name=case["id"],
        version=1,
        metadata={
            "probity_execution_profile": VERSION,
            "probity_declaration_sha256": digest(encode(declared)),
        },
        message_limit=12,
    )
    framework.eval(
        task,
        model=model,
        display="none",
        log_format="json",
        log_dir=str(folder / "native"),
        epochs=1,
        retry_on_error=0,
        max_samples=1,
        fail_on_error=True,
    )
    logs = list((folder / "native").glob("*.json"))
    require(len(logs) == 1, "native_log_count")
    return logs[0]


def run(output: Path) -> dict:
    import inspect_ai

    require(
        importlib.metadata.version("inspect-ai") == INSPECT_VERSION,
        "execution_framework_version",
    )
    output.mkdir(parents=True, exist_ok=False)
    runtime_root = Path(inspect_ai.__file__).parent
    _write(
        output / "inspect-runtime-files.json",
        encode(
            {
                str(path.relative_to(runtime_root)): hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
                for path in sorted(runtime_root.rglob("*.py"))
            }
        ),
    )
    distribution = importlib.metadata.distribution("inspect-ai")
    _write(output / "inspect-METADATA.txt", distribution.read_text("METADATA").encode())
    _write(
        output / "inspect-LICENSE.txt",
        Path(
            distribution.locate_file(
                f"inspect_ai-{INSPECT_VERSION}.dist-info/licenses/LICENSE"
            )
        ).read_bytes(),
    )
    declared = declaration()
    selected_sources = sources(inspect_ai, declared)
    plan = contract_plan(declared, selected_sources)
    _write(output / "declaration-before-run.json", encode(declared))
    _write(output / "common-plan-before-run.json", encode(plan))
    for name, raw in selected_sources.items():
        _write(output / "sources" / name, raw)
    native_logs, bindings, readbacks = {}, {}, {}
    for case in declared["cases"]:
        if not case["launch"]:
            continue
        folder = output / case["id"]
        native = _execute(inspect_ai, declared, case, folder).read_bytes()
        native_logs[case["id"]] = native
        ev = decode(native)["eval"]
        bindings[case["id"]] = {
            "sha256": digest(native),
            "run_id": ev["run_id"],
            "eval_id": ev["eval_id"],
        }
        if case["tier"] == "workloads":
            readbacks[case["id"]] = (folder / "ticket.txt").read_bytes()
    mapped, history, artifacts = adapt(
        declared, native_logs, bindings, selected_sources, readbacks
    )
    require(encode(mapped) == encode(plan), "execution_plan_changed_during_run")
    plan_raw, history_raw = encode(mapped), encode(history)
    pins = {
        "expected_declaration_sha256": digest(encode(declared)),
        "expected_sources_sha256": digest(_source_manifest(selected_sources)),
        "expected_bindings_sha256": digest(encode(bindings)),
        "expected_plan_sha256": digest(plan_raw),
        "expected_history_sha256": digest(history_raw),
    }
    report = verify(
        declared,
        native_logs,
        bindings,
        selected_sources,
        readbacks,
        plan_bytes=plan_raw,
        history_bytes=history_raw,
        artifacts=artifacts,
        expected_plan_sha256=pins["expected_plan_sha256"],
        expected_history_sha256=pins["expected_history_sha256"],
    )
    for name, raw in artifacts.items():
        _write(output / "packet" / name, raw)
    for name, value in {
        "plan.json": mapped,
        "history.json": history,
        "consumer-pins.json": pins,
        "native-bindings.json": bindings,
        "report.json": report,
    }.items():
        _write(output / "packet" / name, encode(value))
    receipt = {
        "profile": VERSION,
        "inspectVersion": INSPECT_VERSION,
        "providerCalls": "none-mock-provider",
        "report": report,
        "localWorkloadReadback": {aid: raw.decode() for aid, raw in readbacks.items()},
        "plannedUnstarted": "declared-launch-false-not-independent-observation",
        "nativeIncomplete": "mutation-control-only",
        "tokenResources": "unmapped-mock-zero",
        "effectAdmission": "unknown-local-readback-retained",
    }
    _write(output / "receipt.json", encode(receipt))
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--pins-file", type=Path)
    args = parser.parse_args()
    if args.verify:
        if args.pins_file is None:
            parser.error("--verify requires --pins-file selected outside the packet")
        result = verify_saved(args.output, decode(args.pins_file.read_bytes()))
    else:
        if args.pins_file is not None:
            parser.error("--pins-file requires --verify")
        result = run(args.output)
    print(json.dumps(result, indent=2))
