"""Frozen deterministic integration populations for the five-tier v0.

The manifest is a local pre-execution declaration. It is not a witnessed prior
commitment. Controlled Inspect responses establish integration behavior rather
than model quality. Historical actual-model runs are never pooled with it.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

VERSION = "probity-five-tier-breadth-v0.1"


def encode(value: Any) -> bytes:
    """Encode local wrapper bytes deterministically, without claiming JCS."""
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def digest(raw: bytes) -> str:
    """Return SHA-256 of the original supplied bytes."""
    return hashlib.sha256(raw).hexdigest()


def case(identifier: str, tier: str, family: str, target: str, calls: list[dict[str, Any]], *, solver: str = "generate", response: str | None = None) -> dict[str, Any]:
    """Declare one attempt and its controlled native model response sequence.

    Parameters
    ----------
    identifier, tier, family : str
        Stable attempt, evaluation tier and bounded task family identifiers.
    target : str
        Exact reference answer; surrounding whitespace is stripped by our reader.
    calls : list of dict
        Ordered tool calls with a fixed name and JSON argument object.
    solver : str, optional
        Native Inspect configuration, ``generate``, ``react-8`` or ``react-12``.
    response : str or None, optional
        Deliberately scripted final completion. None selects the target answer.

    Returns
    -------
    dict
        JSON-compatible declaration consumed by :func:`manifest` and the runner.
    """
    return {"id": identifier, "tier": tier, "family": family, "input": f"Perform {identifier}; report the exact final answer.", "target": target, "response": target if response is None else response, "calls": calls, "solver": solver, "launch": True}


def call(name: str, **arguments: Any) -> dict[str, Any]:
    """Declare a single bounded owned tool invocation."""
    return {"name": name, "arguments": arguments}


def manifest() -> dict[str, Any]:
    """Construct the exact finite population frozen before native execution.

    Returns
    -------
    dict
        Ten author-written arithmetic reasoning questions, twelve tool
        scenarios spanning arithmetic, scoped files and SQLite, three agent
        configurations across arithmetic and file-state families, two complete
        local workflows, and separately declared failure controls. Native A2A
        arithmetic/error interactions remain an unchanged six-attempt child
        profile with its own denominators and admission reader.
    """
    rows = [case(f"reason-{i:02}", "reasoning", "arithmetic", str(i + 3), []) for i in range(1, 11)]
    for row, i in zip(rows, range(1, 11), strict=True):
        row["input"] = f"What is {i} + 3? Return only the decimal integer."
    for i, value in enumerate((0, 2, -3, 100), 1):
        rows.append(case(f"tool-arithmetic-{i}", "tools", "arithmetic", str(value * 2), [call("double", value=value)]))
    file_calls = ([call("read_file")], [call("write_file", content="DONE"), call("read_file")], [call("write_file", content="DONE"), call("write_file", content="DONE")], [call("write_file", content="REFUSED"), call("read_file")])
    for i, (calls, target) in enumerate(zip(file_calls, ("OPEN", "DONE", "DONE", "OPEN"), strict=True), 1):
        rows.append(case(f"tool-file-{i}", "tools", "scoped-file", target, calls))
    sql_calls = ([call("read_balance")], [call("transfer", amount=3), call("read_balance")], [call("transfer", amount=10), call("read_balance")], [call("transfer", amount=11), call("read_balance")])
    for i, (calls, target) in enumerate(zip(sql_calls, ("10,0", "7,3", "0,10", "10,0"), strict=True), 1):
        rows.append(case(f"tool-sqlite-{i}", "tools", "sqlite-transaction", target, calls))
    rows += [case("agent-generate", "agents", "arithmetic", "8", [call("double", value=4)]), case("agent-react-8", "agents", "arithmetic", "10", [call("double", value=5)], solver="react-8"), case("agent-react-12", "agents", "file-state", "DONE", [call("read_file"), call("write_file", content="DONE"), call("read_file")], solver="react-12")]
    rows += [case("workload-file", "workloads", "file-state", "DONE", [call("read_file"), call("write_file", content="DONE"), call("read_file")], solver="react-12"), case("workload-sqlite", "workloads", "sqlite-transaction", "6,4", [call("read_balance"), call("transfer", amount=4), call("read_balance")], solver="react-12")]
    controls = [case("control-task-failure", "controls", "rubric", "4", [], response="wrong"), case("control-harness-error", "controls", "exhausted-mock", "4", [call("double", value=2)])]
    controls[1]["response"] = None
    missing = case("control-not-started", "controls", "launcher", "4", [])
    missing["launch"] = False
    controls.append(missing)
    return {"profile": VERSION, "classification": "probity-operated-native-mock-and-deterministic-integration", "real_model_quality": "not-measured", "historical_cpu_baseline": {"profile": "probity-inspect-local-model-v1", "attempts": 12, "strict_passes": 0, "pooling": "prohibited"}, "budget": {"max_seconds": 180, "max_messages_per_attempt": 12, "max_calls_per_attempt": 3, "max_output_bytes": 32 * 1024 * 1024, "provider_calls": 0, "provider_dollars": 0, "retries": 0}, "framework": {"inspect-ai": "0.3.273", "a2a-sdk": "1.2.1"}, "attempts": rows, "controls": controls, "a2a": {"script": "interop/a2a-native-2026-10-02/a2a_demo.py", "interaction_families": ["arithmetic-request-result", "error-incomplete-refusal"], "planned_attempts": 6, "native_reader": "interop/a2a-native-2026-10-02/a2a_verify.py", "population": "separate-original-six-attempt-profile"}}


def population(records: list[dict[str, Any]]) -> dict[str, int]:
    """Account for all declarations without converting task failure to error.

    Parameters
    ----------
    records : list of dict
        Reconstructed attempt records from retained native logs and launch marks.

    Returns
    -------
    dict of str to int
        Planned/start/completion, error, incomplete and unknown counters. Scores
        are counted only for completed records with decisive exact-rubric output.
    """
    statuses = [row["status"] for row in records]
    return {"planned": len(records), "started": sum(s not in {"not-started", "start-unknown"} for s in statuses), "complete": statuses.count("complete"), "error": statuses.count("error"), "incomplete": statuses.count("incomplete"), "not_started": statuses.count("not-started"), "unknown_start": statuses.count("start-unknown"), "scored": sum(row["task_outcome"] in {"pass", "fail"} for row in records), "task_passed": sum(row["task_outcome"] == "pass" for row in records), "task_failed": sum(row["task_outcome"] == "fail" for row in records)}
