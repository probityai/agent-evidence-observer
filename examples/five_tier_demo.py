"""Launch three native profiles covering five tiers and retain child failures.

This orchestration record accounts for declared launches, not model quality or
independent custody. Each native profile retains and checks its own run plan,
original artifacts and common attempt records. No aggregate score is assigned.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROFILES = (
    ("reasoning", ("reasoning",), "interop/evaluation-contract-2026-10-01/inspect_demo.py", "receipt.json"),
    ("inspect-execution", ("tools", "agents", "workloads"), "interop/evaluation-contract-2026-10-01/inspect_execution.py", "receipt.json"),
    ("a2a", ("a2a",), "interop/a2a-native-2026-10-02/a2a_demo.py", "report.json"),
)


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("duplicate_report_member")
        value[name] = item
    return value


def _float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value):
        raise ValueError("nonfinite_report")
    return value


def _common_report(value: Any) -> bool:
    """Recognize the selected common receipt, without rescoring native attempts."""
    counters = ("planned", "started", "complete", "scored", "task_passed", "task_failed", "failed", "missing", "unknown_start", "incomplete")
    return (type(value) is dict and value.get("profile") == "probity-five-tier-result-reference-v0"
            and all(type(value.get(key)) is int and value[key] >= 0 for key in counters)
            and value["started"] + value["missing"] + value["unknown_start"] == value["planned"]
            and value["complete"] + value["failed"] + value["missing"] + value["unknown_start"] + value["incomplete"] == value["planned"]
            and value["scored"] == value["task_passed"] + value["task_failed"] <= value["complete"])


def _profile_report(name: str, value: dict[str, Any]) -> bool:
    if name == "reasoning":
        cases = value.get("cases")
        return value.get("inspectVersion") == "0.3.273" and value.get("model") == "mockllm/model" and type(cases) is list and len(cases) == 2 and all(_common_report(case) for case in cases)
    if name == "inspect-execution":
        return value.get("profile") == "probity-inspect-execution-v1" and value.get("inspectVersion") == "0.3.273" and _common_report(value.get("report"))
    if name == "a2a":
        return _common_report(value)
    return False


def _launch(command: list[str], directory: Path, report: Path, *, timeout: float, expected_profile: str | None = None) -> dict[str, Any]:
    """Retain actual launch status and require a new, bounded JSON report."""
    if report.exists() or report.is_symlink():
        return {"status": "refused", "reason": "report_already_exists", "exit_code": None}
    with (directory / "stdout.log").open("xb") as stdout, (directory / "stderr.log").open("xb") as stderr:
        try:
            process = subprocess.Popen(command, cwd=ROOT, stdout=stdout, stderr=stderr, start_new_session=True)
        except OSError as error:
            return {"status": "error", "reason": "launch_failed", "error_type": type(error).__name__, "exit_code": None}
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            return {"status": "timeout", "reason": "child_timeout", "exit_code": process.returncode}
    if code != 0:
        return {"status": "error", "reason": "child_failed", "exit_code": code}
    if not report.is_file() or report.is_symlink():
        return {"status": "error", "reason": "fresh_report_missing", "exit_code": code}
    try:
        size = report.stat().st_size
        if not 1 <= size <= 8 * 1024 * 1024:
            raise ValueError("report_size")
        raw = report.read_bytes()
        value = json.loads(raw, object_pairs_hook=_pairs, parse_float=_float, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_report")))
        if type(value) is not dict or not value:
            raise ValueError("report_shape")
    except (OSError, ValueError, UnicodeError, RecursionError) as error:
        return {"status": "error", "reason": "report_unreadable", "error_type": type(error).__name__, "exit_code": code}
    retained = {"report_sha256": _hash(raw), "report_bytes": len(raw)}
    if "status" in value and value["status"] not in ("complete", "valid", "validated", "passed", "success"):
        return {"status": "refused", "reason": "child_report_refused", "declared_status": value["status"] if type(value["status"]) is str else "malformed", "exit_code": code, **retained}
    if expected_profile is not None and not _profile_report(expected_profile, value):
        return {"status": "refused", "reason": "child_report_profile_differs", "exit_code": code, **retained}
    return {"status": "complete", "exit_code": code, **retained}


def run(output: Path, *, timeout: float = 180) -> dict[str, Any]:
    """Run each declared native profile once, preserving unsuccessful launches."""
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be positive")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    launches = []
    for name, tiers, source, report in PROFILES:
        script = ROOT / source
        launches.append({"id": name, "tiers": list(tiers), "script": source,
                         "script_sha256": _hash(script.read_bytes()) if script.is_file() else None,
                         "native_report": report})
    declaration = {"format": "probity-five-tier-launch-v0", "python": sys.version,
                   "launcher_sha256": _hash(Path(__file__).read_bytes()), "launches": launches,
                   "measurement_scope": "three-declared-local-profile-launches"}
    _write(output / "launch-plan.json", declaration)
    results = []
    for spec in launches:
        directory = output / spec["id"]
        directory.mkdir()
        script = ROOT / spec["script"]
        command = [sys.executable, str(script), str(directory / "native")]
        _write(directory / "command.json", {"argv": command, "cwd": str(ROOT)})
        if spec["script_sha256"] is None:
            result = {"status": "not-started", "reason": "profile_source_missing", "exit_code": None}
        elif _hash(script.read_bytes()) != spec["script_sha256"]:
            result = {"status": "refused", "reason": "profile_source_changed", "exit_code": None}
        else:
            result = _launch(command, directory, directory / "native" / spec["native_report"], timeout=timeout, expected_profile=spec["id"])
        result = {"id": spec["id"], "tiers": spec["tiers"], **result}
        _write(directory / "launch-result.json", result)
        results.append(result)
    completed = sum(result["status"] == "complete" for result in results)
    report = {"format": declaration["format"], "launch_plan_sha256": _hash((output / "launch-plan.json").read_bytes()),
              "declared_launches": len(launches), "completed_launches": completed,
              "status": "complete" if completed == len(launches) else "incomplete",
              "tiers": sorted({tier for spec in launches for tier in spec["tiers"]}),
              "launch_results": results,
              "classification": "same-operator-native-mock-and-deterministic-profile-launches",
              "model_quality": "not-established", "independent_custody": "not-established",
              "attempt_accounting": "retained in each profile native plan and common record",
              "aggregate_score": None}
    _write(output / "report.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()
    result = run(args.output, timeout=args.timeout)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "complete" else 1)
