"""Freeze and execute finite native integration breadth with zero provider spend."""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from native import execute
from protocol import digest, encode, manifest
from reader import decode, derive, report, verify

ROOT = Path(__file__).resolve().parents[2]


def write(path: Path, value: Any) -> None:
    """Retain a fresh deterministic local-wrapper file, refusing replacement."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(encode(value))


def launch_case(case: dict[str, Any], declared: dict[str, Any], output: Path, deadline: float) -> dict[str, Any]:
    """Run a declared attempt once, retaining launch refusal and native failure."""
    directory = output / "cases" / case["id"]
    directory.mkdir(parents=True)
    started = time.perf_counter_ns()
    launch: dict[str, Any] = {"status": "not-started", "reason": "declared_not_started", "elapsed_ns": None}
    if case["launch"] and time.monotonic() < deadline:
        try:
            path = execute(case, declared, directory)
            shutil.copyfile(path, directory / "native.json")
            launch = {"status": "returned", "elapsed_ns": time.perf_counter_ns() - started}
        except (OSError, ValueError, RuntimeError, ImportError) as error:
            # Native/launch errors are evidence, never retried or replaced.
            launch = {"status": "error", "type": type(error).__name__, "message": str(error), "elapsed_ns": time.perf_counter_ns() - started}
    elif case["launch"]:
        launch["reason"] = "predeclared_budget_exhausted"
    write(directory / "launch.json", launch)
    artifacts = {str(path.relative_to(directory)): path.read_bytes() for path in directory.rglob("*") if path.is_file()}
    return derive(case, declared, artifacts)


def bounded_child(command: list[str], stdout: Any, stderr: Any, timeout: float) -> subprocess.Popen[bytes]:
    """Bound the child process group so timeout cannot leave an SDK server."""
    process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        raise
    return process


def launch_a2a(declared: dict[str, Any], output: Path, deadline: float) -> dict[str, Any]:
    """Run the unchanged actual SDK HTTP profile under a bounded child deadline."""
    started = time.perf_counter_ns()
    result: dict[str, Any] = {"status": "not-started", "reason": "predeclared_budget_exhausted", "interaction_families": declared["a2a"]["interaction_families"], "planned_attempts": 6}
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return result
    with (output / "a2a-stdout.log").open("xb") as stdout, (output / "a2a-stderr.log").open("xb") as stderr:
        try:
            process = bounded_child([sys.executable, str(ROOT / declared["a2a"]["script"]), str(output / "a2a-native")], stdout, stderr, min(30, remaining))
            result.pop("reason", None)
            result.update({"status": "error", "exit_code": process.returncode})
            path = output / "a2a-native" / "report.json"
            if process.returncode == 0 and path.is_file():
                result.update({"status": "complete", "original_report": decode(path.read_bytes()), "report_sha256": digest(path.read_bytes())})
        except subprocess.TimeoutExpired:
            result.update({"status": "timeout", "reason": "child_deadline"})
        except OSError as error:
            result.update({"status": "error", "type": type(error).__name__})
    result["elapsed_ns"] = time.perf_counter_ns() - started
    return result


def retain_runtime(output: Path) -> None:
    """Retain installed Inspect native implementation bytes and license metadata."""
    import inspect_ai
    package = Path(inspect_ai.__file__).parent
    files = ("_eval/eval.py", "agent/_react.py", "solver/_solver.py", "solver/_use_tools.py", "tool/_tool.py", "model/_providers/mockllm.py", "scorer/_match.py")
    for name in files:
        target = output / "inspect-source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(package / name, target)
    installed = importlib.metadata.distribution("inspect-ai")
    (output / "inspect-METADATA.txt").write_text(installed.read_text("METADATA") or "", encoding="utf-8")
    license_path = installed.locate_file("inspect_ai-0.3.273.dist-info/licenses/LICENSE")
    shutil.copyfile(str(license_path), output / "inspect-LICENSE.txt")
    write(output / "inspect-runtime-files.json", {str(path.relative_to(package)): digest(path.read_bytes()) for path in sorted(package.rglob("*.py"))})


def run(output: Path) -> dict[str, Any]:
    """Execute fresh controlled native populations and retain original provenance.

    Parameters
    ----------
    output : pathlib.Path
        Must not exist. All native artifacts and the pre-run declaration remain
        there, including unsuccessful launches and partial original outputs.

    Returns
    -------
    dict
        Separate integration populations. There is no pooled score, real-model
        result, independent custody claim or protected-effect authorization.
    """
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    declared = manifest()
    deadline = time.monotonic() + declared["budget"]["max_seconds"]
    write(output / "declaration-before-run.json", declared)
    for path in Path(__file__).parent.glob("*.py"):
        shutil.copyfile(path, output / ("source-" + path.name))
    retain_runtime(output)
    write(output / "runtime.json", {"python": sys.version, "packages": {name: importlib.metadata.version(name) for name in ("inspect-ai", "a2a-sdk", "httpx", "protobuf", "starlette", "uvicorn")}})
    records = [launch_case(case, declared, output, deadline) for case in declared["attempts"] + declared["controls"]]
    a2a = launch_a2a(declared, output, deadline)
    write(output / "a2a-launch.json", a2a)
    result = report(declared, records, a2a)
    write(output / "report.json", result)
    index = {str(path.relative_to(output)): digest(path.read_bytes()) for path in output.rglob("*") if path.is_file() and str(path.relative_to(output)) not in {"declaration-before-run.json", "report.json"}}
    if sum(path.stat().st_size for path in output.rglob("*") if path.is_file()) > declared["budget"]["max_output_bytes"]:
        raise ValueError("retention_budget_exceeded")
    write(output / "artifact-index.json", index)
    pins = {"declaration_sha256": digest((output / "declaration-before-run.json").read_bytes()), "index_sha256": digest((output / "artifact-index.json").read_bytes())}
    write(output / "consumer-pins.json", pins)
    return verify(output, pins)


def successful(result: dict[str, Any]) -> bool:
    """Require all target cells executed and all deliberately declared controls."""
    complete = all(result["populations"][tier]["complete"] == expected for tier, expected in (("reasoning", 10), ("tools", 12), ("agents", 3), ("workloads", 2)))
    controls = result["populations"]["controls"]
    return complete and result["a2a"]["status"] == "complete" and controls["task_failed"] == 1 and controls["error"] == 1 and controls["not_started"] == 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--pins-file", type=Path)
    args = parser.parse_args()
    if args.verify:
        if args.pins_file is None:
            parser.error("--verify requires --pins-file selected outside the packet")
        result = verify(args.output, decode(args.pins_file.read_bytes()))
    else:
        if args.pins_file is not None:
            parser.error("--pins-file requires --verify")
        result = run(args.output)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if successful(result) else 1)
