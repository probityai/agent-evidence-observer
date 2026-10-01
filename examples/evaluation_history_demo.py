"""Run official Inspect mock-model contract cases and retain every declared entry.

Requires inspect-ai==0.3.273. No model-provider request is made. The mock outputs
exercise logging and grading behavior; they are not an LLM evaluation.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import sys
import uuid
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from probity_observer.crypto import VerificationError
from probity_observer.evaluation_history import (
    AttemptSpec,
    RunPlan,
    SourcePin,
    artifact_ref,
    encode_record,
    plan_digest,
    verify_history,
)
from probity_observer.inspect_history import (
    INSPECT_VERSION,
    POLICY_BYTES,
    InspectBinding,
    InspectHistory,
    adapt_inspect_log,
    verify_inspect_history,
)


def _now() -> str:
    """Return a UTC wall-clock timestamp without dropping subseconds."""
    return datetime.now(timezone.utc).isoformat()


def _write(path: Path, content: bytes) -> None:
    """Retain fresh bytes without replacing an existing artifact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(content)


def _framework() -> Any:
    """Require the exact supported official framework before running a task."""
    import inspect_ai

    if importlib.metadata.version("inspect-ai") != INSPECT_VERSION:
        raise RuntimeError(f"This example requires inspect-ai=={INSPECT_VERSION}")
    return inspect_ai


def _runtime_files(framework: Any, output: Path) -> dict[str, str]:
    """Retain installed Inspect code hashes and its redistribution license."""
    root = Path(framework.__file__).parent
    files = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*.py"))
    }
    content = encode_record(files)
    _write(output / "inspect-runtime-files.json", content)
    distribution = importlib.metadata.distribution("inspect-ai")
    metadata = distribution.read_text("METADATA").encode("utf-8")
    _write(output / "inspect-METADATA.txt", metadata)
    license_path = Path(
        distribution.locate_file(
            f"inspect_ai-{INSPECT_VERSION}.dist-info/licenses/LICENSE"
        )
    )
    _write(output / "inspect-LICENSE.txt", license_path.read_bytes())
    return {
        "installedCodeManifestSha256": hashlib.sha256(content).hexdigest(),
        "distributionMetadataSha256": hashlib.sha256(metadata).hexdigest(),
        "sourceAuthority": "actual-installed-files-not-inferred-Git-revision",
    }


def _task_config(name: str, samples: int, epochs: int) -> dict[str, Any]:
    """Define the complete finite mock-model task population before execution."""
    return {
        "name": name,
        "version": 1,
        "epochs": epochs,
        "retry_on_error": 0,
        "max_samples": 1,
        "samples": [
            {"id": f"sample-{index}", "input": "What is 2 + 2?", "target": "4"}
            for index in range(1, samples + 1)
        ],
    }


def _sources(
    framework: Any, task: dict[str, Any], outputs: list[str]
) -> tuple[tuple[SourcePin, ...], dict[str, bytes]]:
    """Pin actual installed implementation files, not an inferred Git revision."""
    import probity_observer.evaluation_history as checker
    import probity_observer.inspect_history as adapter

    root = Path(framework.__file__).parent
    source_paths = {
        "solver": root / "solver/_solver.py",
        "scorer": root / "scorer/_match.py",
        "harness": root / "_eval/eval.py",
    }
    content = {f"{role}.py": path.read_bytes() for role, path in source_paths.items()}
    content["task.json"] = encode_record(task)
    content["model.json"] = encode_record(
        {
            "identity": "mockllm/model",
            "custom_outputs": outputs,
            "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
            "provider_source": (root / "model/_providers/mockllm.py").read_text(
                "utf-8"
            ),
        }
    )
    content["checker.json"] = encode_record(
        {
            "evaluation_history.py": Path(checker.__file__).read_text("utf-8"),
            "inspect_history.py": Path(adapter.__file__).read_text("utf-8"),
        }
    )
    content["policy.json"] = POLICY_BYTES
    identity = {
        "task": task["name"],
        "model": "mockllm/model",
        "solver": "generate",
        "checker": "probity-inspect-history",
        "scorer": "match",
        "policy": "match-C-I",
        "harness": "inspect_ai",
    }
    return _source_pins(identity, content), content


def _source_pins(
    identities: dict[str, str], content: dict[str, bytes]
) -> tuple[SourcePin, ...]:
    """Keep scorer implementation and grading policy version independently pinned."""
    pins: list[SourcePin] = []
    for role, identity in identities.items():
        suffix = "json" if role in {"task", "model", "checker", "policy"} else "py"
        name = f"{role}.{suffix}"
        version = (
            "1"
            if role == "task"
            else "v0"
            if role in {"checker", "policy"}
            else INSPECT_VERSION
        )
        pins.append(
            SourcePin(role, identity, version, artifact_ref(name, content[name]))
        )
    return tuple(pins)


def _plan(task: dict[str, Any], sources: tuple[SourcePin, ...]) -> RunPlan:
    """Declare every sample and epoch before invoking the native harness."""
    attempts = tuple(
        AttemptSpec(f"sample-{index}-epoch-{epoch}", sample["id"], epoch)
        for epoch in range(1, task["epochs"] + 1)
        for index, sample in enumerate(task["samples"], 1)
    )
    return RunPlan(f"inspect-contract-{uuid.uuid4().hex}", _now(), attempts, sources)


def _model(outputs: list[str]) -> Any:
    """Use official mock outputs with explicit zero usage and no tokenizer fetch."""
    from inspect_ai.model import ModelOutput, ModelUsage, get_model

    values: list[ModelOutput] = []
    for text in outputs:
        value = ModelOutput.from_content(model="mockllm", content=text)
        value.usage = ModelUsage(input_tokens=0, output_tokens=0, total_tokens=0)
        values.append(value)
    return get_model("mockllm/model", custom_outputs=values)


def _execute(
    framework: Any,
    task_config: dict[str, Any],
    plan: RunPlan,
    output: Path,
    outputs: list[str],
) -> Path:
    """Execute the official Task, generate solver, and match scorer locally."""
    from inspect_ai.dataset import Sample
    from inspect_ai.scorer import match
    from inspect_ai.solver import generate

    task = framework.Task(
        dataset=[Sample(**sample) for sample in task_config["samples"]],
        solver=generate(),
        scorer=match(),
        name=task_config["name"],
        version=task_config["version"],
        metadata={
            "probity_run_id": plan.run_id,
            "probity_plan_digest": plan_digest(plan),
        },
    )
    framework.eval(
        task,
        model=_model(outputs),
        display="none",
        log_format="json",
        log_dir=str(output / "native"),
        epochs=task_config["epochs"],
        retry_on_error=0,
        max_samples=1,
        fail_on_error=True,
    )
    logs = tuple((output / "native").glob("*.json"))
    if len(logs) != 1:
        raise RuntimeError("Expected exactly one retained native JSON log")
    return logs[0]


def _retain(
    output: Path,
    plan: RunPlan,
    history: InspectHistory,
    sources: dict[str, bytes],
    captured_at: str,
) -> dict[str, Any]:
    """Check and retain the full population, including failed and absent entries."""
    for name, content in history.artifacts.items():
        _write(output / "artifacts" / name, content)
    result = verify_history(
        plan,
        history.records,
        artifacts=history.artifacts,
        sources=sources,
        ended_at=captured_at,
    )
    _write(
        output / "attempts.json",
        encode_record([asdict(record) for record in history.records]),
    )
    _write(
        output / "result.json",
        encode_record({"consistency": result, "native": history.report}),
    )
    return result


def _expect_refusal(name: str, callback: Any) -> dict[str, str]:
    """Record refusal receipts without claiming the control was real model work."""
    try:
        callback()
    except VerificationError as error:
        return {"case": name, "status": "refused", "reason": str(error)}
    raise RuntimeError(f"Mutation control was accepted: {name}")


def _controls(
    plan: RunPlan,
    history: InspectHistory,
    sources: dict[str, bytes],
    captured_at: str,
    native: bytes,
    binding: InspectBinding,
) -> list[dict[str, str]]:
    """Check omission, duplicate, summary, stale output, and scorer drift."""

    def check(
        records: Any = history.records,
        artifacts: Any = history.artifacts,
        summary: Any = None,
    ) -> Any:
        return verify_history(
            plan,
            records,
            artifacts=artifacts,
            sources=sources,
            ended_at=captured_at,
            claimed_summary=summary,
        )

    controls = [
        _expect_refusal("missing-attempt", lambda: check(history.records[:-1])),
        _expect_refusal(
            "duplicate-attempt",
            lambda: check(history.records[:-1] + history.records[:1]),
        ),
        _expect_refusal(
            "selective-success-summary",
            lambda: check(summary={"attempts": 2, "pass": 2}),
        ),
    ]
    stale_records, stale_artifacts = _stale(history)
    controls.append(
        _expect_refusal(
            "stale-output-with-updated-hash",
            lambda: check(stale_records, stale_artifacts),
        )
    )
    drift = json.loads(native)
    drift["eval"]["scorers"][0]["name"] = "changed-scorer"
    drift_content = encode_record(drift)
    drift_binding = replace(
        binding, log_sha256=hashlib.sha256(drift_content).hexdigest()
    )
    controls.append(
        _expect_refusal(
            "changed-native-scorer",
            lambda: adapt_inspect_log(drift_content, plan, drift_binding),
        )
    )
    return controls


def _stale(history: InspectHistory) -> tuple[Any, dict[str, bytes]]:
    """Rehash substituted bytes to test the retained run identity."""
    record = history.records[0]
    artifacts = dict(history.artifacts)
    envelope = json.loads(artifacts[record.output.name])
    envelope["run_id"] = "another-run"
    artifacts[record.output.name] = encode_record(envelope)
    replaced = replace(
        record, output=artifact_ref(record.output.name, artifacts[record.output.name])
    )
    return (replaced,) + history.records[1:], artifacts


def _case(
    framework: Any,
    output: Path,
    name: str,
    samples: int,
    epochs: int,
    outputs: list[str],
) -> dict[str, Any]:
    """Create a fresh predeclared run and retain its native and checker receipts."""
    task = _task_config(name, samples, epochs)
    pins, sources = _sources(framework, task, outputs)
    plan = _plan(task, pins)
    _write(output / "plan.json", encode_record(asdict(plan)))
    for identity, content in sources.items():
        _write(output / "sources" / identity, content)
    native_path = _execute(framework, task, plan, output, outputs)
    captured_at = _now()
    native = native_path.read_bytes()
    spec = json.loads(native)["eval"]
    binding = InspectBinding(
        spec["run_id"], spec["eval_id"], hashlib.sha256(native).hexdigest()
    )
    _write(
        output / "launch-receipt.json",
        encode_record(
            {
                "declaredRunId": plan.run_id,
                "planDigest": plan_digest(plan),
                "nativeRunId": binding.run_id,
                "nativeEvalId": binding.eval_id,
                "capturedAt": captured_at,
                "nativeLog": native_path.name,
                "nativeLogSha256": hashlib.sha256(native).hexdigest(),
                "bindingAuthority": "same-operator-retained-receipt",
            }
        ),
    )
    history = adapt_inspect_log(native, plan, binding)
    result = _retain(output, plan, history, sources, captured_at)
    combined = verify_inspect_history(
        native,
        plan,
        binding,
        sources=sources,
        captured_at=captured_at,
        records=history.records,
        artifacts=history.artifacts,
    )
    _write(output / "combined-verification.json", encode_record(combined))
    controls = _controls(plan, history, sources, captured_at, native, binding)
    _write(output / "mutation-controls.json", encode_record(controls))
    return {
        "case": name,
        "nativeStatus": history.report["nativeStatus"],
        "summary": result["summary"],
        "mutationControls": len(controls),
        "interpretation": "official-mock-harness-contract-not-LLM-performance",
    }


def main() -> None:
    """Run the bounded contract without overwriting an earlier receipt directory."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=False)
    framework = _framework()
    runtime_files = _runtime_files(framework, args.output_dir)
    results = [
        _case(
            framework,
            args.output_dir / "graded",
            "probity_graded_contract",
            2,
            2,
            ["4", "wrong", "4", "wrong"],
        ),
        _case(
            framework, args.output_dir / "error", "probity_error_contract", 3, 1, ["4"]
        ),
    ]
    receipt = {
        "mode": "offline-contract",
        "pythonVersion": sys.version.split()[0],
        "inspectVersion": INSPECT_VERSION,
        "model": "mockllm/model",
        "providerCalls": "none-mock-provider",
        "cases": results,
        "executionTruth": "same-operator-native-execution",
        "independentCustody": "not-established",
        "globalNoOmission": "not-established",
        "runtimeFiles": runtime_files,
    }
    _write(args.output_dir / "receipt.json", encode_record(receipt))
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
