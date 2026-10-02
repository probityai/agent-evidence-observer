"""Run pinned official Inspect mock tasks and retain common/native receipts."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from evaluation_contract import ROLES, digest, encode
from inspect_contract import adapt, contract_plan, verify

# Reuse the existing owned official-harness launcher without changing its API.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "examples"))
import evaluation_history_demo as launcher  # noqa: E402

from probity_observer.inspect_history import InspectBinding  # noqa: E402


def run(output: Path) -> dict:
    """Retain two native runs with no remote model calls and no overwritten files."""
    output.mkdir(parents=True, exist_ok=False)
    framework = launcher._framework()
    runtime = launcher._runtime_files(framework, output)
    receipts = []
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
    for name, size, epochs, completions in (
        ("graded", 2, 2, ["4", "wrong", "4", "wrong"]),
        ("error", 3, 1, ["4"]),
    ):
        folder = output / name
        task = launcher._task_config("probity_five_tier_" + name, size, epochs)
        pins, sources = launcher._sources(framework, task, completions)
        plan = launcher._plan(task, pins)
        common, _ = contract_plan(plan, sources, roles)
        launcher._write(folder / "native-plan.json", encode(asdict(plan)))
        launcher._write(folder / "common-plan-before-run.json", encode(common))
        native_path = launcher._execute(framework, task, plan, folder, completions)
        captured = launcher._now()
        native = native_path.read_bytes()
        spec = json.loads(native)["eval"]
        binding = InspectBinding(spec["run_id"], spec["eval_id"], digest(native))
        common, history, artifacts = adapt(
            native, plan, binding, sources=sources, captured_at=captured, roles=roles
        )
        common_bytes, history_bytes = encode(common), encode(history)
        require_plan = (folder / "common-plan-before-run.json").read_bytes()
        if common_bytes != require_plan:
            raise RuntimeError("Common declaration changed during native run")
        selected = {
            "expected_plan_sha256": digest(common_bytes),
            "expected_history_sha256": digest(history_bytes),
        }
        result = verify(
            native,
            plan,
            binding,
            sources=sources,
            captured_at=captured,
            plan_bytes=common_bytes,
            history_bytes=history_bytes,
            artifacts=artifacts,
            **selected,
        )
        for filename, raw in {
            **artifacts,
            "plan.json": common_bytes,
            "history.json": history_bytes,
            "consumer-pins.json": encode(selected),
            "native-binding.json": encode({**asdict(binding), "captured_at": captured}),
            "report.json": encode(result),
        }.items():
            launcher._write(folder / "packet" / filename, raw)
        receipts.append(result)
    receipt = {
        "inspectVersion": launcher.INSPECT_VERSION,
        "runtimeFiles": runtime,
        "model": "mockllm/model",
        "providerCalls": "none-mock-provider",
        "cases": receipts,
        "execution": "same-operator-native-mock-harness",
        "independentCustody": "not-established",
        "nativeOtherTiers": "not-exercised",
    }
    launcher._write(output / "receipt.json", encode(receipt))
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    print(json.dumps(run(parser.parse_args().output), indent=2))
