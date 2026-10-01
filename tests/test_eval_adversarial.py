"""Independent semantic-binding checks for the finite Inspect history profile.

The hand-built native-format fixture tests adapter contracts. It is not a
framework execution receipt or a real model evaluation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest

from probity_observer import evaluation_history as core
from probity_observer import inspect_history as adapter
from probity_observer.crypto import VerificationError
from probity_observer.evaluation_history import (
    AttemptSpec,
    RunPlan,
    SourcePin,
    artifact_ref,
    decode_record,
    encode_record,
    plan_digest,
)
from probity_observer.inspect_history import (
    INSPECT_VERSION,
    InspectBinding,
    adapt_inspect_log,
    verify_inspect_history,
)

CREATED = "2026-10-01T10:00:00Z"
STARTED = "2026-10-01T10:00:01.125000Z"
ENDED = "2026-10-01T10:00:02.875000Z"
CAPTURED = "2026-10-01T10:00:03Z"


@dataclass
class EvalRun:
    """Hold consumer-selected source pins separately from native-format data."""

    plan: RunPlan
    log: dict[str, Any]
    sources: dict[str, bytes]

    def verify(self, **kwargs: Any) -> dict[str, Any]:
        """Rebind exact test bytes and invoke native-derived record verification."""
        content = encode_record(self.log)
        binding = InspectBinding(
            "review-native-run",
            "review-native-eval",
            hashlib.sha256(content).hexdigest(),
        )
        return verify_inspect_history(
            content,
            self.plan,
            binding,
            sources=self.sources,
            captured_at=CAPTURED,
            **kwargs,
        )

    def repin_source(self, role: str, content: bytes) -> None:
        """Change selected source bytes without leaving a trivial digest mismatch."""
        selected = next(pin for pin in self.plan.sources if pin.role == role)
        self.sources[selected.artifact.name] = content
        replacement = replace(
            selected, artifact=artifact_ref(selected.artifact.name, content)
        )
        pins = tuple(
            replacement if pin.role == role else pin for pin in self.plan.sources
        )
        self.plan = replace(self.plan, sources=pins)
        self.log["eval"]["metadata"]["probity_plan_digest"] = plan_digest(self.plan)


def _sample(identity: str, outcome: str) -> dict[str, Any]:
    """Retain an explicit native-format input, target, output and score."""
    return {
        "id": identity,
        "epoch": 1,
        "input": "What is 2 + 2?",
        "target": "4",
        "started_at": STARTED,
        "completed_at": ENDED,
        "error": None,
        "error_retries": [],
        "invalidation": None,
        "limit": None,
        "output": {
            "model": "mockllm",
            "completion": "4" if outcome == "C" else "5",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "4" if outcome == "C" else "5",
                    },
                    "stop_reason": "stop",
                }
            ],
        },
        "scores": {"match": {"value": outcome}},
        "events": [{"event": "model", "model": "mockllm/model"}],
    }


@pytest.fixture
def run() -> EvalRun:
    """Construct the supported finite contract with actual local checker bytes."""
    identities = {
        "task": "review_contract",
        "model": "mockllm/model",
        "solver": "generate",
        "checker": "probity-inspect-history",
        "scorer": "match",
        "policy": "match-C-I",
        "harness": "inspect_ai",
    }
    sources = {
        f"{role}.json": encode_record({"selected_role": role, "identity": identity})
        for role, identity in identities.items()
    }
    sources["checker.json"] = encode_record(
        {
            "evaluation_history.py": Path(core.__file__).read_text("utf-8"),
            "inspect_history.py": Path(adapter.__file__).read_text("utf-8"),
        }
    )
    sources["policy.json"] = encode_record(
        {
            "identity": "match-C-I",
            "version": "v0",
            "C": "pass",
            "I": "fail",
            "missing_score": "not_scored",
            "execution_error": "not_scored",
            "missing_native_entry": "not_scored",
        }
    )
    task = {
        "name": "review_contract",
        "version": 1,
        "epochs": 1,
        "retry_on_error": 0,
        "max_samples": 1,
        "samples": [
            {"id": identity, "input": "What is 2 + 2?", "target": "4"}
            for identity in ("sample-1", "sample-2")
        ],
    }
    sources["task.json"] = encode_record(task)
    sources["model.json"] = encode_record(
        {
            "identity": "mockllm/model",
            "custom_outputs": ["4", "5"],
            "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
            "provider_source": ("selected unit-test provider bytes; not executed"),
        }
    )
    versions = {
        role: "v0"
        if role in {"checker", "policy"}
        else "1"
        if role == "task"
        else INSPECT_VERSION
        for role in identities
    }
    pins = tuple(
        SourcePin(
            role,
            identity,
            versions[role],
            artifact_ref(f"{role}.json", sources[f"{role}.json"]),
        )
        for role, identity in identities.items()
    )
    plan = RunPlan(
        "review-declared-run",
        CREATED,
        (
            AttemptSpec("attempt-1", "sample-1", 1),
            AttemptSpec("attempt-2", "sample-2", 1),
        ),
        pins,
    )
    log = {
        "version": 2,
        "status": "success",
        "eval": {
            "run_id": "review-native-run",
            "eval_id": "review-native-eval",
            "task": "review_contract",
            "task_version": 1,
            "model": "mockllm/model",
            "packages": {"inspect_ai": INSPECT_VERSION},
            "metadata": {
                "probity_run_id": plan.run_id,
                "probity_plan_digest": plan_digest(plan),
            },
            "scorers": [{"name": "match", "options": {}}],
            "config": {"epochs": 1, "retry_on_error": 0, "max_samples": 1},
            "dataset": {"samples": 2, "sample_ids": ["sample-1", "sample-2"]},
        },
        "plan": {
            "steps": [
                {
                    "solver": "generate",
                    "params": {"tool_calls": "loop"},
                    "params_passed": {},
                }
            ]
        },
        "samples": [_sample("sample-1", "C"), _sample("sample-2", "I")],
        "invalidated": False,
    }
    return EvalRun(plan, log, sources)


class TestIndependentEvaluationReview:
    """Retain every attempt while refusing unsupported source semantics."""

    class TestPassingCases:
        def test_pass_and_fail_remain_declared_and_not_model_performance(
            self, run: EvalRun
        ) -> None:
            result = run.verify()
            assert result["consistency"]["summary"]["pass"] == 1
            assert result["consistency"]["summary"]["fail"] == 1
            assert result["consistency"]["mode"] == "offline-contract"
            assert result["native"]["executionTruth"] == "not-established"

        def test_absent_error_run_entry_is_not_claimed_as_executed(
            self, run: EvalRun
        ) -> None:
            run.log["status"] = "error"
            run.log["samples"].pop()
            result = run.verify()
            assert result["consistency"]["summary"]["not_run"] == 1
            assert result["consistency"]["summary"]["not_scored"] == 1

    class TestFailingCases:
        def test_reversed_selected_decision_policy_is_refused(
            self, run: EvalRun
        ) -> None:
            policy = decode_record(run.sources["policy.json"])
            policy.update(C="fail", I="pass")
            run.repin_source("policy", encode_record(policy))
            with pytest.raises(VerificationError):
                run.verify()

        @pytest.mark.parametrize(
            "field,value", [("input", "Different task"), ("target", "99")]
        )
        def test_selected_task_matches_native_sample_input_and_target(
            self, run: EvalRun, field: str, value: str
        ) -> None:
            task = decode_record(run.sources["task.json"])
            task["samples"][0][field] = value
            run.repin_source("task", encode_record(task))
            with pytest.raises(VerificationError):
                run.verify()

        def test_selected_checker_bytes_match_actual_replay_implementation(
            self, run: EvalRun
        ) -> None:
            run.repin_source(
                "checker", encode_record({"inspection": "unrelated implementation"})
            )
            with pytest.raises(VerificationError):
                run.verify()

        def test_omitted_successful_native_sample_refuses(self, run: EvalRun) -> None:
            run.log["samples"].pop()
            with pytest.raises(VerificationError, match="omits declared samples"):
                run.verify()

        def test_sample_retries_cannot_disappear_inside_one_attempt(
            self, run: EvalRun
        ) -> None:
            run.log["samples"][0]["error_retries"] = [{"error": "earlier attempt"}]
            with pytest.raises(VerificationError, match="retries"):
                run.verify()

        def test_mock_execution_cannot_be_relabelled_model_evaluation(
            self, run: EvalRun
        ) -> None:
            run.plan = replace(run.plan, mode="model-evaluation")
            run.log["eval"]["metadata"]["probity_plan_digest"] = plan_digest(run.plan)
            with pytest.raises(VerificationError, match="offline-contract"):
                run.verify()

        def test_self_consistent_edited_native_derived_outcome_refuses(
            self, run: EvalRun
        ) -> None:
            content = encode_record(run.log)
            binding = InspectBinding(
                "review-native-run",
                "review-native-eval",
                hashlib.sha256(content).hexdigest(),
            )
            history = adapt_inspect_log(content, run.plan, binding)
            records = list(history.records)
            artifacts = dict(history.artifacts)
            old = records[1]
            envelope = decode_record(artifacts[old.output.name])
            envelope["outcome"] = "pass"
            replacement_bytes = encode_record(envelope)
            artifacts[old.output.name] = replacement_bytes
            records[1] = replace(
                old,
                outcome="pass",
                output=artifact_ref(old.output.name, replacement_bytes),
            )
            with pytest.raises(VerificationError, match="differ from the native log"):
                run.verify(records=records, artifacts=artifacts)

        def test_deep_retained_json_refuses_with_shared_error(self) -> None:
            raw = b"[" * 1200 + b"0" + b"]" * 1200
            with pytest.raises(VerificationError):
                decode_record(raw)
