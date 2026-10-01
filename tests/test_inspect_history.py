"""Check pinned Inspect log adaptation and native-derived evidence binding."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

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
    POLICY_BYTES,
    InspectBinding,
    adapt_inspect_log,
    verify_inspect_history,
)

CREATED = "2026-10-01T10:00:00Z"
STARTED = "2026-10-01T10:00:01.125000Z"
ENDED = "2026-10-01T10:00:02.875000Z"
CAPTURED = "2026-10-01T10:00:03Z"


def _fixture():
    """Build the supported native schema with explicit versions and identities."""
    identities = {
        "task": "test_task",
        "model": "mockllm/model",
        "solver": "generate",
        "checker": "probity-inspect-history",
        "scorer": "match",
        "policy": "match-C-I",
        "harness": "inspect_ai",
    }
    sources = {
        f"{role}.json": encode_record({"role": role, "identity": identity})
        for role, identity in identities.items()
    }
    sources.update(_profile_sources())
    pins = tuple(
        SourcePin(
            role,
            identity,
            "1"
            if role == "task"
            else "v0"
            if role in {"checker", "policy"}
            else INSPECT_VERSION,
            artifact_ref(f"{role}.json", sources[f"{role}.json"]),
        )
        for role, identity in identities.items()
    )
    plan = RunPlan(
        "declared-run",
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
            "run_id": "native-run",
            "eval_id": "native-eval",
            "task": "test_task",
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
    return plan, log, sources


def _profile_sources():
    """Pin actual checker files and concrete task, model, and policy contracts."""
    import probity_observer.evaluation_history as checker
    import probity_observer.inspect_history as adapter

    task = {
        "name": "test_task",
        "version": 1,
        "epochs": 1,
        "retry_on_error": 0,
        "max_samples": 1,
        "samples": [
            {"id": f"sample-{index}", "input": "2+2?", "target": "4"}
            for index in (1, 2)
        ],
    }
    bundle = {
        "evaluation_history.py": Path(checker.__file__).read_text("utf-8"),
        "inspect_history.py": Path(adapter.__file__).read_text("utf-8"),
    }
    model = {
        "identity": "mockllm/model",
        "custom_outputs": ["4", "wrong"],
        "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
        "provider_source": "retained-mock-provider-fixture-not-executed",
    }
    return {
        "task.json": encode_record(task),
        "model.json": encode_record(model),
        "checker.json": encode_record(bundle),
        "policy.json": POLICY_BYTES,
    }


def _sample(identity, score):
    """Represent the retained fields needed by this finite log profile."""
    return {
        "id": identity,
        "epoch": 1,
        "started_at": STARTED,
        "completed_at": ENDED,
        "error": None,
        "error_retries": [],
        "invalidation": None,
        "limit": None,
        "output": {
            "model": "mockllm",
            "completion": "4" if score == "C" else "wrong",
            "choices": [{"message": {"content": "4" if score == "C" else "wrong"}}],
        },
        "input": "2+2?",
        "target": "4",
        "scores": {"match": {"value": score}},
        "events": [{"event": "model", "model": "mockllm/model"}],
    }


def _binding(content):
    """Select the exact native bytes rather than trusting identity fields alone."""
    return InspectBinding(
        "native-run", "native-eval", hashlib.sha256(content).hexdigest()
    )


def _verify(fixture, **overrides):
    """Verify the exact selected native bytes and all retained source roles."""
    plan, log, sources = fixture
    content = encode_record(log)
    arguments = {"sources": sources, "captured_at": CAPTURED}
    arguments.update(overrides)
    return verify_inspect_history(content, plan, _binding(content), **arguments)


def _set(log, path, value):
    """Apply one bounded test mutation without interpreting a filesystem path."""
    target = log
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


class TestNativeAdaptation:
    class TestPassingCases:
        def test_native_pass_and_fail_are_both_retained(self):
            result = _verify(_fixture())
            assert result["consistency"]["summary"]["attempts"] == 2
            assert result["consistency"]["summary"]["pass"] == 1
            assert result["consistency"]["summary"]["fail"] == 1
            assert result["native"]["inspectVersion"] == INSPECT_VERSION
            assert (
                result["native"]["observedActionScope"]
                == "retained-native-transcript-only"
            )
            assert result["native"]["executionTruth"] == "not-established"

        def test_order_is_declared_not_native_completion_order(self):
            plan, log, sources = _fixture()
            log["samples"].reverse()
            result = _verify((plan, log, sources))
            assert result["consistency"]["summary"]["completed"] == 2

        def test_native_score_mapping_does_not_rescore_completion(self):
            plan, log, sources = _fixture()
            log["samples"][1]["scores"]["match"]["value"] = "C"
            result = _verify((plan, log, sources))
            assert result["consistency"]["summary"]["pass"] == 2
            assert result["consistency"]["summary"]["fail"] == 0
            assert result["native"]["scoreAuthority"] == (
                "selected-native-score-records-not-independent-rescoring"
            )

        @pytest.mark.parametrize("native_status", ["started", "error", "cancelled"])
        def test_missing_entry_is_explicit_and_unscored(self, native_status):
            plan, log, sources = _fixture()
            log["status"] = native_status
            log["samples"] = log["samples"][:1]
            content = encode_record(log)
            history = adapt_inspect_log(content, plan, _binding(content))
            assert history.records[1].status == "not_run"
            assert history.records[1].error_code == "absent-from-native-log"
            assert history.records[1].started_at is None
            assert (
                _verify((plan, log, sources))["consistency"]["summary"]["not_run"] == 1
            )

        def test_no_samples_in_interrupted_log_are_not_executed(self):
            plan, log, sources = _fixture()
            log["status"] = "cancelled"
            log["samples"] = None
            assert (
                _verify((plan, log, sources))["consistency"]["summary"]["not_run"] == 2
            )

        def test_native_sample_error_is_not_a_wrong_answer(self):
            plan, log, sources = _fixture()
            log["status"] = "error"
            log["samples"][0]["error"] = {"message": "local controlled failure"}
            result = _verify((plan, log, sources))
            assert result["consistency"]["summary"]["error"] == 1
            assert result["consistency"]["summary"]["not_scored"] == 1

        def test_interrupted_sample_keeps_start_without_inventing_end(self):
            plan, log, sources = _fixture()
            log["status"] = "cancelled"
            log["samples"][0]["completed_at"] = None
            content = encode_record(log)
            history = adapt_inspect_log(content, plan, _binding(content))
            assert history.records[0].status == "interrupted"
            assert history.records[0].started_at == STARTED
            assert history.records[0].ended_at is None
            assert (
                _verify((plan, log, sources))["consistency"]["summary"]["interrupted"]
                == 1
            )

        @pytest.mark.parametrize("score", [None, {}])
        def test_completed_unscored_sample_remains_in_population(self, score):
            plan, log, sources = _fixture()
            log["samples"][0]["scores"] = score
            result = _verify((plan, log, sources))
            assert result["consistency"]["summary"]["completed"] == 2
            assert result["consistency"]["summary"]["not_scored"] == 1

        def test_supplied_native_derived_evidence_matches(self):
            plan, log, _ = fixture = _fixture()
            content = encode_record(log)
            history = adapt_inspect_log(content, plan, _binding(content))
            assert (
                _verify(fixture, records=history.records, artifacts=history.artifacts)[
                    "consistency"
                ]["status"]
                == "records-consistent"
            )

    class TestFailingCases:
        @pytest.mark.parametrize(
            "path,value",
            [
                (("version",), 1),
                (("version",), True),
                (("status",), "unknown"),
                (("eval", "run_id"), "other"),
                (("eval", "eval_id"), "other"),
                (("eval", "task"), "other"),
                (("eval", "task_version"), 2),
                (("eval", "model"), "other"),
                (("eval", "packages", "inspect_ai"), "0.3.272"),
                (("eval", "metadata", "probity_run_id"), "old-run"),
                (("eval", "metadata", "probity_plan_digest"), "0" * 64),
                (("eval", "scorers", 0, "name"), "other"),
                (("eval", "scorers", 0, "options"), {"location": "begin"}),
                (("plan", "steps", 0, "solver"), "other"),
                (("plan", "steps", 0, "params"), {"tool_calls": "none"}),
                (("plan", "steps", 0, "params_passed"), {"tool_calls": "loop"}),
                (("eval", "config", "retry_on_error"), 1),
                (("eval", "config", "retry_on_error"), False),
                (("eval", "config", "epochs"), True),
                (("eval", "dataset", "samples"), True),
                (("invalidated",), True),
                (("samples", 0, "id"), "unexpected"),
                (("samples", 0, "epoch"), True),
                (("samples", 0, "error_retries"), [{"message": "retry"}]),
                (("samples", 0, "limit"), {"type": "time"}),
                (("samples", 0, "invalidation"), {"reason": "changed"}),
                (("samples", 0, "started_at"), None),
                (("samples", 0, "scores", "match", "value"), 1.0),
                (("samples", 0, "scores", "match", "value"), []),
                (("samples", 0, "scores"), {"other": {"value": "C"}}),
            ],
        )
        def test_native_semantic_mutations_even_with_updated_hash(self, path, value):
            plan, log, sources = _fixture()
            _set(log, path, value)
            with pytest.raises(VerificationError):
                _verify((plan, log, sources))

        @pytest.mark.parametrize("key", ["config_updates", "log_updates"])
        def test_log_rewrites_are_not_silently_accepted(self, key):
            plan, log, sources = _fixture()
            log[key] = [{"change": "scorer"}]
            with pytest.raises(VerificationError, match="rewrites"):
                _verify((plan, log, sources))

        @pytest.mark.parametrize("status", [[], {}, False, None, 1])
        def test_malformed_status_is_a_bounded_refusal(self, status):
            plan, log, sources = _fixture()
            log["status"] = status
            with pytest.raises(VerificationError, match="native run status"):
                _verify((plan, log, sources))

        @pytest.mark.parametrize("retries", [False, 0, "", {}, "retry"])
        def test_malformed_retry_population_is_refused(self, retries):
            plan, log, sources = _fixture()
            log["samples"][0]["error_retries"] = retries
            with pytest.raises(VerificationError, match="retries must"):
                _verify((plan, log, sources))

        def test_unrepresented_finish_solver_is_refused(self):
            plan, log, sources = _fixture()
            log["plan"]["finish"] = {"solver": "generate"}
            with pytest.raises(VerificationError, match="finish solver"):
                _verify((plan, log, sources))

        @pytest.mark.parametrize(
            "mutation",
            [
                "missing-success",
                "duplicate-entry",
                "duplicate-dataset",
                "changed-dataset",
                "missing-size",
                "integer-id",
            ],
        )
        def test_exact_native_population(self, mutation):
            plan, log, sources = _fixture()
            callbacks = {
                "missing-success": lambda: log["samples"].pop(),
                "duplicate-entry": lambda: log["samples"].append(
                    copy.deepcopy(log["samples"][0])
                ),
                "duplicate-dataset": lambda: _set(
                    log, ("eval", "dataset", "sample_ids"), ["sample-1", "sample-1"]
                ),
                "changed-dataset": lambda: _set(
                    log, ("eval", "dataset", "sample_ids"), ["sample-1", "other"]
                ),
                "missing-size": lambda: _set(log, ("eval", "dataset", "samples"), 1),
                "integer-id": lambda: _set(
                    log, ("eval", "dataset", "sample_ids"), [1, 2]
                ),
            }
            callbacks[mutation]()
            with pytest.raises(VerificationError):
                _verify((plan, log, sources))

        @pytest.mark.parametrize(
            "role",
            ["task", "model", "solver", "checker", "scorer", "policy", "harness"],
        )
        @pytest.mark.parametrize("field", ["identity", "version"])
        def test_source_identity_or_version_changes(self, role, field):
            plan, log, sources = _fixture()
            changed = tuple(
                replace(pin, **{field: "changed"}) if pin.role == role else pin
                for pin in plan.sources
            )
            plan = replace(plan, sources=changed)
            log["eval"]["metadata"]["probity_plan_digest"] = plan_digest(plan)
            with pytest.raises(VerificationError):
                _verify((plan, log, sources))

        def test_mock_output_cannot_be_labelled_model_evaluation(self):
            plan, log, sources = _fixture()
            plan = replace(plan, mode="model-evaluation")
            log["eval"]["metadata"]["probity_plan_digest"] = plan_digest(plan)
            with pytest.raises(VerificationError, match="offline-contract"):
                _verify((plan, log, sources))

        def test_replacement_native_bytes_fail_original_digest_binding(self):
            plan, log, _ = _fixture()
            original = encode_record(log)
            binding = _binding(original)
            log["samples"][0]["output"]["completion"] = "replaced"
            with pytest.raises(VerificationError, match="native log digest"):
                adapt_inspect_log(encode_record(log), plan, binding)

        @pytest.mark.parametrize(
            "role,mutation",
            [
                ("policy", "reverse-policy"),
                ("checker", "changed-checker"),
                ("task", "changed-input"),
                ("task", "changed-target"),
                ("task", "extra-field"),
                ("model", "changed-outputs"),
                ("model", "missing-provider"),
                ("model", "boolean-usage"),
            ],
        )
        def test_rebound_source_pins_still_require_profile_semantics(
            self, role, mutation
        ):
            plan, log, sources = _fixture()
            name = f"{role}.json"
            value = decode_record(sources[name])
            callbacks = {
                "reverse-policy": lambda: value.update({"C": "fail", "I": "pass"}),
                "changed-checker": lambda: value.update(
                    {"inspect_history.py": "different checker"}
                ),
                "changed-input": lambda: _set(
                    value, ("samples", 0, "input"), "different input"
                ),
                "changed-target": lambda: _set(
                    value, ("samples", 0, "target"), "different target"
                ),
                "extra-field": lambda: value.update({"another-solver": "hidden"}),
                "changed-outputs": lambda: value.update(
                    {"custom_outputs": ["other", "wrong"]}
                ),
                "missing-provider": lambda: value.update({"provider_source": ""}),
                "boolean-usage": lambda: _set(value, ("usage", "input_tokens"), False),
            }
            callbacks[mutation]()
            sources[name] = encode_record(value)
            pins = tuple(
                replace(pin, artifact=artifact_ref(name, sources[name]))
                if pin.role == role
                else pin
                for pin in plan.sources
            )
            plan = replace(plan, sources=pins)
            log["eval"]["metadata"]["probity_plan_digest"] = plan_digest(plan)
            with pytest.raises(VerificationError):
                _verify((plan, log, sources))

        @pytest.mark.parametrize("field", ["input", "target"])
        def test_changed_native_input_or_target_is_refused(self, field):
            plan, log, sources = _fixture()
            log["samples"][0][field] = "changed"
            with pytest.raises(VerificationError, match="input or target"):
                _verify((plan, log, sources))

        def test_selective_summary_is_refused(self):
            with pytest.raises(VerificationError, match="reported summary"):
                _verify(_fixture(), claimed_summary={"attempts": 1, "pass": 1})

        @pytest.mark.parametrize(
            "population",
            ["records-only", "artifacts-only", "changed-record", "changed-artifact"],
        )
        def test_supplied_evidence_must_be_native_derived(self, population):
            plan, log, _ = fixture = _fixture()
            content = encode_record(log)
            history = adapt_inspect_log(content, plan, _binding(content))
            arguments = {
                "records": history.records,
                "artifacts": dict(history.artifacts),
            }
            if population == "records-only":
                arguments.pop("artifacts")
            elif population == "artifacts-only":
                arguments.pop("records")
            elif population == "changed-record":
                arguments["records"] = (
                    replace(history.records[0], outcome="fail"),
                ) + history.records[1:]
            else:
                name = next(iter(arguments["artifacts"]))
                envelope = decode_record(arguments["artifacts"][name])
                envelope["native_sample"]["output"]["completion"] = "replaced"
                arguments["artifacts"][name] = encode_record(envelope)
            with pytest.raises(
                VerificationError, match="native-derived|differ from the native"
            ):
                _verify(fixture, **arguments)

        @pytest.mark.parametrize(
            "value",
            ["", "space id", "line\n", "nonascii-\u00e9", "x" * 257, True, None],
        )
        @pytest.mark.parametrize("field", ["run_id", "eval_id"])
        def test_binding_identity_fields(self, value, field):
            arguments = {"run_id": "run", "eval_id": "eval", "log_sha256": "0" * 64}
            arguments[field] = value
            with pytest.raises(VerificationError, match="binding identities"):
                InspectBinding(**arguments)

        def test_native_refusal_log_is_bounded(self, caplog):
            plan, log, _ = _fixture()
            content = encode_record(log)
            with pytest.raises(VerificationError):
                adapt_inspect_log(
                    content, plan, replace(_binding(content), log_sha256="0" * 64)
                )
            assert [record.message for record in caplog.records] == [
                "Inspect history refused: native log digest differs from the "
                "selected binding"
            ]
