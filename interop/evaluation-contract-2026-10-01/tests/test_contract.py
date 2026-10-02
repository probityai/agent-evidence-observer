"""Probe population loss, retry ambiguity and false measurement admission."""

from __future__ import annotations

import copy
import logging

import pytest
from demo import fixture, ref
from evaluation_contract import ContractError, decode, digest, encode, validate
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st


def check(plan, history, artifacts):
    """Select pins outside the packet, then check its full declared population."""
    p, h = encode(plan), encode(history)
    return validate(
        p,
        h,
        artifacts,
        expected_plan_sha256=digest(p),
        expected_history_sha256=digest(h),
    )


def rebind(record, artifacts):
    """Rebuild a normalized output for semantic controls, not byte-tamper probes."""
    name = record["output"]["name"]
    artifacts[name] = encode({k: v for k, v in record.items() if k != "output"})
    record["output"] = ref(name, artifacts[name])


def false_absence(record):
    """Invent an absence verdict over explicitly incomplete observations."""
    record["capture"]["observed_effect_count"] = 0
    record["claims"]["effect"] = {
        **record["claims"]["task_outcome"],
        "reason_code": "no_effect_in_scope",
    }


def mutate_history(mutation, history, artifacts):
    """Apply one independent hostile change, preserving the frozen declaration."""
    record = history["records"][0]
    actions = {
        "omit": lambda: history["records"].pop(),
        "duplicate": lambda: history["records"].append(copy.deepcopy(record)),
        "hidden-start": lambda: history["start_ledger"].append("attempt-0"),
        "extra-start": lambda: history["start_ledger"].append("unreported-retry"),
        "cross-run": lambda: record.update(run_id="other-run"),
        "identity": lambda: record["identity"].update(
            runtime_target_id="other-runtime"
        ),
        "score-error": lambda: history["records"][2]["claims"].update(
            task_outcome=copy.deepcopy(record["claims"]["task_outcome"])
        ),
        "zero-effect": lambda: false_absence(record),
        "bool-resource": lambda: record["resources"].update(elapsed_ns=True),
        "output": lambda: artifacts.update({record["output"]["name"]: b"altered"}),
        "raw-result": lambda: record["claims"]["task_outcome"].update(
            native_reason="changed"
        ),
        "decisive-no-evidence": lambda: record["claims"]["task_outcome"].update(
            evidence=[]
        ),
    }
    actions[mutation]()


class TestEvaluationContract:
    class TestPassingCases:
        def test_denominators_retain_failures_missing_and_retry(self):
            result = check(*fixture())
            assert {
                k: result[k]
                for k in (
                    "planned",
                    "started",
                    "complete",
                    "scored",
                    "failed",
                    "missing",
                    "incomplete",
                )
            } == {
                "planned": 7,
                "started": 6,
                "complete": 4,
                "scored": 4,
                "failed": 1,
                "missing": 1,
                "incomplete": 1,
            }
            assert result["mode"] == "synthetic-contract"

        @pytest.mark.parametrize(
            "status", ["error", "timeout", "interrupted", "incomplete"]
        )
        def test_unsuccessful_attempt_remains_unscored(self, status):
            plan, history, artifacts = fixture()
            history["records"][2]["harness_status"] = status
            rebind(history["records"][2], artifacts)
            result = check(plan, history, artifacts)
            assert result["scored"] == 4
            assert result["harness_counts"][status] >= 1

        @given(st.integers(min_value=0, max_value=2**63))
        def test_nonnegative_resource_measurement(self, elapsed):
            plan, history, artifacts = fixture()
            record = history["records"][0]
            record["resources"]["elapsed_ns"] = elapsed
            rebind(record, artifacts)
            assert check(plan, history, artifacts)["planned"] == 7

        def test_unknown_effect_count_preserved(self):
            plan, history, artifacts = fixture()
            assert all(
                r["capture"]["observed_effect_count"] is None
                for r in history["records"]
            )
            assert check(plan, history, artifacts)["started"] == 6

    class TestFailingCases:
        @pytest.mark.parametrize(
            "mutation, reason",
            [
                ("omit", "omitted_attempt"),
                ("duplicate", "duplicate_record"),
                ("hidden-start", "reused_attempt_start"),
                ("extra-start", "start_ledger_mismatch"),
                ("cross-run", "cross_run_record"),
                ("identity", "attempt_identity_changed"),
                ("score-error", "unsuccessful_attempt_scored"),
                ("zero-effect", "absence_without_coverage"),
                ("bool-resource", "resource_value"),
                ("output", "pin_mismatch"),
                ("raw-result", "output_binding_mismatch"),
                ("decisive-no-evidence", "decisive_claim_without_evidence"),
            ],
        )
        def test_hostile_history(self, mutation, reason, caplog):
            plan, history, artifacts = fixture()
            plan = copy.deepcopy(plan)
            mutate_history(mutation, history, artifacts)
            with (
                caplog.at_level(logging.WARNING),
                pytest.raises(ContractError, match=f"^{reason}$"),
            ):
                check(plan, history, artifacts)
            assert f"evaluation contract refused: {reason}" in caplog.text

        @pytest.mark.parametrize(
            "mutation, reason",
            [
                ("parent-missing", "unknown_or_forward_parent"),
                ("hidden", "hidden_retry"),
                ("scope", "retry_scope_changed"),
                ("duplicate", "duplicate_attempt"),
            ],
        )
        def test_invalid_retry_declaration(self, mutation, reason, caplog):
            plan, history, artifacts = fixture()
            child = plan["attempts"][3]
            if mutation == "parent-missing":
                child["parent_attempt_id"] = "later-attempt"
            elif mutation == "hidden":
                child["parent_attempt_id"] = None
            elif mutation == "scope":
                child["identity"]["runtime_target_id"] = "other-runtime"
            else:
                child["identity"]["attempt_id"] = "attempt-2"
            history["plan_sha256"] = digest(encode(plan))
            with (
                caplog.at_level(logging.WARNING),
                pytest.raises(ContractError, match=f"^{reason}$"),
            ):
                check(plan, history, artifacts)
            assert reason in caplog.text

        @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
        @given(suffix=st.binary(min_size=1, max_size=128))
        def test_arbitrary_artifact_substitution(self, suffix, caplog):
            plan, history, artifacts = fixture()
            artifacts["attempt-0.json"] += suffix
            caplog.clear()
            with (
                caplog.at_level(logging.WARNING),
                pytest.raises(ContractError, match="^pin_mismatch$"),
            ):
                check(plan, history, artifacts)
            assert "pin_mismatch" in caplog.text

        @pytest.mark.parametrize(
            "raw, reason",
            [
                (b'{"a":1,"a":2}', "duplicate_json_member"),
                (b'{"a":NaN}', "nonfinite_json"),
                (b'{"a":1e999}', "nonfinite_json"),
                ('{"a":1}'.encode("utf-16"), "malformed_json"),
                (b"{", "malformed_json"),
                (b"[" * 70 + b"0" + b"]" * 70, "json_structure_limit"),
            ],
        )
        def test_ambiguous_json(self, raw, reason, caplog):
            with (
                caplog.at_level(logging.WARNING),
                pytest.raises(ContractError, match=f"^{reason}$"),
            ):
                decode(raw)
            assert reason in caplog.text

        def test_external_pins_prevent_total_replacement(self, caplog):
            plan, history, artifacts = fixture()
            p, h = encode(plan), encode(history)
            with (
                caplog.at_level(logging.WARNING),
                pytest.raises(ContractError, match="^pin_mismatch$"),
            ):
                validate(
                    p + b" ",
                    h,
                    artifacts,
                    expected_plan_sha256=digest(p),
                    expected_history_sha256=digest(h),
                )
            assert "pin_mismatch" in caplog.text


class TestStartLedger:
    class TestPassingCases:
        def test_zero_observed_does_not_establish_absence(self):
            plan, history, artifacts = fixture()
            record = history["records"][0]
            record["capture"]["observed_effect_count"] = 0
            rebind(record, artifacts)
            assert record["claims"]["effect"]["status"] == "unknown"
            assert check(plan, history, artifacts)["started"] == 6

    class TestFailingCases:
        @pytest.mark.parametrize(
            "mutation,reason",
            [
                ("order", "retry_started_before_parent"),
                ("resource", "unstarted_resources"),
                ("effect", "unstarted_effect"),
            ],
        )
        def test_start_constraints(self, mutation, reason, caplog):
            plan, history, artifacts = fixture()
            if mutation == "order":
                history["records"][2], history["records"][3] = (
                    history["records"][3],
                    history["records"][2],
                )
                history["start_ledger"][2], history["start_ledger"][3] = (
                    history["start_ledger"][3],
                    history["start_ledger"][2],
                )
            else:
                record = history["records"][4]
                if mutation == "resource":
                    record["resources"]["elapsed_ns"] = 1
                else:
                    record["capture"]["observed_effect_count"] = 0
                rebind(record, artifacts)
            with (
                caplog.at_level(logging.WARNING),
                pytest.raises(ContractError, match=f"^{reason}$"),
            ):
                check(plan, history, artifacts)
            assert reason in caplog.text
