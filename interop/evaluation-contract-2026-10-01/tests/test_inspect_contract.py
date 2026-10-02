"""Exercise the native/common join and refusal of self-consistent fabrication."""

import copy
import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("probity_observer")

from evaluation_contract import ContractError, ROLES, digest, encode, validate
from inspect_contract import adapt, verify
from probity_observer.crypto import VerificationError
from probity_observer.inspect_history import InspectBinding

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location(
    "native_fixtures", ROOT / "tests/test_inspect_history.py"
)
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


def packet(log_mutation=None):
    plan, log, sources = fixtures._fixture()
    if log_mutation:
        log_mutation(log)
    raw = encode(log)
    binding = InspectBinding("native-run", "native-eval", digest(raw))
    roles = {role: None for role in ROLES}
    common, history, artifacts = adapt(
        raw, plan, binding, sources=sources, captured_at=fixtures.CAPTURED, roles=roles
    )
    return raw, plan, binding, sources, common, history, artifacts


def check(values):
    raw, plan, binding, sources, common, history, artifacts = values
    plan_raw, history_raw = encode(common), encode(history)
    return verify(
        raw,
        plan,
        binding,
        sources=sources,
        captured_at=fixtures.CAPTURED,
        plan_bytes=plan_raw,
        history_bytes=history_raw,
        artifacts=artifacts,
        expected_plan_sha256=digest(plan_raw),
        expected_history_sha256=digest(history_raw),
    )


def test_task_failure_is_complete_not_harness_failure():
    result = check(packet())
    assert (
        result["planned"],
        result["started"],
        result["complete"],
        result["task_failed"],
        result["failed"],
    ) == (2, 2, 2, 1, 0)


@pytest.mark.parametrize(
    "state,started,complete,unknown_start,incomplete,failed",
    [
        ("absent", 1, 1, 1, 0, 0),
        ("error", 2, 1, 0, 0, 1),
        ("incomplete", 2, 1, 0, 1, 0),
        ("unscored", 2, 2, 0, 0, 0),
    ],
)
def test_native_unsuccessful_and_missing_population(
    state, started, complete, unknown_start, incomplete, failed
):
    def mutate(log):
        log["status"] = "error"
        second = log["samples"][1]
        if state == "absent":
            log["samples"].pop()
        elif state == "error":
            second["error"] = {"message": "mock error"}
        elif state == "incomplete":
            second["completed_at"] = None
        else:
            second["scores"] = None

    values = packet(mutate)
    result = check(values)
    assert (
        result["planned"],
        result["started"],
        result["complete"],
        result["unknown_start"],
        result["incomplete"],
        result["failed"],
    ) == (2, started, complete, unknown_start, incomplete, failed)
    if state == "absent":
        record = values[5]["records"][1]
        assert record["harness_status"] == "start-unknown"
        assert "absent_from_native_log_execution_unknown" in record["capture"]["gaps"]
        assert result["missing"] == 0
    if state == "incomplete":
        assert "native_completion_absent" in values[5]["records"][1]["capture"]["gaps"]


def test_unsupported_axes_never_inherit_task_pass():
    values = packet()
    record = values[5]["records"][0]
    assert record["claims"]["task_outcome"]["status"] == "pass"
    assert all(
        claim["status"] == "not-exercised"
        for axis, claim in record["claims"].items()
        if axis != "task_outcome"
    )
    assert record["capture"]["observed_effect_count"] is None
    assert record["identity"]["consumer_decision_id"] is None


@pytest.mark.parametrize(
    "mutation,reason",
    [
        (
            lambda record: record["resources"].update(input_tokens=0),
            "unstarted_resources",
        ),
        (lambda record: record["capture"].update(gaps=[]), "unknown_start_without_gap"),
        (
            lambda record: record["claims"]["effect"].update(
                status="pass",
                reason_code="effect_applied",
                evidence=record["claims"]["task_outcome"]["evidence"]
                or [record["output"]],
            ),
            "unknown_start_effect_inference",
        ),
    ],
)
def test_unknown_start_cannot_acquire_execution_measurements(mutation, reason):
    from demo import fixture

    common, history, artifacts = fixture()
    record = history["records"][4]
    record["harness_status"] = "start-unknown"
    record["capture"]["gaps"].append("start_evidence_missing")
    mutation(record)
    raw = encode({key: value for key, value in record.items() if key != "output"})
    artifacts[record["output"]["name"]] = raw
    record["output"].update(sha256=digest(raw), size_bytes=len(raw))
    plan_raw, history_raw = encode(common), encode(history)
    with pytest.raises(ContractError, match=reason):
        validate(
            plan_raw,
            history_raw,
            artifacts,
            expected_plan_sha256=digest(plan_raw),
            expected_history_sha256=digest(history_raw),
        )


def test_rehashed_fabricated_score_fails_native_reconstruction():
    values = list(packet())
    record = values[5]["records"][1]
    record["claims"]["task_outcome"]["status"] = "pass"
    raw = encode({key: value for key, value in record.items() if key != "output"})
    values[6][record["output"]["name"]] = raw
    record["output"].update(sha256=digest(raw), size_bytes=len(raw))
    # It is common-contract consistent, but not native-derived.
    plan_raw, history_raw = encode(values[4]), encode(values[5])
    validate(
        plan_raw,
        history_raw,
        values[6],
        expected_plan_sha256=digest(plan_raw),
        expected_history_sha256=digest(history_raw),
    )
    with pytest.raises(ContractError, match="native_history_mapping_mismatch"):
        check(values)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda log: log["eval"]["config"].update(retry_on_error=1),
        lambda log: log["samples"][1].update(
            error_retries=[{"message": "first failure"}]
        ),
        lambda log: log["samples"].append(copy.deepcopy(log["samples"][0])),
    ],
)
def test_retries_and_duplicate_native_entries_are_refused(mutation):
    with pytest.raises(VerificationError):
        packet(mutation)


def test_changed_native_digest_is_refused():
    raw, plan, binding, sources, *_ = packet()
    with pytest.raises(VerificationError, match="digest"):
        adapt(
            raw + b" ",
            plan,
            binding,
            sources=sources,
            captured_at=fixtures.CAPTURED,
            roles={role: None for role in ROLES},
        )


@pytest.mark.parametrize(
    "raw", [b'{"status":"started","status":"success"}', b"{", b"[]"]
)
def test_malformed_and_ambiguous_native_logs_are_refused(raw):
    _, plan, _, sources, *_ = packet()
    binding = InspectBinding("native-run", "native-eval", digest(raw))
    with pytest.raises(VerificationError):
        adapt(
            raw,
            plan,
            binding,
            sources=sources,
            captured_at=fixtures.CAPTURED,
            roles={role: None for role in ROLES},
        )


def test_real_inspect_mock_log_integration(tmp_path):
    pytest.importorskip("inspect_ai")
    from inspect_demo import run

    receipt = run(tmp_path / "native")
    graded, error = receipt["cases"]
    assert (
        graded["planned"],
        graded["scored"],
        graded["task_passed"],
        graded["task_failed"],
    ) == (4, 4, 2, 2)
    assert (
        error["planned"],
        error["started"],
        error["failed"],
        error["unknown_start"],
    ) == (3, 3, 2, 0)
    assert error["missing"] == 0
    assert receipt["providerCalls"] == "none-mock-provider"
    assert list((tmp_path / "native/error/native").glob("*.json"))
