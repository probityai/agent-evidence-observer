"""Attack signed candidate pin choice and the covered selected-run transcript."""

from dataclasses import replace

import pytest

from probity_observer.crypto import SigningKey, VerificationError
from probity_observer.evaluation_history import (
    REQUIRED_ROLES,
    AttemptRecord,
    AttemptSpec,
    RunPlan,
    SourcePin,
    artifact_ref,
    encode_record,
    verify_history,
)
from probity_observer.history import Witness, append_history, read_history
from probity_observer.run_selection import (
    close_selected_run,
    execution_digest,
    open_run_selection,
    selection_pins,
    start_selected_run,
    verify_selected_history,
)

CONFIG = b'{"threshold":1}'
CONTROLS = b'{"control":"negative-control-v1"}'
END = "2026-10-04T10:00:03Z"


def fixture():
    """One complete bounded attempt; all seven original sources are retained."""
    sources = {
        f"{role}.json": encode_record({"role": role}) for role in sorted(REQUIRED_ROLES)
    }
    pins = tuple(
        SourcePin(
            role, role, "v1", artifact_ref(f"{role}.json", sources[f"{role}.json"])
        )
        for role in sorted(REQUIRED_ROLES)
    )
    plan = RunPlan(
        "selected-run", "2026-10-04T10:00:00Z", (AttemptSpec("a1", "s1", 1),), pins
    )
    raw = encode_record(
        {
            "run_id": plan.run_id,
            "attempt_id": "a1",
            "status": "completed",
            "outcome": "pass",
            "content": "1",
        }
    )
    records = (
        AttemptRecord(
            plan.run_id,
            "a1",
            1,
            "completed",
            "pass",
            "2026-10-04T10:00:01Z",
            "2026-10-04T10:00:02Z",
            None,
            artifact_ref("output.json", raw),
        ),
    )
    return plan, records, {"output.json": raw}, sources


def producer(tmp_path):
    plan, records, artifacts, sources = fixture()
    history = tmp_path / "history.jsonl"
    witness = Witness(tmp_path / "witness.json", SigningKey.generate())
    opening = open_run_selection(
        history, witness, plan, CONFIG, CONTROLS, operator_id="fixture-author"
    )
    start_selected_run(
        history, witness, plan, CONFIG, CONTROLS, opening, operator_id="fixture-author"
    )
    value, _ = execution_digest(
        plan, records, artifacts=artifacts, sources=sources, ended_at=END
    )
    final = close_selected_run(history, witness, plan, value)
    return history, witness, plan, records, artifacts, sources, opening, final


def verify(state, **overrides):
    history, witness, plan, records, artifacts, sources, opening, final = state
    args = {
        "configuration": CONFIG,
        "controls": CONTROLS,
        "artifacts": artifacts,
        "sources": sources,
        "ended_at": END,
        "opening_checkpoint": opening,
        "final_checkpoint": final,
        "pinned_witness_key": witness.public_hex,
        "expected_operator_id": "fixture-author",
    }
    args.update(overrides)
    return verify_selected_history(history, plan, records, **args)


def rewrite(state, transform):
    """Re-sign hostile history with the original key but retain its opening pin."""
    history, witness, *_ = state
    events = [entry["event"] for entry in read_history(history)]
    changed = transform(events)
    history.unlink()
    for event in changed:
        append_history(history, event)
    signer = Witness(history.parent / "fork-witness.json", witness.signing_key)
    return (*state[:-1], signer.checkpoint(history))


def test_selected_transcript_reuses_reader_and_preserves_limits(tmp_path):
    result = verify(producer(tmp_path))
    assert result["status"] == "selected-history-consistent"
    assert result["historyCoverage"]["lastSequence"] == 3
    assert result["execution"]["summary"]["completed"] == 1
    assert result["declaredOperator"] == "fixture-author"
    for field in ("realTimePrecedence", "globalUniqueSelection", "independentCustody"):
        assert result[field] == "not-established"


def test_timestamped_candidates_can_pass_existing_reader_then_choose_winner(tmp_path):
    state = producer(tmp_path)
    _history, _witness, plan, records, artifacts, sources, *_ = state
    alternate_sources = {**sources, "checker.json": b"candidate-checker-2"}
    alternate = replace(
        plan,
        sources=tuple(
            replace(
                pin,
                version="v2",
                artifact=artifact_ref(
                    "checker.json", alternate_sources["checker.json"]
                ),
            )
            if pin.role == "checker"
            else pin
            for pin in plan.sources
        ),
    )
    # Both candidate declarations precede the recorded result timestamp. Either
    # candidate's supplied records pass the existing consistency-only checker.
    for candidate, retained in [(plan, sources), (alternate, alternate_sources)]:
        assert (
            verify_history(
                candidate, records, artifacts=artifacts, sources=retained, ended_at=END
            )["status"]
            == "records-consistent"
        )
    evil = rewrite(
        state,
        lambda events: [
            events[0],
            {**events[0], "pins": selection_pins(alternate, CONFIG, CONTROLS)},
            *events[1:],
        ],
    )
    with pytest.raises(VerificationError, match="exactly one selection"):
        verify(evil)


@pytest.mark.parametrize(
    "field,value",
    [
        ("configuration", b"changed"),
        ("controls", b"changed"),
        ("expected_operator_id", "another-operator"),
    ],
)
def test_original_pin_substitution_refused(tmp_path, field, value):
    with pytest.raises(VerificationError, match="selected plan"):
        verify(producer(tmp_path), **{field: value})


def test_checker_source_substitution_refused_against_consumer_opening(tmp_path):
    state = producer(tmp_path)
    history, witness, plan, records, artifacts, sources, opening, final = state
    changed_sources = {**sources, "checker.json": b"another-checker"}
    changed_plan = replace(
        plan,
        sources=tuple(
            replace(
                pin,
                artifact=artifact_ref("checker.json", changed_sources["checker.json"]),
            )
            if pin.role == "checker"
            else pin
            for pin in plan.sources
        ),
    )
    with pytest.raises(VerificationError, match="selected plan"):
        verify(
            (
                history,
                witness,
                changed_plan,
                records,
                artifacts,
                changed_sources,
                opening,
                final,
            )
        )


@pytest.mark.parametrize(
    "transform",
    [
        lambda e: [e[1], e[0], e[2]],
        lambda e: [e[0], e[1], e[0], e[2]],
        lambda e: [e[0], e[1], e[2], e[2]],
        lambda e: [e[0], {**e[1], "kind": "future-start"}, e[2]],
        lambda e: [e[0], {**e[1], "profile": "future-profile"}, e[2]],
    ],
)
def test_late_duplicate_and_unsupported_run_events_refused(tmp_path, transform):
    with pytest.raises(VerificationError):
        verify(rewrite(producer(tmp_path), transform))


@pytest.mark.parametrize("field", ["opening_checkpoint", "final_checkpoint"])
def test_missing_consumer_anchor_refused(tmp_path, field):
    with pytest.raises(VerificationError, match="checkpoint is missing"):
        verify(producer(tmp_path), **{field: None})


def test_missing_history_refused(tmp_path):
    state = producer(tmp_path)
    state[0].unlink()
    with pytest.raises(VerificationError, match="outside supplied history"):
        verify(state)


def test_history_suffix_omission_refused(tmp_path):
    state = producer(tmp_path)
    lines = state[0].read_bytes().splitlines(keepends=True)
    state[0].write_bytes(b"".join(lines[:-1]))
    with pytest.raises(VerificationError, match="outside supplied history"):
        verify(state)


def test_fork_with_same_signing_key_refused_by_retained_opening(tmp_path):
    state = rewrite(
        producer(tmp_path), lambda e: [{**e[0], "operatorId": "fork-author"}, *e[1:]]
    )
    with pytest.raises(VerificationError, match="checkpoint does not bind"):
        verify(state, expected_operator_id="fork-author")


def test_selected_execution_digest_cannot_be_changed(tmp_path):
    state = rewrite(
        producer(tmp_path), lambda e: [*e[:2], {**e[2], "executionDigest": "0" * 64}]
    )
    with pytest.raises(VerificationError, match="retained native evidence"):
        verify(state)


def test_start_must_reference_exact_opening_checkpoint(tmp_path):
    state = rewrite(
        producer(tmp_path),
        lambda e: [e[0], {**e[1], "openingCheckpointDigest": "0" * 64}, e[2]],
    )
    with pytest.raises(VerificationError, match="retained opening checkpoint"):
        verify(state)


def test_existing_witness_refuses_fork_checkpoint(tmp_path):
    state = producer(tmp_path)
    history, witness, *_ = state
    events = [entry["event"] for entry in read_history(history)]
    history.unlink()
    for event in [{**events[0], "operatorId": "fork-author"}, *events[1:]]:
        append_history(history, event)
    with pytest.raises(VerificationError, match="does not extend"):
        witness.checkpoint(history)


def test_selection_api_refuses_a_second_opening(tmp_path):
    history, witness, plan, *_ = producer(tmp_path)
    with pytest.raises(VerificationError, match="cannot be replaced"):
        open_run_selection(
            history, witness, plan, CONFIG, CONTROLS, operator_id="fixture-author"
        )


def test_start_api_refuses_different_control_before_dispatch(tmp_path):
    plan, *_ = fixture()
    history = tmp_path / "history.jsonl"
    witness = Witness(tmp_path / "witness.json", SigningKey.generate())
    opening = open_run_selection(
        history, witness, plan, CONFIG, CONTROLS, operator_id="fixture-author"
    )
    with pytest.raises(VerificationError, match="inputs differ"):
        start_selected_run(
            history,
            witness,
            plan,
            CONFIG,
            b"changed",
            opening,
            operator_id="fixture-author",
        )
    assert len(read_history(history)) == 1


def test_start_api_refuses_operator_substitution_before_dispatch(tmp_path):
    plan, *_ = fixture()
    history = tmp_path / "history.jsonl"
    witness = Witness(tmp_path / "witness.json", SigningKey.generate())
    opening = open_run_selection(
        history, witness, plan, CONFIG, CONTROLS, operator_id="fixture-author"
    )
    with pytest.raises(VerificationError, match="inputs differ"):
        start_selected_run(
            history,
            witness,
            plan,
            CONFIG,
            CONTROLS,
            opening,
            operator_id="another-operator",
        )
    assert len(read_history(history)) == 1


@pytest.mark.parametrize("operator", [None, "", "operator with spaces", "nonascii-é"])
def test_unsupported_operator_refused(tmp_path, operator):
    with pytest.raises(VerificationError, match="operator identity"):
        verify(producer(tmp_path), expected_operator_id=operator)


@pytest.mark.parametrize(
    "configuration,controls", [(None, CONTROLS), (b"", CONTROLS), (CONFIG, "text")]
)
def test_missing_original_bytes_refused(configuration, controls):
    plan, *_ = fixture()
    with pytest.raises(VerificationError, match="original bytes"):
        selection_pins(plan, configuration, controls)


def test_untyped_plan_refused():
    with pytest.raises(VerificationError, match="RunPlan"):
        selection_pins({}, CONFIG, CONTROLS)


@pytest.mark.parametrize(
    "change",
    [
        {"count": True},
        {"count": 0},
        {"count": 100},
        {"extra": "unsupported"},
        {"signature": None},
    ],
)
def test_unsupported_checkpoint_refused(tmp_path, change):
    state = producer(tmp_path)
    with pytest.raises(VerificationError):
        verify(state, opening_checkpoint={**state[-2], **change})


def test_wrong_consumer_key_refused(tmp_path):
    with pytest.raises(VerificationError, match="pinned witness key"):
        verify(producer(tmp_path), pinned_witness_key=SigningKey.generate().public_hex)


def test_final_anchor_must_cover_additional_history(tmp_path):
    state = producer(tmp_path)
    append_history(state[0], {"runId": "another-run", "kind": "unrelated"})
    with pytest.raises(VerificationError, match="all supplied history"):
        verify(state)


@pytest.mark.parametrize("raw", [b"{}\n", b"[]\n"])
def test_unsupported_history_entry_refused(tmp_path, raw):
    state = producer(tmp_path)
    state[0].write_bytes(raw)
    with pytest.raises(VerificationError, match="shape is unsupported"):
        verify(state)


def test_nonobject_event_refused(tmp_path):
    state = producer(tmp_path)
    append_history(state[0], [])
    state = (*state[:-1], state[1].checkpoint(state[0]))
    with pytest.raises(VerificationError, match="event is not an object"):
        verify(state)


def test_opening_anchor_cannot_include_start(tmp_path):
    state = producer(tmp_path)
    with pytest.raises(VerificationError, match="end at selection"):
        verify(state, opening_checkpoint=state[-1])


def test_start_requires_single_selection_and_selection_anchor(tmp_path):
    state = producer(tmp_path)
    history, witness, plan, *_ = state
    with pytest.raises(VerificationError, match="one prior selection"):
        start_selected_run(
            history,
            witness,
            plan,
            CONFIG,
            CONTROLS,
            state[-2],
            operator_id="fixture-author",
        )
    history.unlink()
    event = {
        "profile": "probity-evaluation-selection-v1",
        "runId": plan.run_id,
        "kind": "selection",
        "pins": selection_pins(plan, CONFIG, CONTROLS),
        "operatorId": "fixture-author",
    }
    append_history(history, event)
    append_history(history, {"runId": "unrelated-run", "kind": "unrelated"})
    signer = Witness(tmp_path / "another-witness.json", witness.signing_key)
    with pytest.raises(VerificationError, match="end at selection"):
        start_selected_run(
            history,
            signer,
            plan,
            CONFIG,
            CONTROLS,
            signer.checkpoint(history),
            operator_id="fixture-author",
        )


def test_closure_requires_start_and_digest(tmp_path):
    state = producer(tmp_path)
    history, witness, plan, *_ = state
    with pytest.raises(VerificationError, match="one selection and one start"):
        close_selected_run(history, witness, plan, "0" * 64)
    lines = history.read_bytes().splitlines()
    history.write_bytes(b"\n".join(lines[:2]) + b"\n")
    with pytest.raises(VerificationError, match="digest is unsupported"):
        close_selected_run(history, witness, plan, "invalid")
