"""Check declared populations, exact retained bytes, and bounded result claims."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from probity_observer.crypto import VerificationError
from probity_observer.evaluation_history import (
    REQUIRED_ROLES,
    ArtifactRef,
    AttemptRecord,
    AttemptSpec,
    RunPlan,
    SourcePin,
    artifact_ref,
    decode_record,
    encode_record,
    plan_digest,
    verify_history,
)

CREATED = "2026-10-01T10:00:00+00:00"
STARTED = "2026-10-01T10:00:01.125000+00:00"
ENDED = "2026-10-01T10:00:02.875000+00:00"
CAPTURED = "2026-10-01T10:00:03+00:00"


def _fixture(states=("pass", "fail", "error", "not_run", "interrupted")):
    """Build a finite population with separate policy and scorer bytes."""
    sources = {
        f"{role}.json": encode_record({"role": role, "version": "1"})
        for role in sorted(REQUIRED_ROLES)
    }
    pins = tuple(
        SourcePin(
            role, role, "1", artifact_ref(f"{role}.json", sources[f"{role}.json"])
        )
        for role in sorted(REQUIRED_ROLES)
    )
    specs = tuple(
        AttemptSpec(f"attempt-{index}", f"sample-{index}", 1)
        for index in range(1, len(states) + 1)
    )
    plan = RunPlan("run-1", CREATED, specs, pins)
    records, artifacts = _records(plan, states)
    return plan, records, artifacts, sources


def _records(plan, states):
    """Retain complete, failed, interrupted, and absent entries explicitly."""
    records, artifacts = [], {}
    for index, state in enumerate(states, 1):
        status = "completed" if state in {"pass", "fail"} else state
        outcome = state if status == "completed" else "not_scored"
        absent = status == "not_run"
        started = None if absent else STARTED
        ended = None if status in {"not_run", "interrupted"} else ENDED
        error = None if status == "completed" else f"reason-{status}"
        ref = (
            None
            if absent
            else _envelope(
                plan.run_id, f"attempt-{index}", status, outcome, index, artifacts
            )
        )
        records.append(
            AttemptRecord(
                plan.run_id,
                f"attempt-{index}",
                index,
                status,
                outcome,
                started,
                ended,
                error,
                ref,
            )
        )
    return tuple(records), artifacts


def _envelope(run_id, attempt_id, status, outcome, ordinal, artifacts):
    """Keep the exact record identity in the retained output envelope."""
    content = encode_record(
        {
            "run_id": run_id,
            "attempt_id": attempt_id,
            "status": status,
            "outcome": outcome,
            "content": "retained output",
        }
    )
    name = f"attempt-{ordinal}.json"
    artifacts[name] = content
    return artifact_ref(name, content)


def _verify(fixture, **overrides):
    """Invoke the checker with the fixed fixture's full retained populations."""
    plan, records, artifacts, sources = fixture
    arguments = {"artifacts": artifacts, "sources": sources, "ended_at": CAPTURED}
    arguments.update(overrides)
    return verify_history(plan, records, **arguments)


class TestPlan:
    class TestPassingCases:
        def test_complete_source_roles_and_frozen_collections(self):
            plan, records, _, _ = _fixture()
            copied = replace(
                plan, attempts=list(plan.attempts), sources=list(plan.sources)
            )
            assert copied == plan
            assert isinstance(copied.attempts, tuple)
            with pytest.raises(FrozenInstanceError):
                copied.run_id = "changed"
            assert records[0].actions == ()

        def test_digest_binds_population_policy_and_version(self):
            plan, _, _, _ = _fixture()
            altered = replace(
                plan,
                sources=tuple(
                    replace(pin, version="2") if pin.role == "policy" else pin
                    for pin in plan.sources
                ),
            )
            assert plan_digest(plan) != plan_digest(altered)

        @pytest.mark.parametrize(
            "timestamp",
            [CREATED, "0001-01-01T00:00:00Z", "9999-12-31T23:59:59.999999+00:00"],
        )
        def test_aware_utc_timestamp(self, timestamp):
            plan, _, _, _ = _fixture()
            assert replace(plan, created_at=timestamp).created_at == timestamp

    class TestFailingCases:
        @pytest.mark.parametrize(
            "value",
            ["", "space id", "line\n", "tab\t", "nonascii-\u00e9", None, True, 1, []],
        )
        @pytest.mark.parametrize(
            "field",
            [
                "run_id",
                "attempt_id",
                "sample_id",
                "artifact",
                "source_identity",
                "source_version",
            ],
        )
        def test_identity_fields_are_strict(self, value, field):
            callbacks = {
                "run_id": lambda: replace(_fixture()[0], run_id=value),
                "attempt_id": lambda: AttemptSpec(value, "sample", 1),
                "sample_id": lambda: AttemptSpec("attempt", value, 1),
                "artifact": lambda: artifact_ref(value, b"x"),
                "source_identity": lambda: SourcePin(
                    "task", value, "1", artifact_ref("source", b"x")
                ),
                "source_version": lambda: SourcePin(
                    "task", "task", value, artifact_ref("source", b"x")
                ),
            }
            with pytest.raises(VerificationError, match="printable ASCII identifier"):
                callbacks[field]()

        @pytest.mark.parametrize("value", [False, True, 0, -1, "1", 1.5, None])
        def test_epoch_is_positive_nonboolean(self, value):
            with pytest.raises(VerificationError, match="epoch must"):
                AttemptSpec("attempt", "sample", value)

        @pytest.mark.parametrize(
            "timestamp",
            ["2026-10-01T10:00:00", "2026-10-01T10:00:00+01:00", "invalid", None, True],
        )
        def test_non_utc_or_malformed_timestamp(self, timestamp):
            with pytest.raises(VerificationError, match="timezone-aware UTC"):
                replace(_fixture()[0], created_at=timestamp)

        @pytest.mark.parametrize("mode", ["evaluation", "", True, [], None])
        def test_unsupported_modes(self, mode):
            with pytest.raises(VerificationError, match="mode is unsupported"):
                replace(_fixture()[0], mode=mode)

        @pytest.mark.parametrize(
            "mutation",
            [
                "empty",
                "duplicate-id",
                "duplicate-sample-epoch",
                "missing-role",
                "duplicate-role",
                "wrong-type",
            ],
        )
        def test_population_and_roles(self, mutation):
            plan, _, _, _ = _fixture()
            changes = {
                "empty": {"attempts": ()},
                "duplicate-id": {
                    "attempts": (
                        plan.attempts[0],
                        replace(
                            plan.attempts[1], attempt_id=plan.attempts[0].attempt_id
                        ),
                    )
                },
                "duplicate-sample-epoch": {
                    "attempts": (
                        plan.attempts[0],
                        replace(plan.attempts[1], sample_id=plan.attempts[0].sample_id),
                    )
                },
                "missing-role": {"sources": plan.sources[:-1]},
                "duplicate-role": {"sources": plan.sources[:-1] + plan.sources[:1]},
                "wrong-type": {"attempts": ["untyped"]},
            }
            with pytest.raises(VerificationError):
                replace(plan, **changes[mutation])


class TestRetainedHistory:
    class TestPassingCases:
        def test_full_population_keeps_every_outcome(self):
            result = _verify(_fixture())
            assert result["summary"] == {
                "attempts": 5,
                "completed": 2,
                "error": 1,
                "interrupted": 1,
                "not_run": 1,
                "pass": 1,
                "fail": 1,
                "not_scored": 3,
            }
            assert result["executionTruth"] == "not-established"
            assert result["independentCustody"] == "not-established"
            assert result["globalNoOmission"] == "not-established"
            assert result["allDeclaredAttemptsRecorded"] is True

        def test_correct_summary_is_accepted(self):
            fixture = _fixture()
            expected = _verify(fixture)["summary"]
            assert _verify(fixture, claimed_summary=expected)["summary"] == expected

        def test_exact_observed_action_bytes(self):
            plan, records, artifacts, sources = _fixture(("pass",))
            artifacts["action.json"] = b'{"event":"native-transcript"}'
            record = replace(
                records[0],
                actions=[artifact_ref("action.json", artifacts["action.json"])],
            )
            result = verify_history(
                plan, [record], artifacts=artifacts, sources=sources, ended_at=CAPTURED
            )
            assert result["status"] == "records-consistent"

        @given(st.binary(max_size=256))
        def test_source_and_output_hashes_bind_arbitrary_bytes(self, content):
            ref = artifact_ref("bytes", content)
            assert ref.size_bytes == len(content)
            assert len(ref.sha256) == 64

    class TestFailingCases:
        @pytest.mark.parametrize(
            "mutation",
            [
                "missing",
                "extra",
                "duplicate",
                "reorder",
                "other-run",
                "wrong-ordinal",
                "wrong-id",
            ],
        )
        def test_attempt_population(self, mutation):
            plan, records, artifacts, sources = _fixture()
            populations = {
                "missing": records[:-1],
                "extra": records + records[:1],
                "duplicate": records[:-1] + records[:1],
                "reorder": tuple(reversed(records)),
                "other-run": (replace(records[0], run_id="another-run"),) + records[1:],
                "wrong-ordinal": (replace(records[0], ordinal=2),) + records[1:],
                "wrong-id": (replace(records[0], attempt_id="another-attempt"),)
                + records[1:],
            }
            with pytest.raises(VerificationError, match="retained attempt"):
                verify_history(
                    plan,
                    populations[mutation],
                    artifacts=artifacts,
                    sources=sources,
                    ended_at=CAPTURED,
                )

        @pytest.mark.parametrize("population", ["artifacts", "sources"])
        @pytest.mark.parametrize(
            "mutation", ["missing", "extra", "changed-size", "same-size", "nonbytes"]
        )
        def test_retained_bytes(self, population, mutation):
            fixture = _fixture()
            index = 2 if population == "artifacts" else 3
            values = dict(fixture[index])
            name = next(iter(values))
            if mutation == "missing":
                values.pop(name)
            elif mutation == "extra":
                values["extra"] = b"x"
            else:
                values[name] = {
                    "changed-size": b"x",
                    "same-size": b"x" * len(values[name]),
                    "nonbytes": bytearray(values[name]),
                }[mutation]
            with pytest.raises(VerificationError, match="artifact|population"):
                _verify(fixture, **{population: values})

        @pytest.mark.parametrize("field", ["run_id", "attempt_id", "status", "outcome"])
        def test_stale_output_with_fresh_hash(self, field):
            plan, records, artifacts, sources = _fixture(("pass",))
            envelope = decode_record(artifacts[records[0].output.name])
            envelope[field] = "changed"
            content = encode_record(envelope)
            artifacts[records[0].output.name] = content
            record = replace(
                records[0], output=artifact_ref(records[0].output.name, content)
            )
            with pytest.raises(VerificationError, match="stale"):
                verify_history(
                    plan,
                    [record],
                    artifacts=artifacts,
                    sources=sources,
                    ended_at=CAPTURED,
                )

        @pytest.mark.parametrize(
            "summary",
            [
                {"pass": 1},
                {
                    "attempts": 1,
                    "completed": 1,
                    "error": 0,
                    "interrupted": 0,
                    "not_run": 0,
                    "pass": True,
                    "fail": 0,
                    "not_scored": 0,
                },
                {
                    "attempts": 1,
                    "completed": 1,
                    "error": 0,
                    "interrupted": 0,
                    "not_run": 0,
                    "pass": 1,
                    "fail": 0,
                    "not_scored": 0,
                    "extra": 0,
                },
            ],
        )
        def test_selective_or_boolean_summary(self, summary):
            with pytest.raises(VerificationError, match="reported summary"):
                _verify(_fixture(("pass",)), claimed_summary=summary)

        @pytest.mark.parametrize(
            "changes",
            [
                {"started_at": "2026-10-01T09:59:59Z"},
                {"ended_at": "2026-10-01T10:00:04Z"},
                {"ended_at": CREATED},
                {"started_at": None},
                {"ended_at": None},
                {"error_code": "execution-error"},
                {"output": None},
            ],
        )
        def test_completed_attempt_constraints(self, changes):
            plan, records, artifacts, sources = _fixture(("pass",))
            record = replace(records[0], **changes)
            if record.output is None:
                artifacts = {}
            with pytest.raises(VerificationError):
                verify_history(
                    plan,
                    [record],
                    artifacts=artifacts,
                    sources=sources,
                    ended_at=CAPTURED,
                )

        @pytest.mark.parametrize("status", ["error", "not_run", "interrupted"])
        @pytest.mark.parametrize("changes", [{"outcome": "pass"}, {"error_code": None}])
        def test_unscored_reason_is_mandatory(self, status, changes):
            plan, records, artifacts, sources = _fixture((status,))
            record = replace(records[0], **changes)
            with pytest.raises(VerificationError, match="unscored"):
                verify_history(
                    plan,
                    [record],
                    artifacts=artifacts,
                    sources=sources,
                    ended_at=CAPTURED,
                )

        @pytest.mark.parametrize(
            "changes",
            [
                {"started_at": STARTED},
                {"ended_at": ENDED},
                {"output": artifact_ref("forged", b"x")},
                {"actions": (artifact_ref("action", b"x"),)},
            ],
        )
        def test_not_run_cannot_claim_execution(self, changes):
            plan, records, artifacts, sources = _fixture(("not_run",))
            record = replace(records[0], **changes)
            artifacts = {
                ref.name: b"x"
                for ref in ((record.output,) if record.output else ()) + record.actions
            }
            with pytest.raises(VerificationError, match="not-run"):
                verify_history(
                    plan,
                    [record],
                    artifacts=artifacts,
                    sources=sources,
                    ended_at=CAPTURED,
                )

        def test_interrupted_cannot_invent_completion(self):
            plan, records, artifacts, sources = _fixture(("interrupted",))
            with pytest.raises(VerificationError, match="completion timestamp"):
                verify_history(
                    plan,
                    [replace(records[0], ended_at=ENDED)],
                    artifacts=artifacts,
                    sources=sources,
                    ended_at=CAPTURED,
                )

        def test_log_has_one_bounded_reason(self, caplog):
            with pytest.raises(VerificationError):
                _verify(_fixture(), claimed_summary={"pass": 1})
            assert [record.message for record in caplog.records] == [
                "evaluation history refused: reported summary differs from "
                "retained attempts"
            ]


class TestJsonAndReferences:
    class TestPassingCases:
        def test_deterministic_json_preserves_unicode_data(self):
            content = encode_record({"z": "\u00e9", "a": 1})
            assert content == b'{"a":1,"z":"\\u00e9"}'
            assert decode_record(content) == {"z": "\u00e9", "a": 1}

    class TestFailingCases:
        @pytest.mark.parametrize(
            "content",
            [
                b'{"x":1,"x":2}',
                b'{"x":NaN}',
                b'{"x":Infinity}',
                b'{"nested":{"x":1,"x":2}}',
                b"\xff",
                b"{",
                b"",
            ],
        )
        def test_ambiguous_or_malformed_json(self, content):
            with pytest.raises(VerificationError, match="malformed or ambiguous"):
                decode_record(content)

        @pytest.mark.parametrize("depth", [130, 1200])
        def test_deep_json_is_a_bounded_refusal(self, depth, caplog):
            with pytest.raises(VerificationError, match="retained JSON"):
                decode_record(b"[" * depth + b"0" + b"]" * depth)
            assert len(caplog.records) == 1

        def test_oversized_json_is_refused_before_parsing(self):
            with pytest.raises(VerificationError, match="size limit"):
                decode_record(b" " * (8 * 1024 * 1024 + 1))

        def test_overpopulated_json_is_refused(self):
            with pytest.raises(VerificationError, match="node limit"):
                decode_record(encode_record([0] * 100_000))

        @pytest.mark.parametrize(
            "digest", ["", "A" * 64, "x" * 64, "0" * 63, "0" * 65, None, True]
        )
        def test_invalid_digest(self, digest):
            with pytest.raises(VerificationError, match="lowercase SHA-256"):
                ArtifactRef("artifact", digest, 1)

        @pytest.mark.parametrize("size", [True, False, -1, "1", None, 1.0])
        def test_invalid_size(self, size):
            with pytest.raises(VerificationError, match="nonnegative integer"):
                ArtifactRef("artifact", "0" * 64, size)
