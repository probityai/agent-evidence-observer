"""Attack the declared replay context and signed-versus-substantive distinction."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import logging
import re
import sys
from dataclasses import FrozenInstanceError, dataclass, replace
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from probity_observer.attribution import DOMAIN, sign_consumption, verify_consumption
from probity_observer.crypto import SigningKey, VerificationError, canonical
from probity_observer.replay import (
    MAX_DEPTH,
    MAX_INPUT_BYTES,
    MAX_INPUTS,
    MAX_LINES,
    PROFILE,
    InputPin,
    ReplayOutcome,
    ReplayPolicy,
    checker_implementation_bytes,
    consumption_checks,
    replay_checks,
    replay_consumption,
)

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "examples"))
SPEC = importlib.util.spec_from_file_location(
    "replay_demo", ROOT / "examples/replay_demo.py"
)
assert SPEC is not None and SPEC.loader is not None
DEMO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEMO)
REVISION = "1" * 40
LOGGER = "probity_observer.replay"


@dataclass
class ReplayCase:
    """Keep explicit same-operator test inputs and externally selected pins."""

    inputs: dict[str, bytes]
    policy: ReplayPolicy
    signer: SigningKey
    record: dict[str, Any]

    def repin(self, inputs: dict[str, bytes]) -> ReplayPolicy:
        """Select changed test bytes deliberately, rather than bypass hash checks."""
        return replace(
            self.policy,
            input_pins=tuple(
                InputPin(
                    pin.role,
                    replace(
                        pin.artifact,
                        sha256=hashlib.sha256(inputs[pin.role]).hexdigest(),
                    ),
                )
                for pin in self.policy.input_pins
            ),
        )

    def sign(
        self,
        inputs: dict[str, bytes],
        policy: ReplayPolicy,
        report: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Sign actual or deliberately fabricated results for an attack control."""
        actual = replay_checks(inputs, policy) if report is None else report
        return sign_consumption(
            policy.action_id,
            policy.claim_digest,
            consumption_checks(inputs, policy, actual),
            self.signer,
        )

    def verify_bindings(
        self, record: dict[str, Any], inputs: dict[str, bytes], policy: ReplayPolicy
    ) -> dict[str, Any]:
        """Exercise the generic primitive separately from the strict replay gate."""
        return verify_consumption(
            record,
            inputs,
            policy.pins,
            action_id=policy.action_id,
            claim_digest=policy.claim_digest,
            pinned_signer=policy.pinned_signer,
        )


@pytest.fixture
def case(tmp_path: Path) -> ReplayCase:
    """Generate a real native action; the Git identity is explicitly synthetic."""
    output = tmp_path / "native"
    report = DEMO.run_action(output)
    inputs = DEMO._inputs(output, report)
    signer = SigningKey.generate()
    policy = DEMO._policy(inputs, REVISION, signer)
    result = replay_checks(inputs, policy)
    record = DEMO._signed(inputs, policy, signer, result)
    return ReplayCase(inputs, policy, signer, record)


def assert_refused(
    operation: Any, expected: str, caplog: pytest.LogCaptureFixture
) -> None:
    """Compare the complete error and bounded log without candidate contents."""
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        with pytest.raises(VerificationError, match=re.escape(expected)) as caught:
            operation()
    assert str(caught.value) == expected
    assert f"pilot replay refused: {expected}" in caplog.text


def results(report: dict[str, Any]) -> dict[str, str]:
    """Index actual outcomes without inferring success from signatures."""
    return {item["role"]: item["outcome"] for item in report["checks"]}


class TestReplayPolicy:
    class TestPassingCases:
        def test_round_trip_and_immutable_fields(self, case: ReplayCase) -> None:
            loaded = ReplayPolicy.from_fields(
                json.loads(canonical(case.policy.fields()))
            )
            assert loaded == case.policy
            with pytest.raises(
                FrozenInstanceError, match="cannot assign to field 'action_id'"
            ) as caught:
                loaded.action_id = "changed"
            assert str(caught.value) == "cannot assign to field 'action_id'"

        @pytest.mark.parametrize("revision", ["a" * 40, "b" * 64])
        def test_sha1_and_sha256_git_ids(self, case: ReplayCase, revision: str) -> None:
            pin = replace(case.policy.checker_source, revision=revision)
            assert (
                replace(case.policy, checker_source=pin).checker_source.revision
                == revision
            )

        def test_returned_pin_map_does_not_mutate_policy(
            self, case: ReplayCase
        ) -> None:
            pins = case.policy.pins
            pins.clear()
            assert set(case.policy.pins) == case.policy.expected_roles

        @given(st.binary(min_size=0, max_size=512))
        @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
        def test_policy_digest_changes_with_pinned_byte_population(
            self, case: ReplayCase, raw: bytes
        ) -> None:
            changed = {**case.inputs, "copy:request.json": raw}
            policy = case.repin(changed)
            if raw != case.inputs["copy:request.json"]:
                assert policy.policy_digest != case.policy.policy_digest

    class TestFailingCases:
        @pytest.mark.parametrize(
            "revision",
            [
                "main",
                "HEAD",
                "v1.0",
                "abc123",
                "A" * 40,
                "a" * 39,
                "b" * 41,
                "c" * 63,
                "d" * 65,
            ],
        )
        def test_moving_and_truncated_git_ids(
            self, case: ReplayCase, revision: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            pin = replace(case.policy.checker_source, revision=revision)
            assert_refused(
                lambda: replace(case.policy, checker_source=pin),
                "Git replay revision must be a full lowercase object id",
                caplog,
            )

        @pytest.mark.parametrize(
            "names,reason",
            [
                ([], "fixture_names must contain 1 to 12 immutable member names"),
                ((), "fixture_names must contain 1 to 12 immutable member names"),
                (
                    ("../request.json",),
                    "member name must be a normalized relative ASCII path",
                ),
                (
                    ("/absolute",),
                    "member name must be a normalized relative ASCII path",
                ),
                (("a\\b",), "member name must be a normalized relative ASCII path"),
                (("a//b",), "member name must be a normalized relative ASCII path"),
                (("a b",), "member name must be a normalized relative ASCII path"),
                (("a", "a"), "fixture_names contains repeated names"),
                (
                    ("a", "a/b"),
                    "fixture_names contains colliding file and directory names",
                ),
            ],
        )
        def test_unsafe_or_mutable_member_populations(
            self,
            case: ReplayCase,
            names: Any,
            reason: str,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            assert_refused(
                lambda: replace(case.policy, fixture_names=names), reason, caplog
            )

        def test_repeated_roles(
            self, case: ReplayCase, caplog: pytest.LogCaptureFixture
        ) -> None:
            pins = (*case.policy.input_pins, case.policy.input_pins[0])
            assert_refused(
                lambda: replace(case.policy, input_pins=pins),
                "replay input roles differ from the declared profile",
                caplog,
            )

        def test_extra_policy_field(
            self, case: ReplayCase, caplog: pytest.LogCaptureFixture
        ) -> None:
            value = {**case.policy.fields(), "independentCustody": True}
            assert_refused(
                lambda: ReplayPolicy.from_fields(value),
                "replay policy has unexpected fields",
                caplog,
            )

        def test_extra_nested_input_pin_field(
            self, case: ReplayCase, caplog: pytest.LogCaptureFixture
        ) -> None:
            value = case.policy.fields()
            value["input_pins"][0]["uncheckedExtension"] = True
            assert_refused(
                lambda: ReplayPolicy.from_fields(value),
                "replay input pin has unexpected fields",
                caplog,
            )


class TestReplayChecks:
    class TestPassingCases:
        def test_native_checks_and_all_context_are_executed(
            self, case: ReplayCase
        ) -> None:
            report = replay_checks(case.inputs, case.policy)
            assert report["decision"] == "replay-acceptable"
            assert set(results(report)) == case.policy.expected_roles
            assert set(results(report).values()) == {"pass"}
            assert report["resultAuthority"] == "local-substantive-replay"
            assert report["coverage"] == "declared-inputs-only"
            assert report["durableAdmission"] == "not-performed"
            assert report["witnessScope"] == "PEER"

        def test_all_outcomes_are_closed(self) -> None:
            assert {outcome.value for outcome in ReplayOutcome} == {
                "pass",
                "refusal",
                "invalid",
                "incomplete",
                "error",
                "not-run",
            }

        @pytest.mark.parametrize(
            "timestamp", ["0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z"]
        )
        def test_extreme_canonical_years_parse_before_native_validity_check(
            self, case: ReplayCase, timestamp: str
        ) -> None:
            changed = {**case.inputs, "reference-time": canonical({"now": timestamp})}
            report = replay_checks(changed, case.repin(changed))
            assert report["contextOutcome"] == "pass"
            assert results(report)["authorization"] == "refusal"
            assert report["decision"] == "block"

    class TestFailingCases:
        @pytest.mark.parametrize(
            "role",
            [
                "request",
                "grant-policy",
                "admission-policy",
                "key-pins",
                "reference-time",
                "history",
                "ledger",
                "workspace-manifest",
                "owner-manifest",
                "copy-manifest",
                "owner:request.json",
                "copy:request.json",
                "workspace:result.txt",
                "authorization",
                "observation",
            ],
        )
        def test_missing_context_is_incomplete_and_not_run(
            self, case: ReplayCase, role: str
        ) -> None:
            changed = {name: raw for name, raw in case.inputs.items() if name != role}
            report = replay_checks(changed, case.policy)
            assert report["contextOutcome"] == "incomplete"
            assert report["decision"] == "block"
            assert set(results(report).values()) == {"not-run"}

        @pytest.mark.parametrize(
            "role",
            [
                "authorization",
                "request",
                "history",
                "owner:request.json",
                "workspace:result.txt",
            ],
        )
        def test_substituted_bytes_are_rejected_before_checker(
            self, case: ReplayCase, role: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            changed = {**case.inputs, role: case.inputs[role] + b"changed"}
            assert_refused(
                lambda: replay_checks(changed, case.policy),
                "replay input bytes differ from the consumer pin",
                caplog,
            )

        def test_stale_checker_digest(
            self, case: ReplayCase, caplog: pytest.LogCaptureFixture
        ) -> None:
            policy = replace(
                case.policy,
                checker_source=replace(case.policy.checker_source, sha256="0" * 64),
            )
            assert_refused(
                lambda: replay_checks(case.inputs, policy),
                "replay checker bytes differ from the consumer pin",
                caplog,
            )

        def test_resigned_substituted_copy_still_fails_owner_comparison(
            self, case: ReplayCase
        ) -> None:
            changed = {**case.inputs, "copy:request.json": b"substituted"}
            policy = case.repin(changed)
            report = replay_checks(changed, policy)
            assert report["contextOutcome"] == "refusal"
            assert (
                report["contextReason"]
                == "copied fixture bytes differ from the pinned owner"
            )
            assert report["decision"] == "block"

        def test_extra_manifest_member_is_not_silently_ignored(
            self, case: ReplayCase
        ) -> None:
            value = json.loads(case.inputs["owner-manifest"])
            value["files"]["undeclared.json"] = "0" * 64
            changed = {**case.inputs, "owner-manifest": canonical(value)}
            report = replay_checks(changed, case.repin(changed))
            assert (
                report["contextReason"]
                == "replay manifest differs from the declared population"
            )
            assert report["decision"] == "block"

        @pytest.mark.parametrize(
            "timestamp",
            [
                "2026-10-01T00:00:00",
                "2026-10-01T00:00:00.1Z",
                "2026-10-01T00:00:00+00:00",
                "2026-13-01T00:00:00Z",
                "2026-1-1T00:00:00Z",
            ],
        )
        def test_noncanonical_time_context(
            self, case: ReplayCase, timestamp: str
        ) -> None:
            changed = {**case.inputs, "reference-time": canonical({"now": timestamp})}
            report = replay_checks(changed, case.repin(changed))
            assert (
                report["contextReason"]
                == "replay reference time must use canonical UTC seconds"
            )
            assert report["decision"] == "block"

        def test_expired_context_replays_native_refusal(self, case: ReplayCase) -> None:
            changed = {
                **case.inputs,
                "reference-time": canonical({"now": "2099-01-01T00:00:00Z"}),
            }
            report = replay_checks(changed, case.repin(changed))
            assert results(report)["authorization"] == "refusal"
            assert results(report)["observation"] == "refusal"
            assert report["decision"] == "block"

        def test_wrong_key_context_is_not_learned_from_packet(
            self, case: ReplayCase
        ) -> None:
            keys = json.loads(case.inputs["key-pins"])
            keys["observer"] = "0" * 64
            changed = {**case.inputs, "key-pins": canonical(keys)}
            report = replay_checks(changed, case.repin(changed))
            assert report["contextReason"] == "replay key contexts disagree"
            assert report["decision"] == "block"

        def test_changed_workspace_even_when_manifest_is_resigned(
            self, case: ReplayCase
        ) -> None:
            changed = {**case.inputs, "workspace:result.txt": b"wrong durable target"}
            changed["workspace-manifest"] = canonical(
                {
                    "files": {
                        "result.txt": hashlib.sha256(
                            changed["workspace:result.txt"]
                        ).hexdigest()
                    }
                }
            )
            report = replay_checks(changed, case.repin(changed))
            assert results(report)["observation"] == "refusal"
            assert report["decision"] == "block"

        def test_checker_crash_is_explicit_error(
            self,
            case: ReplayCase,
            monkeypatch: pytest.MonkeyPatch,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            def crash(*args: Any, **kwargs: Any) -> None:
                raise RuntimeError("do not leak private diagnostic material")

            monkeypatch.setattr("probity_observer.replay.verify_grant", crash)
            caplog.clear()
            report = replay_checks(case.inputs, case.policy)
            assert results(report)["authorization"] == "error"
            assert report["decision"] == "block"
            assert "pilot replay check error: local checker failed" in caplog.text
            assert "private diagnostic material" not in caplog.text


class TestReplayConsumption:
    class TestPassingCases:
        def test_signed_binding_and_fresh_replay_are_separate(
            self, case: ReplayCase
        ) -> None:
            result = replay_consumption(case.record, case.inputs, case.policy)
            assert result["bindings"]["status"] == "bindings-verified"
            assert result["bindings"]["resultAuthority"] == "signer-asserted"
            assert result["resultAuthority"] == "local-substantive-replay"
            assert result["reportedOutcomeMismatches"] == []
            assert result["decision"] == "replay-acceptable"

    class TestFailingCases:
        def test_fabricated_signed_success_cannot_pass_actual_replay(
            self, case: ReplayCase, caplog: pytest.LogCaptureFixture
        ) -> None:
            packet = json.loads(case.inputs["observation"])
            packet.pop("authorizationBinding")
            changed = {**case.inputs, "observation": canonical(packet)}
            policy = case.repin(changed)
            report = replay_checks(changed, policy)
            for item in report["checks"]:
                item["outcome"] = "pass"
            forged = case.sign(changed, policy, report)
            assert (
                case.verify_bindings(forged, changed, policy)["status"]
                == "bindings-verified"
            )
            caplog.clear()
            actual = replay_consumption(forged, changed, policy)
            assert actual["decision"] == "block"
            assert actual["reportedOutcomeMismatches"] == ["observation"]
            assert results(actual)["observation"] == "refusal"
            assert "reported outcomes differ from actual replay" in caplog.text

        @pytest.mark.parametrize(
            "outcome", ["refusal", "invalid", "incomplete", "error", "not-run"]
        )
        def test_nonpass_report_never_satisfies_gate(
            self, case: ReplayCase, outcome: str
        ) -> None:
            changed = copy.deepcopy(case.record)
            changed["payload"]["checks"][0]["result"]["outcome"] = outcome
            changed["signature"] = case.signer.sign(DOMAIN, changed["payload"])
            actual = replay_consumption(changed, case.inputs, case.policy)
            assert actual["decision"] == "block"
            assert actual["reportedOutcomeMismatches"]

        @pytest.mark.parametrize(
            "outcome", ["success", "permit", "unknown", "", None, True, 1, [], {}]
        )
        def test_unknown_signed_outcomes_are_invalid(
            self, case: ReplayCase, outcome: Any, caplog: pytest.LogCaptureFixture
        ) -> None:
            changed = copy.deepcopy(case.record)
            changed["payload"]["checks"][0]["result"]["outcome"] = outcome
            changed["signature"] = case.signer.sign(DOMAIN, changed["payload"])
            assert_refused(
                lambda: replay_consumption(changed, case.inputs, case.policy),
                "reported replay outcome is outside the closed profile",
                caplog,
            )

        def test_extra_result_fields_are_not_accepted(
            self, case: ReplayCase, caplog: pytest.LogCaptureFixture
        ) -> None:
            changed = copy.deepcopy(case.record)
            changed["payload"]["checks"][0]["result"]["custody"] = "EXTERNAL"
            changed["signature"] = case.signer.sign(DOMAIN, changed["payload"])
            assert_refused(
                lambda: replay_consumption(changed, case.inputs, case.policy),
                "reported replay result has unexpected fields",
                caplog,
            )

        def test_signed_alternate_policy_digest_is_refused(
            self, case: ReplayCase, caplog: pytest.LogCaptureFixture
        ) -> None:
            changed = copy.deepcopy(case.record)
            changed["payload"]["checks"][0]["result"]["policyDigest"] = "0" * 64
            changed["signature"] = case.signer.sign(DOMAIN, changed["payload"])
            assert_refused(
                lambda: replay_consumption(changed, case.inputs, case.policy),
                "reported replay result differs from the consumer profile or policy",
                caplog,
            )

        def test_other_signer_cannot_authorize_receipt(self, case: ReplayCase) -> None:
            policy = replace(
                case.policy, pinned_signer=SigningKey.generate().public_hex
            )
            expected = "consumption signer is not the pinned signer"
            with pytest.raises(VerificationError, match=re.escape(expected)) as caught:
                replay_consumption(case.record, case.inputs, policy)
            assert str(caught.value) == expected


class TestReplayBounds:
    class TestPassingCases:
        def test_checker_manifest_binds_each_required_source(self) -> None:
            value = json.loads(checker_implementation_bytes())
            assert value["profile"] == PROFILE
            assert set(value["fileSha256"]) == {
                "authorization.py",
                "crypto.py",
                "history.py",
                "ledger.py",
                "broker.py",
                "verify.py",
                "replay.py",
                "attribution.py",
            }
            assert all(len(item) == 64 for item in value["fileSha256"].values())

    class TestFailingCases:
        def test_single_input_byte_bound_even_when_owner_is_missing(
            self, case: ReplayCase, caplog: pytest.LogCaptureFixture
        ) -> None:
            changed = {
                role: raw
                for role, raw in case.inputs.items()
                if role != "owner:request.json"
            }
            changed["request"] = b"x" * (MAX_INPUT_BYTES + 1)
            assert_refused(
                lambda: replay_checks(changed, case.policy),
                "replay input exceeds the byte bound",
                caplog,
            )

        def test_total_byte_bound(
            self, case: ReplayCase, caplog: pytest.LogCaptureFixture
        ) -> None:
            changed = {role: b"x" * 40_000 for role in case.inputs}
            assert_refused(
                lambda: replay_checks(changed, case.policy),
                "replay inputs exceed the total byte bound",
                caplog,
            )

        def test_input_count_bound(
            self, case: ReplayCase, caplog: pytest.LogCaptureFixture
        ) -> None:
            changed = {f"extra-{number}": b"" for number in range(MAX_INPUTS + 1)}
            assert_refused(
                lambda: replay_checks(changed, case.policy),
                "replay input count exceeds the profile bound",
                caplog,
            )

        def test_mutable_byte_input(
            self, case: ReplayCase, caplog: pytest.LogCaptureFixture
        ) -> None:
            changed = {**case.inputs, "request": bytearray(case.inputs["request"])}
            assert_refused(
                lambda: replay_checks(changed, case.policy),
                "replay inputs must be immutable bytes",
                caplog,
            )

        def test_record_depth_bound(
            self, case: ReplayCase, caplog: pytest.LogCaptureFixture
        ) -> None:
            value: Any = {}
            for _ in range(MAX_DEPTH + 2):
                value = {"nested": value}
            assert_refused(
                lambda: replay_consumption(value, case.inputs, case.policy),
                "replay JSON exceeds depth or node bounds",
                caplog,
            )

        def test_record_byte_bound(
            self, case: ReplayCase, caplog: pytest.LogCaptureFixture
        ) -> None:
            value = {"oversize": "x" * 65_536}
            assert_refused(
                lambda: replay_consumption(value, case.inputs, case.policy),
                "consumption record exceeds the replay byte bound",
                caplog,
            )

        def test_history_line_bound(self, case: ReplayCase) -> None:
            changed = {**case.inputs, "history": b"{}\n" * (MAX_LINES + 1)}
            report = replay_checks(changed, case.repin(changed))
            assert (
                report["contextReason"]
                == "replay log exceeds line bounds or has an incomplete line"
            )
            assert report["decision"] == "block"

        def test_parser_recursion_is_not_a_success_or_uncaught_crash(
            self, case: ReplayCase
        ) -> None:
            raw = b'{"nested":' * 1500 + b"{}" + b"}" * 1500
            changed = {**case.inputs, "request": raw}
            report = replay_checks(changed, case.repin(changed))
            assert report["contextReason"] == "replay JSON exceeds depth or node bounds"
            assert report["decision"] == "block"
