"""Independent replay attacks using retained native reference effect bytes.

These test fixtures use an explicitly synthetic Git revision. They verify
local checking behavior, not Git source membership or external key custody.
"""

from __future__ import annotations

import hashlib
import importlib.util
import logging
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest

from probity_observer.attribution import sign_consumption
from probity_observer.crypto import (
    SigningKey,
    VerificationError,
    canonical,
    strict_loads,
)
from probity_observer.replay import (
    MAX_DEPTH,
    MAX_INPUT_BYTES,
    InputPin,
    ReplayPolicy,
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
SYNTHETIC_REVISION = "1" * 40


@dataclass
class ReplayRun:
    """Freeze locally selected test pins and a distinct consumption signer."""

    inputs: dict[str, bytes]
    policy: ReplayPolicy
    signer: SigningKey

    def repin(self, role: str, raw: bytes) -> None:
        """Select changed bytes explicitly, testing semantics beyond byte mismatch."""
        self.inputs[role] = raw
        pins = tuple(
            InputPin(
                pin.role, replace(pin.artifact, sha256=hashlib.sha256(raw).hexdigest())
            )
            if pin.role == role
            else pin
            for pin in self.policy.input_pins
        )
        self.policy = replace(self.policy, input_pins=pins)

    def fabricated_success(self) -> dict[str, Any]:
        """Sign every input as pass without running its native semantics."""
        report = {
            "checks": [
                {"role": role, "outcome": "pass"}
                for role in sorted(self.policy.expected_roles)
            ]
        }
        checks = consumption_checks(self.inputs, self.policy, report)
        return sign_consumption(
            self.policy.action_id, self.policy.claim_digest, checks, self.signer
        )

    def mutate_json(self, role: str, field: str, value: Any) -> None:
        """Repin one malformed semantic field while retaining canonical JSON bytes."""
        candidate = strict_loads(self.inputs[role])
        candidate[field] = value
        self.repin(role, canonical(candidate))

    def truncate_history(self) -> None:
        """Remove a genuine native terminal record while preserving complete JSONL."""
        lines = self.inputs["history"].splitlines()
        self.repin("history", b"\n".join(lines[:-1]) + b"\n")


MUTATIONS: dict[str, Callable[[ReplayRun], None]] = {
    "bad-grant-signature": lambda run: run.mutate_json(
        "authorization", "signature", "AA=="
    ),
    "owner-copy-difference": lambda run: run.repin(
        "copy:request.json", b"substituted fixture byte"
    ),
    "wrong-admission-authority": lambda run: run.mutate_json(
        "admission-policy", "authority_digest", "0" * 64
    ),
    "expired-reference": lambda run: run.repin(
        "reference-time", canonical({"now": "2027-10-01T00:00:00Z"})
    ),
    "unknown-request-field": lambda run: run.mutate_json(
        "request", "uncheckedExtension", True
    ),
    "wrong-issuer-context": lambda run: run.mutate_json("key-pins", "issuer", "0" * 64),
    "workspace-manifest-difference": lambda run: run.repin(
        "workspace:result.txt", b"unobserved durable workspace bytes"
    ),
    "truncated-history": lambda run: run.truncate_history(),
}


@pytest.fixture
def run(tmp_path: Path) -> ReplayRun:
    """Generate native positive bytes and select pins outside candidate reports."""
    native = tmp_path / "native"
    report = DEMO.run_action(native)
    inputs = DEMO._inputs(native, report)
    signer = SigningKey.generate()
    policy = DEMO._policy(inputs, SYNTHETIC_REVISION, signer)
    return ReplayRun(inputs, policy, signer)


def assert_refused(
    operation: Callable[[], Any], expected: str, caplog: pytest.LogCaptureFixture
) -> None:
    """Compare complete error text and the bounded refusal log."""
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="probity_observer.replay"):
        with pytest.raises(VerificationError, match=re.escape(expected)) as caught:
            operation()
    assert str(caught.value) == expected
    assert "pilot replay refused: " + expected in caplog.text


class TestIndependentReplayReview:
    """Demand fresh substantive results after valid signed byte binding."""

    class TestPassingCases:
        """Positive controls rerun native signatures, history and workspace checks."""

        def test_positive_reference_effect_freshly_replays(
            self, run: ReplayRun
        ) -> None:
            actual = replay_checks(run.inputs, run.policy)
            assert actual["decision"] == "replay-acceptable"
            assert all(item["outcome"] == "pass" for item in actual["checks"])
            report = replay_consumption(
                run.fabricated_success(), run.inputs, run.policy
            )
            assert report["decision"] == "replay-acceptable"
            assert report["durableAdmission"] == "not-performed"
            assert report["bindings"]["resultAuthority"] == "signer-asserted"
            assert report["resultAuthority"] == "local-substantive-replay"

    class TestFailingCases:
        """A signer may authenticate an assertion, but cannot replace actual replay."""

        @pytest.mark.parametrize("mutation", tuple(MUTATIONS))
        def test_signed_fabricated_success_is_blocked(
            self,
            run: ReplayRun,
            mutation: str,
        ) -> None:
            MUTATIONS[mutation](run)
            report = replay_consumption(
                run.fabricated_success(), run.inputs, run.policy
            )
            assert report["bindings"]["status"] == "bindings-verified"
            assert report["decision"] == "block"
            assert report["reportedOutcomeMismatches"]

        def test_missing_owner_is_incomplete_not_pass(self, run: ReplayRun) -> None:
            del run.inputs["owner:request.json"]
            report = replay_checks(run.inputs, run.policy)
            assert report["decision"] == "block"
            assert report["contextOutcome"] == "incomplete"
            assert all(check["outcome"] == "not-run" for check in report["checks"])

        def test_undeclared_role_is_refused(
            self, run: ReplayRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            run.inputs["undeclared-extension"] = b"surprise"
            assert_refused(
                lambda: replay_checks(run.inputs, run.policy),
                "replay inputs differ from the declared context",
                caplog,
            )

        def test_oversized_native_input_is_refused(
            self, run: ReplayRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            run.inputs["owner:request.json"] = b"x" * (MAX_INPUT_BYTES + 1)
            assert_refused(
                lambda: replay_checks(run.inputs, run.policy),
                "replay input exceeds the byte bound",
                caplog,
            )

        def test_stale_checker_fingerprint_is_refused(
            self, run: ReplayRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            policy = replace(
                run.policy,
                checker_source=replace(run.policy.checker_source, sha256="0" * 64),
            )
            assert_refused(
                lambda: replay_checks(run.inputs, policy),
                "replay checker bytes differ from the consumer pin",
                caplog,
            )

        def test_policy_reader_rejects_unchecked_nested_pin_fields(
            self,
            run: ReplayRun,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            fields = run.policy.fields()
            fields["input_pins"][0]["uncheckedExtension"] = (
                "not part of effective policy"
            )
            assert_refused(
                lambda: ReplayPolicy.from_fields(fields),
                "replay input pin has unexpected fields",
                caplog,
            )

        @pytest.mark.parametrize(
            "outcome", ["success", "PASS", "unknown", "", None, True]
        )
        def test_signed_nonprofile_outcomes_are_refused(
            self, run: ReplayRun, outcome: Any, caplog: pytest.LogCaptureFixture
        ) -> None:
            checks = run.fabricated_success()["payload"]["checks"]
            checks[0]["result"]["outcome"] = outcome
            record = sign_consumption(
                run.policy.action_id, run.policy.claim_digest, checks, run.signer
            )
            assert_refused(
                lambda: replay_consumption(record, run.inputs, run.policy),
                "reported replay outcome is outside the closed profile",
                caplog,
            )

        def test_excessive_result_depth_is_refused(
            self, run: ReplayRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            record = run.fabricated_success()
            nested: dict[str, Any] = {}
            for _ in range(MAX_DEPTH + 1):
                nested = {"nested": nested}
            record["payload"]["checks"][0]["result"] = nested
            assert_refused(
                lambda: replay_consumption(record, run.inputs, run.policy),
                "replay JSON exceeds depth or node bounds",
                caplog,
            )
