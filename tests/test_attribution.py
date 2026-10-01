"""Check substitution, trust pins and action boundaries in consumption records."""

from __future__ import annotations

import copy
import hashlib
import re
from collections.abc import Callable
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from probity_observer.attribution import (
    DOMAIN,
    ArtifactPin,
    check_artifact,
    sign_consumption,
    verify_consumption,
)
from probity_observer.crypto import SigningKey, VerificationError


@pytest.fixture
def sample():
    raw = b"retained artifact\n"
    pin = ArtifactPin(
        "Example",
        "https://example.org/artifact",
        "fixed-revision",
        "Example contributors",
        "Apache-2.0",
        hashlib.sha256(raw).hexdigest(),
    )
    key = SigningKey.generate()
    calls = []

    def checker(value):
        calls.append(value)
        return {"verdict": "permit"}

    check = check_artifact("authorization", raw, pin, checker)
    record = sign_consumption("action-a", "1" * 64, [check], key)
    return raw, pin, key, record, calls


def verify(sample, **overrides):
    raw, pin, key, record, _ = sample
    args = dict(
        record=record,
        inputs={"authorization": raw},
        pins={"authorization": pin},
        action_id="action-a",
        claim_digest="1" * 64,
        pinned_signer=key.public_hex,
    )
    args.update(overrides)
    return verify_consumption(**args)


def _refuse(
    operation: Callable[[], Any],
    expected: str,
    caplog: pytest.LogCaptureFixture,
    exception: type[Exception] = VerificationError,
) -> None:
    """Compare the complete refusal and check that no fallback was logged."""
    with pytest.raises(exception, match=f"^{re.escape(expected)}$") as caught:
        operation()
    assert str(caught.value) == expected
    assert caplog.records == []


class TestConsumption:
    class TestPassingCases:
        def test_exact_bytes_reach_checker_and_offline_verifier(self, sample):
            raw, _, _, _, calls = sample
            assert calls == [raw]
            result = verify(sample)
            assert result["status"] == "bindings-verified"
            assert result["coverage"] == "listed-checks-only"
            assert result["resultAuthority"] == "signer-asserted"

        @given(raw=st.binary(max_size=4096))
        def test_generated_input_bytes_are_retained(self, raw: bytes) -> None:
            pin = ArtifactPin(
                "Example",
                "https://example.org/artifact",
                "fixed-revision",
                "Example contributors",
                "Apache-2.0",
                hashlib.sha256(raw).hexdigest(),
            )
            check = check_artifact(
                "authorization",
                raw,
                pin,
                lambda value: {"inputSha256": hashlib.sha256(value).hexdigest()},
            )
            assert check["input"] == pin.fields()
            assert check["result"] == {"inputSha256": pin.sha256}

    class TestFailingCases:
        @pytest.mark.parametrize(
            "changes,expected",
            [
                (
                    {"action_id": "action-b"},
                    "consumption record binds another action or claim",
                ),
                (
                    {"claim_digest": "2" * 64},
                    "consumption record binds another action or claim",
                ),
                ({"inputs": {}}, "retained inputs differ from the declared check set"),
                ({"pins": {}}, "retained inputs differ from the declared check set"),
                (
                    {"inputs": {"authorization": b"changed"}},
                    "retained artifact bytes differ",
                ),
            ],
        )
        def test_wrong_action_claim_or_retained_set_is_refused(
            self,
            sample,
            changes,
            expected,
            caplog,
        ):
            _refuse(lambda: verify(sample, **changes), expected, caplog)

        def test_unknown_signer_is_refused(self, sample, caplog):
            _refuse(
                lambda: verify(sample, pinned_signer=SigningKey.generate().public_hex),
                "consumption signer is not the pinned signer",
                caplog,
            )

        @pytest.mark.parametrize(
            "field,value",
            [("actionId", "action-b"), ("claimDigest", "2" * 64)],
        )
        def test_post_signature_substitution_is_refused(
            self,
            sample,
            field,
            value,
            caplog,
        ):
            damaged = copy.deepcopy(sample[3])
            damaged["payload"][field] = value
            _refuse(
                lambda: verify(sample, record=damaged),
                "signature does not verify under the pinned key",
                caplog,
            )

        def test_false_provenance_is_refused_even_when_resigned(self, sample, caplog):
            damaged = copy.deepcopy(sample[3])
            damaged["payload"]["checks"][0]["input"]["project"] = "Another project"
            damaged["signature"] = sample[2].sign(DOMAIN, damaged["payload"])
            _refuse(
                lambda: verify(sample, record=damaged),
                "consumption provenance differs from the consumer pin",
                caplog,
            )

        def test_duplicate_roles_cannot_be_signed(self, sample, caplog):
            check = sample[3]["payload"]["checks"][0]
            _refuse(
                lambda: sign_consumption(
                    "action-a", "1" * 64, [check, check], sample[2]
                ),
                "consumption roles are empty or repeated",
                caplog,
            )

        def test_mismatched_bytes_never_reach_checker(self, sample, caplog):
            calls = []
            _refuse(
                lambda: check_artifact(
                    "authorization",
                    b"changed",
                    sample[1],
                    lambda raw: calls.append(raw),
                ),
                "artifact bytes differ from the consumer pin",
                caplog,
            )
            assert calls == []

        def test_checker_crash_propagates(self, sample, caplog):
            def crash(raw):
                raise RuntimeError("checker failed")

            _refuse(
                lambda: check_artifact("authorization", sample[0], sample[1], crash),
                "checker failed",
                caplog,
                RuntimeError,
            )

        def test_missing_receipt_is_not_a_verified_binding(self, sample, caplog):
            _refuse(
                lambda: verify(sample, record={}),
                "consumption envelope fields differ from the profile",
                caplog,
            )
