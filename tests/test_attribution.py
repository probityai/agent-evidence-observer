"""Check substitution, trust pins and action boundaries in consumption records."""

import copy
import hashlib

import pytest

from probity_observer.attribution import (
    ArtifactPin, check_artifact, sign_consumption, verify_consumption,
)
from probity_observer.crypto import SigningKey, VerificationError


@pytest.fixture
def sample():
    raw = b"retained artifact\n"
    pin = ArtifactPin("Example", "https://example.org/artifact", "fixed-revision",
                      "Example contributors", "Apache-2.0", hashlib.sha256(raw).hexdigest())
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
    args = dict(record=record, inputs={"authorization": raw},
                pins={"authorization": pin}, action_id="action-a",
                claim_digest="1" * 64, pinned_signer=key.public_hex)
    args.update(overrides)
    return verify_consumption(**args)


def test_exact_bytes_reach_checker_and_offline_verifier(sample):
    raw, _, _, _, calls = sample
    assert calls == [raw]
    result = verify(sample)
    assert result["status"] == "bindings-verified"
    assert result["coverage"] == "listed-checks-only"
    assert result["resultAuthority"] == "signer-asserted"


@pytest.mark.parametrize("changes", [
    {"action_id": "action-b"}, {"claim_digest": "2" * 64},
    {"inputs": {}}, {"pins": {}}, {"inputs": {"authorization": b"changed"}},
])
def test_wrong_action_claim_or_retained_set_is_refused(sample, changes):
    with pytest.raises(VerificationError):
        verify(sample, **changes)


def test_unknown_signer_is_refused(sample):
    with pytest.raises(VerificationError):
        verify(sample, pinned_signer=SigningKey.generate().public_hex)


@pytest.mark.parametrize("field,value", [("actionId", "action-b"),
                                        ("claimDigest", "2" * 64)])
def test_post_signature_substitution_is_refused(sample, field, value):
    damaged = copy.deepcopy(sample[3])
    damaged["payload"][field] = value
    with pytest.raises(VerificationError):
        verify(sample, record=damaged)


def test_false_provenance_is_refused_even_when_resigned(sample):
    damaged = copy.deepcopy(sample[3])
    damaged["payload"]["checks"][0]["input"]["project"] = "Another project"
    from probity_observer.attribution import DOMAIN
    damaged["signature"] = sample[2].sign(DOMAIN, damaged["payload"])
    with pytest.raises(VerificationError, match="provenance"):
        verify(sample, record=damaged)


def test_duplicate_roles_cannot_be_signed(sample):
    check = sample[3]["payload"]["checks"][0]
    with pytest.raises(VerificationError, match="repeated"):
        sign_consumption("action-a", "1" * 64, [check, check], sample[2])


def test_mismatched_bytes_never_reach_checker(sample):
    calls = []
    with pytest.raises(VerificationError):
        check_artifact("authorization", b"changed", sample[1], lambda raw: calls.append(raw))
    assert calls == []


def test_checker_crash_propagates(sample):
    def crash(raw):
        raise RuntimeError("checker failed")
    with pytest.raises(RuntimeError, match="checker failed"):
        check_artifact("authorization", sample[0], sample[1], crash)


def test_missing_receipt_is_not_a_verified_binding(sample):
    with pytest.raises(VerificationError):
        verify(sample, record={})
