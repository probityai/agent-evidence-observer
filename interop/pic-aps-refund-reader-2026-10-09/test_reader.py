"""Use the real native verifier and existing capture without signing or dispatching."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from importlib import metadata
import json
from pathlib import Path
import shutil
from unittest.mock import patch

import pytest

from probity_pic_aps_refund.reader import _json, _pic_source, _refund, assess, main, read_pic, selection
from probity_observer.crypto import VerificationError

PROFILE = Path(__file__).resolve().parent
FIXTURES = PROFILE / "fixtures"
PROPOSAL = (FIXTURES / "PIC/fixtures/signed-proposal-example.json").read_bytes()
KEYRING = (FIXTURES / "PIC/keys/pic_keys.example.json").read_bytes()
VERIFIER = PROFILE.parent / "aps-durable-refund-2026-10-05/verify-aps.mjs"
NODE = Path(shutil.which("node") or "/missing/node")


def wire(proposal: dict) -> bytes:
    return json.dumps(proposal).encode()


def test_original_native_signature_and_claim():
    result = read_pic(PROPOSAL, KEYRING)
    assert result["nativeSDKCommit"] == "330fdd817ef81d43461ea1787939e0d1cc87d589"
    assert result["decisionId"] == "decision-001"
    assert result["approvalRef"] == "approval-001"
    assert result["refund"] == {"payment_id": "pay_A", "amount_minor": 4000, "currency": "EUR"}
    assert result["proposalSHA256"] == hashlib.sha256(PROPOSAL).hexdigest()
    assert result["argsDigest"] == "0807321ed7a9fd18ced8b410487ef10a43c8f539d1f36b2693619fce62b4e698"


@pytest.mark.parametrize("field,value", [("payment_id", "pay_B"), ("amount_minor", 5000), ("currency", "USD"),
    ("amount_minor", True), ("amount_minor", 0), ("amount_minor", 2**53)])
def test_changed_refund_refuses(field, value):
    proposal = _json(PROPOSAL)
    proposal["action"]["args"][field] = value
    with pytest.raises(VerificationError):
        read_pic(wire(proposal), KEYRING)


@pytest.mark.parametrize("part", ["decision_id", "approval_ref", "tool", "impact", "intent", "signature", "key_id", "expiry"])
def test_changed_signed_binding_refuses(part):
    proposal = _json(PROPOSAL)
    if part in {"decision_id", "approval_ref"}:
        claim = _json(proposal["claims"][0]["text"])
        claim[part] += "-changed"
        proposal["claims"][0]["text"] = json.dumps(claim)
    elif part == "tool":
        proposal["action"]["tool"] = "read"
    elif part in {"impact", "intent"}:
        proposal[part] = "changed"
    elif part == "expiry":
        payload = _json(proposal["evidence"][0]["payload"])
        payload["expires_at"] = "2000-01-01T00:00:00Z"
        proposal["evidence"][0]["payload"] = json.dumps(payload)
    else:
        proposal["evidence"][0][part] = "changed"
    with pytest.raises(VerificationError):
        read_pic(wire(proposal), KEYRING)


@pytest.mark.parametrize("kind", ["hash", "url", "multiple", "none", "legacy", "missing-expiry", "payload-not-string"])
def test_only_selected_inline_canonical_signature_allowed(kind):
    proposal = _json(PROPOSAL)
    evidence = proposal["evidence"][0]
    if kind in {"hash", "url"}:
        evidence["type"] = kind
        evidence["ref"] = "https://must-not-be-called.example/evidence"
    elif kind == "multiple":
        proposal["evidence"].append(deepcopy(evidence))
    elif kind == "none":
        proposal["evidence"] = []
    elif kind == "legacy":
        evidence["payload"] = "raw legacy message"
    elif kind == "payload-not-string":
        evidence["payload"] = {}
    else:
        payload = _json(evidence["payload"])
        del payload["expires_at"]
        evidence["payload"] = json.dumps(payload)
    with pytest.raises(VerificationError):
        read_pic(wire(proposal), KEYRING)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":1,"\\u0078":2}', b'{"n":NaN}',
                                  b'{"n":Infinity}', b'{', b'"\xff"'])
def test_decoded_duplicates_and_invalid_json_refuse(raw):
    with pytest.raises(VerificationError):
        _json(raw)


def test_duplicate_attestation_member_refuses_before_native():
    proposal = _json(PROPOSAL)
    payload = proposal["evidence"][0]["payload"]
    proposal["evidence"][0]["payload"] = payload[:-1] + ',"tool":"refund"}'
    with pytest.raises(VerificationError, match="duplicate JSON member"):
        read_pic(wire(proposal), KEYRING)


def test_public_key_substitution_and_input_budget_refuse():
    with pytest.raises(VerificationError, match="public key selection"):
        read_pic(PROPOSAL, b'{"keys":{}}')
    with pytest.raises(VerificationError, match="input budget"):
        read_pic(b" " * 64_001, KEYRING)


def test_valid_fixture_eventually_expires_in_native_verifier():
    class FutureClock:
        @staticmethod
        def now(tz):
            assert tz is timezone.utc
            return datetime(2100, 1, 1, tzinfo=timezone.utc)

        fromisoformat = staticmethod(datetime.fromisoformat)

    # A test clock changes no fixture or signature. Production uses native wall time.
    with patch("pic_standard.evidence.datetime", FutureClock):
        with pytest.raises(VerificationError, match="native PIC verification refused"):
            read_pic(PROPOSAL, KEYRING)


@pytest.mark.parametrize("amount", [True, 0, -1, 4000.0, 2**53, "4000"])
def test_pic_integer_profile_does_not_alias_host_values(amount):
    with pytest.raises(VerificationError, match="positive safe integer"):
        _refund({"payment_id": "pay_A", "amount_minor": amount, "currency": "EUR"})


@pytest.mark.parametrize("refund", [{}, {"payment_id": "", "amount_minor": 1, "currency": "EUR"},
    {"payment_id": "pay_A", "amount_minor": 1, "currency": "USD"},
    {"payment_id": "pay_A", "amount_minor": 1, "currency": "EUR", "extra": True}])
def test_pic_closed_refund_profile(refund):
    with pytest.raises(VerificationError):
        _refund(refund)


def test_installed_pic_source_selection_is_real_and_refuses_missing_file(tmp_path):
    assert _pic_source() == "330fdd817ef81d43461ea1787939e0d1cc87d589"
    class WrongSource:
        version = "0.9.0"

        @staticmethod
        def locate_file(name):
            return tmp_path / name

    with patch.object(metadata, "distribution", return_value=WrongSource()):
        with pytest.raises(VerificationError, match="installed PIC source differs"):
            _pic_source()
    WrongSource.version = "0.8.0"
    with patch.object(metadata, "distribution", return_value=WrongSource()):
        with pytest.raises(VerificationError, match="installed PIC version differs"):
            _pic_source()


@pytest.mark.parametrize("case,effects", [("restart", 1), ("after-intent", 0), ("approval-reissue", 1)])
def test_existing_native_capture_keeps_join_and_effect_scopes(case, effects):
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in FIXTURES.rglob("*") if path.is_file()}
    result = assess(FIXTURES, case, node=NODE, verifier=VERIFIER)
    assert result["APS"]["retainedLocalCapture"]["logicalAdmissions"] == 1
    assert result["APS"]["retainedLocalCapture"]["localEffects"] == effects
    assert result["APS"]["retainedEvaluationTime"] == "2026-10-05T20:00:00.000Z"
    assert result["PIC"]["argsDigest"] != result["APS"]["payloadRef"]
    assert result["comparison"]["refundFieldsMatch"] is True
    assert result["comparison"]["PICApprovalRefMatchesAPSReceiptId"] is False
    assert result["comparison"]["combinedAdmissionEstablished"] is False
    assert result["APS"]["retainedLocalCapture"]["independentCustody"] is False
    if case == "approval-reissue":
        assert result["APS"]["retainedLocalCapture"]["approvalReissue"] == "same-operation-changed-authorization-refused"
    assert before == {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in FIXTURES.rglob("*") if path.is_file()}


def test_changed_selected_capture_refuses_without_effect(tmp_path):
    fixtures = tmp_path / "fixtures"
    shutil.copytree(FIXTURES, fixtures)
    path = fixtures / "APS/restart/service.sqlite"
    path.write_bytes(path.read_bytes() + b"changed")
    with pytest.raises(VerificationError, match="retained fixture bytes differ"):
        assess(fixtures, "restart", node=NODE, verifier=VERIFIER)


def test_every_retained_fixture_matches_source_selection():
    assert not list(FIXTURES.rglob("*private*"))
    for name, item in selection()["fixtureFiles"].items():
        assert hashlib.sha256((PROFILE / name).read_bytes()).hexdigest() == item["SHA256"]


def test_cli_reports_incomplete_join_with_distinct_exit(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["probity-read-pic-aps-refund", "--fixtures", str(FIXTURES),
        "--node", str(NODE), "--aps-verifier", str(VERIFIER)])
    assert main() == 3
    captured = capsys.readouterr()
    assert json.loads(captured.out)["comparison"]["combinedAdmissionEstablished"] is False
    assert captured.err == "Combined refund admission is not established; see comparison and missingInputs.\n"


def test_cli_invalid_evidence_has_empty_stdout_and_refusal(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr("sys.argv", ["probity-read-pic-aps-refund", "--fixtures", str(tmp_path),
        "--node", str(NODE), "--aps-verifier", str(VERIFIER)])
    assert main() == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("PIC/APS evidence refused: ")
