"""Installed-reader host publication selection and child failure boundaries."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from probity_observer.crypto import VerificationError

from probity_adk.contract import PROFILE, encode, sha
from probity_adk.gate import child_decision, gate


def test_gate_actual_selected_native_population(packet: Path, tmp_path: Path) -> None:
    policy = tmp_path / "host-policy.json"
    policy.write_bytes((packet / "consumer-pins.json").read_bytes())
    reader = Path(sys.executable).parent / "probity-adk-read"
    result = gate(
        reader, packet, policy, sha(policy.read_bytes()), tmp_path / "receipt"
    )
    assert result["publicationDecision"] == "admitted"
    assert (
        tmp_path / "receipt/selected-policy.json"
    ).read_bytes() == policy.read_bytes()


def test_gate_refuses_policy_inside_candidate(packet: Path, tmp_path: Path) -> None:
    policy = packet / "consumer-pins.json"
    with pytest.raises(VerificationError, match="policy-inside-candidate"):
        gate(
            Path(sys.executable).parent / "probity-adk-read",
            packet,
            policy,
            sha(policy.read_bytes()),
            tmp_path / "receipt",
        )


def test_gate_refuses_substituted_policy(packet: Path, tmp_path: Path) -> None:
    policy = tmp_path / "policy.json"
    policy.write_bytes(b"{}")
    with pytest.raises(VerificationError, match="host-policy-bytes"):
        gate(
            Path(sys.executable).parent / "probity-adk-read",
            packet,
            policy,
            "0" * 64,
            tmp_path / "receipt",
        )


@pytest.mark.parametrize(
    "code,report",
    [
        (1, {"profile": PROFILE, "status": "verified", "plannedAttempts": 12}),
        (0, {"profile": PROFILE, "status": "refused", "plannedAttempts": 12}),
        (0, {"profile": "unselected", "status": "verified", "plannedAttempts": 12}),
        (0, {"profile": PROFILE, "status": "verified", "plannedAttempts": 11}),
        (0, {"profile": PROFILE, "status": "verified", "plannedAttempts": True}),
    ],
)
def test_child_failure_wrong_profile_or_population_refuses(
    code: int, report: dict
) -> None:
    assert child_decision(code, encode(report))["publicationDecision"] == "refused"


def test_child_minimal_success_refuses() -> None:
    report = {"profile": PROFILE, "status": "verified", "plannedAttempts": 12}
    assert child_decision(0, encode(report))["publicationDecision"] == "refused"


@pytest.mark.parametrize(
    "path,value",
    [
        (("records",), []),
        (("records", 0, "case"), "unknown"),
        (("records", 4, "nativeRevision"), 0),
        (("records", -1, "taskStatus"), "complete"),
        (("records", 0, "toolCalls"), True),
        (("resources", "modelCalls"), 26),
        (("doesNotAssert",), []),
        (("modelQuality",), "evaluated"),
    ],
)
def test_successful_child_forged_report_refuses(
    packet: Path, path: tuple, value: object
) -> None:
    from probity_adk.contract import decode

    report = decode((packet / "report.json").read_bytes())
    target = report
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    assert child_decision(0, encode(report))["publicationDecision"] == "refused"


def test_reader_inside_candidate_refuses(packet: Path, tmp_path: Path) -> None:
    reader = packet / "selected-reader"
    reader.write_text("untrusted candidate")
    policy = tmp_path / "policy.json"
    policy.write_bytes((packet / "consumer-pins.json").read_bytes())
    try:
        with pytest.raises(VerificationError, match="reader-inside-candidate"):
            gate(reader, packet, policy, sha(policy.read_bytes()), tmp_path / "receipt")
    finally:
        reader.unlink()


def test_timeout_preserves_partial_streams(
    packet: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    def timeout(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(
            "reader", 60, output=b"partial stdout", stderr=b"partial stderr"
        )

    monkeypatch.setattr(subprocess, "run", timeout)
    policy = tmp_path / "policy.json"
    policy.write_bytes((packet / "consumer-pins.json").read_bytes())
    receipt = tmp_path / "receipt"
    result = gate(
        Path(sys.executable).parent / "probity-adk-read",
        packet,
        policy,
        sha(policy.read_bytes()),
        receipt,
    )
    assert result["reason"] == "reader-timeout" and result["returncode"] is None
    assert (receipt / "reader-stdout.bin").read_bytes() == b"partial stdout"
    assert (receipt / "reader-stderr.bin").read_bytes() == b"partial stderr"
    assert (receipt / "launch.json").is_file()
