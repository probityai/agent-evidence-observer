"""Check the installed finite fixture and its retained-byte reader."""

import hashlib
import json
import sys

import pytest

from probity_observer.crypto import VerificationError, canonical, strict_loads
from probity_observer.selection_profile import (
    CHECKER,
    CONTROLS,
    OPERATOR,
    _execute,
    _plan,
    main,
    read_profile,
    run_profile,
)


def test_finite_profile_has_measured_candidate_choice_and_all_refusals(tmp_path):
    packet = tmp_path / "native"
    report = run_profile(packet)
    shopping = report["candidateShopping"]
    assert [item["outcome"] for item in shopping["observedOutcomes"]] == [
        "pass",
        "fail",
    ]
    assert shopping["chosenAfterObservation"] == 0
    assert report["keyCustody"] == "same-local-process"
    assert report["registeredStudy"] is False
    assert report["assessmentTimestamps"] == "synthetic-fixture-values"
    assert report["clockAuthority"] == "local-process-clock"
    assert report["runtimeStartedAt"] <= report["runtimeEndedAt"]
    assert len(report["controls"]) == 10
    assert all(
        result["status"] == "refused"
        for name, result in report["controls"].items()
        if name != "positive"
    )
    result = read_profile(
        packet,
        strict_loads((packet / "consumer-opening.json").read_bytes()),
        strict_loads((packet / "consumer-final.json").read_bytes()),
        report["witnessPublicKey"],
        OPERATOR,
    )
    assert result == report["controls"]["positive"]
    manifest = strict_loads((packet / "manifest.json").read_bytes())
    for name, evidence in manifest.items():
        raw = (packet / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == evidence["sha256"]
        assert len(raw) == evidence["bytes"]


def test_retained_reader_refuses_modified_native_output(tmp_path):
    packet = tmp_path / "native"
    report = run_profile(packet)
    (packet / "output.json").write_bytes(b'{"changed":true}')
    with pytest.raises(VerificationError, match="artifact size|artifact digest"):
        read_profile(
            packet,
            strict_loads((packet / "consumer-opening.json").read_bytes()),
            strict_loads((packet / "consumer-final.json").read_bytes()),
            report["witnessPublicKey"],
            OPERATOR,
        )


def test_finite_runner_does_not_execute_external_source():
    plan, sources = _plan()
    assert sources["checker.json"] == CHECKER
    with pytest.raises(VerificationError, match="bundled checker"):
        _execute(
            plan,
            b'{"threshold":1}',
            CONTROLS,
            {**sources, "checker.json": b"untrusted source"},
        )


def test_reader_requires_complete_supported_packet(tmp_path):
    with pytest.raises(VerificationError, match="missing or unsupported"):
        read_profile(tmp_path, {}, {}, "key", OPERATOR)
    packet = tmp_path / "native"
    report = run_profile(packet)
    values = strict_loads((packet / "records.json").read_bytes())
    values[0]["actions"] = [{"unsupported": True}]
    (packet / "records.json").write_bytes(canonical(values))
    with pytest.raises(VerificationError, match="does not support action"):
        read_profile(packet, {}, {}, report["witnessPublicKey"], OPERATOR)


@pytest.mark.parametrize(
    "filename,raw",
    [
        ("configuration.json", b'{"threshold":1,"threshold":2}'),
        ("configuration.json", b'{"threshold":NaN}'),
        ("configuration.json", b'{"threshold":Infinity}'),
        ("configuration.json", b'{"threshold":true}'),
        ("configuration.json", b'{"threshold":-1}'),
        ("configuration.json", b'{"threshold":1,"unknown":0}'),
        ("controls.json", b'{"belowThreshold":0,"belowThreshold":1,"atThreshold":1}'),
        ("controls.json", b'{"belowThreshold":0,"atThreshold":NaN}'),
        ("controls.json", b'{"belowThreshold":0}'),
        ("plan.json", b'{"run_id":"a","run_id":"b"}'),
        ("records.json", b'[{"outcome":"pass","outcome":"fail"}]'),
    ],
)
def test_external_packet_refuses_ambiguous_or_unsupported_json(tmp_path, filename, raw):
    packet = tmp_path / "native"
    report = run_profile(packet)
    (packet / filename).write_bytes(raw)
    with pytest.raises(VerificationError):
        read_profile(packet, {}, {}, report["witnessPublicKey"], OPERATOR)


def test_installed_cli_run_and_explicit_anchored_read(tmp_path, monkeypatch, capsys):
    packet = tmp_path / "native"
    monkeypatch.setattr(sys, "argv", ["selection", "--output-dir", str(packet)])
    main()
    report = json.loads(capsys.readouterr().out)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "selection",
            "--read-dir",
            str(packet),
            "--opening-checkpoint",
            str(packet / "consumer-opening.json"),
            "--final-checkpoint",
            str(packet / "consumer-final.json"),
            "--witness-key",
            report["witnessPublicKey"],
            "--operator",
            OPERATOR,
        ],
    )
    main()
    assert (
        json.loads(capsys.readouterr().out)["status"] == "selected-history-consistent"
    )
    monkeypatch.setattr(sys, "argv", ["selection", "--read-dir", str(packet)])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
