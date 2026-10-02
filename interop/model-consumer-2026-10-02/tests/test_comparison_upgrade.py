"""Installed comparison/native original replay remains separate from selected host quality."""

from __future__ import annotations
import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("model_gate", ROOT / "model_gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def selected(tmp_path):
    packet = tmp_path / "packet"
    packet.mkdir()
    with zipfile.ZipFile(ROOT / "comparison-run.zip") as archive:
        archive.extractall(packet)
    pins = ROOT / "comparison-native-pins.json"
    return packet, pins, json.loads((packet / "report.json").read_bytes())


def invoke(selected, tmp_path, kind="evidence", policy=None):
    packet, pins, _ = selected
    policy_path = ROOT / ("comparison-" + kind + "-policy.json")
    if policy is not None:
        policy_path = tmp_path / "host-policy.json"
        policy_path.write_text(json.dumps(policy) + "\n")
    return gate.gate(
        packet,
        pins,
        policy_path,
        sha(policy_path.read_bytes()),
        tmp_path / "receipts",
        60,
    )


def test_actual_installed_comparison_preserves_all_models_rows(selected, tmp_path):
    result = invoke(selected, tmp_path)
    assert result["publicationDecision"] == "publish"
    report = json.loads((tmp_path / "receipts" / "reader.stdout").read_bytes())
    assert report == selected[2]
    assert report["population"]["scored"] == 96
    assert len(report["quality"]) == 16
    assert {row["model"] for row in report["quality"]} == {"smol135-q4", "smol360-q4"}
    assert (
        sum(row["correct"] for row in report["quality"] if row["model"] == "smol135-q4")
        == 0
    )
    assert (
        sum(row["correct"] for row in report["quality"] if row["model"] == "smol360-q4")
        == 8
    )
    assert (
        sum(
            row["formatValid"]
            for row in report["quality"]
            if row["model"] == "smol360-q4"
        )
        == 42
    )


def test_actual_360_quality_refuses_weak_abstention_rows(selected, tmp_path):
    result = invoke(selected, tmp_path, "quality")
    assert result["evidenceDecision"] == "verified"
    assert result["publicationDecision"] == "hold-selected-score-or-resource"
    assert len(result["policyFailures"]) == 2
    for item in result["policyFailures"]:
        assert item["row"]["model"] == "smol360-q4"
        assert item["row"]["family"] == "grounded-abstention"
        assert item["measured"] == 0
        assert item["minimum"] == 1


def test_comparison_native_substitution_refuses(selected, tmp_path):
    (selected[0] / "terminal.json").write_bytes(b"{}")
    result = invoke(selected, tmp_path)
    assert result["evidenceDecision"] == "not-verified"
    assert result["child"]["returncode"] == 1


def test_original_reader_does_not_silently_expand_profile(selected, tmp_path):
    policy = json.loads((ROOT / "comparison-evidence-policy.json").read_bytes())
    original = json.loads((ROOT / "source-contract.json").read_bytes())
    policy["readerSha256"] = original["files"]["model_task_reader.py"]["sha256"]
    result = invoke(selected, tmp_path, policy=policy)
    assert result["child"]["returncode"] == 1
    assert result["evidenceDecision"] == "not-verified"


def test_models_cannot_be_omitted_from_selected_population(selected, tmp_path):
    policy = json.loads((ROOT / "comparison-evidence-policy.json").read_bytes())
    for row in policy["rows"]:
        row.pop("model")
    result = invoke(selected, tmp_path, policy=policy)
    assert not result["launched"]
    assert "duplicate selected quality row" in result["reason"]


def test_original_frozen_reader_and_pins_stay_exact():
    contract = json.loads((ROOT / "source-contract.json").read_bytes())
    assert (
        contract["files"]["model_task_reader.py"]["sha256"]
        == "1ced4b0875d56ee33e1bc8749c44669aa44ce87036ad0bbbdfc798cdffa5cee2"
    )
    original_sha = "ec68fd7a43381e879c1d88ed72e92ab14054190cb3d3a57cb9459cd5685501ec"
    assert (
        json.loads((ROOT / "selected-native-pins.json").read_bytes())["manifest"][
            "sha256"
        ]
        == original_sha
    )


def test_inside_receipt_directory_does_not_change_original_bytes(selected, tmp_path):
    packet, pins, _ = selected
    policy = ROOT / "comparison-evidence-policy.json"
    before = {
        str(p.relative_to(packet)): sha(p.read_bytes())
        for p in packet.rglob("*")
        if p.is_file()
    }
    with pytest.raises(ValueError, match="outside producer packet"):
        gate.gate(
            packet, pins, policy, sha(policy.read_bytes()), packet / "receipts", 60
        )
    assert not (packet / "receipts").exists()
    assert before == {
        str(p.relative_to(packet)): sha(p.read_bytes())
        for p in packet.rglob("*")
        if p.is_file()
    }
