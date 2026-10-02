"""Actual installed native replay, separate host policy, transport and substitution refusals."""

from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("model_gate", ROOT / "model_gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2, allow_nan=False) + "\n").encode()


@pytest.fixture
def selected(tmp_path):
    packet = tmp_path / "packet"
    packet.mkdir()
    with zipfile.ZipFile(ROOT / "original-run.zip") as archive:
        archive.extractall(packet)
    report = json.loads((packet / "report.json").read_bytes())
    pins = tmp_path / "outside-pins.json"
    pins.write_bytes((packet / "consumer-pins.json").read_bytes())
    contract = json.loads((ROOT / "source-contract.json").read_bytes())
    policy = {
        "schema": "probity-model-publication-policy-v1",
        "profile": report["profile"],
        "planned": 48,
        "pinsSha256": sha(pins.read_bytes()),
        "readerSha256": contract["files"]["model_task_reader.py"]["sha256"],
        "rows": [
            {k: row[k] for k in ("configuration", "family", "planned")}
            | {"minCorrect": 0, "minFormatValid": 0}
            for row in report["quality"]
        ],
        "limits": {
            "elapsedNs": 60_000_000_000,
            "promptTokens": 24576,
            "completionTokens": 2880,
            "returnedCallProcessCpuNs": 120_000_000_000,
            "processLifetimePeakRssKiB": 524288,
        },
    }
    return packet, pins, policy, report


def invoke(selected, tmp_path, policy=None, timeout=60, packet=None, pins=None):
    original_packet, original_pins, original_policy, _ = selected
    policy_file = tmp_path / "outside-policy.json"
    policy_file.write_bytes(encode(policy if policy is not None else original_policy))
    return gate.gate(
        packet or original_packet,
        pins or original_pins,
        policy_file,
        sha(policy_file.read_bytes()),
        tmp_path / "receipts",
        timeout,
    )


def test_actual_installed_native_report_is_exact(selected, tmp_path):
    result = invoke(selected, tmp_path)
    assert result["publicationDecision"] == "publish"
    assert result["evidenceDecision"] == "verified"
    native = selected[3]
    assert json.loads((tmp_path / "receipts" / "reader.stdout").read_bytes()) == native
    assert sum(row["correct"] for row in native["quality"]) == 0
    assert sum(row["formatValid"] for row in native["quality"]) == 2
    assert result["resources"]["promptTokens"] == 2828
    assert result["resources"]["completionTokens"] == 1840


def test_actual_quality_threshold_refuses_valid_evidence(selected, tmp_path):
    policy = copy.deepcopy(selected[2])
    for row in policy["rows"]:
        row["minCorrect"] = 1
    result = invoke(selected, tmp_path, policy)
    assert result["evidenceDecision"] == "verified"
    assert result["publicationDecision"] == "hold-selected-score-or-resource"
    assert len(result["policyFailures"]) == 8
    assert (tmp_path / "receipts" / "verified-report.json").exists()


@pytest.mark.parametrize("name", gate.LIMIT_KEYS)
def test_actual_resource_threshold_refuses_valid_evidence(selected, tmp_path, name):
    policy = copy.deepcopy(selected[2])
    policy["limits"][name] = 0
    result = invoke(selected, tmp_path, policy)
    assert result["evidenceDecision"] == "verified"
    assert result["publicationDecision"] == "hold-selected-score-or-resource"
    assert any(item.get("resource") == name for item in result["policyFailures"])


def test_native_packet_substitution_refuses(selected, tmp_path):
    (selected[0] / "protocol.json").write_bytes(b"{}")
    result = invoke(selected, tmp_path)
    assert result["evidenceDecision"] == "not-verified"
    assert result["child"]["returncode"] != 0


def test_changed_installed_reader_selection_refuses_before_source_execution(
    selected, tmp_path
):
    policy = copy.deepcopy(selected[2])
    policy["readerSha256"] = "0" * 64
    result = invoke(selected, tmp_path, policy)
    assert result["child"]["returncode"] == 1
    assert (
        "installed reader source differs"
        in (tmp_path / "receipts" / "reader.stdout").read_text()
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "pins",
        "boolean",
        "duplicate-row",
        "missing-row",
        "negative",
        "unknown",
        "profile-type",
    ],
)
def test_policy_selection_refuses_before_launch(selected, tmp_path, mutation):
    policy = copy.deepcopy(selected[2])
    if mutation == "pins":
        policy["pinsSha256"] = "0" * 64
    elif mutation == "boolean":
        policy["rows"][0]["minCorrect"] = False
    elif mutation == "duplicate-row":
        policy["rows"][1] = policy["rows"][0].copy()
    elif mutation == "missing-row":
        policy["rows"].pop()
    elif mutation == "negative":
        policy["limits"]["elapsedNs"] = -1
    elif mutation == "unknown":
        policy["allowDispatch"] = True
    elif mutation == "profile-type":
        policy["profile"] = True
    result = invoke(selected, tmp_path, policy)
    assert not result["launched"]
    assert result["publicationDecision"] == "hold"


@pytest.mark.parametrize("inside", ["pins", "policy", "receipts", "pins-symlink"])
def test_producer_adjacent_selections_refuse(selected, tmp_path, inside):
    packet, pins, policy, _ = selected
    policy_file = tmp_path / "outside-policy.json"
    policy_file.write_bytes(encode(policy))
    output = tmp_path / "receipts"
    if inside == "pins":
        pins = packet / "consumer-pins.json"
    elif inside == "policy":
        policy_file = packet / "policy.json"
        policy_file.write_bytes(encode(policy))
    elif inside == "receipts":
        output = packet / "receipts"
    else:
        pins = tmp_path / "linked-pins.json"
        pins.symlink_to(packet / "consumer-pins.json")
    before = {
        str(p.relative_to(packet)): sha(p.read_bytes())
        for p in packet.rglob("*")
        if p.is_file()
    }
    if inside == "receipts":
        with pytest.raises(ValueError, match="outside producer packet"):
            gate.gate(
                packet, pins, policy_file, sha(policy_file.read_bytes()), output, 60
            )
        assert not output.exists()
    else:
        result = gate.gate(
            packet, pins, policy_file, sha(policy_file.read_bytes()), output, 60
        )
        assert not result["launched"]
    assert before == {
        str(p.relative_to(packet)): sha(p.read_bytes())
        for p in packet.rglob("*")
        if p.is_file()
    }


@pytest.mark.parametrize("timeout", [False, 0, -1, float("nan"), float("inf"), 601])
def test_runtime_selection_refuses_before_launch(selected, tmp_path, timeout):
    result = invoke(selected, tmp_path, timeout=timeout)
    assert not result["launched"]


def test_policy_raw_digest_cannot_be_reselected_from_packet(selected, tmp_path):
    policy = tmp_path / "reviewed.json"
    policy.write_bytes(encode(selected[2]))
    result = gate.gate(
        selected[0], selected[1], policy, "0" * 64, tmp_path / "receipts", 60
    )
    assert not result["launched"]


def test_duplicate_policy_names_refuse(selected, tmp_path):
    policy = tmp_path / "reviewed.json"
    policy.write_bytes(b'{"schema":0,"schema":1}')
    result = gate.gate(
        selected[0],
        selected[1],
        policy,
        sha(policy.read_bytes()),
        tmp_path / "receipts",
        60,
    )
    assert not result["launched"]


def test_existing_receipts_cannot_be_overwritten(selected, tmp_path):
    invoke(selected, tmp_path)
    before = (tmp_path / "receipts" / "gate.json").read_bytes()
    with pytest.raises(FileExistsError):
        invoke(selected, tmp_path)
    assert (tmp_path / "receipts" / "gate.json").read_bytes() == before


def fake_command(tmp_path, monkeypatch, script):
    command = tmp_path / "bin" / "probity-model-task-read"
    command.parent.mkdir()
    command.write_text("#!" + sys.executable + "\n" + script + "\n")
    command.chmod(0o755)
    monkeypatch.setenv("PATH", str(command.parent) + os.pathsep + os.environ["PATH"])


@pytest.mark.parametrize("timeout", [0.001, 0.05])
def test_actual_timeout_is_retained(selected, tmp_path, monkeypatch, timeout):
    fake_command(
        tmp_path,
        monkeypatch,
        'import time; print("started", flush=True); time.sleep(5)',
    )
    result = invoke(selected, tmp_path, timeout=timeout)
    assert result["child"]["timedOut"]
    assert result["child"]["returncode"] is None
    assert result["launched"]
    assert result["evidenceDecision"] == "not-verified"
    assert result["publicationDecision"] == "hold"
    assert result["reason"] == "installed reader timed out or refused selected evidence"
    # The deadline includes Python startup. A killed child can legitimately
    # produce no output; every byte it does produce must remain authenticated.
    stdout = (tmp_path / "receipts" / "reader.stdout").read_bytes()
    assert stdout in (b"", b"started\n")
    for name in ("reader.stdout", "reader.stderr"):
        raw = (tmp_path / "receipts" / name).read_bytes()
        assert result["child"]["streams"][name] == {
            "bytes": len(raw),
            "sha256": sha(raw),
        }
    assert (tmp_path / "receipts" / "launch.json").exists()


def test_nonzero_reader_preserves_streams(selected, tmp_path, monkeypatch):
    fake_command(
        tmp_path,
        monkeypatch,
        'import sys; print("native refusal"); print("details",file=sys.stderr); sys.exit(17)',
    )
    result = invoke(selected, tmp_path)
    assert result["child"]["returncode"] == 17
    assert result["evidenceDecision"] == "not-verified"
    assert "native refusal" in (tmp_path / "receipts" / "reader.stdout").read_text()
    assert "details" in (tmp_path / "receipts" / "reader.stderr").read_text()


@pytest.mark.parametrize(
    "kind",
    [
        "bool-population",
        "bool-row",
        "changed-profile",
        "missing-row",
        "duplicate-row",
        "incomplete",
        "malformed",
        "quality-object",
        "quality-string-row",
        "impossible-correct",
        "changed-token-total",
        "impossible-elapsed",
    ],
)
def test_successful_child_cannot_admit_wrong_report(
    selected, tmp_path, monkeypatch, kind
):
    report = copy.deepcopy(selected[3])
    if kind == "bool-population":
        report["population"]["error"] = False
    elif kind == "bool-row":
        report["quality"][0]["correct"] = False
    elif kind == "changed-profile":
        report["profile"] = "unselected-profile"
    elif kind == "missing-row":
        report["quality"].pop()
    elif kind == "duplicate-row":
        report["quality"][1] = report["quality"][0].copy()
    elif kind == "incomplete":
        report["evidence"]["complete"] = False
    elif kind == "quality-object":
        report["quality"] = {"row": report["quality"][0]}
    elif kind == "quality-string-row":
        report["quality"][0] = "invalid-row"
    elif kind == "impossible-correct":
        report["quality"][0]["formatValid"] = 0
        report["quality"][0]["correct"] = 1
    elif kind == "changed-token-total":
        report["nativeTokens"]["prompt"] += 1
    elif kind == "impossible-elapsed":
        report["quality"][0]["callElapsedNs"] = report["elapsed_ns"] + 1
    source = (
        "print(" + repr(json.dumps(report) if kind != "malformed" else "notjson") + ")"
    )
    fake_command(tmp_path, monkeypatch, source)
    result = invoke(selected, tmp_path)
    assert result["child"]["returncode"] == 0
    assert result["evidenceDecision"] == "not-verified"


def test_model_comparison_identities_are_not_pooled(selected):
    report = copy.deepcopy(selected[3])
    policy = copy.deepcopy(selected[2])
    report["profile"] = policy["profile"] = "probity-local-cpu-model-comparison-v1"
    for rows in (report["quality"], policy["rows"]):
        original = copy.deepcopy(rows)
        rows.clear()
        for model in ("135m", "360m"):
            rows.extend(dict(row, model=model) for row in original)
    report["population"].update(planned=96, started=96, scored=96)
    policy["planned"] = 96
    report["nativeTokens"] = {k: v * 2 for k, v in report["nativeTokens"].items()}
    report["elapsed_ns"] *= 2
    policy["limits"]["completionTokens"] *= 2
    policy["rows"][0]["minCorrect"] = 1
    gate.validate_policy(policy)
    result = gate.decide(report, policy)
    assert len(result["policyFailures"]) == 1
    assert result["policyFailures"][0]["row"]["model"] == "135m"


def test_unselected_reader_bytes_are_not_executed(selected, tmp_path):
    marker = tmp_path / "executed-unselected-code"
    module = tmp_path / "model_task_reader.py"
    module.write_text(
        "from pathlib import Path\nPath("
        + repr(str(marker))
        + ").write_text('executed')\nraise RuntimeError('unselected code')\n"
    )
    child_env = os.environ.copy()
    child_env["PYTHONPATH"] = str(tmp_path)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import model_reader_cli; model_reader_cli.main()",
            str(selected[0]),
            "--pins-file",
            str(selected[1]),
            "--reader-sha256",
            selected[2]["readerSha256"],
        ],
        env=child_env,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1
    assert not marker.exists()
    assert b"installed reader source differs" in result.stdout
