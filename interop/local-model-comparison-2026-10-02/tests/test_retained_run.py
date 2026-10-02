"""Replay exact retained native originals without importing an inference backend."""

import json
import zipfile
from pathlib import Path

from task_matrix import digest, verify


def test_retained_original_96_call_packet_reproduces_selected_report(tmp_path):
    results = Path(__file__).parents[1] / "results"
    acquisition = json.loads((results / "acquisition-37053301748.json").read_bytes())
    selected = acquisition["compactArtifact"]
    archive = results / selected["retainedPath"]
    assert digest(archive.read_bytes()) == selected["providerSHA256"]
    with zipfile.ZipFile(archive) as packet:
        packet.extractall(tmp_path)
        assert (
            digest(packet.read("sources/task_matrix.py"))
            == acquisition["nativeRunnerSHA256"]
        )
        assert (
            packet.read("report.json")
            == (results / "paired-cpu-37053301748.json").read_bytes()
        )
    original = json.loads((tmp_path / "report.json").read_bytes())
    replayed = verify(tmp_path, acquisition["consumerPins"])
    assert replayed == original
    assert replayed["population"] == {
        "planned": 96,
        "started": 96,
        "scored": 96,
        "error": 0,
        "incomplete": 0,
        "unknown-start": 0,
    }
    assert (
        sum(
            row["correct"]
            for row in replayed["quality"]
            if row["model"] == "smol135-q4"
        )
        == 0
    )
    assert (
        sum(
            row["correct"]
            for row in replayed["quality"]
            if row["model"] == "smol360-q4"
        )
        == 8
    )
