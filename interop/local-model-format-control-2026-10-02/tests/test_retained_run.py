"""Replay real originals and verify the unchanged unconstrained baseline."""

import json
import zipfile
from pathlib import Path

from task_matrix import digest, verify


def test_original_192_call_packet_and_96_unconstrained_outputs_replay_exactly(tmp_path):
    root = Path(__file__).parents[1]
    results = root / "results"
    acquisition = json.loads((results / "acquisition-37056945285.json").read_bytes())
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
            == (results / "format-cpu-37056945285.json").read_bytes()
        )
    original = json.loads((tmp_path / "report.json").read_bytes())
    assert verify(tmp_path, acquisition["consumerPins"]) == original
    assert original["population"] == {
        "planned": 192,
        "started": 192,
        "scored": 192,
        "error": 0,
        "unsupported": 0,
        "incomplete": 0,
        "unknown-start": 0,
    }
    earlier = json.loads(
        root.parent.joinpath(
            "local-model-comparison-2026-10-02/results/paired-cpu-37053301748.json"
        ).read_bytes()
    )
    baseline = {row["id"]: row for row in earlier["attempts"]}
    unconstrained = [
        row for row in original["attempts"] if row["decoder"] == "unconstrained"
    ]
    assert len(unconstrained) == 96
    assert all(
        row["output"] == baseline[row["id"].replace("--unconstrained", "")]["output"]
        for row in unconstrained
    )
    constrained = [row for row in original["attempts"] if row["decoder"] == "schema"]
    assert len(constrained) == 96 and all(
        row["schemaValid"] is True for row in constrained
    )
    assert (
        sum(row["correct"] for row in constrained if row["model"] == "smol135-q4") == 10
    )
    assert (
        sum(row["correct"] for row in constrained if row["model"] == "smol360-q4") == 26
    )
