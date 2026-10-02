"""Exact native originals, separate replay and retained negative pair outcomes."""

import hashlib
import json
import stat
import zipfile
from pathlib import Path, PurePosixPath

from task_matrix import verify


def test_original_native_packet_exact_replay(tmp_path):
    root = Path(__file__).parents[1]
    results = root / "results"
    archive = results / "boundary-cpu-native-37060702246.zip"
    acquisition = json.loads((results / "acquisition-37060702246.json").read_bytes())
    report_raw = (results / "boundary-cpu-37060702246.json").read_bytes()
    assert (
        hashlib.sha256(archive.read_bytes()).hexdigest()
        == "d8ff26e82aca136daf734da65ede259b2bfaed9dd547ba25b92d65bdeeef019f"
    )
    assert (
        hashlib.sha256(report_raw).hexdigest()
        == "fa7b0e39b69bcd42f82fc93096e071b534557c34cf0e03e73e1bac56dcdd72af"
    )
    with zipfile.ZipFile(archive) as packet:
        assert packet.read("report.json") == report_raw
        assert (
            packet.read("sources/task_matrix.py")
            == (root / "task_matrix.py").read_bytes()
        )
        for item in packet.infolist():
            path = PurePosixPath(item.filename)
            assert not path.is_absolute() and ".." not in path.parts
            assert not stat.S_ISLNK(item.external_attr >> 16)
        packet.extractall(tmp_path)
    expected = json.loads(report_raw)
    actual = verify(tmp_path, acquisition["consumerPins"])
    assert actual == expected
    assert actual["population"] == {
        "planned": 384,
        "started": 384,
        "scored": 384,
        "error": 0,
        "incomplete": 0,
        "unsupported": 0,
        "unknown-start": 0,
    }
    assert actual["process_cpu_ns"] == 497394631919
    assert (
        sum(
            row["schemaValid"]
            for row in actual["quality"]
            if row["decoder"] == "schema"
        )
        == 192
    )
    assert all(
        row["fullyCorrectPairs"] == 0
        for row in actual["quality"]
        if row["family"] in {"policy-boundary", "grounded-boundary"}
    )
    cases = json.loads((root / "protocol.json").read_bytes())["cases"]
    assert len(cases) == 48 and len({case["input"] for case in cases}) == 46
