"""Rehashed wrapper and nested A2A verdict attacks on a fresh complete packet."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from protocol import digest, encode
from reader import decode, verify


@pytest.fixture(scope="module")
def complete_packet(tmp_path_factory):
    root = tmp_path_factory.mktemp("breadth-parent") / "packet"
    script = Path(__file__).resolve().parents[1] / "run.py"
    subprocess.run([sys.executable, str(script), str(root)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True, timeout=185)
    return root


def repin(root: Path, changed: str) -> dict[str, str]:
    """Select changed artifact hashes to exercise semantic rederivation itself."""
    index = decode((root / "artifact-index.json").read_bytes())
    index[changed] = digest((root / changed).read_bytes())
    (root / "artifact-index.json").write_bytes(encode(index))
    return {"declaration_sha256": digest((root / "declaration-before-run.json").read_bytes()), "index_sha256": digest((root / "artifact-index.json").read_bytes())}


class TestRetainedPacket:
    class TestPassingCases:
        def test_fresh_original_and_offline_native_reconstruction(self, complete_packet):
            pins = decode((complete_packet / "consumer-pins.json").read_bytes())
            result = verify(complete_packet, pins)
            assert result["populations"]["tools"]["complete"] == 12
            assert result["a2a"]["original_report"]["planned"] == 6
            assert result["a2a"]["original_report"]["unknown_start"] == 1
            assert result["aggregate_score"] is None

    class TestFailingCases:
        @pytest.mark.parametrize("mutation,reason", [("wrapper", "report_mapping_mismatch"), ("a2a-summary", "a2a_launch_report_join"), ("launch-time", "launch_resource"), ("solver", "native_solver"), ("configuration", "native_configuration")])
        def test_rehashed_changes_still_refuse(self, mutation, reason, complete_packet, tmp_path, caplog):
            root = tmp_path / "packet"
            shutil.copytree(complete_packet, root)
            changed = "report.json"
            if mutation == "wrapper":
                value = decode((root / changed).read_bytes())
                value["records"][0]["authority"] = "pass"
            elif mutation == "a2a-summary":
                changed = "a2a-launch.json"
                value = decode((root / changed).read_bytes())
                value["original_report"]["task_passed"] = 2
            elif mutation == "launch-time":
                changed = "cases/reason-01/launch.json"
                value = decode((root / changed).read_bytes())
                value["elapsed_ns"] = True
            else:
                changed = "cases/reason-01/native.json"
                value = decode((root / changed).read_bytes())
                if mutation == "solver":
                    value["plan"]["steps"] = []
                else:
                    value["eval"]["config"]["epochs"] = 2
            (root / changed).write_bytes(encode(value))
            pins = decode((root / "consumer-pins.json").read_bytes()) if changed == "report.json" else repin(root, changed)
            with pytest.raises(ValueError, match=f"^{reason}$"):
                verify(root, pins)
            assert caplog.records[-1].getMessage() == reason

        def test_raw_packet_change_without_external_pin_refused(self, complete_packet, tmp_path, caplog):
            root = tmp_path / "packet"
            shutil.copytree(complete_packet, root)
            pins = decode((root / "consumer-pins.json").read_bytes())
            (root / "runtime.json").write_bytes(b"{}")
            with pytest.raises(ValueError, match="^artifact_pin_mismatch$"):
                verify(root, pins)
            assert caplog.records[-1].getMessage() == "artifact_pin_mismatch"
