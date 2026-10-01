"""Exercise the retained consumption bundle through the public command."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path


class TestAttributionDemo:
    class TestPassingCases:
        def test_demo_retains_inputs_and_refusals(self, tmp_path):
            root = Path(__file__).parents[1]
            output = tmp_path / "demo"
            result = subprocess.run(
                [
                    sys.executable,
                    str(root / "examples/attribution_demo.py"),
                    str(output),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            report = json.loads(result.stdout)
            assert report["status"] == "bindings-verified"
            assert set(report["refusals"]) == {
                "wrong-action",
                "wrong-claim",
                "substituted-input",
                "missing-receipt",
            }
            record = json.loads(
                (output / "consumer/consumption-record.json").read_bytes()
            )
            assert {check["role"] for check in record["payload"]["checks"]} == {
                "authorization",
                "observation",
            }
            manifest = json.loads((output / "manifest.json").read_bytes())["fileSha256"]
            for name, expected in manifest.items():
                assert (
                    hashlib.sha256((output / name).read_bytes()).hexdigest() == expected
                )

    class TestFailingCases:
        def test_demo_preserves_existing_operator_data(self, tmp_path, caplog):
            root = Path(__file__).parents[1]
            original = tmp_path / "operator.txt"
            original.write_bytes(b"keep this")
            result = subprocess.run(
                [
                    sys.executable,
                    str(root / "examples/attribution_demo.py"),
                    str(tmp_path),
                ],
                capture_output=True,
                text=True,
            )
            assert result.returncode != 0
            assert result.stderr.strip().endswith(
                "ValueError: protected action output directory must be empty"
            )
            assert caplog.records == []
            assert original.read_bytes() == b"keep this"
