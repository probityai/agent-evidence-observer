"""Verify retained replay examples and preserve existing operator files."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from probity_observer.crypto import canonical

ROOT = Path(__file__).parents[1]


class TestReplayDemo:
    class TestPassingCases:
        def test_command_retains_actual_outcomes_and_all_bytes(
            self, tmp_path: Path
        ) -> None:
            output = tmp_path / "demo"
            process = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "examples/replay_demo.py"),
                    str(output),
                    "--source-revision",
                    "1" * 40,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            report = json.loads(process.stdout)
            assert report["status"] == "demo-passed"
            assert report["fabricatedSuccessDecision"] == "block"
            assert report["missingOwnerOutcome"] == "incomplete"
            assert report["sourceMembership"] == "caller-selected-not-verified"
            manifest = json.loads((output / "replay-manifest.json").read_bytes())[
                "fileSha256"
            ]
            actual = {
                path.relative_to(output).as_posix(): hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
                for path in output.rglob("*")
                if path.is_file() and path.name != "replay-manifest.json"
            }
            assert manifest == actual
            assert "replay-policy.json" in manifest
            assert "mutation-matrix.json" in manifest
            assert "checker-source-manifest.json" in manifest
            assert "checker-source/replay.py" in manifest
            replayed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "examples/replay_demo.py"),
                    str(output),
                    "--replay",
                    "--trusted-policy",
                    str(output / "replay-policy.json"),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            fresh = json.loads(replayed.stdout)
            assert fresh["status"] == "replayed"
            assert fresh["actualReplay"]["decision"] == "replay-acceptable"
            assert fresh["actualReplay"]["reportedOutcomeMismatches"] == []

    class TestFailingCases:
        @pytest.mark.parametrize(
            "filename,key",
            [
                ("consumption-record.json", "signature"),
                ("replay-policy.json", "action_id"),
                ("input-paths.json", "authorization"),
            ],
        )
        def test_duplicate_retained_json_member_never_reaches_gate(
            self, tmp_path: Path, filename: str, key: str
        ) -> None:
            output = tmp_path / "demo"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "examples/replay_demo.py"),
                    str(output),
                    "--source-revision",
                    "1" * 40,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            selected = output / filename
            raw = selected.read_bytes()
            value = json.loads(raw)[key]
            duplicate = (
                raw[:-1] + b"," + canonical(key) + b":" + canonical(value) + b"}"
            )
            selected.write_bytes(duplicate)
            replayed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "examples/replay_demo.py"),
                    str(output),
                    "--replay",
                    "--trusted-policy",
                    str(output / "replay-policy.json"),
                ],
                capture_output=True,
                text=True,
            )
            assert replayed.returncode == 1
            assert "duplicate JSON member" in replayed.stderr
            assert replayed.stdout == ""

        @pytest.mark.parametrize(
            "raw",
            [
                b'{"nested":' * 1500 + b"{}" + b"}" * 1500,
                canonical({"items": [0] * 5000}),
            ],
        )
        def test_retained_record_parser_bounds_are_explicit(
            self, tmp_path: Path, raw: bytes
        ) -> None:
            output = tmp_path / "demo"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "examples/replay_demo.py"),
                    str(output),
                    "--source-revision",
                    "1" * 40,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            (output / "consumption-record.json").write_bytes(raw)
            replayed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "examples/replay_demo.py"),
                    str(output),
                    "--replay",
                    "--trusted-policy",
                    str(output / "replay-policy.json"),
                ],
                capture_output=True,
                text=True,
            )
            assert replayed.returncode == 1
            assert "replay JSON exceeds depth or node bounds" in replayed.stderr
            assert replayed.stdout == ""

        def test_blocked_native_replay_exits_nonzero(self, tmp_path: Path) -> None:
            output = tmp_path / "demo"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "examples/replay_demo.py"),
                    str(output),
                    "--source-revision",
                    "1" * 40,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            matrix = json.loads((output / "mutation-matrix.json").read_bytes())
            control = matrix["fabricated-success"]
            paths = json.loads((output / "input-paths.json").read_bytes())
            (output / paths["observation"]).write_bytes(
                bytes.fromhex(control["mutatedObservationHex"])
            )
            (output / "consumption-record.json").write_bytes(
                canonical(control["record"])
            )
            selected = tmp_path / "explicit-consumer-policy.json"
            selected.write_bytes(canonical(control["policy"]))
            replayed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "examples/replay_demo.py"),
                    str(output),
                    "--replay",
                    "--trusted-policy",
                    str(selected),
                ],
                capture_output=True,
                text=True,
            )
            assert replayed.returncode == 1
            actual = json.loads(replayed.stdout)["actualReplay"]
            assert actual["bindings"]["status"] == "bindings-verified"
            assert actual["decision"] == "block"
            assert actual["reportedOutcomeMismatches"] == ["observation"]

        def test_command_never_overwrites_existing_files(self, tmp_path: Path) -> None:
            original = tmp_path / "operator.txt"
            original.write_bytes(b"keep operator data")
            process = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "examples/replay_demo.py"),
                    str(tmp_path),
                    "--source-revision",
                    "1" * 40,
                ],
                capture_output=True,
                text=True,
            )
            assert process.returncode != 0
            assert "replay output directory must be new or empty" in process.stderr
            assert original.read_bytes() == b"keep operator data"

        def test_command_requires_explicit_source_pin(self, tmp_path: Path) -> None:
            process = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "examples/replay_demo.py"),
                    str(tmp_path / "output"),
                ],
                capture_output=True,
                text=True,
            )
            assert process.returncode == 2
            assert "--source-revision" in process.stderr
            assert not (tmp_path / "output").exists()

        def test_replay_requires_explicit_consumer_policy(self, tmp_path: Path) -> None:
            process = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "examples/replay_demo.py"),
                    str(tmp_path),
                    "--replay",
                ],
                capture_output=True,
                text=True,
            )
            assert process.returncode == 2
            assert "independently selected --trusted-policy" in process.stderr
