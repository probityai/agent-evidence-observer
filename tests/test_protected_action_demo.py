"""Operator-facing integration tests for the retained signed-action bundle."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from pathlib import Path

import pytest

EXAMPLE = Path(__file__).parents[1] / "examples" / "protected_action_demo.py"
SPEC = importlib.util.spec_from_file_location("protected_action_demo", EXAMPLE)
assert SPEC is not None and SPEC.loader is not None
DEMO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEMO)


class TestProtectedActionDemo:
    class TestPassingCases:
        def test_real_effect_refusals_and_persisted_decision(
            self, tmp_path: Path
        ) -> None:
            output = tmp_path / "run"
            report = DEMO.run_demo(output)
            assert report["status"] == "demo-passed"
            assert report["acceptedWrites"] == 1
            assert report["retryReplayed"] is True
            assert report["admissionStatus"] == "admitted"
            assert report["witnessScope"] == "PEER"
            assert report["operator"] == "same-operator-fixture"
            assert len(report["refusals"]) == 13
            assert report["refusals"]["consumer-replay"] == (
                "interval was already admitted by this consumer"
            )
            assert (output / "producer/workspace/result.txt").read_bytes() == (
                b"one authorized durable effect\n"
            )
            state = json.loads((output / "consumer/state.json").read_bytes())
            assert len(state["admissions"]) == 1

        def test_manifest_binds_every_retained_file(self, tmp_path: Path) -> None:
            output = tmp_path / "run"
            DEMO.run_demo(output)
            manifest = json.loads((output / "manifest.json").read_bytes())["fileSha256"]
            actual = {
                path.relative_to(output).as_posix(): hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
                for path in output.rglob("*")
                if path.is_file() and path.name != "manifest.json"
            }
            assert actual == manifest
            assert "producer/grant.json" in manifest
            assert "producer/packet.json" in manifest
            assert "consumer/authorization-result.json" in manifest
            assert "consumer/state.json" in manifest

    class TestFailingCases:
        def test_existing_output_is_preserved(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture
        ) -> None:
            existing = tmp_path / "operator-data.json"
            original = b"private operator data\n"
            existing.write_bytes(original)
            expected = "protected action output directory must be empty"
            with pytest.raises(ValueError, match=re.escape(expected)) as caught:
                DEMO.run_demo(tmp_path)
            assert str(caught.value) == expected
            assert existing.read_bytes() == original
            assert caplog.text == ""
