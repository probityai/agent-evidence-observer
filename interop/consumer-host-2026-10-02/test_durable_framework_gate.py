"""Publication gate admits the explicitly selected durable installed profile only."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("durable_reader_fixtures", HERE.parent / "framework-consumer-2026-10-02/test_durable_installed_reader.py")
assert spec is not None and spec.loader is not None
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


def selected(tmp: Path, change: str | None) -> tuple[Path, Path, Path, str]:
    """Freeze external host policy and original packet pins before child launch."""
    packet, pins = fixtures.selected_durable_packet(tmp / "original")
    policy = tmp / "host-policy.json"
    value = {"schema": "probity-framework-host-gate-v2", "reader": "langgraph-durable", "profile": "probity-langgraph-durable-restart-v0", "plannedAttempts": 6, "pinsSha256": hashlib.sha256(pins.read_bytes()).hexdigest()}
    changes = {"v1-new-reader": {"schema": "probity-framework-host-gate-v1"}, "v2-historical-reader": {"reader": "langgraph"}, "wrong-profile": {"profile": "probity-langgraph-aae-ticket-v0"}, "wrong-count": {"plannedAttempts": 5}, "boolean-count": {"plannedAttempts": True}}
    value.update(changes.get(change, {}))
    policy.write_text(json.dumps(value))
    digest = hashlib.sha256(policy.read_bytes()).hexdigest()
    if change == "pins-digest":
        pins.write_text("{}")
    if change == "reader-refusal":
        (packet / "artifact-manifest.json").write_text("{}")
    return packet, pins, policy, "0" * 64 if change == "policy-digest" else digest


def invoke(tmp: Path, change: str | None = None) -> subprocess.CompletedProcess[str]:
    """Run the actual installed durable reader through the public host wrapper."""
    packet, pins, policy, digest = selected(tmp, change)
    return subprocess.run([sys.executable, str(HERE / "framework_gate.py"), "--packet", str(packet), "--pins", str(pins), "--policy", str(policy), "--policy-sha256", digest, "--reader-bin", str(Path(sys.executable).parent), "--output", str(tmp / "receipt")], capture_output=True, text=True, timeout=60, check=False)


class TestDurableFrameworkGate:
    class TestPassingCases:
        def test_original_bounded_report_admitted(self, tmp_path: Path) -> None:
            result = invoke(tmp_path)
            assert result.returncode == 0, result.stdout + result.stderr
            receipt = tmp_path / "receipt"
            report = json.loads((receipt / "report.json").read_bytes())
            assert report["profile"] == "probity-langgraph-durable-restart-v0"
            assert report["records"][3]["effectOutcome"] == "incomplete-no-automatic-replay"
            assert report["records"][4]["recoveryOutcome"] == "refused-missing-checkpoint"
            assert report["exactlyOnce"] == report["independentCustody"] == "not-established"
            launch = json.loads((receipt / "launch.json").read_bytes())["command"]
            assert Path(launch[0]).name == "probity-langgraph-durable-read"
            assert Path(launch[-1]) == (receipt / "selected-pins.json").resolve()
            assert (receipt / "report.json").read_bytes() == (receipt / "reader.stdout").read_bytes()
            assert json.loads((receipt / "child-status.json").read_bytes())["returncode"] == 0

    class TestFailingCases:
        @pytest.mark.parametrize("change", ["v1-new-reader", "v2-historical-reader", "wrong-profile", "wrong-count", "boolean-count", "policy-digest", "pins-digest", "reader-refusal"])
        def test_refusal_before_publication(self, tmp_path: Path, change: str) -> None:
            result = invoke(tmp_path, change)
            assert result.returncode == 1
            receipt = tmp_path / "receipt"
            assert json.loads((receipt / "gate.json").read_bytes())["status"] == "refused"
            assert not (receipt / "report.json").exists()
            if change == "reader-refusal":
                assert json.loads((receipt / "child-status.json").read_bytes())["returncode"] == 1
            else:
                assert not (receipt / "launch.json").exists()
