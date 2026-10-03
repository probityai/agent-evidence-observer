"""Host publication selection controls; actual wheel execution is a CI stage."""
from __future__ import annotations

import copy
import logging
import sys
from pathlib import Path
from typing import Any

import pytest
from probity_observer.crypto import VerificationError, canonical

from joint_host_gate import admit, gate, reader_closure, select
from joint_common import CASES, PROFILE, sha, write


def selected_files(tmp_path: Path, report: dict[str, Any]) -> tuple[Path, Path, Path, str, Path]:
    """Create a miniature process fixture for selection/refusal controls only.

    These deliberately nonreader files test the gate's filesystem boundary;
    the separately retained normal-wheel positive execution and CI stage use
    the real installed reader. The fixture never claims normal reader output.
    """
    packet = tmp_path / "packet"
    packet.mkdir()
    pins = tmp_path / "selected-pins.json"
    write(pins, {"profile": PROFILE, "selectedNativeReport": sha(canonical(report))})
    policy = tmp_path / "host-policy.json"
    prefix = tmp_path / "installed-reader"
    (prefix / "bin").mkdir(parents=True)
    (prefix / "bin/python").symlink_to(Path(sys.executable).resolve())
    (prefix / "pyvenv.cfg").write_text("home = " + str(Path(sys.executable).resolve().parent) + "\ninclude-system-site-packages = false\n")
    site = prefix / f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
    site.mkdir(parents=True)
    reader = prefix / "bin/probity-read-joint-recovery"
    reader.write_text("#!" + str(prefix / "bin/python") + "\nimport sys\nsys.stderr.write('nonreader fixture refused\\n')\nraise SystemExit(17)\n")
    reader.chmod(0o755)
    fixture_modules(site)
    write(policy, {"profile": PROFILE, "pinsSha256": sha(pins.read_bytes()), "plannedAttempts": len(CASES), "readerSha256": sha(reader.read_bytes()), "readerClosure": reader_closure(reader)})
    return packet, pins, policy, sha(policy.read_bytes()), reader


def fixture_modules(site: Path) -> None:
    """Create explicit tiny package identities without importing their code."""
    for name in ["probity-joint-recovery-reader", "agent-evidence-observer"]:
        metadata = site / (name + "-0.0.1.dist-info/METADATA")
        metadata.parent.mkdir()
        metadata.write_text("Metadata-Version: 2.1\nName: " + name + "\nVersion: 0.0.1\n")
    (site / "probity_observer").mkdir()
    for name in ["joint_reader.py", "joint_common.py", "probity_observer/crypto.py"]:
        (site / name).write_text("raise RuntimeError('nonreader fixture')\n")


class TestHostGate:
    """Publication is a host-selected report decision, separate from action rights."""

    class TestPassingCases:
        def test_native_report_contains_refusals_and_is_publishable(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]]) -> None:
            report = fresh[2]
            assert sum(not row["releasedResult"] for row in report["records"]) == 16
            admit(canonical(report))

        def test_separate_literal_selection_is_frozen(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]], tmp_path: Path) -> None:
            packet, pins, policy, digest, reader = selected_files(tmp_path, fresh[2])
            output = tmp_path / "host-receipts"
            output.mkdir()
            select(packet, pins, policy, digest, reader, output)
            assert (output / "host-policy.json").read_bytes() == policy.read_bytes()
            assert (output / "selected-pins.json").read_bytes() == pins.read_bytes()
            assert (output / "selected-pins.json").stat().st_mode & 0o777 == 0o400

    class TestFailingCases:
        def test_revoked_row_cannot_release_with_unchanged_totals(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]], caplog: pytest.LogCaptureFixture) -> None:
            report = copy.deepcopy(fresh[2])
            next(row for row in report["records"] if row["id"] == "revoked-after")["releasedResult"] = True
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^reader-case-disposition$"):
                admit(canonical(report))
            assert "Joint recovery refused: reader-case-disposition" in caplog.messages

        @pytest.mark.parametrize("name", ["joint_reader.py", "joint_common.py", "probity_observer/crypto.py", "sitecustomize.py", "__pycache__/joint_reader.cpython.pyc"])
        def test_module_swap_or_injection_refused_before_launch(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]], tmp_path: Path, caplog: pytest.LogCaptureFixture, name: str) -> None:
            packet, pins, policy, digest, reader = selected_files(tmp_path, fresh[2])
            prefix = reader.parent.parent
            module = next(prefix.glob("lib/python*/site-packages")) / name
            module.parent.mkdir(parents=True, exist_ok=True)
            module.write_bytes(b"changed installed verification source")
            output = tmp_path / "host-receipts"
            with caplog.at_level(logging.WARNING):
                decision = gate(packet, pins, policy, digest, reader, output)
            assert decision["reason"] == "reader-installed-closure"
            assert decision["readerReturncode"] is None
            assert not (output / "launch.json").exists()
            assert "Joint recovery refused: reader-installed-closure" in caplog.messages

        @pytest.mark.parametrize("field,value,reason", [("plannedAttempts", True, "reader-population"), ("workerProcesses", 39, "reader-population"), ("targetProcesses", 37, "reader-population"), ("releasedResults", 19, "reader-population"), ("priorAuthenticEffects", 12, "reader-population"), ("pendingRefusals", 0, "reader-population"), ("startupRefusals", 0, "reader-population"), ("concurrentCallers", False, "reader-population"), ("witnessScope", "HOST", "reader-scope"), ("doesNotAssert", [], "reader-scope")])
        def test_reselected_reader_output_refused(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]], caplog: pytest.LogCaptureFixture, field: str, value: Any, reason: str) -> None:
            report = {**fresh[2], field: value}
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^" + reason + "$"):
                admit(canonical(report))
            assert "Joint recovery refused: " + reason in caplog.messages

        def test_swapped_reader_refused(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]], tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
            packet, pins, policy, digest, _ = selected_files(tmp_path, fresh[2])
            reader = tmp_path / "different-reader"
            reader.write_bytes(b"different executable")
            output = tmp_path / "host-receipts"
            output.mkdir()
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^host-selection$"):
                select(packet, pins, policy, digest, reader, output)
            assert "Joint recovery refused: host-selection" in caplog.messages

        def test_candidate_self_selection_refused(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]], tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
            packet, pins, policy, digest, reader = selected_files(tmp_path, fresh[2])
            internal = packet / pins.name
            internal.write_bytes(pins.read_bytes())
            output = tmp_path / "host-receipts"
            output.mkdir()
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^selection-must-be-outside-packet$"):
                select(packet, internal, policy, digest, reader, output)
            assert "Joint recovery refused: selection-must-be-outside-packet" in caplog.messages

        def test_actual_nonreader_process_cannot_publish(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]], tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
            packet, pins, policy, digest, reader = selected_files(tmp_path, fresh[2])
            output = tmp_path / "host-receipts"
            with caplog.at_level(logging.WARNING):
                report = gate(packet, pins, policy, digest, reader, output)
            assert report["decision"] == "refuse"
            assert report["reason"] == "reader-refused"
            assert report["readerReturncode"] != 0
            assert (output / "reader.stderr").read_bytes()
            assert "Joint recovery refused: reader-refused" in caplog.messages

        def test_case_omission_refused(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]], caplog: pytest.LogCaptureFixture) -> None:
            report = copy.deepcopy(fresh[2])
            report["records"].pop()
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^reader-case-population$"):
                admit(canonical(report))
            assert "Joint recovery refused: reader-case-population" in caplog.messages
