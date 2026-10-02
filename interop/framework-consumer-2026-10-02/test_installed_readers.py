"""Replay retained native packets through normally installed reader commands."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest
import rfc8785

ROOT = Path(__file__).resolve().parent
ARCHIVES = {
    "langgraph": "e2e28cfcd4af7fc4dbff2fa91640fd2fc23b95e2d32369d75551a264b118b8fd",
    "pydantic": "e79cf593e91902f1ce4b483850a6f3dba186637e5f223e0931cf8333384782d2",
}


def selected_packet(profile: str, destination: Path) -> tuple[Path, Path]:
    """Authenticate the original CI archive, then select its historical pins.

    Parameters
    ----------
    profile : str
        Named native framework fixture.
    destination : Path
        Fresh test directory, separate from the retained original.

    Returns
    -------
    tuple of Path
        Extracted packet and separately copied local consumer policy.
        Copying author pins for a test does not establish outside selection.
    """
    archive = ROOT / "fixtures" / (profile + ".zip")
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == ARCHIVES[profile]
    with zipfile.ZipFile(archive) as bundle:
        bundle.extractall(destination)
    packet = destination / "fresh-run"
    if profile == "pydantic":
        packet /= "packet"
    policy = destination / "selected-pins.json"
    policy.write_bytes((packet / "consumer-pins.json").read_bytes())
    return packet, policy


def invoke(profile: str, packet: Path, policy: Path | None) -> subprocess.CompletedProcess[str]:
    """Execute the installed command with bounded runtime and retained errors."""
    command = [str(Path(sys.executable).parent / ("probity-" + profile + "-read")), str(packet)]
    if policy is not None:
        command.extend(["--pins-file", str(policy)])
    return subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)


def alter_selected_artifact(packet: Path, policy: Path, relative: str,
                            field: list[str | int], value: Any) -> None:
    """Reselect an altered artifact to test semantics beyond byte pin checks."""
    path = packet / relative
    document = json.loads(path.read_bytes())
    parent = document
    for key in field[:-1]:
        parent = parent[key]
    parent[field[-1]] = value
    raw = rfc8785.dumps(document)
    path.write_bytes(raw)
    manifest_path = packet / "artifact-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest[path.name] = hashlib.sha256(raw).hexdigest()
    manifest_raw = rfc8785.dumps(manifest)
    manifest_path.write_bytes(manifest_raw)
    selected = json.loads(policy.read_bytes())
    selected["artifactManifestSha256"] = hashlib.sha256(manifest_raw).hexdigest()
    policy.write_bytes(rfc8785.dumps(selected))


class TestInstalledReaders:
    class TestPassingCases:
        @pytest.mark.parametrize("profile,count", [("langgraph", 6), ("pydantic", 5)])
        def test_original_native_packet(self, profile: str, count: int, tmp_path: Path) -> None:
            packet, policy = selected_packet(profile, tmp_path)
            result = invoke(profile, packet, policy)
            assert result.returncode == 0, result.stderr
            report = json.loads(result.stdout)
            assert report == json.loads((packet / "report.json").read_bytes())
            assert report["status"] == "verified" and report["plannedAttempts"] == count
            assert report["independentCustody"] == "not-established"

        def test_reader_environment_has_no_agent_framework(self) -> None:
            for name in ("langgraph", "pydantic_ai", "inspect_ai"):
                assert importlib.util.find_spec(name) is None

    class TestFailingCases:
        @pytest.mark.parametrize("profile", ["langgraph", "pydantic"])
        def test_explicit_pins_required(self, profile: str, tmp_path: Path) -> None:
            packet, _ = selected_packet(profile, tmp_path)
            result = invoke(profile, packet, None)
            assert result.returncode == 2
            assert "--pins-file" in result.stderr

        @pytest.mark.parametrize("profile,field", [
            ("langgraph", "planSha256"), ("langgraph", "artifactManifestSha256"),
            ("pydantic", "planSha256"), ("pydantic", "sourceManifestSha256"),
            ("pydantic", "artifactManifestSha256"),
        ])
        def test_wrong_selected_pin(self, profile: str, field: str, tmp_path: Path) -> None:
            packet, policy = selected_packet(profile, tmp_path)
            selected = json.loads(policy.read_bytes())
            selected[field] = "0" * 64
            policy.write_bytes(rfc8785.dumps(selected))
            result = invoke(profile, packet, policy)
            assert result.returncode == 1
            assert json.loads(result.stdout)["status"] == "refused"

        @pytest.mark.parametrize("profile,relative,field,value,reason", [
            ("langgraph", "attempts/permit.json", ["http", 0, "candidate", "contentHex"],
             "00", "http-argument-binding"),
            ("langgraph", "attempts/permit.json",
             ["history", 0, "parent_config", "configurable", "checkpoint_id"],
             "other", "native-history-parent"),
            ("pydantic", "artifacts/retry-execution.json", ["trace"], [],
             "native dispatch population differs"),
            ("pydantic", "artifacts/producer-error-execution.json", ["terminal"],
             {"status": "complete", "output": "complete", "exception": None},
             "producer error terminal differs"),
        ])
        def test_reselected_semantic_substitution(self, profile: str, relative: str,
                field: list[str | int], value: Any, reason: str, tmp_path: Path) -> None:
            packet, policy = selected_packet(profile, tmp_path)
            alter_selected_artifact(packet, policy, relative, field, value)
            result = invoke(profile, packet, policy)
            assert result.returncode == 1
            assert json.loads(result.stdout) == {"status": "refused", "reason": reason}
            assert reason in result.stderr
