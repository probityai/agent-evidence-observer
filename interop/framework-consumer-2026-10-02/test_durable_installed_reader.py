"""Source-selected wheel upgrade controls over the original Ubuntu restart packet."""
from __future__ import annotations

import hashlib
import importlib.metadata
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
DURABLE_ARCHIVE_SHA256 = "53226e9a77526c67c759e582b9f40b4512fff78ca64fad99bc99d2e5a4d97ed8"


def selected_durable_packet(destination: Path) -> tuple[Path, Path]:
    """Authenticate the original successful Ubuntu ZIP and externally copy pins."""
    archive = ROOT / "fixtures/langgraph-durable.zip"
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == DURABLE_ARCHIVE_SHA256
    with zipfile.ZipFile(archive) as bundle:
        assert all(not Path(name).is_absolute() and ".." not in Path(name).parts for name in bundle.namelist())
        bundle.extractall(destination)
    packet = destination / "durable-run"
    policy = destination / "selected-durable-pins.json"
    policy.write_bytes((packet / "consumer-pins.json").read_bytes())
    return packet, policy


def invoke(packet: Path, pins: Path | None, command: str = "probity-langgraph-durable-read") -> subprocess.CompletedProcess[str]:
    """Run the installed command from its environment without source PYTHONPATH."""
    args = [str(Path(sys.executable).parent / command), str(packet)]
    if pins is not None:
        args += ["--pins-file", str(pins)]
    return subprocess.run(args, capture_output=True, text=True, timeout=30, check=False)


def mutate_artifact(packet: Path, pins: Path, name: str, path: list[str | int], value: Any) -> None:
    """Reselect adversarial evidence while retaining consumer plan selection."""
    target = packet / "attempts" / (name + ".json")
    artifact = json.loads(target.read_bytes())
    parent = artifact
    for field in path[:-1]:
        parent = parent[field]
    parent[path[-1]] = value
    raw = rfc8785.dumps(artifact)
    target.write_bytes(raw)
    manifest_path = packet / "artifact-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest[target.name] = hashlib.sha256(raw).hexdigest()
    raw = rfc8785.dumps(manifest)
    manifest_path.write_bytes(raw)
    selection = json.loads(pins.read_bytes())
    selection["artifactManifestSha256"] = hashlib.sha256(raw).hexdigest()
    pins.write_bytes(rfc8785.dumps(selection))


MUTATIONS = [
    ("restart-before", ["firstProcess", "exitCode"], 0, "first-hard-exit"),
    ("restart-before", ["second", "pid"], None, "distinct-processes"),
    ("restart-before", ["second", "loaded", "config", "configurable", "checkpoint_id"], "other", "durable-restart-snapshot"),
    ("restart-before", ["second", "http", 0, "candidate", "contentHex"], "00", "http-argument-binding"),
    ("restart-before", ["second", "history", 0, "parent_config", "configurable", "checkpoint_id"], "other", "native-history-parent"),
    ("restart-pending", ["second", "http", 0, "postStatus"], 200, "pending-response-status"),
    ("missing-checkpoint", ["second", "status"], "completed", "recovery-refusal"),
    ("wrong-thread", ["second", "loaded", "next"], ["dispatch"], "missing-checkpoint-no-task"),
]


class TestDurableInstalledReader:
    class TestPassingCases:
        def test_all_original_native_cases(self, tmp_path: Path) -> None:
            packet, pins = selected_durable_packet(tmp_path)
            result = invoke(packet, pins)
            assert result.returncode == 0, result.stderr
            report = json.loads(result.stdout)
            assert report == json.loads((packet / "report.json").read_bytes())
            assert report["plannedAttempts"] == 6 and len(report["records"]) == 6
            assert report["records"][3]["effectOutcome"] == "incomplete-no-automatic-replay"
            assert report["records"][4]["effectOutcome"] == "refused-no-local-row"
            assert report["exactlyOnce"] == report["independentCustody"] == "not-established"
            assert importlib.metadata.version("probity-langgraph-ticket-reader") == "0.0.2"

        def test_installed_source_bytes_and_no_producers(self) -> None:
            contract = json.loads((ROOT / "FRAMEWORK-DURABLE-CONSUMER-CONTRACT-2026-10-02.json").read_bytes())
            for name in ("lg_common", "lg_reader", "durable_reader", "probity_langgraph_reader_cli", "probity_langgraph_durable_reader_cli"):
                installed = importlib.metadata.distribution("probity-langgraph-ticket-reader").locate_file(name + ".py")
                assert installed.is_file()
                selected = next(pin for path, pin in contract["source_files"].items() if Path(path).name == name + ".py")
                assert hashlib.sha256(installed.read_bytes()).hexdigest() == selected["sha256"]
            observer = importlib.metadata.distribution("agent-evidence-observer")
            for path, selected in contract["source_files"].items():
                if path.startswith("src/probity_observer/"):
                    installed = observer.locate_file(path.removeprefix("src/"))
                    assert hashlib.sha256(installed.read_bytes()).hexdigest() == selected["sha256"]
            for name in ("langgraph", "pydantic_ai", "lg_run", "durable_run", "durable_worker"):
                assert importlib.util.find_spec(name) is None

    class TestFailingCases:
        def test_explicit_pins_required(self, tmp_path: Path) -> None:
            packet, _ = selected_durable_packet(tmp_path)
            result = invoke(packet, None)
            assert result.returncode == 2 and "--pins-file" in result.stderr

        @pytest.mark.parametrize("field", ["planSha256", "artifactManifestSha256"])
        def test_wrong_selected_pin(self, tmp_path: Path, field: str) -> None:
            packet, pins = selected_durable_packet(tmp_path)
            selected = json.loads(pins.read_bytes())
            selected[field] = "0" * 64
            pins.write_bytes(rfc8785.dumps(selected))
            result = invoke(packet, pins)
            assert result.returncode == 1 and json.loads(result.stdout)["status"] == "refused"

        @pytest.mark.parametrize("name,path,value,reason", MUTATIONS)
        def test_reselected_native_substitution(self, tmp_path: Path, name: str, path: list, value: Any, reason: str) -> None:
            packet, pins = selected_durable_packet(tmp_path)
            mutate_artifact(packet, pins, name, path, value)
            result = invoke(packet, pins)
            assert result.returncode == 1
            assert json.loads(result.stdout) == {"status": "refused", "reason": reason}

        def test_historical_command_refuses_durable_profile(self, tmp_path: Path) -> None:
            packet, pins = selected_durable_packet(tmp_path)
            result = invoke(packet, pins, "probity-langgraph-read")
            assert result.returncode == 1
            assert json.loads(result.stdout)["reason"] == "plan-profile"

        def test_durable_command_refuses_historical_profile(self, tmp_path: Path) -> None:
            packet, _ = selected_durable_packet(tmp_path)
            historical = packet.parent / "fresh-run"
            pins = tmp_path / "selected-historical-pins.json"
            pins.write_bytes((historical / "consumer-pins.json").read_bytes())
            result = invoke(historical, pins)
            assert result.returncode == 1
            assert json.loads(result.stdout)["reason"] == "plan-profile"


@pytest.mark.parametrize("name", ["interop/langgraph-ticket-2026-10-02/lg_reader.py", "interop/langgraph-ticket-2026-10-02/durable_reader.py", "interop/framework-consumer-2026-10-02/probity_langgraph_durable_reader_cli.py", "interop/framework-consumer-2026-10-02/FRAMEWORK-LANGGRAPH-DURABLE-READER-2026-10-02.toml", "pyproject.toml", "interop/framework-consumer-2026-10-02/FRAMEWORK-CONSUMER-REQUIREMENTS-2026-10-02.lock"])
def test_source_or_metadata_upgrade_requires_reselection(name: str, tmp_path: Path) -> None:
    """Refuse replaced source/metadata bytes before building any output wheel."""
    import os
    import shutil
    root = ROOT.parents[1]
    selection = json.loads((ROOT / "FRAMEWORK-DURABLE-CONSUMER-CONTRACT-2026-10-02.json").read_bytes())
    clone = tmp_path / "changed-source"
    for path in selection["source_files"]:
        target = clone / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / path, target)
    target = clone / name
    target.write_bytes(target.read_bytes() + b"\n# unreviewed byte change\n")
    environment = {**os.environ, "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]}
    result = subprocess.run(["bash", str(ROOT / "FRAMEWORK-DURABLE-CONSUMER-BUILD-2026-10-02.sh"), str(clone), str(tmp_path / "wheels")], capture_output=True, text=True, timeout=30, check=False, env=environment)
    assert result.returncode == 1
    assert "source selection refused: bytes differ: " + name in result.stderr
    assert not (tmp_path / "wheels").exists()
