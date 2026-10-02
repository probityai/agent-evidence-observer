"""Actual SDK execution and semantic refusals even after artifact hash reselection."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
from probity_observer.crypto import VerificationError

from probity_openai.contract import CASES, decode, encode, sha
from probity_openai.producer import run
from probity_openai.reader import verify_saved


@pytest.fixture(scope="session")
def packet(tmp_path_factory: Any) -> Path:
    root = tmp_path_factory.mktemp("native") / "packet"
    run(root)
    return root


def selected(root: Path) -> dict[str, Any]:
    return decode((root / "consumer-pins.json").read_bytes())


def reselect(root: Path) -> dict[str, Any]:
    manifest = {
        p.name: sha(p.read_bytes()) for p in sorted((root / "artifacts").iterdir())
    }
    (root / "artifact-manifest.json").write_bytes(encode(manifest))
    pins = selected(root)
    pins["artifactManifestSha256"] = sha(encode(manifest))
    pins["planSha256"] = sha((root / "plan-before-run.json").read_bytes())
    return pins


def test_actual_sdk_population(packet: Path) -> None:
    report = verify_saved(packet, selected(packet))
    assert [r["case"] for r in report["records"]] == list(CASES)
    assert report["resources"]["modelCalls"] == 9
    assert report["resources"]["toolCalls"] == 6
    assert [r["taskStatus"] for r in report["records"]] == [
        "complete",
        "complete",
        "complete",
        "error",
        "error",
        "incomplete",
    ]
    assert [r["nativeRevision"] for r in report["records"]] == [1, 0, 0, 0, 1, 1]
    assert report == decode((packet / "report.json").read_bytes())


def mutate(execution: dict[str, Any], name: str) -> None:
    end = next(e for e in execution["trace"]["events"] if e["event"] == "span-end")
    mutations = {
        "drop-model": lambda: execution["modelCalls"].pop(),
        "duplicate-model": lambda: execution["modelCalls"].append(
            execution["modelCalls"][0]
        ),
        "drop-tool": lambda: execution["toolCalls"].clear(),
        "drop-callback": lambda: execution["trace"]["events"].pop(2),
        "duplicate-callback": lambda: execution["trace"]["events"].append(end),
        "wrong-parent": lambda: end["native"].update(parent_id=None),
        "wrong-trace": lambda: end["native"].update(trace_id="trace_" + "0" * 32),
        "missing-span-output": lambda: end["native"]["span_data"].update(output=None),
        "fabricated-span-usage": lambda: end["native"]["span_data"].update(
            usage={"total_tokens": 1}
        ),
        "collector-error": lambda: execution["trace"].update(failures=1),
        "collector-unflushed": lambda: execution["trace"].update(flushes=0),
        "collector-unclosed": lambda: execution["trace"].update(closed=False),
        "payloads-disabled": lambda: execution["trace"].update(capturePayloads=False),
        "boolean-elapsed": lambda: execution.update(elapsedNs=True),
        "cpu-over-elapsed": lambda: execution.update(cpuNs=execution["elapsedNs"] + 1),
        "changed-model-input": lambda: execution["modelCalls"][0].update(input=[]),
        "boolean-usage": lambda: execution["modelCalls"][0]["usage"].update(
            total_tokens=False
        ),
        "changed-tool-argument": lambda: execution["toolCalls"][0].update(
            arguments={"content": "CHANGED"}
        ),
        "false-terminal-success": lambda: execution.update(
            terminal={"status": "complete", "output": "complete", "exception": None}
        ),
        "unsigned-effect-edit": lambda: edit_readback(execution),
    }
    mutations[name]()


def edit_readback(execution: dict[str, Any]) -> None:
    native = decode(bytes.fromhex(execution["finalReadbackHex"]))
    native["receipt"]["payload"]["revision"] = 0
    execution["finalReadbackHex"] = encode(native).hex()


@pytest.mark.parametrize(
    "name",
    [
        "drop-model",
        "duplicate-model",
        "drop-tool",
        "drop-callback",
        "duplicate-callback",
        "wrong-parent",
        "wrong-trace",
        "missing-span-output",
        "fabricated-span-usage",
        "collector-error",
        "collector-unflushed",
        "collector-unclosed",
        "payloads-disabled",
        "boolean-elapsed",
        "cpu-over-elapsed",
        "changed-model-input",
        "boolean-usage",
        "changed-tool-argument",
        "false-terminal-success",
        "unsigned-effect-edit",
    ],
)
def test_semantic_refusal_after_hash_reselection(
    packet: Path, tmp_path: Path, name: str
) -> None:
    root = tmp_path / "candidate"
    shutil.copytree(packet, root)
    case = "committed-effect-error" if name == "false-terminal-success" else "permit"
    path = root / "artifacts" / (case + ".json")
    value = decode(path.read_bytes())
    mutate(value, name)
    path.write_bytes(encode(value))
    with pytest.raises((VerificationError, ValueError, KeyError)):
        verify_saved(root, reselect(root))


@pytest.mark.parametrize(
    "field,value",
    [
        ("maxModelCalls", True),
        ("plannedAttempts", 5),
        ("maxElapsedSeconds", 9000),
    ],
)
def test_plan_budget_reselection_refused(
    packet: Path, tmp_path: Path, field: str, value: Any
) -> None:
    root = tmp_path / "candidate"
    shutil.copytree(packet, root)
    path = root / "plan-before-run.json"
    plan = decode(path.read_bytes())
    plan["budget"][field] = value
    path.write_bytes(encode(plan))
    with pytest.raises(VerificationError):
        verify_saved(root, reselect(root))


def test_source_substitution_refused(packet: Path, tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    shutil.copytree(packet, root)
    (root / "sources/adapter/producer.py").write_bytes(b"# replacement")
    with pytest.raises(VerificationError):
        verify_saved(root, selected(root))


def test_missing_population_refused(packet: Path, tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    shutil.copytree(packet, root)
    (root / "artifacts/deny.json").unlink()
    with pytest.raises(VerificationError):
        verify_saved(root, reselect(root))


def test_source_symlink_refused(packet: Path, tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    shutil.copytree(packet, root)
    path = root / "sources/adapter/producer.py"
    path.unlink()
    path.symlink_to(packet / "sources/adapter/producer.py")
    with pytest.raises(VerificationError):
        verify_saved(root, selected(root))


def test_pins_required_by_cli() -> None:
    import subprocess
    import sys

    result = subprocess.run(
        [str(Path(sys.executable).parent / "probity-openai-read"), "/missing"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "--pins-file" in result.stderr


def test_duplicate_json_refused(packet: Path, tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    shutil.copytree(packet, root)
    path = root / "artifacts/permit.json"
    path.write_bytes(b'{"toolCalls":[],"toolCalls":[]}')
    with pytest.raises(VerificationError):
        verify_saved(root, reselect(root))
