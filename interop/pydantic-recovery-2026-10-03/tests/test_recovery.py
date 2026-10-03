"""Real finite process population and refusals after full byte reselection."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from recovery_common import CASES, load, sha
from recovery_reader import verify_saved
from recovery_run import run

from probity_observer.crypto import VerificationError, canonical


@pytest.fixture(scope="session")
def native(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Execute all nine native cases once, including actual OS worker death."""
    root = tmp_path_factory.mktemp("native") / "packet"
    run(root, "test-native-source")
    return root


def reselect(root: Path) -> dict:
    """Select altered bytes so controls must reach their semantic relation."""
    manifest = load(root / "artifact-manifest.json")
    for name in manifest:
        manifest[name] = sha((root / name).read_bytes())
    (root / "artifact-manifest.json").write_bytes(canonical(manifest))
    pins = load(root / "consumer-pins.json")
    pins["artifactManifestSha256"] = sha(canonical(manifest))
    return pins


def test_native_population(native: Path) -> None:
    report = verify_saved(native, load(native / "consumer-pins.json"))
    assert report["freshWorkers"] == report["freshTargets"] == 18
    assert report["providerCalls"] == 0
    assert [record["id"] for record in report["records"]] == list(CASES)
    assert [record["releasedResult"] for record in report["records"]] == [True] + [False] * 8
    assert all(record["priorEffect"]["nativeRevision"] == 1 for record in report["records"])
    assert all(record["recoveryPosts"] == 0 for record in report["records"])


@pytest.mark.parametrize("mutation", ["tool-id", "result", "first-arguments", "completion", "current-authority", "signed-readback", "process-id", "exit-code", "released-denial", "child-env", "counter"])
def test_reselected_semantic_refusal(native: Path, tmp_path: Path, mutation: str) -> None:
    root = tmp_path / "packet"
    shutil.copytree(native, root)
    path, field, value = {
        "process-id": ("permit/processes.json", None, None),
        "exit-code": ("permit/processes.json", None, None),
        "child-env": ("permit/processes.json", None, None),
        "current-authority": ("permit/current-host-selection.json", "grant", {}),
        "signed-readback": ("permit/recovery.json", None, None),
        "released-denial": ("revoked/recovery.json", "releasedResult", True),
        "counter": ("permit/final-parent-readback.json", "revision", 2),
        "completion": ("permit/recovery.json", "status", "refused"),
        "tool-id": ("permit/resumed-history.json", None, None),
        "result": ("permit/resumed-history.json", None, None),
        "first-arguments": ("permit/history.json", None, None),
    }[mutation]
    target = root / path
    data = json.loads(target.read_bytes())
    if field is not None:
        data[field] = value
    else:
        alter(data, mutation)
    target.write_bytes(json.dumps(data, separators=(",", ":")).encode() if "history" in path else canonical(data))
    with pytest.raises((VerificationError, KeyError, TypeError)):
        verify_saved(root, reselect(root))


def alter(data: dict | list, mutation: str) -> None:
    """Change one substantive native/effect/process relationship."""
    if mutation in {"tool-id", "result"}:
        data[2]["parts"][0]["tool_call_id" if mutation == "tool-id" else "content"] = "swapped-result"
    elif mutation == "first-arguments":
        data[1]["parts"][0]["args"] = {"content": "CHANGED"}
    else:
        alter_record(data, mutation)


def alter_record(data: dict, mutation: str) -> None:
    """Change one signed-state or real-process record."""
    if mutation == "signed-readback":
        data["live"]["receipt"]["signature"] = "0" * 128
    elif mutation == "process-id":
        data["workers"][1]["pid"] = data["workers"][0]["pid"]
    elif mutation == "exit-code":
        data["workers"][0]["returncode"] = 0
    elif mutation == "child-env":
        data["workers"][0]["environment"]["OPENAI_API_KEY"] = "injected"
