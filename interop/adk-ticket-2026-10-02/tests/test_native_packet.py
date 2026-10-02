"""Actual ADK runner/plugin matrix and refusals after selected digest replacement."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
from probity_observer.crypto import VerificationError

from probity_adk.contract import CASES, decode, encode, sha
from probity_adk.reader import verify_saved


def pins(root: Path) -> dict[str, Any]:
    return decode((root / "consumer-pins.json").read_bytes())


def reselect(root: Path) -> dict[str, Any]:
    manifest = {
        p.name: sha(p.read_bytes()) for p in sorted((root / "artifacts").iterdir())
    }
    (root / "artifact-manifest.json").write_bytes(encode(manifest))
    policy = pins(root)
    policy["artifactManifestSha256"] = sha(encode(manifest))
    policy["planSha256"] = sha((root / "plan-before-run.json").read_bytes())
    return policy


def test_actual_runner_ordered_retry_errors_and_effects(packet: Path) -> None:
    report = verify_saved(packet, pins(packet))
    assert report == decode((packet / "report.json").read_bytes())
    assert [row["case"] for row in report["records"]] == list(CASES)
    assert report["resources"]["modelCalls"] == 25
    assert report["resources"]["toolCalls"] == 18
    assert report["resources"]["httpPosts"] == 9
    assert sum(row["nativeRevision"] for row in report["records"]) == 7
    by_case = {row["case"]: row for row in report["records"]}
    assert by_case["unhandled-after"]["taskStatus"] == "error"
    assert by_case["unhandled-after"]["nativeRevision"] == 1
    assert by_case["handled-first"]["observedOriginalToolErrorCallbacks"] == 1
    assert by_case["handled-last"]["observedOriginalToolErrorCallbacks"] == 0
    assert by_case["exhausted-first"]["observedOriginalToolErrorCallbacks"] == 2
    assert by_case["exhausted-last"]["observedOriginalToolErrorCallbacks"] == 0
    assert by_case["incomplete-close"]["taskStatus"] == "incomplete"
    assert by_case["incomplete-close"]["nativeRevision"] == 1


def mutate(execution: dict[str, Any], name: str) -> None:
    changes = {
        "drop-model": lambda: execution["modelCalls"].pop(),
        "extra-model": lambda: execution["modelCalls"].append(
            execution["modelCalls"][0]
        ),
        "drop-tool": lambda: execution["toolCalls"].pop(),
        "drop-event": lambda: execution["events"].pop(),
        "extra-event": lambda: execution["events"].append(execution["events"][0]),
        "drop-session": lambda: execution["sessionEvents"].pop(),
        "drop-callback": lambda: execution["capture"]["records"].pop(),
        "extra-callback": lambda: execution["capture"]["records"].append(
            execution["capture"]["records"][0]
        ),
        "callback-counter-bool": lambda: execution["capture"]["records"][0].update(
            sequence=False
        ),
        "capture-failure": lambda: execution["capture"].update(failures=1),
        "capture-counter-bool": lambda: execution["capture"].update(failures=False),
        "capture-unclosed": lambda: execution["capture"].update(closed=False),
        "elapsed-bool": lambda: execution.update(elapsedNs=True),
        "cpu-over-elapsed": lambda: execution.update(cpuNs=execution["elapsedNs"] + 1),
        "suppress-raw-error": lambda: execution["toolCalls"][0].pop("error"),
        "coerce-terminal-success": lambda: execution.update(
            terminal={"status": "complete", "exception": None}
        ),
        "mcp-false-iserror": lambda: execution["toolCalls"][0]["result"].update(
            isError=False
        ),
        "callback-order-change": lambda: execution["capture"]["records"].reverse(),
        "native-byte-projection-change": lambda: execution["events"][0]["value"].update(
            author="unselected"
        ),
        "native-event-bool-time": lambda: edit_event(execution, "timestamp", True),
        "native-wrong-invocation": lambda: edit_event(
            execution, "invocation_id", "e-00000000-0000-4000-8000-000000000000"
        ),
        "native-extra-usage": lambda: edit_event(
            execution, "usage_metadata", {"total_token_count": 1}
        ),
        "unsigned-native-edit": lambda: edit_readback(execution),
    }
    changes[name]()


def edit_event(execution: dict[str, Any], key: str, value: Any) -> None:
    wrapped = execution["events"][0]
    wrapped["value"][key] = value
    wrapped["jsonHex"] = encode(wrapped["value"]).hex()
    execution["sessionEvents"][1] = wrapped
    first_event = next(
        row for row in execution["capture"]["records"] if row["callback"] == "event"
    )
    first_event["native"] = wrapped


def edit_readback(execution: dict[str, Any]) -> None:
    readback = decode(bytes.fromhex(execution["finalReadbackHex"]))
    readback["receipt"]["payload"]["revision"] = 0
    execution["finalReadbackHex"] = encode(readback).hex()


@pytest.mark.parametrize(
    "name",
    [
        "drop-model",
        "extra-model",
        "drop-tool",
        "drop-event",
        "extra-event",
        "drop-session",
        "drop-callback",
        "extra-callback",
        "callback-counter-bool",
        "capture-failure",
        "capture-counter-bool",
        "capture-unclosed",
        "elapsed-bool",
        "cpu-over-elapsed",
        "suppress-raw-error",
        "coerce-terminal-success",
        "mcp-false-iserror",
        "callback-order-change",
        "native-byte-projection-change",
        "native-event-bool-time",
        "native-wrong-invocation",
        "native-extra-usage",
        "unsigned-native-edit",
    ],
)
def test_reselected_semantic_substitution_refused(
    packet: Path, tmp_path: Path, name: str
) -> None:
    root = tmp_path / "candidate"
    shutil.copytree(packet, root)
    case = {
        "suppress-raw-error": "unhandled-after",
        "coerce-terminal-success": "incomplete-close",
        "mcp-false-iserror": "returned-error-first",
    }.get(name, "permit")
    path = root / "artifacts" / (case + ".json")
    value = decode(path.read_bytes())
    mutate(value, name)
    path.write_bytes(encode(value))
    with pytest.raises((VerificationError, ValueError, KeyError)):
        verify_saved(root, reselect(root))


@pytest.mark.parametrize(
    "field,value",
    [("maxModelCalls", True), ("plannedAttempts", 11), ("maxElapsedSeconds", 12000)],
)
def test_reselected_plan_budget_refused(
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


def test_changed_plugin_order_refused(packet: Path, tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    shutil.copytree(packet, root)
    path = root / "plan-before-run.json"
    plan = decode(path.read_bytes())
    plan["cases"][5]["pluginOrder"].reverse()
    path.write_bytes(encode(plan))
    with pytest.raises(VerificationError):
        verify_saved(root, reselect(root))


def test_tied_timestamps_keep_native_sequence_and_identity(
    packet: Path, tmp_path: Path
) -> None:
    root = tmp_path / "candidate"
    shutil.copytree(packet, root)
    path = root / "artifacts/permit.json"
    value = decode(path.read_bytes())
    second = value["events"][1]
    second["value"]["timestamp"] = value["events"][0]["value"]["timestamp"]
    second["jsonHex"] = encode(second["value"]).hex()
    value["sessionEvents"][2] = second
    event_rows = [r for r in value["capture"]["records"] if r["callback"] == "event"]
    event_rows[1]["native"] = second
    path.write_bytes(encode(value))
    assert verify_saved(root, reselect(root))["plannedAttempts"] == 12


def test_source_bytes_and_symlink_refused(packet: Path, tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    shutil.copytree(packet, root)
    source = root / "sources/adapter/producer.py"
    source.unlink()
    source.symlink_to(packet / "sources/adapter/producer.py")
    with pytest.raises(VerificationError):
        verify_saved(root, pins(root))


def test_cli_pins_required() -> None:
    import subprocess
    import sys

    result = subprocess.run(
        [str(Path(sys.executable).parent / "probity-adk-read"), "/missing"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2 and "--pins-file" in result.stderr
