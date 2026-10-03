"""Reconstruct real current native originals and reject semantic mutants."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def packet() -> Path:
    return Path(os.environ["ADK_CURRENT_RETAINED_PACKET"])


def pins(packet: Path) -> dict[str, Any]:
    from probity_adk.contract import sha

    return dict(
        profile="probity-google-adk-ticket-v0",
        planSha256=sha((packet / "plan-before-run.json").read_bytes()),
        sourceManifestSha256=sha(
            (packet / "source-manifest-before-run.json").read_bytes()
        ),
        artifactManifestSha256=sha((packet / "artifact-manifest.json").read_bytes()),
        consumerTime=json.loads((packet.parent / "host-policy.json").read_bytes())[
            "consumerTime"
        ],
    )


def test_actual_original_and_repeat(packet: Path) -> None:
    from probity_adk.reader import verify_saved

    a, b = verify_saved(packet, pins(packet)), verify_saved(packet, pins(packet))
    assert a == b and a["plannedAttempts"] == 12
    assert a["resources"]["modelCalls"] == 25
    assert a["resources"]["toolCalls"] == 18
    by_case = {row["case"]: row for row in a["records"]}
    assert by_case["unhandled-after"]["nativeRevision"] == 1
    assert by_case["unhandled-after"]["taskStatus"] == "error"
    assert by_case["incomplete-close"]["nativeRevision"] == 1
    assert by_case["incomplete-close"]["taskStatus"] == "incomplete"
    assert by_case["handled-last"]["observedOriginalToolErrorCallbacks"] == 0
    assert by_case["handled-first"]["observedOriginalToolErrorCallbacks"] == 1


def mutate(record: dict[str, Any], mutation: str) -> None:
    """Make one semantic change while leaving retained source selection intact."""
    changes = {
        "terminal-success": lambda: record.update(
            terminal={"status": "complete", "exception": None}
        ),
        "invent-error-callback": lambda: record["capture"]["records"].append(
            {"callback": "tool-error"}
        ),
        "error-as-success": lambda: record["toolCalls"][0]["result"].update(
            isError=False
        ),
        "omit-model": lambda: record["modelCalls"].pop(),
        "omit-session": lambda: record["sessionEvents"].pop(),
        "unclosed-capture": lambda: record["capture"].update(closed=False),
        "failed-capture": lambda: record["capture"].update(failures=1),
    }
    changes[mutation]()


@pytest.mark.parametrize(
    "case,mutation",
    [
        ("unhandled-after", "terminal-success"),
        ("incomplete-close", "terminal-success"),
        ("handled-last", "invent-error-callback"),
        ("returned-error-first", "error-as-success"),
        ("permit", "omit-model"),
        ("permit", "omit-session"),
        ("permit", "unclosed-capture"),
        ("permit", "failed-capture"),
    ],
)
def test_reselected_semantic_mutants(
    packet: Path, tmp_path: Path, case: str, mutation: str
) -> None:
    from probity_adk.contract import encode, sha
    from probity_adk.reader import verify_saved

    changed = tmp_path / "mutant"
    shutil.copytree(packet, changed)
    path = changed / "artifacts" / (case + ".json")
    record = json.loads(path.read_bytes())
    mutate(record, mutation)
    path.write_bytes(encode(record))
    manifest = {
        p.name: sha(p.read_bytes()) for p in (changed / "artifacts").glob("*.json")
    }
    (changed / "artifact-manifest.json").write_bytes(encode(manifest))
    selection = pins(packet)
    selection["artifactManifestSha256"] = sha(encode(manifest))
    with pytest.raises((ValueError, TypeError, KeyError)):
        verify_saved(changed, selection)
