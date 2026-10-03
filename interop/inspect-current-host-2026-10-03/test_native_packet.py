"""Semantic controls derived from the fresh current native originals.

Rehashing inside these controls tests parsing and reconstruction under declared
test selections; it establishes no independent selection or custody.
"""

import copy
import json
import os
from pathlib import Path

import pytest

from probity_inspect_current.adapter import load_engine


@pytest.fixture
def packet():
    root = Path(os.environ["INSPECT_CURRENT_PACKET"])
    engine = load_engine()
    declared = engine.decode((root / "declaration-before-run.json").read_bytes())
    sources = {
        name: (root / "sources" / name).read_bytes() for name in engine.SOURCE_NAMES
    }
    bindings = engine.decode((root / "packet/native-bindings.json").read_bytes())
    logs = {
        aid: (root / "packet" / (aid + "-native.json")).read_bytes() for aid in bindings
    }
    readbacks = {
        "workload-pass": (root / "packet/workload-pass-readback.txt").read_bytes()
    }
    return engine, declared, sources, bindings, logs, readbacks


def reconstruct(packet, change):
    engine = packet[0]
    declared, sources, bindings, logs, readbacks = copy.deepcopy(packet[1:])
    log = json.loads(logs["tool-pass"])
    change(log)
    logs["tool-pass"] = engine.encode(log)
    bindings["tool-pass"]["sha256"] = engine.digest(logs["tool-pass"])
    return engine.adapt(declared, logs, bindings, sources, readbacks)


def test_fresh_current_packet_reports_error_unstarted_and_failure_separately(packet):
    engine, declared, sources, bindings, logs, readbacks = packet
    plan, history, artifacts = engine.adapt(
        declared, logs, bindings, sources, readbacks
    )
    plan_raw, history_raw = engine.encode(plan), engine.encode(history)
    report = engine.verify(
        declared,
        logs,
        bindings,
        sources,
        readbacks,
        plan_bytes=plan_raw,
        history_bytes=history_raw,
        artifacts=artifacts,
        expected_plan_sha256=engine.digest(plan_raw),
        expected_history_sha256=engine.digest(history_raw),
    )
    assert {
        key: report[key]
        for key in (
            "planned",
            "started",
            "complete",
            "failed",
            "missing",
            "task_passed",
            "task_failed",
        )
    } == {
        "planned": 6,
        "started": 5,
        "complete": 4,
        "failed": 1,
        "missing": 1,
        "task_passed": 3,
        "task_failed": 1,
    }


@pytest.mark.parametrize("version", ["0.3.273", "0.3.275", "0.3.277", "unknown"])
def test_reselected_native_versions_remain_literal(packet, version):
    def change(log):
        log["eval"]["packages"]["inspect_ai"] = version

    with pytest.raises(ValueError, match="execution_framework_version"):
        reconstruct(packet, change)


@pytest.mark.parametrize(
    "key,value",
    [
        ("epochs", 2),
        ("max_samples", 2),
        ("message_limit", 13),
        ("retry_on_error", 1),
        ("log_samples", False),
        ("score_on_error", True),
    ],
)
def test_reselected_native_run_configuration_refused(packet, key, value):
    def change(log):
        log["eval"]["config"][key] = value

    with pytest.raises(ValueError, match="execution_config"):
        reconstruct(packet, change)


def test_native_run_identifier_is_not_packet_claim(packet):
    def change(log):
        log["eval"]["run_id"] = "different-run"

    with pytest.raises(ValueError, match="execution_native_identity"):
        reconstruct(packet, change)


def test_started_native_record_remains_incomplete_and_unscored(packet):
    def change(log):
        log["status"] = "started"
        log["samples"][0].pop("completed_at", None)
        log["samples"][0].pop("scores", None)

    _, history, _ = reconstruct(packet, change)
    selected = next(
        item
        for item in history["records"]
        if item["identity"]["attempt_id"] == "tool-pass"
    )
    assert selected["harness_status"] == "incomplete"
    assert selected["claims"]["task_outcome"]["status"] == "unknown"


def test_success_with_no_sample_never_becomes_completion(packet):
    def change(log):
        log["samples"] = []

    with pytest.raises(ValueError, match="execution_success_missing_sample"):
        reconstruct(packet, change)
