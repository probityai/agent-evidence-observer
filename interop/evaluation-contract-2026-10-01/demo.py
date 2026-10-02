"""Produce a five-tier synthetic accounting demo, never native benchmark scores."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from evaluation_contract import (
    AXES,
    PROFILE,
    RESOURCES,
    ROLES,
    digest,
    encode,
    validate,
)


def ref(name: str, raw: bytes, revision: str = "synthetic-v0") -> dict[str, Any]:
    """Describe exact retained bytes without modifying their representation."""
    return {
        "name": name,
        "sha256": digest(raw),
        "size_bytes": len(raw),
        "media_type": "application/json",
        "source_revision": revision,
    }


def fixture() -> tuple[dict[str, Any], dict[str, Any], dict[str, bytes]]:
    """Build seven declared attempts over five labelled synthetic tiers.

    Returns
    -------
    tuple
        Plan, history and retained bytes. Includes a failed agent attempt followed
        by an honest retry, an unstarted workload, and an incomplete workload.
        The small pass/fail examples measure contract accounting only.
    """
    source = encode({"kind": "synthetic-contract-input", "version": 0})
    artifacts = {"synthetic-source.json": source}
    source_ref = ref("synthetic-source.json", source)
    source_pin = {
        "identity": "synthetic",
        "revision": "synthetic-v0",
        "artifact": source_ref,
    }
    plan = {
        "profile": PROFILE,
        "run_id": "contract-demo-001",
        "mode": "synthetic-contract",
        "roles": {role: "same-demo-operator" for role in sorted(ROLES)},
        "sources": {
            role: source_pin.copy()
            for role in (
                "task",
                "harness",
                "model",
                "rubric",
                "policy",
                "configuration",
            )
        },
        "attempts": [],
    }
    rows = [
        ("reasoning", "complete", None),
        ("tools", "complete", None),
        ("agents", "error", None),
        ("agents", "complete", "attempt-2"),
        ("workloads", "not-started", None),
        ("a2a", "complete", None),
        ("workloads", "incomplete", None),
    ]
    records = []
    for index, (tier, status, parent) in enumerate(rows):
        request = 2 if parent else index
        identity = {
            "task_id": f"task-{request}",
            "logical_request_id": f"request-{request}",
            "attempt_id": f"attempt-{index}",
            "interval_id": f"interval-{request}",
            "catalog_authority_id": "catalog-demo",
            "capability_id": f"capability-{tier}",
            "runtime_target_id": f"runtime-{tier}",
            "effect_id": None,
            "consumer_decision_id": f"decision-{index}",
        }
        spec = {"identity": identity, "tier": tier, "parent_attempt_id": parent}
        plan["attempts"].append(spec)
        claim = {
            "status": "unknown",
            "reason_code": "not_measured",
            "native_reason": "Synthetic contract exercise only",
            "profile": PROFILE,
            "evidence": [],
        }
        claims = {axis: claim.copy() for axis in sorted(AXES)}
        if status == "complete":
            claims["task_outcome"] = {
                **claim,
                "status": "fail" if tier == "tools" else "pass",
                "reason_code": "synthetic_assertion",
                "evidence": [source_ref],
            }
        record = {
            "run_id": plan["run_id"],
            **spec,
            "harness_status": status,
            "resources": {field: None for field in sorted(RESOURCES)},
            "claims": claims,
            "capture": {
                "scope": f"declared-attempt-{index}",
                "complete": False,
                "gaps": ["external_execution_not_observed"],
                "observed_effect_count": None,
            },
        }
        name = f"attempt-{index}.json"
        artifacts[name] = encode(record)
        records.append({**record, "output": ref(name, artifacts[name])})
    history = {
        "profile": PROFILE,
        "run_id": plan["run_id"],
        "plan_sha256": digest(encode(plan)),
        "start_ledger": [
            r["identity"]["attempt_id"]
            for r in records
            if r["harness_status"] != "not-started"
        ],
        "records": records,
    }
    artifacts["start-ledger.json"] = encode(
        {"run_id": plan["run_id"], "starts": history["start_ledger"]}
    )
    history["history_head_ref"] = ref(
        "start-ledger.json", artifacts["start-ledger.json"]
    )
    return plan, history, artifacts


def run(output: Path) -> dict[str, Any]:
    """Validate and retain a fresh demonstration packet and its measured report.

    Parameters
    ----------
    output : pathlib.Path
        New directory. Existing paths are refused to preserve prior evidence.

    Returns
    -------
    dict
        Accounting result from :func:`evaluation_contract.validate`.
    """
    output.mkdir(parents=True, exist_ok=False)
    plan, history, artifacts = fixture()
    plan_raw, history_raw = encode(plan), encode(history)
    pins = {
        "expected_plan_sha256": digest(plan_raw),
        "expected_history_sha256": digest(history_raw),
    }
    result = validate(plan_raw, history_raw, artifacts, **pins)
    for name, raw in {
        **artifacts,
        "plan.json": plan_raw,
        "history.json": history_raw,
        "consumer-pins.json": encode(pins),
        "report.json": encode(result),
    }.items():
        (output / name).write_bytes(raw)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    print(json.dumps(run(parser.parse_args().output), indent=2))
