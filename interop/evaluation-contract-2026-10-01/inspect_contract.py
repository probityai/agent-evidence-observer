"""Map verified Inspect mock logs into the separate five-tier reference.

The native adapter remains the authority for its bounded schema and source
checks. This bridge retains original bytes and supplies no effect, trust,
authority, independent-judge or consumer-policy verdict from transcript scores.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping

from probity_observer.evaluation_history import RunPlan, encode_record
from probity_observer.inspect_history import (
    INSPECT_VERSION,
    InspectBinding,
    adapt_inspect_log,
    verify_inspect_history,
)

from evaluation_contract import (
    AXES,
    PROFILE,
    RESOURCES,
    ROLES,
    decode,
    digest,
    encode,
    require,
    validate,
)

MAPPING = "probity-inspect-five-tier-v1"


def reference(name: str, raw: bytes, revision: str) -> dict[str, Any]:
    """Pin original octets without treating JSON re-encoding as native bytes."""
    return {
        "name": name,
        "sha256": digest(raw),
        "size_bytes": len(raw),
        "media_type": "text/x-python" if name.endswith(".py") else "application/json",
        "source_revision": revision,
    }


def contract_plan(
    native_plan: RunPlan, sources: Mapping[str, bytes], roles: Mapping[str, str | None]
) -> tuple[dict, dict[str, bytes]]:
    """Declare one reasoning-profile entry per original sample/epoch attempt.

    Role identities are assertions, never independence evidence. The original
    native RunPlan is retained as the common configuration source. The Inspect
    profile supports zero sample retries; retry declarations are refused rather
    than reconstructed from merged retry lists. Other tiers are not exercised.
    """
    require(set(roles) == ROLES, "roles_shape")
    pins = {source.role: source for source in native_plan.sources}
    artifacts = dict(sources)
    require(
        not {"native-plan.json", "mapping-source.json", "mapping-config.json"}
        & artifacts.keys(),
        "artifact_name_collision",
    )
    artifacts["native-plan.json"] = encode_record(asdict(native_plan))
    root = Path(__file__).parent
    artifacts["mapping-source.json"] = encode(
        {
            name: (root / name).read_text("utf-8")
            for name in ("evaluation_contract.py", "inspect_contract.py")
        }
    )
    artifacts["mapping-config.json"] = encode(
        {
            "mapping_profile": MAPPING,
            "native_declaration": reference(
                "native-plan.json", artifacts["native-plan.json"], MAPPING
            ),
            "mapping_source": reference(
                "mapping-source.json", artifacts["mapping-source.json"], MAPPING
            ),
        }
    )
    mapped = {}
    for role, original in {
        "task": "task",
        "harness": "harness",
        "model": "model",
        "rubric": "scorer",
        "policy": "policy",
    }.items():
        pin = pins[original]
        raw = sources[pin.artifact.name]
        require(digest(raw) == pin.artifact.sha256, "native_source_pin_mismatch")
        mapped[role] = {
            "identity": pin.identity,
            "revision": pin.version,
            "artifact": reference(pin.artifact.name, raw, pin.version),
        }
    mapped["configuration"] = {
        "identity": "inspect-native-declaration",
        "revision": MAPPING,
        "artifact": reference(
            "mapping-config.json", artifacts["mapping-config.json"], MAPPING
        ),
    }
    attempts = []
    for attempt in native_plan.attempts:
        identity = {
            "task_id": pins["task"].identity,
            "logical_request_id": "request-"
            + digest(
                encode(
                    {
                        "task": pins["task"].identity,
                        "sample": attempt.sample_id,
                        "epoch": attempt.epoch,
                    }
                )
            ),
            "attempt_id": attempt.attempt_id,
            "interval_id": native_plan.run_id,
            "catalog_authority_id": "declared-task-catalog",
            "capability_id": "inspect-generate-match",
            "runtime_target_id": "mockllm/model",
            "effect_id": None,
            "consumer_decision_id": None,
        }
        attempts.append(
            {"identity": identity, "tier": "reasoning", "parent_attempt_id": None}
        )
    return {
        "profile": PROFILE,
        "run_id": native_plan.run_id,
        "mode": "retained-native",
        "roles": dict(roles),
        "sources": mapped,
        "attempts": attempts,
    }, artifacts


def adapt(
    native: bytes,
    native_plan: RunPlan,
    binding: InspectBinding,
    *,
    sources: Mapping[str, bytes],
    captured_at: str,
    roles: Mapping[str, str | None],
) -> tuple[dict, dict, dict[str, bytes]]:
    """Verify native bytes and reconstruct the complete common result packet.

    Missing entries mean absent from the retained native log, not proven never
    executed. The common start-unknown state carries that explicit named gap.
    A started sample with no completion maps to incomplete, an error stays an
    error, and a completed unscored sample stays complete with unknown outcome.
    No unsupported native retry, changed source or altered score is admitted.
    """
    verify_inspect_history(
        native, native_plan, binding, sources=sources, captured_at=captured_at
    )
    native_history = adapt_inspect_log(native, native_plan, binding)
    plan, artifacts = contract_plan(native_plan, sources, roles)
    require("inspect-log.json" not in artifacts, "artifact_name_collision")
    artifacts["inspect-log.json"] = native
    native_ref = reference("inspect-log.json", native, INSPECT_VERSION)
    records = []
    for spec, original in zip(plan["attempts"], native_history.records, strict=True):
        status = {
            "completed": "complete",
            "error": "error",
            "interrupted": "incomplete",
            "not_run": "start-unknown",
        }[original.status]
        claim = {
            "status": "not-exercised",
            "reason_code": "native_profile_does_not_measure_axis",
            "native_reason": "Inspect mock generate/match does not measure this axis",
            "profile": MAPPING,
            "evidence": [],
        }
        claims = {axis: dict(claim) for axis in AXES}
        claims["task_outcome"] = {
            "status": (
                original.outcome if original.outcome in {"pass", "fail"} else "unknown"
            ),
            "reason_code": (
                "native_match_score"
                if original.outcome != "not_scored"
                else "native_score_absent"
            ),
            "native_reason": original.error_code
            or "Selected native match C/I score; no independent rescoring",
            "profile": "match-C-I-v0",
            "evidence": [native_ref],
        }
        gaps = [
            "external_effects_not_observed",
            "native_transcript_completeness_not_established",
        ]
        if original.status == "not_run":
            gaps.extend(
                ["start_evidence_missing", "absent_from_native_log_execution_unknown"]
            )
        if original.status == "interrupted":
            gaps.append("native_completion_absent")
        record = {
            "run_id": native_plan.run_id,
            **spec,
            "harness_status": status,
            "resources": {key: None for key in RESOURCES},
            "claims": claims,
            "capture": {
                "scope": "retained-inspect-transcript",
                "complete": False,
                "gaps": gaps,
                "observed_effect_count": None,
            },
        }
        name = "mapped-" + digest(original.attempt_id.encode()) + ".json"
        require(name not in artifacts, "artifact_name_collision")
        artifacts[name] = encode(record)
        records.append({**record, "output": reference(name, artifacts[name], MAPPING)})
    starts = [
        r["identity"]["attempt_id"]
        for r in records
        if r["harness_status"] not in {"not-started", "start-unknown"}
    ]
    # This ledger is derived in declaration order. It is not native start order
    # or an authenticated pre-dispatch commitment.
    ledger = encode({"run_id": plan["run_id"], "starts": starts})
    require("mapped-start-ledger.json" not in artifacts, "artifact_name_collision")
    artifacts["mapped-start-ledger.json"] = ledger
    history = {
        "profile": PROFILE,
        "run_id": plan["run_id"],
        "plan_sha256": digest(encode(plan)),
        "start_ledger": starts,
        "history_head_ref": reference("mapped-start-ledger.json", ledger, MAPPING),
        "records": records,
    }
    return plan, history, artifacts


def verify(
    native: bytes,
    native_plan: RunPlan,
    binding: InspectBinding,
    *,
    sources: Mapping[str, bytes],
    captured_at: str,
    plan_bytes: bytes,
    history_bytes: bytes,
    artifacts: dict[str, bytes],
    expected_plan_sha256: str,
    expected_history_sha256: str,
) -> dict[str, Any]:
    """Recompute the mapping before accepting an externally pinned packet.

    Rehashing a fabricated normalized score does not help: the entire common
    packet must equal the one reconstructed from selected original native bytes.
    Caller-selected native binding and common pins remain separate trust inputs.
    """
    supplied = decode(plan_bytes)
    require(
        type(supplied) is dict and type(supplied.get("roles")) is dict, "plan_shape"
    )
    plan, history, retained = adapt(
        native,
        native_plan,
        binding,
        sources=sources,
        captured_at=captured_at,
        roles=supplied["roles"],
    )
    require(encode(decode(plan_bytes)) == encode(plan), "native_plan_mapping_mismatch")
    require(
        encode(decode(history_bytes)) == encode(history),
        "native_history_mapping_mismatch",
    )
    require(artifacts == retained, "native_artifact_mapping_mismatch")
    result = validate(
        plan_bytes,
        history_bytes,
        artifacts,
        expected_plan_sha256=expected_plan_sha256,
        expected_history_sha256=expected_history_sha256,
    )
    return {
        **result,
        "mapping": MAPPING,
        "model": "mockllm/model",
        "interpretation": "native-mock-harness-contract-not-real-model-benchmark",
        "startLedgerAuthority": "derived-declaration-order-not-native-chronology",
        "priorCommonPlanCommitment": "not-established",
        "nativeBindingAuthority": "consumer-selected-retained-receipt",
    }
