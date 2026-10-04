"""Bind one selected evaluation plan to a retained witnessed history prefix.

Signed candidate pins alone do not select a run. This profile records one
selection, then a start referencing its checkpoint, then the retained closure.
The caller supplies its own opening and final witness pins. Ordering covers the
supplied history; it establishes neither wall-clock precedence nor custody.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .crypto import VerificationError, digest
from .evaluation_history import AttemptRecord, RunPlan, encode_record, verify_history
from .evaluation_history import plan_digest as evaluation_plan_digest
from .history import append_history, read_history, verify_checkpoint
from .witness_port import WitnessPort

PROFILE = "probity-evaluation-selection-v1"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


def _operator(value: str) -> None:
    """Validate the declared operator identity without claiming its truth."""
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise VerificationError("selection operator identity is unsupported")


def selection_pins(
    plan: RunPlan, configuration: bytes, controls: bytes
) -> dict[str, str]:
    """Bind the complete existing plan and original configuration/control bytes."""
    if not isinstance(plan, RunPlan):
        raise VerificationError("selection requires a RunPlan")
    if any(not isinstance(raw, bytes) or not raw for raw in (configuration, controls)):
        raise VerificationError(
            "selection configuration and controls need original bytes"
        )
    return {
        "planDigest": evaluation_plan_digest(plan),
        "configurationSha256": hashlib.sha256(configuration).hexdigest(),
        "controlsSha256": hashlib.sha256(controls).hexdigest(),
    }


def _event(plan: RunPlan, kind: str, **fields: Any) -> dict[str, Any]:
    """Construct the closed event shape for the named run."""
    return {"profile": PROFILE, "runId": plan.run_id, "kind": kind, **fields}


def _history(path: Path) -> list[dict[str, Any]]:
    """Reuse native chain checks and turn malformed shapes into explicit refusal."""
    try:
        return read_history(path)
    except (KeyError, TypeError, IndexError) as exc:
        raise VerificationError("selection history shape is unsupported") from exc


def _events(
    entries: list[dict[str, Any]], run_id: str
) -> list[tuple[int, dict[str, Any]]]:
    """Keep every event naming this run, including unknown profile/kind values."""
    result = []
    for index, entry in enumerate(entries):
        event = entry["event"]
        if not isinstance(event, dict):
            raise VerificationError("history event is not an object")
        if event.get("runId") == run_id:
            if event.get("profile") != PROFILE:
                raise VerificationError("run event profile is unsupported")
            result.append((index, event))
    return result


def _checkpoint(
    entries: list[dict[str, Any]], checkpoint: Mapping[str, Any] | None, key: str
) -> None:
    """Check a caller-retained anchor against the exact supplied prefix."""
    if not isinstance(checkpoint, Mapping) or set(checkpoint) != {
        "count",
        "head",
        "keyid",
        "signature",
    }:
        raise VerificationError(
            "retained selection checkpoint is missing or unsupported"
        )
    count = checkpoint["count"]
    if type(count) is not int or count < 1 or count > len(entries):
        raise VerificationError(
            "selection checkpoint count is outside supplied history"
        )
    try:
        verify_checkpoint(entries[:count], dict(checkpoint), key)
    except (KeyError, TypeError) as exc:
        raise VerificationError("selection checkpoint shape is unsupported") from exc


def open_run_selection(
    history: Path,
    witness: WitnessPort,
    plan: RunPlan,
    configuration: bytes,
    controls: bytes,
    *,
    operator_id: str,
) -> dict[str, Any]:
    """Durably select once, then obtain the opening checkpoint before dispatch.

    Use one writer per history, as required by append_history. Keep the returned
    checkpoint outside producer-controlled storage. A failure to checkpoint does
    not authorize execution or an automatic replacement selection.
    """
    _operator(operator_id)
    pins = selection_pins(plan, configuration, controls)
    if _events(_history(history), plan.run_id):
        raise VerificationError("run already has history; selection cannot be replaced")
    append_history(
        history, _event(plan, "selection", pins=pins, operatorId=operator_id)
    )
    return witness.checkpoint(history)


def start_selected_run(
    history: Path,
    witness: WitnessPort,
    plan: RunPlan,
    configuration: bytes,
    controls: bytes,
    opening_checkpoint: Mapping[str, Any],
    *,
    operator_id: str,
) -> None:
    """Append the checkpoint-bound start before the caller invokes its checker."""
    entries = _history(history)
    _checkpoint(entries, opening_checkpoint, witness.public_hex)
    events = _events(entries, plan.run_id)
    if len(events) != 1 or events[0][1].get("kind") != "selection":
        raise VerificationError("execution needs exactly one prior selection")
    if opening_checkpoint["count"] != events[0][0] + 1:
        raise VerificationError("opening checkpoint does not end at selection")
    _operator(operator_id)
    expected = _event(
        plan,
        "selection",
        pins=selection_pins(plan, configuration, controls),
        operatorId=operator_id,
    )
    if events[0][1] != expected:
        raise VerificationError("execution inputs differ from selected inputs")
    append_history(
        history,
        _event(
            plan,
            "execution-start",
            openingCheckpointDigest=digest(PROFILE, dict(opening_checkpoint)),
        ),
    )


def execution_digest(
    plan: RunPlan,
    records: Sequence[AttemptRecord],
    *,
    artifacts: Mapping[str, bytes],
    sources: Mapping[str, bytes],
    ended_at: str,
) -> tuple[str, dict[str, Any]]:
    """Reuse the evaluation reader before binding all retained native byte sets."""
    appraisal = verify_history(
        plan, records, artifacts=artifacts, sources=sources, ended_at=ended_at
    )
    payload = {
        "appraisal": appraisal,
        "records": [asdict(record) for record in records],
        "artifacts": {
            name: hashlib.sha256(raw).hexdigest() for name, raw in artifacts.items()
        },
        "sources": {
            name: hashlib.sha256(raw).hexdigest() for name, raw in sources.items()
        },
    }
    domain = (PROFILE + "-execution").encode("ascii")
    return hashlib.sha256(
        domain + b"\0" + encode_record(payload)
    ).hexdigest(), appraisal


def close_selected_run(
    history: Path, witness: WitnessPort, plan: RunPlan, retained_execution_digest: str
) -> dict[str, Any]:
    """Retain one closure after a selected start; return the signed final head."""
    events = _events(_history(history), plan.run_id)
    if [event.get("kind") for _, event in events] != ["selection", "execution-start"]:
        raise VerificationError("closure needs one selection and one start")
    if not isinstance(retained_execution_digest, str) or not re.fullmatch(
        r"[0-9a-f]{64}", retained_execution_digest
    ):
        raise VerificationError("execution digest is unsupported")
    append_history(
        history,
        _event(plan, "execution-finish", executionDigest=retained_execution_digest),
    )
    return witness.checkpoint(history)


def _bound_events(entries, run_id, opening, final, key):
    """Require complete anchored history and the finite per-run state machine."""
    _checkpoint(entries, opening, key)
    _checkpoint(entries, final, key)
    if final["count"] != len(entries):
        raise VerificationError("final checkpoint does not cover all supplied history")
    events = _events(entries, run_id)
    if [event.get("kind") for _, event in events] != [
        "selection",
        "execution-start",
        "execution-finish",
    ]:
        raise VerificationError(
            "run needs exactly one selection followed by start and finish"
        )
    if opening["count"] != events[0][0] + 1:
        raise VerificationError("opening checkpoint does not end at selection")
    return events


def _selected_inputs(events, plan, pins, operator_id, opening):
    """Bind the exact selected inputs and the consumer's retained opening."""
    expected = _event(plan, "selection", pins=pins, operatorId=operator_id)
    if events[0][1] != expected:
        raise VerificationError(
            "selected plan, configuration, controls or operator differ"
        )
    expected_start = _event(
        plan, "execution-start", openingCheckpointDigest=digest(PROFILE, dict(opening))
    )
    if events[1][1] != expected_start:
        raise VerificationError(
            "execution start does not bind retained opening checkpoint"
        )


def verify_selected_history(
    history: Path,
    plan: RunPlan,
    records: Sequence[AttemptRecord],
    *,
    configuration: bytes,
    controls: bytes,
    artifacts: Mapping[str, bytes],
    sources: Mapping[str, bytes],
    ended_at: str,
    opening_checkpoint: Mapping[str, Any] | None,
    final_checkpoint: Mapping[str, Any] | None,
    pinned_witness_key: str,
    expected_operator_id: str,
) -> dict[str, Any]:
    """Refuse selection substitution, reordering, forks and omitted closure bytes.

    Both checkpoints and the key come from the consumer, not candidate history.
    A pass authenticates one selection in the supplied full history. The signer
    and caller can fabricate a consistent transcript; execution truth, global
    uniqueness, real-time precedence and independent custody remain unestablished.
    """
    _operator(expected_operator_id)
    pins = selection_pins(plan, configuration, controls)
    entries = _history(history)
    events = _bound_events(
        entries, plan.run_id, opening_checkpoint, final_checkpoint, pinned_witness_key
    )
    _selected_inputs(events, plan, pins, expected_operator_id, opening_checkpoint)
    bound_digest, appraisal = execution_digest(
        plan, records, artifacts=artifacts, sources=sources, ended_at=ended_at
    )
    if events[2][1] != _event(plan, "execution-finish", executionDigest=bound_digest):
        raise VerificationError(
            "execution finish differs from retained native evidence"
        )
    return {
        "profile": PROFILE,
        "status": "selected-history-consistent",
        "runId": plan.run_id,
        "pins": pins,
        "executionDigest": bound_digest,
        "historyCoverage": {
            "firstSequence": 1,
            "lastSequence": len(entries),
            "head": entries[-1]["hash"],
        },
        "selectionSequence": events[0][0] + 1,
        "witnessKeyAuthority": "consumer-configured-pin",
        "declaredOperator": expected_operator_id,
        "realTimePrecedence": "not-established",
        "globalUniqueSelection": "not-established",
        "independentCustody": "not-established",
        "execution": appraisal,
    }
