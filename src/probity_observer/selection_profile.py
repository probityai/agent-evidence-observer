"""Installed finite checker/selection controls; local custody only.

This is an executable protocol demonstration, not a registered evaluation study.
It executes only the bundled finite checker, never a user-supplied code path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .crypto import SigningKey, VerificationError, strict_loads
from .evaluation_history import (
    REQUIRED_ROLES,
    ArtifactRef,
    AttemptRecord,
    AttemptSpec,
    RunPlan,
    SourcePin,
    artifact_ref,
    decode_record,
    encode_record,
    verify_history,
)
from .history import Witness, append_history, read_history, verify_checkpoint
from .run_selection import (
    close_selected_run,
    execution_digest,
    open_run_selection,
    selection_pins,
    start_selected_run,
    verify_selected_history,
)

CHECKER = b"def check(value, threshold):\n    return value >= threshold\n"
ALTERNATE_CHECKER = b"def check(value, threshold):\n    return value > threshold\n"
CONTROLS = b'{"belowThreshold":0,"atThreshold":1}'
OPERATOR = "local-installed-profile"
END = "2026-10-04T10:00:03Z"


def _save(path: Path, value: Any) -> None:
    """Retain canonical public evidence, without private signer material."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encode_record(value))


def _plan() -> tuple[RunPlan, dict[str, bytes]]:
    """Pin the original seven-role corpus used by this bounded local run."""
    sources = {
        f"{role}.json": encode_record({"role": role, "kind": "finite-local-fixture"})
        for role in sorted(REQUIRED_ROLES)
    }
    sources["checker.json"] = CHECKER
    sources["harness.json"] = Path(__file__).read_bytes()
    pins = tuple(
        SourcePin(
            role,
            role,
            "local-v1",
            artifact_ref(f"{role}.json", sources[f"{role}.json"]),
        )
        for role in sorted(REQUIRED_ROLES)
    )
    return RunPlan(
        "finite-selection",
        "2026-10-04T10:00:00Z",
        (AttemptSpec("a1", "sample-1", 1),),
        pins,
    ), sources


def _configuration(configuration, controls):
    """Refuse ambiguous JSON and unsupported finite checker inputs."""
    config, cases = decode_record(configuration), decode_record(controls)
    if not isinstance(config, dict) or set(config) != {"threshold"}:
        raise VerificationError("finite configuration shape is unsupported")
    if not isinstance(cases, dict) or set(cases) != {"belowThreshold", "atThreshold"}:
        raise VerificationError("finite controls shape is unsupported")
    values = [config["threshold"], cases["belowThreshold"], cases["atThreshold"]]
    if any(type(value) is not int or value < 0 for value in values):
        raise VerificationError("finite checker inputs must be nonnegative integers")
    return config, cases


def _execute(plan, configuration, controls, sources):
    """Actually invoke the selected retained checker and its negative control."""
    checker_bytes = sources["checker.json"]
    if checker_bytes not in (CHECKER, ALTERNATE_CHECKER):
        raise VerificationError("finite runner only executes its bundled checker")
    config, cases = _configuration(configuration, controls)
    namespace: dict[str, Any] = {}
    # The source is the exact bundled finite checker checked above.
    exec(compile(checker_bytes, "retained-finite-checker", "exec"), namespace)  # noqa: S102
    checker = namespace["check"]
    negative = checker(cases["belowThreshold"], config["threshold"])
    observed = checker(cases["atThreshold"], config["threshold"])
    outcome = "pass" if observed and not negative else "fail"
    raw = encode_record(
        {
            "run_id": plan.run_id,
            "attempt_id": "a1",
            "status": "completed",
            "outcome": outcome,
            "content": {"observed": observed, "negative": negative},
        }
    )
    record = AttemptRecord(
        plan.run_id,
        "a1",
        1,
        "completed",
        outcome,
        "2026-10-04T10:00:01Z",
        "2026-10-04T10:00:02Z",
        None,
        artifact_ref("output.json", raw),
    )
    return (record,), {"output.json": raw}


def _shopping(root, plan, sources, key):
    """Timestamp both candidates, observe results, then choose a passing one."""
    history = root / "candidates.jsonl"
    witness = Witness(root / "candidate-witness-state.json", key)
    configs = (b'{"threshold":1}', b'{"threshold":2}')
    controls = (CONTROLS, b'{"belowThreshold":0,"atThreshold":2}')
    alternate_sources = {**sources, "checker.json": ALTERNATE_CHECKER}
    alternate_plan = replace(
        plan,
        sources=tuple(
            replace(
                pin,
                version="candidate-v2",
                artifact=artifact_ref("checker.json", ALTERNATE_CHECKER),
            )
            if pin.role == "checker"
            else pin
            for pin in plan.sources
        ),
    )
    candidates = ((plan, sources), (alternate_plan, alternate_sources))
    receipts = []
    for index, (candidate, retained) in enumerate(candidates):
        config, control = configs[index], controls[index]
        append_history(
            history,
            {
                "kind": "candidate-pin",
                "claimedAt": plan.created_at,
                "pins": selection_pins(candidate, config, control),
            },
        )
        receipts.append(witness.checkpoint(history))
        _save(root / f"candidate-{index}" / "plan.json", asdict(candidate))
        (root / f"candidate-{index}" / "configuration.json").write_bytes(config)
        (root / f"candidate-{index}" / "controls.json").write_bytes(control)
        (root / f"candidate-{index}" / "checker.py").write_bytes(
            retained["checker.json"]
        )
    outcomes = []
    for index, (candidate, retained) in enumerate(candidates):
        records, artifacts = _execute(
            candidate, configs[index], controls[index], retained
        )
        result = verify_history(
            candidate, records, artifacts=artifacts, sources=retained, ended_at=END
        )
        _save(
            root / f"candidate-{index}" / "records.json",
            [asdict(record) for record in records],
        )
        (root / f"candidate-{index}" / "output.json").write_bytes(
            artifacts["output.json"]
        )
        outcomes.append(
            {"outcome": records[0].outcome, "readerStatus": result["status"]}
        )
    entries = read_history(history)
    for receipt in receipts:
        verify_checkpoint(entries[: receipt["count"]], receipt, key.public_hex)
    chosen = next(
        index for index, result in enumerate(outcomes) if result["outcome"] == "pass"
    )
    result = {
        "signedCandidates": receipts,
        "observedOutcomes": outcomes,
        "chosenAfterObservation": chosen,
        "uniqueSelection": "not-established",
        "timestampAuthority": "same-local-operator",
        "realTimePrecedence": "not-established",
    }
    _save(root / "candidate-shopping.json", result)
    return result


def _produce(root, plan, sources, key):
    """Select and checkpoint before actual invocation; retain exact byte sets."""
    configuration = b'{"threshold":1}'
    history = root / "history.jsonl"
    witness = Witness(root / "witness-state.json", key)
    opening = open_run_selection(
        history, witness, plan, configuration, CONTROLS, operator_id=OPERATOR
    )
    start_selected_run(
        history, witness, plan, configuration, CONTROLS, opening, operator_id=OPERATOR
    )
    records, artifacts = _execute(plan, configuration, CONTROLS, sources)
    closure, _ = execution_digest(
        plan, records, artifacts=artifacts, sources=sources, ended_at=END
    )
    final = close_selected_run(history, witness, plan, closure)
    for name, content in sources.items():
        (root / "sources").mkdir(exist_ok=True)
        (root / "sources" / name).write_bytes(content)
    for name, content in artifacts.items():
        (root / name).write_bytes(content)
    (root / "configuration.json").write_bytes(configuration)
    (root / "controls.json").write_bytes(CONTROLS)
    _save(root / "plan.json", asdict(plan))
    _save(root / "records.json", [asdict(record) for record in records])
    _save(root / "consumer-opening.json", opening)
    _save(root / "consumer-final.json", final)
    return history, records, artifacts, configuration, opening, final


def _rewritten(path, events, key):
    """Let an adversary reuse the same key and a fresh witness state."""
    for event in events:
        append_history(path, event)
    return Witness(path.with_suffix(".witness.json"), key).checkpoint(path)


def _controls(root, plan, sources, key, state):
    """Keep consumer anchors fixed while exercising producer-controlled attacks."""
    history, records, artifacts, config, opening, final = state
    kwargs = {
        "configuration": config,
        "controls": CONTROLS,
        "artifacts": artifacts,
        "sources": sources,
        "ended_at": END,
        "opening_checkpoint": opening,
        "final_checkpoint": final,
        "pinned_witness_key": key.public_hex,
        "expected_operator_id": OPERATOR,
    }
    positive = verify_selected_history(history, plan, records, **kwargs)
    events = [entry["event"] for entry in read_history(history)]
    variants = {
        "substituted-configuration": (events, {"configuration": b'{"threshold":2}'}),
        "substituted-control": (
            events,
            {"controls": b'{"belowThreshold":1,"atThreshold":1}'},
        ),
        "late-commit": ([events[1], events[0], events[2]], {}),
        "multiple-candidates": ([events[0], events[0], *events[1:]], {}),
        "fork": ([{**events[0], "operatorId": "fork-operator"}, *events[1:]], {}),
        "missing-anchor": (events, {"opening_checkpoint": None}),
        "missing-history": (None, {}),
        "missing-history-suffix": (events[:2], {}),
        "unsupported-event": (
            [events[0], {**events[1], "kind": "unknown"}, events[2]],
            {},
        ),
    }
    results = {"positive": positive}
    for name, (candidate, overrides) in variants.items():
        path = root / name / "history.jsonl"
        args = {**kwargs, **overrides}
        if candidate is not None:
            args["final_checkpoint"] = _rewritten(path, candidate, key)
        try:
            verify_selected_history(path, plan, records, **args)
        except VerificationError as exc:
            results[name] = {"status": "refused", "reason": str(exc)}
        else:
            raise AssertionError(f"hostile control unexpectedly passed: {name}")
        _save(root / name / "result.json", results[name])
    return results


def _retained_plan(packet):
    """Reconstruct declared types without executing retained source bytes."""
    value = strict_loads((packet / "plan.json").read_bytes())
    sources = tuple(
        SourcePin(**{**pin, "artifact": ArtifactRef(**pin["artifact"])})
        for pin in value["sources"]
    )
    attempts = tuple(AttemptSpec(**attempt) for attempt in value["attempts"])
    return RunPlan(**{**value, "sources": sources, "attempts": attempts})


def _retained_records(packet):
    """Read the finite profile's action-free native output record."""
    values = strict_loads((packet / "records.json").read_bytes())
    records = []
    for value in values:
        if value["actions"]:
            raise VerificationError(
                "finite packet reader does not support action records"
            )
        output = ArtifactRef(**value["output"]) if value["output"] is not None else None
        records.append(AttemptRecord(**{**value, "output": output, "actions": ()}))
    return tuple(records)


def read_profile(packet, opening, final, key, operator):
    """Verify retained bytes using externally configured consumer anchors."""
    try:
        plan, records = _retained_plan(packet), _retained_records(packet)
        sources = {
            path.name: path.read_bytes()
            for path in (packet / "sources").iterdir()
            if path.is_file()
        }
        configuration = (packet / "configuration.json").read_bytes()
        controls = (packet / "controls.json").read_bytes()
        _configuration(configuration, controls)
        return verify_selected_history(
            packet / "history.jsonl",
            plan,
            records,
            configuration=configuration,
            controls=controls,
            artifacts={"output.json": (packet / "output.json").read_bytes()},
            sources=sources,
            ended_at=END,
            opening_checkpoint=opening,
            final_checkpoint=final,
            pinned_witness_key=key,
            expected_operator_id=operator,
        )
    except (OSError, KeyError, TypeError) as exc:
        raise VerificationError(
            "retained finite packet is missing or unsupported"
        ) from exc


def run_profile(output: Path) -> dict[str, Any]:
    """Retain native evidence and fail unless the positive and all controls work."""
    runtime_started_at = datetime.now(UTC).isoformat()
    output.mkdir(parents=True, exist_ok=False)
    plan, sources = _plan()
    key = SigningKey.generate()
    shopping = _shopping(output, plan, sources, key)
    state = _produce(output, plan, sources, key)
    results = _controls(output, plan, sources, key, state)
    report = {
        "profile": "witnessed-run-selection-finite-v1",
        "operator": OPERATOR,
        "witnessPublicKey": key.public_hex,
        "keyCustody": "same-local-process",
        "registeredStudy": False,
        "assessmentTimestamps": "synthetic-fixture-values",
        "runtimeStartedAt": runtime_started_at,
        "runtimeEndedAt": datetime.now(UTC).isoformat(),
        "clockAuthority": "local-process-clock",
        "candidateShopping": shopping,
        "controls": results,
    }
    _save(output / "report.json", report)
    manifest = {
        str(path.relative_to(output)): {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size,
        }
        for path in sorted(output.rglob("*"))
        if path.is_file()
    }
    _save(output / "manifest.json", manifest)
    return report


def main() -> None:
    """Run the installed finite public profile."""
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output-dir", type=Path)
    mode.add_argument("--read-dir", type=Path)
    parser.add_argument("--opening-checkpoint", type=Path)
    parser.add_argument("--final-checkpoint", type=Path)
    parser.add_argument("--witness-key")
    parser.add_argument("--operator")
    args = parser.parse_args()
    if args.output_dir is not None:
        result = run_profile(args.output_dir)
    else:
        if any(
            value is None
            for value in (
                args.opening_checkpoint,
                args.final_checkpoint,
                args.witness_key,
                args.operator,
            )
        ):
            parser.error(
                "reader requires consumer opening, final, witness key and operator"
            )
        result = read_profile(
            args.read_dir,
            strict_loads(args.opening_checkpoint.read_bytes()),
            strict_loads(args.final_checkpoint.read_bytes()),
            args.witness_key,
            args.operator,
        )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
