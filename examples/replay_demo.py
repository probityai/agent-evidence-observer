"""Retain actual offline replay, including a signed but fabricated success.

All keys and fixture sources in this demonstration belong to one operator.
The protected action is generated before replay; no pre-effect replay gate,
external custody, native protocol conformance, or durable admission is added.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from protected_action_demo import run_demo as run_action

from probity_observer.attribution import (
    ArtifactPin,
    sign_consumption,
    verify_consumption,
)
from probity_observer.crypto import SigningKey, VerificationError, canonical, digest
from probity_observer.replay import (
    CHECKER_MODULES,
    MAX_INPUT_BYTES,
    MAX_RECORD_BYTES,
    InputPin,
    ReplayPolicy,
    checker_implementation_bytes,
    consumption_checks,
    load_replay_object,
    replay_checks,
    replay_consumption,
)

SOURCE = "https://github.com/probityai/agent-evidence-observer"


def _pin(raw: bytes, revision: str) -> ArtifactPin:
    """Attach caller-selected source provenance to exact retained bytes."""
    return ArtifactPin(
        "Probity local reference",
        SOURCE,
        revision,
        "Probity contributors",
        "Apache-2.0",
        hashlib.sha256(raw).hexdigest(),
    )


def _inputs(output: Path, report: dict[str, Any]) -> dict[str, bytes]:
    """Collect every context byte used by native replay, without normalization."""
    producer, consumer = output / "producer", output / "consumer"
    paths = {
        "authorization": producer / "grant.json",
        "observation": producer / "packet.json",
        "request": producer / "request.json",
        "grant-policy": consumer / "grant-policy.json",
        "admission-policy": consumer / "admission-policy.json",
        "history": producer / "history.jsonl",
        "ledger": producer / "ledger.jsonl",
        "workspace:result.txt": producer / "workspace/result.txt",
    }
    inputs = {role: path.read_bytes() for role, path in paths.items()}
    grant_policy = json.loads(inputs["grant-policy"])
    admission = json.loads(inputs["admission-policy"])
    inputs["key-pins"] = canonical(
        {
            "issuer": grant_policy["issuer_key"],
            "observer": admission["observer_key"],
            "witness": admission["witness_key"],
        }
    )
    inputs["reference-time"] = canonical({"now": report["referenceTime"]})
    inputs["workspace-manifest"] = canonical(
        {
            "files": {
                "result.txt": hashlib.sha256(inputs["workspace:result.txt"]).hexdigest()
            }
        }
    )
    fixture = inputs["request"]
    manifest = canonical(
        {"files": {"request.json": hashlib.sha256(fixture).hexdigest()}}
    )
    inputs.update(
        {
            "owner-manifest": manifest,
            "copy-manifest": manifest,
            "owner:request.json": fixture,
            "copy:request.json": fixture,
        }
    )
    return inputs


def _policy(
    inputs: dict[str, bytes], revision: str, signer: SigningKey
) -> ReplayPolicy:
    """Freeze context pins separately from the candidate consumption record."""
    request, packet = json.loads(inputs["request"]), json.loads(inputs["observation"])
    return ReplayPolicy(
        tuple(
            InputPin(role, _pin(raw, revision)) for role, raw in sorted(inputs.items())
        ),
        _pin(checker_implementation_bytes(), revision),
        ("request.json",),
        ("result.txt",),
        request["request_id"],
        digest("probity-claim-v0", packet["claim"]),
        signer.public_hex,
    )


def _signed(
    inputs: dict[str, bytes],
    policy: ReplayPolicy,
    signer: SigningKey,
    report: dict[str, Any],
) -> dict[str, Any]:
    """Sign a report without implying that signing proves its results."""
    return sign_consumption(
        policy.action_id,
        policy.claim_digest,
        consumption_checks(inputs, policy, report),
        signer,
    )


def _require_refusal(operation: Callable[[], Any]) -> str:
    """Fail the demonstration if a malformed or substituted input is accepted."""
    try:
        operation()
    except VerificationError as exc:
        return str(exc)
    raise RuntimeError("replay negative control was accepted")


def _controls(
    inputs: dict[str, bytes],
    policy: ReplayPolicy,
    signer: SigningKey,
    record: dict[str, Any],
) -> dict[str, Any]:
    """Exercise byte substitution, missing owner, stale checker, and false success."""
    changed = {**inputs, "copy:request.json": b"substituted bytes"}
    missing = {
        role: raw for role, raw in inputs.items() if role != "owner:request.json"
    }
    stale = replace(
        policy, checker_source=replace(policy.checker_source, sha256="0" * 64)
    )
    matrix = {
        "substituted-copy": _require_refusal(
            lambda: replay_consumption(record, changed, policy)
        ),
        "missing-owner": replay_checks(missing, policy),
        "stale-checker": _require_refusal(lambda: replay_checks(inputs, stale)),
    }
    altered = dict(inputs)
    packet = json.loads(altered["observation"])
    packet.pop("authorizationBinding")
    altered["observation"] = canonical(packet)
    repinned = replace(
        policy,
        input_pins=tuple(
            InputPin(
                pin.role,
                replace(
                    pin.artifact, sha256=hashlib.sha256(altered[pin.role]).hexdigest()
                ),
            )
            for pin in policy.input_pins
        ),
    )
    actual = replay_checks(altered, repinned)
    fabricated = copy.deepcopy(actual)
    for item in fabricated["checks"]:
        item["outcome"] = "pass"
    false_record = _signed(altered, repinned, signer, fabricated)
    binding = verify_consumption(
        false_record,
        altered,
        repinned.pins,
        action_id=repinned.action_id,
        claim_digest=repinned.claim_digest,
        pinned_signer=repinned.pinned_signer,
    )
    result = replay_consumption(false_record, altered, repinned)
    if binding["status"] != "bindings-verified" or result["decision"] != "block":
        raise RuntimeError("fabricated success did not distinguish binding from replay")
    matrix["fabricated-success"] = {
        "bindings": binding,
        "actualReplay": result,
        "record": false_record,
        "policy": repinned.fields(),
        "mutatedObservationHex": altered["observation"].hex(),
    }
    return matrix


def run_demo(output: Path, source_revision: str) -> dict[str, Any]:
    """Generate and retain a finite same-operator action and replay matrix.

    Parameters
    ----------
    output : Path
        New or empty directory. Existing files are not overwritten.
    source_revision : str
        Full Git object id selected by the caller for the source checkout.
        The caller must verify that this revision contains the executed files;
        this offline example validates syntax, not repository membership.

    Returns
    -------
    dict[str, Any]
        Actual clean acceptance and negative controls with their retained inputs.
    """
    if output.exists() and any(output.iterdir()):
        raise ValueError("replay output directory must be new or empty")
    output.mkdir(parents=True, exist_ok=True)
    action = run_action(output / "native")
    inputs = _inputs(output / "native", action)
    signer = SigningKey.generate()
    policy = _policy(inputs, source_revision, signer)
    actual = replay_checks(inputs, policy)
    record = _signed(inputs, policy, signer, actual)
    clean = replay_consumption(record, inputs, policy)
    if clean["decision"] != "replay-acceptable":
        raise RuntimeError("clean native replay was not acceptable")
    controls = _controls(inputs, policy, signer, record)
    _retain(output, inputs, policy, record, clean, controls)
    return {
        "status": "demo-passed",
        "cleanDecision": clean["decision"],
        "fabricatedSuccessDecision": controls["fabricated-success"]["actualReplay"][
            "decision"
        ],
        "missingOwnerOutcome": controls["missing-owner"]["contextOutcome"],
        "coverage": "declared-inputs-only",
        "operator": "same-operator-fixture",
        "sourceRevision": source_revision,
        "sourceMembership": "caller-selected-not-verified",
        "durableAdmission": "not-performed",
        "witnessScope": "PEER",
    }


def _retain(
    output: Path,
    inputs: dict[str, bytes],
    policy: ReplayPolicy,
    record: dict[str, Any],
    clean: dict[str, Any],
    controls: dict[str, Any],
) -> None:
    """Keep native bytes, actual results, and false-success controls for readers."""
    directory = output / "replay-inputs"
    directory.mkdir()
    files = {}
    for number, (role, raw) in enumerate(sorted(inputs.items())):
        name = f"{number:02d}.bin"
        (directory / name).write_bytes(raw)
        files[role] = "replay-inputs/" + name
    retained = {
        "replay-policy.json": policy.fields(),
        "consumption-record.json": record,
        "replay-result.json": clean,
        "mutation-matrix.json": controls,
        "input-paths.json": files,
    }
    for name, value in retained.items():
        (output / name).write_bytes(canonical(value))
    (output / "checker-source-manifest.json").write_bytes(
        checker_implementation_bytes()
    )
    source_output = output / "checker-source"
    source_output.mkdir()
    source_root = Path(__file__).parents[1] / "src/probity_observer"
    for name in CHECKER_MODULES:
        (source_output / name).write_bytes((source_root / name).read_bytes())
    manifest = {
        path.relative_to(output).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "replay-manifest.json"
    }
    (output / "replay-manifest.json").write_bytes(canonical({"fileSha256": manifest}))


def main() -> None:
    """Run the retained demonstration from one explicit source checkout."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--source-revision")
    parser.add_argument("--replay", action="store_true")
    parser.add_argument("--trusted-policy", type=Path)
    arguments = parser.parse_args()
    report = _command_report(arguments, parser)
    print(json.dumps(report, sort_keys=True))
    _exit_if_blocked(report, arguments.replay)


def _command_report(
    arguments: argparse.Namespace, parser: argparse.ArgumentParser
) -> dict[str, Any]:
    """Choose generation or read-only replay without implicit policy discovery."""
    if arguments.replay:
        return replay_retained(arguments.output, _selected_policy(arguments, parser))
    if arguments.source_revision is None:
        parser.error("the demonstration requires --source-revision")
    return run_demo(arguments.output, arguments.source_revision)


def _selected_policy(
    arguments: argparse.Namespace, parser: argparse.ArgumentParser
) -> Path:
    """Require an explicit consumer-selected policy for retained replay."""
    if arguments.trusted_policy is None:
        parser.error("--replay requires an independently selected --trusted-policy")
    return arguments.trusted_policy


def _exit_if_blocked(report: dict[str, Any], replay: bool) -> None:
    """Expose a blocked gate as a failing command after printing actual results."""
    if replay and report["actualReplay"]["decision"] != "replay-acceptable":
        raise SystemExit(1)


def _read_bounded(path: Path, maximum: int) -> bytes:
    """Refuse oversized retained files before parsing or native verification."""
    if path.is_symlink() or path.stat().st_size > maximum:
        raise VerificationError(
            "retained replay file is a symlink or exceeds its byte bound"
        )
    raw = path.read_bytes()
    if len(raw) > maximum:
        raise VerificationError("retained replay file exceeds its byte bound")
    return raw


def replay_retained(output: Path, trusted_policy: Path) -> dict[str, Any]:
    """Replay a retained package with policy selected outside the candidate.

    Parameters
    ----------
    output : Path
        Read-only retained demonstration directory. The local filesystem and
        Python runtime must be trusted; this is not a hostile-host sandbox.
    trusted_policy : Path
        Consumer-acquired policy, not a pin inferred from candidate signatures.
        The demo's policy is suitable only for same-operator reproduction.
    """
    policy = ReplayPolicy.from_fields(
        load_replay_object(_read_bounded(trusted_policy, MAX_RECORD_BYTES))
    )
    paths = load_replay_object(
        _read_bounded(output / "input-paths.json", MAX_RECORD_BYTES)
    )
    if type(paths) is not dict or set(paths) != policy.expected_roles:
        raise VerificationError(
            "retained replay input paths differ from the trusted policy"
        )
    if any(
        not isinstance(path, str)
        or re.fullmatch(r"replay-inputs/[0-9]{2}\.bin", path) is None
        for path in paths.values()
    ):
        raise VerificationError(
            "retained replay input path is outside the fixed package layout"
        )
    if (output / "replay-inputs").is_symlink():
        raise VerificationError("retained replay input directory is a symlink")
    inputs = {
        role: _read_bounded(output / path, MAX_INPUT_BYTES)
        for role, path in paths.items()
    }
    record = load_replay_object(
        _read_bounded(output / "consumption-record.json", MAX_RECORD_BYTES)
    )
    clean = replay_consumption(record, inputs, policy)
    return {
        "status": "replayed",
        "actualReplay": clean,
        "coverage": "declared-inputs-only",
        "durableAdmission": "not-performed",
        "witnessScope": "PEER",
    }


if __name__ == "__main__":
    main()
