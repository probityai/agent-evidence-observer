"""Framework-free installed replay of the finite operator acceptance population."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from probity_observer.authorization import ActionRequest, GrantPolicy, verify_authorized_packet
from probity_observer.crypto import canonical, strict_loads
from probity_observer.history import read_history, verify_checkpoint
from probity_observer.ledger import read_ledger, verify_ledger_head

from .protocol import FORMAT, checked_identity, exact_fields, require, sha
from .sources import verify_sources
from .worker import CONTENT

CASES = ("permit", "failed-after", "unavailable-before", "unavailable-after", "lost-ack")


def load(path: Path) -> Any:
    """Read exact canonical JSON bytes from a retained artifact."""
    return strict_loads(path.read_bytes())


def _population(directory: Path, expected: dict[str, str]) -> None:
    """Bind the full physical record population to host-selected exact bytes."""
    found = {str(path.relative_to(directory)) for path in directory.rglob("*") if path.is_file()}
    require(found == set(expected), "case file population differs")
    for name, digest in expected.items():
        path = directory / name
        require(not path.is_symlink(), "case file is a symlink")
        require(path.resolve().is_relative_to(directory.resolve()), "case file escapes directory")
        require(sha(path.read_bytes()) == digest, "host-selected case bytes differ")


def _terminal(directory: Path, policy: dict[str, Any]) -> None:
    """Replay issuer authorization, packet signatures and actual target bytes."""
    authorization = load(directory / "authorization.json")
    exact_fields(authorization, {"request", "policy", "grant", "referenceTime"}, "authorization record fields differ")
    require(authorization["request"] == policy["request"], "host action selection differs")
    require(authorization["policy"] == {"issuer_key": policy["issuerKey"], "max_validity_seconds": 120}, "host issuer selection differs")
    verify_authorized_packet(load(directory / "packet.json"), directory / "history.jsonl", authorization["grant"],
                             ActionRequest(**policy["request"]), GrantPolicy(policy["issuerKey"], 120),
                             policy["observerKey"], policy["witnessKey"], now=datetime.fromisoformat(authorization["referenceTime"]),
                             workspace=directory / "work")


def _process(directory: Path, policy: dict[str, Any]) -> dict[str, Any]:
    """Keep native exit state distinct from already committed file effects."""
    worker = load(directory / "worker.json")
    process = load(directory / "process.json")
    require(worker["uid"] == policy["producerUid"], "native producer UID differs")
    require(worker["witnessKeyReadable"] is False, "producer could read witness key")
    require(worker["witnessLedgerReadable"] is False, "producer could read witness ledger")
    require(process["returncode"] == policy["expectedExit"], "native process exit differs")
    require(worker["exitCode"] == process["returncode"], "worker and process exit differ")
    require(worker["state"] == policy["expectedState"], "native task state differs")
    return worker


def _effect(directory: Path, policy: dict[str, Any]) -> int:
    """Read the selected target; unwitnessed history never becomes a signed effect."""
    target = directory / "work/result.txt"
    if policy["expectedWrites"] == 0:
        require(not target.exists(), "unexpected native target effect")
        return 0
    require(target.read_bytes() == CONTENT, "native target bytes differ")
    return 1


def _retry(directory: Path, policy: dict[str, Any], receipts: list[dict[str, Any]]) -> None:
    """A retry after lost acknowledgment must name the original persisted begin."""
    if directory.name != "lost-ack":
        return
    process = load(directory / "process.json")
    require(process["retryReturncode"] == 0, "native retry process failed")
    checkpoint = load(directory / "retry-checkpoint.json")
    verify_checkpoint(read_history(directory / "history.jsonl"), checkpoint, policy["witnessKey"])
    require(checkpoint["ledgerReceipt"] == receipts[0], "native retry made a second receipt")


def _case(directory: Path, policy: dict[str, Any]) -> dict[str, Any]:
    """Replay a complete selected task, including registered missing closure."""
    _population(directory, policy["files"])
    worker = _process(directory, policy)
    entries = read_history(directory / "history.jsonl")
    checked_identity(entries, policy["observerKey"])
    current = load(directory / "head.json")
    summary = verify_ledger_head(directory / "ledger.jsonl", policy["initialHead"], policy["witnessKey"])
    verify_ledger_head(directory / "ledger.jsonl", current, policy["witnessKey"])
    require(summary["count"] == current["count"], "retained operator head is not current")
    require(summary["count"] == policy["expectedLedgerCount"], "native ledger population differs")
    receipts = read_ledger(directory / "ledger.jsonl", policy["witnessKey"])
    _retry(directory, policy, receipts)
    if policy["signedTerminal"]:
        _terminal(directory, policy)
        require(summary["missingTerminals"] == [], "signed terminal is missing from ledger")
    effects = _effect(directory, policy)
    release = (worker["state"], policy["signedTerminal"], worker["exitCode"]) == ("COMPLETED", True, 0)
    return {"case": directory.name, "producerUid": worker["uid"], "producerState": worker["state"], "processExit": worker["exitCode"],
            "committedTargetEffects": effects, "effectEvidence": "signed-terminal" if policy["signedTerminal"] else "retained-target-only",
            "signedTerminal": policy["signedTerminal"], "registeredIntervals": summary["registeredIntervals"],
            "missingTerminals": len(summary["missingTerminals"]), "publicationDecision": "RELEASE" if release else "WITHHOLD"}


def read(directory: Path, policy: dict[str, Any]) -> dict[str, Any]:
    """Read one frozen native population under a separately selected host policy.

    Parameters
    ----------
    directory : Path
        Retained public packet root; no private operator state is required.
    policy : dict
        Host-selected exact source/file population and public pins.

    Returns
    -------
    dict
        Finite native process/effect/ledger decisions. JSON summaries are
        unsigned; effect packets and witness receipts carry signatures.
    """
    exact_fields(policy, {"format", "cases", "source", "faultControls"}, "host policy fields differ")
    require(policy["format"] == FORMAT, "host policy format differs")
    require(set(policy["cases"]) == set(CASES), "host case population differs")
    require({path.name for path in directory.iterdir()} == {*CASES, "source", "fault-controls.json"}, "packet population differs")
    verify_sources(directory / "source", policy["source"])
    _faults(directory / "fault-controls.json", policy["faultControls"])
    records = [_case(directory / name, policy["cases"][name]) for name in CASES]
    return {"profile": FORMAT, "witnessScope": "PEER", "independentCustody": False, "modelInferenceCalls": 0,
            "selectedSourceFiles": len(policy["source"]), "records": records,
            "committedTargetEffects": sum(item["committedTargetEffects"] for item in records)}


def _faults(path: Path, expected_sha256: str) -> None:
    """Replay native CLI refusal controls against actual restored stores."""
    require(sha(path.read_bytes()) == expected_sha256, "native fault controls pin differs")
    controls = load(path)
    require(set(controls) == {"rollback", "fork", "missing-ledger", "wrong-key", "wrong-peer"}, "native fault population differs")
    for value in controls.values():
        require(value["refused"] is True, "native fault was accepted")
        require(value["stateUnchanged"] is True, "native refusal changed durable state")


def main() -> None:
    """Require an outside-packet host policy and its exact selected digest."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--host-policy", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    arguments = parser.parse_args()
    require(not arguments.host_policy.resolve().is_relative_to(arguments.packet.resolve()), "host policy must be outside packet")
    require(sha(arguments.host_policy.read_bytes()) == arguments.policy_sha256, "host policy pin differs")
    sys.stdout.buffer.write(canonical(read(arguments.packet, load(arguments.host_policy))) + b"\n")


if __name__ == "__main__":
    main()
