"""Retain a same-operator declaration, broker effect, and consumer admission."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from probity_observer import (
    AdmissionPolicy,
    AdmissionStore,
    Broker,
    LedgerWitness,
    SigningKey,
    VerificationError,
)
from probity_observer.crypto import canonical, digest


def run_demo(output: Path) -> dict[str, object]:
    """Create one bounded effect, persist its admission, and refuse its replay.

    Parameters
    ----------
    output : Path
        Empty output directory. Producer bytes and consumer-owned policy/state
        are retained in separate subdirectories for offline inspection.

    Returns
    -------
    dict[str, object]
        Demonstration status, admitted interval, replay refusal, and explicit
        PEER/same-operator limits. The report is also retained as JSON.

    Raises
    ------
    ValueError
        If the output directory is nonempty.
    VerificationError
        If a valid interval cannot be admitted or replay is not refused.

    Notes
    -----
    Both signers and the consumer are operated by this script. Its separately
    retained fixture pins demonstrate protocol ordering, not external custody.
    """
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("admission demo output directory must be empty")
    producer, consumer = output / "producer", output / "consumer"
    workspace = producer / "workspace"
    workspace.mkdir(parents=True)
    consumer.mkdir()
    observer, witness_key = SigningKey.generate(), SigningKey.generate()
    witness = LedgerWitness(producer / "ledger.jsonl", witness_key, observer.public_hex)
    authority = {
        "intervalId": "admission-demo-1",
        "scope": "/work",
        "operation": "write-file",
    }
    policy = AdmissionPolicy(
        authority["intervalId"],
        digest("probity-authority-v0", authority),
        observer.public_hex,
        witness_key.public_hex,
        witness.signed_head(),
    )
    (consumer / "policy.json").write_bytes(canonical(asdict(policy)))
    store = AdmissionStore(consumer / "state.json")
    store.initialize(policy.observer_key, policy.witness_key)
    history = producer / "history.jsonl"
    broker = Broker(workspace, history, authority, observer, witness)
    broker.begin()
    broker.write("request-1", "/work/result.txt", b"one durable effect\n")
    packet = broker.seal()
    (producer / "packet.json").write_bytes(canonical(packet))
    decision = store.admit(packet, history, witness.state_path, policy)
    (consumer / "decision.json").write_bytes(canonical(decision))
    refusal = _refuse_replay(store, packet, history, witness.state_path, policy)
    report = {
        "status": "demo-passed",
        "intervalId": policy.interval_id,
        "admissionStatus": decision["status"],
        "replayRefusal": refusal,
        "witnessScope": "PEER",
        "evidence_vantage": "artifact",
        "operator": "same-operator-fixture",
    }
    (output / "demo-report.json").write_bytes(canonical(report))
    return report


def _refuse_replay(
    store: AdmissionStore,
    packet: dict[str, Any],
    history: Path,
    ledger: Path,
    policy: AdmissionPolicy,
) -> str:
    """Require the persisted decision to prevent a second admission."""
    try:
        store.admit(packet, history, ledger, policy)
    except VerificationError as exc:
        if str(exc) != "interval was already admitted by this consumer":
            raise
        return str(exc)
    raise VerificationError("admission demo unexpectedly admitted a replay")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    print(json.dumps(run_demo(parser.parse_args().output), sort_keys=True))
