"""Retain checked authorization and effect inputs for one local action.

This uses the protected-action reference profile, not an external AAE adapter.
All signers are controlled by the demo operator.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path

from protected_action_demo import run_demo as run_action
from probity_observer.attribution import (
    ArtifactPin, check_artifact, sign_consumption, verify_consumption,
)
from probity_observer.authorization import ActionRequest, GrantPolicy, verify_authorized_packet, verify_grant
from probity_observer.crypto import SigningKey, VerificationError, canonical, digest
from datetime import datetime, timezone

SOURCE = "https://github.com/probityai/agent-evidence-observer"
REVISION = "0c3ec928bd8d3c0caf5b292b828143bfa7099d34"


def run_demo(output: Path) -> dict:
    """Make an effect bundle, check its retained inputs, then bind their use."""
    report = run_action(output)
    producer = output / "producer"
    consumer = output / "consumer"
    request = ActionRequest(**json.loads((producer / "request.json").read_bytes()))
    grant_policy = GrantPolicy(**json.loads((consumer / "grant-policy.json").read_bytes()))
    policy = json.loads((consumer / "admission-policy.json").read_bytes())
    now = datetime.strptime(report["referenceTime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    grant_bytes = (producer / "grant.json").read_bytes()
    packet_bytes = (producer / "packet.json").read_bytes()
    grant = json.loads(grant_bytes)

    def authorization(raw: bytes) -> dict:
        verify_grant(json.loads(raw), request, grant_policy, now=now)
        return {"status": "grant-verified", "profile": "experimental-reference"}

    def observation(raw: bytes) -> dict:
        verify_authorized_packet(
            grant, request, grant_policy, json.loads(raw), producer / "history.jsonl",
            policy["observer_key"], policy["witness_key"], now=now,
            workspace=producer / "workspace",
        )
        return {"status": "packet-verified", "witnessScope": "PEER"}

    inputs = {"authorization": grant_bytes, "observation": packet_bytes}
    pins = {
        role: ArtifactPin("Probity", SOURCE, REVISION, "Probity contributors",
                          "Apache-2.0", hashlib.sha256(raw).hexdigest())
        for role, raw in inputs.items()
    }
    checks = [check_artifact(role, inputs[role], pins[role], checker)
              for role, checker in (("authorization", authorization), ("observation", observation))]
    claim_digest = digest("probity-claim-v0", json.loads(packet_bytes)["claim"])
    signer = SigningKey.generate()
    record = sign_consumption(request.request_id, claim_digest, checks, signer)
    arguments = dict(inputs=inputs, pins=pins, action_id=request.request_id,
                     claim_digest=claim_digest, pinned_signer=signer.public_hex)
    verified = verify_consumption(record, **arguments)
    negatives = {}
    for name, changed in (("wrong-action", {"action_id": "another-action"}),
                          ("wrong-claim", {"claim_digest": "0" * 64}),
                          ("substituted-input", {"inputs": {**inputs, "authorization": b"changed"}})):
        try:
            verify_consumption(record, **{**arguments, **changed})
        except VerificationError as exc:
            negatives[name] = str(exc)
        else:
            raise RuntimeError(f"negative control accepted: {name}")
    try:
        verify_consumption({}, **arguments)
    except VerificationError as exc:
        negatives["missing-receipt"] = str(exc)
    else:
        raise RuntimeError("missing consumption receipt was accepted")
    retained = {
        "consumption-record.json": record,
        "consumption-pins.json": {role: asdict(pin) for role, pin in pins.items()},
        "consumption-policy.json": {"signer": signer.public_hex,
                                    "actionId": request.request_id, "claimDigest": claim_digest},
        "consumption-result.json": {**verified, "refusals": negatives,
                                    "missingReceipt": "not-established",
                                    "operator": "same-operator-fixture"},
    }
    for name, value in retained.items():
        (consumer / name).write_bytes(canonical(value))
    manifest = {path.relative_to(output).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(output.rglob("*")) if path.is_file() and path.name != "manifest.json"}
    (output / "manifest.json").write_bytes(canonical({"fileSha256": manifest}))
    return retained["consumption-result.json"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    print(json.dumps(run_demo(parser.parse_args().output), sort_keys=True))
