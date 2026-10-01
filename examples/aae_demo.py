"""Run a native unsigned AAE decision before one recorded local file write."""

from __future__ import annotations

import argparse
import copy
import hashlib
import inspect
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from aae_replay import run_replay

from probity_observer.aae_binding import (
    local_transaction,
    sign_effect_link,
    verify_effect_link,
    write_local_action,
)
from probity_observer.aae_enforce import canonical_bytes, enforce_check, native_digest
from probity_observer.authorization import ActionRequest
from probity_observer.broker import Broker
from probity_observer.crypto import SigningKey, VerificationError
from probity_observer.history import Witness

CONTENT = b"local AAE reference write\n"


def _request() -> ActionRequest:
    return ActionRequest(
        "aae-local-1",
        "attempt-1",
        "request-1",
        "tenant-1",
        "principal-1",
        "local.write-file",
        "/work/result.txt",
        hashlib.sha256(CONTENT).hexdigest(),
    )


def _mandate(transaction: dict[str, Any]) -> dict[str, Any]:
    constraints = [
        {"type": "exact", "field": key, "value": value}
        for key, value in transaction.items()
        if key != "action"
    ]
    return {
        "mandate_version": "1.0",
        "grants": [
            {
                "action_binding": native_digest("action", transaction["action"]),
                "type_fields": ["verb", "targetKind"],
                "disposition": "allow",
                "constraints": constraints,
            }
        ],
    }


def _refusal(operation, message: str) -> str:
    try:
        operation()
    except VerificationError as exc:
        return str(exc)
    raise RuntimeError(message)


def _negative_links(arguments: dict[str, Any]) -> dict[str, str]:
    record = copy.deepcopy(arguments["record"])
    record["core_digest"] = "sha256:" + "0" * 64
    failures = {
        "wrong-core-digest": {"record": record},
        "wrong-observer-pin": {"pinned_observer_key": SigningKey.generate().public_hex},
    }
    return {
        name: _refusal(
            lambda changes=changes: verify_effect_link(**{**arguments, **changes}),
            f"AAE negative control accepted: {name}",
        )
        for name, changes in failures.items()
    }


def _write_records(output: Path, values: dict[str, Any]) -> None:
    for name, value in values.items():
        (output / name).write_bytes(canonical_bytes(value))
    manifest = {
        path.relative_to(output).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "manifest.json"
    }
    (output / "manifest.json").write_bytes(canonical_bytes({"fileSha256": manifest}))


def run_demo(output: Path) -> dict[str, Any]:
    """Retain kernel inputs, a PEER effect and separate non-assertions."""
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("AAE demo output directory must be empty")
    request = _request()
    transaction = local_transaction(request)
    mandate = _mandate(transaction)
    record = enforce_check(mandate, transaction)
    mandate_pin = native_digest("mandate", mandate)
    workspace = output / "workspace"
    workspace.mkdir()
    observer, witness_key = SigningKey.generate(), SigningKey.generate()
    witness = Witness(output / "witness-state.json", witness_key)
    history = output / "history.jsonl"
    broker = Broker(
        workspace,
        history,
        {
            "intervalId": request.run_id,
            "scope": "/work",
            "operation": "write-file",
        },
        observer,
        witness,
    )
    broker.begin()
    write_local_action(
        mandate,
        transaction,
        record,
        request,
        CONTENT,
        broker,
        pinned_mandate_digest=mandate_pin,
    )
    packet = broker.seal()
    link = sign_effect_link(record, request, packet, observer)
    arguments = dict(
        mandate=mandate,
        transaction=transaction,
        record=record,
        request=request,
        link=link,
        packet=packet,
        history=history,
        pinned_mandate_digest=mandate_pin,
        pinned_observer_key=observer.public_hex,
        pinned_witness_key=witness_key.public_hex,
        workspace=workspace,
    )
    linked = verify_effect_link(**arguments)
    missing = verify_effect_link(**{**arguments, "link": None})
    forged = copy.deepcopy(mandate)
    forged["issuer"] = "did:example:forged-unsigned-issuer"
    forged_record = enforce_check(forged, transaction)
    forged_unknown = verify_effect_link(
        **{
            **arguments,
            "mandate": forged,
            "record": forged_record,
            "pinned_mandate_digest": native_digest("mandate", forged),
            "link": None,
        }
    )
    report = {
        "status": "demo-passed",
        "nativeReplay": run_replay(),
        "linked": linked,
        "missingReceipt": missing,
        "unsignedIssuer": forged_unknown,
        "refusals": _negative_links(arguments),
        "operator": "same-operator-fixture",
        "notEstablished": [
            "AAE nine-step JWS conformance",
            "authenticated AAE issuer",
            "EVM transfer execution",
            "independent observer custody",
            "externally witnessed pre-effect kernel commitment",
        ],
        "checkerSha256": hashlib.sha256(
            Path(inspect.getfile(enforce_check)).read_bytes()
        ).hexdigest(),
        "demoSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    _write_records(
        output,
        {
            "mandate.json": mandate,
            "transaction.json": transaction,
            "core-record.json": record,
            "request.json": asdict(request),
            "packet.json": packet,
            "effect-link.json": link,
            "consumer-pins.json": {
                "mandateDigest": mandate_pin,
                "observerKey": observer.public_hex,
                "witnessKey": witness_key.public_hex,
            },
            "unsigned-issuer-mandate.json": forged,
            "unsigned-issuer-record.json": forged_record,
            "demo-report.json": report,
        },
    )
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    print(json.dumps(run_demo(parser.parse_args().output), sort_keys=True))
