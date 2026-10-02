"""Retain a pinned AAE decision joined to protected local effect and history."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path
from typing import Any

from aae_demo import CONTENT, _mandate, _request
from aae_replay import run_replay

from probity_observer.aae_binding import local_transaction
from probity_observer.aae_dispatch import (
    AaeProtectedDispatcher,
    verify_aae_dispatch_bundle,
)
from probity_observer.aae_enforce import enforce_check, native_digest
from probity_observer.authorization import GrantPolicy, issue_grant, utc_clock
from probity_observer.crypto import SigningKey, VerificationError, canonical


def run_demo(output: Path) -> dict[str, Any]:
    """Run one local effect, restart replay and offline decision/history checks.

    Parameters
    ----------
    output : Path
        Empty directory for public inputs, target bytes, signed histories,
        separate demonstration pins and per-file SHA-256 manifest. Private keys
        remain in memory. This is a same-operator fixture, not outside custody.

    Returns
    -------
    dict[str, Any]
        Measured native replay and joined result with explicit non-assertions.

    Raises
    ------
    ValueError
        If output is nonempty, preventing stale reports from being reused.
    VerificationError
        If any native or protected verification fails.
    """
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("AAE protected dispatch demo output directory must be empty")
    workspace = output / "workspace"
    workspace.mkdir()
    request = _request()
    transaction = local_transaction(request)
    mandate = _mandate(transaction)
    decision = {
        "mandate": mandate,
        "transaction": transaction,
        "record": enforce_check(mandate, transaction),
        "pinned_mandate_digest": native_digest("mandate", mandate),
    }
    issuer, observer, witness = (SigningKey.generate() for _ in range(3))
    policy = GrantPolicy(issuer.public_hex)
    host = {
        "workspace": workspace,
        "state_dir": output / "dispatch",
        "expected_request": request,
        "policy": policy,
        "observer_key": observer,
        "witness_key": witness,
    }
    dispatcher = AaeProtectedDispatcher(**host, **decision)
    initial = dispatcher.initialize()
    now = utc_clock()
    grant = issue_grant(
        request, issuer, issued_at=now, expires_at=now + timedelta(seconds=60)
    )
    result = dispatcher.write(request, grant, CONTENT)
    restart = AaeProtectedDispatcher(
        **host, **decision, retained_authorization_head=initial
    )
    replay = restart.write(request, grant, CONTENT)
    arguments = dict(
        **decision,
        directory=host["state_dir"],
        expected_request=request,
        policy=policy,
        observer_key=observer.public_hex,
        witness_key=witness.public_hex,
        retained_authorization_head=initial,
        workspace=workspace,
    )
    linked = verify_aae_dispatch_bundle(**arguments)
    missing = verify_aae_dispatch_bundle(**{**arguments, "directory": None})
    try:
        verify_aae_dispatch_bundle(
            **{**arguments, "pinned_mandate_digest": "sha256:" + "0" * 64}
        )
    except VerificationError as exc:
        refusal = str(exc)
    else:
        raise RuntimeError("AAE protected dispatch accepted the wrong mandate pin")
    report = {
        "status": "demo-passed",
        "nativeReplay": run_replay(),
        "linked": linked,
        "missingBundle": missing,
        "firstResult": asdict(result),
        "restartResult": asdict(replay),
        "wrongPinRefusal": refusal,
        "operator": "same-operator-fixture",
        "notEstablished": [
            "AAE nine-step JWS conformance",
            "authenticated AAE issuer",
            "EVM execution",
            "independent custody",
            "isolated child launch",
            "complete effect capture",
            "production deployment",
        ],
    }
    records = {
        "decision-inputs.json": decision,
        "request.json": asdict(request),
        "grant.json": grant,
        "consumer-pins.json": {
            "mandateDigest": decision["pinned_mandate_digest"],
            "policy": asdict(policy),
            "observerKey": observer.public_hex,
            "witnessKey": witness.public_hex,
            "retainedHead": initial,
        },
        "report.json": report,
    }
    for name, value in records.items():
        (output / name).write_bytes(canonical(value))
    manifest = {
        path.relative_to(output).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in sorted(output.rglob("*"))
        if path.is_file()
    }
    (output / "manifest.json").write_bytes(canonical({"fileSha256": manifest}))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    print(json.dumps(run_demo(parser.parse_args().output), sort_keys=True))
