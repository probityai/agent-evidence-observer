"""Run a signed-action reference kit with durable effect and consumer replay checks.

This example composes the experimental authorization profile with the existing
observer. All keys belong to one operator. It demonstrates a bounded local file
effect and offline checks, not APS, MCP or A2A protocol conformance, an isolated
agent, independent custody, or global exactly-once execution.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import platform
import time
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import cryptography

from probity_observer import (
    AdmissionPolicy,
    AdmissionStore,
    Broker,
    LedgerWitness,
    SigningKey,
    VerificationError,
)
from probity_observer.authorization import (
    ActionRequest,
    AuthorizedBroker,
    GrantPolicy,
    issue_grant,
    verify_authorized_packet,
    verify_grant,
)
from probity_observer.crypto import canonical, digest


def _require_refusal(operation: Callable[[], Any]) -> str:
    """Return an actual verification refusal, propagating unrelated failures.

    Parameters
    ----------
    operation : Callable[[], Any]
        Negative control expected to raise :class:`VerificationError`.

    Returns
    -------
    str
        Actual bounded refusal message, retained in the author-produced report.

    Raises
    ------
    RuntimeError
        If the negative control is accepted.
    """
    try:
        operation()
    except VerificationError as exc:
        return str(exc)
    raise RuntimeError("protected action negative control was accepted")


def _runtime_controls(
    authorized: AuthorizedBroker, request: ActionRequest, content: bytes
) -> dict[str, str]:
    """Require each identity change and changed bytes to fail before dispatch.

    Parameters
    ----------
    authorized : AuthorizedBroker
        Wrapper holding the original issuer-pinned authorization and request.
    request : ActionRequest
        Immutable request for the permitted effect.
    content : bytes
        Bytes whose digest is bound by the original grant.

    Returns
    -------
    dict[str, str]
        Negative case names mapped to actual refusal messages.

    Notes
    -----
    The caller checks the native write history and final durable file. A refusal
    message alone is insufficient evidence that dispatch never occurred.
    """
    mutations = {
        "changed-run": {"run_id": "another-run"},
        "changed-attempt": {"attempt_id": "another-attempt"},
        "changed-request": {"request_id": "another-request"},
        "wrong-tenant": {"tenant_id": "another-tenant"},
        "wrong-principal": {"principal_id": "another-principal"},
        "wrong-tool": {"tool_id": "another-tool"},
        "wrong-target": {"target_path": "/work/another.txt"},
        "changed-digest": {"content_sha256": "0" * 64},
    }
    refusals = {}
    for name, changes in mutations.items():
        changed = replace(request, **changes)
        refusals[name] = _require_refusal(
            lambda changed=changed: authorized.write(changed, content)
        )
    refusals["changed-content"] = _require_refusal(
        lambda: authorized.write(request, content + b"changed")
    )
    return refusals


def _grant_controls(
    grant: dict[str, Any],
    request: ActionRequest,
    policy: GrantPolicy,
    reference_time: datetime,
) -> dict[str, str]:
    """Exercise issuer, signature, and validity checks on retained grant data.

    These controls call :func:`verify_grant` without executing effects. Runtime
    dispatch controls are exercised separately by :func:`_runtime_controls`.
    """
    wrong_policy = GrantPolicy(SigningKey.generate().public_hex)
    damaged = copy.deepcopy(grant)
    signature = damaged["signature"]
    damaged["signature"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    return {
        "wrong-issuer": _require_refusal(
            lambda: verify_grant(grant, request, wrong_policy, now=reference_time)
        ),
        "changed-signature": _require_refusal(
            lambda: verify_grant(damaged, request, policy, now=reference_time)
        ),
        "expired-grant": _require_refusal(
            lambda: verify_grant(
                grant, request, policy, now=reference_time + timedelta(minutes=5)
            )
        ),
    }


def run_demo(output: Path) -> dict[str, Any]:
    """Create a complete signed-action bundle and exercise bounded refusals.

    Parameters
    ----------
    output : Path
        New or empty directory. Producer records and consumer trust/state are
        retained separately. Existing files are never overwritten.

    Returns
    -------
    dict[str, Any]
        Actual write, retry, authorization, admission, and refusal results.

    Raises
    ------
    ValueError
        If the output directory is not empty.
    RuntimeError
        If a negative control passes or durable effect counts/content differ.
    VerificationError
        If the legitimate signed grant, packet, or consumer decision fails.

    Notes
    -----
    Tenant, principal and tool names are consumer-chosen labels in this public
    reference profile. Signature verification binds those labels and bytes; it
    does not establish that an external identity provider authorized the signer.
    The grant reference time is retained and observer-attested. This is not an
    externally witnessed proof of its ordering relative to the action.
    """
    started = time.perf_counter_ns()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("protected action output directory must be empty")
    producer, consumer = output / "producer", output / "consumer"
    workspace = producer / "workspace"
    workspace.mkdir(parents=True)
    consumer.mkdir()
    content = b"one authorized durable effect\n"
    reference_time = datetime.now(timezone.utc).replace(microsecond=0)
    request = ActionRequest(
        run_id="protected-action-1",
        attempt_id="attempt-1",
        request_id="request-1",
        tenant_id="tenant-a",
        principal_id="user-a",
        tool_id="write-result",
        target_path="/work/result.txt",
        content_sha256=hashlib.sha256(content).hexdigest(),
    )
    issuer, observer, witness_key = (
        SigningKey.generate(),
        SigningKey.generate(),
        SigningKey.generate(),
    )
    grant_policy = GrantPolicy(issuer.public_hex)
    grant = issue_grant(
        request,
        issuer,
        issued_at=reference_time,
        expires_at=reference_time + timedelta(minutes=5),
    )
    witness = LedgerWitness(producer / "ledger.jsonl", witness_key, observer.public_hex)
    authority = {
        "intervalId": request.run_id,
        "scope": "/work",
        "operation": "write-file",
    }
    admission_policy = AdmissionPolicy(
        request.run_id,
        digest("probity-authority-v0", authority),
        observer.public_hex,
        witness_key.public_hex,
        witness.signed_head(),
    )
    store = AdmissionStore(consumer / "state.json")
    store.initialize(observer.public_hex, witness_key.public_hex)
    history = producer / "history.jsonl"
    broker = Broker(workspace, history, authority, observer, witness)
    authorized = AuthorizedBroker(broker, grant, grant_policy, request)
    broker.begin()
    result = authorized.write(request, content)
    replay = authorized.write(request, content)
    refusals = _runtime_controls(authorized, request, content)
    refusals.update(_grant_controls(grant, request, grant_policy, reference_time))
    packet = authorized.seal()
    verified = verify_authorized_packet(
        grant,
        request,
        grant_policy,
        packet,
        history,
        observer.public_hex,
        witness_key.public_hex,
        now=reference_time,
        workspace=workspace,
    )
    if (
        len(packet["claim"]["writes"]) != 1
        or (workspace / "result.txt").read_bytes() != content
    ):
        raise RuntimeError("protected action effect count or durable content differs")
    if result.replayed or not replay.replayed:
        raise RuntimeError("protected action retry did not preserve idempotency")
    decision = store.admit(packet, history, witness.state_path, admission_policy)
    reopened = AdmissionStore(consumer / "state.json")
    refusals["consumer-replay"] = _require_refusal(
        lambda: reopened.admit(packet, history, witness.state_path, admission_policy)
    )
    retained = {
        producer / "grant.json": grant,
        producer / "request.json": asdict(request),
        producer / "packet.json": packet,
        consumer / "grant-policy.json": asdict(grant_policy),
        consumer / "admission-policy.json": asdict(admission_policy),
        consumer / "authorization-result.json": verified,
        consumer / "decision.json": decision,
    }
    for path, value in retained.items():
        path.write_bytes(canonical(value))
    report = {
        "status": "demo-passed",
        "runId": request.run_id,
        "referenceTime": reference_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "acceptedWrites": len(packet["claim"]["writes"]),
        "retryReplayed": replay.replayed,
        "admissionStatus": decision["status"],
        "refusals": refusals,
        "witnessScope": "PEER",
        "evidence_vantage": "artifact",
        "operator": "same-operator-fixture",
        "authorizationProfile": "experimental-reference",
        "runtime": {
            "python": platform.python_version(),
            "cryptography": cryptography.__version__,
            "elapsedNanoseconds": time.perf_counter_ns() - started,
        },
        "notEstablished": [
            "independent custody",
            "isolated untrusted agent",
            "APS/MCP/A2A conformance",
            "external identity authority",
            "global exactly-once execution",
            "externally witnessed grant-to-action ordering",
        ],
    }
    (output / "demo-report.json").write_bytes(canonical(report))
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
