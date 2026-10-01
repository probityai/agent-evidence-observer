"""Link an unsigned AAE kernel decision to one local observer write.

The kernel's PERMIT does not authenticate its issuer. Consumer-selected mandate
and observer pins are separate inputs; neither comes from the received record.
The signed link is made after the effect and retains PEER scope.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .aae_enforce import DIGEST, canonical_bytes, enforce_check, native_digest
from .authorization import ActionRequest
from .broker import Broker, WriteResult
from .crypto import SigningKey, VerificationError, digest, verify_signature
from .verify import verify_packet

DOMAIN = "probity-aae-local-effect-link-v0"


def local_transaction(request: ActionRequest) -> dict[str, Any]:
    """Map one exact local invocation to an action type and instance fields.

    The action identifies a write-file operation, not an EVM transfer. All
    invocation identity, target and content fields are transaction siblings
    evaluated by the native kernel's exact constraints.
    """
    return {
        "action": {"verb": "write-file", "targetKind": "local-file"},
        "runId": request.run_id,
        "attemptId": request.attempt_id,
        "requestId": request.request_id,
        "tenantId": request.tenant_id,
        "principalId": request.principal_id,
        "toolId": request.tool_id,
        "targetPath": request.target_path,
        "contentSha256": request.content_sha256,
    }


def verify_local_decision(
    mandate: Any,
    transaction: Any,
    record: dict[str, Any],
    request: ActionRequest,
    pinned_mandate_digest: str,
) -> dict[str, Any]:
    """Replay an unsigned native decision against an exact consumer action.

    Parameters
    ----------
    mandate, transaction, record
        Candidate native inputs and reported core. The core is recomputed.
    request : ActionRequest
        Independently selected exact local file replacement.
    pinned_mandate_digest : str
        Consumer-selected native mandate digest, never sourced from the record.

    Returns
    -------
    dict[str, Any]
        Recomputed PERMIT with exact constraints for every invocation field.

    Raises
    ------
    VerificationError
        If pins, transaction, core, verdict or constraint coverage disagree.
        A successful replay does not authenticate the unsigned AAE issuer.
    """
    if (
        not isinstance(pinned_mandate_digest, str)
        or DIGEST.fullmatch(pinned_mandate_digest) is None
    ):
        raise VerificationError(
            "AAE consumer mandate pin is not a tagged SHA-256 digest"
        )
    if native_digest("mandate", mandate) != pinned_mandate_digest:
        raise VerificationError("AAE mandate differs from the consumer pin")
    if not _same_core(transaction, local_transaction(request)):
        raise VerificationError(
            "AAE transaction differs from the expected local action"
        )
    actual = enforce_check(mandate, transaction)
    _record_matches(record, actual)
    if not _local_grant_covers(mandate, transaction, actual["grant_index"]):
        raise VerificationError(
            "AAE local dispatch requires exact constraints for the request"
        )
    return actual


def _record_matches(record: Any, actual: dict[str, Any]) -> None:
    if not isinstance(record, dict):
        raise VerificationError("AAE core record is missing")
    if (
        not _same_core(record.get("core"), actual["core"])
        or record.get("core_digest") != actual["core_digest"]
    ):
        raise VerificationError(
            "AAE record differs from the independently replayed core"
        )
    if actual["core_digest"] is None or actual["verdict"] != "PERMIT":
        raise VerificationError("AAE local dispatch requires a replayed PERMIT")


def _same_core(left: Any, right: Any) -> bool:
    try:
        return canonical_bytes(left) == canonical_bytes(right)
    except (ValueError, UnicodeError, RecursionError):
        return False


def _local_grant_covers(
    mandate: Any, transaction: dict[str, Any], index: int | None
) -> bool:
    if type(index) is not int or not isinstance(mandate, dict):
        return False
    grants = mandate.get("grants")
    if not isinstance(grants, list) or index < 0 or index >= len(grants):
        return False
    constraints = grants[index].get("constraints")
    if not isinstance(constraints, list):
        return False
    return all(
        any(
            isinstance(item, dict)
            and item.get("type") == "exact"
            and item.get("field") == name
            and isinstance(item.get("value"), str)
            and item["value"] == value
            for item in constraints
        )
        for name, value in transaction.items()
        if name != "action"
    )


def write_local_action(
    mandate: Any,
    transaction: Any,
    record: dict[str, Any],
    request: ActionRequest,
    content: bytes,
    broker: Broker,
    *,
    pinned_mandate_digest: str,
) -> WriteResult:
    """Check the consumer-pinned kernel decision before a native broker write.

    Parameters
    ----------
    mandate, transaction, record : Any
        Retained unsigned AAE kernel inputs and the claimed native core record.
    request : ActionRequest
        Consumer-selected exact invocation identity and content digest.
    content : bytes
        File replacement bytes; checked before the broker is called.
    broker : Broker
        Begun local observer broker. A caller retaining the underlying broker
        or writable workspace can bypass this one dispatch path.
    pinned_mandate_digest : str
        Mandate digest selected by the consumer outside the candidate record.

    Returns
    -------
    WriteResult
        Native broker result. The issuer of an unsigned mandate remains
        unauthenticated; this is not a full AAE JWS authorization decision.

    Raises
    ------
    VerificationError
        If the core, exact invocation, content, consumer pin or broker authority
        does not match. No write is attempted for these mismatches.
    """
    verify_local_decision(mandate, transaction, record, request, pinned_mandate_digest)
    if hashlib.sha256(content).hexdigest() != request.content_sha256:
        raise VerificationError(
            "AAE write content differs from the expected local action"
        )
    authority = {
        "intervalId": request.run_id,
        "scope": "/work",
        "operation": "write-file",
    }
    if broker.authority != authority:
        raise VerificationError(
            "AAE write broker authority differs from the local action"
        )
    return broker.write(request.request_id, request.target_path, content)


def _payload(
    record: dict[str, Any],
    request: ActionRequest,
    packet: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(packet, dict) or not isinstance(packet.get("claim"), dict):
        raise VerificationError("AAE observer packet has no claim object")
    return {
        "profile": DOMAIN,
        "coreDigest": record["core_digest"],
        "transactionDigest": record["core"]["transaction_digest"],
        "claimDigest": digest("probity-claim-v0", packet["claim"]),
        "request": asdict(request),
        "witnessScope": "PEER",
    }


def sign_effect_link(
    record: dict[str, Any],
    request: ActionRequest,
    packet: dict[str, Any],
    observer: SigningKey,
) -> dict[str, Any]:
    """Sign a post-effect link; consumers still replay and verify every input."""
    payload = _payload(record, request, packet)
    return {
        "payload": payload,
        "keyid": observer.public_hex,
        "signature": observer.sign(DOMAIN, payload),
    }


def _verified_link(
    link: Any,
    payload: dict[str, Any],
    pinned_observer_key: str,
) -> None:
    if not isinstance(link, dict) or set(link) != {"payload", "keyid", "signature"}:
        raise VerificationError("AAE effect link envelope differs from the profile")
    if link["keyid"] != pinned_observer_key:
        raise VerificationError("AAE effect link signer differs from the observer pin")
    verify_signature(pinned_observer_key, DOMAIN, link["payload"], link["signature"])
    if not _same_core(link["payload"], payload):
        raise VerificationError(
            "AAE effect link binds a different core, request or claim"
        )


def _matching_write(claim: dict[str, Any], request: ActionRequest) -> None:
    if claim["intervalId"] != request.run_id or len(claim["writes"]) != 1:
        raise VerificationError(
            "AAE effect claim does not contain one expected local write"
        )
    write = claim["writes"][0]
    expected = (request.request_id, request.target_path, request.content_sha256)
    actual = (write["requestId"], write["path"], write["contentDigest"])
    if actual != expected:
        raise VerificationError(
            "AAE observed write differs from the expected local action"
        )


def verify_effect_link(
    mandate: Any,
    transaction: Any,
    record: dict[str, Any],
    request: ActionRequest,
    link: dict[str, Any] | None,
    packet: dict[str, Any],
    history: Path,
    *,
    pinned_mandate_digest: str,
    pinned_observer_key: str,
    pinned_witness_key: str,
    workspace: Path | None = None,
) -> dict[str, Any]:
    """Replay the native core and check a separately pinned observer effect.

    Missing links leave execution unknown, even if the unsigned kernel permits.
    A present valid link establishes only a signed PEER file-write record:
    issuer authentication, independent custody and external EVM execution are
    not supplied by this function.

    Returns
    -------
    dict[str, Any]
        Separate kernel verdict, issuer-authentication and execution results.
        A missing receipt is not converted into a negative execution finding.

    Raises
    ------
    VerificationError
        For substituted core/input/request/claim bytes, unpinned signers or a
        native observer packet/history that fails verification.
    """
    actual = verify_local_decision(
        mandate, transaction, record, request, pinned_mandate_digest
    )
    result = {
        "kernelVerdict": actual["verdict"],
        "coreDigest": actual["core_digest"],
        "issuerAuthentication": "not-established",
        "execution": "unknown",
        "witnessScope": "PEER",
        "evidence_vantage": "artifact",
    }
    if link is None:
        return {**result, "linkage": "missing"}
    _verified_link(link, _payload(actual, request, packet), pinned_observer_key)
    claim = verify_packet(
        packet, history, pinned_observer_key, pinned_witness_key, workspace
    )
    _matching_write(claim, request)
    return {**result, "execution": "recorded-local-write", "linkage": "verified"}
