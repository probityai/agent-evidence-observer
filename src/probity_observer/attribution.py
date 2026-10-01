"""Retain what a checker consumed without turning use into endorsement.

A consumption record is the signer's account of a check. Offline verification
binds that account to retained bytes and a caller-selected action and claim. It
does not prove that every check was recorded, that the signer was independent,
or that a dependency deserves payment.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .crypto import SigningKey, VerificationError, canonical, verify_signature

DOMAIN = "probity-artifact-consumption-v0"
HEX = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class ArtifactPin:
    """Consumer-selected provenance and byte digest for a retained input.

    ``source`` is an informative origin, not a verified ownership claim.
    ``revision`` must identify the version the consumer chose, not a live branch.
    Attribution and license travel with the input; neither grants new rights.
    """

    project: str
    source: str
    revision: str
    attribution: str
    license: str
    sha256: str

    def fields(self) -> dict[str, str]:
        """Refuse incomplete provenance instead of inventing it."""
        result = vars(self).copy()
        if any(not isinstance(value, str) or not value for value in result.values()):
            raise VerificationError("artifact pin has an empty field")
        canonical(result)
        if HEX.fullmatch(self.sha256) is None:
            raise VerificationError("artifact digest must be lowercase SHA-256")
        return result


def check_artifact(
    role: str,
    raw: bytes,
    pin: ArtifactPin,
    checker: Callable[[bytes], dict[str, Any]],
) -> dict[str, Any]:
    """Call a checker on the exact pinned bytes and retain its actual result.

    The caller owns the checker and its trust policy. Exceptions propagate; a
    crash is not a successful consumption event or an unknown outcome.
    """
    provenance = pin.fields()
    if not isinstance(role, str) or not role or not role.isascii():
        raise VerificationError("artifact role must be nonempty ASCII")
    if hashlib.sha256(raw).hexdigest() != pin.sha256:
        raise VerificationError("artifact bytes differ from the consumer pin")
    result = checker(raw)
    if not isinstance(result, dict):
        raise VerificationError("artifact checker must return a result object")
    canonical(result)
    return {"role": role, "input": provenance, "result": result}


def sign_consumption(
    action_id: str,
    claim_digest: str,
    checks: list[dict[str, Any]],
    signer: SigningKey,
) -> dict[str, Any]:
    """Bind checked inputs to one action and one separately verified claim."""
    payload = {
        "profile": DOMAIN,
        "actionId": action_id,
        "claimDigest": claim_digest,
        "checks": checks,
        "coverage": "listed-checks-only",
    }
    _shape(payload)
    return {
        "payload": payload,
        "keyid": signer.public_hex,
        "signature": signer.sign(DOMAIN, payload),
    }


def _shape(payload: dict[str, Any]) -> None:
    """Require a closed profile, unique roles and listed-check coverage."""
    if set(payload) != {"profile", "actionId", "claimDigest", "checks", "coverage"}:
        raise VerificationError("consumption payload fields differ from the profile")
    if payload["profile"] != DOMAIN or payload["coverage"] != "listed-checks-only":
        raise VerificationError("unsupported consumption profile or coverage")
    _identity_fields(payload)
    checks = payload["checks"]
    if not isinstance(checks, list) or not checks:
        raise VerificationError("consumption record has no checks")
    roles: set[str] = set()
    for check in checks:
        _check_shape(check, roles)
    canonical(payload)


def _identity_fields(payload: dict[str, Any]) -> None:
    """Check the action identifier and exact claim digest."""
    if not isinstance(payload["actionId"], str) or not payload["actionId"]:
        raise VerificationError("consumption action id is empty")
    if (
        not isinstance(payload["claimDigest"], str)
        or HEX.fullmatch(payload["claimDigest"]) is None
    ):
        raise VerificationError("consumption claim digest is invalid")


def _check_shape(check: Any, roles: set[str]) -> None:
    """Validate one check while preserving role uniqueness and order."""
    if not isinstance(check, dict) or set(check) != {"role", "input", "result"}:
        raise VerificationError("consumption check fields differ from the profile")
    role = check["role"]
    if not isinstance(role, str) or not role or role in roles:
        raise VerificationError("consumption roles are empty or repeated")
    roles.add(role)
    _provenance_shape(check["input"])
    if not isinstance(check["result"], dict):
        raise VerificationError("consumption check result is not an object")


def _provenance_shape(provenance: Any) -> None:
    """Require every input provenance field before validating its values."""
    if not isinstance(provenance, dict) or set(provenance) != set(
        ArtifactPin.__annotations__
    ):
        raise VerificationError("consumption input provenance is incomplete")
    ArtifactPin(**provenance).fields()


def verify_consumption(
    record: dict[str, Any],
    inputs: Mapping[str, bytes],
    pins: Mapping[str, ArtifactPin],
    *,
    action_id: str,
    claim_digest: str,
    pinned_signer: str,
) -> dict[str, Any]:
    """Recompute byte and action bindings against consumer-selected inputs.

    The caller must separately verify the authorization and execution claims.
    This function verifies the signer's reported results, not those results'
    substantive correctness. Source URLs are never fetched during verification.
    """
    payload = _signed_payload(record, pinned_signer)
    if payload["actionId"] != action_id or payload["claimDigest"] != claim_digest:
        raise VerificationError("consumption record binds another action or claim")
    _verify_inputs(payload, inputs, pins)
    return {
        "status": "bindings-verified",
        "actionId": action_id,
        "claimDigest": claim_digest,
        "coverage": "listed-checks-only",
        "resultAuthority": "signer-asserted",
    }


def _signed_payload(record: dict[str, Any], pinned_signer: str) -> dict[str, Any]:
    """Check the envelope, profile and consumer-pinned signature."""
    if not isinstance(record, dict) or set(record) != {"payload", "keyid", "signature"}:
        raise VerificationError("consumption envelope fields differ from the profile")
    payload = record["payload"]
    if not isinstance(payload, dict):
        raise VerificationError("consumption payload is not an object")
    _shape(payload)
    if record["keyid"] != pinned_signer:
        raise VerificationError("consumption signer is not the pinned signer")
    verify_signature(pinned_signer, DOMAIN, payload, record["signature"])
    return payload


def _verify_inputs(
    payload: dict[str, Any],
    inputs: Mapping[str, bytes],
    pins: Mapping[str, ArtifactPin],
) -> None:
    """Check the exact retained role set, provenance and input bytes."""
    roles = {check["role"] for check in payload["checks"]}
    if roles != set(inputs) or roles != set(pins):
        raise VerificationError("retained inputs differ from the declared check set")
    for check in payload["checks"]:
        role = check["role"]
        if check["input"] != pins[role].fields():
            raise VerificationError(
                "consumption provenance differs from the consumer pin"
            )
        if hashlib.sha256(inputs[role]).hexdigest() != pins[role].sha256:
            raise VerificationError("retained artifact bytes differ")
