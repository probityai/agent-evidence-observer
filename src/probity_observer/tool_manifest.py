"""Read the proposed AgentAvow per-tool static-grade fixture offline.

A verified grade covers its signed tool definition at the selected time.
It supplies no observation that the tool ran or that its action was safe.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import quote

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import VerificationError

PROFILE = "agentavow.mcp-tool-definition.v1"
FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")
KEY_SAFE = "".join(chr(n) for n in range(0x21, 0x7F) if chr(n) not in "%=")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
BASE64URL = re.compile(r"[A-Za-z0-9_-]+\Z")
TIMESTAMP = re.compile(
    r"(?P<second>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?(?:Z|\+00:00)\Z"
)


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise VerificationError(f"{name} must be a nonempty string")
    return value


def tool_key(name: str) -> str:
    """Encode the exact upstream tool-map key, including its partial-triplet cut."""
    try:
        raw = _text(name, "tool name").encode("utf-8")
    except UnicodeError as exc:
        raise VerificationError("tool name must contain valid Unicode") from exc
    encoded = quote(name, safe=KEY_SAFE)
    if len(encoded) > 128:
        encoded = encoded[:96] + "~" + hashlib.sha256(raw).hexdigest()[:16]
    return "tool:" + encoded


def tool_digest(tool: Mapping[str, Any]) -> str:
    """Hash the named served definition under the upstream RFC 8785 profile."""
    tool_key(tool.get("name"))
    selected = {name: tool[name] for name in FIELDS if tool.get(name) is not None}
    preimage = rfc8785.dumps({"profile": PROFILE, "tool": selected})
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def _time(value: str) -> tuple[datetime, int]:
    """Preserve UTC whole seconds and fractional nanoseconds without rounding."""
    match = TIMESTAMP.fullmatch(_text(value, "time"))
    if match is None:
        raise VerificationError("time must be a UTC timestamp with at most nine fractional digits")
    try:
        second = datetime.fromisoformat(match.group("second") + "+00:00")
    except ValueError as exc:
        raise VerificationError("time must contain valid UTC calendar seconds") from exc
    nanoseconds = int((match.group("fraction") or "0").ljust(9, "0"))
    return second, nanoseconds


@dataclass(frozen=True, slots=True)
class ToolGate:
    """Consumer-selected server, tool, observed digest and explicit evaluation time."""

    subject_id: str
    tool_name: str
    observed_tool_digest: str
    evaluation_time: str

    def __post_init__(self) -> None:
        _text(self.subject_id, "subject_id")
        tool_key(self.tool_name)
        if not isinstance(self.observed_tool_digest, str) or not DIGEST.fullmatch(self.observed_tool_digest):
            raise VerificationError("observed_tool_digest must be sha256 and 64 lowercase hex characters")
        _time(self.evaluation_time)


@dataclass(frozen=True, slots=True)
class ToolGrade:
    """The upstream's independent six axes, without a runtime or safety claim."""

    signature_valid: bool
    canonical_bytes: bool
    subject_binds: bool
    tool_binds: bool
    tool_digest_binds: bool | str
    fresh: bool

    @property
    def rely(self) -> bool:
        """Return the fixture's static-grade decision, not execution admission."""
        return all((self.signature_valid, self.canonical_bytes, self.subject_binds,
                    self.tool_binds, self.tool_digest_binds is True, self.fresh))

    def axes(self) -> dict[str, bool | str]:
        """Return the original fixture field names and not_evaluated state."""
        return {"signature_valid": self.signature_valid, "canonical_bytes": self.canonical_bytes,
                "subject_binds": self.subject_binds, "tool_binds": self.tool_binds,
                "tool_digest_binds": self.tool_digest_binds, "fresh": self.fresh, "rely": self.rely}


def _decode(segment: str) -> bytes:
    if not BASE64URL.fullmatch(segment):
        raise VerificationError("JWS segments must use unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except binascii.Error as exc:
        raise VerificationError("JWS segment has invalid base64url") from exc
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != segment:
        raise VerificationError("JWS segment has noncanonical base64url")
    return raw


def _object(data: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError("duplicate JSON member in grade")
            result[key] = value
        return result

    try:
        value = json.loads(data, object_pairs_hook=unique)
    except VerificationError:
        raise
    except (ValueError, UnicodeError) as exc:
        raise VerificationError("grade must contain valid JSON objects") from exc
    if not isinstance(value, dict):
        raise VerificationError("grade must contain valid JSON objects")
    return value


def _public_key(jwk: Mapping[str, Any]) -> Ed25519PublicKey:
    if (jwk.get("kty"), jwk.get("crv"), jwk.get("alg")) != ("OKP", "Ed25519", "EdDSA"):
        raise VerificationError("consumer key must be an Ed25519 signing JWK")
    _text(jwk.get("kid"), "consumer key kid")
    try:
        return Ed25519PublicKey.from_public_bytes(_decode(_text(jwk.get("x"), "consumer key x")))
    except ValueError as exc:
        raise VerificationError("consumer key must have 32 Ed25519 bytes") from exc


def _signed_parts(jws: str) -> tuple[str, str, dict[str, Any], dict[str, Any], bytes, bytes]:
    parts = _text(jws, "JWS").split(".")
    if len(parts) != 3:
        raise VerificationError("compact JWS must have three segments")
    header, payload, signature = parts
    payload_bytes = _decode(payload)
    return header, payload, _object(_decode(header)), _object(payload_bytes), payload_bytes, _decode(signature)


def verify_tool_grade(jws: str, jwk: Mapping[str, Any], gate: ToolGate) -> ToolGrade:
    """Check a compact JWS against a key selected outside the candidate.

    The grade's score and tier remain static-analysis data. The key authenticates
    signed bytes; the caller separately chooses whether to trust that producer.
    Malformed documents refuse rather than produce a passing or guessed axis.
    """
    public = _public_key(jwk)
    h, p, header, payload, payload_bytes, signature = _signed_parts(jws)
    signature_valid = (header.get("alg") == "EdDSA" and header.get("kid") == jwk["kid"]
                       and "crit" not in header and "b64" not in header)
    try:
        public.verify(signature, f"{h}.{p}".encode("ascii"))
    except InvalidSignature:
        signature_valid = False
    try:
        canonical_bytes = rfc8785.dumps(payload) == payload_bytes
        signed = payload["scan"]["toolDigests"].get(tool_key(gate.tool_name))
        subject_binds = payload["subject"]["id"] == gate.subject_id
        fresh = _time(payload["issuedAt"]) <= _time(gate.evaluation_time) < _time(payload["expiresAt"])
    except (KeyError, TypeError, AttributeError, rfc8785.CanonicalizationError) as exc:
        raise VerificationError("grade is outside the supported per-tool schema") from exc
    tool_binds = isinstance(signed, str)
    return ToolGrade(signature_valid, canonical_bytes, subject_binds, tool_binds,
                     signed == gate.observed_tool_digest if tool_binds else "not_evaluated", fresh)


def require_served_tool(jws: str, jwk: Mapping[str, Any], gate: ToolGate,
                        served_tool: Mapping[str, Any]) -> ToolGrade:
    """Refuse static-grade reliance unless the supplied served bytes recompute.

    This joins the named definition to the signed grade. It does not establish
    that a remote server served these bytes to a particular runtime invocation.
    """
    grade = verify_tool_grade(jws, jwk, gate)
    if not grade.rely:
        raise VerificationError("static tool grade does not satisfy the selected gate")
    if served_tool.get("name") != gate.tool_name or tool_digest(served_tool) != gate.observed_tool_digest:
        raise VerificationError("served definition differs from the selected tool binding")
    return grade
