"""Byte and signature primitives for the prototype's restricted JSON profile.

The profile accepts ASCII strings, finite JSON structures, and safe integers. It
intentionally rejects floats and non-ASCII text; it is not a general RFC 8785
implementation. This narrow domain has one portable serialization and is enough
for the prototype's paths, digests, identifiers, and timestamps.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SAFE_INTEGER_LIMIT = 2**53


class VerificationError(ValueError):
    """A purported record does not satisfy the byte or signature contract."""


def _validate(value: Any) -> None:
    """Reject types with ambiguous cross-language JSON representations.

    Parameters
    ----------
    value : Any
        A JSON-compatible value to inspect recursively.

    Raises
    ------
    VerificationError
        If a value is outside the restricted canonical profile.
    """
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) >= SAFE_INTEGER_LIMIT:
            raise VerificationError("integer exceeds the safe JSON range")
        return
    if isinstance(value, str):
        if not value.isascii():
            raise VerificationError("non-ASCII string is outside the prototype profile")
        return
    if isinstance(value, list):
        for item in value:
            _validate(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise VerificationError("JSON object keys must be strings")
            _validate(key)
            _validate(item)
        return
    raise VerificationError("value is outside the prototype JSON profile")


def canonical(value: Any) -> bytes:
    """Serialize the restricted JSON profile to deterministic UTF-8 bytes.

    Parameters
    ----------
    value : Any
        Nested JSON data. Floats, large integers, and non-ASCII strings are
        refused instead of silently transformed.

    Returns
    -------
    bytes
        Compact, key-sorted JSON bytes used by :func:`digest` and signatures.
    """
    _validate(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("ascii")


def strict_loads(data: bytes) -> Any:
    """Parse the canonical profile while refusing duplicate object members.

    Parameters
    ----------
    data : bytes
        UTF-8 JSON document.

    Returns
    -------
    Any
        Parsed value, only if its bytes exactly match :func:`canonical`.

    Raises
    ------
    VerificationError
        For duplicate keys, unsupported values, or noncanonical encoding.
    """
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError("duplicate JSON member")
            result[key] = value
        return result

    try:
        value = json.loads(data, object_pairs_hook=unique)
    except VerificationError:
        raise
    except (ValueError, UnicodeError) as exc:
        raise VerificationError("invalid JSON document") from exc
    if canonical(value) != data:
        raise VerificationError("JSON document is not canonical")
    return value


def digest(domain: str, value: Any) -> str:
    """Hash a domain-separated canonical JSON value with SHA-256.

    The domain is part of the preimage; callers cannot substitute a history
    entry for an authority document even if their JSON values coincide.
    """
    return hashlib.sha256(domain.encode("ascii") + b"\x00" + canonical(value)).hexdigest()


@dataclass(frozen=True)
class SigningKey:
    """An Ed25519 signer used outside the agent's intended trust boundary.

    This class does not establish isolation or custody. A relying party must
    pin the corresponding public key and determine who controlled the signer.
    """

    private: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "SigningKey":
        """Generate an ephemeral key for a local prototype run."""
        return cls(Ed25519PrivateKey.generate())

    @property
    def public_hex(self) -> str:
        """Return the raw 32-byte public key as lowercase hexadecimal."""
        raw = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()

    def sign(self, domain: str, value: Any) -> str:
        """Sign a domain-separated canonical JSON value as base64."""
        message = domain.encode("ascii") + b"\x00" + canonical(value)
        return base64.b64encode(self.private.sign(message)).decode("ascii")


def verify_signature(public_hex: str, domain: str, value: Any, signature: str) -> None:
    """Check an Ed25519 signature against a consumer-pinned public key.

    Raises
    ------
    VerificationError
        If the key, signature encoding, or signature does not verify.
    """
    try:
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        raw = base64.b64decode(signature, validate=True)
        public.verify(raw, domain.encode("ascii") + b"\x00" + canonical(value))
    except (ValueError, InvalidSignature) as exc:
        raise VerificationError("signature does not verify under the pinned key") from exc
