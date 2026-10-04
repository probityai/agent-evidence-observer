"""Reference action-time authority checks over Observer's native ticket service.

This profile uses a local, author-operated authority source. Its signatures do
not make the source independent, and its freshness limit is a consumer choice.
The native ticket transaction is a real local effect, not a remote publication.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from probity_observer.authorization import ActionRequest, GrantPolicy
from probity_observer.crypto import SigningKey, VerificationError, canonical, verify_signature
from probity_observer.ticket_service import TicketStore

LOGGER = logging.getLogger(__name__)
PROFILE = "authority-unreachable-reference-v0"
AUTHORITY_DOMAIN = PROFILE + "-authority"
RECORD_DOMAIN = PROFILE + "-record"
VETO_DOMAIN = PROFILE + "-veto"
MAX_AGE_SECONDS = 180
AUTHORITY_FIELDS = {"principalId", "observedAt", "status", "sourceRevision"}
VETO_FIELDS = {"runId", "requestId", "decidedAt", "decision", "sourceRevision"}
CASE_IDS = (
    "approved-human-reachable", "unreachable-with-prior-fallback", "unreachable-no-fallback",
    "fallback-expired", "late-approval-for-expired-request", "approver-revoked-at-dispatch",
    "authority-evidence-stale", "media-bytes-mutated", "platform-content-mutated",
    "catalogue-mutated", "destination-mutated", "revoked-between-intent-and-effect",
    "crash-after-intent", "crash-inside-effect-transaction", "effect-committed-response-lost",
    "same-request-retry", "effect-then-authority-revoked", "incomplete-proof-after-effect",
    "binding-veto-override-attempt", "revoked-authority-superseded-evidence", "authority-source-unreachable",
)


def refuse(reason: str) -> None:
    """Raise a bounded, logged refusal without printing protected content.

    Parameters
    ----------
    reason : str
        Exact reason returned to the runner and tested with ``caplog``.

    Raises
    ------
    VerificationError
        Always. No dispatch is performed by this function.
    """
    LOGGER.warning("authority profile refused: %s", reason)
    raise VerificationError(reason)


def sign_record(payload: dict[str, Any], key: SigningKey, domain: str) -> dict[str, Any]:
    """Sign finite restricted JSON under an explicit domain and local key."""
    return {"payload": payload, "keyid": key.public_hex, "signature": key.sign(domain, payload)}


def checked_record(record: Any, key: str, domain: str) -> dict[str, Any]:
    """Authenticate an envelope using a separately supplied consumer key.

    Parameters
    ----------
    record : Any
        Exact three-field envelope, never a source of its own trust policy.
    key, domain : str
        Consumer-selected Ed25519 public key and signature domain.

    Returns
    -------
    dict[str, Any]
        Authenticated payload. The caller still checks its field semantics.

    Raises
    ------
    VerificationError
        If the schema, key binding, or signature fails.
    """
    if not isinstance(record, dict) or set(record) != {"payload", "keyid", "signature"}:
        refuse("evidence envelope is incomplete")
    if record["keyid"] != key or not isinstance(record["payload"], dict):
        refuse("evidence signer differs from consumer pin")
    try:
        verify_signature(key, domain, record["payload"], record["signature"])
    except (VerificationError, TypeError):
        refuse("evidence signature does not verify")
    return record["payload"]


def _status(record: Any, key: str, principal: str, at: int) -> dict[str, Any]:
    """Authenticate one status assertion and check its identity and clock."""
    payload = checked_record(record, key, AUTHORITY_DOMAIN)
    if set(payload) != AUTHORITY_FIELDS or payload["principalId"] != principal:
        refuse("authority identity or fields differ")
    stamp = payload["observedAt"]
    if type(at) is not int or type(stamp) is not int or stamp > at:
        refuse("authority time is invalid")
    return payload


def check_authority(record: Any, key: str, principal: str, at: int, latest: Any = None) -> dict[str, Any]:
    """Require bounded-age current authority before the protected dispatch.

    Parameters
    ----------
    record : Any
        Signed status assertion presented for this dispatch.
    key, principal : str
        Source key and exact approver identity selected by the consumer.
    at : int
        Local reference clock in UTC seconds. Trust in that clock and in the
        asserted status remains explicit; this is not an external directory.
    latest : Any, optional
        Newest status assertion the gate itself has authenticated for the
        same principal. Presented evidence older than it is superseded, even
        inside the freshness window: a revocation published after an active
        snapshot cannot be bypassed by presenting the older snapshot.

    Returns
    -------
    dict[str, Any]
        Verified active status assertion, including its actual evidence age.

    Raises
    ------
    VerificationError
        For wrong identity, malformed or future time, stale or superseded
        evidence, or a revoked authority. The oldest admitted age is
        ``MAX_AGE_SECONDS``.
    """
    payload = _status(record, key, principal, at)
    if at - payload["observedAt"] > MAX_AGE_SECONDS:
        refuse("authority evidence is stale")
    if latest is not None and payload["observedAt"] < _status(latest, key, principal, at)["observedAt"]:
        refuse("authority evidence superseded by newer status")
    if payload["status"] != "active":
        refuse("approver authority is not active")
    return {**payload, "ageSeconds": at - payload["observedAt"]}


def check_veto(record: Any, key: str, request: ActionRequest, at: int) -> None:
    """Refuse dispatch when the authority source recorded a binding veto.

    Parameters
    ----------
    record : Any
        Signed veto from the configured authority source, or ``None`` when the
        gate holds no veto for this request. The gate supplies it; the
        executor's own arguments cannot remove it.
    key : str
        Consumer-selected authority source key.
    request : ActionRequest
        Exact run and request the veto must name.
    at : int
        Local reference clock in UTC seconds.

    Raises
    ------
    VerificationError
        For a veto that names another action, carries an invalid time, or
        is recorded for this request. A valid grant does not override it.
    """
    if record is None:
        return
    payload = checked_record(record, key, VETO_DOMAIN)
    if set(payload) != VETO_FIELDS or (payload["runId"], payload["requestId"]) != (request.run_id, request.request_id):
        refuse("veto identity or fields differ")
    if type(payload["decidedAt"]) is not int or type(at) is not int or payload["decidedAt"] > at or payload["decision"] != "veto":
        refuse("veto time or decision is invalid")
    refuse("binding veto recorded for request")


def content_bytes(text: str, media: bytes, destination: str, catalogue: bytes) -> bytes:
    """Bind the complete local publication descriptor into protected bytes.

    Parameters
    ----------
    text : str
        Exact ASCII message, with no platform normalization in this profile.
    media, catalogue : bytes
        Actual media bytes and exact selected tool-catalogue bytes. Their
        SHA-256 digests are bound, not mutable asset references.
    destination : str
        Exact destination identity. This reference writes a native ticket row
        containing the descriptor; it never sends a social-media message.

    Returns
    -------
    bytes
        Canonical restricted JSON. :class:`ActionRequest` binds its digest.
    """
    return canonical({"text": text, "mediaSha256": hashlib.sha256(media).hexdigest(),
                      "destination": destination, "catalogueSha256": hashlib.sha256(catalogue).hexdigest()})


def dispatch(
    store: TicketStore, request: ActionRequest, grant: dict[str, Any] | None,
    content: bytes, authority: dict[str, Any] | None, authority_key: str, *, at: int, request_deadline: int,
    veto: dict[str, Any] | None = None, latest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Check veto, status and exact approved bytes, then enter the native gate.

    No reachable or unavailable human condition creates a grant. A previously
    issued exact grant is required in both cases. A binding veto blocks every
    grant. An unreachable authority source (``authority`` is ``None``) blocks
    dispatch: a fallback grant covers an unavailable human, never missing
    status evidence. Native expiry and persistent revocation are rechecked
    inside :meth:`TicketStore.dispatch`, including cached retries and the
    transaction immediately before the effect.

    Returns
    -------
    dict[str, Any]
        Native signed receipt. Native interruptions remain exceptions; callers
        must retain read-back and task outcome separately, as ``producer.py``
        does. A failed return is not proof of an absent effect.

    Raises
    ------
    VerificationError
        For a binding veto, missing delegated authority, an unreachable or
        invalid authority source, mismatched descriptor bytes, or any native
        admission refusal.
    """
    check_veto(veto, authority_key, request, at)
    if grant is None:
        refuse("no pre-authorized fallback")
    if type(request_deadline) is not int or at >= request_deadline:
        refuse("original decision window has closed")
    if authority is None:
        refuse("authority source unreachable")
    check_authority(authority, authority_key, request.principal_id, at, latest)
    if hashlib.sha256(content).hexdigest() != request.content_sha256:
        refuse("approved action bytes changed")
    return store.dispatch({"request": asdict(request), "grant": grant, "contentHex": content.hex()})


def reference_time(second: int) -> datetime:
    """Convert the reference clock's integer seconds to an aware UTC instant."""
    return datetime.fromtimestamp(second, timezone.utc)
