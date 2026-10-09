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
# Versioned identifier of the comparison record in CONTRACT.md. Every trace
# writes it; a reader refuses a trace without it or with another version.
CONTRACT_ID = "https://probityai.github.io/agent-evidence-observer/contract/authority-at-dispatch/v1"
HOP_FIELDS = {"delegator", "delegate", "actions", "targets"}
AUTHORITY_DOMAIN = PROFILE + "-authority"
RECORD_DOMAIN = PROFILE + "-record"
MAX_AGE_SECONDS = 180
AUTHORITY_FIELDS = {"principalId", "observedAt", "status", "sourceRevision"}
CASE_IDS = (
    "approved-human-reachable", "unreachable-with-prior-fallback", "unreachable-no-fallback",
    "fallback-expired", "late-approval-for-expired-request", "approver-revoked-at-dispatch",
    "authority-evidence-stale", "media-bytes-mutated", "platform-content-mutated",
    "catalogue-mutated", "destination-mutated", "revoked-between-intent-and-effect",
    "crash-after-intent", "crash-inside-effect-transaction", "effect-committed-response-lost",
    "same-request-retry", "effect-then-authority-revoked", "incomplete-proof-after-effect",
    "delegation-hop-amplified",
)


# Residual risks the reference profile leaves open, per case, as named in the
# delegated-authority table of CONTRACT.md. A record must carry exactly these:
# dropping one claims coverage this profile does not provide.
_REVOCATION = ("revocation-propagation-unmeasured",)
_REWRITE = ("post-effect-platform-rewrite-unobserved",)
_CLOCK = ("reference-clock-trusted",)
RESIDUAL_RISKS = {case_id: () for case_id in CASE_IDS} | {
    "approver-revoked-at-dispatch": _REVOCATION, "revoked-between-intent-and-effect": _REVOCATION,
    "effect-then-authority-revoked": _REVOCATION,
    "media-bytes-mutated": _REWRITE, "platform-content-mutated": _REWRITE,
    "catalogue-mutated": _REWRITE, "destination-mutated": _REWRITE,
    "authority-evidence-stale": ("status-source-trusted-within-freshness-limit",),
    "delegation-hop-amplified": ("two-hop-chain-only", "descendant-token-revocation-absent"),
    "fallback-expired": _CLOCK, "late-approval-for-expired-request": _CLOCK,
}


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


def check_authority(record: Any, key: str, principal: str, at: int) -> dict[str, Any]:
    """Require bounded-age current authority before the protected dispatch.

    Parameters
    ----------
    record : Any
        Signed status assertion from the configured authority source.
    key, principal : str
        Source key and exact approver identity selected by the consumer.
    at : int
        Local reference clock in UTC seconds. Trust in that clock and in the
        asserted status remains explicit; this is not an external directory.

    Returns
    -------
    dict[str, Any]
        Verified active status assertion, including its actual evidence age.

    Raises
    ------
    VerificationError
        For wrong identity, malformed or future time, stale evidence, or a
        revoked authority. The oldest admitted age is ``MAX_AGE_SECONDS``.
    """
    payload = checked_record(record, key, AUTHORITY_DOMAIN)
    if set(payload) != AUTHORITY_FIELDS or payload["principalId"] != principal:
        refuse("authority identity or fields differ")
    stamp = payload["observedAt"]
    if type(at) is not int or type(stamp) is not int or stamp > at:
        refuse("authority time is invalid")
    if at - stamp > MAX_AGE_SECONDS:
        refuse("authority evidence is stale")
    if payload["status"] != "active":
        refuse("approver authority is not active")
    return {**payload, "ageSeconds": at - stamp}


def check_delegation(hops: Any, root: str, principal: str, action: str, target: str) -> int:
    """Refuse a delegation chain that breaks, widens, or excludes the action.

    Parameters
    ----------
    hops : Any
        Ordered hops from the root grantor to the dispatching principal. Each
        hop names its delegator, delegate, and the exact action and target
        sets it passes on. Sets are compared exactly; no wildcard expands.
    root, principal : str
        Consumer-selected root grantor and the principal named by the request.
    action, target : str
        Exact tool and target of the attempted dispatch.

    Returns
    -------
    int
        Number of hops checked.

    Raises
    ------
    VerificationError
        If a hop is malformed, the chain does not run from ``root`` to
        ``principal``, a later hop holds any action or target its delegator did
        not hold (amplification), or the final scope excludes the dispatch.
    """
    if not isinstance(hops, list) or not hops:
        refuse("delegation chain is broken")
    holder, actions, targets = root, None, None
    for hop in hops:
        if (not isinstance(hop, dict) or set(hop) != HOP_FIELDS
                or not all(isinstance(hop[k], list) and all(isinstance(v, str) for v in hop[k]) for k in ("actions", "targets"))):
            refuse("delegation hop fields differ")
        if hop["delegator"] != holder:
            refuse("delegation chain is broken")
        if actions is not None and not (set(hop["actions"]) <= actions and set(hop["targets"]) <= targets):
            refuse("delegation hop widens scope")
        holder, actions, targets = hop["delegate"], set(hop["actions"]), set(hop["targets"])
    if holder != principal:
        refuse("delegation chain is broken")
    if action not in actions or target not in targets:
        refuse("delegated scope excludes action")
    return len(hops)


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
    content: bytes, authority: dict[str, Any], authority_key: str, *, at: int, request_deadline: int,
    hops: list[dict[str, Any]], root: str,
) -> dict[str, Any]:
    """Check status and exact approved bytes, then enter the native gate.

    No reachable or unavailable human condition creates a grant. A previously
    issued exact grant is required in both cases. Native expiry and persistent
    revocation are rechecked inside :meth:`TicketStore.dispatch`, including
    cached retries and the transaction immediately before the effect.

    Returns
    -------
    dict[str, Any]
        Native signed receipt. Native interruptions remain exceptions; callers
        must retain read-back and task outcome separately, as ``producer.py``
        does. A failed return is not proof of an absent effect.

    Raises
    ------
    VerificationError
        For missing delegated authority, an amplified or broken delegation
        chain, invalid source evidence, mismatched
        descriptor bytes, or any native admission refusal.
    """
    if grant is None:
        refuse("no pre-authorized fallback")
    if type(request_deadline) is not int or at >= request_deadline:
        refuse("original decision window has closed")
    check_delegation(hops, root, request.principal_id, request.tool_id, request.target_path)
    check_authority(authority, authority_key, request.principal_id, at)
    if hashlib.sha256(content).hexdigest() != request.content_sha256:
        refuse("approved action bytes changed")
    return store.dispatch({"request": asdict(request), "grant": grant, "contentHex": content.hex()})


def reference_time(second: int) -> datetime:
    """Convert the reference clock's integer seconds to an aware UTC instant."""
    return datetime.fromtimestamp(second, timezone.utc)
