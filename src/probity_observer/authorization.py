"""Bind a public reference authorization to one brokered file replacement.

This profile is a local reference integration, not APS, MCP, A2A, DSSE, or
Observed Effect conformance. An explicit issuer grants one exact request; an
observer authenticates that grant before invoking :class:`~.broker.Broker`.
The observer signs a separate grant-to-claim binding when the interval seals.
Native packets and their restricted JSON signing bytes remain unchanged.

The binding attests the observer's dispatch time. Its post-action signature
does not establish cryptographic proof that the grant was witnessed before
the effect. The native prior commitment still covers native authority only.
Different keys and local objects do not establish independent custody.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn

from . import broker as native_broker
from .broker import Broker, WriteResult
from .crypto import (
    SigningKey,
    VerificationError,
    canonical,
    digest,
    strict_loads,
    verify_signature,
)
from .verify import verify_packet

LOGGER = logging.getLogger(__name__)
PROFILE = "probity-protected-action-reference-v0"
GRANT_DOMAIN = "probity-protected-action-grant-v0"
BINDING_DOMAIN = "probity-protected-action-binding-v0"
HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[!-~]{1,128}\Z")
UTC_SECOND = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
GRANT_FIELDS = frozenset(
    {"profile", "request", "issuedAt", "expiresAt", "issuerKey", "signature"}
)
BINDING_FIELDS = frozenset({"payload", "keyid", "signature"})
MAX_VALIDITY_SECONDS = 3600


def _refuse(reason: str) -> NoReturn:
    """Log a bounded refusal without request contents or private key material."""
    LOGGER.warning("protected action refused: %s", reason)
    raise VerificationError(reason)


def _identifier(value: Any, name: str) -> None:
    """Require a finite, nonempty, printable ASCII identifier without spaces."""
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        _refuse(f"{name} must be a nonempty printable ASCII identifier")


def _hex_digest(value: Any, name: str) -> None:
    """Require the exact lowercase hexadecimal representation of 32 bytes."""
    if not isinstance(value, str) or HEX_DIGEST.fullmatch(value) is None:
        _refuse(f"{name} must be a lowercase SHA-256-sized hexadecimal value")


def _target(value: Any) -> None:
    """Validate the literal local profile path without decoding or resolving it."""
    _target_syntax(value)
    if "\\" in value:
        _refuse("target_path must be a normalized literal path under /work")
    if any(part in {"", ".", ".."} for part in value[1:].split("/")):
        _refuse("target_path must be a normalized literal path under /work")


def _target_syntax(value: Any) -> None:
    """Check finite printable literal path syntax before inspecting segments."""
    if not isinstance(value, str) or not value.isascii() or len(value) > 256:
        _refuse("target_path must be a normalized literal path under /work")
    if not value.startswith("/work/"):
        _refuse("target_path must be a normalized literal path under /work")
    if any(ord(character) < 33 or ord(character) == 127 for character in value):
        _refuse("target_path must be a normalized literal path under /work")


@dataclass(frozen=True, slots=True)
class ActionRequest:
    """Immutable exact invocation identity for one local file replacement.

    Parameters
    ----------
    run_id, attempt_id, request_id : str
        Distinct logical run, invocation attempt, and broker idempotency
        identifiers. ``run_id`` must equal the native authority's interval ID.
    tenant_id, principal_id : str
        Exact tenant and requesting principal selected by the relying party.
        These identifiers have no implicit directory or identity resolution.
    tool_id : str
        Exact locally configured tool identifier. The profile binds the value;
        it does not discover a remote tool or establish protocol conformance.
    target_path : str
        Normalized literal absolute path beneath ``/work``. No URL decoding,
        filesystem resolution, or alias conversion occurs in this profile.
        The native :meth:`~.broker.Broker.write` applies its own path checks.
    content_sha256 : str
        SHA-256 of the exact bytes to replace at ``target_path``.

    Raises
    ------
    VerificationError
        If an identifier, target path, or digest is outside the profile.

    Notes
    -----
    All identifiers are 1-128 printable ASCII characters without spaces.
    ``attempt_id`` is an explicit binding, not a generated retry counter.
    """

    run_id: str
    attempt_id: str
    request_id: str
    tenant_id: str
    principal_id: str
    tool_id: str
    target_path: str
    content_sha256: str

    def __post_init__(self) -> None:
        for name in (
            "run_id",
            "attempt_id",
            "request_id",
            "tenant_id",
            "principal_id",
            "tool_id",
        ):
            _identifier(getattr(self, name), name)
        _target(self.target_path)
        _hex_digest(self.content_sha256, "content_sha256")


@dataclass(frozen=True, slots=True)
class GrantPolicy:
    """Consumer-selected issuer key and permitted grant duration.

    Parameters
    ----------
    issuer_key : str
        Raw Ed25519 public key as 64 lowercase hexadecimal characters, acquired
        outside the candidate grant. Copying its key from the candidate would
        remove the issuer authentication this policy is intended to enforce.
    max_validity_seconds : int, default=300
        Positive maximum grant duration, at most 3600 seconds. Boolean values
        are refused even though Python treats them as integers.

    Raises
    ------
    VerificationError
        If the public key or duration is malformed.
    """

    issuer_key: str
    max_validity_seconds: int = 300

    def __post_init__(self) -> None:
        _hex_digest(self.issuer_key, "issuer_key")
        valid = type(self.max_validity_seconds) is int
        if not valid or not 1 <= self.max_validity_seconds <= MAX_VALIDITY_SECONDS:
            _refuse("max_validity_seconds must be an integer from 1 to 3600")


@dataclass(frozen=True, slots=True)
class AuthorizedAction:
    """Frozen result of authenticating an exact request under an issuer policy.

    Attributes
    ----------
    request : ActionRequest
        Exact request selected by the relying party and carried in the grant.
    issuer_key : str
        Public key authenticated against :class:`GrantPolicy`.
    issued_at, expires_at : datetime
        UTC second-precision validity window. The expiration is exclusive.
    grant_digest : str
        Domain-separated digest of the complete canonical signed grant,
        including its signature and issuer key. The observer binds this value
        to the native claim in :meth:`AuthorizedBroker.seal`.

    Notes
    -----
    Authentication does not establish an actual effect, independent operation,
    complete coverage, issuer entitlement beyond policy, or current freshness.
    """

    request: ActionRequest
    issuer_key: str
    issued_at: datetime
    expires_at: datetime
    grant_digest: str


def utc_clock() -> datetime:
    """Return the current UTC time rounded down to this profile's precision."""
    return datetime.now(timezone.utc).replace(microsecond=0)


def _utc(value: Any, name: str) -> datetime:
    """Require an aware UTC datetime with no discarded fractional seconds."""
    if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
        _refuse(f"{name} must be a timezone-aware UTC datetime")
    if value.microsecond:
        _refuse(f"{name} must use UTC second precision")
    return value


def _timestamp(value: datetime) -> str:
    """Format a previously validated UTC datetime in the native lexical form."""
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_timestamp(value: Any, name: str) -> datetime:
    """Parse only valid canonical UTC second-precision grant timestamps."""
    if not isinstance(value, str) or UTC_SECOND.fullmatch(value) is None:
        _refuse(f"{name} must use canonical UTC second precision")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        _refuse(f"{name} must use canonical UTC second precision")


def _window(issued_at: datetime, expires_at: datetime, maximum: int) -> None:
    """Require a strictly positive finite duration bounded by selected policy."""
    duration = (expires_at - issued_at).total_seconds()
    if not 0 < duration <= maximum:
        _refuse("grant validity window exceeds policy or is not positive")


def _payload(grant: Mapping[str, Any]) -> dict[str, Any]:
    """Return exactly the signed payload fields without mutating the candidate."""
    return {
        "profile": grant["profile"],
        "request": grant["request"],
        "issuedAt": grant["issuedAt"],
        "expiresAt": grant["expiresAt"],
    }


def _grant_object(grant: Any) -> dict[str, Any]:
    """Take a canonical private snapshot and reject unexpected grant fields."""
    if not isinstance(grant, Mapping) or set(grant) != GRANT_FIELDS:
        _refuse("grant has unexpected fields")
    try:
        return strict_loads(canonical(dict(grant)))
    except VerificationError:
        _refuse("grant is outside the restricted JSON profile")


def issue_grant(
    request: ActionRequest,
    issuer_key: SigningKey,
    *,
    issued_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    """Sign one exact action request under the public local reference profile.

    Parameters
    ----------
    request : ActionRequest
        Validated invocation identity and exact replacement-byte digest.
    issuer_key : SigningKey
        Explicit authority signer. It must be different from the observer and
        witness keys used with :class:`AuthorizedBroker`.
    issued_at, expires_at : datetime
        Aware UTC datetimes at second precision. Expiration must follow issuance
        by at most one hour. :func:`verify_grant` applies the consumer's usually
        shorter duration policy and the supplied reference time.

    Returns
    -------
    dict[str, Any]
        Canonical-profile grant with the exact payload, issuer public key,
        and Ed25519 signature. No private key bytes are included.

    Raises
    ------
    VerificationError
        If timestamps or their duration are outside the public profile.
    """
    _utc(issued_at, "issued_at")
    _utc(expires_at, "expires_at")
    _window(issued_at, expires_at, MAX_VALIDITY_SECONDS)
    payload = {
        "profile": PROFILE,
        "request": asdict(request),
        "issuedAt": _timestamp(issued_at),
        "expiresAt": _timestamp(expires_at),
    }
    return {
        **payload,
        "issuerKey": issuer_key.public_hex,
        "signature": issuer_key.sign(GRANT_DOMAIN, payload),
    }


def _authenticate(
    grant: dict[str, Any], expected: ActionRequest, policy: GrantPolicy
) -> None:
    """Authenticate the issuer and every exact invocation field before dispatch."""
    if grant["profile"] != PROFILE:
        _refuse("grant profile is unsupported")
    if grant["issuerKey"] != policy.issuer_key:
        _refuse("grant issuer differs from the pinned issuer key")
    try:
        verify_signature(
            policy.issuer_key, GRANT_DOMAIN, _payload(grant), grant["signature"]
        )
    except (VerificationError, TypeError):
        _refuse("grant signature does not verify under the pinned issuer key")
    if grant["request"] != asdict(expected):
        _refuse("grant request differs from the expected action")


def verify_grant(
    grant: Mapping[str, Any],
    expected_request: ActionRequest,
    policy: GrantPolicy,
    *,
    now: datetime,
) -> AuthorizedAction:
    """Authenticate exact authorization at an explicit consumer reference time.

    Parameters
    ----------
    grant : Mapping[str, Any]
        Signed candidate produced by :func:`issue_grant`. A private canonical
        snapshot is verified; unexpected fields are refused.
    expected_request : ActionRequest
        Exact request chosen outside the grant by the relying party.
    policy : GrantPolicy
        Independently configured issuer public key and duration limit.
    now : datetime
        Aware UTC second-precision reference time satisfying
        ``issued_at <= now < expires_at``. Historical offline verification uses
        a declared reference time and does not imply present-day freshness.

    Returns
    -------
    AuthorizedAction
        Immutable authenticated request and complete signed-grant digest.

    Raises
    ------
    VerificationError
        On malformed bytes, unsupported profile, unpinned issuer, invalid
        signature, mismatched request, excessive duration, or invalid time.
        Refusals are logged using bounded reasons without candidate contents.
    """
    reference = _utc(now, "now")
    candidate = _grant_object(grant)
    _authenticate(candidate, expected_request, policy)
    issued_at = _parse_timestamp(candidate["issuedAt"], "issuedAt")
    expires_at = _parse_timestamp(candidate["expiresAt"], "expiresAt")
    _window(issued_at, expires_at, policy.max_validity_seconds)
    if not issued_at <= reference < expires_at:
        _refuse("grant is not valid at the reference time")
    return AuthorizedAction(
        expected_request,
        policy.issuer_key,
        issued_at,
        expires_at,
        digest(GRANT_DOMAIN, candidate),
    )


def _broker_request(
    broker: Broker, request: ActionRequest, policy: GrantPolicy
) -> None:
    """Check the reference broker's native interval, scope, and key boundaries."""
    authority = broker.authority
    if authority["intervalId"] != request.run_id:
        _refuse("action run differs from the broker interval")
    if authority != {
        "intervalId": request.run_id,
        "scope": "/work",
        "operation": "write-file",
    }:
        _refuse("protected action requires the minimal /work write-file broker profile")
    keys = {broker.observer_key.public_hex, broker.witness.signing_key.public_hex}
    if policy.issuer_key in keys:
        _refuse("issuer, observer, and witness keys must differ")


class AuthorizedBroker:
    """Authorize an exact finite action before the native broker applies it.

    Parameters
    ----------
    broker : Broker
        Native broker configured for ``/work`` file writes, with an interval ID
        matching the expected request's ``run_id``. Call
        :meth:`~probity_observer.broker.Broker.begin` before :meth:`write`.
    grant : Mapping[str, Any]
        Signed grant captured into this wrapper's private immutable bytes.
    policy : GrantPolicy
        Explicit issuer key pin and validity-duration policy. Its issuer must
        differ from both native observer and witness keys.
    expected_request : ActionRequest
        Immutable consumer-selected invocation identity, including tenant,
        principal, tool, target, attempt, and exact content digest.
    clock : Callable[[], datetime], optional
        UTC second-precision reference clock used on every call to
        :meth:`write`. Defaults to :func:`utc_clock`.

    Notes
    -----
    This wrapper is one path into a local broker. A holder of the underlying
    broker or workspace can bypass it; the offline reader rejects extra
    recorded effects but cannot discover every omitted or transient effect.
    The observer remains ``PEER`` and ``artifact``. A separate key does not
    establish an independent operator. Consumer replay is handled by the
    existing :class:`~.admission.AdmissionStore`, not by this wrapper.
    """

    def __init__(
        self,
        broker: Broker,
        grant: Mapping[str, Any],
        policy: GrantPolicy,
        expected_request: ActionRequest,
        *,
        clock: Callable[[], datetime] = utc_clock,
    ) -> None:
        _broker_request(broker, expected_request, policy)
        self.broker = broker
        self.policy = policy
        self.expected_request = expected_request
        self.clock = clock
        self._grant = canonical(_grant_object(grant))
        self._authority_digest = digest("probity-authority-v0", broker.authority)
        self._observer_key = broker.observer_key.public_hex
        self._witness_key = broker.witness.signing_key.public_hex
        self._authorization: AuthorizedAction | None = None
        self._authorized_at: datetime | None = None
        self._check_native_binding()

    def _check_native_binding(self) -> None:
        """Refuse mutation of the native authority, its initial digest, or keys."""
        current = digest("probity-authority-v0", self.broker.authority)
        if (
            current != self._authority_digest
            or self.broker._authority_digest != current
        ):
            _refuse("broker authority changed from its initial commitment")
        actual_keys = (
            self.broker.observer_key.public_hex,
            self.broker.witness.signing_key.public_hex,
        )
        if actual_keys != (self._observer_key, self._witness_key):
            _refuse("broker signing keys changed after authorization configuration")

    def _check_dispatch_time(self, reference: datetime) -> None:
        """Check the dispatch clock against this begun interval before the effect."""
        if not self.broker._begin or not self.broker._started:
            _refuse("protected action requires a begun native interval")
        committed_at = _parse_timestamp(
            self.broker._begin["committedAt"], "committedAt"
        )
        observed_at = _parse_timestamp(native_broker.utc_now(), "observerNow")
        if not committed_at <= reference <= observed_at:
            _refuse("authorization dispatch time is outside the native interval")

    def write(self, request: ActionRequest, content: bytes) -> WriteResult:
        """Check issuer, all request fields, bytes, and time before applying work.

        Parameters
        ----------
        request : ActionRequest
            Exact invocation. A changed tenant, principal, tool, target, run,
            attempt, idempotency key, or content digest is refused.
        content : bytes
            Actual replacement bytes. Their SHA-256 must equal the grant's
            signed ``content_sha256`` before native dispatch.

        Returns
        -------
        WriteResult
            Native durable-file result, including exact-retry classification.

        Raises
        ------
        VerificationError
            If authorization fails before dispatch. The native broker's own
            coverage or storage exceptions propagate without being rewritten.
        """
        self._check_native_binding()
        if request != self.expected_request:
            _refuse("invocation differs from the expected action")
        if not isinstance(content, bytes):
            _refuse("protected action content must be bytes")
        if hashlib.sha256(content).hexdigest() != request.content_sha256:
            _refuse("content digest differs from the authorized action")
        reference = self.clock()
        authorization = verify_grant(
            strict_loads(self._grant), request, self.policy, now=reference
        )
        self._check_dispatch_time(reference)
        result = self.broker.write(request.request_id, request.target_path, content)
        if self._authorization is None:
            self._authorization, self._authorized_at = authorization, reference
        return result

    def seal(self) -> dict[str, Any]:
        """Seal the native interval and sign its exact link to the verified grant.

        Returns
        -------
        dict[str, Any]
            Native packet plus ``authorizationBinding``. The signed binding
            links the entire grant, exact request, observer-reported dispatch
            time, native interval, and native claim digest.

        Raises
        ------
        VerificationError
            If no authorized effect completed through this wrapper.

        Notes
        -----
        The additional observer signature is produced after the effect. It
        authenticates an attestation about ordering, not an independently
        witnessed prior commitment to the grant. Use
        :func:`verify_authorized_packet` before native consumer admission.
        """
        self._check_native_binding()
        if self._authorization is None or self._authorized_at is None:
            _refuse("protected action has no completed authorized effect")
        packet = self.broker.seal()
        payload = _binding_payload(self._authorization, packet, self._authorized_at)
        packet["authorizationBinding"] = {
            "payload": payload,
            "keyid": self.broker.observer_key.public_hex,
            "signature": self.broker.observer_key.sign(BINDING_DOMAIN, payload),
        }
        return packet


def _binding_payload(
    authorization: AuthorizedAction, packet: Mapping[str, Any], reference: datetime
) -> dict[str, Any]:
    """Build the exact signed relation from a grant to a native bounded claim."""
    return {
        "profile": PROFILE,
        "grantDigest": authorization.grant_digest,
        "claimDigest": digest("probity-claim-v0", packet["claim"]),
        "intervalId": authorization.request.run_id,
        "request": asdict(authorization.request),
        "authorizedAt": _timestamp(reference),
    }


def _binding_record(packet: Mapping[str, Any], observer_key: str) -> dict[str, Any]:
    """Require one exact binding envelope under the externally pinned observer key."""
    binding = packet.get("authorizationBinding")
    if not isinstance(binding, dict) or set(binding) != BINDING_FIELDS:
        _refuse("packet has no valid authorization binding")
    if binding["keyid"] != observer_key:
        _refuse("authorization binding key differs from the pinned observer key")
    return binding


def _verify_binding(
    packet: Mapping[str, Any], authorization: AuthorizedAction, observer_key: str
) -> datetime:
    """Authenticate a complete observer binding and its exact native claim link."""
    binding = _binding_record(packet, observer_key)
    payload = binding["payload"]
    if not isinstance(payload, dict) or "authorizedAt" not in payload:
        _refuse("authorization binding payload is malformed")
    reference = _parse_timestamp(payload["authorizedAt"], "authorizedAt")
    if payload != _binding_payload(authorization, packet, reference):
        _refuse("authorization binding differs from the grant or native claim")
    try:
        verify_signature(observer_key, BINDING_DOMAIN, payload, binding["signature"])
    except (VerificationError, TypeError):
        _refuse("authorization binding signature does not verify under the pinned key")
    return reference


def _exact_effect(claim: Mapping[str, Any], request: ActionRequest) -> None:
    """Require precisely one native accepted effect matching the authorized call."""
    writes = claim["writes"]
    if len(writes) != 1:
        _refuse("protected action requires exactly one recorded effect")
    write = writes[0]
    observed = (write["requestId"], write["path"], write["contentDigest"])
    expected = (request.request_id, request.target_path, request.content_sha256)
    if observed != expected:
        _refuse("recorded effect differs from the authorized action")


def _dispatch_chronology(packet: Mapping[str, Any], reference: datetime) -> None:
    """Require the reported dispatch time to lie within the signed native interval."""
    committed_at = _parse_timestamp(packet["commitment"]["committedAt"], "committedAt")
    sealed_at = _parse_timestamp(packet["claim"]["sealedAt"], "sealedAt")
    if not committed_at <= reference <= sealed_at:
        _refuse("authorization dispatch time is outside the native interval")


def _packet_object(packet: Any) -> dict[str, Any]:
    """Capture canonical packet bytes before checking its several signed relations."""
    if not isinstance(packet, dict):
        _refuse("protected action packet is malformed")
    return strict_loads(canonical(packet))


def _native_claim(
    packet: dict[str, Any],
    history: Path,
    observer: str,
    witness: str,
    workspace: Path | None,
) -> dict[str, Any]:
    """Preserve native verification reasons while normalizing malformed input."""
    try:
        return verify_packet(packet, history, observer, witness, workspace)
    except VerificationError as exc:
        LOGGER.warning("protected action refused: %s", exc)
        raise
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        _refuse("protected action packet is malformed")


def verify_authorized_packet(
    grant: Mapping[str, Any],
    expected_request: ActionRequest,
    policy: GrantPolicy,
    packet: dict[str, Any],
    history_path: Path,
    pinned_observer_key: str,
    pinned_witness_key: str,
    *,
    now: datetime,
    workspace: Path | None = None,
) -> dict[str, Any]:
    """Verify exact authorization separately from native observation consistency.

    Parameters
    ----------
    grant, expected_request, policy, now
        Inputs to :func:`verify_grant`. Select policy, expected request, and
        historical reference time outside the candidate packet.
    packet : dict[str, Any]
        Native packet with observer-signed ``authorizationBinding`` returned
        by :meth:`AuthorizedBroker.seal`. A plain native packet cannot pass.
    history_path : Path
        Retained native history, checked by :func:`~.verify.verify_packet`.
    pinned_observer_key, pinned_witness_key : str
        Consumer-selected Ed25519 public key pins, separate from the issuer.
    workspace : Path | None, optional
        If supplied, native verification compares the current file tree to
        the claim root. Without it, this is an authenticated record check;
        the current durable file bytes have not been independently compared.

    Returns
    -------
    dict[str, Any]
        ``authorization`` with its explicit verified status, profile, signed
        grant digest, reference time, observer-attested dispatch time, and
        current-workspace-check flag; and ``claim`` with the unchanged native
        bounded observation. Native witness scope remains ``PEER``.

    Raises
    ------
    VerificationError
        If grant, keys, signed binding, interval, scope, single-effect identity,
        or grant validity at either reference time fails. Native verification
        exceptions retain their original reasons.

    Notes
    -----
    This reader does not persist consumer replay state. Call it before
    :meth:`~.admission.AdmissionStore.admit`; native admission alone does not
    authenticate the additional authorization binding. Passing record checks
    do not establish complete capture or independent operator custody.
    """
    candidate_grant = _grant_object(grant)
    candidate = _packet_object(packet)
    authorization = verify_grant(candidate_grant, expected_request, policy, now=now)
    if policy.issuer_key in {pinned_observer_key, pinned_witness_key}:
        _refuse("issuer, observer, and witness keys must differ")
    claim = _native_claim(
        candidate, history_path, pinned_observer_key, pinned_witness_key, workspace
    )
    authority = candidate["authority"]
    if authority != {
        "intervalId": expected_request.run_id,
        "scope": "/work",
        "operation": "write-file",
    }:
        _refuse("native authority differs from the protected action profile")
    dispatch_time = _verify_binding(candidate, authorization, pinned_observer_key)
    verify_grant(candidate_grant, expected_request, policy, now=dispatch_time)
    _dispatch_chronology(candidate, dispatch_time)
    _exact_effect(claim, expected_request)
    return {
        "authorization": {
            "status": "verified",
            "profile": PROFILE,
            "grantDigest": authorization.grant_digest,
            "referenceTime": _timestamp(now),
            "authorizedAt": _timestamp(dispatch_time),
            "orderingEvidence": "observer-attested-dispatch-time",
            "currentWorkspaceCompared": workspace is not None,
        },
        "claim": claim,
    }
