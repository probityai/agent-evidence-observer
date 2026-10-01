"""Join a pinned unsigned AAE kernel decision to protected local dispatch.

The decision commitment is separate from the launch policy and local issuer
signature. It authenticates local ordering under PEER keys, not AAE JWS issuer
identity, production isolation, EVM effects or independently operated custody.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from .aae_binding import verify_local_decision
from .aae_enforce import canonical_bytes
from .authorization import ActionRequest, GrantPolicy, utc_clock
from .broker import WriteResult
from .crypto import SigningKey, digest
from .protected_dispatch import ProtectedDispatcher, verify_dispatch_bundle

DECISION_DOMAIN = "probity-aae-protected-decision-v0"


def decision_digest(
    mandate: Any,
    transaction: Any,
    record: dict[str, Any],
    request: ActionRequest,
    pinned_mandate_digest: str,
) -> str:
    """Replay exact native inputs and derive the protected decision commitment.

    Parameters
    ----------
    mandate, transaction, record
        Native unsigned inputs and claimed core, checked by
        :func:`~.aae_binding.verify_local_decision`.
    request : ActionRequest
        Consumer-selected exact invocation.
    pinned_mandate_digest : str
        Separately acquired native mandate digest.

    Returns
    -------
    str
        Lowercase SHA-256 commitment covering the replayed core, mandate and
        transaction digests. Native digests use the existing JCS kernel.

    Raises
    ------
    VerificationError
        When native replay, exact constraints, pins or request do not match.
    """
    actual = verify_local_decision(
        mandate, transaction, record, request, pinned_mandate_digest
    )
    return digest(
        DECISION_DOMAIN,
        {
            "profile": DECISION_DOMAIN,
            "mandateDigest": pinned_mandate_digest,
            "coreDigest": actual["core_digest"],
            "transactionDigest": actual["core"]["transaction_digest"],
        },
    )


class AaeProtectedDispatcher(ProtectedDispatcher):
    """Replay a frozen AAE PERMIT before every protected local invocation.

    Parameters
    ----------
    workspace, state_dir, expected_request, policy, observer_key, witness_key
        Host-owned native dispatch configuration; see
        :class:`~.protected_dispatch.ProtectedDispatcher`.
    mandate, transaction, record
        Native unsigned decision inputs. Canonical bytes are captured at
        construction so later caller mutation cannot change their meaning.
    pinned_mandate_digest : str
        Consumer mandate pin acquired outside the candidate record.
    clock, retained_authorization_head, execution_digest
        Original host clock, rollback pin and optional launch-policy binding.
        The decision commitment occupies its own configuration field.

    Notes
    -----
    Initialization commits the replayed decision into signed configuration.
    The existing prior authorization journal commits that same configuration
    before the local effect. The original signed local grant remains required;
    its issuer is distinct from the unauthenticated unsigned AAE issuer.
    Host objects/keys remain trusted; this class does not isolate its caller.
    """

    def __init__(
        self,
        workspace: Path,
        state_dir: Path,
        expected_request: ActionRequest,
        policy: GrantPolicy,
        observer_key: SigningKey,
        witness_key: SigningKey,
        *,
        mandate: Any,
        transaction: Any,
        record: dict[str, Any],
        pinned_mandate_digest: str,
        clock: Callable[[], datetime] = utc_clock,
        retained_authorization_head: dict[str, Any] | None = None,
        execution_digest: str | None = None,
    ) -> None:
        commitment = decision_digest(
            mandate, transaction, record, expected_request, pinned_mandate_digest
        )
        self._decision_bytes = canonical_bytes([mandate, transaction, record])
        self._mandate_pin = pinned_mandate_digest
        super().__init__(
            workspace,
            state_dir,
            expected_request,
            policy,
            observer_key,
            witness_key,
            clock=clock,
            retained_authorization_head=retained_authorization_head,
            execution_digest=execution_digest,
            decision_digest=commitment,
        )

    def write(
        self, request: ActionRequest, grant: Mapping[str, Any], content: bytes
    ) -> WriteResult:
        """Replay the frozen decision, then apply normal protected dispatch.

        Parameters
        ----------
        request, grant, content
            Exact invocation, separately signed local grant and replacement
            bytes accepted by :meth:`ProtectedDispatcher.write`.

        Returns
        -------
        WriteResult
            Durable native result, including replay status on a valid retry.

        Raises
        ------
        VerificationError
            For changed request or invalid native/local authorization. Native
            pending/crash states retain their original fail-closed behavior.
        """
        mandate, transaction, record = json.loads(self._decision_bytes)
        verify_local_decision(mandate, transaction, record, request, self._mandate_pin)
        return super().write(request, grant, content)


def verify_aae_dispatch_bundle(
    mandate: Any,
    transaction: Any,
    record: dict[str, Any],
    directory: Path | None,
    expected_request: ActionRequest,
    policy: GrantPolicy,
    observer_key: str,
    witness_key: str,
    retained_authorization_head: dict[str, Any],
    *,
    pinned_mandate_digest: str,
    workspace: Path | None = None,
    execution_digest: str | None = None,
) -> dict[str, Any]:
    """Replay AAE inputs and verify their pre-effect protected journal binding.

    Parameters
    ----------
    mandate, transaction, record, pinned_mandate_digest
        Native decision evidence and separate consumer mandate pin.
    directory : Path | None
        Completed protected bundle. Explicit ``None`` means missing evidence
        and leaves execution unknown. A supplied incomplete or corrupt bundle
        is refused; it is never interpreted as successful or absent evidence.
    expected_request, policy, observer_key, witness_key, retained_authorization_head
        Consumer-selected action and trust inputs for
        :func:`~.protected_dispatch.verify_dispatch_bundle`.
    workspace, execution_digest
        Optional native read-back and separate launch-policy commitment.

    Returns
    -------
    dict[str, Any]
        Separate native-kernel, AAE-issuer and execution results. A successful
        join authenticates local witnessed ordering with PEER/artifact scope.

    Raises
    ------
    VerificationError
        For mismatched decision, request, signatures, history or configuration.
    OSError
        If a supplied retained bundle is incomplete or cannot be read.
    """
    commitment = decision_digest(
        mandate, transaction, record, expected_request, pinned_mandate_digest
    )
    result = {
        "kernelVerdict": "PERMIT",
        "issuerAuthentication": "not-established",
        "decisionDigest": commitment,
        "execution": "unknown",
        "linkage": "missing",
        "witnessScope": "PEER",
        "evidence_vantage": "artifact",
    }
    if directory is None:
        return result
    dispatch = verify_dispatch_bundle(
        directory,
        expected_request,
        policy,
        observer_key,
        witness_key,
        retained_authorization_head,
        workspace=workspace,
        execution_digest=execution_digest,
        decision_digest=commitment,
    )
    return {
        **result,
        "execution": "recorded-local-write",
        "linkage": "verified",
        "dispatch": dispatch,
    }
