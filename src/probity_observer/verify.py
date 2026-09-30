"""Offline checks for a prototype observer packet and witnessed history."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .broker import CoverageError, _path_under_scope, tree_root
from .crypto import VerificationError, digest, verify_signature
from .history import read_history, unresolved_intents, verify_checkpoint, verify_incomplete_terminal

UTC_SECOND = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


def _verify_commitment(packet: dict[str, Any], observer_key: str) -> None:
    commitment = packet["commitment"]
    preimage = commitment["preimage"]
    claim = packet["claim"]
    if commitment["keyid"] != observer_key:
        raise VerificationError("commitment key is not the pinned observer key")
    expected = {
        "authorityDigest": claim["authorityDigest"],
        "beforeRoot": claim["beforeRoot"],
        "intervalId": claim["intervalId"],
        "witnessNonce": preimage["witnessNonce"],
    }
    if preimage != expected:
        raise VerificationError("prior commitment does not bind the claim")
    payload = {"preimage": preimage, "committedAt": commitment["committedAt"]}
    verify_signature(observer_key, "probity-prior-commitment-v0", payload, commitment["signature"])
    if not UTC_SECOND.fullmatch(commitment["committedAt"]) or not UTC_SECOND.fullmatch(claim["sealedAt"]):
        raise VerificationError("record timestamps must use UTC second precision")
    if packet["claim"]["sealedAt"] < commitment["committedAt"]:
        raise VerificationError("claim sealed before prior commitment")


def _verify_events(packet: dict[str, Any], entries: list[dict[str, Any]]) -> None:
    if not entries or entries[0]["event"]["kind"] != "begin":
        raise VerificationError("history has no first commitment")
    if entries[-1]["event"]["kind"] != "seal":
        raise VerificationError("history has no final seal")
    _verify_request_sequence(entries)
    commitment = packet["commitment"]
    payload = {"preimage": commitment["preimage"], "committedAt": commitment["committedAt"]}
    if (
        entries[0]["event"]["commitmentDigest"] != digest("probity-prior-commitment-v0", payload)
        or entries[0]["event"]["commitment"] != commitment
    ):
        raise VerificationError("history begin does not bind the commitment")
    claim = packet["claim"]
    if entries[-1]["event"]["claimDigest"] != digest("probity-claim-v0", claim):
        raise VerificationError("history seal does not bind the claim")
    observed_writes = [entry["event"] for entry in entries if entry["event"]["kind"] == "write"]
    if observed_writes != claim["writes"]:
        raise VerificationError("claim write set differs from the history")


def _verify_request_sequence(entries: list[dict[str, Any]]) -> None:
    """Refuse duplicate boundaries and retries without a matching first effect."""
    seen: dict[str, str] = {}
    for index, entry in enumerate(entries):
        event = entry["event"]
        kind = event["kind"]
        if kind not in {"begin", "write-intent", "write", "denied", "retry", "gap", "seal"}:
            raise VerificationError("history has an unknown event kind")
        if kind in {"begin", "seal"} and index not in {0, len(entries) - 1}:
            raise VerificationError("history has a duplicate interval boundary")
        if kind == "write":
            request_id = event["requestId"]
            if request_id in seen:
                raise VerificationError("history repeats a write request id")
            seen[request_id] = event["path"]
        if kind == "retry" and seen.get(event["requestId"]) != event["path"]:
            raise VerificationError("history retry has no matching write")
    if unresolved_intents(entries):
        raise VerificationError("history has an unresolved write intent")


def verify_incomplete(
    history_path: Path,
    start_checkpoint: dict[str, Any],
    checkpoint: dict[str, Any],
    pinned_observer_key: str,
    pinned_witness_key: str,
) -> dict[str, Any]:
    """Check the retained history and witness head for an interrupted write."""
    entries = read_history(history_path)
    if len(entries) < 2 or entries[0]["event"]["kind"] != "begin":
        raise VerificationError("incomplete history has no begin event")
    terminal = entries[-1]["event"]
    if terminal["kind"] != "incomplete":
        raise VerificationError("history has no incomplete terminal event")
    if any(entry["event"]["kind"] in {"begin", "seal", "incomplete"} for entry in entries[1:-1]):
        raise VerificationError("incomplete history has an extra interval boundary")
    pending = unresolved_intents(entries[:-1])
    verify_incomplete_terminal(terminal, pending)
    checked = entries[:-2] if pending else entries[:-1]
    _verify_request_sequence(checked + [{"event": {"kind": "seal"}}])
    begin = entries[0]["event"]
    commitment = begin["commitment"]
    payload = {"preimage": commitment["preimage"], "committedAt": commitment["committedAt"]}
    if begin["commitmentDigest"] != digest("probity-prior-commitment-v0", payload):
        raise VerificationError("history begin does not bind the commitment")
    if commitment["keyid"] != pinned_observer_key:
        raise VerificationError("commitment key is not the pinned observer key")
    verify_signature(pinned_observer_key, "probity-prior-commitment-v0", payload, commitment["signature"])
    verify_checkpoint(entries[:1], start_checkpoint, pinned_witness_key)
    verify_checkpoint(entries, checkpoint, pinned_witness_key)
    return terminal


def _verify_roots(claim: dict[str, Any], entries: list[dict[str, Any]]) -> None:
    current = claim["beforeRoot"]
    for write in claim["writes"]:
        if write["beforeRoot"] != current:
            raise VerificationError("write roots do not form a continuous chain")
        try:
            _path_under_scope(claim["coverage"]["scope"], write["path"])
        except CoverageError as exc:
            raise VerificationError("observed write is outside the declared scope") from exc
        current = write["afterRoot"]
    if current != claim["afterRoot"]:
        raise VerificationError("after root differs from the observed write chain")
    gaps = [entry["event"]["reason"] for entry in entries if entry["event"]["kind"] == "gap"]
    coverage = claim["coverage"]
    if coverage["knownGaps"] != gaps or coverage["noDetectedGap"] != (not gaps):
        raise VerificationError("coverage claim differs from observed gaps")
    if coverage["observedPopulation"] != "broker-write-calls-with-valid-request-id" or coverage["unmediatedEffects"] != "not-established":
        raise VerificationError("coverage population differs from the prototype contract")
    if claim["witnessScope"] != "PEER":
        raise VerificationError("prototype may only claim PEER witness scope")


def verify_packet(
    packet: dict[str, Any],
    history_path: Path,
    pinned_observer_key: str,
    pinned_witness_key: str,
    workspace: Path | None = None,
) -> dict[str, Any]:
    """Verify all bytes and return the bounded claim for policy evaluation.

    Parameters
    ----------
    packet : dict[str, Any]
        Signed prior commitment, final claim, and two witnessed checkpoints.
    history_path : Path
        Retained event history. Its sequence and hash chain are recomputed.
    pinned_observer_key, pinned_witness_key : str
        Public Ed25519 keys chosen by the consumer outside the packet.
    workspace : Path | None, optional
        If supplied, compare its *current* content tree to the packet's final
        root. This does not prove the tree's state at the earlier observation.

    Returns
    -------
    dict[str, Any]
        Claim whose cryptographic and internal consistency checks passed. A
        caller must still decide whether it trusts the key custodians and
        whether ``coverage`` is adequate for its decision.

    Raises
    ------
    VerificationError
        If a signature, history, binding, or optional current tree differs.
    """
    entries = read_history(history_path)
    claim = packet["claim"]
    if pinned_observer_key == pinned_witness_key:
        raise VerificationError("observer and witness keys must differ")
    authority = packet["authority"]
    if claim["format"] != "probity-observer-prototype-v0" or claim["intervalId"] != authority["intervalId"]:
        raise VerificationError("claim format or interval differs from authority")
    if authority["scope"] != claim["coverage"]["scope"] or authority["operation"] != "write-file":
        raise VerificationError("claim scope or operation differs from authority")
    if packet["claimKeyid"] != pinned_observer_key:
        raise VerificationError("claim key is not the pinned observer key")
    verify_signature(pinned_observer_key, "probity-claim-v0", claim, packet["claimSignature"])
    if claim["authorityDigest"] != digest("probity-authority-v0", packet["authority"]):
        raise VerificationError("claim authority digest differs")
    _verify_commitment(packet, pinned_observer_key)
    _verify_events(packet, entries)
    _verify_roots(claim, entries)
    verify_checkpoint(entries[:1], packet["startCheckpoint"], pinned_witness_key)
    verify_checkpoint(entries, packet["checkpoint"], pinned_witness_key)
    if workspace is not None and tree_root(workspace) != claim["afterRoot"]:
        raise VerificationError("current workspace root differs from the claim")
    return claim
