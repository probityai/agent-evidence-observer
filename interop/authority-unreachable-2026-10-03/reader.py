"""Read signed authority cases and native SQLite effects using consumer pins."""

from __future__ import annotations

import argparse
import json
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any

from probity_observer.authorization import ActionRequest, GrantPolicy, verify_grant
from probity_observer.crypto import VerificationError, digest, strict_loads
from probity_observer.ticket_service import DOMAIN, STATE_FIELDS, _checked as checked_native_receipt, _state_schema, verify_ticket_result

from authority_profile import (AUTHORITY_DOMAIN, CASE_IDS, CONTRACT_ID, MAX_AGE_SECONDS, PROFILE, RECORD_DOMAIN, check_authority, check_delegation,
                               checked_record, reference_time, refuse)


def _native_envelope(raw: bytes, key: str) -> dict[str, Any]:
    """Authenticate native canonical bytes under the pinned service domain."""
    return checked_record(strict_loads(raw), key, DOMAIN)


def _event_body(kind: str, state: dict[str, Any], request: ActionRequest, issuer_key: str) -> dict[str, Any] | None:
    """Select the exact native event fields from the chosen action and state."""
    return {
        "initialize": {"kind": "initialize", "configuration": state["configuration"]},
        "intent": {"kind": "intent", "request": asdict(request), "grantDigest": state["grantDigest"],
                   "effectId": state["effectId"], "beforeRevision": 0, "intentTime": state["intentTime"]},
        "effect": {"kind": "effect", "effectId": state["effectId"], "revision": 1,
                   "contentDigest": request.content_sha256, "effectTime": state["effectTime"], "grantDigest": state["grantDigest"]},
        "incomplete": {"kind": "incomplete", "effectId": state["effectId"], "requestId": request.request_id,
                       "outcome": "not-established-after-interruption"},
        "revoke": {"kind": "revoke", "authorityKey": issuer_key},
    }.get(kind)


def _event_transition(kind: str, phase: str, revoked: bool, sequence: int) -> tuple[str, bool]:
    """Replay native ordering; a signature cannot repair an invalid transition."""
    if (sequence == 1) != (kind == "initialize"):
        refuse("native initialization history differs")
    required = {"intent": "ready", "effect": "pending", "incomplete": "pending"}
    if kind in required and phase != required[kind]:
        refuse("native history transition differs")
    if revoked and kind in {"intent", "effect", "revoke"}:
        refuse("native history transition differs")
    phases = {"initialize": "ready", "intent": "pending", "effect": "completed", "incomplete": "incomplete"}
    return phases.get(kind, phase), revoked or kind == "revoke"


def _events(rows: list[tuple[int, bytes]], state: dict[str, Any], key: str,
            request: ActionRequest, issuer_key: str) -> dict[int, dict[str, Any]]:
    """Require the entire signed history, its exact bodies and terminal phase."""
    head = "0" * 64
    phase, revoked = "ready", False
    prefixes = {}
    for number, (sequence, raw) in enumerate(rows, 1):
        event = _native_envelope(raw, key)
        if set(event) != {"sequence", "previous", "event", "hash"} or type(event["sequence"]) is not int:
            refuse("native event fields differ")
        body = {name: event[name] for name in ("sequence", "previous", "event")}
        if sequence != number or event["sequence"] != number or event["previous"] != head or event["hash"] != digest(DOMAIN + "-event", body):
            refuse("native history continuity differs")
        carried = event["event"]
        if not isinstance(carried, dict) or not isinstance(carried.get("kind"), str):
            refuse("native event body differs")
        kind = carried["kind"]
        expected = _event_body(kind, state, request, issuer_key)
        if expected is None:
            refuse("native history event is unsupported")
        counter = {"intent": "beforeRevision", "effect": "revision"}.get(kind)
        if carried != expected or (counter is not None and type(carried[counter]) is not int):
            refuse("native event body differs")
        phase, revoked = _event_transition(kind, phase, revoked, number)
        head = event["hash"]
        prefixes[number] = {"eventHead": head, "phase": phase, "revoked": revoked}
    if len(rows) != state["eventCount"] or head != state["eventHead"]:
        refuse("native history is incomplete")
    if phase != state["phase"] or revoked != state["revoked"]:
        refuse("native history terminal differs")
    return prefixes


def _ticket(rows: list[tuple[Any, ...]], state: dict[str, Any], request: ActionRequest) -> dict[str, Any]:
    """Compare the actual native row with signed state and exact approved bytes."""
    import hashlib
    if state["revision"] == 0:
        if rows:
            refuse("unrecorded native effect")
        return {"effectObserved": False, "effectStatus": "none-in-bounded-native-table", "nativeRevision": 0}
    if len(rows) != 1:
        refuse("native effect population differs")
    tenant, ticket, content, revision, effect = rows[0]
    expected = (request.tenant_id, request.target_path.removeprefix("/work/tickets/"), 1, state["effectId"])
    if (tenant, ticket, revision, effect) != expected or type(revision) is not int:
        refuse("native effect identity differs")
    if not isinstance(content, bytes) or hashlib.sha256(content).hexdigest() != request.content_sha256 or state["contentDigest"] != request.content_sha256:
        refuse("native effect bytes differ")
    return {"effectObserved": True, "effectStatus": "observed-bounded-native-row", "nativeRevision": 1,
            "effectId": effect, "contentSha256": request.content_sha256}


def read_native(path: Path, payload: dict[str, Any], pins: dict[str, str]) -> tuple[dict[str, Any], dict[str, Any], dict[int, dict[str, Any]]]:
    """Read durable native state using a read-only SQLite transaction.

    A database row and its native history are read separately from the agent's
    return. The same author controls the keys, database and producer; this
    check provides bounded peer evidence, never independent effect custody.
    """
    request = ActionRequest(**payload["request"])
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
        db.execute("BEGIN")
        records = db.execute("SELECT record FROM state WHERE singleton=1").fetchall()
        if len(records) != 1:
            refuse("native signed state is missing")
        state = _native_envelope(records[0][0], pins["serviceKey"])
        _state_schema(state)
        fields = {"request": payload["request"], "policy": payload["grantPolicy"], "serviceKey": pins["serviceKey"]}
        if state["configuration"] != digest(DOMAIN + "-configuration", fields):
            refuse("native configuration differs from selected request")
        prefixes = _events(db.execute("SELECT sequence,record FROM events ORDER BY sequence").fetchall(), state,
                           pins["serviceKey"], request, pins["issuerKey"])
        result = _ticket(db.execute("SELECT tenant,ticket,content,revision,effect FROM tickets").fetchall(), state, request)
    return {**result, "nativePhase": state["phase"], "nativeRevoked": state["revoked"]}, state, prefixes


def _authorization(payload: dict[str, Any], pins: dict[str, str]) -> tuple[str, str | None]:
    """Recompute action-time authority without implying the action completed."""
    request = ActionRequest(**payload["request"])
    try:
        if payload["decisionAt"] >= payload["requestDeadline"]:
            refuse("original decision window has closed")
        check_authority(payload["authorityEvidence"], pins["authorityKey"], request.principal_id, payload["decisionAt"])
        verify_grant(payload["grant"], request, GrantPolicy(**payload["grantPolicy"]), now=reference_time(payload["decisionAt"]))
    except VerificationError as error:
        return "not-admitted", str(error)
    return "valid-for-approved-request-at-reference-time", None


def _delegation(payload: dict[str, Any]) -> tuple[str, str | None]:
    """Recompute the delegation chain; an amplified hop is never admitted."""
    request = ActionRequest(**payload["request"])
    try:
        check_delegation(payload["delegationHops"], payload["delegationRoot"], request.principal_id,
                         request.tool_id, request.target_path)
    except VerificationError as error:
        return "not-admitted", str(error)
    return "narrowing-chain-covers-action", None


def _completion(payload: dict[str, Any], pins: dict[str, str], native_state: dict[str, Any]) -> tuple[str, str | None]:
    """Require native completion proof while leaving observed effects intact."""
    if payload["readback"]["revision"] == 0:
        return "no-completed-effect-proof", None
    try:
        retained = checked_native_receipt(payload["readback"]["receipt"], pins["serviceKey"])
        _state_schema(retained, receipt=True)
    except VerificationError as error:
        return "incomplete-or-no-longer-admissible", str(error)
    if {field: retained[field] for field in STATE_FIELDS} != native_state:
        refuse("retained completion differs from observed native state")
    try:
        verify_ticket_result(payload["readback"]["receipt"], payload["readback"],
                             ActionRequest(**payload["request"]), GrantPolicy(**payload["grantPolicy"]),
                             pins["serviceKey"], payload["grant"], now=reference_time(payload["decisionAt"]))
    except VerificationError as error:
        return "incomplete-or-no-longer-admissible", str(error)
    return "verified-bounded-native-completion", None


def _completed_attempt(attempt: dict[str, Any], payload: dict[str, Any], service_key: str,
                       native_state: dict[str, Any], prefixes: dict[int, dict[str, Any]]) -> None:
    """Authenticate a completed native return under the selected service key."""
    try:
        receipt = checked_native_receipt(attempt["receipt"], service_key)
        _state_schema(receipt, receipt=True)
        request = ActionRequest(**payload["request"])
        authorized = verify_grant(payload["grant"], request, GrantPolicy(**payload["grantPolicy"]),
                                  now=reference_time(payload["decisionAt"]))
    except VerificationError:
        refuse("retained completed dispatch proof differs")
    configuration = digest(DOMAIN + "-configuration", {"request": payload["request"], "policy": payload["grantPolicy"], "serviceKey": service_key})
    effect = digest(DOMAIN + "-effect", {"configuration": configuration, "requestId": request.request_id,
                                       "grantDigest": authorized.grant_digest})
    expected = {"request": payload["request"], "authorityKey": payload["grantPolicy"]["issuer_key"],
                "configuration": configuration, "grantDigest": authorized.grant_digest, "effectId": effect,
                "phase": "completed", "revoked": False, "revision": 1, "witnessScope": "PEER",
                "coverage": "one-native-ticket-row-and-service-events"}
    if any(receipt[field] != value for field, value in expected.items()):
        refuse("retained completed dispatch proof differs")
    immutable = STATE_FIELDS - {"eventCount", "eventHead", "revoked"}
    prefix = {field: receipt[field] for field in ("eventHead", "phase", "revoked")}
    if (any(receipt[field] != native_state[field] for field in immutable)
            or prefixes.get(receipt["eventCount"]) != prefix):
        refuse("retained completed dispatch differs from observed native history")


def _attempts(payload: dict[str, Any]) -> None:
    """Refuse a terminal assertion that contradicts its retained dispatch return."""
    attempts = payload["attempts"]
    if not isinstance(attempts, list) or not 1 <= len(attempts) <= 2:
        refuse("retained attempts are incomplete")
    for attempt in attempts:
        if not isinstance(attempt, dict) or set(attempt) != {"decision", "returnStatus", "reason", "receipt"}:
            refuse("retained attempt fields differ")
        if not isinstance(attempt["decision"], str) or not isinstance(attempt["returnStatus"], str):
            refuse("retained dispatch outcome differs")
        outcome = (attempt["decision"], attempt["returnStatus"])
        if outcome not in {("allow", "completed"), ("allow", "failed"), ("deny", "failed")}:
            refuse("retained dispatch outcome differs")
        completed = outcome == ("allow", "completed")
        if completed and (attempt["reason"] is not None or not isinstance(attempt["receipt"], dict)):
            refuse("retained dispatch outcome differs")
        if not completed and (not isinstance(attempt["reason"], str) or attempt["receipt"] is not None):
            refuse("retained dispatch outcome differs")
    if payload["taskTerminal"] != attempts[-1]["returnStatus"]:
        refuse("task terminal contradicts retained dispatch return")


def _contract(payload: dict[str, Any], pins: dict[str, str]) -> None:
    """Require the versioned contract id and a consistent evidence age.

    The id is checked before any other field, so a trace written against a
    different or unnamed contract is never interpreted under this one.
    ``evidenceAgeSeconds`` must equal decision time minus the observation
    time inside the signed authority evidence, and the deployed freshness
    limit the producer applied must equal the limit this consumer selected.
    """
    if "contractId" not in payload:
        refuse("trace contract id is missing")
    if payload["contractId"] != CONTRACT_ID:
        refuse("trace contract id differs")
    observed = checked_record(payload.get("authorityEvidence"), pins["authorityKey"], AUTHORITY_DOMAIN)
    age = payload.get("evidenceAgeSeconds")
    if type(age) is not int or type(observed.get("observedAt")) is not int or type(payload.get("decisionAt")) is not int \
            or age != payload["decisionAt"] - observed["observedAt"]:
        refuse("evidence age differs from decision time")
    if payload.get("freshnessLimitSeconds") != MAX_AGE_SECONDS or type(payload.get("freshnessLimitSeconds")) is not int:
        refuse("freshness limit differs from consumer selection")


def _record_schema(payload: dict[str, Any]) -> None:
    """Check the finite profile's exact fields before interpreting its claims."""
    fields = {"contractId", "evidenceAgeSeconds", "freshnessLimitSeconds", "delegationRoot", "delegationHops", "profile", "caseId", "request", "grantPolicy", "grant", "authorityEvidence", "decisionAt",
              "requestDeadline", "humanReachable", "priorFallback", "attempts", "faultInjection",
              "dispatchContentSha256", "taskTerminal", "readback", "coverage", "custody", "witnessScope"}
    if set(payload) != fields:
        refuse("profile record fields differ")
    if payload["caseId"] not in CASE_IDS or type(payload["decisionAt"]) is not int or type(payload["requestDeadline"]) is not int:
        refuse("profile identity or clock differs")
    if type(payload["humanReachable"]) is not bool or type(payload["priorFallback"]) is not bool:
        refuse("profile availability fields differ")
    if payload["priorFallback"] != (payload["grant"] is not None):
        refuse("profile fallback contradicts retained grant")
    if payload["coverage"] != "one-local-native-ticket-and-service-events":
        refuse("profile coverage exceeds selected boundary")
    _attempts(payload)


def read_case(path: Path, pins: dict[str, str]) -> dict[str, Any]:
    """Return authority, actual effect, terminal status and publication separately.

    Parameters
    ----------
    path : pathlib.Path
        One case directory with signed ``record.json`` and ``native.sqlite``.
    pins : dict[str, str]
        Caller-selected profile, record, authority, issuer and service keys.
        Candidate records cannot select or replace these trust anchors.

    Returns
    -------
    dict[str, Any]
        Separate output axes. A committed effect remains observed after a
        failed task, lost response, later revocation, or incomplete retained
        proof. ``publicationReady`` additionally requires a completed task,
        currently admissible completion and no native revocation.

    Raises
    ------
    VerificationError
        If signed evidence, native history, selected identities or bytes fail.
        Incomplete native completion proof is retained as its own outcome.
    """
    candidate = json.loads((path / "record.json").read_text(encoding="ascii"))
    payload = checked_record(candidate, pins["recordKey"], RECORD_DOMAIN)
    _contract(payload, pins)
    _record_schema(payload)
    if pins["profile"] != PROFILE or payload["profile"] != PROFILE or payload["caseId"] != path.name:
        refuse("profile or case identity differs")
    if payload["grantPolicy"]["issuer_key"] != pins["issuerKey"]:
        refuse("grant issuer differs from consumer pin")
    if payload["grantPolicy"]["max_validity_seconds"] != pins["maxValiditySeconds"]:
        refuse("grant duration policy differs from consumer pin")
    if payload["taskTerminal"] not in {"completed", "failed"}:
        refuse("task terminal is unsupported")
    if payload["witnessScope"] != "PEER" or payload["custody"] != "author-operated-local":
        refuse("record custody or scope exceeds reference profile")
    native, native_state, prefixes = read_native(path / "native.sqlite", payload, pins)
    authority, authority_reason = _authorization(payload, pins)
    delegation, delegation_reason = _delegation(payload)
    proof, proof_reason = _completion(payload, pins, native_state)
    for attempt in payload["attempts"]:
        if attempt["returnStatus"] == "completed":
            _completed_attempt(attempt, payload, pins["serviceKey"], native_state, prefixes)
    publication = (native["effectObserved"] and payload["taskTerminal"] == "completed"
                   and proof == "verified-bounded-native-completion" and authority == "valid-for-approved-request-at-reference-time"
                   and delegation == "narrowing-chain-covers-action"
                   and not native["nativeRevoked"])
    return {"caseId": payload["caseId"], **native, "authorityStatus": authority, "authorityReason": authority_reason,
            "delegationStatus": delegation, "delegationReason": delegation_reason,
            "evidenceAgeSeconds": payload["evidenceAgeSeconds"],
            "freshnessLimitSeconds": payload["freshnessLimitSeconds"], "contractId": payload["contractId"],
            "taskTerminal": payload["taskTerminal"], "nativeCompletionProof": proof, "proofReason": proof_reason,
            "publicationReady": publication, "attemptCount": len(payload["attempts"]),
            "dispatchDecisions": [a["decision"] for a in payload["attempts"]], "witnessScope": "PEER",
            "custody": "author-operated-local", "coverage": payload["coverage"]}


def read_run(root: Path, pins: dict[str, str]) -> dict[str, Any]:
    """Read all producer-declared cases, retaining each comparison row."""
    producer = json.loads((root / "producer-report.json").read_text(encoding="ascii"))
    declared = [row["caseId"] for row in producer["cases"]]
    if declared != list(CASE_IDS) or producer["caseCount"] != len(CASE_IDS):
        refuse("declared case coverage differs from selected profile")
    rows = [read_case(root / case_id, pins) for case_id in CASE_IDS]
    return {"contractId": CONTRACT_ID, "profile": PROFILE, "caseCount": len(rows), "results": rows,
            "independentCustody": False, "outsideImplementationRerun": False}


def main() -> None:
    """Run the installed reader with an explicitly selected pin file."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--pins", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = read_run(args.run, json.loads(args.pins.read_text(encoding="ascii")))
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="ascii")
    print(json.dumps({"profile": PROFILE, "caseCount": result["caseCount"]}))


if __name__ == "__main__":
    main()
