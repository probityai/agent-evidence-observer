"""Read signed authority cases and native SQLite effects using consumer pins."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any

from probity_observer.authorization import ActionRequest, GrantPolicy, verify_grant
from probity_observer.crypto import VerificationError, digest, strict_loads
from probity_observer.ticket_service import DOMAIN, _state_schema, verify_ticket_result

from authority_profile import CASE_IDS, PROFILE, RECORD_DOMAIN, check_authority, checked_record, reference_time, refuse


def _native_envelope(raw: bytes, key: str) -> dict[str, Any]:
    """Authenticate native canonical bytes under the pinned service domain."""
    return checked_record(strict_loads(raw), key, DOMAIN)


def _events(rows: list[tuple[int, bytes]], state: dict[str, Any], key: str) -> None:
    """Require the entire signed history and its bound terminal phase."""
    head = "0" * 64
    phase, revoked = "ready", False
    phases = {"initialize": "ready", "intent": "pending", "effect": "completed", "incomplete": "incomplete"}
    for number, (sequence, raw) in enumerate(rows, 1):
        event = _native_envelope(raw, key)
        body = {name: event[name] for name in ("sequence", "previous", "event")}
        if sequence != number or event["sequence"] != number or event["previous"] != head or event["hash"] != digest(DOMAIN + "-event", body):
            refuse("native history continuity differs")
        kind = event["event"]["kind"]
        if kind not in {*phases, "revoke"}:
            refuse("native history event is unsupported")
        revoked = revoked or kind == "revoke"
        phase = phases.get(kind, phase)
        head = event["hash"]
    if len(rows) != state["eventCount"] or head != state["eventHead"]:
        refuse("native history is incomplete")
    if phase != state["phase"] or revoked != state["revoked"]:
        refuse("native history terminal differs")


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


def read_native(path: Path, payload: dict[str, Any], pins: dict[str, str]) -> dict[str, Any]:
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
        _events(db.execute("SELECT sequence,record FROM events ORDER BY sequence").fetchall(), state, pins["serviceKey"])
        result = _ticket(db.execute("SELECT tenant,ticket,content,revision,effect FROM tickets").fetchall(), state, request)
    return {**result, "nativePhase": state["phase"], "nativeRevoked": state["revoked"]}


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


def _completion(payload: dict[str, Any], pins: dict[str, str]) -> tuple[str, str | None]:
    """Require native completion proof while leaving observed effects intact."""
    if payload["readback"]["revision"] == 0:
        return "no-completed-effect-proof", None
    try:
        verify_ticket_result(payload["readback"]["receipt"], payload["readback"],
                             ActionRequest(**payload["request"]), GrantPolicy(**payload["grantPolicy"]),
                             pins["serviceKey"], payload["grant"], now=reference_time(payload["decisionAt"]))
    except VerificationError as error:
        return "incomplete-or-no-longer-admissible", str(error)
    return "verified-bounded-native-completion", None


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
    native = read_native(path / "native.sqlite", payload, pins)
    authority, authority_reason = _authorization(payload, pins)
    proof, proof_reason = _completion(payload, pins)
    publication = (native["effectObserved"] and payload["taskTerminal"] == "completed"
                   and proof == "verified-bounded-native-completion" and authority == "valid-for-approved-request-at-reference-time"
                   and not native["nativeRevoked"])
    return {"caseId": payload["caseId"], **native, "authorityStatus": authority, "authorityReason": authority_reason,
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
    return {"profile": PROFILE, "caseCount": len(rows), "results": rows,
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
