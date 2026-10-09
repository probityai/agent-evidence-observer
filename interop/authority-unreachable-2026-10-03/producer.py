"""Produce controlled authority cases with actual durable local ticket effects."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from dataclasses import asdict
from pathlib import Path
from typing import Any

from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant
from probity_observer.crypto import SigningKey, VerificationError, canonical
from probity_observer.ticket_service import TicketStore

from authority_profile import AUTHORITY_DOMAIN, CASE_IDS, CONTRACT_ID, MAX_AGE_SECONDS, PROFILE, RECORD_DOMAIN, RESIDUAL_RISKS, content_bytes, dispatch, reference_time, sign_record

NATIVE_REVISION = "9db0558cf8cc8112ea31b601fa7c7d3c2f38c907"
START = 1791028800
ROOT_GRANTOR = "grantor-1"


def delegation_hops(case_id: str) -> list[dict[str, Any]]:
    """Return the two-hop chain; one case widens scope at the second hop."""
    target = "/work/tickets/publication-1"
    first = {"delegator": ROOT_GRANTOR, "delegate": "orchestrator-1", "actions": ["ticket-update"], "targets": [target]}
    second = {"delegator": "orchestrator-1", "delegate": "approver-1", "actions": ["ticket-update"], "targets": [target]}
    if case_id == "delegation-hop-amplified":
        second = {**second, "actions": ["ticket-update", "ticket-delete"], "targets": [target, "/work/tickets/publication-2"]}
    return [first, second]


def write_json(path: Path, value: Any) -> None:
    """Persist an ASCII JSON record; no private signing keys are serialized."""
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii")


def _action_bytes(case_id: str) -> bytes:
    """Select a controlled descriptor mutation from the immutable baseline."""
    text = "changed" if case_id == "platform-content-mutated" else "approved text"
    media = b"replaced media" if case_id == "media-bytes-mutated" else b"approved media"
    catalogue = b"catalogue-v2" if case_id == "catalogue-mutated" else b"catalogue-v1"
    destination = "destination-2" if case_id == "destination-mutated" else "destination-1"
    return content_bytes(text, media, destination, catalogue)


def _fault_hook(case_id: str, store: TicketStore, fault_log: list[str]):
    """Return a host-controlled native fault hook for one explicit case."""
    points = {"crash-after-intent": "after-intent", "crash-inside-effect-transaction": "inside-effect-transaction",
              "effect-committed-response-lost": "after-effect"}

    def hook(point: str) -> None:
        if case_id == "revoked-between-intent-and-effect" and point == "after-intent":
            fault_log.append("host-revocation-after-intent")
            store.revoke()
        if points.get(case_id) == point:
            fault_log.append(point)
            raise RuntimeError("controlled native interruption: " + point)

    return hook


def _attempt(store: TicketStore, request: ActionRequest, grant: dict[str, Any] | None,
             authority: dict[str, Any], authority_key: str, content: bytes, at: int,
             hops: list[dict[str, Any]]) -> dict[str, Any]:
    """Retain a native return or failure without inferring effect absence."""
    try:
        receipt = dispatch(store, request, grant, content, authority, authority_key, at=at,
                           request_deadline=START + 120, hops=hops, root=ROOT_GRANTOR)
        return {"decision": "allow", "returnStatus": "completed", "reason": None, "receipt": receipt}
    except VerificationError as error:
        return {"decision": "deny", "returnStatus": "failed", "reason": str(error), "receipt": None}
    except RuntimeError as error:
        return {"decision": "allow", "returnStatus": "failed", "reason": str(error), "receipt": None}


def _case(root: Path, case_id: str, keys: dict[str, SigningKey]) -> dict[str, Any]:
    """Run one native case and retain its approval, attempts and final read-back."""
    path = root / case_id
    path.mkdir()
    approved = content_bytes("approved text", b"approved media", "destination-1", b"catalogue-v1")
    request = ActionRequest(case_id, "attempt-1", "request-1", "tenant-1", "approver-1",
                            "ticket-update", "/work/tickets/publication-1", hashlib.sha256(approved).hexdigest())
    policy = GrantPolicy(keys["issuer"].public_hex, max_validity_seconds=300)
    expiry = START + 5 if case_id == "fallback-expired" else START + 120
    grant = issue_grant(request, keys["issuer"], issued_at=reference_time(START), expires_at=reference_time(expiry))
    at = START + 121 if case_id == "late-approval-for-expired-request" else START + 10
    if case_id == "late-approval-for-expired-request":
        grant = issue_grant(request, keys["issuer"], issued_at=reference_time(at), expires_at=reference_time(at + 120))
    status = "revoked" if case_id == "approver-revoked-at-dispatch" else "active"
    age = 181 if case_id == "authority-evidence-stale" else 0
    authority = sign_record({"principalId": request.principal_id, "observedAt": at - age,
                             "status": status, "sourceRevision": "controlled-status-snapshot-1"}, keys["authority"], AUTHORITY_DOMAIN)
    store = TicketStore(path / "native.sqlite", request, policy, keys["service"], clock=lambda: reference_time(at))
    store.initialize()
    faults: list[str] = []
    store.crash_hook = _fault_hook(case_id, store, faults)
    delegated = None if case_id == "unreachable-no-fallback" else grant
    hops = delegation_hops(case_id)
    attempts = [_attempt(store, request, delegated, authority, keys["authority"].public_hex, _action_bytes(case_id), at, hops)]
    store.crash_hook = None
    if case_id == "same-request-retry":
        attempts.append(_attempt(store, request, grant, authority, keys["authority"].public_hex, approved, at, hops))
    if case_id in {"crash-after-intent", "crash-inside-effect-transaction", "revoked-between-intent-and-effect"}:
        store.recover()
        attempts.append(_attempt(store, request, grant, authority, keys["authority"].public_hex, approved, at, hops))
    if case_id == "effect-then-authority-revoked":
        store.revoke()
        attempts.append(_attempt(store, request, grant, authority, keys["authority"].public_hex, approved, at, hops))
    readback = store.readback()
    payload = {"contractId": CONTRACT_ID, "profile": PROFILE, "caseId": case_id, "request": asdict(request), "grantPolicy": asdict(policy),
               "grant": delegated, "authorityEvidence": authority, "decisionAt": at,
               "evidenceAgeSeconds": age, "freshnessLimitSeconds": MAX_AGE_SECONDS, "delegationRoot": ROOT_GRANTOR, "delegationHops": hops,
               "requestDeadline": START + 120,
               "humanReachable": case_id == "approved-human-reachable", "priorFallback": delegated is not None,
               "attempts": attempts, "faultInjection": faults,
               "dispatchContentSha256": hashlib.sha256(_action_bytes(case_id)).hexdigest(),
               "taskTerminal": "completed" if attempts[-1]["returnStatus"] == "completed" else "failed",
               "readback": readback, "coverage": "one-local-native-ticket-and-service-events",
               "custody": "author-operated-local", "witnessScope": "PEER",
               "residualRisks": list(RESIDUAL_RISKS[case_id])}
    if case_id == "incomplete-proof-after-effect":
        # The record remains signed, but the bounded native proof is intentionally incomplete.
        payload["readback"]["receipt"].pop("signature")
    write_json(path / "record.json", sign_record(payload, keys["record"], RECORD_DOMAIN))
    return {"caseId": case_id, "nativeRevision": readback["revision"], "taskTerminal": payload["taskTerminal"]}


def produce(root: Path, source_revision: str) -> dict[str, Any]:
    """Produce all declared cases and a separate local consumer pin file.

    Parameters
    ----------
    root : pathlib.Path
        New output directory. Reusing an existing directory is refused so that
        old native state cannot silently replace a new run.
    source_revision : str
        Immutable commit when run in CI, or ``local-uncommitted`` for a clearly
        labeled development preflight. Runner file hashes are retained too.

    Returns
    -------
    dict[str, Any]
        Actual executed case count and native revision counts. These are
        deterministic local controls, not production rates or vendor scores.

    Notes
    -----
    Separate keys and environments remain controlled by the same author. The
    pin file is generated for this development run; an outside consumer must
    select its own pins and must not take trust keys from candidate evidence.
    """
    root.mkdir(parents=True)
    keys = {name: SigningKey.generate() for name in ("issuer", "authority", "service", "record")}
    write_json(root / "consumer-pins.json", {"profile": PROFILE, "maxValiditySeconds": 300,
                                             **{name + "Key": key.public_hex for name, key in keys.items()}})
    rows = [_case(root, case_id, keys) for case_id in CASE_IDS]
    metadata = {"profile": PROFILE, "sourceRevision": source_revision, "nativeObserverBaseline": NATIVE_REVISION,
                "python": platform.python_version(), "caseCount": len(rows), "cases": rows,
                "runnerSha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob("*.py")},
                "independentCustody": False, "outsideImplementationRerun": False}
    write_json(root / "producer-report.json", metadata)
    return metadata


def main() -> None:
    """Create the reference run selected by command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    result = produce(args.output, args.source_revision)
    print(json.dumps({"profile": PROFILE, "caseCount": result["caseCount"]}))


if __name__ == "__main__":
    main()
