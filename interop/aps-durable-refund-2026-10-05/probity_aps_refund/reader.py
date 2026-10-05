"""Read selected public captures with installed native SDK and public keys only."""
from __future__ import annotations

import argparse
import hashlib
import sqlite3
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from probity_observer.authorization import ActionRequest, GrantPolicy, verify_grant
from probity_observer.crypto import VerificationError, canonical, digest, strict_loads, verify_signature
from probity_observer.ticket_service import DOMAIN, READBACK_FIELDS, VerifiedTicketCapture, verify_ticket_capture

from .service import refund_decision_digest, verify_aps, verify_refund_result


@dataclass(frozen=True)
class _ExpectedCounts:
    """JSON integer expectations, distinct from boolean or floating representations."""
    admissions: int
    effects: int

    @classmethod
    def from_json(cls, value: Any) -> _ExpectedCounts:
        """Require the exact measured population fields and JSON integer types."""
        if not isinstance(value, dict) or set(value) != {"logicalAdmissions", "localEffects"}:
            raise VerificationError("public expected count fields differ")
        if any(type(count) is not int for count in value.values()):
            raise VerificationError("public expected counts must be JSON integers")
        return cls(value["logicalAdmissions"], value["localEffects"])


@dataclass(frozen=True)
class _SelectedPolicy:
    """Externally selected inputs after closed wrapper and exact capture-byte checks."""
    case: Path
    document: dict[str, Any]
    expected: _ExpectedCounts
    request: ActionRequest
    grant_policy: GrantPolicy
    now: datetime
    node: Path
    verifier: Path


@dataclass(frozen=True)
class _SignedReadback:
    """Authenticated receipt and the closed, typed public readback wrapper."""
    receipt: dict[str, Any]
    readback: dict[str, Any]
    state: dict[str, Any]


@dataclass(frozen=True)
class _NativeBinding:
    """Authenticated native approval joined to the host intent and its signed readback."""
    native: dict[str, Any]
    receipt: dict[str, Any]
    readback: dict[str, Any]
    state: dict[str, Any]
    grant_digest: str
    effect_id: str
    decision_digest: str


@dataclass(frozen=True)
class _LocalOutcome:
    """Measured admissions and effects after signed history and completion checks."""
    admissions: int
    effects: int
    description: str


def _signed(raw: bytes, key: str) -> dict[str, Any]:
    """Authenticate selected public state without accepting a candidate's own key."""
    record = strict_loads(raw)
    if not isinstance(record, dict) or set(record) != {"payload", "keyid", "signature"} or record["keyid"] != key or not isinstance(record["payload"], dict):
        raise VerificationError("public native state key or fields differ")
    verify_signature(key, DOMAIN, record["payload"], record["signature"])
    return record["payload"]


def _select_policy(case: Path, policy_sha256: str, node: Path, verifier: Path) -> _SelectedPolicy:
    """Select the closed host wrapper and public bytes before invoking either verifier."""
    raw = (case / "host-policy.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != policy_sha256:
        raise VerificationError("public host policy differs from consumer selection")
    policy = strict_loads(raw)
    required = {"request", "grantPolicy", "tenantId", "evidence", "verifierSha256", "sdkSha256", "now",
                "servicePublicKey", "grant", "expected", "files", "alternateApproval"}
    if not isinstance(policy, dict) or set(policy) != required:
        raise VerificationError("public policy member population differs")
    files = policy["files"]
    expected = _ExpectedCounts.from_json(policy["expected"])
    if not isinstance(files, dict) or set(files) != {"receipt.json", "readback.json", "attempts.json", "service.sqlite"}:
        raise VerificationError("public policy member population differs")
    for filename, pin in files.items():
        if hashlib.sha256((case / filename).read_bytes()).hexdigest() != pin:
            raise VerificationError("selected public capture bytes differ")
    try:
        return _SelectedPolicy(case, policy, expected, ActionRequest(**policy["request"]), GrantPolicy(**policy["grantPolicy"]),
            datetime.fromisoformat(policy["now"]), node, verifier)
    except (TypeError, ValueError) as error:
        raise VerificationError("public host request, grant policy or clock is malformed") from error


def _read_signed_readback(selected: _SelectedPolicy) -> _SignedReadback:
    """Authenticate the selected receipt and require the exact public wrapper types."""
    receipt = strict_loads((selected.case / "receipt.json").read_bytes())
    readback = strict_loads((selected.case / "readback.json").read_bytes())
    state = _signed(canonical(receipt), selected.document["servicePublicKey"])
    if not isinstance(readback, dict) or set(readback) != READBACK_FIELDS or type(readback["revision"]) is not int:
        raise VerificationError("public native readback fields or revision type differ")
    return _SignedReadback(receipt, readback, state)


def _bind_native(selected: _SelectedPolicy) -> _NativeBinding:
    """Verify actual SDK bytes, host configuration and intent-time grant authority."""
    policy, request, grant_policy = selected.document, selected.request, selected.grant_policy
    native = verify_aps(policy["evidence"], node=selected.node, verifier=selected.verifier,
                        verifier_sha256=policy["verifierSha256"], sdk_sha256=policy["sdkSha256"], now=selected.now)
    public = _read_signed_readback(selected)
    receipt, readback, state = public.receipt, public.readback, public.state
    commitment = refund_decision_digest(native, request, tenant_id=policy["tenantId"],
                                        verifier_sha256=policy["verifierSha256"], sdk_sha256=policy["sdkSha256"])
    configuration = digest(DOMAIN + "-configuration", {"request": asdict(request),
        "policy": asdict(grant_policy), "serviceKey": policy["servicePublicKey"], "decisionDigest": commitment})
    if state["format"] != DOMAIN or state["configuration"] != configuration or readback["tenantId"] != request.tenant_id or readback["ticketId"] != request.target_path.removeprefix("/work/tickets/"):
        raise VerificationError("public native configuration or readback identity differs")
    authorized = verify_grant(policy["grant"], request, grant_policy,
                              now=datetime.fromisoformat(state["intentTime"]))
    effect_id = digest(DOMAIN + "-effect", {"configuration": configuration,
        "requestId": request.request_id, "grantDigest": authorized.grant_digest})
    if state["grantDigest"] != authorized.grant_digest or state["effectId"] != effect_id or readback["effectId"] != effect_id:
        raise VerificationError("public native intent authority or effect identity differs")
    return _NativeBinding(native, receipt, readback, state, authorized.grant_digest, effect_id, commitment)


def _read_retained(selected: _SelectedPolicy, binding: _NativeBinding) -> VerifiedTicketCapture:
    """Apply the shared public validator to actual selected read-only SQLite populations."""
    with closing(sqlite3.connect((selected.case / "service.sqlite").resolve().as_uri() + "?mode=ro", uri=True)) as db:
        row = db.execute("SELECT record FROM state WHERE singleton=1").fetchone()
        if row is None:
            raise VerificationError("ticket state is missing")
        events = db.execute("SELECT sequence,record FROM events ORDER BY sequence").fetchall()
        rows = db.execute("SELECT tenant,ticket,content,revision,effect FROM tickets").fetchall()
    retained = verify_ticket_capture(row[0], events, rows, selected.request, selected.grant_policy,
        selected.document["servicePublicKey"], decision_digest=binding.decision_digest, retained_head=binding.receipt)
    expected = {**retained.state, "request": asdict(selected.request), "authorityKey": selected.grant_policy.issuer_key,
                "witnessScope": "PEER", "coverage": "one-native-ticket-row-and-service-events"}
    if canonical(expected) != canonical(binding.state) or canonical(binding.readback["receipt"]) != canonical(binding.receipt):
        raise VerificationError("public native state differs from selected signed readback")
    return retained


def _verify_outcome(selected: _SelectedPolicy, binding: _NativeBinding, retained: VerifiedTicketCapture) -> _LocalOutcome:
    """Measure the SQL effect and require the installed completion verifier for a row."""
    admissions, effects = retained.logical_admissions, retained.local_effects
    policy, request = selected.document, selected.request
    if _ExpectedCounts(admissions, effects) != selected.expected or admissions != 1 or effects not in (0, 1):
        raise VerificationError("public native intent or effect population differs")
    if effects:
        result = verify_refund_result(policy["evidence"], binding.receipt, binding.readback, request, selected.grant_policy,
            policy["servicePublicKey"], policy["grant"], tenant_id=policy["tenantId"], node=selected.node,
            verifier=selected.verifier, verifier_sha256=policy["verifierSha256"], sdk_sha256=policy["sdkSha256"], now=selected.now)
        if retained.content != bytes.fromhex(binding.readback["contentHex"]) or result["effectId"] != binding.effect_id:
            raise VerificationError("public SQLite effect differs from verified readback")
        return _LocalOutcome(admissions, effects, "recorded-local-sqlite-refund-row")
    if binding.state["phase"] != "incomplete" or binding.readback["contentHex"] is not None or binding.readback["revision"] != 0:
        raise VerificationError("absent local effect was upgraded to completion")
    return _LocalOutcome(admissions, effects, "not-established-after-interruption")


def _verify_reissue(selected: _SelectedPolicy, binding: _NativeBinding) -> str:
    """Replay a same-action changed approval against the original frozen completion."""
    policy = selected.document
    alternate = policy["alternateApproval"]
    if alternate is None:
        return "not-exercised"
    if canonical(alternate["policy"]) != canonical(policy["evidence"]["policy"]):
        raise VerificationError("reissued approval changed host authority selection")
    alternate_native = verify_aps(alternate, node=selected.node, verifier=selected.verifier,
        verifier_sha256=policy["verifierSha256"], sdk_sha256=policy["sdkSha256"], now=selected.now)
    if alternate_native["receiptId"] == binding.native["receiptId"] or alternate_native["actionRef"] != binding.native["actionRef"]:
        raise VerificationError("reissued approval does not name the same signed action")
    before = (selected.case / "service.sqlite").read_bytes()
    try:
        verify_refund_result(alternate, binding.receipt, binding.readback, selected.request, selected.grant_policy,
            policy["servicePublicKey"], policy["grant"], tenant_id=policy["tenantId"], node=selected.node,
            verifier=selected.verifier, verifier_sha256=policy["verifierSha256"], sdk_sha256=policy["sdkSha256"], now=selected.now)
    except VerificationError as error:
        if str(error) != "ticket consumer binding differs":
            raise VerificationError("reissue refused outside the frozen configuration boundary") from error
    else:
        raise VerificationError("changed authorization was accepted as the retained completion")
    if (selected.case / "service.sqlite").read_bytes() != before:
        raise VerificationError("public reissue replay changed native state")
    return "same-operation-changed-authorization-refused"


def read(case: Path, policy_sha256: str, *, node: Path, verifier: Path) -> dict[str, Any]:
    """Validate external selection, native authority, retained state, history and effects in order."""
    selected = _select_policy(case, policy_sha256, node, verifier)
    binding = _bind_native(selected)
    retained = _read_retained(selected, binding)
    outcome = _verify_outcome(selected, binding, retained)
    reissue = _verify_reissue(selected, binding)
    return {"case": case.name, "logicalAdmissions": outcome.admissions, "localEffects": outcome.effects,
            "outcome": outcome.description, "approvalReceiptId": binding.native["receiptId"],
            "logicalOperationId": selected.request.request_id, "approvalReissue": reissue,
            "independentCustody": False, "witnessScope": "PEER"}


def main() -> int:
    """Consume one capture under out-of-band policy and installed verifier selections."""
    parser = argparse.ArgumentParser()
    parser.add_argument("case", type=Path)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(canonical(read(args.case, args.policy_sha256, node=args.node, verifier=args.verifier)).decode("ascii"))
    except (VerificationError, ValueError, OSError, sqlite3.Error, KeyError, TypeError) as error:
        parser.exit(2, f"public refund capture refused: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
