"""Keep native signature, business decision, operation and local effect claims distinct."""
from __future__ import annotations

import argparse
import hashlib
from importlib import metadata, resources
import json
from pathlib import Path
import sys
from datetime import datetime, timezone
from typing import Any

from probity_aps_refund.reader import read as read_aps_capture
from probity_aps_refund.service import parse_native_clock, verify_aps
from probity_observer.crypto import VerificationError, strict_loads

MAX_PROPOSAL_BYTES = 64_000
PROFILE = "probity-pic-aps-refund-evaluation-v1"


def selection() -> dict[str, Any]:
    """Load the reader's package-owned source and fixture selection."""
    return json.loads(resources.files(__package__).joinpath("source-selection.json").read_bytes())


def _json(raw: bytes | str) -> Any:
    """Preserve decoded member uniqueness without imposing another native canonicalizer."""
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for name, value in pairs:
            if name in result:
                raise VerificationError("duplicate JSON member")
            result[name] = value
        return result

    def invalid_constant(value: str) -> None:
        raise VerificationError("non-JSON numeric constant: " + value)

    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    except VerificationError:
        raise
    except (ValueError, UnicodeError, RecursionError) as error:
        raise VerificationError("invalid JSON evidence") from error


def _pic_source() -> str:
    """Bind every installed native PIC package file to the actual SDK commit."""
    selected = selection()["PIC"]
    distribution = metadata.distribution("pic-standard")
    if distribution.version != "0.9.0":
        raise VerificationError("installed PIC version differs")
    for name, expected in selected["packageFiles"].items():
        installed = Path(distribution.locate_file("pic_standard/" + name))
        if installed.is_symlink() or not installed.is_file() or hashlib.sha256(installed.read_bytes()).hexdigest() != expected:
            raise VerificationError("installed PIC source differs: " + name)
    return selected["sdkCommit"]


def _refund(value: Any) -> dict[str, Any]:
    """Apply the contributor's closed, EUR minor-unit fixture profile."""
    if not isinstance(value, dict) or set(value) != {"payment_id", "amount_minor", "currency"}:
        raise VerificationError("PIC refund fields differ")
    if not isinstance(value["payment_id"], str) or not value["payment_id"].strip():
        raise VerificationError("PIC payment identity is empty")
    if type(value["amount_minor"]) is not int or not 0 < value["amount_minor"] <= 2**53 - 1:
        raise VerificationError("PIC amount must be a positive safe integer in minor units")
    if value["currency"] != "EUR":
        raise VerificationError("PIC currency differs from the fixture profile")
    return value


def _inline_signature(proposal: dict[str, Any]) -> dict[str, Any]:
    """Limit this reader to inline Ed25519 evidence before native verification."""
    evidence = proposal.get("evidence")
    if not isinstance(evidence, list) or len(evidence) != 1 or not isinstance(evidence[0], dict):
        raise VerificationError("PIC reader needs one inline signature")
    signature = evidence[0]
    if signature.get("type") != "sig" or signature.get("alg") != "ed25519":
        raise VerificationError("PIC reader refuses file, network or other evidence forms")
    payload = signature.get("payload")
    if not isinstance(payload, str):
        raise VerificationError("PIC signature payload must be a string")
    return signature


def _attestation(signature: dict[str, Any]) -> dict[str, Any]:
    """Select the canonical attestation form and a declared expiry."""
    payload = signature["payload"]
    attestation = _json(payload)
    if not isinstance(attestation, dict) or attestation.get("attestation_version") != "PIC-ATT/1.0":
        raise VerificationError("PIC reader needs a canonical attestation")
    if not isinstance(attestation.get("expires_at"), str) or not attestation["expires_at"]:
        raise VerificationError("PIC refund attestation needs expiry")
    return attestation


def _native_pic(proposal: dict[str, Any], keyring_raw: bytes) -> list[str]:
    """Call the native pipeline with the selected local public-key resolver."""

    # These are the genuine native APIs. No signer or integration dispatcher is imported.
    from pic_standard.keyring import StaticKeyRingResolver, TrustedKey, TrustedKeyRing
    from pic_standard.pipeline import PICEvaluateLimits, PipelineOptions, verify_proposal
    from pic_standard.policy import PICPolicy

    key_data = _json(keyring_raw)
    keys = {name: TrustedKey(bytes.fromhex(value)) for name, value in key_data["trusted_keys"].items()}
    resolver = StaticKeyRingResolver(TrustedKeyRing(keys, set(key_data["revoked_keys"])))
    before = datetime.now(timezone.utc).isoformat()
    result = verify_proposal(proposal, options=PipelineOptions(
        tool_name="refund", expected_tool="refund", policy=PICPolicy(), limits=PICEvaluateLimits(),
        verify_evidence=True, strict_trust=True, key_resolver=resolver))
    after = datetime.now(timezone.utc).isoformat()
    if not result.ok or result.evidence_report is None or not result.evidence_report.ok:
        code = result.error.code.value if result.error is not None else "PIC_EVIDENCE_FAILED"
        raise VerificationError("native PIC verification refused: " + code)
    return [before, after]


def _merchant_claim(proposal: dict[str, Any]) -> dict[str, str]:
    """Read exactly the decision and approval references after native binding checks."""
    claims = proposal.get("claims")
    if not isinstance(claims, list) or len(claims) != 1 or not isinstance(claims[0], dict):
        raise VerificationError("PIC refund needs one merchant claim")
    claim = _json(claims[0].get("text", ""))
    if not isinstance(claim, dict) or set(claim) != {"decision_id", "approval_ref"}:
        raise VerificationError("PIC merchant claim fields differ")
    if any(not isinstance(value, str) or not value.strip() for value in claim.values()):
        raise VerificationError("PIC merchant references must be nonempty strings")
    return claim


def read_pic(raw: bytes, keyring_raw: bytes) -> dict[str, Any]:
    """Check the existing inline canonical signature using the selected public test key."""
    if len(raw) > MAX_PROPOSAL_BYTES:
        raise VerificationError("PIC proposal exceeds the reader input budget")
    expected_key = selection()["fixtureFiles"]["fixtures/PIC/keys/pic_keys.example.json"]["SHA256"]
    if hashlib.sha256(keyring_raw).hexdigest() != expected_key:
        raise VerificationError("PIC public key selection differs")
    native_commit = _pic_source()
    proposal = _json(raw)
    if not isinstance(proposal, dict):
        raise VerificationError("PIC proposal must be an object")
    attestation = _attestation(_inline_signature(proposal))
    checked_during = _native_pic(proposal, keyring_raw)
    if proposal.get("impact") != "money":
        raise VerificationError("PIC refund impact differs")
    refund = _refund(proposal["action"]["args"])
    claim = _merchant_claim(proposal)
    return {"nativeSDKCommit": native_commit, "proposalSHA256": hashlib.sha256(raw).hexdigest(),
            "checkedDuringUTC": checked_during, "keyScope": "public RFC8032 fixture key; no merchant authority established",
            "decisionId": claim["decision_id"], "approvalRef": claim["approval_ref"],
            "tool": "refund", "refund": refund, "attestationVersion": "PIC-ATT/1.0",
            "argsDigest": attestation["args_digest"], "claimsDigest": attestation["claims_digest"],
            "intentDigest": attestation.get("intent_digest"), "expiresAt": attestation["expires_at"]}


def _selected_case(fixtures: Path, case_name: str) -> tuple[Path, dict[str, bytes]]:
    """Refuse a replaced retained capture before and after the native readers run."""
    if case_name not in {"restart", "after-intent", "approval-reissue"}:
        raise VerificationError("APS fixture case is outside this finite reader")
    case = fixtures / "APS" / case_name
    prefix = "fixtures/APS/" + case_name + "/"
    pins = {name.removeprefix(prefix): item["SHA256"]
            for name, item in selection()["fixtureFiles"].items() if name.startswith(prefix)}
    contents = {}
    for name, expected in pins.items():
        path = case / name
        if path.is_symlink() or not path.is_file():
            raise VerificationError("APS capture member is not a regular file")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise VerificationError("APS retained fixture bytes differ")
        contents[name] = raw
    return case, contents


def assess(fixtures: Path, case_name: str, *, node: Path, verifier: Path) -> dict[str, Any]:
    """Report verified native evidence and the precise unestablished cross-system joins."""
    pic = read_pic((fixtures / "PIC/fixtures/signed-proposal-example.json").read_bytes(),
                   (fixtures / "PIC/keys/pic_keys.example.json").read_bytes())
    case, original = _selected_case(fixtures, case_name)
    policy = strict_loads(original["host-policy.json"])
    observed = read_aps_capture(case, hashlib.sha256(original["host-policy.json"]).hexdigest(), node=node, verifier=verifier)
    native = verify_aps(policy["evidence"], node=node, verifier=verifier,
        verifier_sha256=policy["verifierSha256"], sdk_sha256=policy["sdkSha256"], now=parse_native_clock(policy["now"]))
    _, final = _selected_case(fixtures, case_name)
    if final != original:
        raise VerificationError("APS capture changed during the read")
    payload = _json(native["payloadCanonical"])
    readback = strict_loads(original["readback.json"])
    approval = _json(policy["evidence"]["approvalRaw"])
    request = policy["request"]
    refund_matches = all(type(payload.get(name)) is type(value) and payload[name] == value for name, value in pic["refund"].items())
    return {"format": PROFILE, "scope": "read-only existing fixture evidence", "PIC": pic,
        "APS": {"sdkVersion": "7.2.1", "retainedEvaluationTime": policy["now"],
                "approvalReceiptId": native["receiptId"], "actionRef": native["actionRef"], "payloadRef": native["payloadRef"],
                "decisionRef": approval["decision_ref"], "refund": payload, "retainedLocalCapture": observed,
                "operationIdentityRule": "host tenant plus signed APS action_ref, including nonce",
                "retainedRequestAttemptId": request["attempt_id"], "localEffectId": readback["effectId"]},
        "comparison": {"refundFieldsMatch": refund_matches,
            "PICApprovalRefMatchesAPSReceiptId": pic["approvalRef"] == native["receiptId"],
            "merchantDecisionCommitmentVerified": False, "merchantDecisionToOperationMappingVerified": False,
            "sharedToolStringBindingVerified": False, "authenticatedConduitHandoffVerified": False,
            "combinedAdmissionEstablished": False},
        "missingInputs": ["native APS decision-evidence preimage containing the PIC decision_id",
            "a PIC approval_ref that names the verified native APS receipt_id",
            "authenticated durable decision_id-to-operation mapping and original evidence binding",
            "explicit shared refund tool binding", "public authenticated Conduit handoff with distinct admission_ref and aps_evidence_ref",
            "Conduit attempt/effect observations and a public reader for their claimed binding"],
        "doesNotAssert": ["merchant legitimacy", "real delegation authority", "current APS admission",
            "remote refund execution", "PIC/APS/Conduit combined success", "independent operation or custody"],
        "witnessScope": "PEER"}


def main() -> int:
    """Exit 3 for the useful incomplete join report, and 2 for invalid evidence."""
    parser = argparse.ArgumentParser(description="Read PIC and retained APS evidence without admitting a refund")
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--case", choices=("restart", "after-intent", "approval-reissue"), default="restart")
    parser.add_argument("--node", required=True, type=Path)
    parser.add_argument("--aps-verifier", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = assess(args.fixtures, args.case, node=args.node, verifier=args.aps_verifier)
    except (VerificationError, OSError, metadata.PackageNotFoundError) as error:
        print("PIC/APS evidence refused: " + str(error), file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    print("Combined refund admission is not established; see comparison and missingInputs.", file=sys.stderr)
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
