"""Join a native APS approval to one durable local refund-record effect.

This consumer profile uses the unchanged installed APS SDK and TicketStore.
It does not establish delegation authority, merchant legitimacy, PIC integration,
provider execution, independent operation or independent custody.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import subprocess
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from probity_observer.authorization import ActionRequest, GrantPolicy, utc_clock
from probity_observer.crypto import SigningKey, VerificationError, canonical, digest, strict_loads
from probity_observer.ticket_service import MAX_BODY, TicketStore, verify_ticket_result

PROFILE = "probity-aps-refund-record-v0"
OPERATION_DOMAIN = "probity-aps-refund-operation-v0"
REPORT_FIELDS = frozenset({"profile", "receiptId", "actionRef", "payloadRef", "payloadCanonical",
                           "boundaryIdentity", "workerIdentity", "keyId", "publicKey", "issuedAt", "validUntil"})


def sdk_digest(verifier: Path) -> str:
    """Hash installed npm runtime files; refuse missing modules and runtime symlinks."""
    root = verifier.parent / "node_modules"
    if root.is_symlink() or not (root / "agent-passport-system/package.json").is_file():
        raise VerificationError("installed APS SDK is missing")
    try:
        metadata = json.loads((root / "agent-passport-system/package.json").read_bytes())
    except (ValueError, OSError) as error:
        raise VerificationError("installed APS SDK metadata is malformed or unavailable") from error
    if not isinstance(metadata, dict) or metadata.get("name") != "agent-passport-system" or metadata.get("version") != "7.2.1":
        raise VerificationError("installed APS SDK version is unsupported by this profile")
    files = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if relative.parts[0] == ".bin" or relative.as_posix() == ".package-lock.json":
            continue
        if path.is_symlink():
            raise VerificationError("installed npm runtime contains a symlink")
        if path.is_file():
            files[relative.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest(PROFILE + "-installed-npm", files)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject decoded duplicate names before ordinary JSON loses the evidence."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("duplicate refund payload member")
        result[key] = value
    return result


def _payload(raw: str) -> dict[str, Any]:
    """Check the closed local minor-unit profile, preserving valid numeric spellings."""
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_BODY:
        raise VerificationError("refund payload exceeds local input budget")
    try:
        payload = json.loads(raw, object_pairs_hook=_unique)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise VerificationError("refund payload is malformed") from error
    if not isinstance(payload, dict) or set(payload) != {"payment_id", "amount_minor", "currency"}:
        raise VerificationError("refund payload fields differ")
    payment, amount, currency = payload["payment_id"], payload["amount_minor"], payload["currency"]
    if not isinstance(payment, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", payment) is None:
        raise VerificationError("refund payment identity differs")
    if type(amount) not in (int, float) or not 0 < amount <= 2**53 - 1 or not math.isfinite(amount) or int(amount) != amount:
        raise VerificationError("refund amount must be a positive safe integer in minor units")
    if not isinstance(currency, str) or re.fullmatch(r"[A-Z]{3}", currency) is None:
        raise VerificationError("refund currency differs")
    return payload


def verify_aps(evidence: dict[str, Any], *, node: Path, verifier: Path,
               verifier_sha256: str, sdk_sha256: str, now: datetime) -> dict[str, Any]:
    """Run host-selected native SDK bytes after preserving the raw payload boundary."""
    if not isinstance(evidence, dict) or set(evidence) != {"actionRaw", "payloadRaw", "approvalRaw", "policy"}:
        raise VerificationError("APS refund input fields differ")
    payload = _payload(evidence["payloadRaw"])
    if hashlib.sha256(verifier.read_bytes()).hexdigest() != verifier_sha256:
        raise VerificationError("APS verifier differs from host source pin")
    if sdk_digest(verifier) != sdk_sha256:
        raise VerificationError("installed APS SDK differs from host byte selection")
    envelope = {**evidence, "now": now.isoformat(timespec="milliseconds").replace("+00:00", "Z")}
    del envelope["payloadRaw"]
    envelope["payloadChecked"] = payload
    raw = json.dumps(envelope, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(raw) > MAX_BODY:
        raise VerificationError("APS refund envelope exceeds local input budget")
    try:
        run = subprocess.run([str(node), str(verifier)], input=raw, capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VerificationError("native APS verifier is unavailable") from error
    if run.returncode != 0 or run.stderr:
        raise VerificationError("native APS approval verification refused")
    try:
        report = json.loads(run.stdout)
    except (ValueError, UnicodeError) as error:
        raise VerificationError("native APS report is malformed") from error
    if not isinstance(report, dict) or set(report) != REPORT_FIELDS or report["profile"] != PROFILE:
        raise VerificationError("native APS report fields differ")
    canonical(report)
    return report


def _join(report: dict[str, Any], request: ActionRequest) -> None:
    """Bind APS subject, exact canonical payload and approval identity to the local effect."""
    receipt_id = report["receiptId"]
    if not isinstance(receipt_id, str) or re.fullmatch(r"[0-9a-f]{64}", receipt_id) is None:
        raise VerificationError("APS receipt identity differs")
    operation = refund_operation_id(report["actionRef"], request.tenant_id)
    if request.principal_id != report["workerIdentity"] or request.request_id != operation:
        raise VerificationError("APS refund actor or logical operation differs")
    if request.target_path != "/work/tickets/refund-" + operation or request.tool_id != "ticket-update":
        raise VerificationError("APS refund local target differs")
    content = report["payloadCanonical"].encode("ascii")
    strict_loads(content)
    if hashlib.sha256(content).hexdigest() != request.content_sha256:
        raise VerificationError("APS refund local content differs")


def refund_operation_id(action_ref: str, tenant_id: str) -> str:
    """Bind one local operation to exact host tenant and signed APS action, including nonce."""
    if not isinstance(action_ref, str) or re.fullmatch(r"[0-9a-f]{64}", action_ref) is None:
        raise VerificationError("APS operation action reference differs")
    if not isinstance(tenant_id, str) or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", tenant_id) is None:
        raise VerificationError("APS operation tenant identity differs")
    return digest(OPERATION_DOMAIN, {"tenantId": tenant_id, "actionRef": action_ref})


def refund_decision_digest(report: dict[str, Any], request: ActionRequest,
                           *, tenant_id: str, verifier_sha256: str, sdk_sha256: str) -> str:
    """Commit the same exact native/local join for dispatch and public readback."""
    _join(report, request)
    if request.tenant_id != tenant_id:
        raise VerificationError("APS refund tenant differs from host selection")
    return digest(PROFILE, {"nativeReport": report,
                            "verifierSha256": verifier_sha256, "sdkSha256": sdk_sha256, "tenantId": tenant_id})


class ApsRefundStore(TicketStore):
    """Freeze native evidence and reuse durable ticket intent/effect transactions.

    The host owns the directory, tenant, public-key policy, local grant, service
    key, verifier and clock. It selects the store by tenant and exact APS action
    reference; changing roots or deleting host state does not establish replay
    protection. A completed retry returns the same logical operation, with no
    second intent or effect. A pending operation is refused until explicit
    recovery, never automatically replayed. The effect is a local SQLite row.
    """

    def __init__(self, path: Path, request: ActionRequest, policy: GrantPolicy, key: SigningKey,
                 *, evidence: dict[str, Any], tenant_id: str, node: Path, verifier: Path,
                 verifier_sha256: str, sdk_sha256: str, clock: Callable[[], datetime] = utc_clock,
                 crash_hook: Callable[[str], None] | None = None) -> None:
        self._evidence = json.dumps(evidence, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        self._node, self._verifier, self._verifier_pin = node, verifier, verifier_sha256
        self._sdk_pin = sdk_sha256
        report = verify_aps(evidence, node=node, verifier=verifier, verifier_sha256=verifier_sha256, sdk_sha256=sdk_sha256, now=clock())
        operation = refund_operation_id(report["actionRef"], tenant_id)
        if path.name != "refund-" + operation + ".sqlite":
            raise VerificationError("APS refund durable store selection differs")
        self._native_report = canonical(report)
        commitment = refund_decision_digest(report, request, tenant_id=tenant_id,
                                            verifier_sha256=verifier_sha256, sdk_sha256=sdk_sha256)
        super().__init__(path, request, policy, key, clock=clock, crash_hook=crash_hook, decision_digest=commitment)

    def _authorize(self) -> None:
        """Reverify fresh native approval at dispatch and immediately before the local effect."""
        report = verify_aps(json.loads(self._evidence), node=self._node, verifier=self._verifier,
                            verifier_sha256=self._verifier_pin, sdk_sha256=self._sdk_pin, now=self.clock())
        _join(report, self.request)
        if canonical(report) != self._native_report:
            raise VerificationError("APS refund frozen native join differs")

    def dispatch(self, candidate: Any) -> dict[str, Any]:
        """Verify the unchanged SDK approval before fresh admission or a completed retry."""
        self._authorize()
        return super().dispatch(candidate)

    def _fault(self, point: str) -> None:
        """Apply the host fault control, then recheck native expiry before effect."""
        super()._fault(point)
        if point == "after-intent":
            self._authorize()


def verify_refund_result(evidence: dict[str, Any], receipt: dict[str, Any], readback: dict[str, Any],
                         request: ActionRequest, policy: GrantPolicy, service_key: str,
                         grant: dict[str, Any], *, tenant_id: str, node: Path, verifier: Path,
                         verifier_sha256: str, sdk_sha256: str, now: datetime) -> dict[str, Any]:
    """Recompute native binding and signed local readback under separate consumer pins."""
    report = verify_aps(evidence, node=node, verifier=verifier, verifier_sha256=verifier_sha256, sdk_sha256=sdk_sha256, now=now)
    commitment = refund_decision_digest(report, request, tenant_id=tenant_id,
                                        verifier_sha256=verifier_sha256, sdk_sha256=sdk_sha256)
    result = verify_ticket_result(receipt, readback, request, policy, service_key, grant,
                                  now=now, decision_digest=commitment)
    return {**result, "nativeSdkVersion": "7.2.1", "approvalActionBinding": "verified",
            "execution": "recorded-local-sqlite-refund-row", "independentCustody": False,
            "doesNotAssert": ["merchant legitimacy", "delegation authority", "PIC integration",
                               "refund provider execution", "outside adoption", "independent operation"]}
