"""Provision author-controlled keys and host configuration for a local native run."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant
from probity_observer.crypto import SigningKey, canonical

from .service import refund_operation_id, sdk_digest, verify_aps

NOW = datetime(2026, 10, 5, 20, 0, 0, tzinfo=timezone.utc)


def provision(directory: Path, profile: Path, *, verdict: str = "permit",
              constraints: list[str] | None = None, alternatives: bool = False) -> dict[str, Any]:
    """Create synthetic evidence; retain only service secrets in a protected runtime file."""
    directory.mkdir(mode=0o700)
    node = Path(shutil.which("node") or "missing-node").resolve()
    verifier = profile / "verify-aps.mjs"
    verifier_pin = hashlib.sha256(verifier.read_bytes()).hexdigest()
    sdk_pin = sdk_digest(verifier)
    options = {"issuedAt": (NOW - timedelta(seconds=1)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
               "validUntil": (NOW + timedelta(seconds=60)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
               "verdict": verdict, "constraints": constraints or [], "alternatives": alternatives,
               "reissuedValidUntil": (NOW + timedelta(seconds=90)).isoformat(timespec="milliseconds").replace("+00:00", "Z")}
    issued = subprocess.run([str(node), str(profile / "fixture.mjs")], input=canonical(options),
                            capture_output=True, timeout=10, check=True)
    fixtures = json.loads(issued.stdout)
    evidence = fixtures["first"] if alternatives else fixtures
    # A refused native verdict still has a real SDK-signed fixture for negative controls.
    approval = json.loads(evidence["approvalRaw"])
    operation = refund_operation_id(approval["action_ref"], "tenant-refund")
    content = canonical(evidence["policy"]["expectedPayload"])
    request = ActionRequest("refund-" + operation, "local-refund-record", operation,
                            "tenant-refund", evidence["policy"]["workerIdentity"], "ticket-update",
                            "/work/tickets/refund-" + operation, hashlib.sha256(content).hexdigest())
    issuer, service = SigningKey.generate(), SigningKey.generate()
    policy = GrantPolicy(issuer.public_hex)
    grant = issue_grant(request, issuer, issued_at=NOW - timedelta(seconds=2), expires_at=NOW + timedelta(seconds=120))
    runtime = {"storePath": str(directory / ("refund-" + operation + ".sqlite")), "request": asdict(request),
               "grantPolicy": asdict(policy), "tenantId": request.tenant_id, "evidence": evidence,
               "node": str(node), "verifier": str(verifier), "verifierSha256": verifier_pin, "sdkSha256": sdk_pin,
               "now": NOW.isoformat().replace("+00:00", "Z"), "servicePublicKey": service.public_hex,
               "servicePrivateKey": service.private.private_bytes(serialization.Encoding.Raw,
                   serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex(),
               "issuerPrivateKey": issuer.private.private_bytes(serialization.Encoding.Raw,
                   serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex(),
               "alternatives": {name: value for name, value in fixtures.items() if name != "first"} if alternatives else {},
               "candidate": {"request": asdict(request), "grant": grant, "contentHex": content.hex()}}
    runtime_path = directory / "runtime.json"
    with runtime_path.open("xb") as stream:
        runtime_path.chmod(0o600)
        stream.write(canonical(runtime))
    if verdict == "permit" and not constraints:
        verify_aps(evidence, node=node, verifier=verifier, verifier_sha256=verifier_pin, sdk_sha256=sdk_pin, now=NOW)
    return runtime


def select_action(runtime: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    """Issue a new genuine local grant for a host-selected synthetic action control."""
    report = verify_aps(evidence, node=Path(runtime["node"]), verifier=Path(runtime["verifier"]),
                        verifier_sha256=runtime["verifierSha256"], sdk_sha256=runtime["sdkSha256"], now=NOW)
    operation = refund_operation_id(report["actionRef"], runtime["tenantId"])
    content = report["payloadCanonical"].encode("ascii")
    request = ActionRequest("refund-" + operation, "local-refund-record", operation,
                            runtime["tenantId"], report["workerIdentity"], "ticket-update",
                            "/work/tickets/refund-" + operation, hashlib.sha256(content).hexdigest())
    issuer = SigningKey(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(runtime["issuerPrivateKey"])))
    grant = issue_grant(request, issuer, issued_at=NOW - timedelta(seconds=2), expires_at=NOW + timedelta(seconds=120))
    return {**runtime, "evidence": evidence, "request": asdict(request),
            "storePath": str(Path(runtime["storePath"]).with_name("refund-" + operation + ".sqlite")),
            "candidate": {"request": asdict(request), "grant": grant, "contentHex": content.hex()}}
