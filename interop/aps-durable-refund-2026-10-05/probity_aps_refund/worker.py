"""Host-only process worker; private runtime configuration is never a public capture."""
from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from probity_observer.authorization import ActionRequest, GrantPolicy
from probity_observer.crypto import SigningKey, canonical

from .service import ApsRefundStore


def load_store(runtime: dict[str, Any], *, fault: str | None = None) -> ApsRefundStore:
    """Open existing host-owned state; initialization is a separate explicit operation."""
    def crash(point: str) -> None:
        """Terminate the actual process at a selected native transaction boundary."""
        if point == fault:
            os._exit(23)
    key = SigningKey(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(runtime["servicePrivateKey"])))
    return ApsRefundStore(Path(runtime["storePath"]), ActionRequest(**runtime["request"]),
                          GrantPolicy(**runtime["grantPolicy"]), key, evidence=runtime["evidence"],
                          tenant_id=runtime["tenantId"], node=Path(runtime["node"]),
                          verifier=Path(runtime["verifier"]), verifier_sha256=runtime["verifierSha256"],
                          sdk_sha256=runtime["sdkSha256"],
                          clock=lambda: datetime.fromisoformat(runtime["now"].replace("Z", "+00:00")), crash_hook=crash)


def main() -> int:
    """Dispatch once from a protected host configuration, without agent-supplied keys."""
    runtime_path = Path(sys.argv[1])
    if runtime_path.stat().st_mode & 0o077:
        raise ValueError("host runtime file permissions are not private")
    runtime = json.loads(runtime_path.read_bytes())
    store = load_store(runtime, fault=sys.argv[2] if len(sys.argv) > 2 else None)
    receipt = store.dispatch(runtime["candidate"])
    result = {"receipt": receipt, "readback": store.readback(), "request": asdict(store.request)}
    sys.stdout.buffer.write(canonical(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
