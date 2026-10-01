"""Fixed hostile socket workload for one measured protected launch.

Runs inside bubblewrap using only the Python standard library. Its assertions
are test evidence checked against host records, not independent custody.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import sys
from pathlib import Path
from typing import Any, Callable


def canonical(value: Any) -> bytes:
    """Serialize this fixture's ASCII-only JSON wire values."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def send(raw: bytes, *, read: bool = True) -> dict[str, Any]:
    """Send one finite wire attempt, optionally discard the first response."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(3)
        client.connect("/broker/write.sock")
        client.sendall(raw)
        client.shutdown(socket.SHUT_WR)
        if not read:
            return {}
        response = client.makefile("rb").readline(65537)
    return json.loads(response)


def request(payload: dict[str, Any]) -> dict[str, Any]:
    """Send one ordinary canonical socket attempt."""
    return send(canonical(payload) + b"\n")


def refused(action: Callable[[], Any]) -> bool:
    """Require the operating system, rather than the workload, to deny a bypass."""
    try:
        action()
    except OSError:
        return True
    return False


def network_attempt() -> None:
    """Attempt an external TCP connection from the unshared namespace."""
    with socket.create_connection(("1.1.1.1", 443), timeout=1):
        return


def changed_requests(payload: dict[str, Any]) -> dict[str, bool]:
    """Attempt every exact-action identity substitution with the unchanged grant."""
    fields = (
        "run_id",
        "attempt_id",
        "request_id",
        "tenant_id",
        "principal_id",
        "tool_id",
        "target_path",
        "content_sha256",
    )
    results: dict[str, bool] = {}
    for field in fields:
        candidate = json.loads(canonical(payload))
        candidate["request"][field] = {
            "target_path": "/work/other.txt",
            "content_sha256": "0" * 64,
        }.get(field, "substituted")
        results[f"changed-{field}"] = (
            request(candidate).get("error")
            == "invocation differs from the expected action"
        )
    return results


def malformed_requests(payload: dict[str, Any]) -> dict[str, bool]:
    """Attempt malformed, oversized, legacy-bypass, and clock-selected requests."""
    attempts = {
        "malformedJson": (b"not-json\n", "invalid JSON document"),
        "missingNewline": (b"{}", "protected socket request missing or oversized"),
        "oversized": (
            b"0" * 65537 + b"\n",
            "protected socket request missing or oversized",
        ),
        "duplicateMember": (b'{"x":1,"x":2}\n', "duplicate JSON member"),
        "nativeBypass": (
            canonical(
                {"requestId": "bypass", "path": "/work/bypass.txt", "contentHex": "00"}
            )
            + b"\n",
            "protected socket request has unexpected fields",
        ),
        "callerClock": (
            canonical({**payload, "now": "2099-01-01T00:00:00Z"}) + b"\n",
            "protected socket request has unexpected fields",
        ),
    }
    return {
        name: send(raw).get("error") == expected
        for name, (raw, expected) in attempts.items()
    }


def grant_attempts(payload: dict[str, Any], inputs: dict[str, Any]) -> dict[str, bool]:
    """Exercise wrong issuer/signature and host-signed expired/future grants."""
    wrong_issuer = {**payload, "grant": {**payload["grant"], "issuerKey": "0" * 64}}
    wrong_signature = {**payload, "grant": {**payload["grant"], "signature": "0" * 64}}
    expired = {**payload, "grant": inputs["expiredGrant"]}
    future = {**payload, "grant": inputs["futureGrant"]}
    return {
        "wrongIssuer": request(wrong_issuer).get("error")
        == "grant issuer differs from the pinned issuer key",
        "wrongSignature": request(wrong_signature).get("error")
        == "grant signature does not verify under the pinned issuer key",
        "expiredGrant": request(expired).get("error")
        == "grant is not valid at the reference time",
        "futureGrant": request(future).get("error")
        == "grant is not valid at the reference time",
    }


def main(host_pid: int) -> None:
    """Exercise refusal controls before and after a response-loss retry."""
    inputs = json.loads(Path("/agent/invocation.json").read_bytes())
    payload = inputs["invocation"]
    result = {
        "directWriteRefused": refused(lambda: open("/work/bypass.txt", "wb").close()),
        "keyReadRefused": refused(lambda: open(f"/proc/{host_pid}/mem", "rb").close()),
        "processSignalRefused": refused(lambda: os.kill(host_pid, signal.SIGCONT)),
        "networkRefused": refused(network_attempt),
    }
    result.update(changed_requests(payload))
    result.update(malformed_requests(payload))
    result.update(grant_attempts(payload, inputs))
    changed_content = {**payload, "contentHex": b"changed bytes".hex()}
    result["changedContent"] = (
        request(changed_content).get("error")
        == "content digest differs from the authorized action"
    )
    send(canonical(payload) + b"\n", read=False)
    replay = request(payload)
    result["lostResponseReplay"] = (
        replay.get("ok") is True and replay.get("replayed") is True
    )
    result["repeatReplay"] = request(payload).get("replayed") is True
    result["changedRetry"] = (
        request(changed_content).get("error")
        == "content digest differs from the authorized action"
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main(int(sys.argv[1]))
