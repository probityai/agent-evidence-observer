"""The fixed adversarial workload for the Linux boundary gate.

This file runs inside the sandbox. It uses only the Python standard library.
Its digest is committed before launch, but the host still treats its output as
test evidence rather than as an independent observation of all agent effects.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import sys


def refused(action: object) -> bool:
    """Return true only when an operating-system attempt raises OSError."""
    try:
        action()
    except OSError:
        return True
    return False


def request(request_id: str, path: str, content: bytes) -> dict[str, object]:
    """Send one bounded file replacement to the host broker."""
    payload = {"requestId": request_id, "path": path, "contentHex": content.hex()}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect("/broker/write.sock")
        client.sendall(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n")
        response = client.makefile("rb").readline(65537)
    return json.loads(response)


def network_attempt() -> None:
    """Attempt an outbound TCP channel from the agent namespace."""
    with socket.create_connection(("1.1.1.1", 443), timeout=1):
        return


def main(host_pid: int) -> None:
    """Try bypasses, then test a write, replay, and two denied requests."""
    direct = refused(lambda: open("/work/direct-write.txt", "wb").close())
    key = refused(lambda: open(f"/proc/{host_pid}/mem", "rb").close())
    process = refused(lambda: os.kill(host_pid, signal.SIGCONT))
    network = refused(network_attempt)
    first = request("write-1", "/work/effect.txt", b"observed effect\n")
    replay = request("write-1", "/work/effect.txt", b"observed effect\n")
    changed = request("write-1", "/work/effect.txt", b"changed effect\n")
    traversal = request("escape-1", "/work/../outside.txt", b"escape\n")
    result = {
        "directWriteRefused": direct,
        "keyReadRefused": key,
        "processSignalRefused": process,
        "networkRefused": network,
        "brokerWrite": first.get("ok") is True,
        "retryReplayed": replay.get("replayed") is True,
        "changedRetryDenied": changed.get("error") == "idempotency key reused with different request",
        "traversalDenied": traversal.get("error") == "write path is not normalized",
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main(int(sys.argv[1]))
