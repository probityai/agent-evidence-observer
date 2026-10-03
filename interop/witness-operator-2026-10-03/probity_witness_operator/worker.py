"""Finite installed producer used by the real IPC acceptance run."""

from __future__ import annotations

import argparse
import os
import time
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from probity_observer import Broker, SigningKey, VerificationError
from probity_observer.authorization import ActionRequest, AuthorizedBroker, GrantPolicy, issue_grant
from probity_observer.crypto import canonical, strict_loads

from .client import WitnessClient
from .protocol import require, sha

CONTENT = b"effect committed through public witness port\n"


def _cannot_read(path: Path) -> bool:
    """Probe actual privilege denial rather than infer it from a directory name."""
    try:
        path.read_bytes()
        return False
    except PermissionError:
        return True


def _client(value: dict[str, Any]) -> WitnessClient:
    """Select public witness inputs from the host's separate worker configuration."""
    return WitnessClient(Path(value["socketPath"]), value["witnessKey"], value["observerKey"],
                         value["serverUid"], value["retainedHead"], timeout=2)


def _wait(path: Path) -> None:
    """Wait at a finite host-only fault barrier after an actual target write."""
    end = time.monotonic() + 15
    while not path.exists():
        require(time.monotonic() < end, "native fault barrier timed out")
        time.sleep(0.01)


def _write_action(broker: Broker, root: Path, value: dict[str, Any]) -> AuthorizedBroker:
    """Exercise AuthorizedBroker's public-key-only witness binding."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    issuer = SigningKey(Ed25519PrivateKey.from_private_bytes(Path(value["issuerKeyPath"]).read_bytes()))
    require(issuer.public_hex == value["issuerKey"], "native issuer key differs")
    request = ActionRequest(broker.authority["intervalId"], "attempt-1", "write-1", "tenant", "principal", "file-write", "/work/result.txt", sha(CONTENT))
    grant = issue_grant(request, issuer, issued_at=now, expires_at=now + timedelta(seconds=120))
    policy = GrantPolicy(issuer.public_hex, 120)
    root.joinpath("authorization.json").write_bytes(canonical({"request": asdict(request), "policy": asdict(policy), "grant": grant, "referenceTime": now.isoformat()}))
    authorized = AuthorizedBroker(broker, grant, policy, request, clock=lambda: now)
    authorized.write(request, CONTENT)
    return authorized


def _attempt(broker: Broker, root: Path, value: dict[str, Any]) -> tuple[int, str, str | None]:
    """Keep a process failure separate from its already committed effect."""
    broker.begin()
    authorized = _write_action(broker, root, value)
    mode = value["case"]
    if mode == "unavailable-after":
        root.joinpath("after-write.ready").write_bytes(b"ready")
        _wait(root / "continue")
    packet = authorized.seal()
    root.joinpath("packet.json").write_bytes(canonical(packet))
    if mode == "failed-after":
        return 7, "FAILED", "controlled producer failure after write"
    return 0, "COMPLETED", None


def produce(value: dict[str, Any], root: Path) -> int:
    """Run a native broker task under the producer's actual Linux UID.

    Parameters
    ----------
    value : dict
        Host-selected endpoint, public pins and finite case selection.
    root : Path
        Producer-owned history and target directory.

    Returns
    -------
    int
        Actual process exit code retained by the host's harness.
    """
    observer = SigningKey(Ed25519PrivateKey.from_private_bytes(Path(value["observerKeyPath"]).read_bytes()))
    require(observer.public_hex == value["observerKey"], "native observer key differs")
    client = _client(value)
    work = root / "work"
    work.mkdir()
    broker = Broker(work, root / "history.jsonl", {"intervalId": value["case"], "scope": "/work", "operation": "write-file"}, observer, client)
    try:
        code, state, reason = _attempt(broker, root, value)
    except VerificationError as exc:
        code, state, reason = 2, "FAILED", str(exc)
    summary = {"uid": os.getuid(), "state": state, "exitCode": code, "reason": reason,
               "beginAcknowledged": broker._started, "witnessKeyReadable": not _cannot_read(Path(value["operatorKeyPath"])),
               "witnessLedgerReadable": not _cannot_read(Path(value["operatorLedgerPath"])),
               "retainedHead": client.retained_head}
    root.joinpath("worker.json").write_bytes(canonical(summary))
    return code


def retry(value: dict[str, Any], root: Path) -> int:
    """Retry exact history after a process died before replying to its durable begin."""
    checkpoint = _client(value).checkpoint(root / "history.jsonl")
    root.joinpath("retry-checkpoint.json").write_bytes(canonical(checkpoint))
    return 0


def main() -> int:
    """Run one installed native producer or exact retry process."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("produce", "retry"))
    parser.add_argument("configuration", type=Path)
    parser.add_argument("directory", type=Path)
    arguments = parser.parse_args()
    value = strict_loads(arguments.configuration.read_bytes())
    handlers = {"produce": produce, "retry": retry}
    return handlers[arguments.operation](value, arguments.directory)


if __name__ == "__main__":
    raise SystemExit(main())
