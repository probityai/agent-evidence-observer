"""Real protected HTTP process with an explicitly selected host clock.

This adapter reopens the merged :class:`TicketStore` durable backend. It does
not create a missing store and does not reimplement intent/effect transactions.
"""
from __future__ import annotations

import argparse
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from probity_observer.authorization import ActionRequest, GrantPolicy
from probity_observer.crypto import SigningKey, VerificationError
from probity_observer.ticket_service import TicketHTTPServer, TicketStore

from joint_common import load, write


def serve(config: Path, fault: str) -> None:
    """Reopen exactly selected state and retain readiness or startup refusal.

    Parameters
    ----------
    config : pathlib.Path
        Private host file containing the store path, signing key, fixed clock,
        request, issuer policy and externally retained history head. This file
        is removed by the launcher and never enters the public packet.
    fault : str
        Host-only fault point. Hard exits occur after durable intent or inside
        the effect transaction; ``concurrent-window`` widens the pending gap.
    """
    selected: dict[str, Any] = load(config.parent, config.name)
    key = SigningKey(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(selected["servicePrivateHex"])))
    clock = datetime.fromisoformat(selected["clockTime"])

    def crash(point: str) -> None:
        if fault == "concurrent-window" and point == "after-intent":
            time.sleep(0.15)
        if point == fault:
            os._exit({"after-intent": 74, "inside-effect-transaction": 75}[point])

    store = TicketStore(Path(selected["store"]), ActionRequest(**selected["request"]), GrantPolicy(**selected["policy"]), key, clock=lambda: clock, crash_hook=crash, retained_head=selected["retainedHead"])
    try:
        initial = store.readback()
        with TicketHTTPServer(store) as server:
            write(Path(selected["readyFile"]), {"pid": os.getpid(), "url": server.url, "initial": initial})
            server.serve_forever(poll_interval=0.05)
    except VerificationError as error:
        write(Path(selected["refusalFile"]), {"status": "refused", "reason": str(error), "pid": os.getpid()})
        raise SystemExit(78) from error


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--fault", default="none")
    args = parser.parse_args()
    serve(args.config, args.fault)
