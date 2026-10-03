"""Actual target process over selected retained keys, state and fixed clock."""
from __future__ import annotations

import argparse
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from probity_observer.authorization import ActionRequest, GrantPolicy
from probity_observer.crypto import SigningKey, VerificationError
from probity_observer.ticket_service import (
    TicketHTTPServer,
    TicketStore,
    _TicketHandler,
)

from probity_pydantic_recovery.common import load, write


class RecordedHandler(_TicketHandler):
    """Retain every request at the actual target before its native operation."""

    def observed(self, method: str) -> None:
        """Fsync a finite target-owned event without caller credentials or bodies."""
        write(self.server.audit_directory / (uuid.uuid4().hex + ".json"), {"method": method, "path": self.path, "pid": os.getpid()})

    def do_POST(self) -> None:
        """Record actual POST receipt, then invoke the unchanged native handler."""
        self.observed("POST")
        super().do_POST()

    def do_GET(self) -> None:
        """Record actual GET receipt, then invoke the unchanged native handler."""
        self.observed("GET")
        super().do_GET()


def serve(config: Path) -> None:
    """Reopen the real SQLite store without initializing a missing one."""
    selected = load(config)
    key = SigningKey(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(selected["privateHex"])))
    store = TicketStore(Path(selected["store"]), ActionRequest(**selected["request"]), GrantPolicy(**selected["policy"]), key, clock=lambda: datetime.now(UTC) if selected["clockTime"] is None else datetime.fromisoformat(selected["clockTime"]), retained_head=selected["retainedHead"])
    try:
        initial = store.readback()
        with TicketHTTPServer(store) as server:
            server.audit_directory = Path(selected["auditDirectory"])
            server.RequestHandlerClass = RecordedHandler
            write(Path(selected["ready"]), {"pid": os.getpid(), "url": server.url, "initial": initial})
            server.serve_forever(poll_interval=0.05)
    except VerificationError as error:
        write(Path(selected["refusal"]), {"pid": os.getpid(), "status": "refused", "reason": str(error)})
        raise SystemExit(78) from error


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    serve(parser.parse_args().config)
