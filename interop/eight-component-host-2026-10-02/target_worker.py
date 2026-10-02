"""Run the ordinarily installed native Observer HTTP ticket target.

Only the host launches this worker and selects its configuration, seed, clock,
fault, retained head and recovery action. POST bytes contain no administrative
clock or recovery switches. Distinct processes reopen one native SQLite store.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any


def write_new(path: Path, value: Any) -> None:
    """Retain a startup or recovery record without replacing an earlier one."""
    with path.open("x") as output:
        json.dump(value, output, sort_keys=True)
        output.write("\n")


def startup_controls(store: Any, config: dict[str, Any], endpoint: Path) -> None:
    """Apply the selected host-only native initialization, revocation and recovery."""
    if config["initialize"]:
        store.initialize()
    if config["revoke"]:
        store.revoke()
    if config["recover"]:
        write_new(endpoint.with_suffix(".recovery.json"), store.recover())


def run(config: dict[str, Any], endpoint: Path) -> None:
    """Initialize or reopen the selected native target in a fresh real process.

    Parameters
    ----------
    config : dict[str, Any]
        Host-selected database, exact request, policy, separate service key,
        mutable host clock path, prior signed head and finite fault control.
    endpoint : Path
        New endpoint readiness file outside candidate bytes.

    Notes
    -----
    ``os._exit(73)`` ends the actual target process at the selected native fault
    hook. SQLite's previously committed intent or effect is read by the next
    process; this is not an in-memory exception substitute for process restart.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from probity_observer.authorization import ActionRequest, GrantPolicy
    from probity_observer.crypto import SigningKey
    from probity_observer.ticket_service import TicketHTTPServer, TicketStore

    seed = bytes.fromhex(Path(config["serviceSeed"]).read_text().strip())
    key = SigningKey(Ed25519PrivateKey.from_private_bytes(seed))

    def clock() -> datetime:
        return datetime.fromisoformat(Path(config["clock"]).read_text().strip().replace("Z", "+00:00"))

    def crash(point: str) -> None:
        if point == config["fault"]:
            os._exit(73)

    store = TicketStore(Path(config["database"]), ActionRequest(**config["request"]),
                        GrantPolicy(**config["grantPolicy"]), key, clock=clock,
                        crash_hook=crash, retained_head=config["retainedHead"])
    startup_controls(store, config, endpoint)
    startup = store.readback()
    with TicketHTTPServer(store) as server:
        write_new(endpoint, {"url": server.url, "startup": startup, "pid": os.getpid()})
        server.serve_forever(poll_interval=0.05)


def main() -> None:
    """Require an explicit host config digest before importing installed tools."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("config_sha256")
    parser.add_argument("endpoint", type=Path)
    args = parser.parse_args()
    raw = args.config.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.config_sha256:
        raise SystemExit("host target configuration digest differs")
    run(json.loads(raw), args.endpoint)


if __name__ == "__main__":
    main()
