"""Own a real HTTP target in a process distinct from its caller and reader."""
from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from probity_observer.authorization import ActionRequest, GrantPolicy
from probity_observer.crypto import SigningKey, VerificationError
from probity_observer.ticket_service import TicketHTTPServer, TicketStore

from target_common import load, write


def serve(config: Path, fault: str) -> None:
    """Reopen host-selected state without creating a missing target store."""
    selected = load(config.parent, config.name)
    key = SigningKey(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(selected['servicePrivateHex'])))
    def crash(point: str) -> None:
        if fault == 'concurrent-window' and point == 'after-intent':
            time.sleep(0.15)
        if point == fault:
            os._exit({'after-intent': 74, 'inside-effect-transaction': 75, 'after-effect': 76}[point])
    store = TicketStore(Path(selected['store']), ActionRequest(**selected['request']), GrantPolicy(**selected['policy']), key, crash_hook=crash, retained_head=selected['retainedHead'])
    try:
        initial = store.readback()
        with TicketHTTPServer(store) as server:
            write(Path(selected['readyFile']), {'pid': os.getpid(), 'url': server.url, 'initial': initial})
            server.serve_forever(poll_interval=0.05)
    except VerificationError as error:
        write(Path(selected['refusalFile']), {'status': 'refused', 'reason': str(error), 'pid': os.getpid()})
        raise SystemExit(78) from error


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path)
    parser.add_argument('--fault', choices=['none', 'after-intent', 'inside-effect-transaction', 'after-effect', 'concurrent-window'], default='none')
    args = parser.parse_args()
    serve(args.config, args.fault)
