"""Explicit authorization-witness initialization, restart and public export."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from probity_observer.crypto import VerificationError, canonical
from probity_witness_operator.server import OperatorServer, remove_stale_socket

from .store import AuthorizationConfiguration, AuthorizationStore, initialize


def main() -> int:
    """Run one host-selected operation; a refusal never prints successful JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "serve", "export", "head"):
        command = commands.add_parser(name)
        command.add_argument("--config", type=Path, required=True)
        command.add_argument("--config-sha256", required=True)
        if name != "init":
            command.add_argument("--retained-checkpoint", type=Path, required=True)
            command.add_argument("--retained-sha256", required=True)
    commands.choices["serve"].add_argument("--remove-stale-socket", action="store_true")
    arguments = parser.parse_args()
    try:
        configuration = AuthorizationConfiguration.read(arguments.config, arguments.config_sha256)
        if arguments.command == "init":
            result = initialize(configuration)
        else:
            store = AuthorizationStore(configuration, arguments.retained_checkpoint, arguments.retained_sha256)
            if arguments.command == "serve":
                if arguments.remove_stale_socket:
                    remove_stale_socket(configuration.socket_path)
                with OperatorServer(store) as server:
                    server.serve_forever(poll_interval=0.05)
                result = None
            else:
                result = store.export()
                if arguments.command == "head":
                    result = result["checkpoint"]
        if result is not None:
            sys.stdout.buffer.write(canonical(result))
        return 0
    except (VerificationError, ValueError, KeyError, TypeError, OSError):
        print("authorization witness command refused", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
