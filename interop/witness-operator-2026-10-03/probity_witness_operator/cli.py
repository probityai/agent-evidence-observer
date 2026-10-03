"""Installed operator commands with explicit host key, state and head choices."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from probity_observer.crypto import VerificationError, canonical

from .protocol import require
from .server import OperatorServer, remove_stale_socket
from .store import Configuration, OperatorStore, absolute_path, generate_key, initialize


def _parser() -> argparse.ArgumentParser:
    """Build the small explicit operator command surface."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    key = commands.add_parser("keygen", help="create one host-selected key exclusively")
    key.add_argument("--output", type=Path, required=True)
    for name in ("init", "serve", "export", "head"):
        command = commands.add_parser(name)
        command.add_argument("--config", type=Path, required=True)
        command.add_argument("--config-sha256", required=True)
        if name != "init":
            command.add_argument("--retained-head", type=Path, required=True)
            command.add_argument("--retained-sha256", required=True)
    commands.choices["serve"].add_argument("--remove-stale-socket", action="store_true")
    return parser


def _configured(arguments: argparse.Namespace) -> dict[str, Any] | None:
    """Dispatch host commands without reading secrets from caller requests."""
    configuration = Configuration.read(arguments.config, arguments.config_sha256)
    if arguments.command == "init":
        return initialize(configuration)
    store = OperatorStore(configuration, arguments.retained_head, arguments.retained_sha256)
    if arguments.command == "serve":
        return _serve(store, arguments.remove_stale_socket)
    exported = store.export()
    return exported["head"] if arguments.command == "head" else exported


def _serve(store: OperatorStore, remove_stale: bool) -> None:
    """Run an authenticated local endpoint after restart verification."""
    path = store.configuration.socket_path
    if remove_stale:
        remove_stale_socket(path)
    with OperatorServer(store) as server:
        server.serve_forever(poll_interval=0.05)


def main() -> int:
    """Run one installed command; refusals return no successful JSON output."""
    arguments = _parser().parse_args()
    try:
        result = _keygen(arguments) if arguments.command == "keygen" else _configured(arguments)
        if result is not None:
            sys.stdout.buffer.write(canonical(result))
        return 0
    except (VerificationError, ValueError, KeyError, TypeError, OSError):
        print("witness command refused", file=sys.stderr)
        return 2


def _keygen(arguments: argparse.Namespace) -> dict[str, str]:
    """Only an explicit keygen command may create a private key."""
    return {"witnessKey": generate_key(absolute_path(str(arguments.output)))}


if __name__ == "__main__":
    raise SystemExit(main())
