"""Small offline demonstration of broker, retry, and witnessed verification."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .broker import Broker
from .crypto import SigningKey, canonical, strict_loads
from .history import Witness
from .verify import verify_packet


def run_demo(output: Path) -> dict[str, str]:
    """Produce a fully checkable one-write packet in an empty output directory.

    The sample uses two keys but one local operator. It demonstrates protocol
    mechanics, not an external observer or independent witness deployment.
    """
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("demo output directory must be empty")
    workspace = output / "workspace"
    workspace.mkdir()
    observer_key = SigningKey.generate()
    witness_key = SigningKey.generate()
    witness = Witness(output / "witness-state.json", witness_key)
    history = output / "history.jsonl"
    authority = {"intervalId": "demo-interval-1", "scope": "/work", "operation": "write-file"}
    broker = Broker(workspace, history, authority, observer_key, witness)
    broker.begin()
    broker.write("request-1", "/work/result.txt", b"one durable effect\n")
    retry = broker.write("request-1", "/work/result.txt", b"one durable effect\n")
    packet = broker.seal()
    (output / "packet.json").write_bytes(canonical(packet))
    keys = {"observer": observer_key.public_hex, "witness": witness_key.public_hex}
    (output / "trusted-keys.json").write_bytes(canonical(keys))
    verified = verify_packet(packet, history, keys["observer"], keys["witness"], workspace)
    return {"status": "verified", "witnessScope": verified["witnessScope"], "noDetectedGap": str(verified["coverage"]["noDetectedGap"]).lower(), "retryReplayed": str(retry.replayed).lower()}


def main(argv: Sequence[str] | None = None) -> int:
    """Run the demonstration or verify a retained packet with pinned keys."""
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    demo = subcommands.add_parser("demo", help="write a sample packet and verify it")
    demo.add_argument("output", type=Path)
    verify = subcommands.add_parser("verify", help="check a retained sample offline")
    verify.add_argument("directory", type=Path)
    arguments = parser.parse_args(argv)
    if arguments.command == "demo":
        result = run_demo(arguments.output)
    else:
        directory = arguments.directory
        packet = strict_loads((directory / "packet.json").read_bytes())
        keys = strict_loads((directory / "trusted-keys.json").read_bytes())
        claim = verify_packet(packet, directory / "history.jsonl", keys["observer"], keys["witness"], directory / "workspace")
        result = {"status": "verified", "witnessScope": claim["witnessScope"], "noDetectedGap": str(claim["coverage"]["noDetectedGap"]).lower()}
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
