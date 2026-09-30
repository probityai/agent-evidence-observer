"""Small offline demonstration of broker, retry, and witnessed verification."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .broker import Broker
from .crypto import SigningKey, canonical, strict_loads
from .history import Witness
from .isolation import run_boundary_probe, verify_boundary_bundle
from .ledger import verify_ledger_receipts
from .remote_witness import RemoteLedgerWitness, export_ledger, load_key, save_key, serve
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


def run_remote_demo(output: Path, socket_path: Path, observer_key_path: Path, witness_key: str) -> dict[str, str]:
    """Use a separate witness process and retain its ledger with the packet."""
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("demo output directory must be empty")
    workspace = output / "workspace"
    workspace.mkdir()
    observer_key = load_key(observer_key_path)
    witness = RemoteLedgerWitness(socket_path, observer_key, witness_key)
    history = output / "history.jsonl"
    broker = Broker(workspace, history, {"intervalId": "remote-demo-1", "scope": "/work", "operation": "write-file"}, observer_key, witness)
    broker.begin()
    broker.write("request-1", "/work/result.txt", b"one durable effect\n")
    packet = broker.seal()
    (output / "packet.json").write_bytes(canonical(packet))
    keys = {"observer": observer_key.public_hex, "witness": witness_key}
    (output / "trusted-keys.json").write_bytes(canonical(keys))
    verified = verify_packet(packet, history, keys["observer"], keys["witness"], workspace)
    export_ledger(socket_path, output / "witness-ledger.jsonl", witness_key)
    ledger = verify_ledger_receipts(output / "witness-ledger.jsonl", packet["startCheckpoint"], packet["checkpoint"], witness_key)
    return {"status": "verified", "witnessScope": verified["witnessScope"], "ledgerHead": ledger["head"]}


def main(argv: Sequence[str] | None = None) -> int:
    """Run the demonstration or verify a retained packet with pinned keys."""
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    demo = subcommands.add_parser("demo", help="write a sample packet and verify it")
    demo.add_argument("output", type=Path)
    boundary = subcommands.add_parser("boundary-probe", help="run the Linux boundary attack probe")
    boundary.add_argument("output", type=Path)
    boundary.add_argument("--witness-socket", type=Path)
    boundary.add_argument("--observer-key-file", type=Path)
    boundary.add_argument("--witness-key")
    checked = subcommands.add_parser("verify-boundary", help="check a retained boundary run with pinned keys")
    checked.add_argument("directory", type=Path)
    checked.add_argument("--observer-key", required=True)
    checked.add_argument("--witness-key", required=True)
    verify = subcommands.add_parser("verify", help="check a retained sample offline")
    verify.add_argument("directory", type=Path)
    keygen = subcommands.add_parser("witness-keygen", help="create a private signing key")
    keygen.add_argument("key_file", type=Path)
    server = subcommands.add_parser("witness-serve", help="serve signed ledger receipts over a Unix socket")
    server.add_argument("--socket", type=Path, required=True)
    server.add_argument("--ledger", type=Path, required=True)
    server.add_argument("--key-file", type=Path, required=True)
    server.add_argument("--observer-key", required=True)
    server.add_argument("--socket-mode", choices=["0600", "0660"], default="0600")
    remote = subcommands.add_parser("remote-demo", help="record one write with a separate witness process")
    remote.add_argument("output", type=Path)
    remote.add_argument("--socket", type=Path, required=True)
    remote.add_argument("--observer-key-file", type=Path, required=True)
    remote.add_argument("--witness-key", required=True)
    exported = subcommands.add_parser("witness-export", help="retain and verify a witness ledger")
    exported.add_argument("output", type=Path)
    exported.add_argument("--socket", type=Path, required=True)
    exported.add_argument("--witness-key", required=True)
    exported.add_argument("--pinned-head")
    remote_check = subcommands.add_parser("verify-remote", help="check a packet and retained witness ledger offline")
    remote_check.add_argument("directory", type=Path)
    remote_check.add_argument("--observer-key", required=True)
    remote_check.add_argument("--witness-key", required=True)
    remote_check.add_argument("--pinned-head")
    arguments = parser.parse_args(argv)
    if arguments.command == "demo":
        result = run_demo(arguments.output)
    elif arguments.command == "boundary-probe":
        remote_fields = (arguments.witness_socket, arguments.observer_key_file, arguments.witness_key)
        if any(remote_fields) and not all(remote_fields):
            parser.error("boundary-probe needs witness socket, observer key file, and pinned witness key together")
        observer = load_key(arguments.observer_key_file) if all(remote_fields) else None
        witness = RemoteLedgerWitness(arguments.witness_socket, observer, arguments.witness_key) if observer else None
        report = run_boundary_probe(arguments.output, observer_key=observer, witness=witness)
        print(json.dumps(report, sort_keys=True))
        return 0 if report["status"] == "probe-passed" else 1
    elif arguments.command == "verify-boundary":
        report = verify_boundary_bundle(arguments.directory, arguments.observer_key, arguments.witness_key)
        result = {"status": "verified", "boundaryStatus": report["status"], "witnessScope": report["witnessScope"]}
    elif arguments.command == "witness-keygen":
        key = SigningKey.generate()
        save_key(arguments.key_file, key)
        result = {"publicKey": key.public_hex}
    elif arguments.command == "witness-serve":
        serve(arguments.socket, arguments.ledger, arguments.key_file, arguments.observer_key, int(arguments.socket_mode, 8))
        return 0
    elif arguments.command == "remote-demo":
        result = run_remote_demo(arguments.output, arguments.socket, arguments.observer_key_file, arguments.witness_key)
    elif arguments.command == "witness-export":
        result = export_ledger(arguments.socket, arguments.output, arguments.witness_key, arguments.pinned_head)
    elif arguments.command == "verify-remote":
        directory = arguments.directory
        packet = strict_loads((directory / "packet.json").read_bytes())
        claim = verify_packet(packet, directory / "history.jsonl", arguments.observer_key, arguments.witness_key, directory / "workspace")
        ledger = verify_ledger_receipts(
            directory / "witness-ledger.jsonl", packet["startCheckpoint"], packet["checkpoint"],
            arguments.witness_key, arguments.pinned_head,
        )
        result = {"status": "verified", "witnessScope": claim["witnessScope"], "ledgerHead": ledger["head"]}
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
