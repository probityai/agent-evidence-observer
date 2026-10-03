"""Selected entry point for native execution or installed model-free reading.

The consumer must select artifact pins independently of an untrusted packet.
The active installed interpreter, package and ancestor filesystem are trusted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
import os

PROCESS_START_WALL = time.monotonic_ns()
PROTOCOL_SHA256 = "f62ded1a32862839da80a80f8e871ef6cda4acc8c30363367cccf6bec9e92c97"
PROTOCOL_COMMIT = "registration-required"
ROOT = Path(__file__).parent
INSTALLED_READER = ROOT.name == "probity_tool_arguments_reader"
READER_MARKER = b'{"installationRole":"model-free-reader","modelDispatch":false}\n'


def active_protocol() -> dict:
    """Validate selected source before exposing its directory to Python imports."""
    raw = (ROOT / "protocol.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROTOCOL_SHA256:
        raise ValueError("active selected protocol changed")
    protocol = json.loads(raw)
    for name, selected in protocol["sourceClosure"].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != selected:
            raise ValueError("active selected source changed")
    verify_reader_role()
    source_cache_absent()
    source_module_inventory(protocol)
    sys.dont_write_bytecode = True
    if __package__ in {None, ""}:
        sys.path.insert(0, str(ROOT))
    return protocol


def verify_reader_role() -> None:
    """Require the source-generated marker for an installed model-free layout."""
    if INSTALLED_READER and (ROOT / "reader-mode.json").read_bytes() != READER_MARKER:
        raise ValueError("installed reader role marker changed")


def source_cache_absent() -> None:
    """Refuse cached executable code before any selected helper imports."""
    for directory, directories, files in os.walk(ROOT, followlinks=False):
        if any((Path(directory) / name).is_symlink() for name in directories):
            raise ValueError("selected source directory links must be absent")
        if any(name.endswith((".pyc", ".pyo")) for name in files):
            raise ValueError("selected source cache population must be empty")


def source_module_inventory(protocol: dict) -> None:
    """Refuse unselected module/package/extension aliases on the source path."""
    selected = set(protocol["sourceClosure"]) | {"task_matrix.py", "__init__.py"}
    directories = {"tests", "selected", "retained", "grammars", "__pycache__"}
    for path in ROOT.iterdir():
        if path.is_dir():
            if path.name not in directories:
                raise ValueError("unselected source module directory refused")
        elif (path.suffix in {".py", ".so", ".pyd", ".dll", ".pyc", ".pyo"}) and path.name not in selected:
            raise ValueError("unselected source module alias refused")


def main() -> None:
    """Run the frozen entry point and retain explicit strict quality exits."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--pins-file", type=Path)
    parser.add_argument("--evidence-only", action="store_true")
    parser.add_argument("--prepared", type=Path)
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--protocol-commit")
    args = parser.parse_args()
    try:
        protocol = active_protocol()
        result = choose_action(args, protocol)
        sys.stdout.buffer.write((json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode())
        if not args.verify:
            raise SystemExit(0 if result["status"] == "complete" else 1)
        evidence = result["publicationDecision"] == "publish-scoped-report"
        admitted = result["qualityDecision"] == "admit-scoped-quality"
        raise SystemExit(0 if evidence and (args.evidence_only or admitted) else 1)
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2) from error


def choose_action(args: argparse.Namespace, protocol: dict) -> dict:
    """Choose model-free reconstruction or explicit preregistered inference."""
    if args.verify:
        return read_action(args, protocol)
    return native_action(args, protocol)


def read_action(args: argparse.Namespace, protocol: dict) -> dict:
    """Consume independently selected pins through model-free frozen source."""
    if args.pins_file is None:
        raise ValueError("reader requires independently selected pins-file")
    if __package__:
        from .evidence_io import read_regular, strict_json
        from .reader import verify
    else:
        from evidence_io import read_regular, strict_json
        from reader import verify
    return verify(args.packet, strict_json(read_regular(args.pins_file)), protocol, PROTOCOL_COMMIT, PROTOCOL_SHA256)


def native_action(args: argparse.Namespace, protocol: dict) -> dict:
    """Require prospective registration before explicitly selected native execution."""
    if __package__ or INSTALLED_READER:
        raise ValueError("installed reader does not dispatch model inference")
    if args.protocol_commit != PROTOCOL_COMMIT or len(PROTOCOL_COMMIT) != 40:
        raise ValueError("inference requires published prospective registration")
    if args.prepared is None or args.repository is None:
        raise ValueError("native execution requires selected prepared runtime and repository")
    if __package__:
        from .native_runner import execute
    else:
        from native_runner import execute
    return execute(args.packet, args.prepared, protocol, PROTOCOL_COMMIT, PROTOCOL_SHA256, args.repository, PROCESS_START_WALL)


if __name__ == "__main__":
    main()
