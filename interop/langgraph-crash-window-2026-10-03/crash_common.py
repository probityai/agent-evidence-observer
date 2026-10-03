"""Finite additive effect/checkpoint crash-window selections."""
import os
import stat
from pathlib import Path

from joint_common import NONCLAIMS, child_environment, require, same, sha, write
from probity_observer.crypto import VerificationError, strict_loads

PROFILE = "probity-langgraph-target-crash-window-v1"
CASES = ("valid-after", "revoked-after", "expired-after", "rollback-after")
POLICY = {"profile": PROFILE, "plannedAttempts": 4, "workerTimeoutSeconds": 30,
          "crashExitCode": 74, "crashPoint": "after-committed-http-before-node-return",
          "recoveryInput": "None-for-pending-native-task", "providerCalls": 0,
          "authorityBoundary": "before-native-pending-task-replay", "targetRestart": True}

__all__ = ["NONCLAIMS", "child_environment", "load", "read", "require", "same", "sha", "write"]


def read(root: Path, name: str) -> bytes:
    """Read a bounded regular member without following links or blocking pipes."""
    path = root / name
    require(path.resolve().is_relative_to(root.resolve()), "packet-path")
    require(not any(p.is_symlink() for p in (path, *path.parents)), "packet-symlink")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except OSError:
        require(False, "packet-open")
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode), "packet-regular-file")
        require(metadata.st_size <= 16 * 1024 * 1024, "packet-size")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(metadata.st_size + 1)
        require(len(raw) == metadata.st_size, "packet-file-changed-size")
        return raw
    finally:
        os.close(descriptor)


def load(root: Path, name: str):
    """Parse selected regular JSON bytes using duplicate/canonical refusal."""
    try:
        value = strict_loads(read(root, name))
    except VerificationError:
        raise
    except (RecursionError, OverflowError):
        require(False, "packet-json-bound")
    pending, seen = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        seen += 1
        require(depth <= 64, "packet-json-bound")
        children = item.values() if type(item) is dict else item if type(item) is list else ()
        require(seen + len(pending) + len(children) <= 16384, "packet-json-bound")
        pending.extend((child, depth + 1) for child in children)
    return value


def packet_files(root: Path) -> set[str]:
    """Give missing/inaccessible populations a stable enumeration refusal."""
    try:
        return enumerate_packet(root)
    except OSError:
        require(False, "packet-enumeration")


def enumerate_packet(root: Path) -> set[str]:
    """Bound the entire regular population before shared helper or SQLite reads."""
    require(root.is_dir() and not any(p.is_symlink() for p in (root, *root.parents)), "packet-symlink")
    pending, names, entries, total = [(root, 0)], set(), 0, 0
    while pending:
        directory, depth = pending.pop()
        require(depth <= 12, "packet-depth-bound")
        with os.scandir(directory) as children:
            for child in children:
                entries += 1
                require(entries <= 1024, "packet-entry-bound")
                metadata = child.stat(follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append((Path(child.path), depth + 1))
                    continue
                require(stat.S_ISREG(metadata.st_mode), "packet-regular-file")
                require(metadata.st_size <= 16 * 1024 * 1024, "packet-size")
                names.add(str(Path(child.path).relative_to(root)))
                total += metadata.st_size
                require(len(names) <= 512 and total <= 64 * 1024 * 1024, "packet-population-bound")
    return names
