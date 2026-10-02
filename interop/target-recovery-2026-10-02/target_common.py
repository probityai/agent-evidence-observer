"""Finite source-selected target process recovery packet utilities."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from probity_observer.crypto import VerificationError, canonical, strict_loads

PROFILE = 'probity-target-process-recovery-v1'
CASES = ('restart-ready', 'crash-after-intent', 'crash-inside-effect', 'crash-after-effect', 'concurrent-intent', 'missing-store', 'changed-configuration')
LIMIT = 16 * 1024 * 1024
NONCLAIMS = ['power-loss', 'general-exactly-once', 'remote-identity', 'independent-custody', 'production-containment']


def require(ok: bool, reason: str) -> None:
    """Refuse a finite invariant with a stable reason."""
    if not ok:
        raise VerificationError(reason)


def sha(raw: bytes) -> str:
    """Hash literal retained bytes."""
    return hashlib.sha256(raw).hexdigest()


def read(root: Path, name: str) -> bytes:
    """Read bounded selected bytes, refusing path escapes and symbolic links."""
    path = root / name
    require(path.resolve().is_relative_to(root.resolve()), 'path-escape')
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink')
    with path.open('rb') as stream:
        raw = stream.read(LIMIT + 1)
    require(len(raw) <= LIMIT, 'file-limit')
    return raw


def load(root: Path, name: str) -> Any:
    """Parse exact restricted canonical JSON."""
    return strict_loads(read(root, name))


def write(path: Path, value: Any) -> None:
    """Exclusively retain canonical evidence without replacing prior output."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(canonical(value))
