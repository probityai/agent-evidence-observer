"""Durably retain public signed witness heads with consumer-selected pins.

The consumer owns the retention directory and uses the witness public key.
See :func:`retain_head` for the prefix checks and crash boundary.
"""

from __future__ import annotations

import argparse
import fcntl
import logging
import os
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Iterator, NoReturn

from probity_observer.crypto import VerificationError, canonical, strict_loads
from probity_observer.ledger import verify_ledger_head

from .protocol import MAX_HISTORY, sha
from .store import absolute_path, flush_directory, public_key

LOGGER = logging.getLogger(__name__)
MAX_HEAD_BYTES = 16_384


def _refuse(message: str) -> NoReturn:
    """Log one fixed refusal message before raising the shared verifier error."""
    LOGGER.warning("retained head refused: %s", message)
    raise VerificationError(message)


def _require(condition: bool, message: str) -> None:
    """Require a host-selection invariant without logging candidate contents."""
    if not condition:
        _refuse(message)


def _read_pinned(path: Path, expected_sha256: str, limit: int) -> bytes:
    """Read bounded regular-file bytes through an explicit host digest pin."""
    descriptor = os.open(absolute_path(str(path)), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        _require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "retention input is not a regular file")
        raw = stream.read(limit + 1)
    _require(len(raw) <= limit, "retention input exceeds finite limit")
    _require(sha(raw) == expected_sha256, "retention input pin differs")
    return raw


def _private_metadata(metadata: os.stat_result) -> None:
    """Require an operator-owned, single-link private retention file."""
    _require(stat.S_ISREG(metadata.st_mode), "retention file is not a regular file")
    _require(metadata.st_uid == os.getuid(), "retention file owner differs")
    _require(metadata.st_nlink == 1, "retention file has multiple links")
    _require(metadata.st_mode & 0o077 == 0, "retention file permissions differ")


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    """Serialize cooperating consumers in their host-owned private directory."""
    metadata = path.parent.stat()
    _require(stat.S_ISDIR(metadata.st_mode), "retention parent is not a directory")
    _require(metadata.st_uid == os.getuid(), "retention parent owner differs")
    _require(metadata.st_mode & 0o077 == 0, "retention parent permissions differ")
    lock = path.with_name(path.name + ".lock")
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(descriptor, "a+b") as stream:
        _private_metadata(os.fstat(stream.fileno()))
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def _previous(path: Path, expected_sha256: str | None) -> dict[str, Any] | None:
    """Apply compare-and-swap selection; an existing retained head cannot reset."""
    if expected_sha256 is None:
        _require(not path.exists(), "initial retention requires a new head path")
        return None
    _require(path.exists(), "selected retained head is missing")
    _private_metadata(path.lstat())
    raw = _read_pinned(path, expected_sha256, MAX_HEAD_BYTES)
    return strict_loads(raw)


def _validate_prefixes(ledger: Path, candidate: dict[str, Any], previous: dict[str, Any] | None, witness_key: str) -> None:
    """Verify the current complete log and the separately retained old prefix."""
    summary = verify_ledger_head(ledger, candidate, witness_key)
    _require((summary["count"], summary["head"]) == (candidate["count"], candidate["head"]),
             "candidate head is not the complete ledger head")
    if previous is not None:
        verify_ledger_head(ledger, previous, witness_key)


def _replace(path: Path, raw: bytes) -> None:
    """Flush a private temporary file, replace atomically, then flush its link."""
    with NamedTemporaryFile(prefix=".retained-head-", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temporary, path)
            flush_directory(path.parent)
        finally:
            temporary.unlink(missing_ok=True)


def retain_head(
    ledger_path: Path,
    candidate_path: Path,
    retained_path: Path,
    *,
    witness_key: str,
    ledger_sha256: str,
    candidate_sha256: str,
    previous_sha256: str | None,
) -> dict[str, Any]:
    """Verify and durably retain one host-selected public witness ledger head.

    Parameters
    ----------
    ledger_path : Path
        Absolute path to the complete public receipt log, at most 256 KiB.
        Its bytes are copied to a private snapshot before validation.
    candidate_path : Path
        Absolute path to the public signed head, at most 16 KiB. The head
        must describe the complete selected log, rather than an older prefix.
    retained_path : Path
        Absolute destination in a pre-existing host-owned 0700 directory.
        Keep that directory outside producer and witness-store authority.
        No caller-selected bundle file may replace this host selection.
    witness_key : str
        Lowercase Ed25519 public key selected through the consumer's trusted
        channel. Neither an input record nor this function establishes its
        operator's identity, custody or key-authority policy.
    ledger_sha256, candidate_sha256 : str
        Exact SHA-256 pins selected for the submitted public files.
    previous_sha256 : str or None
        Exact pin of the head already retained by this consumer. ``None``
        permits an initial write only when the destination does not exist.
        A stale or missing selection refuses; it never silently resets.

    Returns
    -------
    dict
        The verified signed head, after file fsync, atomic replacement and
        parent-directory fsync have all succeeded. Repeating the same head
        is permitted with its current retained pin and does not add receipts.

    Raises
    ------
    VerificationError
        If pins, host-file protections, signatures, complete-log position or
        the retained prefix differ. Rollback and same-key forks refuse.
    OSError
        If reading, locking, writing, replacement or durability fails. A
        failure before replacement preserves the prior head. A failure of
        the directory fsync can leave the new head visible without successful
        acknowledgment; inspect its bytes and retry under that observed pin.

    Notes
    -----
    :func:`probity_observer.ledger.verify_ledger_head` validates every receipt
    and both signed prefixes. The advisory lock serializes cooperating local
    consumers; the private directory must exclude other writers. Checkpoints
    bind order and hashes, not a trusted timestamp. Retaining author-generated
    records does not establish independently operated effect capture.
    """
    destination = absolute_path(str(retained_path))
    _require(destination not in {ledger_path, candidate_path}, "retained head must be separate from submitted files")
    key = public_key(witness_key)
    ledger = _read_pinned(ledger_path, ledger_sha256, MAX_HISTORY)
    candidate = strict_loads(_read_pinned(candidate_path, candidate_sha256, MAX_HEAD_BYTES))
    with _locked(destination):
        previous = _previous(destination, previous_sha256)
        with NamedTemporaryFile(prefix=".retention-ledger-", dir=destination.parent) as snapshot:
            snapshot.write(ledger)
            snapshot.flush()
            _validate_prefixes(Path(snapshot.name), candidate, previous, key)
        _replace(destination, canonical(candidate))
    return candidate


def main() -> int:
    """Run public-key-only head retention; a refusal emits no success JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("retained", type=Path)
    parser.add_argument("--witness-key", required=True)
    parser.add_argument("--ledger-sha256", required=True)
    parser.add_argument("--candidate-sha256", required=True)
    previous = parser.add_mutually_exclusive_group(required=True)
    previous.add_argument("--initial", action="store_true")
    previous.add_argument("--previous-sha256")
    arguments = parser.parse_args()
    try:
        head = retain_head(arguments.ledger, arguments.candidate, arguments.retained,
                           witness_key=arguments.witness_key, ledger_sha256=arguments.ledger_sha256,
                           candidate_sha256=arguments.candidate_sha256, previous_sha256=arguments.previous_sha256)
        sys.stdout.buffer.write(canonical(head) + b"\n")
    except (VerificationError, ValueError, KeyError, TypeError, OSError, RecursionError):
        LOGGER.warning("retained head command refused")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
