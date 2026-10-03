"""Host-selected durable witness state with explicit initialization and restart."""

from __future__ import annotations

import fcntl
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable, Iterator

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from probity_observer.crypto import SigningKey, canonical, strict_loads
from probity_observer.ledger import LedgerWitness, _verify_terminal_intents, read_ledger, verify_ledger_head

from .protocol import FORMAT, MAX_HISTORY, REPLY_DOMAIN, checked_identity, decode_request, exact_fields, history_entries, require, sha

CONFIG_FIELDS = {"format", "keyPath", "storePath", "socketPath", "observerKey", "witnessKey", "clientUid"}


def absolute_path(value: Any) -> Path:
    """Require an exact absolute path without symlink or relative aliases."""
    require(isinstance(value, str), "operator path type differs")
    path = Path(value)
    require(path.is_absolute(), "operator path must be absolute")
    require(str(path.resolve()) == value, "operator path has an alias")
    return path


def public_key(value: Any) -> str:
    """Require a literal lowercase Ed25519 public key."""
    require(isinstance(value, str), "operator public key type differs")
    require(len(value) == 64, "operator public key length differs")
    require(bytes.fromhex(value).hex() == value, "operator public key encoding differs")
    return value


@dataclass(frozen=True)
class Configuration:
    """Immutable host choices; none can be changed by an IPC request."""

    key_path: Path
    store_path: Path
    socket_path: Path
    observer_key: str
    witness_key: str
    client_uid: int
    digest: str

    @classmethod
    def read(cls, path: Path, expected_sha256: str) -> Configuration:
        """Load exact host-selected configuration bytes under an external pin.

        Parameters
        ----------
        path : Path
            Host configuration, outside the workload.
        expected_sha256 : str
            Digest selected by the operator, not an IPC request.

        Returns
        -------
        Configuration
            Validated immutable key, store, peer and observer selections.
        """
        raw = path.read_bytes()
        require(sha(raw) == expected_sha256, "operator configuration pin differs")
        value = strict_loads(raw)
        exact_fields(value, CONFIG_FIELDS, "operator configuration fields differ")
        require(value["format"] == FORMAT, "operator configuration format differs")
        require(type(value["clientUid"]) is int, "operator client UID type differs")
        require(0 <= value["clientUid"] < 2**32, "operator client UID differs")
        require(value["observerKey"] != value["witnessKey"], "operator keys must differ")
        return cls(absolute_path(value["keyPath"]), absolute_path(value["storePath"]),
                   absolute_path(value["socketPath"]), public_key(value["observerKey"]),
                   public_key(value["witnessKey"]), value["clientUid"], expected_sha256)


def secure_file(path: Path) -> bytes:
    """Read an operator-owned single-link private regular file without following links."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode), "operator file type differs")
        require(metadata.st_uid == os.getuid(), "operator file owner differs")
        require(metadata.st_nlink == 1, "operator file link population differs")
        require(metadata.st_mode & 0o077 == 0, "operator file permissions differ")
        return os.read(descriptor, MAX_HISTORY + 1)
    finally:
        os.close(descriptor)


def load_key(configuration: Configuration) -> SigningKey:
    """Load the host's selected 32-byte secret without generating a replacement."""
    raw = secure_file(configuration.key_path)
    require(len(raw) == 32, "operator private key length differs")
    key = SigningKey(Ed25519PrivateKey.from_private_bytes(raw))
    require(key.public_hex == configuration.witness_key, "operator signing key pin differs")
    return key


def write_private(path: Path, raw: bytes) -> None:
    """Create one private file exclusively and flush its bytes and parent."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    flush_directory(path.parent)


def flush_directory(path: Path) -> None:
    """Persist a directory's links before acknowledging initialized state."""
    parent = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def generate_key(path: Path) -> str:
    """Explicitly create a host key once; return only its public key.

    Parameters
    ----------
    path : Path
        Operator-selected private file, which must not exist.

    Returns
    -------
    str
        Public Ed25519 key for an independently selected consumer pin.
    """
    key = SigningKey.generate()
    raw = key.private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    write_private(path, raw)
    return key.public_hex


def initialize(configuration: Configuration) -> dict[str, Any]:
    """Create a fresh witness store exclusively; never reuse restart state."""
    key = load_key(configuration)
    configuration.store_path.mkdir(mode=0o700)
    write_private(configuration.store_path / "configuration.sha256", configuration.digest.encode("ascii"))
    ledger = configuration.store_path / "ledger.jsonl"
    write_private(ledger, b"")
    flush_directory(configuration.store_path.parent)
    return LedgerWitness(ledger, key, configuration.observer_key).signed_head()


def _matches(receipt: dict[str, Any], interval: str, entries: list[dict[str, Any]]) -> bool:
    """Match the complete immutable history position, not an interval alone."""
    return (receipt["intervalId"], receipt["checkpoint"]["count"], receipt["checkpoint"]["head"]) == (
        interval, len(entries), entries[-1]["hash"])


class OperatorStore:
    """Serve registered intervals under host-selected key, state and head pins.

    Parameters
    ----------
    configuration : Configuration
        Immutable host selections.
    retained_path : Path
        Signed head acquired and retained outside this store.
    retained_sha256 : str
        Operator-selected digest of that exact external head file.
    after_commit : callable, optional
        Host-only test hook after durable checkpoint, before response.

    Notes
    -----
    This reference does not establish outside custody. An author-run store
    remains PEER, even when a different UID protects it from the producer.
    """

    def __init__(self, configuration: Configuration, retained_path: Path, retained_sha256: str,
                 after_commit: Callable[[], None] | None = None) -> None:
        """Open existing state under the class's explicit host-selected inputs."""
        self.configuration = configuration
        require(not retained_path.resolve().is_relative_to(configuration.store_path), "retained head must be outside operator store")
        raw = retained_path.read_bytes()
        require(sha(raw) == retained_sha256, "operator retained head pin differs")
        self.retained = strict_loads(raw)
        self.key = load_key(configuration)
        self.ledger = configuration.store_path / "ledger.jsonl"
        self.witness = LedgerWitness(self.ledger, self.key, configuration.observer_key)
        self.after_commit = after_commit
        self._guard(self.retained)
        self.head = self.witness.signed_head()

    def _guard(self, retained: dict[str, Any]) -> None:
        """Refuse missing/config-changed/restored state before any operation."""
        state = self.configuration.store_path
        require(stat.S_ISDIR(state.lstat().st_mode), "operator store type differs")
        require(state.stat().st_uid == os.getuid(), "operator store owner differs")
        require(state.stat().st_mode & 0o077 == 0, "operator store permissions differ")
        require(secure_file(state / "configuration.sha256") == self.configuration.digest.encode("ascii"), "operator restart configuration differs")
        raw = secure_file(self.ledger)
        require(len(raw) <= MAX_HISTORY, "operator ledger exceeds finite limit")
        verify_ledger_head(self.ledger, retained, self.configuration.witness_key)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        """Serialize validation, receipt append and response snapshot."""
        path = self.configuration.store_path / "operator.lock"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "a+b") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            yield

    def _checkpoint(self, history: Path, entries: list[dict[str, Any]]) -> dict[str, Any]:
        """Replay exact acknowledged checkpoints while refusing divergent retries."""
        interval, _ = checked_identity(entries, self.configuration.observer_key)
        if len(entries) > 1:
            _verify_terminal_intents(entries)
        receipts = read_ledger(self.ledger, self.configuration.witness_key)
        found = [item for item in receipts if _matches(item, interval, entries)]
        if found:
            return {**found[0]["checkpoint"], "ledgerReceipt": found[0]}
        return self.witness.checkpoint(history, max_ledger_bytes=MAX_HISTORY)

    def handle(self, raw: bytes) -> bytes:
        """Return a signed exact-history response after durable receipt commit.

        Parameters
        ----------
        raw : bytes
            Bounded canonical request containing full history bytes.

        Returns
        -------
        bytes
            Signed reply with checkpoint, full receipt log and current head.
        """
        operation, history_bytes = decode_request(raw)
        entries = history_entries(history_bytes)
        checked_identity(entries, self.configuration.observer_key)
        with self._locked(), TemporaryDirectory(dir=self.configuration.store_path) as directory:
            self._guard(self.head)
            history = Path(directory) / "submitted.jsonl"
            history.write_bytes(history_bytes)
            checkpoint = self._operation(operation, history, entries)
            self.head = self.witness.signed_head()
            self._committed()
            payload = {"format": FORMAT, "operation": operation, "historySha256": sha(history_bytes),
                       "checkpoint": checkpoint, "ledgerHead": self.head, "ledgerHex": self.ledger.read_bytes().hex()}
            return canonical({"payload": payload, "keyid": self.key.public_hex, "signature": self.key.sign(REPLY_DOMAIN, payload)})

    def _operation(self, operation: str, history: Path, entries: list[dict[str, Any]]) -> dict[str, Any]:
        """Keep recovery's retained begin distinct from new terminal signing."""
        if operation == "latest":
            return self.witness.latest_checkpoint(history)
        return self._checkpoint(history, entries)

    def _committed(self) -> None:
        """Invoke only a host-supplied fault hook, never request data."""
        if self.after_commit is not None:
            self.after_commit()

    def export(self) -> dict[str, Any]:
        """Export verified public receipt bytes and a current signed head."""
        with self._locked():
            self._guard(self.head)
            return {"format": FORMAT, "ledgerHex": self.ledger.read_bytes().hex(), "head": self.witness.signed_head(), "witnessScope": "PEER"}
