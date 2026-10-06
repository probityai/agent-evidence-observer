"""Explicitly initialized, privately retained finite authorization history."""

from __future__ import annotations

import fcntl
import os
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

from probity_observer.authorization import ActionRequest, GrantPolicy
from probity_observer.crypto import SigningKey, canonical, digest, strict_loads
from probity_observer.history import GENESIS
from probity_observer.protected_dispatch import CONFIG_DOMAIN
from probity_witness_operator.protocol import HEX_DIGEST, exact_fields, require, sha
from probity_witness_operator.store import absolute_path, flush_directory, load_key, public_key, secure_file, write_private

from .protocol import FORMAT, REPLY_DOMAIN, checkpoint_prefix, decode_request, journal_entries


@dataclass(frozen=True)
class AuthorizationConfiguration:
    """Immutable operator-selected role, exact action, root, endpoint and state."""

    key_path: Path
    store_path: Path
    socket_path: Path
    client_uid: int
    dispatch: dict[str, Any]
    before_root: str
    digest: str

    @property
    def witness_key(self) -> str:
        """Return the operator's exact public witness pin."""
        return self.dispatch["witnessKey"]

    @classmethod
    def read(cls, path: Path, expected_sha256: str) -> AuthorizationConfiguration:
        """Require externally pinned exact configuration before loading any secret."""
        raw = path.read_bytes()
        require(sha(raw) == expected_sha256, "authorization configuration pin differs")
        value = strict_loads(raw)
        exact_fields(value, {"format", "keyPath", "storePath", "socketPath", "clientUid", "dispatchConfiguration", "beforeRoot"}, "authorization configuration fields differ")
        require(value["format"] == FORMAT, "authorization configuration format differs")
        require(type(value["clientUid"]) is int and 0 <= value["clientUid"] < 2**32, "authorization client UID differs")
        dispatch = value["dispatchConfiguration"]
        fields = {"request", "policy", "observerKey", "witnessKey", "executionDigest"}
        exact_fields(dispatch, fields | ({"decisionDigest"} if "decisionDigest" in dispatch else set()), "authorization dispatch fields differ")
        ActionRequest(**dispatch["request"])
        policy = GrantPolicy(**dispatch["policy"])
        observer, witness = public_key(dispatch["observerKey"]), public_key(dispatch["witnessKey"])
        require(len({policy.issuer_key, observer, witness}) == 3, "authorization role keys must differ")
        for field in ("executionDigest", "decisionDigest"):
            if field in dispatch and dispatch[field] is not None:
                require(isinstance(dispatch[field], str) and HEX_DIGEST.fullmatch(dispatch[field]) is not None, "authorization configured digest differs")
        root = value["beforeRoot"]
        require(isinstance(root, str) and HEX_DIGEST.fullmatch(root) is not None, "authorization initial root differs")
        return cls(absolute_path(value["keyPath"]), absolute_path(value["storePath"]), absolute_path(value["socketPath"]), value["clientUid"], dispatch, root, expected_sha256)


def _checkpoint(entries: list[dict[str, Any]], key: SigningKey) -> dict[str, Any]:
    """Keep the existing checkpoint domain and exact signed field bytes."""
    payload = {"count": len(entries), "head": entries[-1]["hash"] if entries else GENESIS}
    return {**payload, "keyid": key.public_hex, "signature": key.sign("probity-checkpoint-v0", payload)}


def initialize(configuration: AuthorizationConfiguration) -> dict[str, Any]:
    """Create fresh private state exclusively; restart never calls this function."""
    key = load_key(configuration)
    configuration.store_path.mkdir(mode=0o700)
    checkpoint = _checkpoint([], key)
    state = {"format": FORMAT, "configurationSha256": configuration.digest, "historyHex": "", "checkpoint": checkpoint}
    write_private(configuration.store_path / "state.json", canonical(state))
    flush_directory(configuration.store_path.parent)
    return checkpoint


class AuthorizationStore:
    """Witness one selected dispatch journal without receiving a workload path.

    The store authenticates recorded order and observer statements. It cannot
    independently establish grant entitlement, target truth or wall-clock truth.
    Those checks remain with the gateway, target and separately selected reader.
    """

    def __init__(self, configuration: AuthorizationConfiguration, retained_path: Path,
                 retained_sha256: str, after_commit: Callable[[int], None] | None = None) -> None:
        """Open existing state under an explicit externally retained checkpoint."""
        self.configuration = configuration
        require(not retained_path.resolve().is_relative_to(configuration.store_path), "authorization retained checkpoint must be outside store")
        raw = retained_path.read_bytes()
        require(sha(raw) == retained_sha256, "authorization retained checkpoint pin differs")
        self.retained = strict_loads(raw)
        self.key = load_key(configuration)
        self.after_commit = after_commit
        self._read(self.retained)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        """Serialize checkpoint validation, replacement and acknowledgment."""
        descriptor = os.open(self.configuration.store_path / "operator.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "a+b") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            yield

    def _read(self, retained: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
        """Refuse missing, reconfigured, truncated, forked or rolled-back state."""
        directory = self.configuration.store_path
        metadata = directory.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.getuid(), "authorization store owner or type differs")
        require(metadata.st_mode & 0o077 == 0, "authorization store permissions differ")
        value = strict_loads(secure_file(directory / "state.json"))
        exact_fields(value, {"format", "configurationSha256", "historyHex", "checkpoint"}, "authorization store fields differ")
        require(value["format"] == FORMAT and value["configurationSha256"] == self.configuration.digest, "authorization restart configuration differs")
        raw = bytes.fromhex(value["historyHex"])
        require(raw.hex() == value["historyHex"], "authorization store encoding differs")
        entries = journal_entries(raw, self.configuration.dispatch, self.configuration.before_root) if raw else []
        checkpoint_prefix(entries, retained, self.configuration.witness_key)
        checkpoint_prefix(entries, value["checkpoint"], self.configuration.witness_key)
        require(value["checkpoint"]["count"] == len(entries), "authorization store checkpoint is not current")
        return raw, value["checkpoint"]

    def _persist(self, raw: bytes, checkpoint: dict[str, Any]) -> None:
        """Replace one canonical private state atomically and flush its directory."""
        directory = self.configuration.store_path
        descriptor, name = tempfile.mkstemp(prefix=".authorization-", dir=directory)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(canonical({"format": FORMAT, "configurationSha256": self.configuration.digest, "historyHex": raw.hex(), "checkpoint": checkpoint}))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, directory / "state.json")
            flush_directory(directory)
        finally:
            temporary.unlink(missing_ok=True)

    def handle(self, raw: bytes) -> bytes:
        """Return an exact signed response only after durable witness retention."""
        operation, submitted = decode_request(raw)
        entries = journal_entries(submitted, self.configuration.dispatch, self.configuration.before_root)
        with self._locked():
            previous, checkpoint = self._read(self.retained)
            require(submitted.startswith(previous), "authorization history does not extend store")
            if operation == "latest":
                require(submitted == previous, "authorization latest history differs from store")
            elif submitted != previous:
                checkpoint = _checkpoint(entries, self.key)
                self._persist(submitted, checkpoint)
                self.retained = checkpoint
                if self.after_commit is not None:
                    self.after_commit(len(entries))
            payload = {"format": FORMAT, "operation": operation, "historySha256": sha(submitted), "configurationDigest": digest(CONFIG_DOMAIN, self.configuration.dispatch), "checkpoint": checkpoint}
            return canonical({"payload": payload, "keyid": self.key.public_hex, "signature": self.key.sign(REPLY_DOMAIN, payload)})

    def export(self) -> dict[str, Any]:
        """Export public journal bytes and checkpoint after the same restart guard."""
        with self._locked():
            raw, checkpoint = self._read(self.retained)
            return {"historyHex": raw.hex(), "checkpoint": checkpoint}
