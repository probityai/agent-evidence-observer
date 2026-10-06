"""Public-key-only authorization client with retained-prefix verification."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from probity_observer.crypto import canonical, strict_loads, verify_signature
from probity_observer.history import verify_checkpoint
from probity_witness_operator.protocol import HEX_DIGEST, exact_fields, exchange, history_entries, require, sha
from probity_witness_operator.store import absolute_path, public_key

from .protocol import FORMAT, REPLY_DOMAIN, checkpoint_prefix, request_bytes


class AuthorizationClient:
    """Use an operator-selected endpoint, public key, configuration and prefix."""

    def __init__(self, socket_path: Path, witness_key: str, server_uid: int,
                 configuration_digest: str, retained_checkpoint: dict[str, Any], timeout: float = 5) -> None:
        """Capture explicit public pins without opening an operator key or store."""
        self._socket_path = absolute_path(str(socket_path))
        self._public_hex = public_key(witness_key)
        require(type(server_uid) is int and 0 <= server_uid < 2**32, "authorization server UID differs")
        require(isinstance(configuration_digest, str) and HEX_DIGEST.fullmatch(configuration_digest) is not None, "authorization configuration digest differs")
        require(0 < timeout <= 30, "authorization timeout differs")
        self._server_uid, self._configuration_digest, self._timeout = server_uid, configuration_digest, timeout
        self._retained = canonical(retained_checkpoint)

    @property
    def public_hex(self) -> str:
        """Return the selected public pin without loading a private signer."""
        return self._public_hex

    @property
    def retained_checkpoint(self) -> dict[str, Any]:
        """Return public retention bytes for a separately protected host store."""
        return strict_loads(self._retained)

    def configuration_error(self, workspace: Path, history: Path) -> str | None:
        """Keep the operator endpoint outside the broker's writable tree."""
        return "authorization endpoint must be outside workspace" if self._socket_path.is_relative_to(workspace) else None

    def _operation(self, operation: str, history_path: Path) -> dict[str, Any]:
        """Check peer, response signature, exact bytes, configuration and prefix."""
        history = history_path.read_bytes()
        raw = exchange(self._socket_path, self._server_uid, self._timeout, request_bytes(operation, history))
        reply = strict_loads(raw)
        require(canonical(reply) == raw, "authorization reply bytes differ")
        exact_fields(reply, {"payload", "keyid", "signature"}, "authorization reply envelope differs")
        require(reply["keyid"] == self.public_hex, "authorization reply key differs")
        payload = reply["payload"]
        verify_signature(self.public_hex, REPLY_DOMAIN, payload, reply["signature"])
        exact_fields(payload, {"format", "operation", "historySha256", "configurationDigest", "checkpoint"}, "authorization reply fields differ")
        require(payload["format"] == FORMAT and payload["operation"] == operation, "authorization reply operation differs")
        require(payload["historySha256"] == sha(history), "authorization reply history differs")
        require(payload["configurationDigest"] == self._configuration_digest, "authorization reply configuration differs")
        entries = history_entries(history)
        checkpoint_prefix(entries, self.retained_checkpoint, self.public_hex)
        checkpoint_prefix(entries, payload["checkpoint"], self.public_hex)
        verify_checkpoint(entries, payload["checkpoint"], self.public_hex)
        require(history_path.read_bytes() == history, "authorization history changed during request")
        self._retained = canonical(payload["checkpoint"])
        return payload["checkpoint"]

    def checkpoint(self, history_path: Path) -> dict[str, Any]:
        """Return a durably retained exact authorization checkpoint."""
        return self._operation("checkpoint", history_path)

    def latest_checkpoint(self, history_path: Path) -> dict[str, Any]:
        """Return the existing exact checkpoint; never create or reset state."""
        return self._operation("latest", history_path)
