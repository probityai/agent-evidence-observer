"""Public-key-only broker witness client; no signer or store reset API."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from probity_observer.crypto import VerificationError, canonical, strict_loads

from .protocol import exchange, request_bytes, require, verify_reply
from .store import absolute_path, public_key


class WitnessClient:
    """Connect a broker to a host-selected witness without its private key.

    Parameters
    ----------
    socket_path : Path
        Operator-owned Unix endpoint selected outside the packet.
    witness_key, observer_key : str
        Host-selected public pins.
    server_uid : int
        Kernel UID required at the other end of the socket.
    retained_head : dict
        Signed head independently acquired by the host.
    timeout : float
        Finite socket timeout in seconds.

    Notes
    -----
    Every reply must extend the last accepted signed prefix. These mechanics
    do not establish custody or full capture; local evidence remains PEER.
    """

    def __init__(self, socket_path: Path, witness_key: str, observer_key: str,
                 server_uid: int, retained_head: dict[str, Any], timeout: float = 5) -> None:
        """Capture public host pins without loading a private key or local ledger."""
        self._socket_path = absolute_path(str(socket_path))
        self._public_hex = public_key(witness_key)
        self._observer_key = public_key(observer_key)
        require(type(server_uid) is int, "IPC server UID type differs")
        require(0 <= server_uid < 2**32, "IPC server UID differs")
        require(0 < timeout <= 30, "IPC timeout differs")
        self._server_uid = server_uid
        self._retained = canonical(retained_head)
        self._timeout = timeout
        self._receipt_log: bytes | None = None

    @property
    def public_hex(self) -> str:
        """Return the selected public key without a signing operation."""
        return self._public_hex

    def configuration_error(self, workspace: Path, history: Path) -> str | None:
        """Keep a host-selected endpoint outside the writable workspace."""
        if self._socket_path.is_relative_to(workspace):
            return "witness endpoint must be outside the observed workspace"
        return None

    @property
    def retained_head(self) -> dict[str, Any]:
        """Return an immutable-byte copy for separate host persistence."""
        return strict_loads(self._retained)

    def _exchange(self, raw: bytes) -> bytes:
        """Authenticate the kernel server before sending history bytes."""
        return exchange(self._socket_path, self._server_uid, self._timeout, raw)

    def _operation(self, operation: str, history_path: Path) -> dict[str, Any]:
        """Verify exact history, key, registered receipt and retained prefix."""
        history = history_path.read_bytes()
        reply = self._exchange(request_bytes(operation, history))
        payload = verify_reply(reply, operation, history, self.public_hex, self._observer_key, self.retained_head)
        require(history_path.read_bytes() == history, "history changed during witness request")
        self._retained = canonical(payload["ledgerHead"])
        self._receipt_log = bytes.fromhex(payload["ledgerHex"])
        return payload["checkpoint"]

    def checkpoint(self, history_path: Path) -> dict[str, Any]:
        """Return a verified durably recorded begin or terminal checkpoint."""
        return self._operation("checkpoint", history_path)

    def latest_checkpoint(self, history_path: Path) -> dict[str, Any]:
        """Return the verified retained begin for interrupted broker recovery."""
        return self._operation("latest", history_path)

    def receipt_log(self, history_path: Path) -> bytes:
        """Refresh an exact durable checkpoint and return verified public receipts.

        The operator returns an existing receipt for an identical checkpoint
        retry. The refresh checks its current signed log against this client's
        retained prefix. No private signer or operator pathname is exported.
        """
        self._operation("checkpoint", history_path)
        if self._receipt_log is None:
            raise VerificationError("witness receipt proof is missing")
        return self._receipt_log
