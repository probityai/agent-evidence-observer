"""Public-key-only broker witness client; no signer or store reset API."""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

from probity_observer.crypto import VerificationError, canonical, strict_loads

from .protocol import peer_uid, receive, request_bytes, require, send, verify_reply
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
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                stream.settimeout(self._timeout)
                stream.connect(str(self._socket_path))
                require(peer_uid(stream) == self._server_uid, "IPC server UID differs")
                send(stream, raw)
                return receive(stream)
        except OSError as exc:
            raise VerificationError("witness IPC unavailable") from exc

    def _operation(self, operation: str, history_path: Path) -> dict[str, Any]:
        """Verify exact history, key, registered receipt and retained prefix."""
        history = history_path.read_bytes()
        reply = self._exchange(request_bytes(operation, history))
        payload = verify_reply(reply, operation, history, self.public_hex, self._observer_key, self.retained_head)
        require(history_path.read_bytes() == history, "history changed during witness request")
        self._retained = canonical(payload["ledgerHead"])
        return payload["checkpoint"]

    def checkpoint(self, history_path: Path) -> dict[str, Any]:
        """Return a verified durably recorded begin or terminal checkpoint."""
        return self._operation("checkpoint", history_path)

    def latest_checkpoint(self, history_path: Path) -> dict[str, Any]:
        """Return the verified retained begin for interrupted broker recovery."""
        return self._operation("latest", history_path)
