"""Linux Unix IPC with kernel peer authentication and finite framing."""

from __future__ import annotations

import errno
import logging
import os
import socket
import socketserver
import stat
from pathlib import Path
from typing import Any

from probity_observer.crypto import VerificationError, canonical

from .protocol import peer_uid, receive, require, send
from .store import OperatorStore

LOGGER = logging.getLogger(__name__)


def socket_parent(path: Path) -> None:
    """Require an operator-owned socket directory other users cannot replace."""
    parent = path.parent
    require(parent.resolve() == parent, "IPC socket directory has an alias")
    metadata = parent.stat()
    require(stat.S_ISDIR(metadata.st_mode), "IPC socket directory type differs")
    require(metadata.st_uid == os.getuid(), "IPC socket directory owner differs")
    require(metadata.st_mode & 0o022 == 0, "IPC socket directory is writable by peers")


def remove_stale_socket(path: Path) -> None:
    """Remove only an operator-owned refused endpoint, through an explicit CLI flag."""
    socket_parent(path)
    metadata = path.lstat()
    require(stat.S_ISSOCK(metadata.st_mode), "stale IPC path is not a socket")
    require(metadata.st_uid == os.getuid(), "stale IPC socket owner differs")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(1)
        require(stream.connect_ex(str(path)) == errno.ECONNREFUSED, "IPC socket is still active")
    require(path.lstat().st_ino == metadata.st_ino, "stale IPC socket changed")
    path.unlink()


class OperatorServer(socketserver.ThreadingUnixStreamServer):
    """Serve one immutable store configuration to a single allowed peer UID.

    Parameters
    ----------
    store : OperatorStore
        Host-selected signer, durable store and external retained head.

    Notes
    -----
    Socket permissions permit connections; SO_PEERCRED selects the peer.
    No TCP listener, request-selected reset or key export is provided.
    """

    daemon_threads = True
    block_on_close = False

    def __init__(self, store: OperatorStore) -> None:
        """Bind only the host-selected Unix endpoint after state verification."""
        self.store = store
        self._bound_inode: int | None = None
        path = store.configuration.socket_path
        socket_parent(path)
        super().__init__(str(path), _Handler)
        self._bound_inode = path.lstat().st_ino
        path.chmod(0o666)

    def server_close(self) -> None:
        """Close the owned socket without removing someone else's replacement."""
        path = self.store.configuration.socket_path
        super().server_close()
        if self._bound_inode is None:
            return
        if path.exists() and path.lstat().st_ino == self._bound_inode:
            path.unlink()


class _Handler(socketserver.BaseRequestHandler):
    """Refuse unauthenticated, interrupted and malformed requests finitely."""

    server: OperatorServer
    request: socket.socket

    def handle(self) -> None:
        """Authenticate the kernel peer before reading caller-supplied bytes."""
        self.request.settimeout(5)
        try:
            require(peer_uid(self.request) == self.server.store.configuration.client_uid, "IPC client UID differs")
            raw = self.server.store.handle(receive(self.request))
        except (VerificationError, ValueError, TypeError, KeyError, OSError, RecursionError):
            LOGGER.warning("witness IPC refused")
            raw = canonical({"status": "refused", "reason": "witness peer, framing, history or state differs"})
        self._reply(raw)

    def _reply(self, raw: bytes) -> None:
        """A disconnected client never changes the persisted checkpoint outcome."""
        try:
            send(self.request, raw)
        except OSError:
            LOGGER.warning("witness IPC reply interrupted")
