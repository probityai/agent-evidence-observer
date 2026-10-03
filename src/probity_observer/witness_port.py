"""Public witness operations without a private signing key in the client."""

from pathlib import Path
from typing import Any, Protocol


class WitnessPort(Protocol):
    """Describe the broker's checkpoint port, not operator custody.

    A local signer and a separately running client can implement this port.
    The host selects the public key. Returned checkpoints must bind to the
    submitted history before the broker receives them.
    """

    @property
    def public_hex(self) -> str:
        """Return the host-selected witness public key."""
        ...

    def configuration_error(self, workspace: Path, history: Path) -> str | None:
        """Return a local boundary configuration refusal, if applicable."""
        ...

    def checkpoint(self, history_path: Path) -> dict[str, Any]:
        """Authenticate and return a checkpoint for exact submitted history."""
        ...

    def latest_checkpoint(self, history_path: Path) -> dict[str, Any]:
        """Authenticate the retained begin used for interrupted recovery."""
        ...
