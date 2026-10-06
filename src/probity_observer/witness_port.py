"""Public witness operations without a private signing key in the client."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .crypto import VerificationError


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
        """Authenticate the selected profile's existing retained checkpoint."""
        ...


class LedgerWitnessPort(WitnessPort, Protocol):
    """Supply full public receipt bytes for an acknowledged native history."""

    def receipt_log(self, history_path: Path) -> bytes:
        """Check the selected checkpoint and return its full signed receipt log."""
        ...


@dataclass(frozen=True)
class DispatchWitnessPorts:
    """Select one public witness key and two separately supplied checkpoint ports.

    The authorization port retains the grant-before-effect journal. The native
    port retains broker intervals and supplies their public receipt proof.
    Neither client needs a private signing key or a private witness pathname.
    These ports describe runtime boundaries, not independent operator custody.
    """

    public_key: str
    authorization: WitnessPort
    native: LedgerWitnessPort

    def __post_init__(self) -> None:
        """Refuse inferred or mismatched role pins before any target action."""
        if (
            not isinstance(self.public_key, str)
            or len(self.public_key) != 64
            or any(character not in "0123456789abcdef" for character in self.public_key)
        ):
            raise VerificationError("dispatch witness public key differs")
        if (
            self.authorization.public_hex != self.public_key
            or self.native.public_hex != self.public_key
        ):
            raise VerificationError("dispatch witness ports differ from the selected key")
