"""Installed CLI for the unchanged, source-selected LangGraph packet reader."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from lg_common import PacketError, decode
from lg_reader import verify_saved

LOGGER = logging.getLogger(__name__)


def main() -> None:
    """Reconstruct a selected historical packet using the original native reader.

    The required ``--pins-file`` supplies a consumer-selected plan digest,
    artifact-manifest digest and historical evaluation time. This command
    never selects the producer's convenience pin file automatically. The
    verification semantics are entirely those of :func:`lg_reader.verify_saved`;
    packaging adds no authorization or custody claim.

    Returns
    -------
    None
        Write the reconstructed native report to standard output on success.

    Raises
    ------
    SystemExit
        Exit with status one for a native :class:`lg_common.PacketError`, an
        unreadable input or invalid JSON. Argument errors exit with status two.
        Other malformed inputs also propagate a nonzero process exit.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--pins-file", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = verify_saved(args.output, decode(args.pins_file.read_bytes()))
    except (PacketError, OSError, ValueError) as error:
        reason = str(error) if isinstance(error, PacketError) else type(error).__name__
        LOGGER.warning("LangGraph reader refused: %s", reason)
        print(json.dumps({"status": "refused", "reason": reason}))
        raise SystemExit(1) from error
    print(json.dumps(report, indent=2, allow_nan=False))
