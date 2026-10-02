"""Retain the actual installed0.0.1 refusal before the normal0.0.2 upgrade."""
from __future__ import annotations

import importlib.metadata
import json
import sys
import tempfile
from pathlib import Path

from test_durable_installed_reader import invoke, selected_durable_packet


def main(output: Path) -> None:
    """Require old version/command behavior without borrowing the candidate's CLI."""
    assert importlib.metadata.version("probity-langgraph-ticket-reader") == "0.0.1"
    assert not (Path(sys.executable).parent / "probity-langgraph-durable-read").exists()
    with tempfile.TemporaryDirectory() as directory:
        packet, pins = selected_durable_packet(Path(directory))
        result = invoke(packet, pins, "probity-langgraph-read")
    refusal = json.loads(result.stdout)
    assert result.returncode == 1 and refusal == {"status": "refused", "reason": "plan-profile"}
    with output.open("x") as stream:
        json.dump({"installedVersion": "0.0.1", "durableCommandAbsent": True, "historicalCommandExit": result.returncode, "durablePacketResult": refusal}, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
