"""Materialize the original eight reviewed source selections for a clean host.

This is trusted installation setup, not candidate execution. Repository names,
exact revisions and every tracked-file hash come from the original fixed public
selection. Candidate bytes cannot select a repository, revision or build script.
"""

from __future__ import annotations

import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from trust import SOURCE_SHA256, read_json, refuse, sha256, validate_sources, write_json

PROFILE = Path(__file__).resolve().parent


def checkout(name: str, component: dict[str, Any], root: Path, logs: Path) -> None:
    """Clone and detach one selected public source, preserving raw Git streams."""
    target = root / name
    commands = [
        ["git", "clone", "--quiet", "https://github.com/" + component["repository"] + ".git", str(target)],
        ["git", "-C", str(target), "checkout", "--detach", component["head"]],
    ]
    for index, command in enumerate(commands):
        result = subprocess.run(command, capture_output=True, timeout=180)
        prefix = logs / (name + "-" + str(index))
        prefix.with_suffix(".stdout").write_bytes(result.stdout)
        prefix.with_suffix(".stderr").write_bytes(result.stderr)
        write_json(prefix.with_suffix(".process.json"), {"command": command, "returnCode": result.returncode})
        if result.returncode != 0:
            refuse("selected public source materialization failed")


def main() -> None:
    """Prepare all frozen sources in parallel, then verify all tracked bytes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--logs", type=Path, required=True)
    args = parser.parse_args()
    if sha256((PROFILE / "SOURCE-SELECTION.json").read_bytes()) != SOURCE_SHA256:
        refuse("original component source selection differs")
    args.output.mkdir()
    args.logs.mkdir()
    selection = read_json(PROFILE / "SOURCE-SELECTION.json")
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(checkout, name, component, args.output.resolve(), args.logs.resolve())
                   for name, component in selection["components"].items()]
        for future in futures:
            future.result()
    validate_sources(PROFILE, args.output)
    write_json(args.logs / "source-byte-verification.json", {
        "sourceSelectionSha256": SOURCE_SHA256,
        "components": {name: {"head": component["head"], "verifiedFiles": len(component["files"])}
                       for name, component in selection["components"].items()},
    })


if __name__ == "__main__":
    main()
