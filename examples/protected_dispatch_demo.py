"""Run the measured protected-action socket boundary and retain its result."""

from __future__ import annotations

import argparse
from pathlib import Path

from probity_observer.crypto import canonical
from probity_observer.protected_isolation import run_protected_isolation


def main() -> int:
    """Exit successfully only when the actual protected boundary gate passes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--bwrap", type=Path)
    args = parser.parse_args()
    report = run_protected_isolation(args.output, bwrap=args.bwrap)
    print(canonical(report).decode("ascii"))
    return 0 if report["status"] == "probe-passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
