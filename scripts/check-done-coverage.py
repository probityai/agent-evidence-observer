"""Fail when any module of probity_observer.done is below 80 percent line coverage.

Run after ``coverage run --source=probity_observer.done -m pytest tests/done``.
"""

from __future__ import annotations

import json
import subprocess
import sys

FLOOR = 80.0


def main() -> int:
    report = json.loads(subprocess.run([sys.executable, "-m", "coverage", "json", "-o", "-"],
                                       check=True, capture_output=True, text=True).stdout)
    low = {name: data["summary"]["percent_covered"] for name, data in report["files"].items()
           if data["summary"]["percent_covered"] < FLOOR}
    for name, percent in sorted(report["files"].items()):
        print(f"{percent['summary']['percent_covered']:6.1f}  {name}")
    if not report["files"]:
        print("no coverage data")
        return 1
    for name, percent in sorted(low.items()):
        print(f"below {FLOOR:.0f} percent: {name} ({percent:.1f})")
    return 1 if low else 0


if __name__ == "__main__":
    sys.exit(main())
