"""Host-side isolated invocation under separately selected installed closure."""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "joint-recovery-2026-10-02"))
from joint_host_gate import reader_closure  # noqa: E402
from crash_common import NONCLAIMS, PROFILE, child_environment, load, require, same, write  # noqa: E402
from probity_observer.crypto import strict_loads  # noqa: E402


def consume(packet, pins, reader, selected_closure, output):
    """Refuse changed installation before launch; retain actual isolated streams."""
    root = packet.resolve(strict=True)
    reader = reader.absolute()
    for selection in (pins, selected_closure):
        require(not selection.resolve(strict=True).is_relative_to(root), "selection-must-be-outside-packet")
    require(not output.resolve().is_relative_to(root), "consumer-receipts-outside-packet")
    output.mkdir(parents=True, exist_ok=False)
    expected = load(selected_closure.parent, selected_closure.name)
    same(reader_closure(reader), expected, "reader-installed-closure")
    write(output / "selected-installed-closure.json", expected)
    write(output / "selected-pins.json", load(pins.parent, pins.name))
    command = [str(reader.parent / "python"), "-I", "-B", str(reader), str(root), "--pins-file", str(pins.resolve())]
    timed_out = False
    try:
        result = subprocess.run(command, env=child_environment(), capture_output=True, timeout=30, check=False)
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        stdout, stderr, returncode, timed_out = error.stdout or b"", error.stderr or b"", 124, True
    (output / "reader.stdout").write_bytes(stdout)
    (output / "reader.stderr").write_bytes(stderr)
    write(output / "reader.process.json", {"command": command, "environment": child_environment(),
                                           "returncode": returncode, "timedOut": timed_out})
    same(reader_closure(reader), expected, "reader-installed-closure-after-launch")
    require(returncode == 0 and not timed_out and stderr == b"", "installed-reader-outcome")
    report = strict_loads(stdout)
    same([report["profile"], report["status"], report["plannedAttempts"], report["releasedResults"], report["recoveryRefusals"]], [PROFILE, "verified", 4, 1, 3], "installed-reader-report")
    same([report["witnessScope"], report["doesNotAssert"], report["providerCalls"], report["independentCustody"]], ["PEER", NONCLAIMS, 0, "not-established"], "installed-reader-scope")
    decision = {"profile": PROFILE, "decision": "publish-scoped-evidence", "releasedResults": 1,
                "recoveryRefusals": 3, "scope": "same-operator installed replay; no outside adoption or independent custody"}
    write(output / "consumer-decision.json", decision)
    return report


def main():
    """Consume caller-owned pins and installed bytes without framework imports."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--pins-file", type=Path, required=True)
    parser.add_argument("--reader", type=Path, required=True)
    parser.add_argument("--selected-closure", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    from probity_observer.crypto import canonical
    print(canonical(consume(args.packet, args.pins_file, args.reader, args.selected_closure, args.output)).decode(), end="")


if __name__ == "__main__":
    main()
