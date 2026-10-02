"""Freeze external host policy before launching the separately installed reader."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path
from typing import Any

from .contract import (
    CASES,
    NONCLAIMS,
    PROFILE,
    decode,
    encode,
    plugin_order,
    require,
    same,
    sha,
    write,
)


def gate(
    reader: Path, packet: Path, policy: Path, policy_sha: str, output: Path
) -> dict[str, Any]:
    """Admit the selected population and retain child receipts."""
    require(reader.is_absolute() and reader.is_file(), "selected-reader-path")
    reader = reader.resolve()
    require(not reader.is_relative_to(packet.resolve()), "reader-inside-candidate")
    require(
        not policy.resolve().is_relative_to(packet.resolve()), "policy-inside-candidate"
    )
    require(
        not output.resolve().is_relative_to(packet.resolve()),
        "receipt-inside-candidate",
    )
    raw = policy.read_bytes()
    require(sha(raw) == policy_sha, "host-policy-bytes")
    output.mkdir(parents=True, exist_ok=False)
    frozen = output / "selected-policy.json"
    write(frozen, raw)
    command = [str(reader), str(packet.resolve()), "--pins-file", str(frozen.resolve())]
    write(
        output / "launch.json", encode({"command": command, "policySha256": policy_sha})
    )
    try:
        child = subprocess.run(command, capture_output=True, timeout=60, check=False)
    except subprocess.TimeoutExpired as error:
        write(output / "reader-stdout.bin", error.stdout or b"")
        write(output / "reader-stderr.bin", error.stderr or b"")
        record = {
            "profile": PROFILE,
            "publicationDecision": "refused",
            "reason": "reader-timeout",
            "returncode": None,
        }
    else:
        write(output / "reader-stdout.bin", child.stdout)
        write(output / "reader-stderr.bin", child.stderr)
        record = child_decision(child.returncode, child.stdout)
    write(output / "gate-result.json", encode(record))
    return record


def child_decision(code: int, stdout: bytes) -> dict[str, Any]:
    """Require exact reader population and a successful exit without coercion."""
    record = {
        "profile": PROFILE,
        "publicationDecision": "refused",
        "reason": "selected-reader-refused",
        "returncode": code,
    }
    if code != 0 or len(stdout) > 1024 * 1024:
        return record
    try:
        report = decode(stdout)
    except (ValueError, TypeError):
        return record
    if not isinstance(report, dict):
        return record
    try:
        check_report(report)
    except (ValueError, TypeError, KeyError):
        return record
    record.update(
        publicationDecision="admitted",
        reason="complete-selected-reference-population",
        reportSha256=sha(stdout),
    )
    return record


# Frozen finite reference population, independently enforced by the host wrapper.
ROWS = (
    ("complete", 1, 2, 1, 1, 3, 14, 0),
    ("complete", 0, 2, 1, 1, 3, 14, 0),
    ("complete", 0, 2, 1, 1, 3, 14, 0),
    ("error", 0, 1, 1, 0, 2, 11, 1),
    ("error", 1, 1, 1, 1, 2, 11, 1),
    ("complete", 1, 3, 2, 1, 5, 21, 1),
    ("complete", 1, 3, 2, 1, 5, 20, 0),
    ("error", 0, 2, 2, 0, 4, 18, 2),
    ("error", 0, 2, 2, 0, 4, 16, 0),
    ("complete", 1, 3, 2, 1, 5, 20, 0),
    ("complete", 1, 3, 2, 1, 5, 19, 0),
    ("incomplete", 1, 1, 1, 1, 2, 10, 0),
)
COUNTERS = (
    "taskStatus",
    "nativeRevision",
    "modelCalls",
    "toolCalls",
    "httpPosts",
    "nativeEvents",
    "capturedCallbacks",
    "observedOriginalToolErrorCallbacks",
)


def check_row(row: dict[str, Any], case: str, values: tuple[Any, ...]) -> None:
    expected = dict(zip(COUNTERS, values, strict=True))
    expected.update(case=case, pluginOrder=plugin_order(case))
    same(sorted(row), sorted([*expected, "elapsedNs", "cpuNs"]), "host-record-schema")
    for key, value in expected.items():
        same(row[key], value, "host-record-" + key)
    require(
        type(row["elapsedNs"]) is int and 0 < row["elapsedNs"] <= 120_000_000_000,
        "host-wall-budget",
    )
    require(
        type(row["cpuNs"]) is int and 0 <= row["cpuNs"] <= row["elapsedNs"],
        "host-cpu-budget",
    )


def check_report(report: dict[str, Any]) -> None:
    expected = {
        "profile": PROFILE,
        "status": "verified",
        "plannedAttempts": 12,
        "publicationDecision": "admit-complete-bounded-reference-population",
        "modelQuality": "not-evaluated",
        "custody": "same-operator; author-run synthetic HTTP service",
        "doesNotAssert": NONCLAIMS,
    }
    same(
        sorted(report),
        sorted([*expected, "records", "resources"]),
        "host-report-schema",
    )
    for key, value in expected.items():
        same(report[key], value, "host-report-" + key)
    require(
        isinstance(report["records"], list) and len(report["records"]) == 12,
        "host-record-population",
    )
    for case, values, row in zip(CASES, ROWS, report["records"], strict=True):
        check_row(row, case, values)
    resources = {
        key: sum(row[key] for row in report["records"])
        for key in ("modelCalls", "toolCalls", "httpPosts", "elapsedNs", "cpuNs")
    }
    same(report["resources"], resources, "host-resource-join")
    require(resources["elapsedNs"] <= 120_000_000_000, "host-total-budget")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--reader", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = gate(
        args.reader, args.packet, args.policy, args.policy_sha256, args.output
    )
    print(encode(report).decode())
    raise SystemExit(0 if report["publicationDecision"] == "admitted" else 1)
