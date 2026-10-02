"""Consumer CI entrypoint for the existing bounded offline native readers."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import re
import signal
import subprocess
import sys
from pathlib import Path

FORMAT = "probity-native-consumer-selection-v1"
ROOT_FILES = ("LICENSE", "pyproject.toml")
EVAL = "interop/evaluation-contract-2026-10-01/"
A2A = "interop/a2a-native-2026-10-02/"
FILES = {
    "inspect-execution": ROOT_FILES
    + tuple(
        EVAL + n
        for n in (
            "evaluation_contract.py",
            "inspect_contract.py",
            "inspect_execution.py",
        )
    ),
    "a2a": ROOT_FILES
    + (
        EVAL + "evaluation_contract.py",
        A2A + "a2a_contract.py",
        A2A + "a2a_verify.py",
        A2A + "sdk-source-pins.json",
        A2A + "SDK-LICENSE",
    ),
}
COUNTERS = (
    "planned",
    "started",
    "complete",
    "scored",
    "task_passed",
    "task_failed",
    "failed",
    "missing",
    "unknown_start",
    "incomplete",
)
LIMIT = 8 * 1024 * 1024


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def _pairs(items: list) -> dict:
    value = {}
    for key, item in items:
        _require(key not in value, "duplicate_json_member")
        value[key] = item
    return value


def _float(raw: str) -> float:
    value = float(raw)
    _require(math.isfinite(value), "nonfinite_json")
    return value


def decode(raw: bytes) -> dict:
    _require(0 < len(raw) <= LIMIT, "json_size")
    value = json.loads(
        raw,
        object_pairs_hook=_pairs,
        parse_float=_float,
        parse_constant=lambda _: _require(False, "nonfinite_json"),
    )
    _require(type(value) is dict and bool(value), "json_object")
    return value


def _digest(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _write(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def _plain(path: Path) -> Path:
    absolute = path.absolute()
    _require(absolute.resolve() == absolute, "symlink_or_noncanonical_path")
    return absolute


def _outside(path: Path, folder: Path) -> None:
    _require(
        not path.is_relative_to(folder), "consumer_selection_or_output_inside_packet"
    )


def describe_sources(checkout: Path, profile: str) -> dict:
    """Expose hashes for review, without selecting or trusting native inputs."""
    checkout = _plain(checkout)
    _require(profile in FILES, "unsupported_profile")
    package = Path(__file__).resolve().parent
    return {
        "reader_sources": {
            name: sha(_plain(checkout / name).read_bytes()) for name in FILES[profile]
        },
        "installed_sources": {
            path.name: sha(_plain(path).read_bytes())
            for path in sorted(package.glob("*.py"))
        },
    }


def _selection(
    checkout: Path, packet: Path, selection: Path, selection_sha256: str
) -> tuple[dict, bytes]:
    _require(_digest(selection_sha256), "selection_digest")
    _outside(selection, packet)
    raw = selection.read_bytes()
    _require(sha(raw) == selection_sha256, "selection_pin_mismatch")
    value = decode(raw)
    _require(
        set(value)
        == {
            "format",
            "profile",
            "selection_id",
            "reader_revision",
            "python_minor",
            "reader_sources",
            "installed_sources",
            "native_pins",
        },
        "selection_fields",
    )
    _require(
        value["format"] == FORMAT and value["profile"] in FILES, "selection_profile"
    )
    _require(
        type(value["selection_id"]) is str and 0 < len(value["selection_id"]) <= 256,
        "selection_id",
    )
    _require(
        type(value["reader_revision"]) is str
        and re.fullmatch(r"[0-9a-f]{40}", value["reader_revision"]) is not None,
        "reader_revision",
    )
    _require(
        value["python_minor"]
        == f"{sys.version_info.major}.{sys.version_info.minor}"
        == "3.12",
        "python_minor",
    )
    actual = describe_sources(checkout, value["profile"])
    for key in ("reader_sources", "installed_sources"):
        _require(
            type(value[key]) is dict
            and all(_digest(v) for v in value[key].values())
            and value[key] == actual[key],
            key + "_mismatch",
        )
    return value, raw


def _command(checkout: Path, packet: Path, output: Path, value: dict) -> list[str]:
    pins = value["native_pins"]
    _require(type(pins) is dict, "native_pin_shape")
    if value["profile"] == "inspect-execution":
        expected = {
            "expected_declaration_sha256",
            "expected_sources_sha256",
            "expected_bindings_sha256",
            "expected_plan_sha256",
            "expected_history_sha256",
        }
        _require(
            set(pins) == expected and all(_digest(v) for v in pins.values()),
            "native_pin_shape",
        )
        _write(output / "selected-native-pins.json", pins)
        return [
            sys.executable,
            str(checkout / EVAL / "inspect_execution.py"),
            str(packet),
            "--verify",
            "--pins-file",
            str(output / "selected-native-pins.json"),
        ]
    _require(
        set(pins) == {"artifacts", "plan_sha256", "history_sha256", "sources_sha256"}
        and type(pins["artifacts"]) is dict
        and bool(pins["artifacts"])
        and all(_digest(v) for v in pins["artifacts"].values())
        and all(
            _digest(pins[name])
            for name in ("plan_sha256", "history_sha256", "sources_sha256")
        ),
        "native_pin_shape",
    )
    _write(output / "selected-native-pins.json", pins["artifacts"])
    return [
        sys.executable,
        str(checkout / A2A / "a2a_verify.py"),
        str(packet),
        "--native-pins",
        str(output / "selected-native-pins.json"),
        "--plan-sha256",
        pins["plan_sha256"],
        "--history-sha256",
        pins["history_sha256"],
        "--sources-sha256",
        pins["sources_sha256"],
    ]


def _common(value: dict) -> None:
    _require(
        value.get("profile") == "probity-five-tier-result-reference-v0"
        and all(type(value.get(n)) is int and value[n] >= 0 for n in COUNTERS),
        "reader_report_profile",
    )
    _require(
        value["started"] + value["missing"] + value["unknown_start"] == value["planned"]
        and value["complete"]
        + value["failed"]
        + value["missing"]
        + value["unknown_start"]
        + value["incomplete"]
        == value["planned"]
        and value["scored"]
        == value["task_passed"] + value["task_failed"]
        <= value["complete"],
        "reader_report_counts",
    )
    _require(value.get("status", "valid") == "valid", "reader_report_refusal")


def _child(command: list[str], checkout: Path, output: Path, timeout: float) -> dict:
    # A new directory and exclusive stdout file prevent a stale report from passing.
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    with (
        (output / "reader-stdout.json").open("xb") as stdout,
        (output / "reader-stderr.txt").open("xb") as stderr,
    ):
        child = subprocess.Popen(
            command,
            cwd=checkout,
            env=env,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            _write(
                output / "child-status.json",
                {"status": "timeout", "exit_code": child.returncode},
            )
            raise ValueError("reader_timeout")
    _write(output / "child-status.json", {"status": "exited", "exit_code": code})
    _require(code == 0, "reader_child_failure")
    _require(0 < (output / "reader-stdout.json").stat().st_size <= LIMIT, "json_size")
    result = decode((output / "reader-stdout.json").read_bytes())
    _common(result)
    return result


def run(
    checkout: Path,
    packet: Path,
    selection: Path,
    output: Path,
    *,
    selection_sha256: str,
    timeout: float = 120,
) -> dict:
    """Recompute an existing packet; never execute a model, SDK or native workload."""
    _require(
        type(timeout) in (int, float) and math.isfinite(timeout) and timeout > 0,
        "reader_timeout_value",
    )
    checkout, packet, selection, output = map(
        _plain, (checkout, packet, selection, output)
    )
    _require(packet.is_dir() and checkout.is_dir(), "input_directory")
    _outside(output, packet)
    _require(not output.exists(), "reader_output_already_exists")
    output.mkdir()  # Parent must already exist, under the consumer's control.
    report = {
        "format": "probity-native-consumer-receipt-v1",
        "status": "refused",
        "claim": "selected-input-byte-consistency",
        "independent_custody": "not-established",
        "model_quality": "not-established",
        "python": sys.version.split()[0],
        "runtime_dependencies": {
            name: importlib.metadata.version(name)
            for name in ("cryptography", "cffi", "pycparser")
        },
    }
    try:
        # The legacy A2A reader does not follow its own symlink policy. Refuse all
        # links here, including unknown entries, before opening retained bytes.
        for path in packet.rglob("*"):
            _require(not path.is_symlink(), "packet_symlink")
        value, raw = _selection(checkout, packet, selection, selection_sha256)
        (output / "consumer-selection.json").write_bytes(raw)
        command = _command(checkout, packet, output, value)
        _write(
            output / "launch.json",
            {
                "command": command,
                "selection_sha256": selection_sha256,
                "timeout_seconds": timeout,
            },
        )
        result = _child(command, checkout, output, timeout)
        report.update(
            status="valid",
            profile=value["profile"],
            selection_id=value["selection_id"],
            selected_reader_revision=value["reader_revision"],
            reader_revision_authority="consumer-label-with-file-hashes-verified; not-git-signature-verification",
            selection_sha256=selection_sha256,
            reader_report_sha256=sha((output / "reader-stdout.json").read_bytes()),
            observer_distribution_version=importlib.metadata.version(
                "agent-evidence-observer"
            ),
            report=result,
        )
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        RecursionError,
        UnicodeError,
    ) as error:
        report.update(reason=str(error), error_type=type(error).__name__)
    _write(output / "report.json", report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-checkout", type=Path, required=True)
    parser.add_argument("--describe-sources", choices=tuple(FILES))
    parser.add_argument("--packet", type=Path)
    parser.add_argument("--selection", type=Path)
    parser.add_argument("--selection-sha256")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    if args.describe_sources:
        print(
            json.dumps(
                describe_sources(args.source_checkout, args.describe_sources),
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if not all((args.packet, args.selection, args.selection_sha256, args.output)):
        parser.error(
            "reading requires --packet, --selection, --selection-sha256 and --output"
        )
    try:
        report = run(
            args.source_checkout,
            args.packet,
            args.selection,
            args.output,
            selection_sha256=args.selection_sha256,
            timeout=args.timeout,
        )
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "valid" else 1
