"""Retain a bounded installed-reader run and fail closed before publication."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

COMMANDS = {'langgraph': 'probity-langgraph-read', 'pydantic': 'probity-pydantic-read'}
DURABLE_COMMAND = 'probity-langgraph-durable-read'


def unique_names(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse ambiguous JSON objects in host policy and reader reports."""
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('duplicate JSON name: ' + name)
        result[name] = value
    return result


def read_json(raw: bytes) -> Any:
    """Parse exact JSON bytes with duplicate-name detection."""
    return json.loads(raw, object_pairs_hook=unique_names)


def write_json(path: Path, value: Any) -> None:
    """Retain an ordinary JSON receipt."""
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def durable_shape(selection: dict[str, Any]) -> None:
    """Require the separately reviewed additive durable reader/profile/population."""
    if selection['reader'] != 'langgraph-durable':
        raise ValueError('unsupported durable installed reader')
    if selection['profile'] != 'probity-langgraph-durable-restart-v0':
        raise ValueError('unsupported durable profile')
    if type(selection['plannedAttempts']) is not int or selection['plannedAttempts'] != 6:
        raise ValueError('durable plannedAttempts must be six')


def selection_shape(selection: dict[str, Any]) -> None:
    """Preserve original v1 enums; explicitly select additive durable schema v2."""
    if selection['schema'] == 'probity-framework-host-gate-v2':
        durable_shape(selection)
        return
    if selection['schema'] != 'probity-framework-host-gate-v1':
        raise ValueError('unknown host policy schema')
    if selection['reader'] not in COMMANDS:
        raise ValueError('unsupported installed reader')
    count = selection['plannedAttempts']
    if type(count) is not int or count < 1:
        raise ValueError('plannedAttempts must be a positive integer')


def selected_command(selection: dict[str, Any]) -> str:
    """Resolve a reviewed command after policy validation, never from packet data."""
    if selection['schema'] == 'probity-framework-host-gate-v2':
        return DURABLE_COMMAND
    return COMMANDS[selection['reader']]


def select(args: argparse.Namespace) -> dict[str, Any]:
    """Check the outside selection and freeze its exact pins for the child."""
    packet = args.packet.resolve(strict=True)
    policy = args.policy.resolve(strict=True)
    if policy.is_relative_to(packet):
        raise ValueError('policy must be outside the producer packet')
    raw = policy.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.policy_sha256:
        raise ValueError('host policy digest differs')
    selection = read_json(raw)
    selection_shape(selection)
    pins = args.pins.resolve(strict=True)
    if pins.is_relative_to(packet):
        raise ValueError('pins must be outside the producer packet')
    pin_raw = pins.read_bytes()
    if hashlib.sha256(pin_raw).hexdigest() != selection['pinsSha256']:
        raise ValueError('selected pins digest differs')
    read_json(pin_raw)
    (args.output / 'host-policy.json').write_bytes(raw)
    (args.output / 'selected-pins.json').write_bytes(pin_raw)
    return selection


def capture(command: list[str], timeout: int, output: Path) -> int:
    """Bound the child and preserve both streams even on refusal or timeout."""
    with (output / 'reader.stdout').open('wb') as stdout:
        with (output / 'reader.stderr').open('wb') as stderr:
            try:
                child = subprocess.run(command, stdout=stdout, stderr=stderr,
                                       timeout=timeout, check=False)
                code = child.returncode
            except subprocess.TimeoutExpired:
                code = 124
    write_json(output / 'child-status.json', {'returncode': code, 'timeoutSeconds': timeout})
    return code


def require_report(output: Path, selection: dict[str, Any], code: int) -> None:
    """Admit evidence only when child exit and bounded report agree."""
    if code != 0:
        raise ValueError('installed reader did not exit zero')
    raw = (output / 'reader.stdout').read_bytes()
    report = read_json(raw)
    if report['status'] != 'verified' or report['profile'] != selection['profile']:
        raise ValueError('reader status or selected profile differs')
    if type(report['plannedAttempts']) is not int or report['plannedAttempts'] != selection['plannedAttempts']:
        raise ValueError('selected denominator differs')
    if not isinstance(report['records'], list) or len(report['records']) != selection['plannedAttempts']:
        raise ValueError('reader attempt population differs')
    (output / 'report.json').write_bytes(raw)


def run(args: argparse.Namespace) -> int:
    """Produce fresh retained receipts and a publication decision."""
    args.output.mkdir()  # Existing output, including symlinks, must refuse.
    try:
        selection = select(args)
        executable = args.reader_bin / selected_command(selection)
        command = [str(executable.resolve(strict=True)), str(args.packet.resolve()),
                   '--pins-file', str((args.output / 'selected-pins.json').resolve())]
        write_json(args.output / 'launch.json', {'command': command})
        code = capture(command, args.timeout, args.output)
        require_report(args.output, selection, code)
        decision = {'status': 'admitted', 'decision': 'publish-selected-bounded-record',
                    'policySha256': args.policy_sha256,
                    'scope': 'Record integrity; per-case failures remain. Outside adoption and custody are separate.'}
    except (ValueError, KeyError, TypeError, OSError) as error:
        decision = {'status': 'refused', 'reason': str(error)}
    write_json(args.output / 'gate.json', decision)
    print(json.dumps(decision))
    return 0 if decision['status'] == 'admitted' else 1


def main() -> int:
    """Run a selected installed framework reader before result publication."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packet', type=Path, required=True)
    parser.add_argument('--pins', type=Path, required=True)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--reader-bin', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=60, choices=range(1, 301), metavar='1..300')
    args = parser.parse_args()
    try:
        return run(args)
    except FileExistsError:
        print('gate refused: output already exists', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
