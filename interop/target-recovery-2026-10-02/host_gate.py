"""Retain a host's separately selected target-reader publication decision."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

PROFILE = 'probity-target-process-recovery-v1'
CASES = ['restart-ready', 'crash-after-intent', 'crash-inside-effect', 'crash-after-effect', 'concurrent-intent', 'missing-store', 'changed-configuration']
NONCLAIMS = ['power-loss', 'general-exactly-once', 'remote-identity', 'independent-custody', 'production-containment']


def unique_names(pairs: list[tuple[str, Any]]) -> dict:
    """Refuse duplicated object names rather than interpreting the last one."""
    value = {}
    for name, child in pairs:
        if name in value:
            raise ValueError('duplicate-json-name')
        value[name] = child
    return value


def nonfinite(value: str) -> None:
    """Refuse nonfinite constants outside finite JSON evidence."""
    raise ValueError('nonfinite-json-' + value)


def decode(raw: bytes) -> Any:
    """Parse ordinary JSON while preserving type and name distinctions."""
    return json.loads(raw, object_pairs_hook=unique_names, parse_constant=nonfinite)


def select(packet: Path, pins: Path, policy: Path, digest: str, output: Path) -> None:
    """Require externally selected raw policy and pins before freezing child inputs."""
    root = packet.resolve(strict=True)
    policy_path, pins_path = policy.resolve(strict=True), pins.resolve(strict=True)
    if policy_path.is_relative_to(root) or pins_path.is_relative_to(root):
        raise ValueError('selection-must-be-outside-packet')
    raw_policy, raw_pins = policy_path.read_bytes(), pins_path.read_bytes()
    if hashlib.sha256(raw_policy).hexdigest() != digest:
        raise ValueError('host-policy-digest-differs')
    selected = decode(raw_policy)
    if not isinstance(selected, dict) or set(selected) != {'profile', 'pinsSha256', 'plannedAttempts'}:
        raise ValueError('host-policy-fields-differ')
    if selected['profile'] != PROFILE or type(selected['plannedAttempts']) is not int or selected['plannedAttempts'] != 7 or hashlib.sha256(raw_pins).hexdigest() != selected['pinsSha256']:
        raise ValueError('host-selection-differs')
    decode(raw_pins)
    (output / 'host-policy.json').write_bytes(raw_policy)
    (output / 'selected-pins.json').write_bytes(raw_pins)
    (output / 'selected-pins.json').chmod(0o400)


def gate(packet: Path, pins: Path, policy: Path, digest: str, reader: Path, output: Path) -> dict:
    """Retain the complete selected-reader outcome and refuse on every invalid path."""
    output.mkdir(parents=True, exist_ok=False)
    report = {'decision': 'refuse', 'profile': PROFILE, 'plannedAttempts': 7, 'reason': None, 'readerReturncode': None, 'policySha256': digest}
    try:
        select(packet, pins, policy, digest, output)
        execute(packet, output / 'selected-pins.json', reader, output, report)
    except (ValueError, OSError, TypeError, KeyError) as error:
        report['reason'] = str(error)
    (output / 'gate-report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def execute(packet: Path, selected: Path, reader: Path, output: Path, report: dict) -> None:
    """Bound child time and output retention, preserving errors and timeout streams."""
    command = [str(reader.resolve(strict=True)), str(packet.resolve()), '--pins-file', str(selected.resolve())]
    (output / 'launch.json').write_text(json.dumps({'command': command, 'timeoutSeconds': 15}, indent=2) + '\n')
    with (output / 'reader.stdout').open('wb') as stdout, (output / 'reader.stderr').open('wb') as stderr:
        try:
            child = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=15, check=False)
            code = child.returncode
        except subprocess.TimeoutExpired:
            code = 124
    report['readerReturncode'] = code
    if code != 0:
        report['reason'] = 'reader-refused'
        return
    admit((output / 'reader.stdout').read_bytes(), report)


def counters(value: dict) -> None:
    """Preserve the selected bounded population and explicit case dispositions."""
    expected = {'plannedAttempts': 7, 'completedEffects': 3, 'incompleteRefusals': 2, 'startupRefusals': 2, 'targetProcesses': 14}
    for name, count in expected.items():
        if type(value.get(name)) is not int or value[name] != count:
            raise ValueError('reader-population-differs')
    if not isinstance(value.get('records'), list) or [row['id'] for row in value['records']] != CASES:
        raise ValueError('reader-case-population-differs')


def admit(raw: bytes, report: dict) -> None:
    """Require finite typed selected scope and complete output before publication."""
    value = decode(raw)
    if not isinstance(value, dict):
        raise ValueError('reader-output-malformed')
    if value.get('profile') != PROFILE or value.get('status') != 'verified' or value.get('witnessScope') != 'PEER' or value.get('doesNotAssert') != NONCLAIMS:
        raise ValueError('reader-selection-differs')
    counters(value)
    report.update(decision='publish', reason='selected-complete-bounded-report')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('packet', type=Path)
    parser.add_argument('--pins-file', type=Path, required=True)
    parser.add_argument('--policy-file', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--reader', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    decision = gate(args.packet, args.pins_file, args.policy_file, args.policy_sha256, args.reader, args.output)
    print(json.dumps(decision, indent=2))
    raise SystemExit(0 if decision['decision'] == 'publish' else 1)
