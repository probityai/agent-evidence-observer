"""Retain a host's separately selected target-reader publication decision."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

PROFILE = 'probity-target-process-recovery-v1'


def gate(packet: Path, pins: Path, policy: dict, reader: Path, output: Path) -> dict:
    """Run an installed reader against immutable selected pins and retain every outcome."""
    output.mkdir(parents=True, exist_ok=False)
    raw = pins.read_bytes()
    selected = output / 'selected-pins.json'
    selected.write_bytes(raw)
    selected.chmod(0o400)
    report = {'decision': 'refuse', 'profile': PROFILE, 'plannedAttempts': 7, 'reason': None, 'readerReturncode': None}
    if set(policy) != {'profile', 'pinsSha256', 'plannedAttempts'} or policy['profile'] != PROFILE or type(policy['plannedAttempts']) is not int or policy['plannedAttempts'] != 7 or hashlib.sha256(raw).hexdigest() != policy['pinsSha256']:
        report['reason'] = 'host-selection-differs'
    else:
        report = execute(packet, selected, reader, output, report)
    (output / 'host-policy.json').write_text(json.dumps(policy, indent=2) + '\n')
    (output / 'gate-report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def execute(packet: Path, selected: Path, reader: Path, output: Path, report: dict) -> dict:
    """Keep child errors/timeouts distinct from selected-reader success."""
    command = [str(reader.resolve()), str(packet.resolve()), '--pins-file', str(selected.resolve())]
    (output / 'launch.json').write_text(json.dumps({'command': command, 'timeoutSeconds': 15}, indent=2) + '\n')
    try:
        child = subprocess.run(command, capture_output=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        (output / 'reader.stdout').write_bytes(getattr(error, 'stdout', None) or b'')
        (output / 'reader.stderr').write_bytes(getattr(error, 'stderr', None) or b'')
        report['reason'] = type(error).__name__
        return report
    (output / 'reader.stdout').write_bytes(child.stdout)
    (output / 'reader.stderr').write_bytes(child.stderr)
    report['readerReturncode'] = child.returncode
    if child.returncode != 0:
        report['reason'] = 'reader-refused'
        return report
    return admit(child.stdout, report)


def admit(raw: bytes, report: dict) -> dict:
    """Require selected profile, denominator, bounded success and scope before publication."""
    try:
        value = json.loads(raw)
    except ValueError:
        report['reason'] = 'reader-output-malformed'
        return report
    if not isinstance(value, dict):
        report['reason'] = 'reader-output-malformed'
        return report
    if value.get('profile') == PROFILE and value.get('status') == 'verified' and type(value.get('plannedAttempts')) is int and value['plannedAttempts'] == 7 and value.get('witnessScope') == 'PEER':
        report.update(decision='publish', reason='selected-complete-bounded-report')
    else:
        report['reason'] = 'reader-selection-differs'
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('packet', type=Path)
    parser.add_argument('--pins-file', type=Path, required=True)
    parser.add_argument('--policy-file', type=Path, required=True)
    parser.add_argument('--reader', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    decision = gate(args.packet, args.pins_file, json.loads(args.policy_file.read_bytes()), args.reader, args.output)
    print(json.dumps(decision, indent=2))
    raise SystemExit(0 if decision['decision'] == 'publish' else 1)
