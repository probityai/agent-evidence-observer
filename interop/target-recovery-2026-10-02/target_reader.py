"""Reconstruct selected target restart evidence without the target's signing key."""
from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from probity_observer.authorization import ActionRequest, GrantPolicy, verify_grant
from probity_observer.crypto import VerificationError, canonical, strict_loads
from probity_observer.ticket_service import TicketStore, _checked, _state_schema, verify_ticket_result

from target_common import CASES, NONCLAIMS, PROFILE, load, read, require, sha


def exact(value: Any, expected: Any) -> bool:
    """Preserve JSON types so false never substitutes for zero."""
    return canonical(value) == canonical(expected)


def authenticated_readback(value: dict, case: dict) -> dict:
    """Authenticate bounded native response identity, phase and selected service key."""
    require(set(value) == {'tenantId', 'ticketId', 'contentHex', 'revision', 'effectId', 'receipt'}, 'readback-fields')
    payload = _checked(value['receipt'], case['serviceKey'])
    _state_schema(payload, receipt=True)
    require(type(value['revision']) is int and value['revision'] == payload['revision'], 'readback-revision')
    require(value['tenantId'] == 'tenant' and value['ticketId'] == case['id'] and value['effectId'] == payload['effectId'], 'readback-identity')
    require(exact(payload['request'], case['request']) and payload['authorityKey'] == case['policy']['issuer_key'], 'readback-authority')
    require(payload['witnessScope'] == 'PEER' and payload['coverage'] == 'one-native-ticket-row-and-service-events', 'readback-scope')
    require(value['contentHex'] == (case['contentHex'] if value['revision'] == 1 else None), 'readback-content')
    return payload


def check_processes(attempt: dict, name: str) -> None:
    """Require distinct actually captured target process identities and exact exits."""
    processes = attempt['processes']
    require(type(processes) is list and len(processes) == 2, 'process-population')
    expected = {'crash-after-intent': 74, 'crash-inside-effect': 75, 'crash-after-effect': 76}.get(name, -15)
    for ordinal, process in enumerate(processes, 1):
        require(set(process) == {'ordinal', 'pid', 'fault', 'result', 'returncode', 'stdoutHex', 'stderrHex'}, 'process-fields')
        require(type(process['pid']) is int and process['pid'] > 0 and type(process['ordinal']) is int and process['ordinal'] == ordinal, 'process-identity')
        require(process['result']['pid'] == process['pid'] and type(process['result']['pid']) is int, 'process-ready-pid')
        expected_exit = expected if ordinal == 1 else (78 if name in {'missing-store', 'changed-configuration'} else -15)
        require(type(process['returncode']) is int and process['returncode'] == expected_exit, 'process-exit')
        require(process['stdoutHex'] == '' and process['stderrHex'] == '', 'process-streams')
    require(processes[0]['pid'] != processes[1]['pid'], 'process-reuse')
    faults = {'crash-after-intent': 'after-intent', 'crash-inside-effect': 'inside-effect-transaction', 'crash-after-effect': 'after-effect'}
    require(processes[0]['fault'] == faults.get(name, 'none') and processes[1]['fault'] == ('concurrent-window' if name == 'concurrent-intent' else 'none'), 'selected-crash-point')


def check_http(attempt: dict, case: dict) -> list[dict]:
    """Bind captured HTTP bytes to exact selected request and reopened service."""
    exchanges = attempt['http']
    crash = case['id'].startswith('crash-')
    startup_refusal = case['id'] in {'missing-store', 'changed-configuration'}
    expected = 0 if startup_refusal else (10 if case['id'] == 'concurrent-intent' else 3) + int(crash)
    require(type(exchanges) is list and len(exchanges) == expected, 'http-population')
    decoded = []
    for index, exchange in enumerate(exchanges):
        require(set(exchange) == {'url', 'requestHex', 'startedNs', 'endedNs', 'status', 'responseHex', 'error'}, 'http-fields')
        require(type(exchange['startedNs']) is int and type(exchange['endedNs']) is int and 0 <= exchange['startedNs'] < exchange['endedNs'], 'http-time')
        process = attempt['processes'][0 if crash and index == 0 else 1]
        base = process['result']['url']
        require(exchange['url'] in {base + '/dispatch', base + '/tickets/tenant/' + case['id']}, 'http-endpoint')
        post = exchange['url'].endswith('/dispatch')
        require(exchange['requestHex'] == (canonical({k: case[k] for k in ('request', 'grant', 'contentHex')}).hex() if post else None), 'http-request')
        if crash and index == 0:
            require(exchange['status'] is None and exchange['responseHex'] is None and exchange['error'] in {'RemoteDisconnected', 'ConnectionResetError'}, 'crash-response')
            continue
        require(type(exchange['status']) is int and exchange['error'] is None, 'http-response')
        decoded.append({'post': post, 'status': exchange['status'], 'value': strict_loads(bytes.fromhex(exchange['responseHex']))})
    return decoded


def check_snapshot(root: Path, attempt: dict, case: dict) -> dict:
    """Replay service-signed SQLite rows/history read-only against retained prefix."""
    require(attempt['snapshot'] == case['id'] + '.sqlite', 'snapshot-name')
    raw = read(root, attempt['snapshot'])
    require(raw.startswith(b'SQLite format 3\x00'), 'snapshot-format')
    request, policy = ActionRequest(**case['request']), GrantPolicy(**case['policy'])
    public_key = SimpleNamespace(public_hex=case['serviceKey'])
    store = TicketStore(root / attempt['snapshot'], request, policy, public_key, retained_head=attempt['intermediate']['receipt'])
    database = sqlite3.connect((root / attempt['snapshot']).resolve().as_uri() + '?mode=ro', uri=True)
    try:
        state, content = store._load(database)
    finally:
        database.close()
    current = authenticated_readback(attempt['final'], case)
    require(exact(state, {k: current[k] for k in state}), 'snapshot-final-state')
    require(content == (None if attempt['final']['contentHex'] is None else bytes.fromhex(attempt['final']['contentHex'])), 'snapshot-native-content')
    return current


def check_completed(root: Path, attempt: dict, case: dict, http: list[dict], now: datetime) -> dict:
    """Verify retained completion, native revision and concurrent duplicate outcomes."""
    current = check_snapshot(root, attempt, case)
    require(current['phase'] == 'completed' and current['revision'] == 1 and current['eventCount'] == 3, 'completed-phase')
    posts = [exchange for exchange in http if exchange['post']]
    require(any(exchange['status'] == 200 for exchange in posts), 'completed-dispatch')
    if case['id'] == 'concurrent-intent':
        require(any(exchange['status'] == 409 for exchange in posts), 'concurrent-pending-refusal')
        intervals = [e for e in attempt['http'] if e['requestHex'] is not None]
        require(max(e['startedNs'] for e in intervals) < min(e['endedNs'] for e in intervals), 'concurrent-overlap')
    for exchange in posts:
        if exchange['status'] == 200:
            verify_ticket_result(exchange['value'], attempt['final'], ActionRequest(**case['request']), GrantPolicy(**case['policy']), case['serviceKey'], case['grant'], now=now)
        else:
            require(case['id'] == 'concurrent-intent' and exchange['status'] == 409 and exact(exchange['value'], {'status': 'refused', 'reason': 'ticket request, authority, state or framing differs'}), 'concurrent-refusal')
    require(exact(http[-1]['value'], attempt['final']) and http[-1]['status'] == 200, 'final-http-readback')
    return {'id': case['id'], 'outcome': 'completed', 'nativeRevision': 1, 'effectId': current['effectId'], 'targetProcesses': 2, 'dispatchResponses': [p['status'] for p in posts]}


def check_pending(root: Path, attempt: dict, case: dict, http: list[dict]) -> dict:
    """Keep interrupted native work incomplete and refuse every automatic retry."""
    intermediate = authenticated_readback(attempt['intermediate'], case)
    require(intermediate['phase'] == 'pending' and intermediate['revision'] == 0 and intermediate['eventCount'] == 2, 'pending-native-intent')
    require(http[0]['status'] == 200 and exact(http[0]['value'], attempt['intermediate']), 'pending-reopen-readback')
    require(http[1]['post'] and http[1]['status'] == 409 and exact(http[1]['value'], {'status': 'refused', 'reason': 'ticket request, authority, state or framing differs'}), 'pending-automatic-replay')
    require(exact(http[-1]['value'], attempt['intermediate']) and http[-1]['status'] == 200, 'pending-unchanged-after-refusal')
    current = check_snapshot(root, attempt, case)
    require(current['phase'] == 'incomplete' and current['revision'] == 0 and current['eventCount'] == 3, 'operator-incomplete')
    require(exact(attempt['recovery'], attempt['final']['receipt']), 'operator-recovery-receipt')
    return {'id': case['id'], 'outcome': 'incomplete-refused', 'nativeRevision': 0, 'effectId': current['effectId'], 'targetProcesses': 2, 'dispatchResponses': [409]}


def verify_case(root: Path, case: dict, now: datetime) -> dict:
    """Check the finite selected case and all process/HTTP/store relations."""
    require(set(case) == {'id', 'request', 'policy', 'serviceKey', 'grant', 'contentHex', 'initial'}, 'case-fields')
    attempt = load(root, case['id'] + '.json')
    check_processes(attempt, case['id'])
    initial = authenticated_readback(case['initial'], case)
    require(initial['phase'] == 'ready' and initial['eventCount'] == 1, 'initial-ready')
    verify_grant(case['grant'], ActionRequest(**case['request']), GrantPolicy(**case['policy']), now=now)
    require(exact(attempt['processes'][0]['result']['initial'], case['initial']), 'initial-target-state')
    http = check_http(attempt, case)
    if case['id'] in {'missing-store', 'changed-configuration'}:
        require(set(attempt) == {'processes', 'http', 'intermediate', 'final', 'snapshot'}, 'startup-refusal-fields')
        require(exact(attempt['intermediate'], case['initial']), 'startup-retained-state')
        require(attempt['final'] is None and attempt['snapshot'] is None, 'startup-refusal-effect')
        require(attempt['processes'][1]['result']['status'] == 'refused', 'startup-refusal')
        return {'id': case['id'], 'outcome': 'startup-refused', 'nativeRevision': 0, 'effectId': None, 'targetProcesses': 2, 'dispatchResponses': []}
    require(set(attempt) == {'processes', 'http', 'intermediate', 'final', 'recovery', 'snapshot'}, 'attempt-fields')
    require(exact(attempt['processes'][1]['result']['initial'], attempt['intermediate']), 'reopened-retained-state')
    if case['id'] in {'crash-after-intent', 'crash-inside-effect'}:
        return check_pending(root, attempt, case, http)
    require(attempt['recovery'] is None, 'completed-recovery')
    if case['id'] == 'crash-after-effect':
        require(exact(attempt['intermediate'], attempt['final']), 'cached-effect-unchanged')
    else:
        require(exact(attempt['intermediate'], case['initial']), 'fresh-ready-before-dispatch')
    require(http[0]['status'] == 200 and exact(http[0]['value'], attempt['intermediate']), 'completed-reopen-readback')
    return check_completed(root, attempt, case, http, now)


def verify_saved(root: Path, pins: dict) -> dict:
    """Require selected complete manifest and separately supplied consumer pins."""
    require(set(pins) == {'profile', 'planSha256', 'artifactManifestSha256', 'evaluationTime'} and pins['profile'] == PROFILE, 'pins-fields')
    require(sha(read(root, 'plan-before-run.json')) == pins['planSha256'] and sha(read(root, 'artifact-manifest.json')) == pins['artifactManifestSha256'], 'pins-digest')
    manifest = load(root, 'artifact-manifest.json')
    for name, selected_digest in manifest.items():
        require(sha(read(root, name)) == selected_digest, 'artifact-digest')
    plan = load(root, 'plan-before-run.json')
    require(set(plan) == {'profile', 'runId', 'sourceRevision', 'observerVersion', 'python', 'selectedTime', 'cases', 'sources', 'witnessScope', 'doesNotAssert', 'parallelDispatches'}, 'plan-fields')
    require(set(plan['sources']) == {'ticket_service.py', 'crypto.py', 'authorization.py', 'target_common.py', 'target_worker.py', 'target_run.py', 'target_reader.py'}, 'source-population')
    require(plan['profile'] == PROFILE and plan['witnessScope'] == 'PEER' and exact(plan['doesNotAssert'], NONCLAIMS), 'plan-scope')
    require(type(plan['parallelDispatches']) is int and plan['parallelDispatches'] == 8, 'parallel-selection')
    require([case['id'] for case in plan['cases']] == list(CASES), 'case-population')
    expected = {'plan-before-run.json'} | {name + '.json' for name in CASES} | {name + '.sqlite' for name in CASES if name not in {'missing-store', 'changed-configuration'}} | {'sources/' + name for name in plan['sources']}
    require(set(manifest) == expected, 'manifest-population')
    for name, selected_digest in plan['sources'].items():
        require(sha(read(root, 'sources/' + name)) == selected_digest, 'source-digest')
    now = datetime.fromisoformat(pins['evaluationTime'])
    rows = [verify_case(root, case, now) for case in plan['cases']]
    return {'profile': PROFILE, 'status': 'verified', 'plannedAttempts': 7, 'completedEffects': 3, 'incompleteRefusals': 2, 'startupRefusals': 2, 'targetProcesses': 14, 'records': rows, 'witnessScope': 'PEER', 'doesNotAssert': NONCLAIMS, 'interpretation': 'same-operator local SQLite/HTTP target process hard-exit and recovery; process evidence is unsigned runner testimony, not independent custody'}


def main() -> None:
    """Run the offline reader only with an explicit external pins selection."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('packet', type=Path)
    parser.add_argument('--pins-file', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify_saved(args.packet, load(args.pins_file.parent, args.pins_file.name))
    except (VerificationError, OSError, KeyError, TypeError, sqlite3.Error) as error:
        raise SystemExit('target recovery packet refused: ' + str(error)) from error
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
