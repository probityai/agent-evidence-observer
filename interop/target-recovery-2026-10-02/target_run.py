"""Execute every selected target hard-exit/reopen case over real local HTTP."""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
import probity_observer
from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant, utc_clock
from probity_observer.crypto import SigningKey, canonical
from probity_observer.ticket_service import MAX_BODY, TicketStore

from target_common import CASES, NONCLAIMS, PROFILE, load, require, sha, write

ACTIVE: list[tuple[subprocess.Popen, Path, int]] = []


def cleanup() -> None:
    """Terminate and reap owned process groups even when execution raises."""
    while ACTIVE:
        process, private, ordinal = ACTIVE.pop()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                stdout, stderr = process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate(timeout=2)
            write(private / f'cleanup-{ordinal}.json', {'pid': process.pid, 'returncode': process.returncode, 'stdoutHex': stdout.hex(), 'stderrHex': stderr.hex(), 'reason': 'abnormal-execution-cleanup'})


def exchange(url: str, candidate: dict | None = None) -> dict:
    """Retain exact HTTP request/response bytes, including broken-response outcome."""
    started = time.monotonic_ns()
    request = Request(url, data=None if candidate is None else canonical(candidate), headers={'Content-Type': 'application/json'})
    try:
        try:
            response = urlopen(request, timeout=5)
        except HTTPError as error:
            response = error
        with response:
            raw = response.read(MAX_BODY + 1)
            require(len(raw) <= MAX_BODY, 'http-response-limit')
            result = {'status': response.code, 'responseHex': raw.hex(), 'error': None}
    except (OSError, EOFError) as error:
        result = {'status': None, 'responseHex': None, 'error': type(error).__name__}
    return {'url': url, 'requestHex': None if candidate is None else canonical(candidate).hex(), 'startedNs': started, 'endedNs': time.monotonic_ns(), **result}


def start(private: Path, store: TicketStore, head: dict, ordinal: int, fault: str = 'none', changed: bool = False, timeout: float = 10) -> tuple[subprocess.Popen, dict]:
    """Retain launch and wait for concrete listener readiness or startup refusal."""
    config = private / f'worker-{ordinal}.json'
    ready = private / f'ready-{ordinal}.json'
    refusal = private / f'refusal-{ordinal}.json'
    request = asdict(store.request)
    if changed:
        request['principal_id'] = 'changed-principal'
    secret = store.key.private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
    write(config, {'store': str(store.path.resolve()), 'request': request, 'policy': asdict(store.policy), 'servicePrivateHex': secret, 'retainedHead': head, 'readyFile': str(ready.resolve()), 'refusalFile': str(refusal.resolve())})
    config.chmod(0o600)
    command = [sys.executable, str(Path(__file__).with_name('target_worker.py')), str(config.resolve()), '--fault', fault]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    ACTIVE.append((process, private, ordinal))
    deadline = time.monotonic() + timeout
    try:
        while not ready.exists() and not refusal.exists() and process.poll() is None:
            require(time.monotonic() < deadline, 'target-startup-timeout')
            time.sleep(0.02)
        result = load(private, ready.name) if ready.exists() else load(private, refusal.name)
    except BaseException:
        cleanup()
        raise
    return process, {'ordinal': ordinal, 'pid': process.pid, 'fault': fault, 'result': result}


def stop(process: subprocess.Popen, record: dict, expected: int | None = None) -> None:
    """Retain real process exit code and stderr without leaving a target alive."""
    if expected is not None:
        process.wait(timeout=10)
    else:
        process.send_signal(signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=10)
    record.update(returncode=process.returncode, stdoutHex=stdout.hex(), stderrHex=stderr.hex())
    require(process.returncode == (expected if expected is not None else -signal.SIGTERM), 'target-exit-code')


def selected(root: Path, private: Path, run_id: str, name: str) -> tuple[dict, TicketStore]:
    """Initialize once and freeze distinct host keys and exact grant before launch."""
    issuer, service = SigningKey.generate(), SigningKey.generate()
    content = b'{"status":"DONE"}'
    request = ActionRequest(run_id, name, 'request-' + name, 'tenant', 'principal', 'ticket-update', '/work/tickets/' + name, sha(content))
    policy = GrantPolicy(issuer.public_hex, max_validity_seconds=3600)
    now = utc_clock()
    grant = issue_grant(request, issuer, issued_at=now, expires_at=now + timedelta(seconds=3600))
    store = TicketStore(private / 'target.sqlite', request, policy, service)
    initial = store.initialize()
    return {'id': name, 'request': asdict(request), 'policy': asdict(policy), 'serviceKey': service.public_hex, 'grant': grant, 'contentHex': content.hex(), 'initial': initial}, store


def concurrent_dispatch(url: str, candidate: dict) -> list[dict]:
    """Start eight HTTP callers together against one pending native intent."""
    barrier = threading.Barrier(8)
    def dispatch(_: int) -> dict:
        barrier.wait(timeout=5)
        return exchange(url + '/dispatch', candidate)
    with ThreadPoolExecutor(max_workers=8) as pool:
        return list(pool.map(dispatch, range(8)))


def _execute(root: Path, private: Path, case: dict, store: TicketStore) -> dict:
    """Crash and reopen the actual target, then retain all dispatch and readbacks."""
    name = case['id']
    candidate = {k: case[k] for k in ('request', 'grant', 'contentHex')}
    fault = {'crash-after-intent': 'after-intent', 'crash-inside-effect': 'inside-effect-transaction', 'crash-after-effect': 'after-effect'}.get(name, 'none')
    processes, calls = [], []
    process, launch = start(private, store, case['initial']['receipt'], 1, fault)
    processes.append(launch)
    if fault != 'none':
        calls.append(exchange(launch['result']['url'] + '/dispatch', candidate))
        stop(process, launch, {'after-intent': 74, 'inside-effect-transaction': 75, 'after-effect': 76}[fault])
    else:
        stop(process, launch)
    head = store.readback()['receipt']
    intermediate = store.readback()
    if name == 'missing-store':
        store.path.unlink()
    process, launch = start(private, store, head, 2, fault='concurrent-window' if name == 'concurrent-intent' else 'none', changed=name == 'changed-configuration')
    processes.append(launch)
    if name in {'missing-store', 'changed-configuration'}:
        stop(process, launch, 78)
        return {'processes': processes, 'http': calls, 'intermediate': intermediate, 'final': None, 'snapshot': None}
    url = launch['result']['url']
    calls.append(exchange(url + '/tickets/tenant/' + name))
    if name == 'concurrent-intent':
        calls.extend(concurrent_dispatch(url, candidate))
    else:
        calls.append(exchange(url + '/dispatch', candidate))
    calls.append(exchange(url + '/tickets/tenant/' + name))
    stop(process, launch)
    recovery = store.recover() if name in {'crash-after-intent', 'crash-inside-effect'} else None
    final = store.readback()
    snapshot = name + '.sqlite'
    shutil.copyfile(store.path, root / snapshot)
    return {'processes': processes, 'http': calls, 'intermediate': intermediate, 'final': final, 'recovery': recovery, 'snapshot': snapshot}


def execute(root: Path, private: Path, case: dict, store: TicketStore) -> dict:
    """Guarantee owned target cleanup on every exceptional execution path."""
    try:
        return _execute(root, private, case, store)
    finally:
        cleanup()


def run(root: Path, revision: str) -> dict:
    """Retain source selection, complete finite population and offline reconstruction."""
    from target_reader import verify_saved
    root.mkdir(parents=True, exist_ok=False)
    private = root.parent / (root.name + '-host-private')
    private.mkdir(mode=0o700)
    run_id = 'target-' + uuid.uuid4().hex
    selections = []
    for name in CASES:
        case_private = private / name
        case_private.mkdir(mode=0o700)
        selections.append((selected(root, case_private, run_id, name), case_private))
    sources = {}
    base = Path(probity_observer.__file__).parent
    own = Path(__file__).parent
    for path in [base / name for name in ('ticket_service.py', 'crypto.py', 'authorization.py')] + [own / name for name in ('target_common.py', 'target_worker.py', 'target_run.py', 'target_reader.py')]:
        destination = root / 'sources' / path.name
        destination.parent.mkdir(exist_ok=True)
        destination.write_bytes(path.read_bytes())
        sources[path.name] = sha(path.read_bytes())
    plan = {'profile': PROFILE, 'runId': run_id, 'sourceRevision': revision, 'observerVersion': importlib.metadata.version('agent-evidence-observer'), 'python': sys.version, 'selectedTime': utc_clock().isoformat(), 'cases': [pair[0] for pair, _ in selections], 'sources': sources, 'witnessScope': 'PEER', 'doesNotAssert': NONCLAIMS, 'parallelDispatches': 8}
    write(root / 'plan-before-run.json', plan)
    try:
        for (case, store), case_private in selections:
            write(root / (case['id'] + '.json'), execute(root, case_private, case, store))
    finally:
        # Host keys stay outside the public retained packet; no reader receives them.
        for config in private.glob('*/worker-*.json'):
            config.unlink()
    manifest = {str(p.relative_to(root)): sha(p.read_bytes()) for p in sorted(root.rglob('*')) if p.is_file()}
    write(root / 'artifact-manifest.json', manifest)
    pins = {'profile': PROFILE, 'planSha256': sha((root / 'plan-before-run.json').read_bytes()), 'artifactManifestSha256': sha((root / 'artifact-manifest.json').read_bytes()), 'evaluationTime': utc_clock().isoformat()}
    write(root / 'consumer-pins.json', pins)
    report = verify_saved(root, pins)
    write(root / 'report.json', report)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--source-revision', required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.output, args.source_revision), indent=2))
