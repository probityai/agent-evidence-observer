"""Real target lifecycle controls and reselected semantic packet refusals."""
from __future__ import annotations

import copy
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))
from target_common import CASES, load, sha, write
from target_reader import verify_saved
import target_run


@pytest.fixture(scope='session')
def fresh(tmp_path_factory):
    root = tmp_path_factory.mktemp('native') / 'packet'
    report = target_run.run(root, '0' * 40)
    return root, report


def reseal(root: Path) -> dict:
    manifest = load(root, 'artifact-manifest.json')
    for name in manifest:
        manifest[name] = sha((root / name).read_bytes())
    (root / 'artifact-manifest.json').unlink()
    write(root / 'artifact-manifest.json', manifest)
    pins = load(root, 'consumer-pins.json')
    pins['planSha256'] = sha((root / 'plan-before-run.json').read_bytes())
    pins['artifactManifestSha256'] = sha((root / 'artifact-manifest.json').read_bytes())
    return pins


def replace_json(root: Path, name: str, mutation):
    value = load(root, name)
    mutation(value)
    (root / name).unlink()
    write(root / name, value)


def test_real_target_process_population(fresh):
    root, report = fresh
    assert report['targetProcesses'] == 14
    assert report['completedEffects'] == 3
    assert report['incompleteRefusals'] == 2
    assert report['startupRefusals'] == 2
    assert [row['id'] for row in report['records']] == list(CASES)
    assert verify_saved(root, load(root, 'consumer-pins.json')) == report
    assert not list(root.rglob('*worker*.json'))


MUTATIONS = [
    ('restart-ready.json', lambda x: x['processes'][1].update(pid=x['processes'][0]['pid'])),
    ('restart-ready.json', lambda x: x['processes'][0].update(returncode=0)),
    ('restart-ready.json', lambda x: x['processes'][0].update(stderrHex='00')),
    ('crash-after-intent.json', lambda x: x['processes'][0].update(returncode=0)),
    ('crash-inside-effect.json', lambda x: x['processes'][0].update(fault='after-effect')),
    ('crash-after-effect.json', lambda x: x['processes'][0].update(returncode=75)),
    ('restart-ready.json', lambda x: x['processes'][0].update(ordinal=True)),
    ('restart-ready.json', lambda x: x['processes'][1]['result'].update(pid=False)),
    ('restart-ready.json', lambda x: x['http'].pop()),
    ('restart-ready.json', lambda x: x['http'][0].update(status=False)),
    ('restart-ready.json', lambda x: x['http'][1].update(url='http://127.0.0.1:1/dispatch')),
    ('restart-ready.json', lambda x: x['http'][1].update(requestHex='7b7d')),
    ('restart-ready.json', lambda x: x['http'][1].update(endedNs=x['http'][1]['startedNs'])),
    ('crash-after-effect.json', lambda x: x['http'][0].update(status=200)),
    ('crash-after-intent.json', lambda x: x['http'][2].update(status=200)),
    ('crash-inside-effect.json', lambda x: x.update(recovery=None)),
    ('crash-after-effect.json', lambda x: x['final'].update(revision=0)),
    ('restart-ready.json', lambda x: x['final'].update(contentHex='00')),
    ('restart-ready.json', lambda x: x['final'].update(effectId='0' * 64)),
    ('restart-ready.json', lambda x: x['final']['receipt']['payload'].update(witnessScope='HOST')),
    ('missing-store.json', lambda x: x['processes'][1].update(returncode=0)),
    ('changed-configuration.json', lambda x: x.update(final={})),
    ('restart-ready.json', lambda x: x.update(snapshot='crash-after-effect.sqlite')),
    ('concurrent-intent.json', lambda x: x['http'][1].update(startedNs=x['http'][-2]['endedNs'])),
    ('plan-before-run.json', lambda x: x['cases'].pop()),
    ('plan-before-run.json', lambda x: x.update(parallelDispatches=True)),
    ('plan-before-run.json', lambda x: x.update(witnessScope='HOST')),
    ('plan-before-run.json', lambda x: x['doesNotAssert'].pop()),
]


@pytest.mark.parametrize('name,mutation', MUTATIONS)
def test_reselected_semantic_mutation(fresh, tmp_path, name, mutation):
    root = tmp_path / 'packet'
    shutil.copytree(fresh[0], root)
    replace_json(root, name, mutation)
    pins = reseal(root)
    with pytest.raises((ValueError, KeyError, TypeError)):
        verify_saved(root, pins)


def test_rollback_signed_store_refused_by_retained_prefix(fresh, tmp_path):
    root = tmp_path / 'packet'
    shutil.copytree(fresh[0], root)
    path = root / 'crash-after-effect.sqlite'
    database = sqlite3.connect(path)
    try:
        database.execute('DELETE FROM events WHERE sequence=3')
        database.commit()
    finally:
        database.close()
    with pytest.raises(ValueError):
        verify_saved(root, reseal(root))


def test_wrong_external_pins_refused(fresh):
    pins = copy.deepcopy(load(fresh[0], 'consumer-pins.json'))
    pins['artifactManifestSha256'] = '0' * 64
    with pytest.raises(ValueError):
        verify_saved(fresh[0], pins)


def test_reader_requires_explicit_pins(fresh):
    process = subprocess.run([sys.executable, str(Path(target_run.__file__).with_name('target_reader.py')), str(fresh[0])], capture_output=True, timeout=10)
    assert process.returncode == 2
    assert b'--pins-file' in process.stderr


def test_startup_timeout_reaps_owned_process(monkeypatch, tmp_path):
    _, store = target_run.selected(tmp_path, tmp_path, 'timeout-run', 'restart-ready')
    actual = target_run.subprocess.Popen
    children = []
    def sleeping(command, **kwargs):
        process = actual([sys.executable, '-c', 'import time; time.sleep(30)'], **kwargs)
        children.append(process)
        return process
    monkeypatch.setattr(target_run.subprocess, 'Popen', sleeping)
    with pytest.raises(ValueError, match='target-startup-timeout'):
        target_run.start(tmp_path, store, store.readback()['receipt'], 1, timeout=0.05)
    assert children[0].poll() == -15
    receipt = load(tmp_path, 'cleanup-1.json')
    assert receipt['pid'] == children[0].pid
    assert receipt['reason'] == 'abnormal-execution-cleanup'


def test_http_exception_reaps_started_target(monkeypatch, tmp_path):
    private = tmp_path / 'host'
    private.mkdir()
    case, store = target_run.selected(tmp_path, private, 'failure-run', 'crash-after-intent')
    def failed_exchange(*args, **kwargs):
        raise RuntimeError('forced-http-failure')
    monkeypatch.setattr(target_run, 'exchange', failed_exchange)
    with pytest.raises(RuntimeError, match='forced-http-failure'):
        target_run.execute(tmp_path, private, case, store)
    receipt = load(private, 'cleanup-1.json')
    assert receipt['returncode'] == -15
    assert target_run.ACTIVE == []


def test_cached_completion_cannot_be_relabelled_as_fresh_restart(fresh, tmp_path):
    from probity_observer.crypto import canonical
    root = tmp_path / 'packet'
    shutil.copytree(fresh[0], root)
    def mutation(attempt):
        attempt['intermediate'] = copy.deepcopy(attempt['final'])
        attempt['processes'][1]['result']['initial'] = copy.deepcopy(attempt['final'])
        attempt['http'][0]['responseHex'] = canonical(attempt['final']).hex()
    replace_json(root, 'restart-ready.json', mutation)
    with pytest.raises(ValueError, match='fresh-ready-before-dispatch'):
        verify_saved(root, reseal(root))
