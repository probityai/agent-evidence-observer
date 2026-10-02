"""Host selection refusals run a real separately launched reader."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))
from host_gate import gate


@pytest.fixture(scope='module')
def packet(tmp_path_factory):
    from target_run import run
    root = tmp_path_factory.mktemp('host-run') / 'packet'
    run(root, '0' * 40)
    return root


@pytest.fixture
def policy(packet):
    return {'profile': 'probity-target-process-recovery-v1', 'pinsSha256': hashlib.sha256((packet / 'consumer-pins.json').read_bytes()).hexdigest(), 'plannedAttempts': 7}


def executable(tmp_path, command):
    reader = tmp_path / 'reader'
    reader.write_text('#!/bin/sh\nexec ' + command + ' "$@"\n')
    reader.chmod(0o700)
    return reader


def test_host_accepts_actual_reader(packet, policy, tmp_path):
    reader = executable(tmp_path, str(Path(sys.executable).absolute()) + ' ' + str(Path(__file__).parents[1] / 'target_reader.py'))
    result = gate(packet, packet / 'consumer-pins.json', policy, reader, tmp_path / 'receipts')
    assert result['decision'] == 'publish'
    assert result['readerReturncode'] == 0
    retained = json.loads((tmp_path / 'receipts/reader.stdout').read_bytes())
    assert retained['completedEffects'] == 3
    assert retained['incompleteRefusals'] == 2


@pytest.mark.parametrize('field,value', [('profile', 'other'), ('pinsSha256', '0' * 64), ('plannedAttempts', False), ('plannedAttempts', 6)])
def test_host_refuses_changed_selection_without_launch(packet, policy, tmp_path, field, value):
    policy[field] = value
    result = gate(packet, packet / 'consumer-pins.json', policy, Path('/does-not-exist'), tmp_path / 'receipts')
    assert result['decision'] == 'refuse'
    assert result['reason'] == 'host-selection-differs'
    assert not (tmp_path / 'receipts/launch.json').exists()


def test_reader_child_failure_is_retained(packet, policy, tmp_path):
    reader = executable(tmp_path, '/bin/false')
    result = gate(packet, packet / 'consumer-pins.json', policy, reader, tmp_path / 'receipts')
    assert result['decision'] == 'refuse'
    assert result['readerReturncode'] == 1
    assert (tmp_path / 'receipts/reader.stderr').is_file()


def test_reader_manifest_refusal_is_host_refusal(packet, policy, tmp_path):
    import shutil
    changed = tmp_path / 'changed'
    shutil.copytree(packet, changed)
    with (changed / 'restart-ready.json').open('ab') as stream:
        stream.write(b' ')
    reader = executable(tmp_path, str(Path(sys.executable).absolute()) + ' ' + str(Path(__file__).parents[1] / 'target_reader.py'))
    result = gate(changed, changed / 'consumer-pins.json', policy, reader, tmp_path / 'receipts')
    assert result['decision'] == 'refuse'
    assert result['readerReturncode'] == 1
    assert b'artifact-digest' in (tmp_path / 'receipts/reader.stderr').read_bytes()
