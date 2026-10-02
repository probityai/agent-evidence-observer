"""Host selection refusals run a real separately launched reader."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))
from host_gate import gate as selected_gate, admit


def gate(packet, pins, policy, reader, output):
    # Tests independently freeze raw host selections outside the producer packet.
    outside = output.parent
    policy_path = outside / (output.name + "-policy.json")
    policy_path.write_text(json.dumps(policy))
    pins_path = outside / (output.name + "-pins.json")
    pins_path.write_bytes(pins.read_bytes())
    return selected_gate(packet, pins_path, policy_path, hashlib.sha256(policy_path.read_bytes()).hexdigest(), reader, output)


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


@pytest.mark.parametrize('change', [lambda x: x['records'].pop(), lambda x: x['doesNotAssert'].pop(), lambda x: x.update(witnessScope='HOST'), lambda x: x.update(plannedAttempts=True)])
def test_host_refuses_malformed_success_population(packet, change):
    report = json.loads((packet / 'report.json').read_bytes())
    change(report)
    with pytest.raises(ValueError):
        admit(json.dumps(report).encode(), {})


def test_host_refuses_duplicate_json_success_names(packet):
    raw = (packet / 'report.json').read_bytes()
    raw = raw[:-1] + b',"status":"verified"}'
    with pytest.raises(ValueError, match='duplicate-json-name'):
        admit(raw, {})


def test_host_refuses_producer_owned_selection(packet, policy, tmp_path):
    policy_path = tmp_path / 'policy.json'
    policy_path.write_text(json.dumps(policy))
    result = selected_gate(packet, packet / 'consumer-pins.json', policy_path, hashlib.sha256(policy_path.read_bytes()).hexdigest(), Path('/does-not-exist'), tmp_path / 'receipts')
    assert result['reason'] == 'selection-must-be-outside-packet'


def test_host_refuses_changed_policy_bytes(packet, policy, tmp_path):
    pins = tmp_path / 'pins.json'
    pins.write_bytes((packet / 'consumer-pins.json').read_bytes())
    policy_path = tmp_path / 'policy.json'
    policy_path.write_text(json.dumps(policy))
    result = selected_gate(packet, pins, policy_path, '0' * 64, Path('/does-not-exist'), tmp_path / 'receipts')
    assert result['reason'] == 'host-policy-digest-differs'
