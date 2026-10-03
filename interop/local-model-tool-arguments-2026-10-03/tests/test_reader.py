"""Reconstruct disclosed synthetic originals and attack exact evidence relations."""
import copy
import json
import logging
import os
from pathlib import Path

import pytest

import evidence_io as io
import execution_contract as execution
import protocol_builder as builder
import reader
import synthetic_packet
import task_matrix


@pytest.fixture
def packet(tmp_path):
    selected=os.environ.get('PROBITY_PRIOR_NATIVE_ZIP')
    if selected:
        archive=Path(selected)
    else:
        archive=builder.ROOT.parent/'local-model-vocabulary-2026-10-02/retained/native-37094901561.zip'
    protocol=json.loads((builder.ROOT/'protocol.json').read_bytes())
    root=tmp_path/'native'
    synthetic_packet.build(root,archive,protocol,task_matrix.PROTOCOL_COMMIT,task_matrix.PROTOCOL_SHA256)
    pins=json.loads((root/'consumer-pins.json').read_bytes())
    return root,pins,protocol


def verify(packet):
    return reader.verify(*packet,task_matrix.PROTOCOL_COMMIT,task_matrix.PROTOCOL_SHA256)


def resign(packet,path,value):
    root,pins,_=packet
    (root/path).write_bytes(io.encode(value))
    manifest=json.loads((root/'manifest.json').read_bytes());manifest[path]=io.digest((root/path).read_bytes())
    (root/'manifest.json').write_bytes(io.encode(manifest));pins['manifest']['sha256']=io.digest((root/'manifest.json').read_bytes())
    for name in ['declaration','terminal']:
        if path==name+'.json':pins[name]['sha256']=io.digest((root/path).read_bytes())


class TestReconstruction:
    class TestPassingCases:
        def test_selected_model_free_reader_exact_population(self,packet):
            result=verify(packet)
            assert result['population']=={'planned':128,'started':128,'scored':128,'error':0,'unsupported':0,'incomplete':0,'unknown-start':0}
            assert result['qualityDecision']=='admit-scoped-quality'
            assert result['executionMode']=='synthetic-control'
            assert result['preparationReuse']['nativeFiles']==31
            assert all(row['planned']==16 and row['plannedAbstentions']==8 and row['fullyCorrectPairs']==8 for row in result['quality'])

        def test_complete_parseable_length_return_keeps_scores_but_quality_failure(self,packet):
            root,_,protocol=packet;ident=protocol['order']['attemptIds'][0];name='calls/'+ident+'-returned.json';value=json.loads((root/name).read_bytes());value['response']['choices'][0]['finish_reason']='length';resign(packet,name,value)
            result=verify(packet);row=result['attempts'][0]
            assert row['formatValid'] and row['schemaValid'] and row['truncated'] and not row['correct']
            assert result['publicationDecision']=='publish-scoped-report' and result['qualityDecision']=='hold-tool-decision-quality'

        def test_external_budget_failure_preserves_all_128_returns(self,packet):
            root,_,protocol=packet;value=json.loads((root/'terminal.json').read_bytes());value['process_maxrss_kib']=protocol['budgets']['maximum_process_lifetime_peak_rss_kib']+1;resign(packet,'terminal.json',value)
            result=verify(packet)
            assert result['population']['scored']==128 and not result['evidence']['withinRunBudget']
            assert result['publicationDecision']=='hold-incomplete-or-resource-evidence'

    class TestFailingCases:
        def test_changed_call_original_refuses(self,packet,caplog):
            root,_,protocol=packet;name='calls/'+protocol['order']['attemptIds'][0]+'-returned.json';(root/name).write_bytes(b'{}')
            with caplog.at_level(logging.ERROR),pytest.raises(ValueError,match='original retained bytes changed'):verify(packet)
            assert 'original retained bytes changed' in caplog.text

        def test_resigned_helper_still_refuses_frozen_source(self,packet,caplog):
            resign(packet,'sources/schema_contract.py',{})
            with caplog.at_level(logging.ERROR),pytest.raises(ValueError,match='retained source differs from active frozen reader'):verify(packet)
            assert 'retained source differs' in caplog.text

        def test_typed_bool_usage_refuses(self,packet,caplog):
            root,_,protocol=packet;name='calls/'+protocol['order']['attemptIds'][0]+'-returned.json';value=json.loads((root/name).read_bytes());value['response']['usage']['completion_tokens']=True;resign(packet,name,value)
            with caplog.at_level(logging.ERROR),pytest.raises(ValueError,match='native usage must contain nonnegative integers'):verify(packet)
            assert 'nonnegative integers' in caplog.text

        def test_call_after_first_hole_refuses(self,packet,caplog):
            root,pins,protocol=packet
            manifest=json.loads((root/'manifest.json').read_bytes())
            for kind in ['started','returned']:
                name='calls/'+protocol['order']['attemptIds'][0]+'-'+kind+'.json';(root/name).unlink();manifest.pop(name)
            (root/'manifest.json').write_bytes(io.encode(manifest));pins['manifest']['sha256']=io.digest((root/'manifest.json').read_bytes())
            with caplog.at_level(logging.ERROR),pytest.raises(ValueError,match='attempt started after frozen stop boundary'):verify(packet)
            assert 'frozen stop boundary' in caplog.text

        def test_return_without_start_refuses(self,packet,caplog):
            root,pins,protocol=packet;name='calls/'+protocol['order']['attemptIds'][0]+'-started.json';(root/name).unlink();manifest=json.loads((root/'manifest.json').read_bytes());manifest.pop(name);(root/'manifest.json').write_bytes(io.encode(manifest));pins['manifest']['sha256']=io.digest((root/'manifest.json').read_bytes())
            with caplog.at_level(logging.ERROR),pytest.raises(ValueError,match='returned or error call lacks started original'):verify(packet)
            assert 'lacks started original' in caplog.text

        def test_reuse_install_resource_laundering_refuses(self,packet,caplog):
            root,_,_=packet;name='sources/reuse/installation.json';value=json.loads((root/name).read_bytes());value['elapsedSeconds']=336;resign(packet,name,value)
            with caplog.at_level(logging.ERROR),pytest.raises(ValueError,match='retained installation duration exceeds its budget or is invalid'):verify(packet)
            assert 'installation duration' in caplog.text

        def test_candidate_protocol_targets_cannot_select_themselves(self,packet,caplog):
            root,pins,_=packet;value=json.loads((root/'protocol.json').read_bytes());value['cases'][0]['target']['abstain']=True;resign(packet,'protocol.json',value);pins['protocol']['sha256']=io.digest((root/'protocol.json').read_bytes())
            with caplog.at_level(logging.ERROR),pytest.raises(ValueError,match='packet protocol differs from frozen installation'):verify(packet)
            assert 'frozen installation' in caplog.text
