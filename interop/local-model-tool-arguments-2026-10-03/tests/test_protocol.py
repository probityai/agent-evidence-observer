"""Preregister task, treatment, rubric and denominator relations without inference."""
import copy
import json
import logging
from pathlib import Path

from hypothesis import given, strategies as st
import pytest

import evidence_io as io
import execution_contract as execution
import protocol_builder as builder
import schema_contract as schema


class TestProspectiveTasks:
    class TestPassingCases:
        def test_eight_single_field_pairs(self):
            cases = builder.original_cases()
            assert len(cases) == 16
            for left, right in zip(cases[::2], cases[1::2]):
                assert {key for key in left['record'] if left['record'][key] != right['record'][key]} == {left['changedField']}
                assert left['target']['abstain'] is False and right['target']['abstain'] is True
                assert left['target'] == builder.target(left['record'])
                assert right['target'] == builder.target(right['record'])

        def test_128_balanced_shared_prompt_population(self):
            protocol = builder.build()
            calls = execution.population(protocol)
            assert len(calls) == 128
            positions = {}
            for position, (_, cell, case) in enumerate(calls):
                key = cell['model'], cell['id'], cell['mode']
                positions.setdefault(key, []).append(position % 8)
                alternate = dict(case, mode='control' if case['mode']=='tool-schema' else 'tool-schema')
                assert execution.request(protocol, cell, case)['prompt'] == execution.request(protocol, cell, alternate)['prompt']
            assert all(sorted(value) == sorted(list(range(8))*2) for value in positions.values())

        def test_schema_is_global_generic_not_case_target(self):
            for mode in builder.MODES:
                contract = builder.schema_for(mode)
                assert schema.schema_accepts({'tool':'none','arguments':{'key':None,'value':None},'abstain':False},contract)
                assert schema.schema_accepts({'tool':'write_record','arguments':{'key':'unseen','value':-901},'abstain':True},contract)
                assert 'alpha' not in json.dumps(contract)
            assert schema.schema_accepts({'tool':'arbitrary','arguments':{'key':[], 'value':{'x':True}},'abstain':False},builder.schema_for('control'))

        @given(st.integers(), st.text(min_size=1))
        def test_typed_copied_arguments(self, value, key):
            record = dict(builder.original_cases()[0]['record'],key=key,matches=[key],value=value)
            assert builder.target(record) == {'tool':'write_record','arguments':{'key':key,'value':value},'abstain':False}

    class TestFailingCases:
        @pytest.mark.parametrize('value',[True,False,'3',3.0,None,[],{}])
        def test_noninteger_arguments_abstain(self,value):
            record = dict(builder.original_cases()[0]['record'],value=value)
            assert builder.target(record)['abstain'] is True

        def test_population_hole_refuses_logged_selection(self,caplog):
            protocol = builder.build(); protocol['order']['attemptIds'].pop()
            with caplog.at_level(logging.ERROR), pytest.raises(ValueError,match='attempt population differs from frozen128 selection'):
                execution.population(protocol)
            assert 'attempt population differs from frozen128 selection' in caplog.text


class TestStrictRubric:
    class TestPassingCases:
        @given(st.text())
        def test_arbitrary_tool_string_schema_is_not_quality(self,tool):
            target=builder.original_cases()[0]['target'];answer=copy.deepcopy(target);answer['tool']=tool
            result=schema.score(json.dumps(answer),target,builder.schema_for('control'))
            assert result['schemaValid'] is True
            assert result['correct'] == (tool=='write_record')

        def test_whitespace_is_not_a_new_case(self):
            target=builder.original_cases()[0]['target']
            assert schema.score(json.dumps(target,indent=4),target,builder.schema_for('tool-schema')) == {'formatValid':True,'schemaValid':True,'correct':True}

    class TestFailingCases:
        @pytest.mark.parametrize('text',['{"tool":','{"x":1,"x":2}','{"x":NaN}','[]','null'])
        def test_invalid_or_wrong_shape_keeps_failure(self,text):
            result=schema.score(text,builder.original_cases()[0]['target'],builder.schema_for('tool-schema'))
            assert not result['correct'] and not result['schemaValid']

        def test_boolean_and_numeric_coercion_refuse(self):
            assert not schema.exact(True,1)
            assert not schema.exact(3,3.0)
            assert not schema.schema_accepts({'tool':'write_record','arguments':{'key':'alpha','value':True},'abstain':False},builder.schema_for('tool-schema'))

        def test_extra_answer_members_refuse(self):
            target=builder.original_cases()[0]['target'];answer=dict(target,grant=True)
            assert not schema.score(json.dumps(answer),target,builder.schema_for('control'))['schemaValid']


class TestFiniteOriginals:
    class TestPassingCases:
        def test_buffer_is_unmodified(self,tmp_path):
            raw=b'  {"a":1}\r\n';(tmp_path/'original.json').write_bytes(raw)
            assert io.packet_buffers(tmp_path)=={'original.json':raw}

    class TestFailingCases:
        def test_candidate_link_refuses(self,tmp_path,caplog):
            (tmp_path/'linked').symlink_to('/dev/null')
            with caplog.at_level(logging.ERROR),pytest.raises(ValueError,match='packet contains links or exceeds entry selection'):
                io.packet_buffers(tmp_path)
            assert 'packet contains links' in caplog.text

        def test_candidate_fifo_refuses_without_blocking(self,tmp_path,caplog):
            import os
            os.mkfifo(tmp_path/'fifo')
            with caplog.at_level(logging.ERROR),pytest.raises(ValueError,match='selected artifact must be a regular file'):
                io.packet_buffers(tmp_path)
            assert 'regular file' in caplog.text

        def test_selected_file_budget_refuses(self,tmp_path,caplog):
            path=tmp_path/'large';path.write_bytes(b'abcd')
            with caplog.at_level(logging.ERROR),pytest.raises(ValueError,match='selected artifact exceeds file budget'):
                io.read_regular(path,3)
            assert 'file budget' in caplog.text


class TestFrozenProfileCacheSelection:
    class TestFailingCases:
        def test_source_valid_but_cached_helper_refuses_before_import(self,tmp_path,monkeypatch):
            import task_matrix
            (tmp_path/'__pycache__').mkdir();(tmp_path/'__pycache__/reader.cpython-312.pyc').write_bytes(b'cached executable placeholder')
            monkeypatch.setattr(task_matrix,'ROOT',tmp_path)
            with pytest.raises(ValueError,match='selected source cache population must be empty'):task_matrix.source_cache_absent()

        def test_linked_cache_directory_refuses(self,tmp_path,monkeypatch):
            import task_matrix
            (tmp_path/'__pycache__').symlink_to(tmp_path,target_is_directory=True);monkeypatch.setattr(task_matrix,'ROOT',tmp_path)
            with pytest.raises(ValueError,match='selected source directory links must be absent'):task_matrix.source_cache_absent()

        def test_installed_direct_source_cannot_dispatch(self,monkeypatch):
            import argparse,task_matrix
            monkeypatch.setattr(task_matrix,'INSTALLED_READER',True)
            with pytest.raises(ValueError,match='installed reader does not dispatch model inference'):
                task_matrix.native_action(argparse.Namespace(protocol_commit='bad'),builder.build())


class TestSourceModulePopulation:
    class TestFailingCases:
        @pytest.mark.parametrize('name',['reader.so','typing.py','unselected.cpython-312-x86_64-linux-gnu.so'])
        def test_unselected_root_module_alias_refuses(self,tmp_path,monkeypatch,name):
            import task_matrix
            (tmp_path/name).write_bytes(b'inert alias');monkeypatch.setattr(task_matrix,'ROOT',tmp_path)
            with pytest.raises(ValueError,match='unselected source module alias refused'):task_matrix.source_module_inventory({'sourceClosure':{'reader.py':'selected'}})

        def test_unselected_root_package_directory_refuses(self,tmp_path,monkeypatch):
            import task_matrix
            (tmp_path/'reader').mkdir();monkeypatch.setattr(task_matrix,'ROOT',tmp_path)
            with pytest.raises(ValueError,match='unselected source module directory refused'):task_matrix.source_module_inventory({'sourceClosure':{'reader.py':'selected'}})
