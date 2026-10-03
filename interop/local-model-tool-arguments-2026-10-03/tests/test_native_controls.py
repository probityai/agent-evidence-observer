"""Probe execution/refusal boundaries with fake engines, never native inference."""
import json
import time
from pathlib import Path

import pytest

import evidence_io as io
import native_runner as native
import protocol_builder as builder


class FakeModel:
    def __init__(self,fail=False,context=10):self.calls=0;self.resets=0;self.fail=fail;self.context=context
    def reset(self):self.resets+=1
    def tokenize(self,*args,**kwargs):return [1]*self.context
    def create_completion(self,**kwargs):
        self.calls+=1
        if self.fail:raise RuntimeError('controlled native failure')
        return {'choices':[{'text':'{}','finish_reason':'stop'}],'usage':{'prompt_tokens':self.context,'completion_tokens':1,'total_tokens':self.context+1}}


class TestNativeControls:
    class TestPassingCases:
        def test_exact_128_no_retry_or_warmup(self,tmp_path,monkeypatch):
            protocol=builder.build();models={model['id']:FakeModel() for model in protocol['models']};monkeypatch.setattr(native,'engines',lambda *args:(models,{mode:object() for mode in protocol['modes']}))
            native.run_population(tmp_path,tmp_path,protocol,time.monotonic_ns(),time.process_time_ns())
            assert sum(model.calls for model in models.values())==128
            assert sum(model.resets for model in models.values())==128
            assert len(list((tmp_path/'calls').glob('*-started.json')))==128
            assert len(list((tmp_path/'calls').glob('*-returned.json')))==128

    class TestFailingCases:
        def test_first_error_stops_without_retry(self,tmp_path,monkeypatch):
            protocol=builder.build();models={model['id']:FakeModel(fail=True) for model in protocol['models']};monkeypatch.setattr(native,'engines',lambda *args:(models,{mode:object() for mode in protocol['modes']}))
            with pytest.raises(RuntimeError,match='controlled native failure'):native.run_population(tmp_path,tmp_path,protocol,time.monotonic_ns(),time.process_time_ns())
            assert sum(model.calls for model in models.values())==1
            assert len(list((tmp_path/'calls').glob('*-error.json')))==1
            assert not list((tmp_path/'calls').glob('*-returned.json'))

        def test_context_preflight_stops_before_native_calls(self,tmp_path,monkeypatch):
            protocol=builder.build();models={model['id']:FakeModel(context=513) for model in protocol['models']};monkeypatch.setattr(native,'engines',lambda *args:(models,{mode:object() for mode in protocol['modes']}))
            with pytest.raises(ValueError,match='native context preflight exceeds selected runtime'):native.run_population(tmp_path,tmp_path,protocol,time.monotonic_ns(),time.process_time_ns())
            assert sum(model.calls for model in models.values())==0
            assert not (tmp_path/'calls').exists()

        def test_observed_resource_limit_precedes_native_call(self,tmp_path,monkeypatch):
            protocol=builder.build();models={model['id']:FakeModel() for model in protocol['models']};monkeypatch.setattr(native,'engines',lambda *args:(models,{mode:object() for mode in protocol['modes']}))
            with pytest.raises(ValueError,match='native wall budget exhausted'):native.run_population(tmp_path,tmp_path,protocol,time.monotonic_ns()-601000000000,time.process_time_ns())
            assert sum(model.calls for model in models.values())==0

        def test_unpublished_protocol_refuses_before_git_or_inference(self,tmp_path):
            with pytest.raises(ValueError,match='inference requires published prospective registration'):native.selected_registration(tmp_path,'registration-required',builder.build(),'fake')


class TestNativeInstallationBoundary:
    class TestPassingCases:
        def test_normal_regular_site(self,tmp_path):
            (tmp_path/'module.py').write_bytes(b'print("selected")\n')
            assert native.installed_population(tmp_path,1000)=={'module.py':{'bytes':18,'sha256':io.digest(b'print("selected")\n')}}

    class TestFailingCases:
        def test_descriptor_installation_fifo_refuses_before_launch(self,tmp_path):
            import os
            os.mkfifo(tmp_path/'installation.json')
            with pytest.raises(ValueError,match='selected artifact must be a regular file'):
                native.verify_installation(tmp_path,builder.build())

        def test_site_directory_link_refuses(self,tmp_path):
            (tmp_path/'linked').symlink_to(tmp_path,target_is_directory=True)
            with pytest.raises(ValueError,match='installed population is linked or exceeds entry limit'):
                native.installed_population(tmp_path,1000)

        def test_resigned_unknown_startup_hook_refuses(self,tmp_path):
            protocol={'runtimeReuse':{'wheels':[]}}
            for name in ['sitecustomize.py','sitecustomize/__init__.py','usercustomize.py','__pycache__/sitecustomize.cpython-312.pyc','injected.pth']:
                with pytest.raises(ValueError,match='unselected installed startup hook refused'):
                    native.verify_startup_hooks({name:{'bytes':1,'sha256':'resigned'}},tmp_path,protocol)


class TestExecutableCacheSelection:
    class TestPassingCases:
        def test_trusted_pip_seed_cache_scope_is_explicit(self):
            native.verify_cache_population({'pip/__pycache__/__init__.cpython-312.pyc':{'bytes':1}})

    class TestFailingCases:
        def test_timestamp_valid_cache_changes_import_despite_exact_source_and_B(self,tmp_path):
            import os,py_compile,subprocess,sys
            module=tmp_path/'selection_probe.py';original=b'value = 1\n';changed=b'value = 2\n'
            assert len(original)==len(changed)
            module.write_bytes(changed);os.utime(module,(1700000000,1700000000));cache=Path(py_compile.compile(str(module),doraise=True))
            module.write_bytes(original);os.utime(module,(1700000000,1700000000))
            result=subprocess.run([sys.executable,'-I','-B','-c','import sys;sys.path.insert(0,'+repr(str(tmp_path))+');import selection_probe;print(selection_probe.value)'],capture_output=True,check=True)
            assert result.stdout==b'2\n' and module.read_bytes()==original
            # A self-reselected installation map cannot authorize this cache.
            with pytest.raises(ValueError,match='selected runtime/dependency caches must be absent'):
                native.verify_cache_population({'selection_probe.py':{'bytes':len(original),'sha256':io.digest(original)},cache.relative_to(tmp_path).as_posix():{'bytes':cache.stat().st_size,'sha256':io.digest(cache.read_bytes())}})

        @pytest.mark.parametrize('name',['llama_cpp/__pycache__/llama.cpython-312.pyc','numpy/__init__.pyc','__pycache__/typing_extensions.cpython-312.pyc','diskcache/core.pyo'])
        def test_selected_runtime_dependency_cache_refuses(self,name):
            with pytest.raises(ValueError,match='selected runtime/dependency caches must be absent'):native.verify_cache_population({name:{'bytes':1}})


class TestImportablePopulation:
    class TestFailingCases:
        def test_extension_neighbor_precedes_source_but_is_not_selected(self,tmp_path):
            import importlib.machinery as machinery
            source=tmp_path/'population_probe.py';source.write_text('value = 1\n')
            extension=tmp_path/('population_probe'+machinery.EXTENSION_SUFFIXES[0]);extension.write_bytes(b'inert not a library')
            finder=machinery.FileFinder(str(tmp_path),(machinery.ExtensionFileLoader,machinery.EXTENSION_SUFFIXES),(machinery.SourceFileLoader,machinery.SOURCE_SUFFIXES),(machinery.SourcelessFileLoader,machinery.BYTECODE_SUFFIXES))
            assert finder.find_spec('population_probe').origin==str(extension)
            with pytest.raises(ValueError,match='unselected installed importable member refused'):
                native.verify_importable_population({source.name:{'bytes':10},extension.name:{'bytes':19}},{source.name})
