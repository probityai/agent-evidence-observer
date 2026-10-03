"""Exercise external resource joins and signal races without native dispatch."""
from types import SimpleNamespace

import pytest

import execute_guard as guard


class TestWholeProcessObserver:
    class TestPassingCases:
        def test_exact_exit_and_wait4_resources(self,monkeypatch):
            usage=SimpleNamespace(ru_utime=0.25,ru_stime=0.125,ru_maxrss=1234)
            process=SimpleNamespace(pid=17,returncode=None)
            monkeypatch.setattr(guard.os,'wait4',lambda pid,flags:(pid,0,usage))
            code,observed,terminated=guard.reap(process,0)
            assert code==0 and observed is usage and not terminated and process.returncode==0

        def test_term_kill_then_reap_missing_signal_target(self,monkeypatch):
            process=SimpleNamespace(pid=17,returncode=None);usage=SimpleNamespace(ru_utime=1.0,ru_stime=0.5,ru_maxrss=4096)
            replies=iter([(0,0,None),(0,0,None),(17,9,usage)])
            times=iter([595.5,600.1]);signals=[]
            monkeypatch.setattr(guard.os,'wait4',lambda *args:next(replies));monkeypatch.setattr(guard.time,'monotonic',lambda:next(times));monkeypatch.setattr(guard.time,'sleep',lambda seconds:None)
            def gone(pid,signal):signals.append(signal);raise ProcessLookupError()
            monkeypatch.setattr(guard.os,'killpg',gone)
            code,observed,terminated=guard.reap(process,0)
            assert code==-9 and terminated and observed is usage
            assert signals==[guard.signal.SIGTERM,guard.signal.SIGKILL]

    class TestFailingCases:
        def test_unselected_cpu_instructions_refuse(self,monkeypatch):
            monkeypatch.setattr(guard.Path,'read_text',lambda self:'flags : sse2 pni\n')
            with pytest.raises(ValueError,match='selected retained runtime CPU instructions unavailable'):guard.cpu_preflight()
