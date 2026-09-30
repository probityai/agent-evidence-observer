"""Host decisions for a caller-supplied workload."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from probity_observer import VerificationError
from probity_observer.broker import Broker
from probity_observer.crypto import canonical, strict_loads
from probity_observer.history import read_history
from probity_observer.isolation import _WriteHandler
from probity_observer.workload import _run_workload_child, run_workload, verify_workload_bundle


class FakeServer:
    def __init__(self, path: Path, broker: Broker) -> None:
        self.broker = broker
        path.write_bytes(b"")

    def __enter__(self) -> "FakeServer":
        return self

    def __exit__(self, *_: object) -> None:
        return None


def keys(output: Path) -> tuple[str, str]:
    pinned = strict_loads((output / "trusted-keys.json").read_bytes())
    return pinned["observer"], pinned["witness"]


def test_host_counts_effects_without_trusting_stdout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from probity_observer import workload

    monkeypatch.setattr(workload, "_WriteServer", FakeServer)
    script = tmp_path / "agent.py"
    script.write_text("print('I did nothing')\n", encoding="ascii")

    def child(_command: list[str], server: FakeServer) -> tuple[int, bytes, bytes]:
        broker = server.broker
        broker.write("one", "/work/result", b"effect")
        broker.write("one", "/work/result", b"effect")
        with pytest.raises(ValueError):
            broker.write("one", "/work/result", b"changed")
        return 0, b"I did nothing\n", b""

    monkeypatch.setattr(workload, "_run_workload_child", child)
    output = tmp_path / "run"
    report = run_workload(output, script)
    assert report["status"] == "completed"
    assert report["channelCounts"] == {"accepted": 1, "replayed": 1, "denied": 1, "knownGaps": 0}
    assert verify_workload_bundle(output, *keys(output)) == report
    assert (output / "workspace" / "result").read_bytes() == b"effect"
    assert b"I did nothing" in (output / "workload-stdout.bin").read_bytes()


@pytest.mark.parametrize("effect,exit_code", [(False, 0), (True, 7)])
def test_no_effect_or_failed_child_is_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, effect: bool, exit_code: int,
) -> None:
    from probity_observer import workload

    monkeypatch.setattr(workload, "_WriteServer", FakeServer)
    script = tmp_path / "agent.py"
    script.write_bytes(b"pass\n")

    def child(_command: list[str], server: FakeServer) -> tuple[int, bytes, bytes]:
        if effect:
            server.broker.write("one", "/work/result", b"effect")
        return exit_code, b"", b""

    monkeypatch.setattr(workload, "_run_workload_child", child)
    output = tmp_path / "run"
    report = run_workload(output, script)
    assert report["status"] == "incomplete"
    assert not (output / "packet.json").exists()
    assert verify_workload_bundle(output, *keys(output)) == report


def test_gap_after_an_effect_keeps_the_interval_incomplete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from probity_observer import workload

    monkeypatch.setattr(workload, "_WriteServer", FakeServer)
    script = tmp_path / "agent.py"
    script.write_bytes(b"pass\n")

    def child(_command: list[str], server: FakeServer) -> tuple[int, bytes, bytes]:
        server.broker.write("one", "/work/result", b"effect")
        server.broker._record_gap("malformed broker request")
        return 0, b"", b""

    monkeypatch.setattr(workload, "_run_workload_child", child)
    output = tmp_path / "run"
    report = run_workload(output, script)
    assert report["status"] == "incomplete"
    assert report["channelCounts"]["accepted"] == 1
    assert report["channelCounts"]["knownGaps"] == 1
    assert verify_workload_bundle(output, *keys(output)) == report


def test_direct_workspace_change_keeps_the_interval_incomplete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from probity_observer import workload

    monkeypatch.setattr(workload, "_WriteServer", FakeServer)
    script = tmp_path / "agent.py"
    script.write_bytes(b"pass\n")

    def child(_command: list[str], server: FakeServer) -> tuple[int, bytes, bytes]:
        server.broker.write("one", "/work/result", b"effect")
        (server.broker.workspace / "bypass").write_bytes(b"outside broker")
        return 0, b"", b""

    monkeypatch.setattr(workload, "_run_workload_child", child)
    output = tmp_path / "run"
    report = run_workload(output, script)
    assert report["status"] == "incomplete"
    assert report["channelCounts"]["knownGaps"] == 1
    assert verify_workload_bundle(output, *keys(output)) == report


def test_report_and_script_tampering_are_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from probity_observer import workload

    monkeypatch.setattr(workload, "_WriteServer", FakeServer)
    script = tmp_path / "agent.py"
    script.write_bytes(b"pass\n")

    def child(_command: list[str], server: FakeServer) -> tuple[int, bytes, bytes]:
        server.broker.write("one", "/work/result", b"effect")
        return 0, b"", b""

    monkeypatch.setattr(workload, "_run_workload_child", child)
    output = tmp_path / "run"
    run_workload(output, script)
    pinned = keys(output)
    recorded = (output / "workload.py").read_bytes()
    (output / "workload.py").write_bytes(recorded + b"# change\n")
    with pytest.raises(VerificationError, match="workload bytes differ"):
        verify_workload_bundle(output, *pinned)
    (output / "workload.py").write_bytes(recorded)
    report_path = output / "workload-report.json"
    report = strict_loads(report_path.read_bytes())
    report["channelCounts"]["accepted"] = 2
    report_path.write_bytes(canonical(report))
    with pytest.raises(VerificationError, match="channel counts differ"):
        verify_workload_bundle(output, *pinned)


def test_malformed_socket_request_marks_a_gap(tmp_path: Path) -> None:
    from probity_observer import SigningKey, Witness

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    history = tmp_path / "history.jsonl"
    broker = Broker(workspace, history, {"intervalId": "bad", "scope": "/work", "operation": "write-file"},
                    SigningKey.generate(), Witness(tmp_path / "witness.json", SigningKey.generate()))
    broker.begin()
    handler = _WriteHandler.__new__(_WriteHandler)
    handler.server = type("Server", (), {"broker": broker})()
    handler.rfile = io.BytesIO(b"bad json\n")
    handler.wfile = io.BytesIO()
    handler.handle()
    assert read_history(history)[-1]["event"] == {"kind": "gap", "reason": "malformed broker request"}
    assert b'"ok":false' in handler.wfile.getvalue()


def test_child_output_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    from probity_observer import workload

    monkeypatch.setattr(workload, "MAX_OUTPUT", 1024)

    class Server:
        def serve_forever(self, **_: object) -> None:
            return

        def shutdown(self) -> None:
            return

    command = [sys.executable, "-c", "import sys; sys.stdout.write('x' * 100000)"]
    code, stdout, stderr = _run_workload_child(command, Server())
    assert code == -1
    assert len(stdout) == 1024
    assert b"output limit" in stderr


def test_child_cannot_outlive_closed_output_pipes(monkeypatch: pytest.MonkeyPatch) -> None:
    from probity_observer import workload

    monkeypatch.setattr(workload, "DEADLINE", 0.2)

    class Server:
        def serve_forever(self, **_: object) -> None:
            return

        def shutdown(self) -> None:
            return

    command = [sys.executable, "-c", "import os,time; os.close(1); os.close(2); time.sleep(10)"]
    code, _, stderr = _run_workload_child(command, Server())
    assert code == -1
    assert b"deadline" in stderr
