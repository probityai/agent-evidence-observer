"""Gate tests. The passing control-flow case stubs bwrap, not isolation."""

from __future__ import annotations

from pathlib import Path

import pytest

from probity_observer import CoverageError, SigningKey, VerificationError, Witness, verify_packet
from probity_observer.broker import Broker
from probity_observer.crypto import canonical, strict_loads
from probity_observer.history import append_history, read_history
from probity_observer.isolation import EXPECTED, launch_command, run_boundary_probe, verify_boundary_bundle
from probity_observer.verify import verify_incomplete


class FakeServer:
    """Exercise host protocol without pretending to exercise a namespace."""

    def __init__(self, path: Path, broker: Broker) -> None:
        self.broker = broker
        self.path = path
        path.write_bytes(b"")

    def __enter__(self) -> "FakeServer":
        return self

    def __exit__(self, *_: object) -> None:
        return None


def run_fixed_requests(server: FakeServer, *, complete: bool = True) -> None:
    """Make host-side effects while the child process is stubbed."""
    server.broker.write("write-1", "/work/effect.txt", b"observed effect\n")
    if not complete:
        return
    server.broker.write("write-1", "/work/effect.txt", b"observed effect\n")
    for request_id, path, content in [
        ("write-1", "/work/effect.txt", b"changed effect\n"),
        ("escape-1", "/work/../outside.txt", b"escape\n"),
    ]:
        with pytest.raises(CoverageError):
            server.broker.write(request_id, path, content)


class TestBoundaryGate:
    class TestPassingCases:
        def test_command_hides_tree_key_and_host_process(self, tmp_path: Path) -> None:
            command = launch_command(Path("/usr/bin/bwrap"), tmp_path / "socket", Path("/usr/bin/python3"), 12345)
            assert "--unshare-all" in command
            assert "--cap-drop" in command
            assert "--clearenv" in command
            assert "--proc" in command
            assert "--ro-bind" in command
            assert "--bind" not in command
            assert "/work" not in command
            assert "/proc/12345" not in command
            assert command[-1] == "12345"

        def test_host_checks_broker_events_and_retains_peer(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
            from probity_observer import isolation

            monkeypatch.setattr(isolation, "_WriteServer", FakeServer)

            def child(_command: list[str], server: FakeServer) -> tuple[int, bytes, bytes]:
                run_fixed_requests(server)
                return 0, canonical({key: True for key in EXPECTED}) + b"\n", b""

            monkeypatch.setattr(isolation, "_run_child", child)
            report = run_boundary_probe(tmp_path / "run")
            output = tmp_path / "run"
            packet = strict_loads((output / "packet.json").read_bytes())
            keys = strict_loads((output / "trusted-keys.json").read_bytes())
            claim = verify_packet(packet, output / "history.jsonl", keys["observer"], keys["witness"], output / "workspace")
            assert report["status"] == "probe-passed"
            assert report["evidence_vantage"] == "artifact"
            assert claim["witnessScope"] == report["witnessScope"] == "PEER"
            assert claim["authorityDigest"] == read_history(output / "history.jsonl")[0]["event"]["commitment"]["preimage"]["authorityDigest"]
            assert verify_boundary_bundle(output, keys["observer"], keys["witness"])["status"] == "probe-passed"

        def test_relative_output_yields_absolute_mount_sources(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
            from probity_observer import isolation

            monkeypatch.chdir(tmp_path)
            monkeypatch.setattr(isolation, "_WriteServer", FakeServer)
            launched: list[str] = []

            def child(command: list[str], server: FakeServer) -> tuple[int, bytes, bytes]:
                launched.extend(command)
                run_fixed_requests(server)
                return 0, canonical({key: True for key in EXPECTED}) + b"\n", b""

            monkeypatch.setattr(isolation, "_run_child", child)
            run_boundary_probe(Path("relative-output"))
            sources = [launched[index + 1] for index, arg in enumerate(launched[:-1]) if arg == "--ro-bind"]
            assert str(tmp_path / "relative-output" / "socket") in sources
            assert str(tmp_path / "relative-output" / "agent-probe.py") in sources

    class TestFailingCases:
        def test_failed_socket_setup_is_a_witnessed_incomplete_interval(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
            from probity_observer import isolation

            def fail(*_: object) -> None:
                raise PermissionError("socket denied")

            monkeypatch.setattr(isolation, "_WriteServer", fail)
            output = tmp_path / "failed"
            report = run_boundary_probe(output)
            keys = strict_loads((output / "trusted-keys.json").read_bytes())
            incomplete = strict_loads((output / "incomplete.json").read_bytes())
            event = verify_incomplete(output / "history.jsonl", incomplete["startCheckpoint"], incomplete["checkpoint"], keys["observer"], keys["witness"])
            assert report["status"] == "incomplete"
            assert report["evidence_vantage"] == "artifact"
            assert report["witnessScope"] == "PEER"
            assert event["reason"] == "isolation setup failed"
            assert b"socket denied" in (output / "probe-stderr.bin").read_bytes()
            assert not (output / "packet.json").exists()
            assert verify_boundary_bundle(output, keys["observer"], keys["witness"])["status"] == "incomplete"

        def test_pinned_reader_rejects_changed_probe_and_result(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
            from probity_observer import isolation

            monkeypatch.setattr(isolation, "_WriteServer", FakeServer)

            def child(_command: list[str], server: FakeServer) -> tuple[int, bytes, bytes]:
                run_fixed_requests(server)
                return 0, canonical({key: True for key in EXPECTED}) + b"\n", b""

            monkeypatch.setattr(isolation, "_run_child", child)
            output = tmp_path / "run"
            run_boundary_probe(output)
            keys = strict_loads((output / "trusted-keys.json").read_bytes())
            with pytest.raises(VerificationError, match="boundary attestation differs"):
                verify_boundary_bundle(output, SigningKey.generate().public_hex, keys["witness"])
            script = output / "agent-probe.py"
            original = script.read_bytes()
            script.write_bytes(original + b"\n")
            with pytest.raises(VerificationError, match="probe bytes differ"):
                verify_boundary_bundle(output, keys["observer"], keys["witness"])
            script.write_bytes(original)
            stdout = output / "probe-stdout.bin"
            stdout.write_bytes(stdout.read_bytes() + b"x")
            with pytest.raises(VerificationError, match="raw probe output differs"):
                verify_boundary_bundle(output, keys["observer"], keys["witness"])

        def test_incomplete_reader_rejects_unknown_intermediate_event(self, tmp_path: Path) -> None:
            workspace = tmp_path / "workspace"
            workspace.mkdir()
            history = tmp_path / "history.jsonl"
            observer_key = SigningKey.generate()
            witness_key = SigningKey.generate()
            broker = Broker(
                workspace, history,
                {"intervalId": "bad", "scope": "/work", "operation": "write-file"},
                observer_key, Witness(tmp_path / "witness.json", witness_key),
            )
            broker.begin()
            append_history(history, {"kind": "unknown"})
            incomplete = broker.abort("boundary probes failed")
            with pytest.raises(VerificationError, match="unknown event kind"):
                verify_incomplete(history, incomplete["startCheckpoint"], incomplete["checkpoint"], observer_key.public_hex, witness_key.public_hex)

        @pytest.mark.parametrize("complete, flags_pass", [(False, True), (True, False)])
        def test_missing_broker_event_or_refusal_aborts(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, complete: bool, flags_pass: bool) -> None:
            from probity_observer import isolation

            monkeypatch.setattr(isolation, "_WriteServer", FakeServer)

            def child(_command: list[str], server: FakeServer) -> tuple[int, bytes, bytes]:
                run_fixed_requests(server, complete=complete)
                flags = {key: True for key in EXPECTED}
                flags["networkRefused"] = flags_pass
                return 0, canonical(flags) + b"\n", b""

            monkeypatch.setattr(isolation, "_run_child", child)
            output = tmp_path / "failed"
            report = run_boundary_probe(output)
            incomplete = strict_loads((output / "incomplete.json").read_bytes())
            keys = strict_loads((output / "trusted-keys.json").read_bytes())
            assert report["status"] == "incomplete"
            assert incomplete["event"]["reason"] == "boundary probes failed"
            assert not (output / "packet.json").exists()
            verify_incomplete(output / "history.jsonl", incomplete["startCheckpoint"], incomplete["checkpoint"], keys["observer"], keys["witness"])
