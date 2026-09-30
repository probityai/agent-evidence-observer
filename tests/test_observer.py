"""Adversarial tests for the prototype's actual, bounded claim."""

from __future__ import annotations

import copy
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import HealthCheck, given, settings, strategies as st

from probity_observer import Broker, CoverageError, SigningKey, VerificationError, Witness, verify_packet
from probity_observer.broker import recover_interrupted, tree_root
from probity_observer.crypto import canonical, strict_loads
from probity_observer.history import read_history
from probity_observer.verify import _verify_commitment, _verify_request_sequence, verify_incomplete


class TestBroker:
    """Shared setup for passing and failing broker cases."""

    def build(self, temporary: Path) -> tuple[Broker, SigningKey, SigningKey, Path, Path]:
        workspace = temporary / "workspace"
        workspace.mkdir()
        history = temporary / "history.jsonl"
        observer_key = SigningKey.generate()
        witness_key = SigningKey.generate()
        witness = Witness(temporary / "witness-state.json", witness_key)
        authority = {"intervalId": "test-interval", "scope": "/work", "operation": "write-file"}
        broker = Broker(workspace, history, authority, observer_key, witness)
        broker.begin()
        return broker, observer_key, witness_key, workspace, history


class TestPassingCases(TestBroker):
    """Properties that a consumer can recompute from preserved bytes."""

    @given(st.binary(max_size=256))
    @settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_arbitrary_file_bytes_bind_to_one_witnessed_history(self, tmp_path: Path, content: bytes) -> None:
        # Hypothesis reuses tmp_path across examples; each case gets its own tree.
        with tempfile.TemporaryDirectory(dir=tmp_path) as directory:
            broker, observer_key, witness_key, workspace, history = self.build(Path(directory))
            first = broker.write("one", "/work/result", content)
            replay = broker.write("one", "/work/result", content)
            packet = broker.seal()
            claim = verify_packet(packet, history, observer_key.public_hex, witness_key.public_hex, workspace)
            assert replay.replayed
            assert replay.after_root == first.after_root == tree_root(workspace)
            assert claim["coverage"]["noDetectedGap"] is True
            assert claim["witnessScope"] == "PEER"
            assert [entry["event"]["kind"] for entry in read_history(history)] == ["begin", "write-intent", "write", "retry", "seal"]

    def test_unbrokered_change_is_reported_as_gap(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        broker, observer_key, witness_key, workspace, history = self.build(tmp_path)
        (workspace / "bypass").write_text("not through broker", encoding="ascii")
        with caplog.at_level(logging.WARNING):
            packet = broker.seal()
        claim = verify_packet(packet, history, observer_key.public_hex, witness_key.public_hex)
        assert claim["coverage"]["noDetectedGap"] is False
        assert claim["coverage"]["knownGaps"] == ["workspace changed outside the broker"]
        assert "observer coverage gap: workspace changed outside the broker" in caplog.text

    def test_witness_extends_same_history(self, tmp_path: Path) -> None:
        broker, _, witness_key, _, history = self.build(tmp_path)
        broker.write("one", "/work/result", b"data")
        packet = broker.seal()
        second = broker.witness.checkpoint(history)
        assert second["count"] == packet["checkpoint"]["count"]
        assert second["head"] == packet["checkpoint"]["head"]
        assert second["keyid"] == witness_key.public_hex


class TestFailingCases(TestBroker):
    """Failures that would otherwise look like legitimate covered effects."""

    @pytest.mark.parametrize(
        ("path", "message"),
        [
            ("/work/../outside", "write path is not normalized"),
            ("/work//outside", "write path is not normalized"),
            ("/workspace/file", "write path is outside the authorized scope"),
            ("work/file", "write path must be an ASCII absolute path"),
            ("/work/caf\u00e9", "write path must be an ASCII absolute path"),
        ],
    )
    def test_path_escape_is_denied_and_logged(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture, path: str, message: str
    ) -> None:
        broker, _, _, _, history = self.build(tmp_path)
        with caplog.at_level(logging.WARNING), pytest.raises(CoverageError, match=message):
            broker.write("escape", path, b"malice")
        assert read_history(history)[-1]["event"]["kind"] == "denied"
        assert message in caplog.text

    def test_non_ascii_denial_uses_digest_in_history(self, tmp_path: Path) -> None:
        broker, _, _, _, history = self.build(tmp_path)
        with pytest.raises(CoverageError, match="write path must be an ASCII absolute path"):
            broker.write("unicode", "/work/caf\u00e9", b"data")
        assert read_history(history)[-1]["event"]["path"].startswith("non-ascii-sha256:")

    def test_retry_cannot_change_its_effect(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        broker, _, _, workspace, history = self.build(tmp_path)
        broker.write("one", "/work/result", b"first")
        with caplog.at_level(logging.WARNING), pytest.raises(CoverageError, match="idempotency key reused with different request"):
            broker.write("one", "/work/result", b"second")
        assert (workspace / "result").read_bytes() == b"first"
        assert read_history(history)[-1]["event"]["kind"] == "denied"
        assert "idempotency key reused with different request" in caplog.text

    def test_retry_refuses_a_changed_workspace(self, tmp_path: Path) -> None:
        broker, observer_key, witness_key, workspace, history = self.build(tmp_path)
        broker.write("one", "/work/result", b"first")
        (workspace / "bypass").write_bytes(b"direct write")
        with pytest.raises(CoverageError, match="workspace changed outside the broker"):
            broker.write("one", "/work/result", b"first")
        packet = broker.seal()
        claim = verify_packet(packet, history, observer_key.public_hex, witness_key.public_hex)
        assert claim["coverage"]["noDetectedGap"] is False
        assert [entry["event"]["kind"] for entry in read_history(history)] == ["begin", "write-intent", "write", "denied", "gap", "seal"]

    @pytest.mark.parametrize("identical", [False, True])
    def test_replacement_then_process_death_is_witnessed_as_incomplete(self, tmp_path: Path, identical: bool) -> None:
        source = Path(__file__).resolve().parents[1] / "src"
        script = """
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from probity_observer import Broker, SigningKey, Witness
from probity_observer import broker as broker_module

root = Path(os.environ["OBSERVER_TEST_ROOT"])
workspace = root / "workspace"
workspace.mkdir()
if os.environ["OBSERVER_TEST_IDENTICAL"] == "1":
    (workspace / "result").write_bytes(b"same")
witness_key = SigningKey(Ed25519PrivateKey.from_private_bytes(bytes(range(32))))
observer_key = SigningKey(Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64))))
broker = Broker(workspace, root / "history.jsonl",
                {"intervalId": "crash", "scope": "/work", "operation": "write-file"},
                observer_key, Witness(root / "witness-state.json", witness_key))
broker.begin()
original_write = broker_module._atomic_write

def stop_after_replace(target, content):
    original_write(target, content)
    os._exit(91)

broker_module._atomic_write = stop_after_replace
broker.write("one", "/work/result", b"same" if os.environ["OBSERVER_TEST_IDENTICAL"] == "1" else b"changed")
"""
        env = dict(
            os.environ,
            PYTHONPATH=str(source),
            OBSERVER_TEST_ROOT=str(tmp_path),
            OBSERVER_TEST_IDENTICAL=str(int(identical)),
        )
        child = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, check=False)
        assert child.returncode == 91, child.stderr.decode()

        history = tmp_path / "history.jsonl"
        workspace = tmp_path / "workspace"
        assert (workspace / "result").read_bytes() == (b"same" if identical else b"changed")
        assert [entry["event"]["kind"] for entry in read_history(history)] == ["begin", "write-intent"]
        witness_key = SigningKey(Ed25519PrivateKey.from_private_bytes(bytes(range(32))))
        observer_key = SigningKey(Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64))))
        recovered = recover_interrupted(history, workspace, Witness(tmp_path / "witness-state.json", witness_key))
        assert recovered["status"] == "incomplete"
        assert recovered["event"]["recoveryRoot"] == tree_root(workspace)
        if identical:
            before_root = read_history(history)[0]["event"]["commitment"]["preimage"]["beforeRoot"]
            assert recovered["event"]["recoveryRoot"] == before_root
        assert recovered["event"]["requestIds"] == ["one"]
        assert verify_incomplete(
            history,
            recovered["startCheckpoint"],
            recovered["checkpoint"],
            observer_key.public_hex,
            witness_key.public_hex,
        ) == recovered["event"]
        with pytest.raises(VerificationError, match="pinned witness key"):
            verify_incomplete(
                history,
                recovered["startCheckpoint"],
                recovered["checkpoint"],
                observer_key.public_hex,
                SigningKey.generate().public_hex,
            )
        with pytest.raises(VerificationError, match="terminal event"):
            recover_interrupted(history, workspace, Witness(tmp_path / "witness-state.json", witness_key))

    def test_pending_write_cannot_be_sealed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from probity_observer import broker as broker_module

        broker, _, _, workspace, history = self.build(tmp_path)
        original_write = broker_module._atomic_write

        def stop_after_replace(target: Path, content: bytes) -> None:
            original_write(target, content)
            raise OSError("simulated interruption")

        monkeypatch.setattr(broker_module, "_atomic_write", stop_after_replace)
        with pytest.raises(OSError, match="simulated interruption"):
            broker.write("one", "/work/result", b"changed")
        assert (workspace / "result").read_bytes() == b"changed"
        assert read_history(history)[-1]["event"]["kind"] == "write-intent"
        with pytest.raises(CoverageError, match="unresolved write intent"):
            broker.seal()
        with pytest.raises(CoverageError, match="unresolved write intent"):
            broker.write("two", "/work/next", b"other")

    def test_partial_history_line_is_refused(self, tmp_path: Path) -> None:
        _, _, _, _, history = self.build(tmp_path)
        history.write_bytes(history.read_bytes().rstrip(b"\n"))
        with pytest.raises(VerificationError, match="incomplete line"):
            read_history(history)

    def test_intent_must_match_effect_event(self) -> None:
        begin = {"kind": "begin"}
        intent = {"kind": "write-intent", "requestId": "one", "path": "/work/result", "contentDigest": "a", "beforeRoot": "b"}
        changed = {"kind": "write", "requestId": "one", "path": "/work/result", "contentDigest": "c", "beforeRoot": "b"}
        with pytest.raises(VerificationError, match="differs from its durable intent"):
            _verify_request_sequence([{"event": event} for event in (begin, intent, changed, {"kind": "seal"})])
        with pytest.raises(VerificationError, match="unresolved write intent"):
            _verify_request_sequence([{"event": event} for event in (begin, intent, {"kind": "seal"})])

    def test_changed_history_fails_offline_check(self, tmp_path: Path) -> None:
        broker, observer_key, witness_key, _, history = self.build(tmp_path)
        broker.write("one", "/work/result", b"data")
        packet = broker.seal()
        original = history.read_bytes()
        history.write_bytes(original.replace(b'"requestId":"one"', b'"requestId":"two"', 1))
        with pytest.raises(VerificationError, match="history entry digest differs"):
            verify_packet(packet, history, observer_key.public_hex, witness_key.public_hex)

    def test_truncated_history_fails_witness_binding(self, tmp_path: Path) -> None:
        broker, observer_key, witness_key, _, history = self.build(tmp_path)
        broker.write("one", "/work/result", b"data")
        packet = broker.seal()
        history.write_bytes(history.read_bytes().splitlines()[0] + b"\n")
        with pytest.raises(VerificationError, match="history has no final seal"):
            verify_packet(packet, history, observer_key.public_hex, witness_key.public_hex)
        with pytest.raises(VerificationError, match="history does not extend the witnessed head"):
            broker.witness.checkpoint(history)

    def test_second_key_does_not_grant_observer_authority(self, tmp_path: Path) -> None:
        broker, observer_key, witness_key, _, history = self.build(tmp_path)
        packet = broker.seal()
        forged = copy.deepcopy(packet)
        forged["claim"]["witnessScope"] = "EXTERNAL"
        with pytest.raises(VerificationError, match="signature does not verify under the pinned key"):
            verify_packet(forged, history, observer_key.public_hex, witness_key.public_hex)

    def test_unpinned_witness_is_rejected(self, tmp_path: Path) -> None:
        broker, observer_key, _, _, history = self.build(tmp_path)
        packet = broker.seal()
        with pytest.raises(VerificationError, match="checkpoint key is not the pinned witness key"):
            verify_packet(packet, history, observer_key.public_hex, SigningKey.generate().public_hex)

    def test_symlink_in_scope_becomes_explicit_gap(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        broker, observer_key, witness_key, workspace, history = self.build(tmp_path)
        (workspace / "link").symlink_to(tmp_path / "outside")
        with caplog.at_level(logging.WARNING):
            packet = broker.seal()
        claim = verify_packet(packet, history, observer_key.public_hex, witness_key.public_hex)
        assert claim["coverage"]["noDetectedGap"] is False
        assert claim["coverage"]["knownGaps"] == ["workspace contains a symbolic link"]
        assert "workspace contains a symbolic link" in caplog.text

    def test_repaired_bypass_does_not_erase_detected_gap(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        broker, observer_key, witness_key, workspace, history = self.build(tmp_path)
        bypass = workspace / "bypass"
        bypass.write_bytes(b"transient between calls")
        with caplog.at_level(logging.WARNING), pytest.raises(CoverageError, match="workspace changed outside the broker"):
            broker.write("one", "/work/result", b"legitimate")
        bypass.unlink()
        packet = broker.seal()
        claim = verify_packet(packet, history, observer_key.public_hex, witness_key.public_hex, workspace)
        assert claim["coverage"]["noDetectedGap"] is False
        assert claim["coverage"]["knownGaps"] == ["workspace changed outside the broker"]
        assert "observer coverage gap: workspace changed outside the broker" in caplog.text

    def test_duplicate_json_member_is_refused(self) -> None:
        with pytest.raises(VerificationError, match="duplicate JSON member"):
            strict_loads(b'{"a":1,"a":2}')

    def test_noncanonical_encoding_is_refused(self) -> None:
        with pytest.raises(VerificationError, match="JSON document is not canonical"):
            strict_loads(b'{ "a": 1 }')

    def test_prototype_rejects_unsafe_number(self) -> None:
        with pytest.raises(VerificationError, match="integer exceeds the safe JSON range"):
            canonical({"n": 2**53})

    @pytest.mark.parametrize(
        ("events", "message"),
        [
            ([{"kind": "begin"}, {"kind": "begin"}, {"kind": "seal"}], "history has a duplicate interval boundary"),
            ([{"kind": "begin"}, {"kind": "retry", "requestId": "one", "path": "/work/x"}, {"kind": "seal"}], "history retry has no matching write"),
            ([{"kind": "begin"}, {"kind": "write", "requestId": "one", "path": "/work/x"}, {"kind": "write", "requestId": "one", "path": "/work/x"}, {"kind": "seal"}], "history repeats a write request id"),
            ([{"kind": "begin"}, {"kind": "unrecognized"}, {"kind": "seal"}], "history has an unknown event kind"),
        ],
    )
    def test_history_refuses_invalid_event_sequences(self, events: list[dict[str, str]], message: str) -> None:
        with pytest.raises(VerificationError, match=message):
            _verify_request_sequence([{"event": event} for event in events])

    def test_offset_timestamp_cannot_pass_lexical_order_gate(self, tmp_path: Path) -> None:
        broker, observer_key, _, _, _ = self.build(tmp_path)
        packet = broker.seal()
        commitment = packet["commitment"]
        commitment["committedAt"] = "2026-09-18T20:00:00-05:00"
        payload = {"preimage": commitment["preimage"], "committedAt": commitment["committedAt"]}
        commitment["signature"] = observer_key.sign("probity-prior-commitment-v0", payload)
        with pytest.raises(VerificationError, match="record timestamps must use UTC second precision"):
            _verify_commitment(packet, observer_key.public_hex)

    def test_witness_cannot_reuse_observer_key(self, tmp_path: Path) -> None:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        key = SigningKey.generate()
        with pytest.raises(CoverageError, match="observer and witness must use different keys"):
            Broker(
                workspace,
                tmp_path / "history.jsonl",
                {"intervalId": "one", "scope": "/work", "operation": "write-file"},
                key,
                Witness(tmp_path / "witness.json", key),
            )

    def test_witness_state_cannot_overlap_history(self, tmp_path: Path) -> None:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        same_file = tmp_path / "history.jsonl"
        with pytest.raises(CoverageError, match="history and witness state must use different files"):
            Broker(
                workspace,
                same_file,
                {"intervalId": "one", "scope": "/work", "operation": "write-file"},
                SigningKey.generate(),
                Witness(same_file, SigningKey.generate()),
            )
