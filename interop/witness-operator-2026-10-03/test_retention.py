"""Signed-prefix, filesystem, crash and concurrency controls for host retention."""

from __future__ import annotations

import logging
import os
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from probity_observer import Broker, LedgerWitness, SigningKey, VerificationError
from probity_observer.crypto import canonical, strict_loads
from probity_observer.ledger import verify_ledger_head
from probity_witness_operator import retention
from probity_witness_operator.protocol import sha


@dataclass
class Case:
    """Real author-generated receipt chains and separately selected host state."""

    root: Path
    observer: SigningKey
    witness: LedgerWitness
    candidate: Path
    retained: Path

    def advance(self, interval: str) -> dict[str, Any]:
        """Register a real signed begin under a fresh observed workspace."""
        work = self.root / interval
        work.mkdir()
        broker = Broker(work, self.root / (interval + ".jsonl"),
                        {"intervalId": interval, "scope": "/work", "operation": "write-file"},
                        self.observer, self.witness)
        broker.begin()
        head = self.witness.signed_head()
        self.candidate.write_bytes(canonical(head))
        return head

    def promote(self, *, initial: bool = False, previous_sha256: str | None = None) -> dict[str, Any]:
        """Call the public consumer seam using selected exact file digests."""
        selected = previous_sha256
        if selected is None and not initial:
            selected = sha(self.retained.read_bytes())
        return retention.retain_head(self.witness.state_path, self.candidate, self.retained,
                                     witness_key=self.witness.public_hex,
                                     ledger_sha256=sha(self.witness.state_path.read_bytes()),
                                     candidate_sha256=sha(self.candidate.read_bytes()), previous_sha256=selected)


def make_case(root: Path) -> Case:
    """Build an empty real ledger and a private, separately retained head path."""
    observer, signer = SigningKey.generate(), SigningKey.generate()
    ledger = root / "ledger.jsonl"
    ledger.write_bytes(b"")
    witness = LedgerWitness(ledger, signer, observer.public_hex)
    candidate = root / "candidate.json"
    candidate.write_bytes(canonical(witness.signed_head()))
    retained_directory = root / "consumer"
    retained_directory.mkdir(mode=0o700)
    return Case(root, observer, witness, candidate, retained_directory / "head.json")


@pytest.fixture
def case(tmp_path: Path) -> Case:
    """Give every example a distinct author-controlled custody prototype."""
    return make_case(tmp_path)


def _rollback(case: Case, genesis: bytes) -> None:
    """Offer the earlier coherent empty prefix against a retained begin."""
    case.witness.state_path.write_bytes(b"")
    case.candidate.write_bytes(genesis)


def _fork(case: Case, genesis: bytes) -> None:
    """Offer a different real begin signed by the same witness operator."""
    fork_path = case.root / "fork.jsonl"
    fork_path.write_bytes(b"")
    original = case.witness
    case.witness = LedgerWitness(fork_path, original.signing_key, case.observer.public_hex)
    case.advance("alternate")
    original.state_path.write_bytes(fork_path.read_bytes())
    case.witness = original


def _signature(case: Case, genesis: bytes) -> None:
    """Replace the candidate's actual signature while keeping its ledger position."""
    head = strict_loads(case.candidate.read_bytes())
    head["signature"] = "A" * 88
    case.candidate.write_bytes(canonical(head))


def _old_candidate(case: Case, genesis: bytes) -> None:
    """Offer a valid signed old candidate against the complete newer log."""
    case.candidate.write_bytes(genesis)


def _wrong_key(case: Case, genesis: bytes) -> None:
    """Change the consumer-selected witness pin without rewriting receipts."""
    case.witness.signing_key = SigningKey.generate()


class TestRetainHead:
    class TestPassingCases:
        def test_initial_head_is_flushed_before_ack(self, case: Case, monkeypatch: pytest.MonkeyPatch) -> None:
            events: list[str] = []
            fsync, replace = os.fsync, os.replace

            def observe_fsync(descriptor: int) -> None:
                events.append("directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file")
                fsync(descriptor)

            def observe_replace(source: Path, destination: Path) -> None:
                events.append("replace")
                replace(source, destination)

            monkeypatch.setattr(os, "fsync", observe_fsync)
            monkeypatch.setattr(os, "replace", observe_replace)
            head = case.promote(initial=True)
            assert events == ["file", "replace", "directory"]
            assert case.retained.read_bytes() == canonical(head)
            assert stat.S_IMODE(case.retained.stat().st_mode) == 0o600
            assert not list(case.retained.parent.glob(".retain*"))

        @settings(max_examples=12, suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=None)
        @given(count=st.integers(min_value=1, max_value=5))
        def test_monotonic_extensions_and_exact_retry(self, tmp_path: Path, count: int) -> None:
            with TemporaryDirectory(dir=tmp_path) as directory:
                selected = make_case(Path(directory))
                selected.promote(initial=True)
                for index in range(count):
                    head = selected.advance("interval-" + str(index))
                    assert selected.promote() == head
                    assert selected.promote() == head
                retained = strict_loads(selected.retained.read_bytes())
                summary = verify_ledger_head(selected.witness.state_path, retained, selected.witness.public_hex)
                assert retained["count"] == summary["count"] == count

        def test_concurrent_stale_selection_cannot_overwrite(self, case: Case, caplog: pytest.LogCaptureFixture) -> None:
            case.promote(initial=True)
            selected = sha(case.retained.read_bytes())
            candidate = case.advance("begin")

            def try_promote() -> tuple[str, Any]:
                try:
                    return "accepted", case.promote(previous_sha256=selected)
                except VerificationError as error:
                    return "refused", str(error)

            with caplog.at_level(logging.WARNING), ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: try_promote(), range(2)))
            assert sorted(item[0] for item in results) == ["accepted", "refused"]
            assert ("refused", "retention input pin differs") in results
            assert case.retained.read_bytes() == canonical(candidate)
            assert "retained head refused: retention input pin differs" in caplog.text

        def test_installed_cli_emits_exact_durable_head(self, case: Case) -> None:
            command = [sys.executable, "-I", "-B", "-m", "probity_witness_operator.retention",
                       str(case.witness.state_path), str(case.candidate), str(case.retained),
                       "--witness-key", case.witness.public_hex,
                       "--ledger-sha256", sha(case.witness.state_path.read_bytes()),
                       "--candidate-sha256", sha(case.candidate.read_bytes()), "--initial"]
            result = subprocess.run(command, capture_output=True, timeout=10)
            assert result.returncode == 0, result.stderr.decode()
            assert result.stdout == case.retained.read_bytes() + b"\n"
            assert result.stderr == b""

    class TestFailingCases:
        @pytest.mark.parametrize("control, expected", [
            ("rollback", "ledger is shorter than the retained witness head"),
            ("fork", "ledger does not extend the retained witness head"),
            ("signature", "signature does not verify under the pinned key"),
            ("old-candidate", "candidate head is not the complete ledger head"),
            ("wrong-key", "witness receipt key differs from the pinned key"),
            ("initial-reset", "initial retention requires a new head path"),
            ("stale-pin", "retention input pin differs"),
        ])
        def test_refusal_preserves_prior_head(self, case: Case, control: str, expected: str,
                                             caplog: pytest.LogCaptureFixture) -> None:
            genesis = case.candidate.read_bytes()
            case.promote(initial=True)
            case.advance("original")
            case.promote()
            previous = case.retained.read_bytes()
            mutators = {"rollback": _rollback, "fork": _fork, "signature": _signature,
                        "old-candidate": _old_candidate, "wrong-key": _wrong_key}
            if control in mutators:
                mutators[control](case, genesis)
            initial = control == "initial-reset"
            selected = "0" * 64 if control == "stale-pin" else None
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^" + expected + "$"):
                case.promote(initial=initial, previous_sha256=selected)
            assert case.retained.read_bytes() == previous
            assert expected in caplog.text
            assert not list(case.retained.parent.glob(".retain*"))

        @pytest.mark.parametrize("stage", ["file-fsync", "replace", "directory-fsync"])
        def test_durability_failures_never_acknowledge(self, case: Case, monkeypatch: pytest.MonkeyPatch,
                                                     stage: str, caplog: pytest.LogCaptureFixture) -> None:
            case.promote(initial=True)
            previous = case.retained.read_bytes()
            head = case.advance("next")
            fsync = os.fsync

            def fail_fsync(descriptor: int) -> None:
                directory = stat.S_ISDIR(os.fstat(descriptor).st_mode)
                if directory == (stage == "directory-fsync"):
                    raise OSError("selected fsync failure")
                fsync(descriptor)

            def fail_replace(source: Path, destination: Path) -> None:
                raise OSError("selected replace failure")

            if stage == "replace":
                monkeypatch.setattr(os, "replace", fail_replace)
                message = "selected replace failure"
            else:
                monkeypatch.setattr(os, "fsync", fail_fsync)
                message = "selected fsync failure"
            with caplog.at_level(logging.WARNING), pytest.raises(OSError, match="^" + message + "$"):
                case.promote()
            expected = canonical(head) if stage == "directory-fsync" else previous
            assert case.retained.read_bytes() == expected
            assert not list(case.retained.parent.glob(".retain*"))
            assert "accepted" not in caplog.text
            monkeypatch.undo()
            assert case.promote() == head

        @pytest.mark.parametrize("mode", [0o755, 0o770, 0o777])
        def test_host_retention_directory_excludes_peers(self, case: Case, mode: int,
                                                       caplog: pytest.LogCaptureFixture) -> None:
            case.retained.parent.chmod(mode)
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^retention parent permissions differ$"):
                case.promote(initial=True)
            assert not case.retained.exists()
            assert "retained head refused: retention parent permissions differ" in caplog.text

        @pytest.mark.parametrize("control", ["hardlink", "permissions", "missing"])
        def test_existing_retained_file_protection(self, case: Case, control: str,
                                                   caplog: pytest.LogCaptureFixture) -> None:
            case.promote(initial=True)
            selected = sha(case.retained.read_bytes())
            expected = "retention file has multiple links"
            if control == "hardlink":
                os.link(case.retained, case.retained.parent / "other-link")
            elif control == "permissions":
                case.retained.chmod(0o644)
                expected = "retention file permissions differ"
            else:
                case.retained.unlink()
                expected = "selected retained head is missing"
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^" + expected + "$"):
                case.promote(previous_sha256=selected)
            assert expected in caplog.text

        @pytest.mark.parametrize("input_name", ["ledger", "candidate"])
        def test_candidate_byte_pin_is_selected_outside_bundle(self, case: Case, input_name: str,
                                                              caplog: pytest.LogCaptureFixture) -> None:
            args = {"ledger_sha256": sha(case.witness.state_path.read_bytes()),
                    "candidate_sha256": sha(case.candidate.read_bytes())}
            args[input_name + "_sha256"] = "f" * 64
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^retention input pin differs$"):
                retention.retain_head(case.witness.state_path, case.candidate, case.retained,
                                      witness_key=case.witness.public_hex, previous_sha256=None, **args)
            assert not case.retained.exists()
            assert "retained head refused: retention input pin differs" in caplog.text

        @pytest.mark.parametrize("input_name", ["ledger", "candidate"])
        def test_oversized_input_refuses_before_retaining(self, case: Case, input_name: str,
                                                        caplog: pytest.LogCaptureFixture) -> None:
            path, limit = (case.candidate, retention.MAX_HEAD_BYTES)
            if input_name == "ledger":
                path, limit = case.witness.state_path, retention.MAX_HISTORY
            path.write_bytes(b"x" * (limit + 1))
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^retention input exceeds finite limit$"):
                case.promote(initial=True)
            assert not case.retained.exists()
            assert "retained head refused: retention input exceeds finite limit" in caplog.text

        def test_installed_cli_refusal_emits_no_success_json(self, case: Case) -> None:
            command = [sys.executable, "-I", "-B", "-m", "probity_witness_operator.retention",
                       str(case.witness.state_path), str(case.candidate), str(case.retained),
                       "--witness-key", case.witness.public_hex,
                       "--ledger-sha256", "0" * 64,
                       "--candidate-sha256", sha(case.candidate.read_bytes()), "--initial"]
            result = subprocess.run(command, capture_output=True, timeout=10)
            assert result.returncode == 2
            assert result.stdout == b""
            assert result.stderr.endswith(b"retained head command refused\n")
            assert b"retention input pin differs" in result.stderr
            assert not case.retained.exists()

        @pytest.mark.parametrize("input_name", ["ledger", "candidate"])
        def test_retained_selection_cannot_be_a_submitted_file(self, case: Case, input_name: str,
                                                             caplog: pytest.LogCaptureFixture) -> None:
            destination = case.candidate if input_name == "candidate" else case.witness.state_path
            before = destination.read_bytes()
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^retained head must be separate from submitted files$"):
                retention.retain_head(case.witness.state_path, case.candidate, destination,
                                      witness_key=case.witness.public_hex,
                                      ledger_sha256=sha(case.witness.state_path.read_bytes()),
                                      candidate_sha256=sha(case.candidate.read_bytes()), previous_sha256=None)
            assert destination.read_bytes() == before
            assert "retained head must be separate from submitted files" in caplog.text

        def test_retained_symlink_alias_refuses(self, case: Case, caplog: pytest.LogCaptureFixture) -> None:
            original = case.candidate.read_bytes()
            case.retained.symlink_to(case.candidate)
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^operator path has an alias$"):
                case.promote(initial=True)
            assert case.retained.is_symlink()
            assert case.candidate.read_bytes() == original
            assert "accepted" not in caplog.text

        @pytest.mark.parametrize("input_name", ["ledger", "candidate"])
        def test_fifo_input_refuses_without_waiting_for_a_writer(self, case: Case, input_name: str,
                                                               caplog: pytest.LogCaptureFixture) -> None:
            args = {"ledger_sha256": sha(case.witness.state_path.read_bytes()),
                    "candidate_sha256": sha(case.candidate.read_bytes())}
            path = case.candidate if input_name == "candidate" else case.witness.state_path
            path.unlink()
            os.mkfifo(path, 0o600)
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^retention input is not a regular file$"):
                retention.retain_head(case.witness.state_path, case.candidate, case.retained,
                                      witness_key=case.witness.public_hex, previous_sha256=None, **args)
            assert not case.retained.exists()
            assert "retention input is not a regular file" in caplog.text
