"""Replay signed native forks using only retained public input files."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from probity_observer import Broker, LedgerWitness, SigningKey, VerificationError
from probity_observer.crypto import canonical, strict_loads

from probity_witness_operator import reader


@pytest.fixture
def public_fork(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    """Produce two authentic equal-count histories under one witness public pin."""
    witness_key, observer = SigningKey.generate(), SigningKey.generate()
    directory = tmp_path / "public"
    directory.mkdir()
    for name, interval in [("ledger", "authentic"), ("fork-ledger", "alternate")]:
        workspace = tmp_path / interval
        workspace.mkdir()
        witness = LedgerWitness(directory / (name + ".jsonl"), witness_key, observer.public_hex)
        (tmp_path / "genesis.json").write_bytes(canonical(witness.signed_head()))
        broker = Broker(workspace, tmp_path / (interval + ".jsonl"), {"intervalId": interval, "scope": "/work", "operation": "write-file"}, observer, witness)
        broker.begin()
        head = "head.json" if name == "ledger" else "fork-head.json"
        (directory / head).write_bytes(canonical(witness.signed_head()))
    return directory, {"witnessKey": witness_key.public_hex, "files": {path.name: reader.sha(path.read_bytes()) for path in directory.iterdir()}}


class TestPublicForkReplay:
    class TestPassingCases:
        def test_authentic_signed_alternate_refuses_in_fresh_consumer(self, public_fork: tuple[Path, dict[str, Any]]) -> None:
            """An installed CLI refuses the actual equal-count fork without keys."""
            directory, policy = public_fork
            before = {path.name: path.read_bytes() for path in directory.iterdir()}
            report = reader._replay_fork(directory, policy)
            assert report["sameKey"] is True
            assert report["receiptCount"] == 1
            assert report["returncode"] == 2
            assert report["stdoutHex"] == ""
            assert report["retainedHeadUnchanged"] is True
            assert b"ledger does not extend the retained witness head" in bytes.fromhex(report["stderrHex"])
            assert {path.name: path.read_bytes() for path in directory.iterdir()} == before

    class TestFailingCases:
        @pytest.mark.parametrize("selected", ["fork-head.json", "fork-ledger.jsonl"])
        def test_missing_public_input_refuses(self, public_fork: tuple[Path, dict[str, Any]], selected: str) -> None:
            """A summary alone cannot substitute for a missing rejected signed input."""
            directory, policy = public_fork
            (directory / selected).unlink()
            with pytest.raises((FileNotFoundError, VerificationError)):
                reader._replay_fork(directory, policy)

        def test_different_selected_key_refuses(self, public_fork: tuple[Path, dict[str, Any]]) -> None:
            """The rejected records cannot choose their own witness key."""
            directory, _ = public_fork
            with pytest.raises(VerificationError):
                reader._replay_fork(directory, {"witnessKey": SigningKey.generate().public_hex})

        @pytest.mark.parametrize("selected", ["fork-head.json", "fork-ledger.jsonl"])
        def test_rehashed_public_signature_substitution_refuses(self, public_fork: tuple[Path, dict[str, Any]], selected: str) -> None:
            """Selected bytes still need authentic signatures and a coherent log."""
            directory, policy = public_fork
            path = directory / selected
            value = strict_loads(path.read_bytes().strip())
            value["signature"] = "0" * len(value["signature"])
            path.write_bytes(canonical(value) + (b"\n" if selected.endswith("jsonl") else b""))
            with pytest.raises(VerificationError):
                reader._replay_fork(directory, policy)

        def test_same_history_is_not_a_fork_control(self, public_fork: tuple[Path, dict[str, Any]]) -> None:
            """A genuine cached head cannot pass as the required hostile history."""
            directory, policy = public_fork
            (directory / "fork-ledger.jsonl").write_bytes((directory / "ledger.jsonl").read_bytes())
            (directory / "fork-head.json").write_bytes((directory / "head.json").read_bytes())
            with pytest.raises(VerificationError, match="equal-count alternate"):
                reader._replay_fork(directory, policy)

        def test_valid_shorter_history_is_not_the_same_count_fork(self, public_fork: tuple[Path, dict[str, Any]]) -> None:
            """A valid signed rollback cannot substitute for the alternate fork."""
            directory, policy = public_fork
            (directory / "fork-ledger.jsonl").write_bytes(b"")
            (directory / "fork-head.json").write_bytes((directory.parent / "genesis.json").read_bytes())
            with pytest.raises(VerificationError, match="equal-count alternate"):
                reader._replay_fork(directory, policy)

        @pytest.mark.parametrize("control", ["initial-refusal", "fork-success", "fork-unrelated-refusal", "retained-mutation", "fork-input-mutated"])
        def test_process_outcome_cannot_false_pass(self, public_fork: tuple[Path, dict[str, Any]], monkeypatch: pytest.MonkeyPatch, control: str) -> None:
            """Only a prefix refusal with unchanged real retained bytes can pass."""
            directory, policy = public_fork
            real = reader._retain_command

            def command(ledger: Path, candidate: Path, retained: Path, key: str, pins: dict[str, str], selection: list[str]) -> subprocess.CompletedProcess[bytes]:
                """Keep real initial custody and discriminate later process failures."""
                if control == "fork-input-mutated" and selection != ["--initial"]:
                    ledger.write_bytes((directory / "ledger.jsonl").read_bytes())
                    candidate.write_bytes((directory / "head.json").read_bytes())
                result = real(ledger, candidate, retained, key, pins, selection)
                if control == "fork-input-mutated" and selection != ["--initial"]:
                    assert result.returncode == 2
                    assert b"retention input pin differs" in result.stderr
                    return result
                if selection == ["--initial"]:
                    return subprocess.CompletedProcess([], 2, b"", b"") if control == "initial-refusal" else result
                if control == "fork-success":
                    return subprocess.CompletedProcess([], 0, candidate.read_bytes() + b"\n", b"")
                if control == "fork-unrelated-refusal":
                    return subprocess.CompletedProcess([], 2, b"", b"retained head command refused\n")
                retained.write_bytes(b"changed")
                return result

            monkeypatch.setattr(reader, "_retain_command", command)
            with pytest.raises(VerificationError):
                reader._replay_fork(directory, policy)
