"""Retained witness heads expose registered omissions and valid-prefix rollback."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from probity_observer import Broker, LedgerWitness, SigningKey, VerificationError, verify_ledger_head, verify_packet
from probity_observer.crypto import digest, verify_signature
from probity_observer.history import GENESIS
from probity_observer.ledger import HEAD_DOMAIN, read_ledger


@dataclass(frozen=True)
class LedgerRun:
    """Keep one local protocol fixture's keys and receipt log together."""

    root: Path
    observer: SigningKey
    witness: LedgerWitness

    def begin(self, interval: str) -> tuple[Broker, Path]:
        """Register an interval without asserting independent operation."""
        workspace = self.root / interval / "workspace"
        workspace.mkdir(parents=True)
        history = workspace.parent / "history.jsonl"
        authority = {"intervalId": interval, "scope": "/work", "operation": "write-file"}
        broker = Broker(workspace, history, authority, self.observer, self.witness)
        broker.begin()
        return broker, history

    def head(self, **changes: Any) -> dict[str, Any]:
        """Create a correctly signed candidate head, including hostile fields."""
        payload = {"format": HEAD_DOMAIN, "count": 0, "head": GENESIS, **changes}
        signer = self.witness.signing_key
        return {**payload, "keyid": signer.public_hex, "signature": signer.sign(HEAD_DOMAIN, payload)}


@pytest.fixture
def ledger_run(tmp_path: Path) -> LedgerRun:
    """Create a fresh same-operator fixture for each regression."""
    observer = SigningKey.generate()
    witness = LedgerWitness(tmp_path / "ledger.jsonl", SigningKey.generate(), observer.public_hex)
    return LedgerRun(tmp_path, observer, witness)


def assert_rejected(
    run: LedgerRun,
    retained_head: dict[str, Any],
    expected: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Compare the exact exception and the bounded warning for a rejection."""
    caplog.clear()
    with pytest.raises(VerificationError) as caught:
        verify_ledger_head(run.witness.state_path, retained_head, run.witness.signing_key.public_hex)
    assert str(caught.value) == expected
    assert caplog.messages == [f"witness ledger verification failed: {expected}"]
    assert run.observer.public_hex not in caplog.text
    assert run.witness.signing_key.public_hex not in caplog.text


class TestLedgerHead:
    class TestPassingCases:
        def test_empty_log_is_bound_to_genesis(self, ledger_run: LedgerRun) -> None:
            witness = ledger_run.witness
            head = witness.signed_head()
            payload = {key: head[key] for key in ("format", "count", "head")}
            verify_signature(witness.signing_key.public_hex, HEAD_DOMAIN, payload, head["signature"])
            assert payload == {"format": HEAD_DOMAIN, "count": 0, "head": GENESIS}
            assert head == witness.signed_head()
            assert verify_ledger_head(witness.state_path, head, witness.signing_key.public_hex) == {
                "count": 0, "head": GENESIS, "registeredIntervals": 0, "missingTerminals": [],
            }

        def test_missing_terminal_is_visible_after_signed_extension(self, ledger_run: LedgerRun) -> None:
            first, history = ledger_run.begin("sealed")
            first.write("write", "/work/x", b"observed")
            packet = first.seal()
            retained = ledger_run.witness.signed_head()
            missing, _ = ledger_run.begin("missing")
            receipts = read_ledger(ledger_run.witness.state_path, ledger_run.witness.signing_key.public_hex)
            result = verify_ledger_head(ledger_run.witness.state_path, retained, ledger_run.witness.signing_key.public_hex)
            assert result == {
                "count": 3, "head": receipts[-1]["hash"], "registeredIntervals": 2,
                "missingTerminals": [{
                    "intervalId": "missing",
                    "authorityDigest": digest("probity-authority-v0", missing.authority),
                    "observerKey": ledger_run.observer.public_hex,
                }],
            }
            claim = verify_packet(packet, history, ledger_run.observer.public_hex, ledger_run.witness.signing_key.public_hex)
            assert claim["witnessScope"] == "PEER"
            assert claim["coverage"]["unmediatedEffects"] == "not-established"

        @settings(max_examples=30, suppress_health_check=[HealthCheck.function_scoped_fixture])
        @given(terminals=st.lists(st.booleans(), min_size=0, max_size=8))
        def test_interval_summary_matches_registered_population(self, tmp_path: Path, terminals: list[bool]) -> None:
            with TemporaryDirectory(dir=tmp_path) as directory:
                root = Path(directory)
                observer = SigningKey.generate()
                witness = LedgerWitness(root / "ledger.jsonl", SigningKey.generate(), observer.public_hex)
                run = LedgerRun(root, observer, witness)
                retained = witness.signed_head()
                brokers = [run.begin(f"interval-{index}")[0] for index in range(len(terminals))]
                for broker, terminal in zip(brokers, terminals, strict=True):
                    if terminal:
                        broker.seal()
                summary = verify_ledger_head(witness.state_path, retained, witness.signing_key.public_hex)
                assert summary["count"] == len(terminals) + sum(terminals)
                assert summary["registeredIntervals"] == len(terminals)
                assert [item["intervalId"] for item in summary["missingTerminals"]] == [
                    f"interval-{index}" for index, terminal in enumerate(terminals) if not terminal
                ]

        def test_concurrent_exports_bind_to_serial_receipt_prefixes(self, ledger_run: LedgerRun) -> None:
            def produce(index: int) -> dict[str, Any]:
                broker, _ = ledger_run.begin(f"interval-{index}")
                head = ledger_run.witness.signed_head()
                broker.seal()
                return head

            with ThreadPoolExecutor(max_workers=6) as pool:
                retained = list(pool.map(produce, range(6)))
            for head in retained:
                summary = verify_ledger_head(ledger_run.witness.state_path, head, ledger_run.witness.signing_key.public_hex)
                assert summary["count"] == 12
                assert summary["registeredIntervals"] == 6
                assert summary["missingTerminals"] == []

    class TestFailingCases:
        def test_whole_interval_omission_leaves_valid_prefix_but_fails_retained_head(
            self, ledger_run: LedgerRun, caplog: pytest.LogCaptureFixture,
        ) -> None:
            for interval in ("first", "omitted"):
                ledger_run.begin(interval)[0].seal()
            retained = ledger_run.witness.signed_head()
            path = ledger_run.witness.state_path
            lines = path.read_bytes().splitlines(keepends=True)
            path.write_bytes(b"".join(lines[:2]))
            assert len(read_ledger(path, ledger_run.witness.signing_key.public_hex)) == 2
            assert_rejected(ledger_run, retained, "ledger is shorter than the retained witness head", caplog)

        def test_operator_restoration_and_resigning_still_fails_old_consumer_head(
            self, ledger_run: LedgerRun, caplog: pytest.LogCaptureFixture,
        ) -> None:
            ledger_run.begin("common")[0].seal()
            prefix = ledger_run.witness.state_path.read_bytes()
            ledger_run.begin("withheld")[0].seal()
            retained = ledger_run.witness.signed_head()
            ledger_run.witness.state_path.write_bytes(prefix)
            ledger_run.begin("replacement")[0].seal()
            fork_head = ledger_run.witness.signed_head()
            assert fork_head["count"] == retained["count"] == 4
            assert fork_head["head"] != retained["head"]
            # Trusting only the newly supplied head accepts the operator's fork.
            assert verify_ledger_head(ledger_run.witness.state_path, fork_head, fork_head["keyid"])["count"] == 4
            assert_rejected(ledger_run, retained, "ledger does not extend the retained witness head", caplog)

        @pytest.mark.parametrize("field,value", [("count", 1), ("head", "a" * 64)])
        def test_altered_signed_head_is_refused(
            self, ledger_run: LedgerRun, caplog: pytest.LogCaptureFixture, field: str, value: Any,
        ) -> None:
            head = ledger_run.witness.signed_head()
            head[field] = value
            assert_rejected(ledger_run, head, "signature does not verify under the pinned key", caplog)

        def test_correct_signature_from_unpinned_witness_is_refused(
            self, ledger_run: LedgerRun, caplog: pytest.LogCaptureFixture,
        ) -> None:
            attacker = SigningKey.generate()
            payload = {"format": HEAD_DOMAIN, "count": 0, "head": GENESIS}
            head = {**payload, "keyid": attacker.public_hex, "signature": attacker.sign(HEAD_DOMAIN, payload)}
            assert_rejected(ledger_run, head, "witness ledger head key differs from the pinned key", caplog)

        def test_checkpoint_signature_cannot_be_replayed_as_ledger_head(
            self, ledger_run: LedgerRun, caplog: pytest.LogCaptureFixture,
        ) -> None:
            head = ledger_run.witness.signed_head()
            head["signature"] = ledger_run.witness.signing_key.sign("probity-checkpoint-v0", {"count": 0, "head": GENESIS})
            assert_rejected(ledger_run, head, "signature does not verify under the pinned key", caplog)

        @pytest.mark.parametrize("changes,expected", [
            ({"count": True}, "witness ledger head has an invalid count"),
            ({"count": -1}, "witness ledger head has an invalid count"),
            ({"count": "0"}, "witness ledger head has an invalid count"),
            ({"head": None}, "witness ledger head has an invalid hash"),
            ({"head": "A" * 64}, "witness ledger head has an invalid hash"),
            ({"head": "0" * 63}, "witness ledger head has an invalid hash"),
            ({"head": "0" * 64 + "\n"}, "witness ledger head has an invalid hash"),
            ({"format": "other-v0"}, "witness ledger head has an unsupported format"),
            ({"signature": None}, "witness ledger head has an invalid signature"),
            ({"extra": "value"}, "witness ledger head has invalid fields"),
        ])
        def test_malformed_head_fields_are_refused(
            self, ledger_run: LedgerRun, caplog: pytest.LogCaptureFixture, changes: dict[str, Any], expected: str,
        ) -> None:
            head = {**ledger_run.witness.signed_head(), **changes}
            assert_rejected(ledger_run, head, expected, caplog)

        @pytest.mark.parametrize("count,head,expected", [
            (1, GENESIS, "ledger is shorter than the retained witness head"),
            (0, "a" * 64, "ledger does not extend the retained witness head"),
        ])
        def test_correctly_signed_false_position_is_refused(
            self, ledger_run: LedgerRun, caplog: pytest.LogCaptureFixture, count: int, head: str, expected: str,
        ) -> None:
            assert_rejected(ledger_run, ledger_run.head(count=count, head=head), expected, caplog)

        def test_missing_middle_receipt_is_refused_before_head_binding(
            self, ledger_run: LedgerRun, caplog: pytest.LogCaptureFixture,
        ) -> None:
            ledger_run.begin("first")[0].seal()
            ledger_run.begin("second")[0].seal()
            retained = ledger_run.witness.signed_head()
            path = ledger_run.witness.state_path
            lines = path.read_bytes().splitlines(keepends=True)
            path.write_bytes(b"".join(lines[:1] + lines[2:]))
            assert_rejected(ledger_run, retained, "witness ledger sequence or predecessor differs", caplog)

        def test_partial_receipt_line_is_refused(
            self, ledger_run: LedgerRun, caplog: pytest.LogCaptureFixture,
        ) -> None:
            ledger_run.begin("first")[0].seal()
            retained = ledger_run.witness.signed_head()
            path = ledger_run.witness.state_path
            path.write_bytes(path.read_bytes()[:-1])
            assert_rejected(ledger_run, retained, "witness ledger ends with an incomplete line", caplog)
