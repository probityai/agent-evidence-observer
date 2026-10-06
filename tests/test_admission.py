"""Consumer policy and durable replay refusal over actual signed broker records."""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from probity_observer import (
    AdmissionPolicy,
    AdmissionStore,
    Broker,
    LedgerWitness,
    SigningKey,
    VerificationError,
)
from probity_observer.admission import STATE_FORMAT, main
from probity_observer.crypto import canonical, digest, strict_loads
from probity_observer.history import GENESIS, append_history
from probity_observer.ledger import RECEIPT_DOMAIN, read_ledger


@dataclass
class ConsumerRun:
    """Hold one same-operator fixture; no test establishes external custody."""

    root: Path
    observer: SigningKey
    witness: LedgerWitness
    store: AdmissionStore

    def produce(
        self, interval: str = "requested", content: bytes = b"observed"
    ) -> tuple[dict[str, Any], Path, AdmissionPolicy]:
        """Commit consumer expectations before producing a brokered write."""
        workspace = self.root / interval / "workspace"
        workspace.mkdir(parents=True)
        history = workspace.parent / "history.jsonl"
        authority = {
            "intervalId": interval,
            "scope": "/work",
            "operation": "write-file",
        }
        policy = AdmissionPolicy(
            interval,
            digest("probity-authority-v0", authority),
            self.observer.public_hex,
            self.witness.signing_key.public_hex,
            self.witness.signed_head(),
        )
        broker = Broker(workspace, history, authority, self.observer, self.witness)
        broker.begin()
        broker.write("write", "/work/result", content)
        return broker.seal(), history, policy

    def state(self) -> dict[str, Any]:
        """Read consumer-owned canonical state for exact persistence assertions."""
        return strict_loads(self.store.state_path.read_bytes())


def make_run(root: Path) -> ConsumerRun:
    """Initialize a local consumer store and a separately keyed local witness."""
    observer = SigningKey.generate()
    witness = LedgerWitness(
        root / "producer" / "ledger.jsonl", SigningKey.generate(), observer.public_hex
    )
    store = AdmissionStore(root / "consumer" / "state.json")
    store.initialize(observer.public_hex, witness.signing_key.public_hex)
    return ConsumerRun(root, observer, witness, store)


@pytest.fixture
def run(tmp_path: Path) -> ConsumerRun:
    """Supply fresh producer and consumer directories for each regression."""
    return make_run(tmp_path)


def assert_refused(
    run: ConsumerRun,
    packet: dict[str, Any],
    history: Path,
    policy: AdmissionPolicy,
    expected: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Require exact refusal text, bounded logging, and unchanged consumer state."""
    caplog.clear()
    before = (
        run.store.state_path.read_bytes() if run.store.state_path.exists() else None
    )
    with pytest.raises(VerificationError) as caught:
        run.store.admit(packet, history, run.witness.state_path, policy)
    assert str(caught.value) == expected
    messages = [
        record.message
        for record in caplog.records
        if record.name == "probity_observer.admission"
    ]
    assert messages == [f"consumer admission refused: {expected}"]
    assert run.observer.public_hex not in caplog.text
    assert run.witness.signing_key.public_hex not in caplog.text
    after = run.store.state_path.read_bytes() if run.store.state_path.exists() else None
    assert after == before


class TestAdmissionStore:
    class TestPassingCases:
        def test_declaration_write_verification_and_decision_are_bound(
            self, run: ConsumerRun
        ) -> None:
            packet, history, policy = run.produce()
            decision = run.store.admit(packet, history, run.witness.state_path, policy)
            assert decision == {
                "status": "admitted",
                "intervalId": "requested",
                "authorityDigest": policy.authority_digest,
                "claimDigest": digest("probity-claim-v0", packet["claim"]),
                "afterRoot": packet["claim"]["afterRoot"],
                "historyHead": packet["checkpoint"]["head"],
                "ledger": {
                    "count": 2,
                    "head": packet["checkpoint"]["ledgerReceipt"]["hash"],
                },
                "witnessScope": "PEER",
            }
            assert run.state() == {
                "format": STATE_FORMAT,
                "observerKey": policy.observer_key,
                "witnessKey": policy.witness_key,
                "ledger": decision["ledger"],
                "admissions": [decision],
            }
            decision["ledger"]["head"] = "0" * 64
            assert (
                run.state()["ledger"]["head"]
                == packet["checkpoint"]["ledgerReceipt"]["hash"]
            )

        # This property checks durable bytes and retained state. Real fsync calls
        # have no per-example wall-clock requirement on a shared host.
        @settings(
            max_examples=25,
            deadline=None,
            suppress_health_check=[HealthCheck.function_scoped_fixture],
        )
        @given(content=st.binary(max_size=128))
        def test_arbitrary_durable_bytes_survive_admission(
            self, tmp_path: Path, content: bytes
        ) -> None:
            with TemporaryDirectory(dir=tmp_path) as directory:
                fixture = make_run(Path(directory))
                packet, history, policy = fixture.produce(content=content)
                result = fixture.store.admit(
                    packet, history, fixture.witness.state_path, policy
                )
                assert (
                    packet["claim"]["writes"][0]["contentDigest"]
                    == hashlib.sha256(content).hexdigest()
                )
                assert result["afterRoot"] == packet["claim"]["afterRoot"]
                assert fixture.state()["admissions"] == [result]

        def test_new_interval_advances_saved_head_across_store_instances(
            self, run: ConsumerRun
        ) -> None:
            first, first_history, first_policy = run.produce("first")
            run.store.admit(first, first_history, run.witness.state_path, first_policy)
            second, second_history, second_policy = run.produce("second")
            reopened = AdmissionStore(run.store.state_path)
            decision = reopened.admit(
                second, second_history, run.witness.state_path, second_policy
            )
            assert decision["ledger"]["count"] == 4
            assert [item["intervalId"] for item in run.state()["admissions"]] == [
                "first",
                "second",
            ]

        def test_existing_complete_intervals_can_share_one_captured_ledger_head(
            self, run: ConsumerRun
        ) -> None:
            first, first_history, first_policy = run.produce("first")
            second, second_history, second_policy = run.produce("second")
            one = run.store.admit(
                first, first_history, run.witness.state_path, first_policy
            )
            two = run.store.admit(
                second, second_history, run.witness.state_path, second_policy
            )
            assert one["ledger"] == two["ledger"]
            assert two["ledger"]["count"] == 4

        def test_unrelated_missing_terminal_does_not_assert_global_completion(
            self, run: ConsumerRun
        ) -> None:
            packet, history, policy = run.produce()
            workspace = run.root / "unfinished"
            workspace.mkdir()
            broker = Broker(
                workspace,
                run.root / "unfinished.jsonl",
                {
                    "intervalId": "unfinished",
                    "scope": "/work",
                    "operation": "write-file",
                },
                run.observer,
                run.witness,
            )
            broker.begin()
            decision = run.store.admit(packet, history, run.witness.state_path, policy)
            assert decision["ledger"]["count"] == 3
            assert decision["intervalId"] == "requested"
            assert decision["witnessScope"] == "PEER"

        def test_concurrent_consumers_admit_same_interval_only_once(
            self, run: ConsumerRun
        ) -> None:
            packet, history, policy = run.produce()

            def attempt(index: int) -> str:
                store = AdmissionStore(run.store.state_path)
                try:
                    store.admit(packet, history, run.witness.state_path, policy)
                    return "admitted"
                except VerificationError as exc:
                    return str(exc)

            with ThreadPoolExecutor(max_workers=6) as pool:
                outcomes = list(pool.map(attempt, range(6)))
            assert outcomes.count("admitted") == 1
            assert outcomes.count("interval was already admitted by this consumer") == 5
            assert len(run.state()["admissions"]) == 1

        def test_command_requires_explicit_policy_and_persists_decision(
            self,
            run: ConsumerRun,
            capsys: pytest.CaptureFixture[str],
        ) -> None:
            packet, history, policy = run.produce()
            policy_path = run.root / "consumer-policy.json"
            packet_path = run.root / "packet.json"
            policy_path.write_bytes(canonical(asdict(policy)))
            packet_path.write_bytes(canonical(packet))
            args = [
                "admit",
                "--state",
                str(run.store.state_path),
                "--policy",
                str(policy_path),
                "--packet",
                str(packet_path),
                "--history",
                str(history),
                "--ledger",
                str(run.witness.state_path),
            ]
            assert main(args) == 0
            assert json.loads(capsys.readouterr().out) == run.state()["admissions"][0]
            assert main(args) == 1
            assert json.loads(capsys.readouterr().out) == {"status": "refused"}

        def test_initialize_command_creates_private_consumer_state(
            self,
            tmp_path: Path,
            capsys: pytest.CaptureFixture[str],
        ) -> None:
            observer, witness = SigningKey.generate(), SigningKey.generate()
            path = tmp_path / "consumer.json"
            assert (
                main(
                    [
                        "init",
                        "--state",
                        str(path),
                        "--observer-key",
                        observer.public_hex,
                        "--witness-key",
                        witness.public_hex,
                    ]
                )
                == 0
            )
            assert json.loads(capsys.readouterr().out) == {"status": "initialized"}
            assert path.stat().st_mode & 0o777 == 0o600

    class TestFailingCases:
        @pytest.mark.parametrize(
            "field,value,expected",
            [
                (
                    "format",
                    "other-format",
                    "consumer admission state has invalid fields",
                ),
                ("unexpected", True, "consumer admission state has invalid fields"),
                (
                    "ledger",
                    [],
                    "consumer admission state has an invalid ledger position",
                ),
                (
                    "ledger",
                    {"count": 0, "head": "invalid"},
                    "consumer admission state has an invalid ledger head",
                ),
                (
                    "ledger",
                    {"count": 0, "head": "f" * 64},
                    "consumer admission state differs from its decision history",
                ),
                ("admissions", {}, "consumer admission state has invalid decisions"),
                ("admissions", [{}], "consumer admission state has invalid decisions"),
            ],
        )
        def test_malformed_consumer_state_is_refused(
            self,
            run: ConsumerRun,
            field: str,
            value: Any,
            expected: str,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            packet, history, policy = run.produce()
            state = run.state()
            state[field] = value
            run.store.state_path.write_bytes(canonical(state))
            assert_refused(run, packet, history, policy, expected, caplog)

        @pytest.mark.parametrize(
            "field,value,expected",
            [
                ("intervalId", "", "consumer admission state has invalid decisions"),
                (
                    "afterRoot",
                    "invalid",
                    "consumer admission state has invalid decisions",
                ),
                (
                    "status",
                    "verified",
                    "consumer admission state has invalid decisions",
                ),
                (
                    "witnessScope",
                    "EXTERNAL",
                    "consumer admission state has invalid decisions",
                ),
                (
                    "ledger",
                    {"count": True, "head": GENESIS},
                    "consumer admission state has an invalid ledger count",
                ),
            ],
        )
        def test_malformed_saved_decision_is_refused(
            self,
            run: ConsumerRun,
            field: str,
            value: Any,
            expected: str,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            first, first_history, first_policy = run.produce("first")
            run.store.admit(first, first_history, run.witness.state_path, first_policy)
            packet, history, policy = run.produce("second")
            state = run.state()
            state["admissions"][0][field] = value
            run.store.state_path.write_bytes(canonical(state))
            assert_refused(run, packet, history, policy, expected, caplog)

        def test_signed_receipts_must_bind_the_consumer_authority_and_interval(
            self,
            run: ConsumerRun,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            packet, history, policy = run.produce()
            receipts = read_ledger(run.witness.state_path, policy.witness_key)
            previous = GENESIS
            forged = []
            for receipt in receipts:
                body = {
                    key: receipt[key]
                    for key in (
                        "sequence",
                        "previous",
                        "intervalId",
                        "authorityDigest",
                        "observerKey",
                        "phase",
                        "checkpoint",
                    )
                }
                body["intervalId"] = "other-interval"
                body["previous"] = previous
                candidate = {
                    **body,
                    "hash": digest(RECEIPT_DOMAIN, body),
                    "keyid": policy.witness_key,
                    "signature": run.witness.signing_key.sign(RECEIPT_DOMAIN, body),
                }
                forged.append(candidate)
                previous = candidate["hash"]
            run.witness.state_path.write_bytes(
                b"".join(canonical(item) + b"\n" for item in forged)
            )
            packet["startCheckpoint"]["ledgerReceipt"] = forged[0]
            packet["checkpoint"]["ledgerReceipt"] = forged[1]
            assert_refused(
                run,
                packet,
                history,
                policy,
                "witness receipt differs from consumer policy",
                caplog,
            )

        def test_unresolved_intent_cannot_supply_a_complete_packet(
            self,
            run: ConsumerRun,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            packet, history, policy = run.produce()
            history.write_bytes(history.read_bytes().splitlines()[0] + b"\n")
            append_history(
                history,
                {
                    "kind": "write-intent",
                    "requestId": "unresolved",
                    "path": "/work/x",
                    "contentDigest": "0" * 64,
                    "beforeRoot": packet["claim"]["beforeRoot"],
                },
            )
            append_history(
                history,
                {
                    "kind": "seal",
                    "claimDigest": digest("probity-claim-v0", packet["claim"]),
                },
            )
            assert_refused(
                run,
                packet,
                history,
                policy,
                "history has an unresolved write intent",
                caplog,
            )

        def test_missing_ledger_receipt_is_not_an_admission(
            self,
            run: ConsumerRun,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            packet, history, policy = run.produce()
            del packet["checkpoint"]["ledgerReceipt"]
            assert_refused(
                run, packet, history, policy, "admission input is malformed", caplog
            )

        @pytest.mark.parametrize(
            "field,value,expected",
            [
                (
                    "interval_id",
                    "other",
                    "packet interval differs from consumer policy",
                ),
                (
                    "authority_digest",
                    "0" * 64,
                    "packet authority differs from consumer policy",
                ),
                ("interval_id", "", "consumer policy has an invalid interval id"),
                (
                    "interval_id",
                    "non-ascii-\u00e9",
                    "consumer policy has an invalid interval id",
                ),
                (
                    "authority_digest",
                    "not-a-digest",
                    "consumer policy has an invalid authority digest",
                ),
                (
                    "observer_key",
                    "0" * 64,
                    "consumer admission state belongs to different keys",
                ),
                (
                    "witness_key",
                    "f" * 64,
                    "consumer admission state belongs to different keys",
                ),
                ("observer_key", "short", "consumer policy has an invalid public key"),
            ],
        )
        def test_policy_mismatches_and_invalid_fields_are_refused(
            self,
            run: ConsumerRun,
            field: str,
            value: str,
            expected: str,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            packet, history, policy = run.produce()
            assert_refused(
                run,
                packet,
                history,
                replace(policy, **{field: value}),
                expected,
                caplog,
            )

        def test_differently_authorized_scope_is_not_accepted_even_with_valid_signatures(
            self,
            run: ConsumerRun,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            packet, history, policy = run.produce()
            expected_authority = {
                "intervalId": "requested",
                "scope": "/elsewhere",
                "operation": "write-file",
            }
            policy = replace(
                policy,
                authority_digest=digest("probity-authority-v0", expected_authority),
            )
            assert_refused(
                run,
                packet,
                history,
                policy,
                "packet authority differs from consumer policy",
                caplog,
            )

        def test_identical_packet_is_refused_after_restart(
            self, run: ConsumerRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            packet, history, policy = run.produce()
            run.store.admit(packet, history, run.witness.state_path, policy)
            run.store = AdmissionStore(run.store.state_path)
            assert_refused(
                run,
                packet,
                history,
                policy,
                "interval was already admitted by this consumer",
                caplog,
            )

        def test_missing_store_never_initializes_implicitly(
            self, run: ConsumerRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            packet, history, policy = run.produce()
            run.store.state_path.unlink()
            assert_refused(
                run,
                packet,
                history,
                policy,
                "consumer admission state is missing",
                caplog,
            )

        def test_initialization_cannot_overwrite_accepted_state(
            self, run: ConsumerRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            packet, history, policy = run.produce()
            run.store.admit(packet, history, run.witness.state_path, policy)
            before = run.store.state_path.read_bytes()
            with pytest.raises(VerificationError) as caught:
                run.store.initialize(policy.observer_key, policy.witness_key)
            assert str(caught.value) == "consumer admission state already exists"
            assert caplog.messages == [
                "consumer initialization refused: state already exists"
            ]
            assert run.store.state_path.read_bytes() == before

        def test_empty_and_corrupt_state_do_not_reset_decisions(
            self,
            run: ConsumerRun,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            packet, history, policy = run.produce()
            run.store.state_path.write_bytes(b"")
            assert_refused(
                run, packet, history, policy, "invalid JSON document", caplog
            )

        @pytest.mark.parametrize("count", [True, -1, "1"])
        def test_invalid_saved_head_count_is_refused(
            self,
            run: ConsumerRun,
            count: Any,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            packet, history, policy = run.produce()
            state = run.state()
            state["ledger"]["count"] = count
            run.store.state_path.write_bytes(canonical(state))
            assert_refused(
                run,
                packet,
                history,
                policy,
                "consumer admission state has an invalid ledger count",
                caplog,
            )

        def test_signed_retained_head_detects_withheld_terminal(
            self, run: ConsumerRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            packet, history, policy = run.produce()
            policy = replace(policy, retained_witness_head=run.witness.signed_head())
            raw = run.witness.state_path.read_bytes()
            run.witness.state_path.write_bytes(raw.splitlines()[0] + b"\n")
            assert_refused(
                run,
                packet,
                history,
                policy,
                "ledger is shorter than the retained witness head",
                caplog,
            )

        def test_old_head_cannot_hide_missing_terminal_receipt(
            self, run: ConsumerRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            packet, history, policy = run.produce()
            raw = run.witness.state_path.read_bytes()
            run.witness.state_path.write_bytes(raw.splitlines()[0] + b"\n")
            assert_refused(
                run,
                packet,
                history,
                policy,
                "witness checkpoint is absent from the ledger",
                caplog,
            )

        def test_local_saved_head_prevents_rollback_even_with_older_policy_pin(
            self,
            run: ConsumerRun,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            first, first_history, first_policy = run.produce("first")
            old_bytes = run.witness.state_path.read_bytes()
            second, second_history, second_policy = run.produce("second")
            run.store.admit(
                second, second_history, run.witness.state_path, second_policy
            )
            run.witness.state_path.write_bytes(old_bytes)
            assert_refused(
                run,
                first,
                first_history,
                first_policy,
                "ledger is shorter than the consumer retained head",
                caplog,
            )

        def test_same_length_signed_fork_does_not_extend_saved_consumer_head(
            self,
            run: ConsumerRun,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            first, first_history, first_policy = run.produce("first")
            run.store.admit(first, first_history, run.witness.state_path, first_policy)
            run.witness.state_path.unlink()
            fork, fork_history, fork_policy = run.produce("fork")
            assert_refused(
                run,
                fork,
                fork_history,
                fork_policy,
                "ledger does not extend the consumer retained head",
                caplog,
            )

        def test_forged_retained_head_signature_is_refused(
            self, run: ConsumerRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            packet, history, policy = run.produce()
            head = {**policy.retained_witness_head, "head": "f" * 64}
            assert_refused(
                run,
                packet,
                history,
                replace(policy, retained_witness_head=head),
                "signature does not verify under the pinned key",
                caplog,
            )

        def test_observer_and_witness_cannot_share_one_key(
            self, run: ConsumerRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            packet, history, policy = run.produce()
            assert_refused(
                run,
                packet,
                history,
                replace(policy, witness_key=policy.observer_key),
                "consumer observer and witness keys must differ",
                caplog,
            )

        def test_truncated_broker_history_is_refused(
            self, run: ConsumerRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            packet, history, policy = run.produce()
            history.write_bytes(
                b"\n".join(history.read_bytes().splitlines()[:-1]) + b"\n"
            )
            assert_refused(
                run, packet, history, policy, "history has no final seal", caplog
            )

        def test_unfinished_interval_cannot_supply_an_old_complete_packet(
            self,
            run: ConsumerRun,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            packet, history, policy = run.produce()
            history.write_bytes(history.read_bytes().splitlines()[0] + b"\n")
            assert_refused(
                run, packet, history, policy, "history has no final seal", caplog
            )

        def test_abort_history_is_not_a_complete_admission(
            self, run: ConsumerRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            packet, history, policy = run.produce()
            history.write_bytes(history.read_bytes().splitlines()[0] + b"\n")
            append_history(
                history,
                {
                    "kind": "incomplete",
                    "reason": "isolation setup failed",
                    "requestIds": [],
                },
            )
            assert_refused(
                run, packet, history, policy, "history has no final seal", caplog
            )

        def test_known_coverage_gap_is_not_admitted(
            self, run: ConsumerRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            workspace = run.root / "gap" / "workspace"
            workspace.mkdir(parents=True)
            authority = {
                "intervalId": "gap",
                "scope": "/work",
                "operation": "write-file",
            }
            policy = AdmissionPolicy(
                "gap",
                digest("probity-authority-v0", authority),
                run.observer.public_hex,
                run.witness.signing_key.public_hex,
                run.witness.signed_head(),
            )
            history = workspace.parent / "history.jsonl"
            broker = Broker(workspace, history, authority, run.observer, run.witness)
            broker.begin()
            (workspace / "bypass").write_bytes(b"outside the broker")
            packet = broker.seal()
            assert_refused(
                run,
                packet,
                history,
                policy,
                "consumer admission requires no detected coverage gap",
                caplog,
            )

        def test_valid_other_interval_receipts_cannot_be_swapped(
            self, run: ConsumerRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            packet, history, policy = run.produce()
            other, _, _ = run.produce("other")
            packet["startCheckpoint"]["ledgerReceipt"] = other["startCheckpoint"][
                "ledgerReceipt"
            ]
            assert_refused(
                run,
                packet,
                history,
                policy,
                "witness receipts name different intervals or order",
                caplog,
            )

        def test_self_signed_packet_from_unpinned_keys_is_refused(
            self, run: ConsumerRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            run.produce("consumer-original")
            alien = make_run(run.root / "alien")
            packet, history, _ = alien.produce()
            policy = AdmissionPolicy(
                "requested",
                digest("probity-authority-v0", packet["authority"]),
                run.observer.public_hex,
                run.witness.signing_key.public_hex,
                run.witness.signed_head(),
            )
            assert_refused(
                run,
                packet,
                history,
                policy,
                "claim key is not the pinned observer key",
                caplog,
            )

        @pytest.mark.parametrize(
            "packet", [{}, {"claim": []}, {"claim": {"format": "bad"}}]
        )
        def test_malformed_packet_has_a_bounded_refusal(
            self,
            run: ConsumerRun,
            packet: dict[str, Any],
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            _, history, policy = run.produce()
            assert_refused(
                run, packet, history, policy, "admission input is malformed", caplog
            )

        def test_failed_atomic_replace_leaves_prior_decisions_unchanged(
            self,
            run: ConsumerRun,
            caplog: pytest.LogCaptureFixture,
            monkeypatch: pytest.MonkeyPatch,
        ) -> None:
            packet, history, policy = run.produce()

            def fail_replace(source: Path, destination: Path) -> None:
                raise OSError("sensitive host error")

            monkeypatch.setattr("probity_observer.admission.os.replace", fail_replace)
            assert_refused(
                run, packet, history, policy, "admission storage is unavailable", caplog
            )
            assert not list(run.store.state_path.parent.glob(".admission-*"))
            assert "sensitive host error" not in caplog.text

        def test_failure_after_replacement_never_allows_duplicate_admission(
            self,
            run: ConsumerRun,
            caplog: pytest.LogCaptureFixture,
            monkeypatch: pytest.MonkeyPatch,
        ) -> None:
            packet, history, policy = run.produce()

            def fail_sync(path: Path) -> None:
                raise OSError("directory flush failed")

            with monkeypatch.context() as patch:
                patch.setattr("probity_observer.admission._sync_parent", fail_sync)
                with pytest.raises(VerificationError) as caught:
                    run.store.admit(packet, history, run.witness.state_path, policy)
                assert str(caught.value) == "admission storage is unavailable"
            assert len(run.state()["admissions"]) == 1
            assert_refused(
                run,
                packet,
                history,
                policy,
                "interval was already admitted by this consumer",
                caplog,
            )

        def test_snapshot_checks_do_not_reread_a_changed_original_ledger(
            self,
            run: ConsumerRun,
            monkeypatch: pytest.MonkeyPatch,
        ) -> None:
            packet, history, policy = run.produce()
            from probity_observer import admission

            original = admission.verify_ledger_head

            def check_snapshot(
                path: Path, head: dict[str, Any], key: str
            ) -> dict[str, Any]:
                assert path != run.witness.state_path
                result = original(path, head, key)
                run.witness.state_path.write_bytes(
                    b"withheld or damaged after snapshot"
                )
                return result

            monkeypatch.setattr(admission, "verify_ledger_head", check_snapshot)
            result = run.store.admit(packet, history, run.witness.state_path, policy)
            assert result["ledger"]["count"] == 2
            assert len(run.state()["admissions"]) == 1
