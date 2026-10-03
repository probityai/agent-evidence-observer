"""Discriminating operator, public port and exact-history refusal controls."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings, strategies as st

from probity_observer import Broker, SigningKey, VerificationError, Witness, verify_packet
from probity_observer.crypto import canonical, strict_loads
from probity_observer.history import append_history, read_history
from probity_observer.ledger import read_ledger, verify_ledger_head

from probity_witness_operator.client import WitnessClient
from probity_witness_operator.protocol import FORMAT, REPLY_DOMAIN, history_entries, request_bytes, sha, verify_reply
from probity_witness_operator.store import Configuration, OperatorStore, generate_key, initialize
from probity_witness_operator.reader import _terminal
from probity_witness_operator.worker import _write_action


@dataclass
class Case:
    """Keep independent host inputs separate from submitted history bytes."""

    root: Path
    config: Configuration
    retained: Path
    store: OperatorStore
    observer: SigningKey

    def client(self, monkeypatch: pytest.MonkeyPatch) -> WitnessClient:
        """Use direct request bytes for unit tests; native IPC is tested separately."""
        client = WitnessClient(self.config.socket_path, self.config.witness_key,
                               self.config.observer_key, os.getuid(), strict_loads(self.retained.read_bytes()))
        monkeypatch.setattr(client, "_exchange", self.store.handle)
        return client

    def broker(self, monkeypatch: pytest.MonkeyPatch, interval: str = "run") -> Broker:
        """Create a broker using only the public witness port."""
        directory = self.root / interval
        directory.mkdir()
        workspace = directory / "work"
        workspace.mkdir()
        return Broker(workspace, directory / "history.jsonl", {"intervalId": interval, "scope": "/work", "operation": "write-file"},
                      self.observer, self.client(monkeypatch))

    def reopen(self, head: dict[str, Any]) -> OperatorStore:
        """Retain a head outside the operator store before reopening."""
        self.retained.write_bytes(canonical(head))
        return OperatorStore(self.config, self.retained, sha(self.retained.read_bytes()))


@pytest.fixture
def case(tmp_path: Path) -> Case:
    """Initialize one fresh explicit host configuration for each control."""
    observer = SigningKey.generate()
    key_path = tmp_path / "operator.key"
    witness_key = generate_key(key_path)
    value = {"format": FORMAT, "keyPath": str(key_path), "storePath": str(tmp_path / "state"),
             "socketPath": str(tmp_path / "operator.sock"), "observerKey": observer.public_hex,
             "witnessKey": witness_key, "clientUid": os.getuid()}
    config_path = tmp_path / "operator.json"
    config_path.write_bytes(canonical(value))
    config = Configuration.read(config_path, sha(config_path.read_bytes()))
    head = initialize(config)
    retained = tmp_path / "host-retained-head.json"
    retained.write_bytes(canonical(head))
    return Case(tmp_path, config, retained, OperatorStore(config, retained, sha(retained.read_bytes())), observer)


class TestOperator:
    class TestPassingCases:
        @pytest.mark.parametrize("alter_target", [False, True])
        def test_authorized_reader_replays_actual_worker_record(self, case: Case, monkeypatch: pytest.MonkeyPatch, alter_target: bool) -> None:
            broker = case.broker(monkeypatch)
            issuer_path = case.root / "issuer.key"
            issuer_key = generate_key(issuer_path)
            broker.begin()
            directory = broker.history_path.parent
            authorized = _write_action(broker, directory, {"issuerKeyPath": str(issuer_path), "issuerKey": issuer_key})
            directory.joinpath("packet.json").write_bytes(canonical(authorized.seal()))
            record = strict_loads(directory.joinpath("authorization.json").read_bytes())
            selected = {"request": record["request"], "issuerKey": issuer_key,
                        "observerKey": case.observer.public_hex, "witnessKey": case.config.witness_key}
            if alter_target:
                broker.workspace.joinpath("result.txt").write_bytes(b"different committed bytes")
                with pytest.raises(VerificationError):
                    _terminal(directory, selected)
            else:
                _terminal(directory, selected)

        def test_initialized_directory_link_is_flushed_before_ack(self, case: Case, monkeypatch: pytest.MonkeyPatch) -> None:
            import stat
            original = os.fsync
            observed = []
            def capture(descriptor: int) -> None:
                metadata = os.fstat(descriptor)
                observed.append((metadata.st_ino, stat.S_ISDIR(metadata.st_mode)))
                original(descriptor)
            monkeypatch.setattr(os, "fsync", capture)
            selected = replace(case.config, store_path=case.root / "fresh-state")
            head = initialize(selected)
            assert head["count"] == 0
            assert observed[-1] == (selected.store_path.parent.stat().st_ino, True)
            assert (selected.store_path.stat().st_ino, True) in observed
            assert sum(not directory for _, directory in observed) == 2

        def test_public_port_broker_retains_signed_effect(self, case: Case, monkeypatch: pytest.MonkeyPatch) -> None:
            broker = case.broker(monkeypatch)
            assert not hasattr(broker.witness, "signing_key")
            assert not hasattr(broker.witness, "state_path")
            broker.begin()
            broker.write("write-1", "/work/result.txt", b"committed")
            packet = broker.seal()
            claim = verify_packet(packet, broker.history_path, case.observer.public_hex, case.config.witness_key, broker.workspace)
            assert claim["witnessScope"] == "PEER"
            assert len(claim["writes"]) == 1
            assert case.store.export()["witnessScope"] == "PEER"
            assert len(read_ledger(case.store.ledger, case.config.witness_key)) == 2

        def test_lost_ack_retries_same_receipt_once(self, case: Case, monkeypatch: pytest.MonkeyPatch) -> None:
            broker = case.broker(monkeypatch)
            broker.begin()
            request = request_bytes("checkpoint", broker.history_path.read_bytes())
            first = case.store.handle(request)
            assert first == case.store.handle(request)
            assert len(read_ledger(case.store.ledger, case.config.witness_key)) == 1
            broker.write("write", "/work/x", b"yes")
            broker.seal()
            terminal = request_bytes("checkpoint", broker.history_path.read_bytes())
            assert case.store.handle(terminal) == case.store.handle(terminal)
            assert len(read_ledger(case.store.ledger, case.config.witness_key)) == 2

        def test_restart_extends_external_head(self, case: Case, monkeypatch: pytest.MonkeyPatch) -> None:
            broker = case.broker(monkeypatch)
            broker.begin()
            head = case.store.head
            case.store = case.reopen(head)
            client = case.client(monkeypatch)
            assert client.latest_checkpoint(broker.history_path) == broker._start_checkpoint
            broker.witness = client
            broker.seal()
            result = verify_ledger_head(case.store.ledger, head, case.config.witness_key)
            assert result["count"] == 2
            assert result["missingTerminals"] == []

        def test_registered_missing_terminal_stays_visible(self, case: Case, monkeypatch: pytest.MonkeyPatch) -> None:
            broker = case.broker(monkeypatch)
            broker.begin()
            broker.write("write", "/work/x", b"done before loss")
            summary = verify_ledger_head(case.store.ledger, case.store.head, case.config.witness_key)
            assert [x["intervalId"] for x in summary["missingTerminals"]] == ["run"]
            assert (broker.workspace / "x").read_bytes() == b"done before loss"

        def test_local_witness_port_keeps_boundary_refusals(self, case: Case) -> None:
            witness = Witness(case.root / "local.json", SigningKey.generate())
            assert witness.public_hex == witness.signing_key.public_hex
            assert witness.configuration_error(case.root / "work", case.root / "local.json") == "history and witness state must use different files"
            assert witness.configuration_error(case.root, case.root / "history") == "witness state must be outside the observed workspace"

    class TestFailingCases:
        @pytest.mark.parametrize("field,value", [("clientUid", True), ("clientUid", -1), ("format", "other"), ("keyPath", "relative"), ("observerKey", "wrong")])
        def test_changed_host_configuration_refuses(self, case: Case, field: str, value: Any) -> None:
            config = json.loads((case.root / "operator.json").read_text())
            config[field] = value
            raw = canonical(config)
            path = case.root / "changed.json"
            path.write_bytes(raw)
            with pytest.raises((VerificationError, ValueError)):
                Configuration.read(path, sha(raw))
            assert case.store.ledger.read_bytes() == b""

        def test_config_digest_not_bundle_value(self, case: Case) -> None:
            with pytest.raises(VerificationError, match="operator configuration pin differs"):
                Configuration.read(case.root / "operator.json", "0" * 64)

        def test_exclusive_init_never_resets_existing_store(self, case: Case) -> None:
            original = case.store.ledger.read_bytes()
            with pytest.raises(FileExistsError):
                initialize(case.config)
            assert case.store.ledger.read_bytes() == original

        @pytest.mark.parametrize("name", ["operator.key", "state/ledger.jsonl", "state/configuration.sha256"])
        def test_missing_restart_file_never_recreated(self, case: Case, name: str) -> None:
            path = case.root / name
            path.unlink()
            with pytest.raises(FileNotFoundError):
                OperatorStore(case.config, case.retained, sha(case.retained.read_bytes()))
            assert not path.exists()

        @pytest.mark.parametrize("kind", ["wrong-key", "permissions", "link"])
        def test_host_private_key_controls(self, case: Case, kind: str) -> None:
            if kind == "wrong-key":
                case.config.key_path.write_bytes(b"\0" * 32)
            elif kind == "permissions":
                case.config.key_path.chmod(0o640)
            else:
                os.link(case.config.key_path, case.root / "linked-key")
            with pytest.raises(VerificationError):
                OperatorStore(case.config, case.retained, sha(case.retained.read_bytes()))

        def test_head_inside_store_refuses(self, case: Case) -> None:
            path = case.config.store_path / "head.json"
            path.write_bytes(case.retained.read_bytes())
            with pytest.raises(VerificationError, match="retained head must be outside operator store"):
                OperatorStore(case.config, path, sha(path.read_bytes()))

        def test_wrong_retained_digest_refuses(self, case: Case) -> None:
            with pytest.raises(VerificationError, match="operator retained head pin differs"):
                OperatorStore(case.config, case.retained, "0" * 64)

        def test_rollback_refuses_old_valid_prefix(self, case: Case, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
            broker = case.broker(monkeypatch)
            broker.begin()
            prefix = case.store.ledger.read_bytes()
            broker.seal()
            head = case.store.head
            case.store.ledger.write_bytes(prefix)
            with pytest.raises(VerificationError, match="ledger is shorter than the retained witness head"):
                case.reopen(head)
            assert caplog.messages[-1] == "witness ledger verification failed: ledger is shorter than the retained witness head"

        def test_running_store_rejects_rollback(self, case: Case, monkeypatch: pytest.MonkeyPatch) -> None:
            broker = case.broker(monkeypatch)
            broker.begin()
            case.store.ledger.write_bytes(b"")
            with pytest.raises(VerificationError, match="ledger is shorter than the retained witness head"):
                case.store.export()

        def test_resigned_fork_refuses_retained_prefix(self, case: Case, monkeypatch: pytest.MonkeyPatch) -> None:
            first = case.broker(monkeypatch)
            first.begin()
            first.seal()
            retained = case.store.head
            case.store.ledger.write_bytes(b"")
            fresh = OperatorStore(case.config, case.retained, sha(case.retained.read_bytes()))
            case.store = fresh
            second = case.broker(monkeypatch, "fork")
            second.begin()
            second.seal()
            assert case.store.head["count"] == retained["count"]
            with pytest.raises(VerificationError, match="ledger does not extend the retained witness head"):
                case.reopen(retained)

        def test_wrong_observer_signed_begin_refuses(self, case: Case, monkeypatch: pytest.MonkeyPatch) -> None:
            broker = case.broker(monkeypatch)
            broker.observer_key = SigningKey.generate()
            with pytest.raises(VerificationError, match="witness history has an unpinned observer key"):
                broker.begin()
            assert not broker._started
            assert list(broker.workspace.iterdir()) == []
            assert case.store.ledger.read_bytes() == b""

        @pytest.mark.parametrize("field,value", [("intervalId", []), ("intervalId", True), ("intervalId", ""),
                                 ("intervalId", "x" * 129), ("intervalId", "x" * 100000),
                                 ("intervalId", "space here"), ("intervalId", "tab\there"),
                                 ("authorityDigest", []), ("authorityDigest", "bad"), ("authorityDigest", "A" * 64)])
        def test_signed_malformed_identity_never_appends(self, case: Case, field: str, value: Any) -> None:
            from probity_observer.crypto import digest
            payload = {"preimage": {"intervalId": "valid", "authorityDigest": "a" * 64, "beforeRoot": "b" * 64,
                       "witnessNonce": "c" * 64}, "committedAt": "2026-10-03T00:00:00Z"}
            payload["preimage"][field] = value
            commitment = {**payload, "keyid": case.observer.public_hex,
                          "signature": case.observer.sign("probity-prior-commitment-v0", payload)}
            path = case.root / "malformed.jsonl"
            append_history(path, {"kind": "begin", "commitmentDigest": digest("probity-prior-commitment-v0", payload), "commitment": commitment})
            before = case.store.export()
            with pytest.raises(VerificationError):
                case.store.handle(request_bytes("checkpoint", path.read_bytes()))
            assert case.store.export() == before

        def test_signed_witness_cannot_replace_observer_signature(self, case: Case, monkeypatch: pytest.MonkeyPatch) -> None:
            from probity_observer.crypto import digest
            from probity_observer.ledger import RECEIPT_DOMAIN, HEAD_DOMAIN
            broker = case.broker(monkeypatch)
            broker.begin()
            history = broker.history_path.read_bytes()
            reply = strict_loads(case.store.handle(request_bytes("checkpoint", history)))
            event = read_history(broker.history_path)[0]["event"]
            event["commitment"]["signature"] = "AA=="
            forged = case.root / "forged.jsonl"
            append_history(forged, event)
            changed = forged.read_bytes()
            checkpoint = reply["payload"]["checkpoint"]
            checkpoint["head"] = read_history(forged)[0]["hash"]
            checkpoint["signature"] = case.store.key.sign("probity-checkpoint-v0", {"count": 1, "head": checkpoint["head"]})
            receipt = checkpoint["ledgerReceipt"]
            receipt["checkpoint"] = {k: v for k, v in checkpoint.items() if k != "ledgerReceipt"}
            body = {k: receipt[k] for k in ("sequence", "previous", "intervalId", "authorityDigest", "observerKey", "phase", "checkpoint")}
            receipt["hash"] = digest(RECEIPT_DOMAIN, body)
            receipt["signature"] = case.store.key.sign(RECEIPT_DOMAIN, body)
            head = reply["payload"]["ledgerHead"]
            head["head"] = receipt["hash"]
            head["signature"] = case.store.key.sign(HEAD_DOMAIN, {k: head[k] for k in ("format", "count", "head")})
            reply["payload"]["ledgerHex"] = (canonical(receipt) + b"\n").hex()
            reply["payload"]["historySha256"] = sha(changed)
            reply["signature"] = case.store.key.sign(REPLY_DOMAIN, reply["payload"])
            with pytest.raises(VerificationError, match="signature does not verify under the pinned key"):
                verify_reply(canonical(reply), "checkpoint", changed, case.config.witness_key, case.observer.public_hex,
                             strict_loads(case.retained.read_bytes()))

        @pytest.mark.parametrize("field,value", [("keyPath", "attacker"), ("storePath", "attacker"), ("reset", True)])
        def test_request_cannot_select_operator_controls(self, case: Case, monkeypatch: pytest.MonkeyPatch, field: str, value: Any) -> None:
            broker = case.broker(monkeypatch)
            broker.begin()
            original = case.store.ledger.read_bytes()
            request = strict_loads(request_bytes("checkpoint", broker.history_path.read_bytes()))
            request[field] = value
            with pytest.raises(VerificationError, match="request fields differ"):
                case.store.handle(canonical(request))
            assert case.store.ledger.read_bytes() == original

        @pytest.mark.parametrize("mutation", ["drop-newline", "extra-entry-field", "noncanonical", "changed-chain", "boolean-sequence"])
        def test_exact_history_controls(self, case: Case, monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
            broker = case.broker(monkeypatch)
            broker.begin()
            raw = broker.history_path.read_bytes()
            entry = strict_loads(raw[:-1])
            if mutation == "drop-newline":
                raw = raw[:-1]
            elif mutation == "extra-entry-field":
                raw = canonical({**entry, "extra": 1}) + b"\n"
            elif mutation == "noncanonical":
                raw = json.dumps(entry).encode() + b"\n"
            elif mutation == "changed-chain":
                raw = canonical({**entry, "hash": "0" * 64}) + b"\n"
            else:
                raw = canonical({**entry, "sequence": True}) + b"\n"
            with pytest.raises(VerificationError):
                history_entries(raw)

        def test_conflicting_terminal_retry_refuses(self, case: Case, monkeypatch: pytest.MonkeyPatch) -> None:
            broker = case.broker(monkeypatch)
            broker.begin()
            broker.seal()
            entries = read_history(broker.history_path)
            broker.history_path.write_bytes(canonical(entries[0]) + b"\n")
            append_history(broker.history_path, {"kind": "seal", "claimDigest": "0" * 64})
            with pytest.raises(VerificationError, match="witness interval already has a terminal head"):
                case.store.handle(request_bytes("checkpoint", broker.history_path.read_bytes()))

        def test_exact_capacity_refusal_leaves_store_exportable(self, case: Case, monkeypatch: pytest.MonkeyPatch) -> None:
            from probity_observer.crypto import digest
            from probity_witness_operator import store
            histories = []
            for index in range(2):
                payload = {"preimage": {"intervalId": "interval-" + str(index),
                           "authorityDigest": "a" * 64, "beforeRoot": "b" * 64, "witnessNonce": "c" * 64},
                           "committedAt": "2026-10-03T00:00:00Z"}
                commitment = {**payload, "keyid": case.observer.public_hex,
                              "signature": case.observer.sign("probity-prior-commitment-v0", payload)}
                history = case.root / f"large-{index}.jsonl"
                append_history(history, {"kind": "begin", "commitmentDigest": digest("probity-prior-commitment-v0", payload), "commitment": commitment})
                histories.append(history.read_bytes())
            case.store.handle(request_bytes("checkpoint", histories[0]))
            before = case.store.ledger.read_bytes()
            head = case.store.head
            monkeypatch.setattr(store, "MAX_HISTORY", 2 * len(before) - 1)
            with pytest.raises(VerificationError, match="witness ledger capacity reached"):
                case.store.handle(request_bytes("checkpoint", histories[1]))
            assert case.store.ledger.read_bytes() == before
            assert case.store.head == head
            assert case.store.export()["head"] == head

        @pytest.mark.parametrize("mutation", ["history", "operation", "wrong-key", "receipt", "head-prefix"])
        def test_rebound_signed_reply_refuses(self, case: Case, monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
            broker = case.broker(monkeypatch)
            broker.begin()
            history = broker.history_path.read_bytes()
            reply = strict_loads(case.store.handle(request_bytes("checkpoint", history)))
            payload = reply["payload"]
            if mutation == "history":
                payload["historySha256"] = "0" * 64
            elif mutation == "operation":
                payload["operation"] = "latest"
            elif mutation == "receipt":
                payload["checkpoint"]["ledgerReceipt"]["observerKey"] = "0" * 64
            elif mutation == "head-prefix":
                payload["ledgerHex"] = ""
            else:
                reply["keyid"] = SigningKey.generate().public_hex
            reply["signature"] = case.store.key.sign(REPLY_DOMAIN, payload)
            with pytest.raises(VerificationError):
                verify_reply(canonical(reply), "checkpoint", history, case.config.witness_key,
                             case.observer.public_hex, strict_loads(case.retained.read_bytes()))

        @settings(max_examples=20)
        @given(length=st.integers(min_value=262145, max_value=300000), prefix=st.binary(max_size=64))
        def test_oversized_history_refuses_before_parse(self, length: int, prefix: bytes) -> None:
            raw = prefix + b"x" * (length - len(prefix))
            with pytest.raises(VerificationError, match="history exceeds finite limit"):
                history_entries(raw)
