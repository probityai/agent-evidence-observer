"""Behavior and refusal controls for the local authority/effect comparison."""

from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

from probity_observer.authorization import ActionRequest, GrantPolicy, verify_grant
from probity_observer.crypto import SigningKey, VerificationError, canonical, digest, strict_loads
from probity_observer.ticket_service import DOMAIN

from authority_profile import (AUTHORITY_DOMAIN, CONTRACT_ID, RESIDUAL_RISKS, MAX_AGE_SECONDS, PROFILE, RECORD_DOMAIN, check_authority,
                               check_delegation, checked_record, content_bytes, reference_time, sign_record)
from producer import START, _case, produce
from reader import read_case, read_run
from source_discriminator import inspect_fingerprint


@pytest.fixture(scope="session")
def produced(tmp_path_factory):
    """Create native durable cases once; every reader reopens the databases."""
    path = tmp_path_factory.mktemp("authority") / "run"
    produce(path, "local-uncommitted")
    pins = json.loads((path / "consumer-pins.json").read_text())
    return path, pins


@pytest.fixture
def signable_case(tmp_path):
    """Retain author keys only inside a test that constructs signed contradictions."""
    keys = {name: SigningKey.generate() for name in ("issuer", "authority", "service", "record")}
    pins = {"profile": PROFILE, "maxValiditySeconds": 300,
            **{name + "Key": key.public_hex for name, key in keys.items()}}
    return tmp_path, keys, pins


def rewrite_native(path, key, mutation):
    """Re-sign an internally contradictory native record, preserving its chain."""
    with sqlite3.connect(path / "native.sqlite") as db:
        state = strict_loads(db.execute("SELECT record FROM state WHERE singleton=1").fetchone()[0])["payload"]
        if mutation == "effect-identity":
            state["effectId"] = "1" * 64
            db.execute("UPDATE tickets SET effect=?", (state["effectId"],))
        if mutation == "effect-time":
            state["effectTime"] = "2026-10-03T12:00:11Z"
        head = "0" * 64
        for sequence, raw in db.execute("SELECT sequence,record FROM events ORDER BY sequence").fetchall():
            event = strict_loads(raw)["payload"]
            carried = event["event"]
            if mutation == "effect-identity" and "effectId" in carried:
                carried["effectId"] = state["effectId"]
            if mutation == "effect-time" and carried["kind"] == "effect":
                carried["effectTime"] = state["effectTime"]
            if mutation == "wrong-initial-configuration" and sequence == 1:
                carried["configuration"] = "0" * 64
            if mutation == "repeated-initialize" and sequence == 2:
                event["event"] = {"kind": "initialize", "configuration": state["configuration"]}
            if mutation == "boolean-effect-revision" and carried["kind"] == "effect":
                carried["revision"] = True
            if mutation == "wrong-intent-principal" and carried["kind"] == "intent":
                carried["request"]["principal_id"] = "other-principal"
            event["previous"] = head
            event["hash"] = digest(DOMAIN + "-event", {field: event[field] for field in ("sequence", "previous", "event")})
            head = event["hash"]
            db.execute("UPDATE events SET record=? WHERE sequence=?", (canonical(sign_record(event, key, DOMAIN)), sequence))
        state["eventHead"] = head
        db.execute("UPDATE state SET record=? WHERE singleton=1", (canonical(sign_record(state, key, DOMAIN)),))


class TestAuthorityProfile:
    class TestPassingCases:
        @given(age=st.integers(min_value=0, max_value=MAX_AGE_SECONDS))
        @settings(max_examples=40)
        def test_all_admitted_freshness_ages(self, age):
            key = SigningKey.generate()
            record = sign_record({"principalId": "approver", "observedAt": START - age,
                                  "status": "active", "sourceRevision": "revision-1"}, key, AUTHORITY_DOMAIN)
            result = check_authority(record, key.public_hex, "approver", START)
            assert result["ageSeconds"] == age

        @pytest.mark.parametrize("field", ["text", "media", "destination", "catalogue"])
        def test_each_final_descriptor_field_is_bound(self, field):
            original = {"text": "approved", "media": b"media", "destination": "destination-1", "catalogue": b"catalogue-1"}
            replacements = {"text": "changed", "media": b"changed", "destination": "destination-2", "catalogue": b"catalogue-2"}
            changed = {**original, field: replacements[field]}
            assert content_bytes(**original) != content_bytes(**changed)

        def test_each_case_carries_the_residual_risks_the_profile_leaves(self, produced):
            root, pins = produced
            for case_id, risks in RESIDUAL_RISKS.items():
                assert read_case(root / case_id, pins)["residualRisks"] == list(risks)
            assert RESIDUAL_RISKS["authority-evidence-stale"] == ("status-source-trusted-within-freshness-limit",)

    class TestFailingCases:
        @pytest.mark.parametrize("change,reason", [
            ({"status": "revoked"}, "approver authority is not active"),
            ({"principalId": "other"}, "authority identity or fields differ"),
            ({"observedAt": START + 1}, "authority time is invalid"),
            ({"observedAt": True}, "authority time is invalid"),
            ({"observedAt": START - 181}, "authority evidence is stale"),
        ])
        def test_current_authority_refusals_are_exact_and_logged(self, change, reason, caplog):
            key = SigningKey.generate()
            fields = {"principalId": "approver", "observedAt": START, "status": "active", "sourceRevision": "revision-1"}
            record = sign_record({**fields, **change}, key, AUTHORITY_DOMAIN)
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError) as error:
                check_authority(record, key.public_hex, "approver", START)
            assert str(error.value) == reason
            assert "authority profile refused: " + reason in caplog.messages

        @pytest.mark.parametrize("mutation,reason", [
            ("signature", "evidence signature does not verify"),
            ("wrong-key", "evidence signer differs from consumer pin"),
            ("missing-signature", "evidence envelope is incomplete"),
        ])
        def test_consumer_selects_the_source_key(self, mutation, reason, caplog):
            key = SigningKey.generate()
            record = sign_record({"claim": "bounded"}, key, AUTHORITY_DOMAIN)
            expected = key.public_hex
            if mutation == "signature":
                record["signature"] = "AA=="
            if mutation == "wrong-key":
                expected = SigningKey.generate().public_hex
            if mutation == "missing-signature":
                record.pop("signature")
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError) as error:
                checked_record(record, expected, AUTHORITY_DOMAIN)
            assert str(error.value) == reason
            assert "authority profile refused: " + reason in caplog.messages


        @pytest.mark.parametrize("hops,reason", [
            ([], "delegation chain is broken"),
            ([{"delegator": "issuer", "delegate": "orchestrator", "actions": ["ticket-update"], "targets": ["/t/1"]},
              {"delegator": "someone-else", "delegate": "approver", "actions": ["ticket-update"], "targets": ["/t/1"]}],
             "delegation chain is broken"),
            ([{"delegator": "issuer", "delegate": "orchestrator", "actions": ["ticket-update"], "targets": ["/t/1"]},
              {"delegator": "orchestrator", "delegate": "approver", "actions": ["ticket-update", "ticket-delete"], "targets": ["/t/1"]}],
             "delegation hop widens scope"),
            ([{"delegator": "issuer", "delegate": "orchestrator", "actions": ["ticket-update"], "targets": ["/t/1"]},
              {"delegator": "orchestrator", "delegate": "approver", "actions": ["ticket-update"], "targets": ["/t/1", "/t/2"]}],
             "delegation hop widens scope"),
            ([{"delegator": "issuer", "delegate": "approver", "actions": ["ticket-read"], "targets": ["/t/1"]}],
             "delegated scope excludes action"),
            ([{"delegator": "issuer", "delegate": "other", "actions": ["ticket-update"], "targets": ["/t/1"]}],
             "delegation chain is broken"),
            ([{"delegator": "issuer", "delegate": "approver", "actions": "ticket-update", "targets": ["/t/1"]}],
             "delegation hop fields differ"),
        ])
        def test_delegation_amplification_and_breaks_are_refused(self, hops, reason, caplog):
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError) as error:
                check_delegation(hops, "issuer", "approver", "ticket-update", "/t/1")
            assert str(error.value) == reason
            assert "authority profile refused: " + reason in caplog.messages

    class TestDelegationPassing:
        def test_narrowing_chain_admits_exact_action(self):
            hops = [{"delegator": "issuer", "delegate": "orchestrator", "actions": ["ticket-update", "ticket-read"],
                     "targets": ["/t/1", "/t/2"]},
                    {"delegator": "orchestrator", "delegate": "approver", "actions": ["ticket-update"], "targets": ["/t/1"]}]
            assert check_delegation(hops, "issuer", "approver", "ticket-update", "/t/1") == 2


class TestReader:
    class TestPassingCases:
        @pytest.mark.parametrize("case_id,revision,terminal,publish", [
            ("approved-human-reachable", 1, "completed", True),
            ("unreachable-with-prior-fallback", 1, "completed", True),
            ("unreachable-no-fallback", 0, "failed", False),
            ("fallback-expired", 0, "failed", False),
            ("late-approval-for-expired-request", 0, "failed", False),
            ("approver-revoked-at-dispatch", 0, "failed", False),
            ("authority-evidence-stale", 0, "failed", False),
            ("media-bytes-mutated", 0, "failed", False),
            ("platform-content-mutated", 0, "failed", False),
            ("catalogue-mutated", 0, "failed", False),
            ("destination-mutated", 0, "failed", False),
            ("revoked-between-intent-and-effect", 0, "failed", False),
            ("crash-after-intent", 0, "failed", False),
            ("crash-inside-effect-transaction", 0, "failed", False),
            ("effect-committed-response-lost", 1, "failed", False),
            ("same-request-retry", 1, "completed", True),
            ("effect-then-authority-revoked", 1, "failed", False),
            ("incomplete-proof-after-effect", 1, "completed", False),
            ("delegation-hop-amplified", 0, "failed", False),
        ])
        def test_effect_task_and_publication_are_separate(self, produced, case_id, revision, terminal, publish):
            root, pins = produced
            result = read_case(root / case_id, pins)
            assert result["nativeRevision"] == revision
            assert result["effectObserved"] == bool(revision)
            assert result["taskTerminal"] == terminal
            assert result["publicationReady"] is publish
            assert result["witnessScope"] == "PEER"

        def test_late_fresh_grant_does_not_reopen_old_request(self, produced):
            root, pins = produced
            payload = json.loads((root / "late-approval-for-expired-request" / "record.json").read_text())["payload"]
            # The new approval is cryptographically valid at arrival; the original
            # decision deadline is the distinct reason dispatch remains blocked.
            verify_grant(payload["grant"], ActionRequest(**payload["request"]), GrantPolicy(**payload["grantPolicy"]),
                         now=reference_time(payload["decisionAt"]))
            assert payload["attempts"][0]["reason"] == "original decision window has closed"
            assert read_case(root / payload["caseId"], pins)["nativeRevision"] == 0

        def test_retry_reuses_one_effect_identity(self, produced):
            root, pins = produced
            payload = json.loads((root / "same-request-retry" / "record.json").read_text())["payload"]
            assert payload["attempts"][0]["receipt"] == payload["attempts"][1]["receipt"]
            result = read_case(root / "same-request-retry", pins)
            assert result["attemptCount"] == 2 and result["nativeRevision"] == 1

        def test_missing_retained_proof_preserves_native_effect(self, produced):
            root, pins = produced
            result = read_case(root / "incomplete-proof-after-effect", pins)
            assert result["nativeCompletionProof"] == "incomplete-or-no-longer-admissible"
            assert result["proofReason"] == "ticket envelope fields differ"
            assert result["effectObserved"] is True and result["publicationReady"] is False

        def test_run_reports_the_full_selected_case_set(self, produced):
            root, pins = produced
            result = read_run(root, pins)
            assert result["caseCount"] == 19
            assert sum(row["effectObserved"] for row in result["results"]) == 6
            assert sum(row["publicationReady"] for row in result["results"]) == 3
            assert result["independentCustody"] is False
            assert result["contractId"] == CONTRACT_ID

        def test_every_trace_writes_the_contract_id_and_evidence_age(self, produced):
            root, _ = produced
            for case in sorted(p for p in root.iterdir() if p.is_dir()):
                payload = json.loads((case / "record.json").read_text())["payload"]
                assert payload["contractId"] == CONTRACT_ID
                assert payload["freshnessLimitSeconds"] == MAX_AGE_SECONDS
                observed = checked_record(payload["authorityEvidence"], json.loads(
                    (root / "consumer-pins.json").read_text())["authorityKey"], AUTHORITY_DOMAIN)["observedAt"]
                assert payload["evidenceAgeSeconds"] == payload["decisionAt"] - observed

        def test_amplified_hop_is_denied_before_native_mutation(self, produced):
            root, pins = produced
            payload = json.loads((root / "delegation-hop-amplified" / "record.json").read_text())["payload"]
            assert payload["attempts"][0]["reason"] == "delegation hop widens scope"
            result = read_case(root / "delegation-hop-amplified", pins)
            assert result["delegationStatus"] == "not-admitted"
            assert result["effectObserved"] is False

    class TestFailingCases:
        @pytest.mark.parametrize("mutation,reason", [
            ("missing", "trace contract id is missing"),
            ("other-version", "trace contract id differs"),
            ("age", "evidence age differs from decision time"),
            ("age-bool", "evidence age differs from decision time"),
            ("limit", "freshness limit differs from consumer selection"),
        ])
        def test_trace_without_contract_or_with_wrong_age_is_rejected(self, signable_case, mutation, reason, caplog):
            root, keys, pins = signable_case
            _case(root, "approved-human-reachable", keys)
            case = root / "approved-human-reachable"
            assert read_case(case, pins)["publicationReady"] is True
            payload = json.loads((case / "record.json").read_text())["payload"]
            if mutation == "missing":
                payload.pop("contractId")
            if mutation == "other-version":
                payload["contractId"] = CONTRACT_ID.replace("/v1", "/v0")
            if mutation == "age":
                payload["evidenceAgeSeconds"] += 1
            if mutation == "age-bool":
                payload["evidenceAgeSeconds"] = False
            if mutation == "limit":
                payload["freshnessLimitSeconds"] = MAX_AGE_SECONDS + 1
            (case / "record.json").write_bytes(canonical(sign_record(payload, keys["record"], RECORD_DOMAIN)))
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError) as error:
                read_case(case, pins)
            assert str(error.value) == reason
            assert "authority profile refused: " + reason in caplog.messages

        @pytest.mark.parametrize("mutation,reason", [
            ("dropped", "record closes a residual risk this profile leaves open"),
            ("added", "residual risks differ from selected profile"),
            ("not-a-list", "residual risks differ from selected profile"),
        ])
        def test_record_that_closes_a_residual_risk_is_rejected(self, signable_case, mutation, reason, caplog):
            root, keys, pins = signable_case
            _case(root, "authority-evidence-stale", keys)
            case = root / "authority-evidence-stale"
            assert read_case(case, pins)["residualRisks"] == ["status-source-trusted-within-freshness-limit"]
            payload = json.loads((case / "record.json").read_text())["payload"]
            if mutation == "dropped":
                payload["residualRisks"] = []
            if mutation == "added":
                payload["residualRisks"].append("revocation-propagation-unmeasured")
            if mutation == "not-a-list":
                payload["residualRisks"] = "status-source-trusted-within-freshness-limit"
            (case / "record.json").write_bytes(canonical(sign_record(payload, keys["record"], RECORD_DOMAIN)))
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError) as error:
                read_case(case, pins)
            assert str(error.value) == reason
            assert "authority profile refused: " + reason in caplog.messages

        @pytest.mark.parametrize("mutation", ["content", "head", "time", "revoked-prefix"])
        def test_signed_completed_return_must_match_native_prefix(self, signable_case, mutation, caplog):
            root, keys, pins = signable_case
            case_id = "effect-then-authority-revoked" if mutation == "revoked-prefix" else "approved-human-reachable"
            _case(root, case_id, keys)
            case = root / case_id
            original = read_case(case, pins)
            assert original["effectObserved"] is True
            assert original["publicationReady"] is (mutation != "revoked-prefix")
            payload = json.loads((case / "record.json").read_text())["payload"]
            receipt = payload["attempts"][0]["receipt"]["payload"]
            if mutation == "content":
                receipt["contentDigest"] = "0" * 64
            if mutation == "head":
                receipt["eventHead"] = "0" * 64
            if mutation == "time":
                receipt["effectTime"] = "2026-10-03T12:01:00Z"
            if mutation == "revoked-prefix":
                current = payload["readback"]["receipt"]["payload"]
                receipt.update(eventCount=current["eventCount"], eventHead=current["eventHead"])
            payload["attempts"][0]["receipt"] = sign_record(receipt, keys["service"], DOMAIN)
            (case / "record.json").write_bytes(canonical(sign_record(payload, keys["record"], RECORD_DOMAIN)))
            reason = "retained completed dispatch differs from observed native history"
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError) as error:
                read_case(case, pins)
            assert str(error.value) == reason
            assert "authority profile refused: " + reason in caplog.messages

        @pytest.mark.parametrize("mutation,reason", [
            ("effect-identity", "retained completion differs from observed native state"),
            ("effect-time", "retained completion differs from observed native state"),
            ("wrong-initial-configuration", "native event body differs"),
            ("repeated-initialize", "native initialization history differs"),
            ("boolean-effect-revision", "native event body differs"),
            ("wrong-intent-principal", "native event body differs"),
        ])
        def test_signed_native_contradictions_are_refused(self, signable_case, mutation, reason, caplog):
            root, keys, pins = signable_case
            _case(root, "approved-human-reachable", keys)
            case = root / "approved-human-reachable"
            assert read_case(case, pins)["publicationReady"] is True
            rewrite_native(case, keys["service"], mutation)
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError) as error:
                read_case(case, pins)
            assert str(error.value) == reason
            assert "authority profile refused: " + reason in caplog.messages

        @pytest.mark.parametrize("mutation,reason", [
            ("terminal", "task terminal contradicts retained dispatch return"),
            ("deny-completed", "retained dispatch outcome differs"),
            ("empty-completion", "retained completed dispatch proof differs"),
            ("wrong-completion-binding", "retained completed dispatch proof differs"),
            ("coverage", "profile coverage exceeds selected boundary"),
            ("missing-field", "profile record fields differ"),
        ])
        def test_signed_profile_contradictions_are_refused(self, signable_case, mutation, reason, caplog):
            root, keys, pins = signable_case
            case_id = "approved-human-reachable" if mutation == "wrong-completion-binding" else "effect-committed-response-lost"
            _case(root, case_id, keys)
            case = root / case_id
            original = read_case(case, pins)
            assert original["effectObserved"] is True
            assert original["taskTerminal"] == ("completed" if mutation == "wrong-completion-binding" else "failed")
            record = json.loads((case / "record.json").read_text())
            payload = record["payload"]
            if mutation == "terminal":
                payload["taskTerminal"] = "completed"
            if mutation in {"deny-completed", "empty-completion"}:
                payload["taskTerminal"] = "completed"
                payload["attempts"][-1] = {"decision": "deny" if mutation == "deny-completed" else "allow",
                                          "returnStatus": "completed", "reason": None, "receipt": {}}
            if mutation == "coverage":
                payload["coverage"] = "all-effects"
            if mutation == "wrong-completion-binding":
                receipt = payload["attempts"][-1]["receipt"]["payload"]
                receipt["grantDigest"] = "0" * 64
                payload["attempts"][-1]["receipt"] = sign_record(receipt, keys["service"], DOMAIN)
            if mutation == "missing-field":
                payload.pop("faultInjection")
            (case / "record.json").write_bytes(canonical(sign_record(payload, keys["record"], RECORD_DOMAIN)))
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError) as error:
                read_case(case, pins)
            assert str(error.value) == reason
            assert "authority profile refused: " + reason in caplog.messages

        @pytest.mark.parametrize("mutation,reason", [
            ("wrong-record-key", "evidence signer differs from consumer pin"),
            ("unsigned-task-edit", "evidence signature does not verify"),
            ("changed-native-bytes", "native effect bytes differ"),
            ("missing-native-event", "native history is incomplete"),
        ])
        def test_reader_tamper_controls(self, produced, tmp_path, mutation, reason, caplog):
            root, pins = produced
            case = tmp_path / "approved-human-reachable"
            shutil.copytree(root / case.name, case)
            selected = dict(pins)
            if mutation == "wrong-record-key":
                selected["recordKey"] = SigningKey.generate().public_hex
            if mutation == "unsigned-task-edit":
                record = json.loads((case / "record.json").read_text())
                record["payload"]["taskTerminal"] = "failed"
                (case / "record.json").write_text(json.dumps(record))
            if mutation in {"changed-native-bytes", "missing-native-event"}:
                with sqlite3.connect(case / "native.sqlite") as db:
                    if mutation == "changed-native-bytes":
                        db.execute("UPDATE tickets SET content=?", (b"unapproved",))
                    else:
                        db.execute("DELETE FROM events WHERE sequence=(SELECT max(sequence) FROM events)")
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError) as error:
                read_case(case, selected)
            assert str(error.value) == reason
            assert "authority profile refused: " + reason in caplog.messages

        def test_deleted_case_is_not_complete_coverage(self, produced, tmp_path, caplog):
            root, pins = produced
            report = json.loads((root / "producer-report.json").read_text())
            report["cases"].pop()
            (tmp_path / "producer-report.json").write_text(json.dumps(report))
            reason = "declared case coverage differs from selected profile"
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError) as error:
                read_run(tmp_path, pins)
            assert str(error.value) == reason
            assert "authority profile refused: " + reason in caplog.messages


class TestSourceDiscriminator:
    class TestPassingCases:
        @pytest.mark.skipif(not os.environ.get("ALAKRIS_SOURCE"), reason="pinned Alakris source must be explicitly selected")
        def test_exact_source_function_discriminators(self):
            result = inspect_fingerprint(Path(os.environ["ALAKRIS_SOURCE"]))
            expected = [True, True, True, False, False, False]
            assert [row["fingerprintChanged"] for row in result["results"]] == expected
            assert result["originalTestsRerun"] is False
            assert result["deployedSystemRerun"] is False

    class TestFailingCases:
        def test_unpinned_source_never_executes(self, tmp_path, caplog):
            source = tmp_path / "publication_jobs.py"
            source.write_text("raise RuntimeError('must not run')\n")
            with caplog.at_level(logging.WARNING), pytest.raises(ValueError) as error:
                inspect_fingerprint(source)
            assert str(error.value) == "Alakris source differs from pinned SHA-256"
            assert str(error.value) in caplog.messages
