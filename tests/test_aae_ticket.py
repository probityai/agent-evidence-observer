"""Native unsigned decision joined to actual HTTP persistence and consumer pins."""
from __future__ import annotations
import copy
import hashlib
import json
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
import pytest
from probity_observer.aae_enforce import enforce_check, native_digest, canonical_bytes
from probity_observer.aae_ticket import AaeTicketStore, ticket_transaction, ticket_decision_digest, verify_aae_ticket_result
from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant
from probity_observer.crypto import SigningKey, VerificationError, digest
from probity_observer.ticket_service import TicketStore, running_server, http_json, verify_ticket_result


def make_case(tmp_path: Path):
    now = datetime.now(UTC).replace(microsecond=0)
    issuer, key = SigningKey.generate(), SigningKey.generate()
    content = b'{"status":"approved by native decision"}'
    request = ActionRequest("run", "attempt", "request", "tenant", "principal", "ticket-update", "/work/tickets/ticket", hashlib.sha256(content).hexdigest())
    transaction = ticket_transaction(request)
    mandate = {"grants": [{"action_binding": native_digest("action", transaction["action"]), "type_fields": ["verb", "targetKind"], "disposition": "allow", "constraints": [{"type": "exact", "field": name, "value": value} for name, value in transaction.items() if name != "action"]}]}
    decision = dict(mandate=mandate, transaction=transaction, record=enforce_check(mandate, transaction), pinned_mandate_digest=native_digest("mandate", mandate))
    policy = GrantPolicy(issuer.public_hex)
    grant = issue_grant(request, issuer, issued_at=now - timedelta(seconds=1), expires_at=now + timedelta(seconds=120))
    host = dict(path=tmp_path / "store.sqlite", request=request, policy=policy, key=key, clock=lambda: now)
    store = AaeTicketStore(**host, **decision)
    initial = store.initialize()
    return dict(store=store, host=host, decision=decision, initial=initial, now=now, grant=grant, candidate=dict(request=asdict(request), grant=grant, contentHex=content.hex()))


@pytest.fixture
def case(tmp_path):
    return make_case(tmp_path)


def consume(case, receipt, native, **changes):
    return verify_aae_ticket_result(**{**case["decision"], **changes}, receipt=receipt, readback=native, request=case["host"]["request"], policy=case["host"]["policy"], service_key=case["host"]["key"].public_hex, grant=case["grant"], now=case["now"])


def complete(case):
    with running_server(case["store"]) as server:
        status, receipt = http_json(server.url + "/dispatch", case["candidate"])
        read_status, native = http_json(server.url + "/tickets/tenant/ticket")
        assert status == read_status == 200
        return receipt, native


def test_actual_http_completion_restart_and_prior_commitment(case):
    commitment = case["store"].configuration["decisionDigest"]
    assert case["initial"]["revision"] == 0
    assert case["initial"]["receipt"]["payload"]["configuration"] == case["store"].configuration_digest
    receipt, native = complete(case)
    result = consume(case, receipt, native)
    assert result["decisionDigest"] == commitment and result["kernelVerdict"] == "PERMIT"
    assert result["issuerAuthentication"] == "not-established"
    restart = AaeTicketStore(**case["host"], **case["decision"], retained_head=receipt)
    with running_server(restart) as server:
        assert http_json(server.url + "/dispatch", case["candidate"]) == (200, receipt)
        assert http_json(server.url + "/tickets/tenant/ticket")[1] == native


def test_frozen_inputs_survive_caller_mutation(case):
    original = copy.deepcopy(case["decision"])
    case["decision"]["mandate"]["grants"].clear()
    receipt, native = complete(case)
    assert consume(case, receipt, native, **original)["linkage"] == "verified"


@pytest.mark.parametrize("kind", ["pin", "record", "transaction", "request", "constraint", "rehashed-core", "changed-valid-mandate"])
def test_changed_native_inputs_cannot_admit_completed_effect(case, kind):
    receipt, native = complete(case)
    changed = copy.deepcopy(case["decision"])
    if kind == "pin":
        changed["pinned_mandate_digest"] = "sha256:" + "0" * 64
    elif kind == "record":
        changed["record"]["core_digest"] = "sha256:" + "0" * 64
    elif kind == "transaction":
        changed["transaction"]["content_sha256"] = "0" * 64
    elif kind == "request":
        changed["transaction"]["request_id"] = "other"
    elif kind == "constraint":
        changed["mandate"]["grants"][0]["constraints"].pop()
        changed["pinned_mandate_digest"] = native_digest("mandate", changed["mandate"])
        changed["record"] = enforce_check(changed["mandate"], changed["transaction"])
    elif kind == "rehashed-core":
        changed["record"]["core"]["transaction_digest"] = "sha256:" + "0" * 64
        changed["record"]["core_digest"] = native_digest("core", changed["record"]["core"])
    else:
        changed["mandate"]["grants"][0]["constraints"].append(copy.deepcopy(changed["mandate"]["grants"][0]["constraints"][0]))
        changed["pinned_mandate_digest"] = native_digest("mandate", changed["mandate"])
        changed["record"] = enforce_check(changed["mandate"], changed["transaction"])
    with pytest.raises(VerificationError):
        consume(case, receipt, native, **changed)


def test_base_reader_and_base_restart_refuse_lost_commitment(case):
    receipt, native = complete(case)
    host = case["host"]
    with pytest.raises(VerificationError, match="binding"):
        verify_ticket_result(receipt, native, host["request"], host["policy"], host["key"].public_hex, case["grant"], now=case["now"])
    with pytest.raises(VerificationError, match="configuration"):
        TicketStore(**host).readback()


def test_plain_ticket_profile_still_works(tmp_path):
    case = make_case(tmp_path)
    host = {**case["host"], "path": tmp_path / "plain.sqlite"}
    store = TicketStore(**host)
    assert "decisionDigest" not in store.configuration
    store.initialize()
    receipt = store.dispatch(case["candidate"])
    assert verify_ticket_result(receipt, store.readback(), host["request"], host["policy"], host["key"].public_hex, case["grant"], now=case["now"])["status"] == "verified"


@pytest.mark.parametrize("after", [False, True])
def test_revocation_refuses_fresh_and_cached_native_decision(case, after):
    if after:
        complete(case)
    case["store"].revoke()
    with running_server(case["store"]) as server:
        assert http_json(server.url + "/dispatch", case["candidate"])[0] == 409
        native = http_json(server.url + "/tickets/tenant/ticket")[1]
        assert native["revision"] == int(after)


def test_native_replay_runs_even_for_completed_retry(case):
    complete(case)
    inputs = json.loads(case["store"]._decision_bytes)
    inputs[2]["core_digest"] = "sha256:" + "0" * 64
    case["store"]._decision_bytes = canonical_bytes(inputs)
    with running_server(case["store"]) as server:
        assert http_json(server.url + "/dispatch", case["candidate"])[0] == 409
        assert http_json(server.url + "/tickets/tenant/ticket")[1]["revision"] == 1


def test_changed_request_refused_before_native_effect(case):
    candidate = copy.deepcopy(case["candidate"])
    candidate["request"]["request_id"] = "other"
    with running_server(case["store"]) as server:
        assert http_json(server.url + "/dispatch", candidate)[0] == 409
        assert http_json(server.url + "/tickets/tenant/ticket")[1]["revision"] == 0


def test_denied_kernel_initializes_but_never_dispatches(case, tmp_path):
    decision = copy.deepcopy(case["decision"])
    decision["mandate"]["grants"][0]["disposition"] = "forbid"
    decision["record"] = enforce_check(decision["mandate"], decision["transaction"])
    decision["pinned_mandate_digest"] = native_digest("mandate", decision["mandate"])
    host = {**case["host"], "path": tmp_path / "denied.sqlite"}
    store = AaeTicketStore(**host, **decision)
    store.initialize()
    with running_server(store) as server:
        assert http_json(server.url + "/dispatch", case["candidate"])[0] == 409
        native = http_json(server.url + "/tickets/tenant/ticket")[1]
        assert native["revision"] == 0 and native["receipt"]["payload"]["phase"] == "ready"


def test_rehashed_and_resigned_wrapper_cannot_override_native_replay(case):
    """A local wrapper/signature cannot make a fabricated native core true."""
    from probity_observer.ticket_service import DOMAIN
    receipt, native = complete(case)
    changed = copy.deepcopy(case["decision"])
    changed["record"]["core"]["transaction_digest"] = "sha256:" + "0" * 64
    changed["record"]["core_digest"] = native_digest("core", changed["record"]["core"])
    # Rehash the surrounding config/effect and sign it with the demo service key.
    # Native core recomputation must still fail before this wrapper is considered.
    configuration = copy.deepcopy(case["store"].configuration)
    configuration["decisionDigest"] = "0" * 64
    wrapper = copy.deepcopy(receipt)
    wrapper["payload"]["configuration"] = digest(DOMAIN + "-configuration", configuration)
    wrapper["payload"]["effectId"] = digest(DOMAIN + "-effect", {"configuration": wrapper["payload"]["configuration"], "requestId": case["host"]["request"].request_id, "grantDigest": wrapper["payload"]["grantDigest"]})
    wrapper["signature"] = case["host"]["key"].sign(DOMAIN, wrapper["payload"])
    readback = copy.deepcopy(native)
    readback["receipt"] = wrapper
    readback["effectId"] = wrapper["payload"]["effectId"]
    with pytest.raises(VerificationError, match="native replay"):
        consume(case, wrapper, readback, **changed)


def test_native_ticket_bypass_detected_with_joined_decision(case):
    """A still-valid AAE decision does not excuse changed native persistent bytes."""
    import sqlite3
    complete(case)
    with sqlite3.connect(case["host"]["path"]) as db:
        db.execute("UPDATE tickets SET content=?", (b"changed outside service",))
    with running_server(case["store"]) as server:
        assert http_json(server.url + "/dispatch", case["candidate"])[0] == 409
        assert http_json(server.url + "/tickets/tenant/ticket")[0] == 409


@pytest.mark.parametrize("commitment", ["0" * 64, None])
def test_changed_or_missing_decision_configuration_refuses_restart(case, commitment):
    """Restart does not accept a newly selected optional commitment on old state."""
    with pytest.raises(VerificationError, match="configuration"):
        TicketStore(**case["host"], decision_digest=commitment).readback()
