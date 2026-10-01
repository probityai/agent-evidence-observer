"""Keep kernel permission, issuer authentication and local execution separate."""

from __future__ import annotations

import copy
import hashlib
import re
from dataclasses import replace

import pytest

from probity_observer.aae_binding import (
    local_transaction,
    sign_effect_link,
    verify_effect_link,
    write_local_action,
)
from probity_observer.aae_enforce import enforce_check, native_digest
from probity_observer.authorization import ActionRequest
from probity_observer.broker import Broker
from probity_observer.crypto import SigningKey, VerificationError
from probity_observer.history import Witness

CONTENT = b"one local reference effect\n"


@pytest.fixture
def context(tmp_path):
    request = ActionRequest(
        "run-1",
        "attempt-1",
        "request-1",
        "tenant-1",
        "principal-1",
        "local.write-file",
        "/work/result.txt",
        hashlib.sha256(CONTENT).hexdigest(),
    )
    transaction = local_transaction(request)
    mandate = {
        "grants": [
            {
                "action_binding": native_digest("action", transaction["action"]),
                "type_fields": ["verb", "targetKind"],
                "disposition": "allow",
                "constraints": [
                    {"type": "exact", "field": key, "value": value}
                    for key, value in transaction.items()
                    if key != "action"
                ],
            }
        ],
    }
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    observer, witness = SigningKey.generate(), SigningKey.generate()
    history = tmp_path / "history.jsonl"
    broker = Broker(
        workspace,
        history,
        {"intervalId": request.run_id, "scope": "/work", "operation": "write-file"},
        observer,
        Witness(tmp_path / "witness.json", witness),
    )
    broker.begin()
    return {
        "mandate": mandate,
        "transaction": transaction,
        "record": enforce_check(mandate, transaction),
        "request": request,
        "pinned_mandate_digest": native_digest("mandate", mandate),
        "broker": broker,
        "observer": observer,
        "history": history,
        "workspace": workspace,
        "pinned_observer_key": observer.public_hex,
        "pinned_witness_key": witness.public_hex,
    }


def _write(context, **changes):
    names = (
        "mandate",
        "transaction",
        "record",
        "request",
        "pinned_mandate_digest",
        "broker",
    )
    arguments = {name: context[name] for name in names}
    return write_local_action(**{**arguments, "content": CONTENT, **changes})


def _complete(context):
    _write(context)
    packet = context["broker"].seal()
    link = sign_effect_link(
        context["record"], context["request"], packet, context["observer"]
    )
    names = (
        "mandate",
        "transaction",
        "record",
        "request",
        "pinned_mandate_digest",
        "history",
        "workspace",
        "pinned_observer_key",
        "pinned_witness_key",
    )
    return {**{name: context[name] for name in names}, "packet": packet, "link": link}


def _refuse(operation, expected, caplog):
    with pytest.raises(VerificationError, match=f"^{re.escape(expected)}$") as caught:
        operation()
    assert str(caught.value) == expected
    assert caplog.records == []


class TestAaeEffectBinding:
    class TestPassingCases:
        def test_replayed_permit_precedes_one_verified_local_write(self, context):
            arguments = _complete(context)
            result = verify_effect_link(**arguments)
            assert result["kernelVerdict"] == "PERMIT"
            assert result["execution"] == "recorded-local-write"
            assert result["linkage"] == "verified"
            assert result["issuerAuthentication"] == "not-established"
            assert result["witnessScope"] == "PEER"
            assert (context["workspace"] / "result.txt").read_bytes() == CONTENT

        def test_missing_link_leaves_execution_unknown(self, context):
            arguments = _complete(context)
            result = verify_effect_link(**{**arguments, "link": None})
            assert result["execution"] == "unknown"
            assert result["linkage"] == "missing"
            assert result["issuerAuthentication"] == "not-established"

        def test_unsigned_issuer_text_does_not_upgrade_authentication(self, context):
            arguments = _complete(context)
            mandate = copy.deepcopy(context["mandate"])
            mandate["issuer"] = "did:example:forged-unsigned-issuer"
            result = verify_effect_link(
                **{
                    **arguments,
                    "mandate": mandate,
                    "record": enforce_check(mandate, context["transaction"]),
                    "pinned_mandate_digest": native_digest("mandate", mandate),
                    "link": None,
                }
            )
            assert result["kernelVerdict"] == "PERMIT"
            assert result["issuerAuthentication"] == "not-established"
            assert result["execution"] == "unknown"

        def test_jcs_equivalent_number_core_remains_acceptable(self, context):
            record = copy.deepcopy(context["record"])
            record["core"]["grant_index"] = 0.0
            _write(context, record=record)
            assert (context["workspace"] / "result.txt").read_bytes() == CONTENT

    class TestFailingCases:
        @pytest.mark.parametrize(
            "change,expected",
            [
                ("core", "AAE record differs from the independently replayed core"),
                ("bool", "AAE record differs from the independently replayed core"),
                ("pin", "AAE mandate differs from the consumer pin"),
                ("content", "AAE write content differs from the expected local action"),
                ("request", "AAE transaction differs from the expected local action"),
            ],
        )
        def test_dispatch_substitution_fails_before_any_write(
            self, context, change, expected, caplog
        ):
            record = copy.deepcopy(context["record"])
            changes = {
                "core": {"record": {**record, "core_digest": "sha256:" + "0" * 64}},
                "bool": {
                    "record": {
                        **record,
                        "core": {**record["core"], "grant_index": False},
                    }
                },
                "pin": {"pinned_mandate_digest": "sha256:" + "0" * 64},
                "content": {"content": b"substituted"},
                "request": {"request": replace(context["request"], attempt_id="other")},
            }
            before = context["history"].read_bytes()
            _refuse(lambda: _write(context, **changes[change]), expected, caplog)
            assert context["history"].read_bytes() == before
            assert list(context["workspace"].iterdir()) == []

        def test_denied_kernel_does_not_dispatch(self, context, caplog):
            mandate = copy.deepcopy(context["mandate"])
            mandate["grants"][0]["disposition"] = "forbid"
            _refuse(
                lambda: _write(
                    context,
                    mandate=mandate,
                    record=enforce_check(mandate, context["transaction"]),
                    pinned_mandate_digest=native_digest("mandate", mandate),
                ),
                "AAE local dispatch requires a replayed PERMIT",
                caplog,
            )
            assert list(context["workspace"].iterdir()) == []

        def test_broad_permit_does_not_dispatch(self, context, caplog):
            mandate = copy.deepcopy(context["mandate"])
            mandate["grants"][0]["constraints"] = []
            record = enforce_check(mandate, context["transaction"])
            assert record["verdict"] == "PERMIT"
            _refuse(
                lambda: _write(
                    context,
                    mandate=mandate,
                    record=record,
                    pinned_mandate_digest=native_digest("mandate", mandate),
                ),
                "AAE local dispatch requires exact constraints for the request",
                caplog,
            )
            assert list(context["workspace"].iterdir()) == []

        def test_effect_link_requires_consumer_selected_observer_pin(
            self, context, caplog
        ):
            arguments = _complete(context)
            _refuse(
                lambda: verify_effect_link(
                    **{
                        **arguments,
                        "pinned_observer_key": SigningKey.generate().public_hex,
                    }
                ),
                "AAE effect link signer differs from the observer pin",
                caplog,
            )

        def test_unsigned_replacement_payload_is_not_accepted(self, context, caplog):
            arguments = _complete(context)
            arguments["link"]["payload"]["coreDigest"] = "sha256:" + "0" * 64
            _refuse(
                lambda: verify_effect_link(**arguments),
                "signature does not verify under the pinned key",
                caplog,
            )
