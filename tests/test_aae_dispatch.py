"""Native decision, protected order, restart, and evidence-substitution controls."""

from __future__ import annotations

import copy
import hashlib
import re
import tempfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from probity_observer.aae_binding import local_transaction
from probity_observer.aae_dispatch import (
    AaeProtectedDispatcher,
    verify_aae_dispatch_bundle,
)
from probity_observer.aae_enforce import enforce_check, native_digest
from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant
from probity_observer.crypto import SigningKey, VerificationError, strict_loads
from probity_observer.history import read_history
from probity_observer.protected_dispatch import (
    ProtectedDispatcher,
    verify_dispatch_bundle,
)


def make_case(root: Path, content: bytes = b"protected AAE effect\n") -> dict:
    """Configure an exact native decision and a distinct local issuer grant."""
    now = datetime.now(UTC).replace(microsecond=0)
    issuer, observer, witness = (SigningKey.generate() for _ in range(3))
    request = ActionRequest(
        "run",
        "attempt",
        "request",
        "tenant",
        "principal",
        "write-file",
        "/work/result.txt",
        hashlib.sha256(content).hexdigest(),
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
        ]
    }
    workspace = root / "workspace"
    workspace.mkdir()
    decision = {
        "mandate": mandate,
        "transaction": transaction,
        "record": enforce_check(mandate, transaction),
        "pinned_mandate_digest": native_digest("mandate", mandate),
    }
    host = {
        "workspace": workspace,
        "state_dir": root / "state",
        "expected_request": request,
        "policy": GrantPolicy(issuer.public_hex),
        "observer_key": observer,
        "witness_key": witness,
        "clock": lambda: now,
    }
    grant = issue_grant(
        request,
        issuer,
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(seconds=60),
    )
    dispatcher = AaeProtectedDispatcher(**host, **decision)
    initial = dispatcher.initialize()
    return {
        "host": host,
        "decision": decision,
        "dispatcher": dispatcher,
        "grant": grant,
        "initial": initial,
        "content": content,
        "request": request,
        "root": root,
    }


@pytest.fixture
def case(tmp_path):
    return make_case(tmp_path)


def verify(case, **changes):
    host = case["host"]
    arguments = dict(
        **case["decision"],
        directory=host["state_dir"],
        expected_request=case["request"],
        policy=host["policy"],
        observer_key=host["observer_key"].public_hex,
        witness_key=host["witness_key"].public_hex,
        retained_authorization_head=case["initial"],
        workspace=host["workspace"],
    )
    return verify_aae_dispatch_bundle(**{**arguments, **changes})


def complete(case):
    return case["dispatcher"].write(case["request"], case["grant"], case["content"])


def refuse(operation, expected, caplog):
    caplog.clear()
    with pytest.raises(VerificationError, match=f"^{re.escape(expected)}$") as caught:
        operation()
    assert str(caught.value) == expected
    assert all(expected in record.message for record in caplog.records)


class TestAaeProtectedDispatcher:
    class TestPassingCases:
        def test_decision_committed_before_effect_and_verified_after_restart(
            self, case
        ):
            initial_state = strict_loads(
                (case["host"]["state_dir"] / "dispatch-state.json").read_bytes()
            )
            decision_digest = initial_state["payload"]["configuration"][
                "decisionDigest"
            ]
            assert initial_state["payload"]["phase"] == "ready"
            result = complete(case)
            assert result.replayed is False
            restart = AaeProtectedDispatcher(
                **case["host"],
                **case["decision"],
                retained_authorization_head=case["initial"],
            )
            assert restart.write(
                case["request"], case["grant"], case["content"]
            ).replayed
            verified = verify(case)
            assert verified["decisionDigest"] == decision_digest
            assert verified["execution"] == "recorded-local-write"
            assert verified["issuerAuthentication"] == "not-established"
            assert verified["witnessScope"] == "PEER"
            assert (
                len(read_history(case["host"]["state_dir"] / "authorization.jsonl"))
                == 3
            )
            state = strict_loads(
                (case["host"]["state_dir"] / "dispatch-state.json").read_bytes()
            )["payload"]
            assert len(state["packet"]["claim"]["writes"]) == 1
            assert (case["host"]["workspace"] / "result.txt").read_bytes() == case[
                "content"
            ]

        def test_explicit_absent_evidence_leaves_execution_unknown(self, case):
            result = verify(case, directory=None)
            assert result["execution"] == "unknown"
            assert result["linkage"] == "missing"
            assert result["kernelVerdict"] == "PERMIT"

        def test_mutating_callers_inputs_does_not_change_frozen_decision(self, case):
            original = copy.deepcopy(case["decision"])
            case["decision"]["mandate"]["grants"].clear()
            complete(case)
            assert verify(case, **original)["linkage"] == "verified"

        def test_legacy_configuration_omits_decision_digest(self, case):
            host = {**case["host"], "state_dir": case["root"] / "legacy"}
            dispatcher = ProtectedDispatcher(**host)
            head = dispatcher.initialize()
            dispatcher.write(case["request"], case["grant"], case["content"])
            state = strict_loads(
                (host["state_dir"] / "dispatch-state.json").read_bytes()
            )
            assert "decisionDigest" not in state["payload"]["configuration"]
            verify_dispatch_bundle(
                host["state_dir"],
                case["request"],
                host["policy"],
                host["observer_key"].public_hex,
                host["witness_key"].public_hex,
                head,
            )

        @given(content=st.binary(max_size=512))
        @settings(max_examples=12, deadline=None)
        def test_arbitrary_content_has_one_effect_and_replay(self, content):
            with tempfile.TemporaryDirectory() as directory:
                case = make_case(Path(directory), content)
                assert complete(case).replayed is False
                assert complete(case).replayed is True
                assert verify(case)["linkage"] == "verified"

    class TestFailingCases:
        @pytest.mark.parametrize("field", list(ActionRequest.__dataclass_fields__))
        def test_all_request_substitutions_refused_before_effect(
            self, case, field, caplog
        ):
            replacement = {
                "target_path": "/work/other.txt",
                "content_sha256": "0" * 64,
            }.get(field, "other")
            request = replace(case["request"], **{field: replacement})
            refuse(
                lambda: case["dispatcher"].write(
                    request, case["grant"], case["content"]
                ),
                "AAE transaction differs from the expected local action",
                caplog,
            )
            assert list(case["host"]["workspace"].iterdir()) == []
            assert (
                len(read_history(case["host"]["state_dir"] / "authorization.jsonl"))
                == 1
            )

        @pytest.mark.parametrize("disposition", ["forbid", "hold"])
        def test_nonpermit_cannot_initialize_dispatch(self, case, disposition, caplog):
            decision = copy.deepcopy(case["decision"])
            decision["mandate"]["grants"][0]["disposition"] = disposition
            decision["record"] = enforce_check(
                decision["mandate"], decision["transaction"]
            )
            decision["pinned_mandate_digest"] = native_digest(
                "mandate", decision["mandate"]
            )
            refuse(
                lambda: AaeProtectedDispatcher(**case["host"], **decision),
                "AAE local dispatch requires a replayed PERMIT",
                caplog,
            )
            assert list(case["host"]["workspace"].iterdir()) == []

        def test_changed_unsigned_mandate_cannot_reuse_dispatch(self, case, caplog):
            complete(case)
            decision = copy.deepcopy(case["decision"])
            decision["mandate"]["issuer"] = "did:example:substitute"
            decision["record"] = enforce_check(
                decision["mandate"], decision["transaction"]
            )
            decision["pinned_mandate_digest"] = native_digest(
                "mandate", decision["mandate"]
            )
            refuse(
                lambda: verify(case, **decision),
                "dispatch bundle differs from the expected completed action",
                caplog,
            )

        def test_missing_bundle_file_is_not_unknown_or_success(self, case, caplog):
            complete(case)
            (case["host"]["state_dir"] / "dispatch-state.json").unlink()
            with pytest.raises(FileNotFoundError, match="No such file or directory"):
                verify(case)
            assert caplog.records == []

        def test_incomplete_bundle_is_refused(self, case, caplog):
            refuse(
                lambda: verify(case),
                "dispatch bundle differs from the expected completed action",
                caplog,
            )

        @pytest.mark.parametrize(
            "name", ["packet.json", "authorization.jsonl", "history.jsonl"]
        )
        def test_tampered_retained_artifact_refused(self, case, name, caplog):
            complete(case)
            path = case["host"]["state_dir"] / name
            path.write_bytes(b"{}")
            expected = {
                "packet.json": "retained native packet differs from the completed result",
                "authorization.jsonl": "history ends with an incomplete line",
                "history.jsonl": "history ends with an incomplete line",
            }[name]
            refuse(lambda: verify(case), expected, caplog)

        @pytest.mark.parametrize("value", ["", "A" * 64, "0" * 63, 1, False])
        def test_invalid_decision_digest_refused(self, case, value, caplog):
            refuse(
                lambda: ProtectedDispatcher(**case["host"], decision_digest=value),
                "decision digest must be a lowercase SHA-256-sized value",
                caplog,
            )

        def test_restart_with_changed_decision_refuses_before_replay(
            self, case, caplog
        ):
            complete(case)
            decision = copy.deepcopy(case["decision"])
            decision["mandate"]["issuer"] = "did:example:changed"
            decision["record"] = enforce_check(
                decision["mandate"], decision["transaction"]
            )
            decision["pinned_mandate_digest"] = native_digest(
                "mandate", decision["mandate"]
            )
            restarted = AaeProtectedDispatcher(**case["host"], **decision)
            refuse(
                lambda: restarted.write(
                    case["request"], case["grant"], case["content"]
                ),
                "dispatch configuration differs from the retained action",
                caplog,
            )

        def test_unbound_generic_dispatch_cannot_be_upgraded(self, case, caplog):
            host = {**case["host"], "state_dir": case["root"] / "legacy"}
            legacy = ProtectedDispatcher(**host)
            initial = legacy.initialize()
            legacy.write(case["request"], case["grant"], case["content"])
            refuse(
                lambda: verify(
                    case,
                    directory=host["state_dir"],
                    retained_authorization_head=initial,
                ),
                "dispatch bundle differs from the expected completed action",
                caplog,
            )

        def test_corrupt_local_grant_refused_despite_native_permit(self, case, caplog):
            grant = {**case["grant"], "signature": "00" * 64}
            refuse(
                lambda: case["dispatcher"].write(
                    case["request"], grant, case["content"]
                ),
                "grant signature does not verify under the pinned issuer key",
                caplog,
            )
            assert list(case["host"]["workspace"].iterdir()) == []

        def test_pending_effect_never_reexecutes(self, case, monkeypatch, caplog):
            from probity_observer.broker import Broker

            def interrupted(*args, **kwargs):
                raise OSError("injected native write interruption")

            with monkeypatch.context() as patch:
                patch.setattr(Broker, "write", interrupted)
                with pytest.raises(
                    OSError, match="^injected native write interruption$"
                ):
                    complete(case)
            assert caplog.records == []
            restarted = AaeProtectedDispatcher(**case["host"], **case["decision"])
            refuse(
                lambda: restarted.write(
                    case["request"], case["grant"], case["content"]
                ),
                "write outcome unresolved; operator recovery required",
                caplog,
            )
            assert list(case["host"]["workspace"].iterdir()) == []
