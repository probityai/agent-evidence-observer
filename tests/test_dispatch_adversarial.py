"""Independent attacks on the exact protected-dispatch candidate.

Signed mutants test semantic consistency even when the declared local signers
emit contradictory records; they do not purport to forge Ed25519 signatures.
Fault injection tests bounded crash behavior, not production custody.
"""

from __future__ import annotations

import copy
import hashlib
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from probity_observer import broker as native_broker
from probity_observer import protected_dispatch as dispatch_module
from probity_observer import protected_isolation as isolation_module
from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant
from probity_observer.crypto import (
    SigningKey,
    VerificationError,
    canonical,
    digest,
    strict_loads,
)
from probity_observer.history import Witness, append_history, read_history
from probity_observer.protected_dispatch import (
    ProtectedDispatcher,
    verify_dispatch_bundle,
)

CONTENT = b"independent reviewer effect\n"


@dataclass
class DispatchRun:
    """Carry externally selected test keys and exact action configuration."""

    workspace: Path
    state: Path
    request: ActionRequest
    policy: GrantPolicy
    grant: dict[str, Any]
    observer: SigningKey
    witness: SigningKey
    now: datetime
    dispatcher: ProtectedDispatcher

    def restart(self, **kwargs: Any) -> ProtectedDispatcher:
        """Reopen a store without changing its retained action or role pins."""
        return ProtectedDispatcher(
            self.workspace,
            self.state,
            self.request,
            self.policy,
            self.observer,
            self.witness,
            clock=lambda: self.now,
            **kwargs,
        )

    def complete(self) -> dict[str, Any]:
        """Create a genuinely completed native effect before attacking records."""
        result = self.dispatcher.write(self.request, self.grant, CONTENT)
        assert result.replayed is False
        assert (self.workspace / "result.txt").read_bytes() == CONTENT
        return self.dispatcher.retained_head()

    def verify(self, head: dict[str, Any]) -> dict[str, Any]:
        """Use reviewer-held request, issuer, observer and witness key pins."""
        return verify_dispatch_bundle(
            self.state,
            self.request,
            self.policy,
            self.observer.public_hex,
            self.witness.public_hex,
            head,
            workspace=self.workspace,
        )

    def signed_state(self, payload: dict[str, Any]) -> None:
        """Emit an observer-authenticated mutant without weakening signature checks."""
        envelope = {
            "payload": payload,
            "keyid": self.observer.public_hex,
            "signature": self.observer.sign(dispatch_module.STATE_DOMAIN, payload),
        }
        (self.state / "dispatch-state.json").write_bytes(canonical(envelope))


@pytest.fixture
def run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> DispatchRun:
    """Create an isolated bounded effect fixture with deterministic native clock."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    monkeypatch.setattr(
        native_broker, "utc_now", lambda: now.strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "result.txt").write_bytes(b"before\n")
    issuer, observer, witness = (SigningKey.generate() for _ in range(3))
    request = ActionRequest(
        "review-run",
        "review-attempt",
        "review-request",
        "tenant",
        "principal",
        "file-tool",
        "/work/result.txt",
        hashlib.sha256(CONTENT).hexdigest(),
    )
    policy = GrantPolicy(issuer.public_hex)
    grant = issue_grant(
        request,
        issuer,
        issued_at=now - timedelta(seconds=5),
        expires_at=now + timedelta(seconds=120),
    )
    state = tmp_path / "state"
    dispatcher = ProtectedDispatcher(
        workspace,
        state,
        request,
        policy,
        observer,
        witness,
        clock=lambda: now,
    )
    dispatcher.initialize()
    return DispatchRun(
        workspace, state, request, policy, grant, observer, witness, now, dispatcher
    )


def synthetic_isolation_fixture(
    run: DispatchRun, root: Path
) -> tuple[Path, str, dict[str, Any]]:
    """Build an explicitly signed unit fixture, not actual namespace evidence.

    The native host effect is genuinely executed. Child assertions and launch
    metadata are synthetic solely to test signed report consistency.
    """
    output = root / "synthetic-signed-report"
    output.mkdir()
    workspace = output / "workspace"
    workspace.mkdir()
    (workspace / "result.txt").write_bytes(b"before\n")
    probe = b"synthetic unit probe: not executed\n"
    invocation = canonical(
        {
            "invocation": {
                "request": asdict(run.request),
                "grant": run.grant,
                "contentHex": CONTENT.hex(),
            }
        }
    )
    (output / "agent-probe.py").write_bytes(probe)
    (output / "invocation.json").write_bytes(invocation)
    launch = {
        "argv": ["synthetic-unit-fixture-not-a-real-launch"],
        "probeSha256": hashlib.sha256(probe).hexdigest(),
        "invocationSha256": hashlib.sha256(invocation).hexdigest(),
        "interpreterSha256": "0" * 64,
        "bwrapSha256": "0" * 64,
        "observerBuildDigest": "0" * 64,
        "mountProfile": "public-input-and-protected-socket-only",
    }
    launch_digest = digest(isolation_module.LAUNCH_DOMAIN, launch)
    dispatcher = ProtectedDispatcher(
        workspace,
        output / "producer",
        run.request,
        run.policy,
        run.observer,
        run.witness,
        clock=lambda: run.now,
        execution_digest=launch_digest,
    )
    dispatcher.initialize()
    dispatcher.write(run.request, run.grant, CONTENT)
    head = dispatcher.retained_head()
    attempts = {name: True for name in isolation_module.EXPECTED}
    stdout = canonical(attempts) + b"\n"
    (output / "probe-stdout.bin").write_bytes(stdout)
    (output / "probe-stderr.bin").write_bytes(b"")
    report = {
        "status": "probe-passed",
        "reason": None,
        "exitCode": 0,
        "attempts": attempts,
        "launchDigest": launch_digest,
        "stdoutSha256": hashlib.sha256(stdout).hexdigest(),
        "stderrSha256": hashlib.sha256(b"").hexdigest(),
        "witnessScope": "PEER",
        "evidence_vantage": "artifact",
        "restartReplayed": True,
        "consumerStatus": "admitted",
        "authorizationHead": head,
    }
    (output / "launch-policy.json").write_bytes(canonical(launch))
    (output / "protected-isolation-report.json").write_bytes(canonical(report))
    payload = {
        "reportDigest": digest(isolation_module.REPORT_DOMAIN, report),
        "launchDigest": launch_digest,
        "authorizationHead": head,
    }
    attestation = {
        "payload": payload,
        "keyid": run.observer.public_hex,
        "signature": run.observer.sign(isolation_module.REPORT_DOMAIN, payload),
    }
    (output / "protected-isolation-attestation.json").write_bytes(
        canonical(attestation)
    )
    return output, launch_digest, head


class TestIndependentDispatchReview:
    """Distinguish positive reruns, hostile refusal and signed inconsistencies."""

    class TestPassingCases:
        """Positive controls prevent attacks from merely breaking fixtures."""

        def test_completed_native_effect_verifies(self, run: DispatchRun) -> None:
            head = run.complete()
            result = run.verify(head)
            assert (
                result["orderingEvidence"]
                == "local-witnessed-grant-before-host-dispatch"
            )

        def test_restart_returns_result_without_another_effect(
            self,
            run: DispatchRun,
            monkeypatch: pytest.MonkeyPatch,
        ) -> None:
            head = run.complete()

            def forbidden_effect(*args: Any, **kwargs: Any) -> None:
                raise AssertionError("a completed restart attempted a second effect")

            monkeypatch.setattr(native_broker, "_atomic_write", forbidden_effect)
            result = run.restart(retained_authorization_head=head).write(
                run.request, run.grant, CONTENT
            )
            assert result.replayed is True

        def test_concurrent_identical_requests_apply_only_one_local_effect(
            self,
            run: DispatchRun,
            monkeypatch: pytest.MonkeyPatch,
        ) -> None:
            real_effect = native_broker._atomic_write
            effects: list[bool] = []
            results: list[Any] = []
            start = threading.Barrier(3)

            def effect(target: Path, content: bytes) -> None:
                effects.append(True)
                real_effect(target, content)

            def invoke() -> None:
                start.wait(timeout=3)
                results.append(run.dispatcher.write(run.request, run.grant, CONTENT))

            monkeypatch.setattr(native_broker, "_atomic_write", effect)
            threads = [threading.Thread(target=invoke) for _ in range(2)]
            for thread in threads:
                thread.start()
            start.wait(timeout=3)
            for thread in threads:
                thread.join(timeout=3)
                assert not thread.is_alive()
            assert len(effects) == 1
            assert sorted(result.replayed for result in results) == [False, True]

    class TestFailingCases:
        """Each mutation must fail closed rather than become replay-acceptable."""

        @pytest.mark.parametrize("mutation", ["extra-field", "wrong-format"])
        def test_offline_reader_rejects_authenticated_wrong_state_profile(
            self,
            run: DispatchRun,
            mutation: str,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            head = run.complete()
            state = strict_loads((run.state / "dispatch-state.json").read_bytes())[
                "payload"
            ]
            if mutation == "extra-field":
                state["uncheckedExtension"] = {"claims": "unconstrained"}
            else:
                state["format"] = "another-dispatch-state-profile"
            run.signed_state(state)
            with pytest.raises(
                VerificationError, match="^dispatch state has unexpected fields$"
            ):
                run.verify(head)
            assert "dispatch state has unexpected fields" in caplog.text

        def test_initial_root_must_match_native_prior_root(
            self, run: DispatchRun, caplog: pytest.LogCaptureFixture
        ) -> None:
            run.complete()
            state = strict_loads((run.state / "dispatch-state.json").read_bytes())[
                "payload"
            ]
            old_entries = read_history(run.state / "authorization.jsonl")
            events = [copy.deepcopy(entry["event"]) for entry in old_entries]
            state["beforeRoot"] = "f" * 64
            events[0]["beforeRoot"] = state["beforeRoot"]
            journal = run.state / "authorization.jsonl"
            journal.write_bytes(b"")
            witness_path = run.state / "review-rewitness.json"
            witness = Witness(witness_path, run.witness)
            append_history(journal, events[0])
            witness.checkpoint(journal)
            append_history(journal, events[1])
            state["priorCheckpoint"] = witness.checkpoint(journal)
            append_history(journal, events[2])
            head = witness.checkpoint(journal)
            state["checkpoint"] = head
            run.signed_state(state)
            with pytest.raises(
                VerificationError,
                match="^native before root differs from the retained initialization$",
            ):
                run.verify(head)
            assert (
                "native before root differs from the retained initialization"
                in caplog.text
            )

        def test_cached_retry_rechecks_expiry_after_waiting_for_lock(
            self,
            run: DispatchRun,
        ) -> None:
            run.complete()
            initial_check = threading.Event()
            expired = threading.Event()
            errors: list[VerificationError] = []

            def clock() -> datetime:
                initial_check.set()
                if expired.is_set():
                    return run.now + timedelta(seconds=120)
                return run.now

            run.dispatcher.clock = clock

            def retry() -> None:
                try:
                    run.dispatcher.write(run.request, run.grant, CONTENT)
                except VerificationError as exc:
                    errors.append(exc)

            with dispatch_module._locked(run.state / "dispatch.lock"):
                thread = threading.Thread(target=retry)
                thread.start()
                assert initial_check.wait(timeout=3), (
                    "retry did not reach pre-lock grant check"
                )
                expired.set()
            thread.join(timeout=3)
            assert not thread.is_alive(), "retry did not finish after lock release"
            assert len(errors) == 1
            assert isinstance(errors[0], VerificationError)
            assert str(errors[0]) == "grant is not valid at the reference time"

        @pytest.mark.parametrize("after_effect", [False, True])
        def test_pending_crash_never_automatically_repeats_effect(
            self,
            run: DispatchRun,
            monkeypatch: pytest.MonkeyPatch,
            after_effect: bool,
        ) -> None:
            real_write = dispatch_module.AuthorizedBroker.write
            actual_effects: list[bool] = []

            def crash(broker: Any, request: ActionRequest, content: bytes) -> Any:
                if after_effect:
                    result = real_write(broker, request, content)
                    actual_effects.append(True)
                    del result
                raise RuntimeError("reviewer crash at authorized write")

            monkeypatch.setattr(dispatch_module.AuthorizedBroker, "write", crash)
            with pytest.raises(
                RuntimeError, match="^reviewer crash at authorized write$"
            ):
                run.dispatcher.write(run.request, run.grant, CONTENT)
            monkeypatch.setattr(dispatch_module.AuthorizedBroker, "write", real_write)
            with pytest.raises(
                VerificationError,
                match="^write outcome unresolved; operator recovery required$",
            ):
                run.restart().write(run.request, run.grant, CONTENT)
            assert len(actual_effects) == int(after_effect)
            expected = CONTENT if after_effect else b"before\n"
            assert (run.workspace / "result.txt").read_bytes() == expected

        def test_truncated_journal_refuses_cached_replay(
            self, run: DispatchRun
        ) -> None:
            head = run.complete()
            journal = run.state / "authorization.jsonl"
            journal.write_bytes(
                b"\n".join(journal.read_bytes().splitlines()[:2]) + b"\n"
            )
            with pytest.raises(
                VerificationError,
                match="^checkpoint does not bind the supplied history$",
            ):
                run.restart(retained_authorization_head=head).write(
                    run.request, run.grant, CONTENT
                )

        def test_backward_clock_cannot_return_an_unverifiable_success(
            self,
            run: DispatchRun,
            monkeypatch: pytest.MonkeyPatch,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            references = iter(
                (run.now, run.now, run.now + timedelta(seconds=1), run.now)
            )
            native_times = iter(
                (
                    run.now,
                    run.now + timedelta(seconds=2),
                    run.now + timedelta(seconds=2),
                )
            )
            run.dispatcher.clock = lambda: next(references)
            monkeypatch.setattr(
                native_broker,
                "utc_now",
                lambda: next(native_times).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            with pytest.raises(
                VerificationError,
                match="^dispatch clock precedes the witnessed authorization$",
            ):
                run.dispatcher.write(run.request, run.grant, CONTENT)
            assert (run.workspace / "result.txt").read_bytes() == b"before\n"
            assert "dispatch clock precedes the witnessed authorization" in caplog.text

        @pytest.mark.parametrize("mutation", ["attestation-head", "report-head"])
        def test_signed_report_heads_match_the_actual_completed_checkpoint(
            self,
            run: DispatchRun,
            tmp_path: Path,
            mutation: str,
        ) -> None:
            output, launch_digest, retained = synthetic_isolation_fixture(run, tmp_path)

            def verify() -> dict[str, Any]:
                """Verify the fixture with independently held action and key pins."""
                return isolation_module.verify_protected_isolation_bundle(
                    output,
                    run.request,
                    run.policy,
                    run.observer.public_hex,
                    run.witness.public_hex,
                    retained,
                    expected_launch_digest=launch_digest,
                )

            assert verify()["status"] == "probe-passed"
            attestation = strict_loads(
                (output / "protected-isolation-attestation.json").read_bytes()
            )
            bogus_head = {**retained, "head": "f" * 64}
            if mutation == "attestation-head":
                attestation["payload"]["authorizationHead"] = bogus_head
            else:
                report = strict_loads(
                    (output / "protected-isolation-report.json").read_bytes()
                )
                report["authorizationHead"] = bogus_head
                (output / "protected-isolation-report.json").write_bytes(
                    canonical(report)
                )
                attestation["payload"]["reportDigest"] = digest(
                    isolation_module.REPORT_DOMAIN, report
                )
            attestation["signature"] = run.observer.sign(
                isolation_module.REPORT_DOMAIN, attestation["payload"]
            )
            (output / "protected-isolation-attestation.json").write_bytes(
                canonical(attestation)
            )
            with pytest.raises(
                VerificationError,
                match="^protected report head differs from the completed journal$",
            ):
                verify()
