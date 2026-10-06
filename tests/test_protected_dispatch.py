"""Exact host dispatch, durable replay, and fail-closed interruption tests."""

from __future__ import annotations

import hashlib
import socket
import threading
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from probity_observer import broker as native
from probity_observer import protected_dispatch as module
from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant
from probity_observer.crypto import (
    SigningKey,
    VerificationError,
    canonical,
    strict_loads,
)
from probity_observer.history import read_history
from probity_observer.protected_dispatch import (
    ProtectedDispatcher,
    ProtectedWriteServer,
    verify_dispatch_bundle,
)


@pytest.fixture
def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Create an independently selected finite action and three role keys."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    monkeypatch.setattr(
        native,
        "utc_now",
        lambda: now.isoformat(timespec="seconds").replace("+00:00", "Z"),
    )
    issuer, observer, witness = (SigningKey.generate() for _ in range(3))
    content = b"one protected effect\n"
    request = ActionRequest(
        "run-1",
        "attempt-1",
        "request-1",
        "tenant-1",
        "principal-1",
        "file-write",
        "/work/effect.txt",
        hashlib.sha256(content).hexdigest(),
    )
    policy = GrantPolicy(issuer.public_hex)
    grant = issue_grant(
        request,
        issuer,
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(seconds=60),
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    directory = tmp_path / "state"
    dispatch = ProtectedDispatcher(
        workspace, directory, request, policy, observer, witness, clock=lambda: now
    )
    initial = dispatch.initialize()
    return {
        "now": now,
        "issuer": issuer,
        "observer": observer,
        "witness": witness,
        "content": content,
        "request": request,
        "policy": policy,
        "grant": grant,
        "workspace": workspace,
        "directory": directory,
        "dispatch": dispatch,
        "initial": initial,
    }


def reopen(case: dict[str, Any], **kwargs: Any) -> ProtectedDispatcher:
    """Reconstruct only from externally held policy, request, and role keys."""
    return ProtectedDispatcher(
        case["workspace"],
        case["directory"],
        case["request"],
        case["policy"],
        case["observer"],
        case["witness"],
        clock=kwargs.pop("clock", lambda: case["now"]),
        **kwargs,
    )


def invoke(case: dict[str, Any]) -> Any:
    """Apply the configured action through the host dispatcher."""
    return case["dispatch"].write(case["request"], case["grant"], case["content"])


def state(case: dict[str, Any]) -> dict[str, Any]:
    """Read the saved signed state payload without treating it as trusted."""
    return strict_loads((case["directory"] / "dispatch-state.json").read_bytes())[
        "payload"
    ]


class TestProtectedDispatcher:
    class TestPassingCases:
        def test_pre_effect_grant_is_witnessed_before_native_write(
            self, case: dict[str, Any], monkeypatch: pytest.MonkeyPatch
        ) -> None:
            original = native._atomic_write
            observed: list[str] = []

            def check(target: Path, content: bytes) -> None:
                saved = state(case)
                assert saved["phase"] == "pending"
                assert saved["priorCheckpoint"]["count"] == 2
                assert (
                    read_history(case["directory"] / "authorization.jsonl")[-1][
                        "event"
                    ]["kind"]
                    == "grant-before-dispatch"
                )
                observed.append("prior-witness-durable")
                original(target, content)

            monkeypatch.setattr(native, "_atomic_write", check)
            result = invoke(case)
            assert observed == ["prior-witness-durable"]
            assert result.replayed is False
            assert state(case)["phase"] == "complete"

        def test_replay_after_restart_does_not_apply_another_effect(
            self, case: dict[str, Any], monkeypatch: pytest.MonkeyPatch
        ) -> None:
            first = invoke(case)

            def forbidden(*args: Any) -> None:
                pytest.fail("cached result must not enter native write")

            monkeypatch.setattr(native, "_atomic_write", forbidden)
            restarted = reopen(
                case, retained_authorization_head=case["dispatch"].retained_head()
            )
            replay = restarted.write(case["request"], case["grant"], case["content"])
            assert replay == replace(first, replayed=True)
            assert (case["workspace"] / "effect.txt").read_bytes() == case["content"]
            assert (
                len(
                    [
                        entry
                        for entry in read_history(case["directory"] / "history.jsonl")
                        if entry["event"]["kind"] == "write"
                    ]
                )
                == 1
            )

        def test_consumer_verifies_retained_prior_and_current_tree(
            self, case: dict[str, Any]
        ) -> None:
            invoke(case)
            checked = verify_dispatch_bundle(
                case["directory"],
                case["request"],
                case["policy"],
                case["observer"].public_hex,
                case["witness"].public_hex,
                case["initial"],
                workspace=case["workspace"],
            )
            assert (
                checked["orderingEvidence"]
                == "local-witnessed-grant-before-host-dispatch"
            )
            assert checked["witnessScope"] == "PEER"
            assert checked["authorization"]["currentWorkspaceCompared"] is True

        # This property checks durable bytes and replay. Disk latency is not its contract.
        @settings(
            max_examples=40,
            deadline=None,
            suppress_health_check=[HealthCheck.function_scoped_fixture],
        )
        @given(content=st.binary(max_size=256))
        def test_arbitrary_exact_replacement_bytes(
            self, case: dict[str, Any], tmp_path: Path, content: bytes
        ) -> None:
            number = len(list(tmp_path.glob("generated-*")))
            workspace = tmp_path / f"generated-{number}"
            workspace.mkdir()
            request = replace(
                case["request"], content_sha256=hashlib.sha256(content).hexdigest()
            )
            grant = issue_grant(
                request,
                case["issuer"],
                issued_at=case["now"],
                expires_at=case["now"] + timedelta(seconds=30),
            )
            dispatch = ProtectedDispatcher(
                workspace,
                tmp_path / f"state-{number}",
                request,
                case["policy"],
                case["observer"],
                case["witness"],
                clock=lambda: case["now"],
            )
            dispatch.initialize()
            result = dispatch.write(request, grant, content)
            assert result.replayed is False
            assert dispatch.write(request, grant, content).replayed is True
            assert (workspace / "effect.txt").read_bytes() == content

    class TestFailingCases:
        @pytest.mark.parametrize(
            "field,value",
            [
                ("run_id", "other"),
                ("attempt_id", "other"),
                ("request_id", "other"),
                ("tenant_id", "other"),
                ("principal_id", "other"),
                ("tool_id", "other"),
                ("target_path", "/work/other.txt"),
                ("content_sha256", "0" * 64),
            ],
        )
        def test_changed_identity_refused_before_effect(
            self,
            case: dict[str, Any],
            caplog: pytest.LogCaptureFixture,
            field: str,
            value: str,
        ) -> None:
            with pytest.raises(
                VerificationError, match="^invocation differs from the expected action$"
            ):
                case["dispatch"].write(
                    replace(case["request"], **{field: value}),
                    case["grant"],
                    case["content"],
                )
            assert not list(case["workspace"].iterdir())
            assert state(case)["phase"] == "ready"
            assert (
                "protected dispatch refused: "
                "invocation differs from the expected action" in caplog.text
            )

        @pytest.mark.parametrize(
            "content", [b"changed", "wrong type", bytearray(b"wrong")]
        )
        def test_content_refusal_has_no_effect(
            self, case: dict[str, Any], caplog: pytest.LogCaptureFixture, content: Any
        ) -> None:
            message = (
                "content digest differs from the authorized action"
                if isinstance(content, bytes)
                else "protected dispatch content must be bytes"
            )
            with pytest.raises(VerificationError, match=f"^{message}$"):
                case["dispatch"].write(case["request"], case["grant"], content)
            assert not list(case["workspace"].iterdir())
            assert message in caplog.text

        @pytest.mark.parametrize("offset", [-2, 60, 61])
        def test_expired_or_premature_clock_refused(
            self, case: dict[str, Any], offset: int, caplog: pytest.LogCaptureFixture
        ) -> None:
            dispatch = reopen(
                case, clock=lambda: case["now"] + timedelta(seconds=offset)
            )
            with pytest.raises(
                VerificationError, match="^grant is not valid at the reference time$"
            ):
                dispatch.write(case["request"], case["grant"], case["content"])
            assert not list(case["workspace"].iterdir())
            assert "grant is not valid at the reference time" in caplog.text

        def test_grant_rechecked_after_lock_wait_for_replay(
            self, case: dict[str, Any]
        ) -> None:
            invoke(case)
            times = iter([case["now"], case["now"] + timedelta(seconds=60)])
            dispatch = reopen(case, clock=lambda: next(times))
            with pytest.raises(
                VerificationError, match="^grant is not valid at the reference time$"
            ):
                dispatch.write(case["request"], case["grant"], case["content"])
            assert len(read_history(case["directory"] / "history.jsonl")) == 4

        @pytest.mark.parametrize("mutation", ["issuer", "signature", "unknown"])
        def test_invalid_grant_never_prepares_native_effect(
            self, case: dict[str, Any], mutation: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            grant = {**case["grant"]}
            messages = {
                "issuer": "grant issuer differs from the pinned issuer key",
                "signature": "grant signature does not verify "
                "under the pinned issuer key",
                "unknown": "grant has unexpected fields",
            }
            if mutation == "unknown":
                grant["extra"] = True
            else:
                grant["issuerKey" if mutation == "issuer" else "signature"] = "0" * 64
            with pytest.raises(VerificationError, match=f"^{messages[mutation]}$"):
                case["dispatch"].write(case["request"], grant, case["content"])
            assert not (case["directory"] / "history.jsonl").exists()
            assert messages[mutation] in caplog.text

        @pytest.mark.parametrize("after_effect", [False, True])
        def test_interrupted_effect_never_repeats_after_restart(
            self,
            case: dict[str, Any],
            monkeypatch: pytest.MonkeyPatch,
            after_effect: bool,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            original = native._atomic_write
            calls: list[bool] = []

            def crash(target: Path, content: bytes) -> None:
                calls.append(after_effect)
                if after_effect:
                    original(target, content)
                raise OSError("injected crash at effect boundary")

            monkeypatch.setattr(native, "_atomic_write", crash)
            with pytest.raises(OSError, match="^injected crash at effect boundary$"):
                invoke(case)
            assert state(case)["phase"] == "pending"
            with pytest.raises(
                VerificationError,
                match="^write outcome unresolved; operator recovery required$",
            ):
                reopen(case).write(case["request"], case["grant"], case["content"])
            assert calls == [after_effect]
            assert (case["workspace"] / "effect.txt").exists() is after_effect
            assert "write outcome unresolved; operator recovery required" in caplog.text

        @pytest.mark.parametrize(
            "failure", ["packet-save", "completed-journal", "completed-state"]
        )
        def test_late_crash_is_not_reported_as_success(
            self, case: dict[str, Any], monkeypatch: pytest.MonkeyPatch, failure: str
        ) -> None:
            save, append = module._save, module.append_history

            def interrupted_save(path: Path, value: dict[str, Any]) -> None:
                payload = value.get("payload", {})
                if (failure == "packet-save" and path.name == "packet.json") or (
                    failure == "completed-state" and payload.get("phase") == "complete"
                ):
                    raise OSError("injected late persistence failure")
                save(path, value)

            def interrupted_append(path: Path, event: dict[str, Any]) -> Any:
                if (
                    failure == "completed-journal"
                    and event["kind"] == "dispatch-completed"
                ):
                    raise OSError("injected late persistence failure")
                return append(path, event)

            monkeypatch.setattr(module, "_save", interrupted_save)
            monkeypatch.setattr(module, "append_history", interrupted_append)
            with pytest.raises(OSError, match="^injected late persistence failure$"):
                invoke(case)
            assert (case["workspace"] / "effect.txt").read_bytes() == case["content"]
            refusal = (
                "checkpoint does not bind the supplied history"
                if failure == "completed-state"
                else "write outcome unresolved; operator recovery required"
            )
            with pytest.raises(VerificationError, match=f"^{refusal}$"):
                reopen(case).write(case["request"], case["grant"], case["content"])
            assert (
                len(
                    [
                        entry
                        for entry in read_history(case["directory"] / "history.jsonl")
                        if entry["event"]["kind"] == "write"
                    ]
                )
                == 1
            )

        def test_changed_target_tree_refuses_cached_response(
            self, case: dict[str, Any], caplog: pytest.LogCaptureFixture
        ) -> None:
            invoke(case)
            (case["workspace"] / "effect.txt").write_bytes(b"outside mutation")
            with pytest.raises(
                VerificationError,
                match="^current workspace root differs from the claim$",
            ):
                reopen(case).write(case["request"], case["grant"], case["content"])
            assert "current workspace root differs from the claim" in caplog.text

        @pytest.mark.parametrize(
            "missing", ["dispatch-state.json", "authorization-witness.json"]
        )
        def test_missing_protected_state_is_not_reset(
            self, case: dict[str, Any], missing: str, caplog: pytest.LogCaptureFixture
        ) -> None:
            invoke(case)
            (case["directory"] / missing).unlink()
            with pytest.raises(
                VerificationError,
                match="^dispatch state or retained authorization witness is missing$",
            ):
                reopen(case).write(case["request"], case["grant"], case["content"])
            assert (
                "dispatch state or retained authorization witness is missing"
                in caplog.text
            )

        def test_authorization_history_rollback_refused(
            self, case: dict[str, Any]
        ) -> None:
            initial = (case["directory"] / "authorization.jsonl").read_bytes()
            invoke(case)
            (case["directory"] / "authorization.jsonl").write_bytes(initial)
            with pytest.raises(
                VerificationError,
                match="^checkpoint does not bind the supplied history$",
            ):
                reopen(case).write(case["request"], case["grant"], case["content"])

        def test_witness_rollback_refused(self, case: dict[str, Any]) -> None:
            initial = (case["directory"] / "authorization-witness.json").read_bytes()
            invoke(case)
            (case["directory"] / "authorization-witness.json").write_bytes(initial)
            with pytest.raises(
                VerificationError,
                match="^checkpoint does not bind the supplied history$",
            ):
                reopen(case).write(case["request"], case["grant"], case["content"])

        def test_complete_local_rollback_detected_by_external_head(
            self, case: dict[str, Any], caplog: pytest.LogCaptureFixture
        ) -> None:
            initial = {
                path.name: path.read_bytes()
                for path in case["directory"].iterdir()
                if path.is_file()
            }
            invoke(case)
            retained = case["dispatch"].retained_head()
            for path in case["directory"].iterdir():
                if path.is_file():
                    path.unlink()
            for name, data in initial.items():
                (case["directory"] / name).write_bytes(data)
            with pytest.raises(
                VerificationError,
                match="^authorization history is shorter than the retained head$",
            ):
                reopen(case, retained_authorization_head=retained).write(
                    case["request"], case["grant"], case["content"]
                )
            assert (
                "authorization history is shorter than the retained head" in caplog.text
            )


@pytest.fixture
def wire(case: dict[str, Any], tmp_path: Path) -> Any:
    """Serve the actual host socket with no native-broker escape operation."""
    path = tmp_path / "protected.sock"
    server = ProtectedWriteServer(path, case["dispatch"])
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}
    )
    thread.start()

    def send(raw: bytes, read: bool = True) -> Any:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(3)
            client.connect(str(path))
            client.sendall(raw)
            client.shutdown(socket.SHUT_WR)
            if read:
                return strict_loads(
                    client.makefile("rb").readline(module.MAX_REQUEST + 1).rstrip(b"\n")
                )
        return None

    yield send
    server.shutdown()
    thread.join(timeout=3)
    server.server_close()


def payload(case: dict[str, Any]) -> dict[str, Any]:
    """Construct the exact public wire profile without signer material."""
    return {
        "request": asdict(case["request"]),
        "grant": case["grant"],
        "contentHex": case["content"].hex(),
    }


class TestProtectedWriteServer:
    class TestPassingCases:
        def test_actual_socket_dispatch_and_replay(
            self, case: dict[str, Any], wire: Any
        ) -> None:
            raw = canonical(payload(case)) + b"\n"
            assert wire(raw)["ok"] is True
            assert wire(raw)["replayed"] is True
            assert (case["workspace"] / "effect.txt").read_bytes() == case["content"]

        def test_lost_response_replays_saved_effect(
            self, case: dict[str, Any], wire: Any
        ) -> None:
            raw = canonical(payload(case)) + b"\n"
            wire(raw, read=False)
            assert wire(raw)["replayed"] is True
            assert (
                len(
                    [
                        entry
                        for entry in read_history(case["directory"] / "history.jsonl")
                        if entry["event"]["kind"] == "write"
                    ]
                )
                == 1
            )

    class TestFailingCases:
        @pytest.mark.parametrize(
            "raw,message",
            [
                (b"{}\n", "protected socket request has unexpected fields"),
                (b"bad\n", "invalid JSON document"),
                (b"{}", "protected socket request missing or oversized"),
                (b"{ }\n", "JSON document is not canonical"),
                (b'{"x":1,"x":2}\n', "duplicate JSON member"),
                (
                    b"[" * 1000 + b"]" * 1000 + b"\n",
                    "protected socket request exceeds structural limits",
                ),
            ],
        )
        def test_malformed_request_has_no_effect(
            self, case: dict[str, Any], wire: Any, raw: bytes, message: str
        ) -> None:
            response = wire(raw)
            assert response == {"ok": False, "error": message}
            assert not list(case["workspace"].iterdir())

        @pytest.mark.parametrize(
            "mutation,message",
            [
                ("native", "protected socket request has unexpected fields"),
                ("clock", "protected socket request has unexpected fields"),
                ("request-extra", "protected socket action has unexpected fields"),
                (
                    "hex-upper",
                    "protected socket content must use lowercase hexadecimal bytes",
                ),
                (
                    "hex-space",
                    "protected socket content must use lowercase hexadecimal bytes",
                ),
                (
                    "hex-odd",
                    "protected socket content must use lowercase hexadecimal bytes",
                ),
                ("tenant", "invocation differs from the expected action"),
                ("tool", "invocation differs from the expected action"),
                ("oversized", "protected socket request missing or oversized"),
            ],
        )
        def test_wire_substitutions_refused(
            self, case: dict[str, Any], wire: Any, mutation: str, message: str
        ) -> None:
            candidate = payload(case)
            if mutation in {"native", "clock"}:
                candidate[mutation] = True
            elif mutation == "request-extra":
                candidate["request"]["extra"] = True
            elif mutation in {"tenant", "tool"}:
                candidate["request"][f"{mutation}_id"] = "changed"
            else:
                candidate["contentHex"] = {
                    "hex-upper": "FF",
                    "hex-space": "ff ff",
                    "hex-odd": "f",
                    "oversized": "0" * module.MAX_REQUEST,
                }[mutation]
            assert wire(canonical(candidate) + b"\n") == {"ok": False, "error": message}
            assert not list(case["workspace"].iterdir())
