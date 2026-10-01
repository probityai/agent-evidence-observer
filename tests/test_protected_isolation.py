"""Launch policy, truthful failure retention, and protected gate consistency."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from probity_observer import protected_isolation as module
from probity_observer.authorization import ActionRequest, GrantPolicy
from probity_observer.crypto import (
    VerificationError,
    canonical,
    strict_loads,
)
from probity_observer.protected_dispatch import ProtectedDispatcher
from probity_observer.protected_isolation import (
    protected_launch_command,
    run_protected_isolation,
    verify_protected_isolation_bundle,
)


class TestProtectedLaunchCommand:
    class TestPassingCases:
        def test_child_mounts_public_inputs_and_socket_only(
            self, tmp_path: Path
        ) -> None:
            args = protected_launch_command(
                Path("/usr/bin/bwrap"),
                tmp_path / "socket",
                Path("/usr/bin/python3"),
                12345,
                tmp_path / "probe.py",
                tmp_path / "invocation.json",
            )
            assert "--unshare-all" in args
            assert "--cap-drop" in args
            assert args[args.index("--cap-drop") + 1] == "ALL"
            assert "/agent/invocation.json" in args
            assert str(tmp_path / "socket") in args
            assert "/work" not in args
            assert all(
                "producer" not in argument and "private" not in argument
                for argument in args
            )

    class TestFailingCases:
        @pytest.mark.parametrize(
            "raw,exit_code",
            [(b"{}\n", -1), (b"not-json\n", 0), (b"[]\n", 0), (b"{ }\n", 0)],
        )
        def test_child_output_cannot_invent_results(
            self, raw: bytes, exit_code: int
        ) -> None:
            assert module._attempts(raw, exit_code) is None


class TestProtectedIsolation:
    class TestPassingCases:
        def test_host_component_sequence_is_complete_without_claiming_isolation(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
        ) -> None:
            """Exercise host persistence/admission; a stub is not an isolation pass."""
            output = tmp_path / "unit-run"

            def host_fixture(
                command: list[str], socket_path: Path, dispatcher: ProtectedDispatcher
            ) -> tuple[int, bytes, bytes]:
                inputs = strict_loads(
                    (socket_path.parent.parent / "invocation.json").read_bytes()
                )["invocation"]
                request = ActionRequest(**inputs["request"])
                dispatcher.write(
                    request, inputs["grant"], bytes.fromhex(inputs["contentHex"])
                )
                return (
                    0,
                    canonical({name: True for name in module.EXPECTED}) + b"\n",
                    b"",
                )

            monkeypatch.setattr(module, "_child", host_fixture)
            report = run_protected_isolation(output)
            assert report["status"] == "probe-passed"
            assert report["restartReplayed"] is True
            assert report["consumerStatus"] == "admitted"
            assert report["witnessScope"] == "PEER"
            keys = strict_loads((output / "trusted-keys.json").read_bytes())
            request = ActionRequest(
                **strict_loads((output / "invocation.json").read_bytes())["invocation"][
                    "request"
                ]
            )
            verified = verify_protected_isolation_bundle(
                output,
                request,
                GrantPolicy(keys["issuer"]),
                keys["observer"],
                keys["witness"],
                report["authorizationHead"],
                expected_launch_digest=report["launchDigest"],
            )
            assert verified == report

    class TestFailingCases:
        def test_partial_state_failure_still_retains_signed_incomplete_result(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
        ) -> None:
            monkeypatch.setattr(
                module, "_child", lambda *args: (-1, b"", b"injected child failure")
            )

            def partial_head(*args: Any) -> dict[str, Any]:
                raise VerificationError("checkpoint does not bind the supplied history")

            monkeypatch.setattr(ProtectedDispatcher, "retained_head", partial_head)
            output = tmp_path / "partial"
            report = run_protected_isolation(output)
            assert report["status"] == "incomplete"
            assert report["reason"] == "protected retained state is incomplete"
            assert (
                report["retainedStateError"]
                == "checkpoint does not bind the supplied history"
            )
            assert (output / "protected-isolation-attestation.json").is_file()
            assert (output / "manifest.json").is_file()
            assert not list((output / "workspace").iterdir())

        def test_permission_failure_retains_incomplete_not_success(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
        ) -> None:
            monkeypatch.setattr(
                module, "_child", lambda *args: (-1, b"", b"Operation not permitted")
            )
            output = tmp_path / "blocked"
            report = run_protected_isolation(output)
            assert report["status"] == "incomplete"
            assert report["exitCode"] == -1
            assert report["restartReplayed"] is False
            assert report["consumerStatus"] == "not-admitted"
            assert (
                output / "probe-stderr.bin"
            ).read_bytes() == b"Operation not permitted"
            assert not list((output / "workspace").iterdir())
            assert not (output / "producer" / "packet.json").exists()
            assert (output / "protected-isolation-attestation.json").is_file()

        @pytest.mark.parametrize(
            "results",
            [
                {},
                {"lostResponseReplay": True},
                {name: False for name in module.EXPECTED},
                {**{name: True for name in module.EXPECTED}, "extra": True},
            ],
        )
        def test_missing_false_or_extra_child_checks_refuse_success(
            self,
            tmp_path: Path,
            monkeypatch: pytest.MonkeyPatch,
            results: dict[str, Any],
        ) -> None:
            monkeypatch.setattr(
                module, "_child", lambda *args: (0, canonical(results) + b"\n", b"")
            )
            report = run_protected_isolation(tmp_path / "failed")
            assert report["status"] == "incomplete"
            assert report["reason"] == "protected boundary probes failed"
            assert report["consumerStatus"] == "not-admitted"

        def test_all_true_child_report_cannot_replace_host_effect(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
        ) -> None:
            monkeypatch.setattr(
                module,
                "_child",
                lambda *args: (
                    0,
                    canonical({name: True for name in module.EXPECTED}) + b"\n",
                    b"",
                ),
            )
            report = run_protected_isolation(tmp_path / "false-positive")
            assert report["status"] == "incomplete"
            assert report["reason"] == "protected target bytes differ"

        def test_nonempty_output_is_not_overwritten(self, tmp_path: Path) -> None:
            (tmp_path / "keep.txt").write_bytes(b"preserve")
            with pytest.raises(
                ValueError, match="^protected isolation output directory must be empty$"
            ):
                run_protected_isolation(tmp_path)
            assert (tmp_path / "keep.txt").read_bytes() == b"preserve"

        @pytest.mark.parametrize(
            "field,value",
            [
                ("exitCode", -1),
                ("restartReplayed", False),
                ("consumerStatus", "not-admitted"),
            ],
        )
        def test_success_requires_every_host_gate(
            self, tmp_path: Path, field: str, value: Any
        ) -> None:
            report = {
                "status": "probe-passed",
                "exitCode": 0,
                "restartReplayed": True,
                "consumerStatus": "admitted",
                "attempts": {name: True for name in module.EXPECTED},
            }
            report[field] = value
            with pytest.raises(
                VerificationError,
                match="^protected isolation success omits a required gate$",
            ):
                module._verify_probe_result(tmp_path, report)
