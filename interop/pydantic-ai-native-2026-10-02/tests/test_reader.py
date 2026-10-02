"""Consumer controls covering external pins and deep native/effect relations."""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from probity_observer.crypto import VerificationError

from probity_pydantic.contract import CONTENT, ERROR, decode, encode, sha
from probity_pydantic.reader import native_parts, verify_saved


def copy_packet(original: Path, destination: Path) -> tuple[Path, dict[str, Any]]:
    """Copy retained bytes for one mutation without changing the source fixture."""
    output = destination / "packet"
    if output.exists():
        shutil.rmtree(output)
    shutil.copytree(original, output)
    return output, decode((output / "consumer-pins.json").read_bytes())


def replace_artifact(
    output: Path, selected: dict[str, Any], name: str, value: Any
) -> None:
    """Select a tampered artifact afresh to exercise semantic checks after pins.

    This adversarial test deliberately changes the consumer-selected manifest
    hash. It does not demonstrate bypassing a fixed real consumer policy pin.
    """
    raw = (
        json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()
        if name.endswith("-messages.json")
        else encode(value)
    )
    (output / "artifacts" / name).write_bytes(raw)
    manifest = decode((output / "artifact-manifest.json").read_bytes())
    manifest[name] = sha(raw)
    raw_manifest = encode(manifest)
    (output / "artifact-manifest.json").write_bytes(raw_manifest)
    selected["artifactManifestSha256"] = sha(raw_manifest)


def refuse(
    output: Path,
    selected: dict[str, Any],
    reason: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Require exact public exception and logged reason without candidate data."""
    caplog.clear()
    with (
        caplog.at_level(logging.WARNING),
        pytest.raises(VerificationError, match="^" + re.escape(reason) + "$"),
    ):
        verify_saved(output, selected)
    assert "pydantic consumer refused: " + reason in caplog.text


class TestSavedReader:
    """Validate passing records and each independent fail-closed relation."""

    class TestPassingCases:
        """Actual installed framework and native HTTP execution controls."""

        def test_complete_finite_population(self, original_packet: Path) -> None:
            selected = decode((original_packet / "consumer-pins.json").read_bytes())
            report = verify_saved(original_packet, selected)
            assert report["status"] == "verified"
            assert report["plannedAttempts"] == 5
            assert [record["nativeRevision"] for record in report["records"]] == [
                1,
                0,
                0,
                1,
                0,
            ]
            assert [record["executionStatus"] for record in report["records"]] == [
                "complete",
                "complete",
                "complete",
                "complete",
                "error",
            ]
            assert report["records"][3]["retries"] == 1
            assert all(
                record["taskQuality"] == "not-evaluated" for record in report["records"]
            )

        def test_offline_reader_never_imports_framework(
            self, original_packet: Path, tmp_path: Path
        ) -> None:
            selected_file = tmp_path / "consumer-policy.json"
            selected_file.write_bytes(
                (original_packet / "consumer-pins.json").read_bytes()
            )
            code = (
                "import sys; from pathlib import Path; "
                "from probity_pydantic.reader import native_parts, verify_saved; "
                "from probity_pydantic.contract import decode; "
                "r=verify_saved(Path(sys.argv[1]),"
                "decode(Path(sys.argv[2]).read_bytes())); "
                "assert r['status']=='verified'; "
                "assert 'pydantic_ai' not in sys.modules"
            )
            result = subprocess.run(
                [sys.executable, "-c", code, str(original_packet), str(selected_file)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            assert result.returncode == 0, result.stderr

        def test_original_native_serializer_bytes_are_retained(
            self, original_packet: Path
        ) -> None:
            raw = (original_packet / "artifacts" / "permit-messages.json").read_bytes()
            native = json.loads(raw)
            assert native[1]["parts"][0]["tool_name"] == "dispatch_ticket"
            assert raw != encode(native)
            assert native[2]["parts"][0]["outcome"] == "success"

        def test_exact_upper_native_timestamp_boundary_is_accepted(
            self,
            original_packet: Path,
        ) -> None:
            plan = decode((original_packet / "plan-before-run.json").read_bytes())
            messages = json.loads(
                (original_packet / "artifacts" / "permit-messages.json").read_bytes()
            )
            reference = max(
                datetime.fromisoformat(message["timestamp"]) for message in messages
            )
            parts = native_parts(json.dumps(messages).encode(), plan, reference)
            assert parts[-1]["part_kind"] == "text"

    class TestFailingCases:
        """Altered packet controls refusing both hash and relational corruption."""

        @pytest.mark.parametrize(
            "field", ["planSha256", "sourceManifestSha256", "artifactManifestSha256"]
        )
        def test_external_pin_mismatch(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
            field: str,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path)
            selected[field] = "0" * 64
            refuse(output, selected, "external pin differs: " + field, caplog)

        def test_changed_native_call_arguments(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path)
            name = "permit-messages.json"
            messages = json.loads((output / "artifacts" / name).read_bytes())
            messages[1]["parts"][0]["args"]["content"] = "CHANGED"
            replace_artifact(output, selected, name, messages)
            refuse(output, selected, "native tool call differs", caplog)

        def test_omitted_native_retry(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path)
            name = "retry-messages.json"
            messages = json.loads((output / "artifacts" / name).read_bytes())
            messages[2]["parts"][0]["part_kind"] = "tool-return"
            replace_artifact(output, selected, name, messages)
            refuse(output, selected, "native retry differs", caplog)

        def test_deleted_retry_attempt(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path)
            name = "retry-messages.json"
            messages = json.loads((output / "artifacts" / name).read_bytes())
            messages[1:3] = []
            replace_artifact(output, selected, name, messages)
            refuse(output, selected, "native transcript population differs", caplog)

        def test_hidden_retry_trace(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path)
            name = "retry-execution.json"
            execution = decode((output / "artifacts" / name).read_bytes())
            execution["trace"].pop(0)
            replace_artifact(output, selected, name, execution)
            refuse(output, selected, "native dispatch population differs", caplog)

        def test_swapped_native_readback(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path)
            name = "permit-0-http.json"
            packet = decode((output / "artifacts" / name).read_bytes())
            other = decode((output / "artifacts" / "retry-1-http.json").read_bytes())
            packet["getResponseHex"] = other["getResponseHex"]
            replace_artifact(output, selected, name, packet)
            refuse(output, selected, "ticket key differs from consumer pin", caplog)

        def test_producer_error_cannot_be_completion(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path)
            name = "producer-error-execution.json"
            execution = decode((output / "artifacts" / name).read_bytes())
            execution["terminal"] = {
                "status": "complete",
                "output": "complete",
                "exception": None,
            }
            replace_artifact(output, selected, name, execution)
            refuse(output, selected, "producer error terminal differs", caplog)

        def test_refusal_cannot_gain_effect(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path)
            name = "deny-0-http.json"
            packet = decode((output / "artifacts" / name).read_bytes())
            packet["postStatus"] = 200
            replace_artifact(output, selected, name, packet)
            refuse(output, selected, "HTTP refusal status differs", caplog)

        def test_native_return_digest_cannot_be_swapped(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path)
            name = "permit-messages.json"
            messages = json.loads((output / "artifacts" / name).read_bytes())
            messages[2]["parts"][0]["content"] = "{}"
            replace_artifact(output, selected, name, messages)
            refuse(output, selected, "native HTTP return join differs", caplog)

        def test_duplicate_native_json_names(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path)
            name = "permit-messages.json"
            raw = (
                (output / "artifacts" / name)
                .read_bytes()
                .replace(b'"args":', b'"args":{},"args":', 1)
            )
            path = output / "artifacts" / name
            path.write_bytes(raw)
            manifest = decode((output / "artifact-manifest.json").read_bytes())
            manifest[name] = sha(raw)
            manifest_raw = encode(manifest)
            (output / "artifact-manifest.json").write_bytes(manifest_raw)
            selected["artifactManifestSha256"] = sha(manifest_raw)
            refuse(output, selected, "duplicate native JSON name", caplog)

        def test_extra_artifact_is_refused(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path)
            (output / "artifacts" / "hidden-http.json").write_bytes(b"{}")
            refuse(output, selected, "artifact population differs", caplog)

        def test_linked_packet_is_refused(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            selected = decode((original_packet / "consumer-pins.json").read_bytes())
            linked = tmp_path / "linked"
            linked.symlink_to(original_packet, target_is_directory=True)
            refuse(linked, selected, "packet root missing or linked", caplog)

        def test_missing_external_pins_is_cli_error(
            self, original_packet: Path
        ) -> None:
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from probity_pydantic.reader import main;main()",
                    str(original_packet),
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            assert result.returncode == 2
            assert "--pins-file" in result.stderr

        @pytest.mark.parametrize(
            ("field", "value", "reason"),
            [
                ("tool_call_id", "substituted-call", "native tool call differs"),
                ("tool_name", "unselected_tool", "native tool call differs"),
                (
                    "args",
                    {"content": "DONE", "extra": "unselected"},
                    "native tool call differs",
                ),
            ],
        )
        def test_native_call_identity_and_argument_population(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
            field: str,
            value: Any,
            reason: str,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path)
            name = "permit-messages.json"
            messages = json.loads((output / "artifacts" / name).read_bytes())
            messages[1]["parts"][0][field] = value
            replace_artifact(output, selected, name, messages)
            refuse(output, selected, reason, caplog)

        def test_native_run_cannot_change_mid_history(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path)
            name = "permit-messages.json"
            messages = json.loads((output / "artifacts" / name).read_bytes())
            messages[2]["run_id"] = "changed-native-run"
            replace_artifact(output, selected, name, messages)
            refuse(output, selected, "native run identity differs", caplog)

        def test_bool_http_status_is_not_integer_status(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path)
            name = "permit-0-http.json"
            packet = decode((output / "artifacts" / name).read_bytes())
            packet["getStatus"] = True
            replace_artifact(output, selected, name, packet)
            refuse(output, selected, "HTTP read status differs", caplog)

        def test_changed_retained_source_bytes(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path)
            source = output / "sources" / "pydantic_ai" / "models" / "function.py"
            source.write_bytes(
                source.read_bytes() + b"\n# unselected source mutation\n"
            )
            refuse(output, selected, "source bytes differ", caplog)

        def test_linked_original_artifact_is_refused(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path)
            artifact = output / "artifacts" / "permit-messages.json"
            artifact.unlink()
            artifact.symlink_to(original_packet / "artifacts" / artifact.name)
            refuse(output, selected, "packet contains symlink", caplog)

        @pytest.mark.parametrize("identity", [True, 1, "", "not-a-native-uuid"])
        def test_native_run_id_requires_canonical_uuid_string(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
            identity: Any,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path)
            name = "permit-messages.json"
            messages = json.loads((output / "artifacts" / name).read_bytes())
            for message in messages:
                message["run_id"] = identity
            replace_artifact(output, selected, name, messages)
            refuse(output, selected, "native run identity differs", caplog)

        @pytest.mark.parametrize("target", ["message", "part"])
        @pytest.mark.parametrize("malformed", ["future", "naive"])
        def test_native_timestamps_are_aware_and_before_consumer_reference(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
            target: str,
            malformed: str,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path)
            name = "permit-messages.json"
            messages = json.loads((output / "artifacts" / name).read_bytes())
            node = messages[0] if target == "message" else messages[0]["parts"][0]
            current = datetime.fromisoformat(node["timestamp"])
            changed = (
                current + timedelta(days=365)
                if malformed == "future"
                else current.replace(tzinfo=None)
            )
            node["timestamp"] = changed.isoformat()
            replace_artifact(output, selected, name, messages)
            reason = (
                "native chronology differs"
                if target == "message"
                else "native part chronology differs"
            )
            refuse(output, selected, reason, caplog)

        def test_cross_case_error_branch_cannot_skip_native_effect_verifier(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path)
            name = "permit-execution.json"
            execution = decode((output / "artifacts" / name).read_bytes())
            plan = decode((output / "plan-before-run.json").read_bytes())
            execution["trace"] = [
                {
                    "id": "producer-error-0",
                    "arguments": {"content": CONTENT},
                    "outcome": "error",
                    "reason": ERROR,
                }
            ]
            execution["finalReadbackHex"] = encode(plan["cases"][0]["initial"]).hex()
            replace_artifact(output, selected, name, execution)
            refuse(output, selected, "frozen dispatch outcome differs", caplog)

        @settings(
            max_examples=20, suppress_health_check=[HealthCheck.function_scoped_fixture]
        )
        @given(
            changed=st.text(min_size=1, max_size=40).filter(
                lambda value: value != "DONE"
            )
        )
        def test_arbitrary_native_argument_changes(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
            changed: str,
        ) -> None:
            destination = tmp_path / sha(
                changed.encode("utf-8", errors="surrogatepass")
            )
            output, selected = copy_packet(original_packet, destination)
            name = "permit-messages.json"
            messages = json.loads((output / "artifacts" / name).read_bytes())
            messages[1]["parts"][0]["args"]["content"] = changed
            replace_artifact(output, selected, name, messages)
            refuse(output, selected, "native tool call differs", caplog)

        @settings(
            max_examples=20, suppress_health_check=[HealthCheck.function_scoped_fixture]
        )
        @given(
            changed=st.binary(min_size=1, max_size=40).filter(
                lambda value: value != b"DONE"
            )
        )
        def test_actual_http_argument_bytes_are_bound(
            self,
            original_packet: Path,
            tmp_path: Path,
            caplog: pytest.LogCaptureFixture,
            changed: bytes,
        ) -> None:
            output, selected = copy_packet(original_packet, tmp_path / sha(changed))
            name = "permit-0-http.json"
            packet = decode((output / "artifacts" / name).read_bytes())
            candidate = decode(bytes.fromhex(packet["postRequestHex"]))
            candidate["contentHex"] = changed.hex()
            packet["postRequestHex"] = encode(candidate).hex()
            replace_artifact(output, selected, name, packet)
            refuse(output, selected, "native argument to HTTP binding differs", caplog)
