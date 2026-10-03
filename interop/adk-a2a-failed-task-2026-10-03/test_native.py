"""Native fault controls for installed, source-pinned ADK/A2A execution."""
from __future__ import annotations

import copy
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from hypothesis import given, strategies as st

from probity_adk_failure import producer as producer_module
from probity_adk_failure.contract import CASES, decode, encode, identity, population, sha
from probity_adk_failure.producer import produce
from probity_adk_failure.reader import checked_file, publish_saved, verify_case, verify_saved
from probity_adk_failure.source import qualify_sdk

VARIANT = os.environ.get("ADK_FAILURE_VARIANT", "proposed-fix")


@pytest.fixture(scope="session")
def native(tmp_path_factory):
    """Run the real server, transport, Runner and broker once per selected pin."""
    root = tmp_path_factory.mktemp("native") / "run"
    policy = produce(root, VARIANT)
    return root, policy


def case_copy(native, tmp_path, case="failed-after", streaming=True):
    """Copy one retained case and its host pins for a discriminating mutation."""
    root, policy = native
    name = identity(case, streaming)
    target = tmp_path / "case"
    shutil.copytree(root / "packet" / name, target)
    return target, copy.deepcopy(policy["cases"][name])


def reselect(root, pins, file, value):
    """Select changed original bytes so semantic checks remain exercised."""
    (root / file).write_bytes(encode(value))
    pins["artifacts"][file] = sha((root / file).read_bytes())


class TestNativeTaskEffects:
    class TestPassingCases:
        def test_producer_runs_installed_source(self):
            selected = importlib.metadata.distribution("probity-adk-failure-reference")
            expected = Path(selected.locate_file("probity_adk_failure/producer.py"))
            assert Path(producer_module.__file__).resolve() == expected.resolve()

        @pytest.mark.parametrize("case,streaming", population())
        def test_each_native_case_preserves_effect_and_remote_state(self, native, case, streaming):
            root, policy = native
            name = identity(case, streaming)
            result = verify_case(root / "packet" / name, case, streaming, VARIANT, policy["cases"][name])
            assert result["committedEffects"] == CASES[case].effects
            assert result["remoteTaskState"] == ("COMPLETED" if case == "permit" else "FAILED")
            assert result["callerTaskState"] == CASES[case].state
            assert result["callerComplete"] == CASES[case].complete
            assert result["publicationDecision"] == ("RELEASE" if case == "permit" else "WITHHOLD")
            assert result["witnessScope"] == "PEER"

        def test_population_has_matching_controls_and_zero_model_inference(self, native):
            root, policy = native
            report = verify_saved(root / "packet", policy)
            assert report["remoteTasks"] == 11
            assert report["committedEffects"] == 9
            assert report["modelInferenceCalls"] == 0
            assert report["independentCustody"] is False
            assert sum(row["publicationDecision"] == "RELEASE" for row in report["records"]) == 2
            assert sum(row["nativeErrorCode"] == "A2A_TASK_FAILED" for row in report["records"]) == (8 if VARIANT == "proposed-fix" else 0)

        def test_working_done_content_is_not_terminal_success(self, native):
            root, policy = native
            name = "status-after-content-streamed"
            observed = json.loads((root / "packet" / name / "native.json").read_bytes())
            assert observed["events"][-2]["text"] == "done"
            assert observed["events"][-2]["isFinalResponse"] is True
            assert observed["events"][-2]["state"] == "TASK_STATE_WORKING"
            result = verify_case(root / "packet" / name, "status-after-content", True, VARIANT, policy["cases"][name])
            assert result["committedEffects"] == 1
            assert result["remoteTaskState"] == "FAILED"
            assert result["publicationDecision"] == "WITHHOLD"

        def test_permit_publication_only(self, native, tmp_path):
            root, policy = native
            report = publish_saved(root / "packet", policy, tmp_path / "publication")
            assert [row["case"] for row in report["records"]] == ["permit-streamed", "permit-nonstreamed"]
            assert json.loads((tmp_path / "publication/published.json").read_bytes()) == report

        def test_installed_reader_has_no_native_frameworks(self, native):
            reader = os.environ["ADK_FAILURE_READER_PYTHON"]
            probe = subprocess.run([reader, "-I", "-B", "-c",
                "import importlib.metadata as m; packages={d.metadata['Name'].lower() for d in m.distributions()}; assert 'google-adk' not in packages and 'a2a-sdk' not in packages"], capture_output=True, text=True, check=False)
            assert probe.returncode == 0, probe.stderr
            root, policy = native
            arguments = [reader, "-I", "-B", "-m", "probity_adk_failure.reader", str(root / "packet"),
                         "--host-policy", str(root / "host-policy.json"), "--policy-sha256", sha(encode(policy))]
            first = subprocess.run(arguments, capture_output=True, text=True, check=False)
            second = subprocess.run(arguments, capture_output=True, text=True, check=False)
            assert first.returncode == second.returncode == 0, first.stderr + second.stderr
            assert first.stdout == second.stdout
            assert json.loads(first.stdout)["committedEffects"] == 9

    class TestFailingCases:
        @pytest.mark.parametrize("field,value,reason", [
            ("callerComplete", False, "caller closure differs"),
            ("streaming", False, "native identity differs"),
            ("case", "permit", "native identity differs"),
            ("variant", "baseline" if VARIANT == "proposed-fix" else "proposed-fix", "native identity differs"),
            ("sdkVersion", "0.0.0", "native identity differs"),
        ])
        def test_reselected_native_identity_or_closure(self, native, tmp_path, caplog, field, value, reason):
            root, pins = case_copy(native, tmp_path)
            record = json.loads((root / "native.json").read_bytes())
            record[field] = value
            reselect(root, pins, "native.json", record)
            with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"), caplog.at_level("WARNING"):
                verify_case(root, "failed-after", True, VARIANT, pins)
            assert reason in caplog.messages

        @pytest.mark.parametrize("field,value,reason", [
            ("state", "TASK_STATE_COMPLETED", "native state, content or error differs"),
            ("text", "done", "native state, content or error differs"),
            ("isFinalResponse", False, "native final-response flag differs"),
        ])
        def test_final_event_relabel(self, native, tmp_path, caplog, field, value, reason):
            root, pins = case_copy(native, tmp_path)
            record = json.loads((root / "native.json").read_bytes())
            record["events"][-1][field] = value
            reselect(root, pins, "native.json", record)
            with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"), caplog.at_level("WARNING"):
                verify_case(root, "failed-after", True, VARIANT, pins)
            assert reason in caplog.messages

        @pytest.mark.parametrize("mutation,reason", [
            ("drop-event", "native event population differs"),
            ("drop-session", "native session population differs"),
            ("repeat-event", "native event identity repeated"),
            ("hide-effect", "native server boundary order differs"),
            ("effect-after-failure", "native server boundary order differs"),
            ("clear-error", "native state, content or error differs"),
            ("different-task", "native task binding differs"),
        ])
        def test_reselected_omissions_and_boundary_changes(self, native, tmp_path, caplog, mutation, reason):
            root, pins = case_copy(native, tmp_path)
            record = json.loads((root / "native.json").read_bytes())
            if mutation == "drop-event":
                record["events"].pop()
            elif mutation == "drop-session":
                record["sessionEvents"].pop()
            elif mutation == "repeat-event":
                record["events"][-1]["event"]["id"] = record["events"][0]["event"]["id"]
            elif mutation == "hide-effect":
                record["serverTrace"].pop(1)
            elif mutation == "effect-after-failure":
                record["serverTrace"][1:] = record["serverTrace"][1:][::-1]
            elif mutation == "clear-error":
                record["events"][-1]["event"]["error_code"] = None if VARIANT == "proposed-fix" else "A2A_TASK_FAILED"
            else:
                record["events"][-1]["event"]["custom_metadata"]["a2a:task_id"] = "different-task"
            reselect(root, pins, "native.json", record)
            with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"), caplog.at_level("WARNING"):
                verify_case(root, "failed-after", True, VARIANT, pins)
            assert reason in caplog.messages

        @pytest.mark.parametrize("mutation,reason", [
            ("drop-terminal", "native wire task states differ"),
            ("unclosed-wire", "native wire response did not close"),
            ("terminal-success", "native wire task states differ"),
            ("no-final-flag", "native wire terminal flag differs"),
            ("wrong-terminal-text", "native wire status message differs"),
            ("different-rpc", "native wire RPC identity differs"),
            ("early-closure", "native wire response closure order differs"),
            ("unknown-route", "native wire route differs"),
        ])
        def test_reselected_native_wire(self, native, tmp_path, caplog, mutation, reason):
            root, pins = case_copy(native, tmp_path)
            wire = json.loads((root / "wire.json").read_bytes())
            index = next(i for i, row in enumerate(wire) if '"state":"failed"' in row["body"])
            if mutation == "drop-terminal":
                wire.pop(index)
            elif mutation == "unclosed-wire":
                wire.pop()
            elif mutation == "early-closure":
                wire[index - 1]["moreBody"] = False
            elif mutation == "unknown-route":
                wire[index]["path"] = "/other"
            else:
                payload = json.loads(wire[index]["body"].removeprefix("data: ").strip())
                if mutation == "terminal-success":
                    payload["result"]["status"]["state"] = "completed"
                elif mutation == "no-final-flag":
                    payload["result"]["final"] = False
                elif mutation == "wrong-terminal-text":
                    payload["result"]["status"]["message"]["parts"][0]["text"] = "done"
                else:
                    payload["id"] = "different-rpc"
                wire[index]["body"] = "data: " + encode(payload).decode() + "\r\n\r\n"
            reselect(root, pins, "wire.json", wire)
            with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"), caplog.at_level("WARNING"):
                verify_case(root, "failed-after", True, VARIANT, pins)
            assert reason in caplog.messages

        @pytest.mark.parametrize("file", ["packet.json", "history.jsonl", "native.json", "wire.json"])
        def test_original_byte_pin(self, native, tmp_path, caplog, file):
            root, pins = case_copy(native, tmp_path)
            with (root / file).open("ab") as stream:
                stream.write(b" ")
            reason = "artifact digest differs from host selection"
            with pytest.raises(ValueError, match="^" + reason + "$"), caplog.at_level("WARNING"):
                verify_case(root, "failed-after", True, VARIANT, pins)
            assert reason in caplog.messages

        def test_changed_current_target_keeps_signed_bytes_unaccepted(self, native, tmp_path, caplog):
            root, pins = case_copy(native, tmp_path)
            (root / "work/result.txt").write_text("different effect")
            reason = "signed effect verification refused"
            with pytest.raises(ValueError, match="^" + reason + "$"), caplog.at_level("WARNING"):
                verify_case(root, "failed-after", True, VARIANT, pins)
            assert reason in caplog.messages

        def test_wrong_observer_key(self, native, tmp_path, caplog):
            root, pins = case_copy(native, tmp_path)
            pins["observerKey"] = "00" * 32
            reason = "signed effect verification refused"
            with pytest.raises(ValueError, match="^" + reason + "$"), caplog.at_level("WARNING"):
                verify_case(root, "failed-after", True, VARIANT, pins)
            assert reason in caplog.messages

        def test_no_partial_publication_on_refusal(self, native, tmp_path, caplog):
            root, policy = native
            selected = copy.deepcopy(policy)
            selected["cases"].pop("failed-after-streamed")
            reason = "planned population differs"
            with pytest.raises(ValueError, match="^" + reason + "$"), caplog.at_level("WARNING"):
                publish_saved(root / "packet", selected, tmp_path / "publication")
            assert reason in caplog.messages
            assert not (tmp_path / "publication").exists()

        def test_unlisted_retained_source(self, native, tmp_path, caplog):
            root, policy = native
            target = tmp_path / "packet"
            shutil.copytree(root / "packet", target)
            (target / "source/extra.py").write_text("different source\n")
            reason = "retained source population differs"
            with pytest.raises(ValueError, match="^" + reason + "$"), caplog.at_level("WARNING"):
                verify_saved(target, policy)
            assert reason in caplog.messages


class TestSelectedSourceAndJson:
    class TestPassingCases:
        def test_all_native_importable_source_is_selected(self):
            assert len(qualify_sdk(VARIANT)) == 905

        @given(st.dictionaries(st.text(max_size=30), st.integers(), max_size=10))
        def test_finite_unsigned_json_roundtrip(self, value):
            assert decode(encode(value)) == value

    class TestFailingCases:
        @pytest.mark.parametrize("raw,reason", [
            ('{"a":1,"a":2}', "duplicate JSON member"),
            ('{"x":NaN}', "non-finite JSON number"),
            ('{"x":Infinity}', "non-finite JSON number"),
            ('{"x":1e999}', "non-finite JSON number"),
        ])
        def test_ambiguous_unsigned_json(self, raw, reason, caplog):
            with pytest.raises(ValueError, match="^" + reason + "$"), caplog.at_level("WARNING"):
                decode(raw)
            assert reason in caplog.messages

        @pytest.mark.parametrize("path", ["../escape", "/absolute", "x/../../escape", "x//y", "./x"])
        def test_escaping_artifact_path(self, tmp_path, path, caplog):
            reason = "artifact path differs"
            with pytest.raises(ValueError, match="^" + reason + "$"), caplog.at_level("WARNING"):
                checked_file(tmp_path, path, "00" * 32)
            assert reason in caplog.messages

        def test_symlink_artifact(self, tmp_path, caplog):
            (tmp_path / "actual").write_bytes(b"selected")
            (tmp_path / "link").symlink_to(tmp_path / "actual")
            reason = "artifact must be a regular file"
            with pytest.raises(ValueError, match="^" + reason + "$"), caplog.at_level("WARNING"):
                checked_file(tmp_path, "link", sha(b"selected"))
            assert reason in caplog.messages

        def test_unknown_sdk_variant(self, caplog):
            reason = "unknown SDK variant"
            with pytest.raises(ValueError, match="^" + reason + "$"), caplog.at_level("WARNING"):
                qualify_sdk("unselected-head")
            assert reason in caplog.messages
