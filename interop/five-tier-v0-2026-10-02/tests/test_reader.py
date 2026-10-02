"""Native log mutation controls using an actual fresh Inspect tool execution."""
from __future__ import annotations

import copy

import pytest
from native import execute
from protocol import encode, manifest
from reader import decode, derive, read


@pytest.fixture(scope="module")
def native_packet(tmp_path_factory):
    declared = manifest()
    case = next(case for case in declared["attempts"] if case["id"] == "tool-file-2")
    directory = tmp_path_factory.mktemp("native")
    native = execute(case, declared, directory).read_bytes()
    artifacts = {"native.json": native, "tool-events.jsonl": (directory / "tool-events.jsonl").read_bytes(), "readback.json": (directory / "readback.json").read_bytes(), "launch.json": encode({"status": "returned", "elapsed_ns": 100})}
    return declared, case, artifacts


class TestNativeReader:
    class TestPassingCases:
        def test_actual_native_tool_values_and_original_readback(self, native_packet):
            declared, case, artifacts = native_packet
            result = derive(case, declared, artifacts)
            assert result["status"] == "complete"
            assert result["task_outcome"] == "pass"
            assert result["authority"] == "not-exercised"
            assert result["effect"] == "local-state-matches-declaration"
            assert result["resources"]["input_tokens"] is None

        @pytest.mark.parametrize("launch,status", [(False, "not-started"), (True, "start-unknown")])
        def test_absent_native_execution_does_not_become_success(self, launch, status):
            declared = manifest()
            case = {**declared["attempts"][0], "launch": launch}
            record = derive(case, declared, {"launch.json": encode({"status": "error" if launch else "not-started", "elapsed_ns": 0 if launch else None})})
            assert record["status"] == status
            assert record["task_outcome"] == "unknown"
            assert record["resources"]["elapsed_ns"] is None

    class TestFailingCases:
        @pytest.mark.parametrize("mutation,reason", [("score", "native_score_recomputed"), ("population", "native_sample_population"), ("arguments", "native_tool_arguments"), ("result", "native_tool_result"), ("binding", "native_declaration_binding"), ("readback", "local_readback_recomputed"), ("missing-tool", "native_tool_population")])
        def test_changed_native_join_refused_with_exact_reason(self, mutation, reason, native_packet, caplog):
            declared, case, original = native_packet
            artifacts = copy.deepcopy(original)
            native = decode(artifacts["native.json"])
            sample = native["samples"][0]
            if mutation == "score":
                sample["scores"]["match"]["value"] = "I"
            elif mutation == "population":
                native["samples"].append(copy.deepcopy(sample))
            elif mutation == "arguments":
                next(event for event in sample["events"] if event.get("event") == "tool")["arguments"] = {"changed": True}
            elif mutation == "result":
                next(event for event in sample["events"] if event.get("event") == "tool")["result"] = "substituted"
            elif mutation == "binding":
                native["eval"]["metadata"]["declaration_sha256"] = "0" * 64
            elif mutation == "readback":
                artifacts["readback.json"] = encode({"file": "OPEN", "sqlite": "10,0"})
            else:
                artifacts["tool-events.jsonl"] = b""
            artifacts["native.json"] = encode(native)
            with pytest.raises(ValueError, match=f"^{reason}$"):
                derive(case, declared, artifacts)
            assert caplog.records[-1].getMessage() == reason

        @pytest.mark.parametrize("name", ["../outside.json", "/tmp/outside.json"])
        def test_path_escape_refused(self, name, tmp_path, caplog):
            with pytest.raises(ValueError, match="^artifact_path_escape$"):
                read(tmp_path, name)
            assert caplog.records[-1].getMessage() == "artifact_path_escape"

        def test_symlink_refused(self, tmp_path, caplog):
            (tmp_path / "target.json").write_bytes(b"{}")
            (tmp_path / "link.json").symlink_to(tmp_path / "target.json")
            with pytest.raises(ValueError, match="^artifact_path_escape$"):
                read(tmp_path, "link.json")
            assert caplog.records[-1].getMessage() == "artifact_path_escape"
