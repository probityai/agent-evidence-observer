"""Controls against an actual, caller-selected native host run."""

from __future__ import annotations

import hashlib
import json
import os
import re
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from probity_control_arena_reader import (
    DOES_NOT_ASSERT,
    Policy,
    ReaderRefusal,
    parse,
    read_log,
)


@pytest.fixture(scope="session")
def native_bytes() -> bytes:
    path = os.environ.get("CONTROL_ARENA_LOG")
    if not path:
        raise RuntimeError("CONTROL_ARENA_LOG must select an actual native host export")
    return Path(path).read_bytes()


@pytest.fixture(scope="session")
def selected_policy() -> Policy:
    path = os.environ.get("CONTROL_ARENA_POLICY")
    if not path:
        raise RuntimeError(
            "CONTROL_ARENA_POLICY must select an outside consumer policy"
        )
    return Policy.from_bytes(Path(path).read_bytes())


def modified_native(raw: bytes, mutation: str) -> bytes:
    data = json.loads(raw)
    first = data["samples"][0]
    events = first["events"]
    models = [event for event in events if event["event"] == "model"]
    tools = [event for event in events if event["event"] == "tool"]
    solver_begin = next(
        event
        for event in events
        if event["event"] == "span_begin" and event.get("type") == "solver"
    )
    solver_end = next(
        event
        for event in events
        if event["event"] == "span_end" and event["id"] == solver_begin["id"]
    )
    operations: dict[str, Any] = {
        "reversed_model_time": lambda: models[0].update(completed=first["started_at"]),
        "reversed_tool_time": lambda: tools[0].update(completed=first["started_at"]),
        "tool_before_model": lambda: tools[0].update(timestamp=models[0]["timestamp"]),
        "model_before_tool_completion": lambda: models[1].update(
            timestamp=tools[0]["timestamp"]
        ),
        "action_interleaving": lambda: events.insert(
            events.index(models[0]), events.pop(events.index(models[1]))
        ),
        "event_outside_span": lambda: models[0].update(timestamp=first["started_at"]),
        "sample_outside_eval": lambda: first.update(
            completed_at=(
                datetime.fromisoformat(data["stats"]["completed_at"])
                + timedelta(seconds=5)
            ).isoformat()
        ),
        "span_end_fields": lambda: solver_end.update(name="another_solver"),
        "unsupported_root_span": lambda: events[0].update(name="other"),
        "unknown_span_parent": lambda: solver_begin.update(parent_id="unknown"),
        "omit_sample": lambda: data["samples"].pop(),
        "duplicate_sample": lambda: data["samples"].append(deepcopy(first)),
        "unexpected_epoch": lambda: first.update(epoch=3),
        "bool_epoch": lambda: first.update(epoch=True),
        "changed_input": lambda: first.update(input="retuned"),
        "evaluation_error": lambda: data.update(error={"message": "failed"}),
        "sample_error": lambda: first.update(error={"message": "failed"}),
        "empty_error": lambda: first.update(error={}),
        "sample_limit": lambda: first.update(limit={"type": "custom", "limit": 1}),
        "solver_error": lambda: first["metadata"].update(control_solver_error="failed"),
        "incomplete_eval": lambda: data.update(status="started"),
        "invalidated_eval": lambda: data.update(invalidated=True),
        "omit_model": lambda: events.remove(models[0]),
        "omit_tool": lambda: events.remove(tools[0]),
        "duplicate_model": lambda: events.append(deepcopy(models[0])),
        "incomplete_spans": lambda: events.pop(),
        "unknown_event": lambda: tools[0].update(event="target_commit"),
        "model_error": lambda: models[0].update(error={"message": "failed"}),
        "tool_error": lambda: tools[0].update(error={"message": "failed"}),
        "model_name": lambda: models[0].update(model="openai/other"),
        "model_message": lambda: models[0]["output"]["choices"][0]["message"].update(
            content="changed"
        ),
        "tool_result": lambda: tools[0].update(result="changed"),
        "tool_call": lambda: tools[0].update(arguments={"value": "changed"}),
        "tool_join": lambda: tools[0].update(message_id="unmatched"),
        "nested_tool_event": lambda: tools[0].update(events=[{"event": "unknown"}]),
        "message_join": lambda: first["messages"][3].update(tool_call_id="unmatched"),
        "message_result": lambda: first["messages"][3].update(content="changed"),
        "output_join": lambda: first["output"]["choices"][0]["message"].update(
            content="changed"
        ),
        "submit_store": lambda: first["store"].update(
            submit_args='{"answer":"changed"}'
        ),
        "step_count": lambda: first["store"].update({"StepCounter:count": 1}),
        "plain_inspect": lambda: data["plan"]["steps"][0].update(solver="generate"),
        "custom_scaffold": lambda: data["plan"]["steps"][0]["params"].update(
            scaffold={"type": "other"}
        ),
        "changed_source": lambda: data["eval"]["revision"].update(commit="00000000"),
        "changed_inspect": lambda: data["eval"]["packages"].update(inspect_ai="0.3.1"),
        "old_time": lambda: tools[0].update(timestamp="2000-01-01T00:00:00Z"),
        "missing_timezone": lambda: tools[0].update(timestamp="2026-10-02T21:06:00"),
        "metadata_mirror": lambda: data["metadata"].update(mode="attack"),
    }
    operations[mutation]()
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


class TestControlArenaReader:
    class TestPassingCases:
        def test_actual_native_population(
            self, native_bytes: bytes, selected_policy: Policy
        ) -> None:
            report = read_log(native_bytes, selected_policy)
            assert report["decision"] == "publish"
            assert report["witnessScope"] == "PEER"
            assert report["modelObservations"] == 8
            assert report["toolObservations"] == 8
            assert report["samples"] == [
                {"id": "alpha", "epoch": 1},
                {"id": "alpha", "epoch": 2},
                {"id": "beta", "epoch": 1},
                {"id": "beta", "epoch": 2},
            ]
            assert report["doesNotAssert"] == list(DOES_NOT_ASSERT)

        def test_framework_free_installation(self) -> None:
            import sys

            assert "control_arena" not in sys.modules
            assert "inspect_ai" not in sys.modules

    class TestFailingCases:
        @pytest.mark.parametrize(
            ("mutation", "expected"),
            [
                ("reversed_model_time", "Native event time is reversed"),
                ("reversed_tool_time", "Native event time is reversed"),
                ("tool_before_model", "Native action causal order mismatch"),
                ("model_before_tool_completion", "Native action causal order mismatch"),
                ("action_interleaving", "Native action order mismatch"),
                ("event_outside_span", "Event outside owning native span"),
                ("sample_outside_eval", "Sample outside evaluation interval"),
                ("span_end_fields", "Span begin/end fields mismatch"),
                ("unsupported_root_span", "Unsupported root span"),
                ("unknown_span_parent", "Unknown span parent"),
                ("omit_sample", "Missing selected sample identity"),
                ("duplicate_sample", "Duplicate sample identity"),
                ("unexpected_epoch", "Unexpected sample identity"),
                ("bool_epoch", "Sample epoch must be an integer"),
                ("changed_input", "Selected sample input mismatch"),
                ("evaluation_error", "Evaluation contains error"),
                ("sample_error", "Sample contains error"),
                ("empty_error", "Sample contains error"),
                ("sample_limit", "Sample contains limit"),
                ("solver_error", "Sample metadata contains control_solver_error"),
                ("incomplete_eval", "Evaluation incomplete or invalidated"),
                ("invalidated_eval", "Evaluation incomplete or invalidated"),
                ("omit_model", "Incomplete or duplicate native execution events"),
                ("omit_tool", "Incomplete or duplicate native execution events"),
                ("duplicate_model", "Duplicate native event uuid"),
                ("incomplete_spans", "Incomplete native spans"),
                ("unknown_event", "Unsupported native event"),
                ("model_error", "Native event contains error"),
                ("tool_error", "Native event contains error"),
                ("model_name", "Unexpected native model event"),
                ("model_message", "Native model/message mismatch"),
                ("tool_result", "Native tool/result mismatch"),
                ("tool_call", "Native tool/call mismatch"),
                ("tool_join", "Native tool/result mismatch"),
                ("nested_tool_event", "Unsupported nested tool events"),
                ("message_join", "Unmatched tool result"),
                ("message_result", "Tool result differs from selected literal"),
                ("output_join", "Final output/message mismatch"),
                ("submit_store", "Submission store mismatch"),
                ("step_count", "Unexpected native step count"),
                ("plain_inspect", "Unsupported ControlArena solver plan"),
                ("custom_scaffold", "Unsupported ControlArena scaffold parameters"),
                ("changed_source", "Source revision mismatch"),
                ("changed_inspect", "Inspect version mismatch"),
                ("old_time", "Event timestamp outside selected time window"),
                ("missing_timezone", "Event timestamp must include a timezone"),
                ("metadata_mirror", "Evaluation metadata mirror mismatch"),
            ],
        )
        def test_reselected_native_mutants(
            self,
            native_bytes: bytes,
            selected_policy: Policy,
            caplog: pytest.LogCaptureFixture,
            mutation: str,
            expected: str,
        ) -> None:
            mutant = modified_native(native_bytes, mutation)
            # Reselect only the digest to reach the semantic refusal. A real
            # candidate cannot authorise this change to the consumer's policy.
            policy = replace(
                selected_policy, log_sha256=hashlib.sha256(mutant).hexdigest()
            )
            with pytest.raises(ReaderRefusal, match=f"^{re.escape(expected)}$"):
                read_log(mutant, policy)
            assert f"ControlArena publication refused: {expected}" in caplog.text

        def test_original_selection_refuses_changed_bytes(
            self,
            native_bytes: bytes,
            selected_policy: Policy,
            caplog: pytest.LogCaptureFixture,
        ) -> None:
            with pytest.raises(ReaderRefusal, match="^Selected log digest mismatch$"):
                read_log(native_bytes + b" ", selected_policy)
            assert "Selected log digest mismatch" in caplog.text

        @given(st.integers(min_value=3, max_value=100000))
        @settings(max_examples=40, deadline=None)
        def test_property_epoch_outside_selected_population(self, epoch: int) -> None:
            raw = Path(os.environ["CONTROL_ARENA_LOG"]).read_bytes()
            policy = Policy.from_bytes(
                Path(os.environ["CONTROL_ARENA_POLICY"]).read_bytes()
            )
            data = json.loads(raw)
            data["samples"][0]["epoch"] = epoch
            mutant = json.dumps(data).encode()
            selected = replace(policy, log_sha256=hashlib.sha256(mutant).hexdigest())
            with pytest.raises(ReaderRefusal, match="^Unexpected sample identity$"):
                read_log(mutant, selected)

        def test_duplicate_json_keys(self, caplog: pytest.LogCaptureFixture) -> None:
            with pytest.raises(ReaderRefusal, match="^Duplicate JSON object key$"):
                parse(b'{"status":"success","status":"started"}')
            assert "Duplicate JSON object key" in caplog.text

        @pytest.mark.parametrize("raw", [b"{", b"\xff"])
        def test_malformed_json(
            self, raw: bytes, caplog: pytest.LogCaptureFixture
        ) -> None:
            expected = (
                "Invalid JSON: JSONDecodeError"
                if raw == b"{"
                else "Invalid JSON: UnicodeDecodeError"
            )
            with pytest.raises(ReaderRefusal, match=f"^{re.escape(expected)}$"):
                parse(raw)
            assert expected in caplog.text
