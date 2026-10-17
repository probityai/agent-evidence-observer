"""Claims from plain-text and Claude Code stream-json transcripts."""

import json

from probity_observer.done import claims

VISIBLE = ["python", "test.py"]


def test_a_shell_line_and_a_passing_summary():
    found = claims.from_text("$ python -m pytest -q\n3 passed in 0.1s\n", VISIBLE)
    assert found == [{"id": "c1", "argv": ["python", "-m", "pytest", "-q"], "exit": 0}]


def test_a_summary_with_no_command_claims_the_visible_acceptance_run():
    assert claims.from_text("working...\n12 passed\n", VISIBLE) == [
        {"id": "c1", "argv": VISIBLE, "exit": 0}]
    assert claims.from_text("12 passed\n", None) == []


def test_a_failing_summary_claims_no_exit():
    found = claims.from_text("$ pytest\n1 failed, 2 passed\n", VISIBLE)
    assert found == [{"id": "c1", "argv": ["pytest"]}]


def test_shell_syntax_is_kept_whole():
    assert claims.command_argv("pytest -q && echo ok") == ["sh", "-c", "pytest -q && echo ok"]
    assert claims.command_argv("echo 'unterminated") == ["sh", "-c", "echo 'unterminated"]


def test_claude_stream_bash_calls_and_their_results():
    lines = [
        {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "python test.py"}},
            {"type": "tool_use", "id": "t2", "name": "Read", "input": {"file_path": "x"}}]}},
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1", "is_error": False, "content": "ok"}]}},
        {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "t3", "name": "Bash", "input": {"command": "pytest | tail"}}]}},
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t3", "is_error": True}]}},
        {"type": "result", "message": None},
    ]
    text = "\n".join(json.dumps(line) for line in lines) + "\nnot json\n"
    assert claims.from_claude_stream(text) == [
        {"id": "c1", "argv": ["python", "test.py"], "exit": 0},
        {"id": "c2", "argv": ["sh", "-c", "pytest | tail"], "exit": 1}]


def test_record_shape():
    record = claims.record([], "c", "i")
    assert record == {"schema_version": claims.SCHEMA, "claim_id": "c", "invocation_id": "i",
                      "producer": "transcript-parser", "claims": []}
