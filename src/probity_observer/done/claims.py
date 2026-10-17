"""Parse what an agent says it ran into a ``probity-tool-claims/v1`` record.

Claims are the agent's statements, so they come from its own output and carry no vantage.
Two transcript shapes are read:

- **plain text** (any agent run by the launcher): a line ``$ <command>`` is a claimed run of
  that command; a later test summary (``N passed``, ``All tests passed``, ``OK``) with no
  failure claims that run's exit was 0. A summary with no claimed command before it is a claim
  that the contract's first visible acceptance command ran and passed, which is how a
  fabricated ``12 passed`` becomes a checkable claim;
- **Claude Code ``stream-json``** (:func:`from_claude_stream`): each ``Bash`` tool call is a
  claimed run of its command, and its tool result's error flag gives the claimed exit.

A shell command line is split with :mod:`shlex`; a line that does not split, or that uses
shell syntax beyond one simple command, is claimed as ``["sh", "-c", <line>]``.
"""

from __future__ import annotations

import json
import re
import shlex
from typing import Any

SCHEMA = "probity-tool-claims/v1"
_PASSED = re.compile(r"(?:\b\d+ passed\b|All tests passed|^OK\b)", re.MULTILINE)
_FAILED = re.compile(r"\b\d+ (?:failed|error|errors)\b|^FAILED\b|Traceback", re.MULTILINE)
_SHELL = set("|&;<>()$`*?[]{}~!")


def command_argv(line: str) -> list[str]:
    """The argv a command line runs: split when it is one simple command."""
    stripped = line.strip()
    if not (_SHELL & set(stripped)):
        try:
            parts = shlex.split(stripped)
        except ValueError:
            parts = []
        if parts:
            return parts
    return ["sh", "-c", stripped]


def from_text(transcript: str, visible_argv: list[str] | None) -> list[dict[str, Any]]:
    """Claims in a plain-text transcript."""
    claims: list[dict[str, Any]] = []
    block: list[str] = []

    def close() -> None:
        text = "\n".join(block)
        if _PASSED.search(text) and not _FAILED.search(text):
            if claims and "exit" not in claims[-1]:
                claims[-1]["exit"] = 0
            elif visible_argv is not None:
                claims.append({"id": f"c{len(claims) + 1}", "argv": list(visible_argv), "exit": 0})
        block.clear()

    for line in transcript.splitlines():
        if line.startswith("$ ") and line[2:].strip():
            close()
            claims.append({"id": f"c{len(claims) + 1}", "argv": command_argv(line[2:])})
        else:
            block.append(line)
    close()
    return claims


def from_claude_stream(lines: str) -> list[dict[str, Any]]:
    """Claims in Claude Code ``--output-format stream-json`` output."""
    calls: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for raw in lines.splitlines():
        try:
            message = json.loads(raw)
        except json.JSONDecodeError:
            continue
        content = (message.get("message") or {}).get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use" and block.get("name") == "Bash":
                command = (block.get("input") or {}).get("command")
                if isinstance(command, str) and command.strip():
                    calls[block["id"]] = {"argv": command_argv(command)}
                    order.append(block["id"])
            elif block.get("type") == "tool_result" and block.get("tool_use_id") in calls:
                calls[block["tool_use_id"]]["exit"] = 1 if block.get("is_error") else 0
    return [{"id": f"c{index}", **calls[key]} for index, key in enumerate(order, start=1)]


def record(claims: list[dict[str, Any]], claim_id: str, invocation_id: str,
           producer: str = "transcript-parser") -> dict[str, Any]:
    return {"schema_version": SCHEMA, "claim_id": claim_id, "invocation_id": invocation_id,
            "producer": producer, "claims": claims}
