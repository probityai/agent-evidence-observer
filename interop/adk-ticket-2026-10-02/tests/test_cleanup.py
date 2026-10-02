"""Unexpected native invocation failures still close the real Runner plugins."""

import asyncio

import pytest
from google.adk import Runner
from google.adk.sessions import InMemorySessionService

from probity_adk.producer import invocation


def test_session_read_failure_closes_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    closed = []
    original_close = Runner.close
    original_get = InMemorySessionService.get_session
    reads = []

    async def get(service: InMemorySessionService, **kwargs: object):
        reads.append(kwargs)
        if len(reads) > 1:
            raise OSError("selected unexpected session read failure")
        return await original_get(service, **kwargs)

    async def close(runner: Runner) -> None:
        await original_close(runner)
        closed.append(True)

    async def dispatch_ticket(content: str) -> dict:
        return {"synthetic": True}

    monkeypatch.setattr(InMemorySessionService, "get_session", get)
    monkeypatch.setattr(Runner, "close", close)
    with pytest.raises(OSError, match="session read failure"):
        asyncio.run(
            invocation(
                {
                    "id": "permit",
                    "pluginOrder": ["probity_capture"],
                    "plannedTools": 1,
                    "arguments": {"content": "DONE"},
                },
                dispatch_ticket,
            )
        )
    assert closed == [True]
