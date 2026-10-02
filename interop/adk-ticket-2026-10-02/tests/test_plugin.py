"""Real BasePlugin serialization/default/close/failure controls."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

from google.genai import types

from probity_adk.contract import encode
from probity_adk.plugin import CapturePlugin


def test_default_metadata_does_not_serialize_payload() -> None:
    class SensitiveUnserializable:
        def model_dump_json(self) -> None:
            raise RuntimeError("synthetic-sensitive-sentinel")

    plugin = CapturePlugin()
    asyncio.run(
        plugin.on_user_message_callback(
            invocation_context=SimpleNamespace(invocation_id="selected"),
            user_message=SensitiveUnserializable(),
        )
    )
    assert plugin.snapshot()["failures"] == 0
    assert plugin.snapshot()["records"][0]["native"] == {}
    assert "synthetic-sensitive" not in encode(plugin.snapshot()).decode()


def test_payload_opt_in_retains_native_json() -> None:
    plugin = CapturePlugin(capture_payloads=True)
    message = types.Content(
        role="user", parts=[types.Part(text="synthetic-public-payload")]
    )
    asyncio.run(
        plugin.on_user_message_callback(
            invocation_context=SimpleNamespace(invocation_id="selected"),
            user_message=message,
        )
    )
    assert plugin.snapshot()["failures"] == 0
    assert "synthetic-public-payload" in encode(plugin.snapshot()).decode()


def test_opt_in_serialization_failure_counts_without_payload_or_log(
    capsys: Any,
) -> None:
    class Unserializable:
        def model_dump_json(self) -> None:
            raise RuntimeError("synthetic-sensitive-exception")

    plugin = CapturePlugin(capture_payloads=True)
    asyncio.run(
        plugin.on_user_message_callback(
            invocation_context=SimpleNamespace(invocation_id="selected"),
            user_message=Unserializable(),
        )
    )
    assert plugin.snapshot()["failures"] == 1
    assert plugin.snapshot()["records"] == []
    assert capsys.readouterr() == ("", "")
    assert "synthetic-sensitive" not in encode(plugin.snapshot()).decode()


def test_close_and_resource_limits_refuse_late_capture() -> None:
    plugin = CapturePlugin(capture_payloads=True)
    plugin.capture("oversize", "selected", lambda: {"large": "x" * (1024 * 1024)})
    assert plugin.snapshot()["failures"] == 1
    asyncio.run(plugin.close())
    asyncio.run(plugin.close())
    plugin.capture("late", "selected", lambda: {})
    assert plugin.snapshot()["closed"] is True
    assert plugin.snapshot()["failures"] == 2
