"""External BasePlugin capture, preserving its actual position in plugin order."""

from __future__ import annotations

import threading
from typing import Any

from google.adk.plugins.base_plugin import BasePlugin

from .contract import decode, encode, require


def native(value: Any) -> dict[str, Any]:
    """Retain original installed framework JSON bytes and decoded fields together."""
    raw = value.model_dump_json().encode()
    return {"jsonHex": raw.hex(), "value": decode(raw)}


class CapturePlugin(BasePlugin):
    """Local synchronous snapshot, payloads off by default and no network/logging.

    This observer never changes ADK return values. Earlier plugins can consume
    after-tool or tool-error callbacks; raw tool records must therefore remain
    separately retained before plugin handling. Close does not imply run success.
    """

    def __init__(self, *, capture_payloads: bool = False) -> None:
        super().__init__(name="probity_capture")
        self.capture_payloads = capture_payloads
        self.records: list[dict[str, Any]] = []
        self.failures = 0
        self.closed = False
        self.lock = threading.RLock()

    def capture(self, kind: str, invocation: str, payload: Any) -> None:
        """Count closed/serialization/size failures without retaining exception text."""
        with self.lock:
            try:
                require(not self.closed and len(self.records) < 512, "capture-bound")
                value = payload() if self.capture_payloads else {}
                require(len(encode(value)) <= 1024 * 1024, "callback-byte-bound")
                self.records.append(
                    decode(
                        encode(
                            {
                                "sequence": len(self.records),
                                "callback": kind,
                                "invocationId": invocation,
                                "native": value,
                            }
                        )
                    )
                )
            except Exception:
                self.failures += 1

    async def on_user_message_callback(
        self, *, invocation_context: Any, user_message: Any
    ) -> None:
        self.capture(
            "user-message",
            invocation_context.invocation_id,
            lambda: native(user_message),
        )

    async def before_run_callback(self, *, invocation_context: Any) -> None:
        self.capture("before-run", invocation_context.invocation_id, lambda: {})

    async def after_run_callback(self, *, invocation_context: Any) -> None:
        self.capture("after-run", invocation_context.invocation_id, lambda: {})

    async def before_agent_callback(self, *, agent: Any, callback_context: Any) -> None:
        self.capture(
            "before-agent",
            callback_context.invocation_id,
            lambda: {"agent": agent.name},
        )

    async def after_agent_callback(self, *, agent: Any, callback_context: Any) -> None:
        self.capture(
            "after-agent", callback_context.invocation_id, lambda: {"agent": agent.name}
        )

    async def before_model_callback(
        self, *, callback_context: Any, llm_request: Any
    ) -> None:
        self.capture(
            "before-model", callback_context.invocation_id, lambda: native(llm_request)
        )

    async def after_model_callback(
        self, *, callback_context: Any, llm_response: Any
    ) -> None:
        self.capture(
            "after-model", callback_context.invocation_id, lambda: native(llm_response)
        )

    async def before_tool_callback(
        self, *, tool: Any, tool_args: Any, tool_context: Any
    ) -> None:
        self.capture(
            "before-tool",
            tool_context.invocation_id,
            lambda: {
                "tool": tool.name,
                "functionCallId": tool_context.function_call_id,
                "arguments": tool_args,
            },
        )

    async def after_tool_callback(
        self, *, tool: Any, tool_args: Any, tool_context: Any, result: Any
    ) -> None:
        self.capture(
            "after-tool",
            tool_context.invocation_id,
            lambda: {
                "tool": tool.name,
                "functionCallId": tool_context.function_call_id,
                "arguments": tool_args,
                "result": result,
            },
        )

    async def on_tool_error_callback(
        self, *, tool: Any, tool_args: Any, tool_context: Any, error: Exception
    ) -> None:
        self.capture(
            "tool-error",
            tool_context.invocation_id,
            lambda: {
                "tool": tool.name,
                "functionCallId": tool_context.function_call_id,
                "arguments": tool_args,
                "error": {"type": type(error).__name__, "message": str(error)},
            },
        )

    async def on_agent_error_callback(
        self, *, agent: Any, callback_context: Any, error: Exception
    ) -> None:
        self.capture(
            "agent-error",
            callback_context.invocation_id,
            lambda: {
                "agent": agent.name,
                "error": {"type": type(error).__name__, "message": str(error)},
            },
        )

    async def on_run_error_callback(
        self, *, invocation_context: Any, error: Exception
    ) -> None:
        self.capture(
            "run-error",
            invocation_context.invocation_id,
            lambda: {"error": {"type": type(error).__name__, "message": str(error)}},
        )

    async def on_event_callback(self, *, invocation_context: Any, event: Any) -> None:
        self.capture("event", invocation_context.invocation_id, lambda: native(event))

    async def close(self) -> None:
        with self.lock:
            self.closed = True

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return decode(
                encode(
                    {
                        "capturePayloads": self.capture_payloads,
                        "records": self.records,
                        "failures": self.failures,
                        "closed": self.closed,
                    }
                )
            )
