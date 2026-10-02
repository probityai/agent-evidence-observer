"""Application-owned synchronous TraceProcessor with explicit capture controls."""

from __future__ import annotations

import threading
from typing import Any

from agents.tracing import TracingProcessor

from .contract import decode, encode, require


class LocalTraceProcessor(TracingProcessor):
    """Collect lifecycle exports locally; registration must replace default exporters.

    Payload capture is opt-in. Metadata mode uses a fixed allowlist, omitting
    workflow/operation names, model configuration, errors and user metadata too.
    No export destination, background worker, network request or logging exists.
    Callback failures are counted and later refuse publication, since the SDK may
    otherwise isolate processor exceptions and keep executing tools.
    """

    def __init__(self, *, capture_payloads: bool = False) -> None:
        self.capture_payloads = capture_payloads
        self.events: list[dict[str, Any]] = []
        self.failures = 0
        self.flushes = 0
        self.shutdowns = 0
        self.closed = False
        self.lock = threading.RLock()

    def _payload(self, item: Any) -> dict[str, Any]:
        raw = item.export()
        require(isinstance(raw, dict), "native-export-missing")
        if self.capture_payloads:
            return decode(encode(raw))
        keys = ("object", "id", "trace_id", "parent_id", "started_at", "ended_at")
        result = {key: raw[key] for key in keys if key in raw}
        if "span_data" in raw:
            result["span_data"] = {"type": raw["span_data"]["type"]}
        return result

    def _capture(self, kind: str, item: Any) -> None:
        with self.lock:
            try:
                require(not self.closed, "processor-closed")
                payload = self._payload(item)
                self.events.append(
                    {"sequence": len(self.events), "event": kind, "native": payload}
                )
            except Exception:
                self.failures += 1

    def on_trace_start(self, trace: Any) -> None:
        self._capture("trace-start", trace)

    def on_trace_end(self, trace: Any) -> None:
        self._capture("trace-end", trace)

    def on_span_start(self, span: Any) -> None:
        self._capture("span-start", span)

    def on_span_end(self, span: Any) -> None:
        self._capture("span-end", span)

    def force_flush(self) -> None:
        """Record a flush boundary for synchronous capture."""
        with self.lock:
            self.flushes += 1

    def shutdown(self) -> None:
        """Idempotently close capture; late callbacks become counted refusals."""
        with self.lock:
            if not self.closed:
                self.force_flush()
                self.shutdowns += 1
                self.closed = True

    def snapshot(self) -> dict[str, Any]:
        """Return a detached export with all lifecycle accounting."""
        with self.lock:
            return decode(
                encode(
                    {
                        "capturePayloads": self.capture_payloads,
                        "events": self.events,
                        "failures": self.failures,
                        "flushes": self.flushes,
                        "shutdowns": self.shutdowns,
                        "closed": self.closed,
                    }
                )
            )
