"""Run real Haystack Pipeline/Agent/Tool operations with scripted model replies."""
from __future__ import annotations

import argparse
import contextlib
import contextvars
import importlib.metadata
import threading
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from haystack import Pipeline, component, tracing
from haystack.components.agents import Agent
from haystack.dataclasses import ChatMessage, ToolCall
from haystack.tools import Tool
from haystack.tracing import Span, Tracer

from probity_observer.authorization import ActionRequest, AuthorizedBroker, GrantPolicy, issue_grant
from probity_observer.broker import Broker
from probity_observer.crypto import SigningKey
from probity_observer.history import Witness

from .contract import CASES, CONTENT, PROFILE, SDK_SOURCE, SDK_VERSION, encode, sha


class SavedSpan(Span):
    """Save declared scalar native tags without sensitive content tags."""
    def __init__(self, row: dict[str, Any]) -> None:
        self.row = row

    def set_tag(self, key: str, value: Any) -> None:
        if value is None or type(value) in (str, bool, int, float):
            self.row["tags"][key] = value
        else:
            self.row["omittedContentTags"].append(key)

    def set_content_tag(self, key: str, value: Any) -> None:
        # Model messages are saved explicitly below. Pipeline contents remain disabled.
        self.row["omittedContentTags"].append(key)


class SavedTracer(Tracer):
    """Use context-local ancestry, including Haystack's concurrent tool workers."""
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self.active: contextvars.ContextVar[SavedSpan | None] = contextvars.ContextVar("haystack_saved_span", default=None)
        self.lock = threading.Lock()

    @contextlib.contextmanager
    def trace(self, operation_name: str, tags: dict[str, Any] | None = None, parent_span: Span | None = None):
        parent = parent_span if parent_span is not None else self.current_span()
        with self.lock:
            row = {"id": len(self.rows), "parent": parent.row["id"] if isinstance(parent, SavedSpan) else None,
                   "operation": operation_name, "tags": {}, "omittedContentTags": [], "closed": False, "exception": None}
            self.rows.append(row)
        span = SavedSpan(row)
        span.set_tags(tags or {})
        token = self.active.set(span)
        try:
            yield span
        except BaseException as error:
            row["exception"] = type(error).__name__
            raise
        finally:
            row["closed"] = True
            self.active.reset(token)

    def current_span(self) -> SavedSpan | None:
        return self.active.get()


@component
class ScriptedGenerator:
    """Exercise the native loop without any external provider or model inference."""
    def __init__(self, case: str) -> None:
        self.case = case
        self.calls: list[dict[str, Any]] = []

    @component.output_types(replies=list[ChatMessage])
    def run(self, messages: list[ChatMessage], tools: list[Tool] | None = None) -> dict[str, Any]:
        if not self.calls and self.case != "length":
            content = "wrong bytes" if self.case == "wrong-content" else CONTENT
            reply = ChatMessage.from_assistant(tool_calls=[ToolCall(tool_name="write_result", arguments={"content": content}, id="call-1")])
        else:
            reason = "length" if self.case == "length" else "stop"
            reply = ChatMessage.from_assistant("partial" if self.case == "length" else "done", meta={"finish_reason": reason})
        self.calls.append({"input": [message.to_dict() for message in messages], "output": reply.to_dict()})
        return {"replies": [reply]}


def run_case(root: Path, case: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run one real framework fault case and seal its bounded native history."""
    root.mkdir()
    work = root / "work"
    work.mkdir()
    issuer, observer, witness_key = (SigningKey.generate() for _ in range(3))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    request = ActionRequest(case, "attempt-1", "request-1", "tenant-1", "principal-1", "write_result", "/work/result.txt", sha(CONTENT.encode()))
    grant = issue_grant(request, issuer, issued_at=now, expires_at=now + timedelta(seconds=300))
    broker = Broker(work, root / "history.jsonl", {"intervalId": case, "scope": "/work", "operation": "write-file"}, observer, Witness(root / "witness.json", witness_key))
    authorized = AuthorizedBroker(broker, grant, GrantPolicy(issuer.public_hex), request)
    broker.begin()
    calls: list[dict[str, Any]] = []

    def write_result(content: str) -> str:
        row = {"content": content, "committed": False, "exception": None}
        calls.append(row)
        try:
            if case == "error-before":
                raise RuntimeError("controlled failure before effect")
            authorized.write(request, content.encode())
            row["committed"] = True
            if case in {"handled-after", "unhandled-after"}:
                raise RuntimeError("controlled failure after committed effect")
            return "committed"
        except Exception as error:
            row["exception"] = type(error).__name__
            raise

    tool = Tool(name="write_result", description="Write exactly the host-authorized bytes.",
                parameters={"type": "object", "properties": {"content": {"type": "string"}}, "required": ["content"], "additionalProperties": False}, function=write_result)
    model = ScriptedGenerator(case)
    agent = Agent(chat_generator=model, tools=[tool], max_agent_steps=1 if case == "max-steps" else 3,
                  raise_on_tool_invocation_failure=case == "unhandled-after")
    pipeline = Pipeline()
    pipeline.add_component("agent", agent)
    capture = SavedTracer()
    old = tracing.tracer.actual_tracer
    tracing.enable_tracing(capture)
    output = None
    error_name = None
    try:
        output = pipeline.run({"agent": {"messages": [ChatMessage.from_user("Run the selected controlled write.")]}})["agent"]
    except Exception as error:
        error_name = type(error).__name__
    finally:
        tracing.enable_tracing(old)
    committed = sum(row["committed"] for row in calls)
    packet = authorized.seal() if committed else broker.seal()
    (root / "packet.json").write_bytes(encode(packet))
    (root / "grant.json").write_bytes(encode(grant))
    record = {"profile": PROFILE, "case": case, "sdkVersion": importlib.metadata.version("haystack-ai"),
              "modelCalls": model.calls, "toolCalls": calls, "spans": capture.rows,
              "terminal": {"exception": error_name, "exitReason": output["exit_reason"] if output else None,
                           "stepCount": output["step_count"] if output else None},
              "messages": [message.to_dict() for message in output["messages"]] if output else []}
    (root / "native.json").write_bytes(encode(record))
    pins = {"request": asdict(request), "issuerKey": issuer.public_hex, "observerKey": observer.public_hex,
            "witnessKey": witness_key.public_hex, "referenceTime": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
    pins["artifacts"] = {name: sha((root / name).read_bytes()) for name in ("packet.json", "grant.json", "history.jsonl", "native.json")}
    return record, pins


def produce(output: Path) -> dict[str, Any]:
    """Save a new complete seven-case population and externally selected policy."""
    if importlib.metadata.version("haystack-ai") != SDK_VERSION:
        raise ValueError("the installed native SDK differs from the declared release")
    output.mkdir()
    source_manifest = {}
    for distribution, prefix in (("probity-haystack-reference", "probity_haystack/"), ("agent-evidence-observer", "probity_observer/"), ("haystack-ai", "haystack/")):
        installed = importlib.metadata.distribution(distribution)
        for member in installed.files or []:
            name = str(member)
            if name.startswith(prefix) and name.endswith(".py"):
                source = Path(installed.locate_file(member))
                if source.is_symlink():
                    raise ValueError("selected installed source must not be a symlink")
                target = output / "source" / name
                target.parent.mkdir(parents=True, exist_ok=True)
                body = source.read_bytes()
                target.write_bytes(body)
                source_manifest[name] = sha(body)
    if not source_manifest:
        raise ValueError("installed source population is empty")
    manifest_bytes = encode(source_manifest)
    (output / "source-before-run.json").write_bytes(manifest_bytes)
    policy: dict[str, Any] = {"profile": PROFILE, "sdkVersion": SDK_VERSION, "sdkSource": SDK_SOURCE,
                              "sourceManifestSha256": sha(manifest_bytes), "cases": {}}
    for case in CASES:
        _, policy["cases"][case] = run_case(output / case, case)
    (output / "host-policy.json").write_bytes(encode(policy))
    return policy


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    produce(args.output)


if __name__ == "__main__":
    main()
