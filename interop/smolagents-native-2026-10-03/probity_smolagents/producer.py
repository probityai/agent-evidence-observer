"""Run actual smolagents loops and authorized effects with scripted replies."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from probity_observer.authorization import (
    ActionRequest, AuthorizedBroker, GrantPolicy, issue_grant,
)
from probity_observer.broker import Broker
from probity_observer.crypto import SigningKey
from probity_observer.history import Witness

from .contract import CASES, CONTENT, PROFILE, SDK_SOURCE, SDK_VERSION, encode, reply, require, sha
from .source import snapshot_sources


def scripted_model(case: str) -> Any:
    """Construct an actual Model subclass after source qualification.

    Each call retains native input messages and a complete reply or raised
    error. It invokes no model provider and fabricates no inference metric.
    """
    from smolagents.models import ChatMessage, Model

    class ScriptedModel(Model):
        """Exercise the native tool loop with a literal finite script."""
        def __init__(self) -> None:
            super().__init__(model_id="credential-free-script")
            self.calls: list[dict[str, Any]] = []

        def generate(self, messages: list[Any], **kwargs: Any) -> Any:
            """Retain one attempted call, including the controlled second error."""
            index = len(self.calls)
            response = reply(index, case)
            row = {
                "input": [message.dict() for message in messages],
                "output": response,
                "error": None,
                "tools": [tool.name for tool in kwargs.get("tools_to_call_from") or []],
            }
            self.calls.append(row)
            if response is None:
                row["error"] = "RuntimeError"
                raise RuntimeError("controlled model error after effect")
            # from_dict consumes its own copy when coercing tool calls.
            return ChatMessage.from_dict(json.loads(encode(response)))

    return ScriptedModel()


def write_tool(case: str, authorized: AuthorizedBroker, request: ActionRequest) -> Any:
    """Construct the native Tool and retain actual forward/effect boundaries."""
    from smolagents.tools import Tool

    class WriteResult(Tool):
        """Write only the host-selected bytes through the authorized broker."""
        name = "write_result"
        description = "Write exactly the host-authorized bytes."
        inputs = {"content": {"type": "string", "description": "Exact selected content."}}
        output_type = "string"

        def __init__(self) -> None:
            super().__init__()
            self.calls: list[dict[str, Any]] = []

        def forward(self, content: str) -> str:
            """Retain refusal or error without concealing a preceding write."""
            row = {"content": content, "committed": False, "exception": None}
            self.calls.append(row)
            try:
                if case == "error-before":
                    raise RuntimeError("controlled failure before effect")
                authorized.write(request, content.encode("utf-8"))
                row["committed"] = True
                if case == "error-after":
                    raise RuntimeError("controlled failure after committed effect")
                return "committed"
            except Exception as error:
                row["exception"] = type(error).__name__
                raise

    return WriteResult()


def run_agent(case: str, model: Any, tool: Any) -> tuple[Any, list[dict[str, Any]], list[dict[str, Any]], str | None]:
    """Capture ActionStep and FinalAnswerStep separately from native memory.

    The incomplete case stops only after the first ActionStep was finalized.
    Closing earlier at ToolOutput can make the SDK yield during GeneratorExit.
    """
    from smolagents import ToolCallingAgent
    from smolagents.memory import ActionStep, FinalAnswerStep

    callbacks: list[dict[str, Any]] = []

    def capture(step: Any, **kwargs: Any) -> None:
        callbacks.append({"kind": type(step).__name__, "data": step.dict()})

    agent = ToolCallingAgent(
        tools=[tool], model=model, max_steps=1 if case == "max-steps" else 3,
        step_callbacks={ActionStep: [capture], FinalAnswerStep: [capture]},
        max_tool_threads=1, verbosity_level=0,
    )
    output, exception = None, None
    try:
        if case == "incomplete-after":
            stream = agent.run("Run the selected controlled write.", stream=True)
            for step in stream:
                if isinstance(step, ActionStep):
                    stream.close()
                    break
        else:
            result = agent.run("Run the selected controlled write.", return_full_result=True)
            output = {"state": result.state, "output": result.output}
    except Exception as error:
        exception = type(error).__name__
    actions = [step.dict() for step in agent.memory.steps if isinstance(step, ActionStep)]
    return output, callbacks, actions, exception


def run_case(root: Path, case: str) -> dict[str, Any]:
    """Execute one native case and retain its signed peer-witnessed effects."""
    root.mkdir()
    work = root / "work"
    work.mkdir()
    issuer, observer, witness = (SigningKey.generate() for _ in range(3))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    request = ActionRequest(
        case, "attempt-1", "request-1", "tenant-1", "principal-1",
        "write_result", "/work/result.txt", sha(CONTENT.encode("utf-8")),
    )
    grant = issue_grant(request, issuer, issued_at=now, expires_at=now + timedelta(seconds=300))
    broker = Broker(
        work, root / "history.jsonl",
        {"intervalId": case, "scope": "/work", "operation": "write-file"},
        observer, Witness(root / "witness.json", witness),
    )
    authorized = AuthorizedBroker(broker, grant, GrantPolicy(issuer.public_hex), request)
    broker.begin()
    model, tool = scripted_model(case), write_tool(case, authorized, request)
    result, callbacks, actions, exception = run_agent(case, model, tool)
    packet = authorized.seal() if any(row["committed"] for row in tool.calls) else broker.seal()
    state = result["state"] if result else "raised" if exception else "incomplete"
    native = {
        "profile": PROFILE, "case": case, "sdkVersion": SDK_VERSION,
        "modelCalls": model.calls, "toolCalls": tool.calls, "callbacks": callbacks,
        "memoryActions": actions,
        "terminal": {"state": state, "exception": exception, "result": result},
    }
    for name, value in (("packet.json", packet), ("grant.json", grant), ("native.json", native)):
        (root / name).write_bytes(encode(value))
    pins = {
        "request": asdict(request), "issuerKey": issuer.public_hex,
        "observerKey": observer.public_hex, "witnessKey": witness.public_hex,
        "referenceTime": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    pins["artifacts"] = {
        name: sha((root / name).read_bytes())
        for name in ("packet.json", "grant.json", "history.jsonl", "native.json")
    }
    return pins


def produce(output: Path) -> dict[str, Any]:
    """Save a new population and sibling host policy without provider inference.

    Parameters
    ----------
    output : pathlib.Path
        New output directory. Its packet subdirectory contains retained source
        and native cases; host-policy.json is outside that packet.

    Returns
    -------
    dict
        Host source, key, action and original-artifact selections. A caller
        explicitly selects its digest when invoking the installed reader.
    """
    require(not output.exists(), "producer output already exists")
    output.mkdir()
    packet = output / "packet"
    packet.mkdir()
    sources = snapshot_sources(packet)
    policy = {
        "schema": "probity.smolagents-host-policy.v1",
        "profile": PROFILE,
        "sdk": {"version": SDK_VERSION, "commit": SDK_SOURCE},
        "sourceManifestSha256": sha(encode(sources)),
        "cases": {case: run_case(packet / case, case) for case in CASES},
    }
    (output / "host-policy.json").write_bytes(encode(policy))
    return policy


def main() -> None:
    """Run the native producer CLI in an authenticated installed environment."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    produce(args.output)


if __name__ == "__main__":
    main()
