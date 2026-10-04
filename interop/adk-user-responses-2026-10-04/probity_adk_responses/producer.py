"""Actual installed ADK runner, fixed model, confirmation and LRO tools."""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict
from pathlib import Path
from typing import Any

from google.adk.agents.llm_agent import LlmAgent
from google.adk.apps.app import App, ResumabilityConfig
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.adk.tools.function_tool import FunctionTool
from google.adk.tools.long_running_tool import LongRunningFunctionTool
from google.adk.tools.tool_context import ToolContext
from google.genai import types
from pydantic import Field

from probity_observer.broker import Broker
from probity_observer.crypto import SigningKey, canonical
from probity_observer.history import Witness

from .capture import CapturePlugin
from .contract import (CASES, CONTENT, FINAL_TEXT, ROOT_TEXT, decode, native,
                       plan, require, sha, store)


class FixedModel(BaseLlm):
    """Supplies finite public Parts through the real BaseLlm interface."""

    model: str = "probity-fixed-script"
    responses: list[Any]
    requests: list[Any] = Field(default_factory=list)

    async def generate_content_async(self, llm_request: Any, stream: bool = False):
        require(not stream and len(self.requests) < len(self.responses),
                "finite-model-call-bound")
        self.requests.append(native(llm_request))
        part = self.responses[len(self.requests) - 1]
        if isinstance(part, str):
            part = types.Part(text=part)
        yield LlmResponse(content=types.Content(role="model", parts=[part]))


async def execute_case(root: Path, case: str) -> dict[str, Any]:
    directory = root / "cases" / case
    directory.mkdir(parents=True)
    workspace = directory / "workspace"
    workspace.mkdir()
    observer, witness_key = SigningKey.generate(), SigningKey.generate()
    keys = {"observer": observer.public_hex, "witness": witness_key.public_hex}
    store(directory / "trusted-keys-before-run.json", keys)
    authority = {"intervalId": case, "scope": "/work", "operation": "write-file"}
    store(directory / "authority-before-run.json", authority)
    broker = Broker(workspace, directory / "history.jsonl", authority, observer,
                    Witness(directory / "witness-state.json", witness_key))
    store(directory / "begin-before-run.json", broker.begin())
    bodies: list[dict[str, Any]] = []
    operator_effects: list[dict[str, Any]] = []

    def approved_write(tool_context: ToolContext) -> dict[str, Any]:
        """Write one fixed file after native confirmation accepts the call."""
        call_id = tool_context.function_call_id
        result = broker.write(call_id, "/work/result.txt", CONTENT)
        bodies.append({"tool": "approved_write", "functionCallId": call_id,
                       "result": asdict(result), "effectOperator": "tool-body"})
        return {"status": "written", "requestId": call_id}

    def pending_work(tool_context: ToolContext) -> None:
        """Start a finite long-running operation completed by the host next turn."""
        bodies.append({"tool": "pending_work",
                       "functionCallId": tool_context.function_call_id,
                       "result": None, "effectOperator": None})
        return None

    is_lro = case == "long-running-completed"
    tool = (LongRunningFunctionTool(func=pending_work) if is_lro else
            FunctionTool(func=approved_write, require_confirmation=True))
    sub_model = FixedModel(responses=[
        types.Part.from_function_call(name=tool.name, args={}), FINAL_TEXT])
    root_model = FixedModel(responses=[
        types.Part.from_function_call(name="transfer_to_agent",
                                      args={"agent_name": "issuer"}), ROOT_TEXT])
    issuer = LlmAgent(name="issuer", model=sub_model, tools=[tool],
                      disallow_transfer_to_parent=True,
                      disallow_transfer_to_peers=True)
    root_agent = LlmAgent(name="root", model=root_model, sub_agents=[issuer])
    capture = CapturePlugin(capture_payloads=True)
    app = App(name="probity_routing", root_agent=root_agent, plugins=[capture],
              resumability_config=ResumabilityConfig(is_resumable=False))
    sessions = InMemorySessionService()
    runner = Runner(app=app, session_service=sessions)
    session = await sessions.create_session(app_name=app.name, user_id="author",
                                            session_id=case)
    turns: list[list[dict[str, Any]]] = []

    async def turn(message: Any) -> list[Any]:
        events = [event async for event in runner.run_async(
            user_id="author", session_id=case, new_message=message)]
        turns.append([native(event) for event in events])
        return events

    first = await turn(types.UserContent(parts=[types.Part(text="Start finite work")]))
    require(not list(workspace.iterdir()), "effect-before-user-response")
    name = "pending_work" if is_lro else "adk_request_confirmation"
    calls = [fc for event in first if event.author == "issuer"
             for fc in event.get_function_calls() if fc.name == name]
    require(len(calls) == 1 and bool(calls[0].id), "issuing-call-population")
    call = calls[0]
    store(directory / "effect-before-response.json", {"files": []})
    if is_lro:
        result = broker.write(call.id, "/work/result.txt", CONTENT)
        operator_effects.append({"functionCallId": call.id,
                                 "result": asdict(result),
                                 "effectOperator": "same-author-host-completion"})
        response = {"status": "completed", "requestId": call.id}
    else:
        response = {"confirmed": case == "approval-granted"}
    part = types.Part.from_function_response(name=name, response=response)
    part.function_response.id = call.id
    supplied = types.UserContent(parts=[part])
    store(directory / "supplied-user-response.json", native(supplied))
    second = await turn(supplied)
    third = await turn(types.UserContent(parts=[types.Part(text="Later plain text")]))
    require(second and {event.author for event in second} == {"issuer"},
            "response-not-routed-to-issuer")
    require(third and {event.author for event in third} == {"root"},
            "later-plain-text-not-routed-to-root")
    await runner.close()
    require(capture.closed and capture.failures == 0, "capture-did-not-close")
    retained = await sessions.get_session(app_name=app.name, user_id="author",
                                           session_id=case)
    store(directory / "session.json", native(retained))
    store(directory / "turns.json", turns)
    store(directory / "callbacks.json", capture.snapshot())
    store(directory / "model-requests.json", {"root": root_model.requests,
                                               "issuer": sub_model.requests})
    store(directory / "tool-bodies.json", bodies)
    store(directory / "operator-effects.json", operator_effects)
    packet = broker.seal()
    (directory / "observer-packet.json").write_bytes(canonical(packet))
    return {"case": case, "nativeResponseAuthors": sorted({e.author for e in second}),
            "nativeLaterTextAuthors": sorted({e.author for e in third}),
            "modelCalls": len(root_model.requests) + len(sub_model.requests),
            "toolBodyCalls": len(bodies), "observedWrites": len(packet["claim"]["writes"])}


async def produce(root: Path) -> dict[str, Any]:
    selected = decode((root / "plan-before-run.json").read_bytes())
    require(selected == plan(selected["runId"]), "unselected-plan")
    rows = [await execute_case(root, case) for case in CASES]
    result = {"profile": selected["profile"], "runId": selected["runId"], "rows": rows,
              "providerRequests": 0, "modelQuality": "not-evaluated",
              "authority": "explicit author-operated broker scope",
              "effectCustody": "author-operated PEER",
              "publicationDecision": None, "prospectiveEightTaskRun": "not-started"}
    store(root / "native-result.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(produce_json(args.directory))
    return 0


def produce_json(directory: Path) -> str:
    from .contract import encode
    return encode(asyncio.run(produce(directory))).decode()
