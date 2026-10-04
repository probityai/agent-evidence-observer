"""Execute the unchanged ADK #7401 source with fixed public BaseLlm scripts."""

import argparse
import asyncio
from dataclasses import asdict
import hashlib
from pathlib import Path
import time
from typing import Any

from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.genai import types
from pydantic import Field

from .capture import native
from .contract import CASES, PAYLOAD, decode, encode, plan, require, store as save

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


async def execute(root, case):
    from google.adk.agents.llm_agent import LlmAgent
    from google.adk.apps.app import App, EventsCompactionConfig
    from google.adk.apps.llm_event_summarizer import LlmEventSummarizer
    from google.adk.runners import Runner
    from google.adk.sessions.in_memory_session_service import InMemorySessionService
    from google.adk.tools.agent_tool import AgentTool
    from google.adk.tools.tool_context import ToolContext
    from google.genai import types
    from .capture import CapturePlugin, native
    
    from probity_observer.broker import Broker
    from probity_observer.crypto import SigningKey
    from probity_observer.history import Witness

    directory = root / "cases" / case
    directory.mkdir(parents=True)
    work = directory / "workspace"
    work.mkdir()
    observer, witness = SigningKey.generate(), SigningKey.generate()
    save(directory / "keys-before-run.json", {"observer": observer.public_hex, "witness": witness.public_hex})
    authority = {"intervalId": case, "scope": "/work", "operation": "write-file"}
    save(directory / "authority-before-run.json", authority)
    broker = Broker(work, directory / "history.jsonl", authority, observer,
                    Witness(directory / "witness-state.json", witness))
    save(directory / "begin-before-run.json", broker.begin())
    effects = []
    payload = PAYLOAD

    class ConfigCapture(CapturePlugin):
        def __init__(self):
            super().__init__(capture_payloads=True)
            self.close_calls = 0
            self.parent_closing = False

        async def before_run_callback(self, *, invocation_context):
            await super().before_run_callback(invocation_context=invocation_context)
            config = invocation_context.events_compaction_config
            self.capture("config-before-run", invocation_context.invocation_id,
                         lambda: {"sessionId": invocation_context.session.id,
                                  "rootAgent": invocation_context.agent.name,
                                  "runStartedAt": time.time(),
                                  "sharesParentSummarizer": (config.summarizer is parent_config.summarizer
                                                            if config is not None and parent_config is not None else False),
                                  "configJSONHex": (config.model_dump_json(exclude={"summarizer"}).encode().hex()
                                                    if config is not None else None)})

        async def close(self):
            self.close_calls += 1
            self.capture("plugin-close", "parent", lambda: {"phase": "parent-close" if self.parent_closing else "run-active",
                         "ordinal": self.close_calls, "closedAt": time.time(), "closedBefore": self.closed})
            await super().close()

    def read_large_file(tool_context: ToolContext):
        """Return one public large fixture and record its native body effect."""
        content = payload.encode()
        path = f"/work/chapter-{len(effects)}.txt"
        result = broker.write(tool_context.function_call_id, path, content)
        effects.append({"functionCallId": tool_context.function_call_id,
                        "invocationId": tool_context.invocation_id, "result": asdict(result),
                        "operator": "native-tool-body", "contentSHA256": hashlib.sha256(content).hexdigest()})
        return payload

    def call(name):
        return types.Part.from_function_call(name=name, args={} if name == "read_large_file"
                                             else {"request": "Read the public finite fixture"})

    leaf_model = FixedModel(responses=[call("read_large_file") for _ in range(3)] + ["leaf answer 1"]
                                     + [call("read_large_file") for _ in range(3)] + ["leaf answer 2"])
    middle_model = FixedModel(responses=[call("leaf"), "middle answer 1", call("leaf"), "middle answer 2"])
    root_model = FixedModel(responses=[call("middle"), call("middle"), "root answer"])
    summary_model = FixedModel(responses=["NESTED SUMMARY"] * 40)
    include = case != "token-no-plugins"
    leaf = LlmAgent(name="leaf", model=leaf_model, tools=[read_large_file])
    middle = LlmAgent(name="middle", model=middle_model,
                      tools=[AgentTool(agent=leaf, include_plugins=include)])
    agent = LlmAgent(name="root", model=root_model,
                     tools=[AgentTool(agent=middle, include_plugins=include)])
    config = (None if case == "no-config" else EventsCompactionConfig(
        compaction_interval=1 if case == "window-only" else 10000,
        overlap_size=0, token_threshold=None if case == "window-only" else 100,
        event_retention_size=None if case == "window-only" else 0,
        summarizer=LlmEventSummarizer(llm=summary_model)))
    parent_config = config
    before = config.model_dump_json(exclude={"summarizer"}) if config else None
    save(directory / "parent-config-before.json", {"json": before})
    capture = ConfigCapture()
    app = App(name="probity_nested", root_agent=agent, plugins=[capture], events_compaction_config=config)
    sessions = InMemorySessionService()
    runner = Runner(app=app, session_service=sessions)
    session = await sessions.create_session(app_name=app.name, user_id="author", session_id=case)
    try:
        events = [e async for e in runner.run_async(user_id="author", session_id=case,
                   new_message=types.UserContent(parts=[types.Part(text="Start finite nested work")]))]
        save(directory / "yielded-root-events.json", [native(e) for e in events])
        save(directory / "plugin-before-parent-close.json", {**capture.snapshot(), "closeCalls": capture.close_calls})
        retained = await sessions.get_session(app_name=app.name, user_id="author", session_id=case)
        save(directory / "root-session.json", native(retained))
    finally:
        capture.parent_closing = True
        await runner.close()
        save(directory / "plugin-after-parent-close.json", {**capture.snapshot(), "closeCalls": capture.close_calls})
        save(directory / "model-requests.json", {"root": root_model.requests, "middle": middle_model.requests,
                                                  "leaf": leaf_model.requests, "summarizer": summary_model.requests})
        save(directory / "tool-effects.json", effects)
        save(directory / "parent-config-after.json", {"json": config.model_dump_json(exclude={"summarizer"}) if config else None})
        save(directory / "observer-packet.json", broker.seal())
    requests = [r["value"] for r in leaf_model.requests]
    text = lambda r: " ".join((p.get("text") or "") for c in r["contents"] for p in (c.get("parts") or []))
    configs = [r for r in capture.records if r["callback"] == "config-before-run"]
    assert len(requests) == 8 and len(effects) == 6
    assert before == (config.model_dump_json(exclude={"summarizer"}) if config else None)
    assert not capture.failures and capture.close_calls == 1
    assert len(requests[4]["contents"]) == 1 and "NESTED SUMMARY" not in text(requests[4])
    assert all(("NESTED SUMMARY" in text(requests[i])) is (case.startswith("token")) for i in [3, 7])
    assert len(configs) == (1 if not include else 5)
    return {"case": case, "rootCalls": len(root_model.requests), "middleCalls": len(middle_model.requests),
            "leafCalls": len(leaf_model.requests), "summaryCalls": len(summary_model.requests),
            "nativeToolEffects": len(effects), "capturedInvocationConfigs": len(configs),
            "pluginCloseCalls": capture.close_calls, "captureFailures": capture.failures,
            "nestedPluginCoverage": include, "parentConfigUnchanged": True, "publicationDecision": None}


async def produce(root):
    selected = decode((root / "plan-before-run.json").read_bytes())
    require(selected == plan(selected["runId"]), "unselected-plan")
    rows = []
    for case in CASES:
        rows.append(await execute(root, case))
    result = {"rows": rows, "providerRequests": 0, "operator": "author-operated",
              "witnessScope": "PEER", "publicationDecision": None,
              "prospectiveEightTaskRun": "not-started", "older16Rows": "unchanged"}
    save(root / "native-result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    args = parser.parse_args()
    print(encode(asyncio.run(produce(args.packet))).decode())
    return 0
