"""Execute installed ADK Runner/plugins with real protected HTTP effects."""

from __future__ import annotations

import argparse
import asyncio
import time
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from importlib import metadata
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import uuid4

from probity_observer.authorization import (
    ActionRequest,
    GrantPolicy,
    issue_grant,
    utc_clock,
)
from probity_observer.crypto import SigningKey
from probity_observer.ticket_service import TicketStore, running_server

from .contract import (
    AFTER_ERROR,
    BEFORE_ERROR,
    CASES,
    CONTENT,
    PROFILE,
    PROMPT,
    VERSION,
    arguments,
    decode,
    encode,
    plugin_order,
    require,
    sha,
    tool_count,
    write,
)


def sources(output: Path) -> dict[str, str]:
    """Freeze installed adapter, SDK and protected-target source bytes."""
    import google.adk
    import probity_observer

    manifest = {}
    packages = {
        "adapter": Path(__file__).parent,
        "observer": Path(probity_observer.__file__).parent,
        "adk": Path(google.adk.__file__).parent,
    }
    for label, folder in packages.items():
        for path in sorted(folder.rglob("*.py")):
            name = label + "/" + str(path.relative_to(folder))
            raw = path.read_bytes()
            write(output / "sources" / name, raw)
            manifest[name] = sha(raw)
    distribution = metadata.distribution("google-adk")
    for entry in distribution.files or []:
        if str(entry).endswith((".dist-info/METADATA", ".dist-info/licenses/LICENSE")):
            raw = distribution.locate_file(entry).read_bytes()
            name = "distribution/" + Path(str(entry)).name
            write(output / "sources" / name, raw)
            manifest[name] = sha(raw)
    versions = {
        name: metadata.version(name)
        for name in (
            "google-adk",
            "google-genai",
            "mcp",
            "pydantic",
            "cryptography",
            "agent-evidence-observer",
            "probity-adk-reference",
        )
    }
    write(output / "sources/distribution/versions.json", encode(versions))
    manifest["distribution/versions.json"] = sha(encode(versions))
    return manifest


def host(directory: Path, run_id: str, case: str) -> tuple[dict[str, Any], TicketStore]:
    """Select separate issuer/service keys and one initial synthetic native row."""
    issuer, service = SigningKey.generate(), SigningKey.generate()
    now = utc_clock()
    request = ActionRequest(
        run_id,
        case,
        "request-" + case,
        "tenant",
        "principal",
        "ticket-update",
        "/work/tickets/" + case,
        sha(CONTENT.encode()),
    )
    policy = GrantPolicy(issuer.public_hex)
    grant = issue_grant(
        request, issuer, issued_at=now, expires_at=now + timedelta(seconds=240)
    )
    store = TicketStore(directory / (case + ".sqlite"), request, policy, service)
    store.initialize()
    if case == "deny":
        store.revoke()
    entry = {
        "id": case,
        "request": asdict(request),
        "policy": asdict(policy),
        "serviceKey": service.public_hex,
        "grant": grant,
        "initial": store.readback(),
        "arguments": arguments(case),
        "pluginOrder": plugin_order(case),
        "plannedTools": tool_count(case),
    }
    return entry, store


def http(url: str, body: bytes | None = None) -> tuple[int, bytes]:
    """Make one bounded actual request, retaining exact refusal responses too."""
    request = Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        response = urlopen(request, timeout=5)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read(65537)
        require(len(raw) <= 65536, "http-response-bound")
        return response.code, raw


def scripted_model(entry: dict[str, Any]) -> Any:
    """Native BaseLlm emits original typed contents, with no remote inference."""
    from google.adk.models.base_llm import BaseLlm
    from google.adk.models.llm_response import LlmResponse
    from google.genai import types
    from pydantic import PrivateAttr

    from .plugin import native

    class ScriptedLlm(BaseLlm):
        _calls: list[dict[str, Any]] = PrivateAttr(default_factory=list)

        async def generate_content_async(
            self, llm_request: Any, stream: bool = False
        ) -> Any:
            index = len(self._calls)
            if index < entry["plannedTools"]:
                content = types.Content(
                    role="model",
                    parts=[
                        types.Part(
                            function_call=types.FunctionCall(
                                name="dispatch_ticket",
                                args=entry["arguments"],
                                id=entry["id"] + "-" + str(index),
                            )
                        )
                    ],
                )
            else:
                content = types.Content(
                    role="model", parts=[types.Part(text="complete")]
                )
            response = LlmResponse(content=content)
            self._calls.append(
                {
                    "index": index,
                    "request": native(llm_request),
                    "response": native(response),
                }
            )
            yield response

    return ScriptedLlm(model="probity-scripted-no-inference")


def tool_for(entry: dict[str, Any], url: str, calls: list[dict[str, Any]]) -> Any:
    """Retain original tool effects and errors before any plugin can handle them."""

    def dispatch_ticket(content: str) -> dict[str, Any]:
        """Update the selected synthetic protected ticket using literal content."""
        index = len(calls)
        case = entry["id"]
        record: dict[str, Any] = {
            "id": case + "-" + str(index),
            "arguments": {"content": content},
        }
        calls.append(record)
        before = (
            case == "unhandled-before"
            or case.startswith("exhausted-")
            or (case.startswith("handled-") and index == 0)
        )
        if before:
            record["error"] = {"type": "RuntimeError", "message": BEFORE_ERROR}
            raise RuntimeError(BEFORE_ERROR)
        if case.startswith("returned-error-") and index == 0:
            from mcp.types import CallToolResult, TextContent

            result = CallToolResult(
                isError=True, content=[TextContent(type="text", text=BEFORE_ERROR)]
            ).model_dump(mode="json", by_alias=True)
            record["result"] = result
            return result
        body = encode(
            {
                "request": entry["request"],
                "grant": entry["grant"],
                "contentHex": content.encode().hex(),
            }
        )
        post_status, post_raw = http(url + "/dispatch", body)
        get_status, get_raw = http(url + "/tickets/tenant/" + case)
        record["http"] = {
            "endpoint": url,
            "postRequestHex": body.hex(),
            "postStatus": post_status,
            "postResponseHex": post_raw.hex(),
            "getStatus": get_status,
            "getResponseHex": get_raw.hex(),
        }
        result = {
            "httpSha256": sha(encode(record["http"])),
            "postStatus": post_status,
            "nativeRevision": decode(get_raw)["revision"],
        }
        record["result"] = result
        if case == "unhandled-after":
            record["error"] = {"type": "RuntimeError", "message": AFTER_ERROR}
            raise RuntimeError(AFTER_ERROR)
        return result

    return dispatch_ticket


def retry_plugin() -> Any:
    """Use native ReflectAndRetry handling with explicit typed isError extraction."""
    from google.adk.plugins.reflect_retry_tool_plugin import ReflectAndRetryToolPlugin

    class TypedErrorRetry(ReflectAndRetryToolPlugin):
        async def extract_error_from_result(
            self, *, tool: Any, tool_args: Any, tool_context: Any, result: Any
        ) -> Any:
            return (
                result
                if isinstance(result, dict) and result.get("isError") is True
                else None
            )

    return TypedErrorRetry(name="probity_reflect_retry", max_retries=1)


async def invocation(entry: dict[str, Any], tool: Any) -> dict[str, Any]:
    """Actual native async Runner, plugin ordering and full session history."""
    from contextlib import aclosing

    from google.adk import Agent, Runner
    from google.adk.agents.run_config import RunConfig
    from google.adk.apps.app import App
    from google.adk.sessions import InMemorySessionService
    from google.genai import types

    from .plugin import CapturePlugin, native

    collector = CapturePlugin(capture_payloads=True)
    retry = retry_plugin()
    plugins = {"probity_capture": collector, "probity_reflect_retry": retry}
    model = scripted_model(entry)
    app = App(
        name="probity_ticket_reference",
        root_agent=Agent(name="probity_ticket", model=model, tools=[tool]),
        plugins=[plugins[name] for name in entry["pluginOrder"]],
    )
    sessions = InMemorySessionService()
    session = await sessions.create_session(
        app_name=app.name, user_id="synthetic-user", session_id=entry["id"]
    )
    runner = Runner(app=app, session_service=sessions)
    try:
        events = []
        terminal = {"status": "complete", "exception": None}
        try:
            async with aclosing(
                runner.run_async(
                    user_id="synthetic-user",
                    session_id=session.id,
                    new_message=types.Content(
                        role="user", parts=[types.Part(text=PROMPT)]
                    ),
                    run_config=RunConfig(max_llm_calls=3),
                )
            ) as stream:
                async for event in stream:
                    events.append(native(event))
                    if (
                        entry["id"] == "incomplete-close"
                        and event.get_function_responses()
                    ):
                        terminal = {"status": "incomplete", "exception": None}
                        break
        except RuntimeError as error:
            terminal = {
                "status": "error",
                "exception": {"type": type(error).__name__, "message": str(error)},
            }
        retained = await sessions.get_session(
            app_name=app.name, user_id="synthetic-user", session_id=session.id
        )
    finally:
        await runner.close()
    return {
        "modelCalls": model._calls,
        "events": events,
        "sessionEvents": [native(event) for event in retained.events],
        "capture": collector.snapshot(),
        "terminal": terminal,
    }


def execute(entry: dict[str, Any], store: TicketStore) -> dict[str, Any]:
    """Execute a finite invocation; resource and effect state remain separate."""
    started = time.monotonic_ns()
    cpu_started = time.process_time_ns()
    calls: list[dict[str, Any]] = []
    with running_server(store) as server:
        execution = asyncio.run(invocation(entry, tool_for(entry, server.url, calls)))
        final_status, final_raw = http(server.url + "/tickets/tenant/" + entry["id"])
    execution.update(
        toolCalls=calls,
        finalGetStatus=final_status,
        finalReadbackHex=final_raw.hex(),
        elapsedNs=time.monotonic_ns() - started,
        cpuNs=time.process_time_ns() - cpu_started,
    )
    return execution


def run(output: Path, revision: str = "working-tree") -> dict[str, Any]:
    """Freeze all attempts and installed source bytes before actual native runs."""
    from .reader import verify_saved

    output.mkdir(parents=True, exist_ok=False)
    require(metadata.version("google-adk") == VERSION, "sdk-version")
    source_manifest = sources(output)
    write(output / "source-manifest-before-run.json", encode(source_manifest))
    start = datetime.now(timezone.utc)
    run_id = "adk-reference-" + uuid4().hex
    with TemporaryDirectory() as temporary:
        pairs = [host(Path(temporary), run_id, case) for case in CASES]
        plan = {
            "profile": PROFILE,
            "sdkVersion": VERSION,
            "sourceRevision": revision,
            "selectedTime": start.isoformat(),
            "runId": run_id,
            "model": "scripted native BaseLlm; no inference",
            "modelQuality": "not-evaluated",
            "prompt": PROMPT,
            "capturePayloads": True,
            "telemetry": "no exporter configured; no provider request",
            "budget": {
                "plannedAttempts": 12,
                "maxModelCalls": 25,
                "maxToolCalls": 18,
                "maxElapsedSeconds": 120,
            },
            "sourceManifestSha256": sha(encode(source_manifest)),
            "cases": [entry for entry, _ in pairs],
        }
        write(output / "plan-before-run.json", encode(plan))
        for entry, store in pairs:
            write(
                output / "artifacts" / (entry["id"] + ".json"),
                encode(execute(entry, store)),
            )
    artifacts = {
        path.name: sha(path.read_bytes())
        for path in sorted((output / "artifacts").iterdir())
    }
    write(output / "artifact-manifest.json", encode(artifacts))
    pins = {
        "profile": PROFILE,
        "planSha256": sha(encode(plan)),
        "sourceManifestSha256": sha(encode(source_manifest)),
        "artifactManifestSha256": sha(encode(artifacts)),
        "consumerTime": datetime.now(timezone.utc).isoformat(),
    }
    write(output / "consumer-pins.json", encode(pins))
    report = verify_saved(output, pins)
    write(output / "report.json", encode(report))
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--source-revision", default="working-tree")
    args = parser.parse_args()
    print(encode(run(args.output, args.source_revision)).decode())
