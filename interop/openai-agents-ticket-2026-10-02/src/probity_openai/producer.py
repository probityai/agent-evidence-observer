"""Execute the installed SDK with scripted Model and real protected HTTP effects."""

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
    require,
    sha,
    write,
)


def sources(output: Path) -> dict[str, str]:
    """Freeze installed adapter, SDK and protected-target source bytes."""
    import agents
    import probity_observer

    manifest = {}
    packages = {
        "adapter": Path(__file__).parent,
        "observer": Path(probity_observer.__file__).parent,
        "agents": Path(agents.__file__).parent,
    }
    for label, folder in packages.items():
        for path in sorted(folder.rglob("*.py")):
            name = label + "/" + str(path.relative_to(folder))
            raw = path.read_bytes()
            write(output / "sources" / name, raw)
            manifest[name] = sha(raw)
    distribution = metadata.distribution("openai-agents")
    for entry in distribution.files or []:
        if str(entry).endswith((".dist-info/METADATA", ".dist-info/licenses/LICENSE")):
            raw = distribution.locate_file(entry).read_bytes()
            name = "distribution/" + Path(str(entry)).name
            write(output / "sources" / name, raw)
            manifest[name] = sha(raw)
    versions = {
        name: metadata.version(name)
        for name in (
            "openai-agents",
            "openai",
            "pydantic",
            "cryptography",
            "agent-evidence-observer",
            "probity-openai-agents-reference",
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
        "traceId": "trace_" + uuid4().hex,
        "maxTurns": 1 if case == "turns-exhausted" else 2,
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
    """Use real ModelResponse and native generation spans, with no remote inference."""
    from agents import Model, ModelResponse, Usage, generation_span
    from openai.types.responses import (
        ResponseFunctionToolCall,
        ResponseOutputMessage,
        ResponseOutputText,
    )

    class ScriptedModel(Model):
        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []

        async def get_response(
            self,
            system_instructions: Any,
            input: Any,
            model_settings: Any,
            tools: Any,
            output_schema: Any,
            handoffs: Any,
            tracing: Any,
            **kwargs: Any,
        ) -> Any:
            index = len(self.calls)
            with generation_span(model="probity-scripted-no-inference") as span:
                if index == 0:
                    output = [
                        ResponseFunctionToolCall(
                            type="function_call",
                            id="item-" + entry["id"],
                            call_id=entry["id"] + "-0",
                            name="dispatch_ticket",
                            arguments=encode(entry["arguments"]).decode(),
                            status="completed",
                        )
                    ]
                else:
                    output = [
                        ResponseOutputMessage(
                            type="message",
                            id="final-" + entry["id"],
                            role="assistant",
                            content=[
                                ResponseOutputText(
                                    type="output_text", text="complete", annotations=[]
                                )
                            ],
                            status="completed",
                        )
                    ]
                response = ModelResponse(output=output, usage=Usage(), response_id=None)
                native = response.to_input_items()
                span.span_data.input = (
                    [{"content": input}] if isinstance(input, str) else input
                )
                span.span_data.output = native
                self.calls.append(
                    {
                        "index": index,
                        "input": input,
                        "output": native,
                        "usage": {
                            "requests": response.usage.requests,
                            "input_tokens": response.usage.input_tokens,
                            "output_tokens": response.usage.output_tokens,
                            "total_tokens": response.usage.total_tokens,
                            "input_tokens_details": (
                                response.usage.input_tokens_details.model_dump()
                            ),
                            "output_tokens_details": (
                                response.usage.output_tokens_details.model_dump()
                            ),
                            "request_usage_entries": [],
                        },
                    }
                )
                return response

        async def stream_response(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("streaming is outside this finite profile")
            yield None

    return ScriptedModel()


def tool_for(entry: dict[str, Any], url: str, calls: list[dict[str, Any]]) -> Any:
    """Expose native function_tool dispatch and preserve terminal errors."""
    from agents import function_tool

    @function_tool(failure_error_function=None)
    def dispatch_ticket(content: str) -> str:
        """Update the selected synthetic protected ticket using the literal content."""
        record: dict[str, Any] = {
            "id": entry["id"] + "-0",
            "arguments": {"content": content},
        }
        calls.append(record)
        if entry["id"] == "producer-error":
            record["error"] = BEFORE_ERROR
            raise RuntimeError(BEFORE_ERROR)
        body = encode(
            {
                "request": entry["request"],
                "grant": entry["grant"],
                "contentHex": content.encode().hex(),
            }
        )
        post_status, post_raw = http(url + "/dispatch", body)
        get_status, get_raw = http(url + "/tickets/tenant/" + entry["id"])
        record["http"] = {
            "endpoint": url,
            "postRequestHex": body.hex(),
            "postStatus": post_status,
            "postResponseHex": post_raw.hex(),
            "getStatus": get_status,
            "getResponseHex": get_raw.hex(),
        }
        result = encode(
            {
                "httpSha256": sha(encode(record["http"])),
                "postStatus": post_status,
                "nativeRevision": decode(get_raw)["revision"],
            }
        ).decode()
        record["result"] = result
        if entry["id"] == "committed-effect-error":
            record["error"] = AFTER_ERROR
            raise RuntimeError(AFTER_ERROR)
        return result

    return dispatch_ticket


def execute(entry: dict[str, Any], store: TicketStore) -> dict[str, Any]:
    """Run Runner and retain task terminal state separately from native effect state."""
    from agents import (
        Agent,
        MaxTurnsExceeded,
        RunConfig,
        Runner,
        UserError,
        set_trace_processors,
    )

    from .processor import LocalTraceProcessor

    processor = LocalTraceProcessor(capture_payloads=True)
    set_trace_processors([processor])
    model = scripted_model(entry)
    calls: list[dict[str, Any]] = []
    started = time.monotonic_ns()
    cpu_started = time.process_time_ns()
    with running_server(store) as server:
        agent = Agent(
            name="probity_synthetic_ticket",
            model=model,
            tools=[tool_for(entry, server.url, calls)],
        )
        config = RunConfig(
            workflow_name="probity_synthetic_ticket",
            trace_id=entry["traceId"],
            trace_include_sensitive_data=True,
        )
        terminal = {"status": "complete", "output": None, "exception": None}
        try:
            result = asyncio.run(
                Runner.run(
                    agent, PROMPT, max_turns=entry["maxTurns"], run_config=config
                )
            )
            terminal["output"] = result.final_output
        except (UserError, MaxTurnsExceeded) as error:
            terminal = {
                "status": "incomplete"
                if isinstance(error, MaxTurnsExceeded)
                else "error",
                "output": None,
                "exception": {"type": type(error).__name__, "message": str(error)},
            }
        final_status, final_raw = http(server.url + "/tickets/tenant/" + entry["id"])
    processor.force_flush()
    processor.shutdown()
    return {
        "toolCalls": calls,
        "modelCalls": model.calls,
        "terminal": terminal,
        "trace": processor.snapshot(),
        "finalGetStatus": final_status,
        "finalReadbackHex": final_raw.hex(),
        "elapsedNs": time.monotonic_ns() - started,
        "cpuNs": time.process_time_ns() - cpu_started,
    }


def run(output: Path, revision: str = "working-tree") -> dict[str, Any]:
    """Freeze the complete source/population plan before any native execution."""
    from .reader import verify_saved

    output.mkdir(parents=True, exist_ok=False)
    require(metadata.version("openai-agents") == VERSION, "sdk-version")
    source_manifest = sources(output)
    write(output / "source-manifest-before-run.json", encode(source_manifest))
    start = utc_clock()
    run_id = "openai-reference-" + uuid4().hex
    with TemporaryDirectory() as temporary:
        pairs = [host(Path(temporary), run_id, case) for case in CASES]
        plan = {
            "profile": PROFILE,
            "sdkVersion": VERSION,
            "sourceRevision": revision,
            "selectedTime": start.isoformat(),
            "runId": run_id,
            "model": "scripted native Model; no inference",
            "modelQuality": "not-evaluated",
            "prompt": PROMPT,
            "capturePayloads": True,
            "defaultExporter": "replaced before any execution",
            "budget": {
                "plannedAttempts": 6,
                "maxModelCalls": 9,
                "maxToolCalls": 6,
                "maxElapsedSeconds": 90,
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
