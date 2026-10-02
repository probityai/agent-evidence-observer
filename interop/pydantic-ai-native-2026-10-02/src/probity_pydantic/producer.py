"""Run actual Pydantic AI FunctionModel tools against local protected HTTP."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from importlib import metadata
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from probity_observer.authorization import (
    ActionRequest,
    GrantPolicy,
    issue_grant,
    utc_clock,
)
from probity_observer.crypto import SigningKey
from probity_observer.ticket_service import TicketStore, running_server

from .contract import (
    CASES,
    CONTENT,
    ERROR,
    PROFILE,
    PROMPT,
    RETRY,
    VERSION,
    decode,
    encode,
    require,
    script,
    sha,
    write,
)


def http_bytes(url: str, body: bytes | None = None) -> tuple[int, bytes]:
    """Perform one bounded HTTP request and retain exact refusal response bytes.

    Parameters
    ----------
    url : str
        Local service route selected by the executing producer.
    body : bytes or None
        Exact canonical POST body; ``None`` selects GET.

    Returns
    -------
    tuple[int, bytes]
        HTTP status and original response bytes. No network retry is performed.
    """
    request = Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        response = urlopen(request, timeout=5)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read(65537)
        require(len(raw) <= 65536, "HTTP response exceeds bound")
        return response.code, raw


def distribution_bytes(distribution: metadata.Distribution, name: str) -> bytes:
    """Read exact installed metadata/license bytes without text normalization."""
    suffix = ".dist-info/" + name
    files = [entry for entry in distribution.files or [] if str(entry).endswith(suffix)]
    require(len(files) == 1, "framework provenance missing")
    return distribution.locate_file(files[0]).read_bytes()


def capture_sources(output: Path) -> dict[str, str]:
    """Retain exact installed producer, service, framework and metadata sources.

    Notes
    -----
    These files authenticate only the selected record provenance. Python source
    hashes do not prove that an independently witnessed process executed them.
    The Pydantic AI MIT license is retained beside installed framework sources.
    """
    import probity_observer
    import pydantic_ai

    packages = {
        "adapter": Path(__file__).parent,
        "observer": Path(probity_observer.__file__).parent,
        "pydantic_ai": Path(pydantic_ai.__file__).parent,
    }
    manifest = {}
    for label, folder in packages.items():
        for path in sorted(folder.rglob("*.py")):
            name = label + "/" + str(path.relative_to(folder))
            raw = path.read_bytes()
            write(output / "sources" / name, raw)
            manifest[name] = sha(raw)
    distribution = metadata.distribution("pydantic-ai-slim")
    for name in ("METADATA", "licenses/LICENSE"):
        raw = distribution_bytes(distribution, name)
        target = "distribution/" + name
        write(output / "sources" / target, raw)
        manifest[target] = sha(raw)
    versions = {
        name: metadata.version(name)
        for name in (
            "pydantic-ai-slim",
            "pydantic-graph",
            "pydantic",
            "cryptography",
            "agent-evidence-observer",
        )
    }
    write(output / "sources" / "distribution/versions.json", encode(versions))
    manifest["distribution/versions.json"] = sha(encode(versions))
    return manifest


def prepare(
    output: Path, revision: str
) -> tuple[dict[str, Any], dict[str, TicketStore]]:
    """Freeze five cases, exact grants and source bytes before any agent runs.

    Parameters
    ----------
    output : Path
        New artifact directory. Existing directories are refused.
    revision : str
        Source revision selected by CI or the author; retained as provenance.

    Returns
    -------
    tuple[dict[str, Any], dict[str, TicketStore]]
        Public frozen plan and in-memory host handles. Host private keys and
        SQLite stores remain in a temporary directory supplied by :func:`run`.
    """
    output.mkdir(parents=True, exist_ok=False)
    (output / "artifacts").mkdir()
    require(
        metadata.version("pydantic-ai-slim") == VERSION, "framework version differs"
    )
    source = capture_sources(output)
    write(output / "source-manifest-before-run.json", encode(source))
    now = utc_clock()
    plan = {
        "profile": PROFILE,
        "frameworkVersion": VERSION,
        "model": "FunctionModel scripted local function",
        "modelQuality": "not-evaluated",
        "prompt": PROMPT,
        "retries": 1,
        "sourceRevision": revision,
        "sourceManifestSha256": sha(encode(source)),
        "selectedTime": now.isoformat(),
        "runId": "pydantic-reference-" + now.strftime("%Y%m%dT%H%M%S"),
        "cases": [],
    }
    return plan, {}


def create_host(
    directory: Path, plan: dict[str, Any], case: str
) -> tuple[dict[str, Any], TicketStore]:
    """Initialize one independently identified local row with separate role keys."""
    issuer, service = SigningKey.generate(), SigningKey.generate()
    now = utc_clock()
    request = ActionRequest(
        plan["runId"],
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
        "contentHex": CONTENT.encode().hex(),
        "initial": store.readback(),
        "script": script(case),
    }
    return entry, store


def scripted_model(name: str, sequence: list[str]) -> Any:
    """Create the real native FunctionModel with a frozen local response script.

    Parameters
    ----------
    name : str
        Selected case identifier used in native tool call IDs.
    sequence : list[str]
        Exact arguments selected before execution by :func:`prepare`.

    Returns
    -------
    pydantic_ai.models.function.FunctionModel
        Native testing model. It makes no remote provider request and performs
        no inference; message usage counters are local estimates only.
    """
    from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
    from pydantic_ai.models.function import FunctionModel

    model_calls = 0

    def local_model(messages: Any, info: Any) -> ModelResponse:
        """Supply the fixed call sequence through the native model interface."""
        nonlocal model_calls
        index = model_calls
        model_calls += 1
        if index < len(sequence):
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "dispatch_ticket",
                        {"content": sequence[index]},
                        tool_call_id=f"{name}-{index}",
                    )
                ]
            )
        return ModelResponse(parts=[TextPart("complete")])

    return FunctionModel(local_model)


def execute(output: Path, entry: dict[str, Any], store: TicketStore) -> None:
    """Run native typed tools and retain complete message history on exceptions.

    Notes
    -----
    ``FunctionModel`` supplies fixed calls rather than inference. Pydantic AI
    owns validation, tool dispatch, retry messages and its serialized history.
    :func:`http_bytes` performs actual HTTP POST and separate GET operations.
    A selected producer failure is retained as an error, never a task success.
    """
    from pydantic_ai import Agent, ModelRetry, capture_run_messages
    from pydantic_ai.messages import ModelMessagesTypeAdapter

    name = entry["id"]
    sequence = entry["script"]
    tool_calls = 0
    trace = []
    agent = Agent(
        scripted_model(name, sequence), retries=1, name="probity_ticket_reference"
    )
    with running_server(store) as server:

        @agent.tool_plain
        def dispatch_ticket(content: str) -> str:
            """Dispatch one typed content string through the selected ticket gate.

            Parameters
            ----------
            content : str
                Actual framework-validated tool argument. Its UTF-8 bytes are
                sent unchanged, including the changed-argument refusal case.

            Returns
            -------
            str
                Canonical digest/status join to the retained exact HTTP packet.
            """
            nonlocal tool_calls
            index = tool_calls
            tool_calls += 1
            identity = f"{name}-{index}"
            if name == "retry" and index == 0:
                trace.append(
                    {
                        "id": identity,
                        "arguments": {"content": content},
                        "outcome": "retry",
                        "reason": RETRY,
                    }
                )
                raise ModelRetry(RETRY)
            if name == "producer-error":
                trace.append(
                    {
                        "id": identity,
                        "arguments": {"content": content},
                        "outcome": "error",
                        "reason": ERROR,
                    }
                )
                raise RuntimeError(ERROR)
            candidate = {
                "request": entry["request"],
                "grant": entry["grant"],
                "contentHex": content.encode().hex(),
            }
            body = encode(candidate)
            status, response = http_bytes(server.url + "/dispatch", body)
            get_status, readback = http_bytes(server.url + "/tickets/tenant/" + name)
            packet = {
                "endpoint": server.url,
                "postPath": "/dispatch",
                "getPath": "/tickets/tenant/" + name,
                "postRequestHex": body.hex(),
                "postStatus": status,
                "postResponseHex": response.hex(),
                "getStatus": get_status,
                "getResponseHex": readback.hex(),
            }
            raw = encode(packet)
            filename = identity + "-http.json"
            write(output / "artifacts" / filename, raw)
            result = encode(
                {
                    "httpSha256": sha(raw),
                    "postStatus": status,
                    "nativeRevision": decode(readback)["revision"],
                }
            ).decode()
            trace.append(
                {
                    "id": identity,
                    "arguments": {"content": content},
                    "outcome": "return",
                    "artifact": filename,
                    "result": result,
                }
            )
            return result

        terminal = {"status": "complete", "output": None, "exception": None}
        with capture_run_messages() as messages:
            try:
                result = agent.run_sync(PROMPT)
                terminal["output"] = result.output
            except RuntimeError as error:
                require(str(error) == ERROR, "unexpected producer error")
                terminal = {
                    "status": "error",
                    "output": None,
                    "exception": {"type": type(error).__name__, "message": str(error)},
                }
        write(
            output / "artifacts" / (name + "-messages.json"),
            ModelMessagesTypeAdapter.dump_json(messages),
        )
        _, final = http_bytes(server.url + "/tickets/tenant/" + name)
    write(
        output / "artifacts" / (name + "-execution.json"),
        encode({"trace": trace, "terminal": terminal, "finalReadbackHex": final.hex()}),
    )


def run(output: Path, revision: str = "working-tree") -> dict[str, Any]:
    """Create a fresh packet, execute all cases and invoke the offline reader."""
    from tempfile import TemporaryDirectory

    from .reader import verify_saved

    plan, hosts = prepare(output, revision)
    with TemporaryDirectory(prefix="probity-pydantic-host-") as temporary:
        for case in CASES:
            entry, host = create_host(Path(temporary), plan, case)
            plan["cases"].append(entry)
            hosts[case] = host
        write(output / "plan-before-run.json", encode(plan))
        for entry in plan["cases"]:
            execute(output, entry, hosts[entry["id"]])
    manifest = {
        path.name: sha(path.read_bytes())
        for path in sorted((output / "artifacts").iterdir())
    }
    write(output / "artifact-manifest.json", encode(manifest))
    selected = {
        "planSha256": sha(encode(plan)),
        "sourceManifestSha256": plan["sourceManifestSha256"],
        "artifactManifestSha256": sha(encode(manifest)),
        "evaluationTime": datetime.now(timezone.utc).isoformat(),
    }
    write(output / "consumer-pins.json", encode(selected))
    report = verify_saved(output, selected)
    write(output / "report.json", encode(report))
    return report


def main() -> None:
    """Execute a new bounded reference packet through the installed CLI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--source-revision", default="working-tree")
    args = parser.parse_args()
    print(encode(run(args.output, args.source_revision)).decode())
