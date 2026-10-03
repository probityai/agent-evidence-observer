"""Exercise native ADK Runner and A2A transport after signed target writes."""
from __future__ import annotations

import argparse
import asyncio
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

from .contract import (
    A2A_VERSION, CASES, CONTENT, FAILURE, PROFILE, REVISIONS, SDK_VERSION,
    encode, identity, population, require, sha,
)
from .source import snapshot_sources


def native_app(case: str, authorized: AuthorizedBroker, request: ActionRequest,
               trace: list[dict[str, Any]], wire: list[dict[str, Any]]) -> Any:
    """Build a real plain-A2A server with task store and JSONRPC/SSE routes.

    Parameters
    ----------
    case : str
        One literal case from :data:`.contract.CASES`.
    authorized : AuthorizedBroker
        Signed request-bound target writer. Only this boundary writes bytes.
    request : ActionRequest
        Exact host-selected authorized action.
    trace, wire : list of dict
        Append-only server boundary rows and exact ASGI request/response body
        bytes. HTTP runs through ``ASGITransport``, without external services.

    Returns
    -------
    Any
        ASGI callable serving the native A2A request handler and transport.
    """
    from a2a.client.card_resolver import parse_agent_card
    from a2a.helpers.proto_helpers import new_task
    from a2a.server.agent_execution import AgentExecutor
    from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
    from a2a.types import Part, TaskState
    from google.adk.a2a import _compat
    from starlette.applications import Starlette

    class Executor(AgentExecutor):
        """Commit an effect before selecting the remote terminal outcome."""
        async def execute(self, context: Any, event_queue: Any) -> None:
            task_id, context_id = context.task_id, context.context_id
            trace.append({"kind": "request", "taskId": task_id, "contextId": context_id})
            await event_queue.enqueue_event(new_task(
                task_id, context_id, TaskState.TASK_STATE_SUBMITTED))
            updater = TaskUpdater(event_queue, task_id, context_id)
            await updater.start_work(message=updater.new_agent_message([Part(text="working")]))
            if CASES[case].effects:
                authorized.write(request, CONTENT.encode())
                trace.append({"kind": "effect", "committed": True, "request": asdict(request)})
            if case in {"status-after-content", "dropped-closure"}:
                await updater.start_work(message=updater.new_agent_message([Part(text="done")]))
            failed = case != "permit"
            text = None if case == "failed-after-bare" else FAILURE if failed else "done"
            message = updater.new_agent_message([Part(text=text)]) if text else None
            if failed:
                await updater.failed(message=message)
            else:
                await updater.complete(message=message)
            trace.append({"kind": "terminal", "state": "FAILED" if failed else "COMPLETED",
                          "text": text, "taskId": task_id, "contextId": context_id})

        async def cancel(self, context: Any, event_queue: Any) -> None:
            """Refuse cancellation outside this finite profile."""
            raise RuntimeError("cancellation is outside this profile")

    card = parse_agent_card({
        "name": "remote", "description": "Finite native failed-task fixture",
        "version": "1", "url": "http://127.0.0.1:8000/", "preferredTransport": "JSONRPC",
        "capabilities": {"streaming": True}, "defaultInputModes": ["text"],
        "defaultOutputModes": ["text"], "skills": [],
    })
    app = Starlette()
    _compat.attach_a2a_routes_to_app(app, agent_card=card, agent_executor=Executor(),
                                  task_store=InMemoryTaskStore())

    async def capture(scope: Any, receive: Any, send: Any) -> None:
        """Retain exact native transport bodies before the client consumes them."""
        async def retained_receive() -> Any:
            message = await receive()
            if message["type"] == "http.request":
                wire.append({"direction": "request", "path": scope["path"],
                             "body": message.get("body", b"").decode("utf-8"),
                             "moreBody": message.get("more_body", False)})
            return message

        async def retained_send(message: Any) -> None:
            if message["type"] == "http.response.body":
                wire.append({"direction": "response", "path": scope["path"],
                             "body": message.get("body", b"").decode("utf-8"),
                             "moreBody": message.get("more_body", False)})
            await send(message)

        await app(scope, retained_receive, retained_send)

    return capture


def event_state(event: Any) -> Any:
    """Get the actual A2A response state retained by the native converter."""
    response = (event.custom_metadata or {}).get("a2a:response") or {}
    return (response.get("status") or {}).get("state")


async def consume(app: Any, case: str, streaming: bool) -> dict[str, Any]:
    """Invoke the public RemoteA2aAgent/Runner and retain session events.

    No native converter or handler is mocked or replaced. The dropped-closure
    control explicitly closes the caller's event generator after its ``done``
    working message; it therefore records an incomplete caller capture.
    """
    import httpx
    from a2a.client.client import ClientConfig
    from a2a.client.client_factory import ClientFactory
    from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
    from google.adk.runners import Runner
    from google.adk.sessions.in_memory_session_service import InMemorySessionService
    from google.genai import types

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), timeout=30) as client:
        agent = RemoteA2aAgent(
            name="remote", agent_card="http://127.0.0.1:8000/.well-known/agent-card.json",
            a2a_client_factory=ClientFactory(config=ClientConfig(
                streaming=streaming, httpx_client=client)),
        )
        runner = Runner(app_name="native-failure", agent=agent,
                        session_service=InMemorySessionService())
        session = await runner.session_service.create_session(app_name="native-failure", user_id="u")
        events: list[dict[str, Any]] = []
        stream = runner.run_async(
            user_id="u", session_id=session.id,
            new_message=types.Content(role="user", parts=[types.Part(text=case)]),
        )
        complete = True
        async for event in stream:
            row = event.model_dump(mode="json")
            text = " ".join(part.text for part in (event.content.parts if event.content else []) if part.text)
            events.append({"event": row, "isFinalResponse": event.is_final_response(),
                           "state": event_state(event), "text": text})
            if case == "dropped-closure" and text == "done":
                complete = False
                await stream.aclose()
                break
        retained = await runner.session_service.get_session(
            app_name="native-failure", user_id="u", session_id=session.id)
        return {"events": events, "sessionEvents": [event.model_dump(mode="json")
                for event in retained.events], "callerComplete": complete}


def run_case(root: Path, case: str, streaming: bool, variant: str) -> dict[str, Any]:
    """Retain native closure and signed effects as separate evidence objects."""
    root.mkdir()
    work = root / "work"
    work.mkdir()
    issuer, observer, witness = (SigningKey.generate() for _ in range(3))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    case_id = identity(case, streaming)
    request = ActionRequest(case_id, "attempt-1", "request-1", "tenant-1", "principal-1",
                            "write_result", "/work/result.txt", sha(CONTENT.encode()))
    grant = issue_grant(request, issuer, issued_at=now, expires_at=now + timedelta(seconds=300))
    broker = Broker(work, root / "history.jsonl",
                    {"intervalId": case_id, "scope": "/work", "operation": "write-file"},
                    observer, Witness(root / "witness.json", witness))
    authorized = AuthorizedBroker(broker, grant, GrantPolicy(issuer.public_hex), request)
    broker.begin()
    trace: list[dict[str, Any]] = []
    wire: list[dict[str, Any]] = []
    app = native_app(case, authorized, request, trace, wire)
    capture = asyncio.run(consume(app, case, streaming))
    packet = authorized.seal() if CASES[case].effects else broker.seal()
    native = {"profile": PROFILE, "case": case, "streaming": streaming, "variant": variant,
              "sdkVersion": SDK_VERSION, "a2aVersion": A2A_VERSION, "serverTrace": trace,
              **capture}
    for name, value in (("packet.json", packet), ("grant.json", grant),
                        ("native.json", native), ("wire.json", wire)):
        (root / name).write_bytes(encode(value))
    return {"request": asdict(request), "issuerKey": issuer.public_hex,
            "observerKey": observer.public_hex, "witnessKey": witness.public_hex,
            "referenceTime": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "artifacts": {name: sha((root / name).read_bytes()) for name in
                          ("grant.json", "history.jsonl", "native.json", "packet.json", "wire.json")}}


def produce(output: Path, variant: str) -> dict[str, Any]:
    """Qualify source before native imports, then run the finite population.

    Parameters
    ----------
    output : pathlib.Path
        New directory containing ``packet/`` and an external host policy.
    variant : str
        Independently selected ``baseline`` or ``proposed-fix`` source pin.

    Returns
    -------
    dict[str, Any]
        Host-selected keys, requests, original bytes and source-manifest pin.
        The installed reader requires this policy's digest explicitly.

    Raises
    ------
    ValueError
        If the output already exists or installed native source differs.
    """
    require(variant in REVISIONS, "unknown SDK variant")
    require(not output.exists(), "producer output already exists")
    output.mkdir()
    packet = output / "packet"
    packet.mkdir()
    sources = snapshot_sources(packet, variant)
    policy = {"schema": "probity.adk-a2a-failure-host-policy.v1", "profile": PROFILE,
              "variant": variant, "sdk": {"version": SDK_VERSION, "commit": REVISIONS[variant],
                                         "a2aVersion": A2A_VERSION},
              "sourceManifestSha256": sha(encode(sources)),
              "cases": {identity(case, streaming): run_case(packet / identity(case, streaming),
                        case, streaming, variant) for case, streaming in population()}}
    (output / "host-policy.json").write_bytes(encode(policy))
    return policy


def main() -> None:
    """Run the installed producer for an explicitly selected native variant."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--variant", choices=list(REVISIONS), required=True)
    args = parser.parse_args()
    produce(args.output, args.variant)


if __name__ == "__main__":
    main()
