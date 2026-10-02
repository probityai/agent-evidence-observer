"""Source-native A2A caller/history boundaries with real SQL competing commits."""

from __future__ import annotations

import asyncio
import json

import httpx
from google.protobuf.json_format import MessageToDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from starlette.applications import Starlette

from a2a.auth.user import User
from a2a.helpers.proto_helpers import new_task_from_user_message
from a2a.server.agent_execution.agent_executor import AgentExecutor
from a2a.server.cluster.database_event_stream import DatabaseTaskEventStream
from a2a.server.cluster.database_task_store import VersionedDatabaseTaskStore
from a2a.server.cluster.task_store import ConcurrentTaskModificationError
from a2a.server.context import ServerCallContext
from a2a.server.models import TaskModel, TaskVersionModel
from a2a.server.request_handlers.default_request_handler_v2 import (
    DefaultRequestHandlerV2,
)
from a2a.server.routes.common import ServerCallContextBuilder
from a2a.server.routes.jsonrpc_routes import create_jsonrpc_routes
from a2a.server.tasks.task_updater import TaskUpdater
from a2a.types.a2a_pb2 import AgentCapabilities, AgentCard, Part, Role
from a2a.utils.errors import A2AError


class FixtureUser(User):
    """One public local fixture actor; no outside authentication claim."""

    @property
    def is_authenticated(self):
        return True

    @property
    def user_name(self):
        return "probity-fixture"


class FixtureContext(ServerCallContextBuilder):
    """Use the same explicit owner across two native replicas and a readback."""

    def build(self, request):
        return ServerCallContext(
            user=FixtureUser(), state={"headers": dict(request.headers)}
        )


class InputAgent(AgentExecutor):
    """Deterministic public task agent, without any model or external service."""

    async def execute(self, context, event_queue):
        if context.current_task is None:
            await event_queue.enqueue_event(new_task_from_user_message(context.message))
        updater = TaskUpdater(
            event_queue, str(context.task_id or ""), str(context.context_id or "")
        )
        await updater.requires_input(
            message=updater.new_agent_message(
                [Part(text="public fixture input required")]
            )
        )

    async def cancel(self, context, event_queue):
        pass


class ContendedStore(VersionedDatabaseTaskStore):
    """Schedule actual native commits before CAS; never raise a fabricated error."""

    def __init__(self, engine, competitor, budget, followup):
        super().__init__(engine=engine, create_table=False)
        self.competitor, self.budget, self.followup = competitor, budget, followup
        self.trace = []

    async def save(self, task, *, event=None, prev=None, prev_version, context):
        disrupt = self.budget > 0 and any(
            m.message_id == self.followup for m in task.history
        )
        record = {
            "candidateUserTurns": [
                m.message_id for m in task.history if m.role == Role.ROLE_USER
            ],
            "expectedVersion": repr(prev_version),
            "competingCommit": None,
            "nativeError": None,
            "eventClass": None if event is None else type(event).__name__,
        }
        if disrupt:
            latest = await self.competitor.get(task.id, context)
            committed = await self.competitor.save(
                latest.task,
                event=None,
                prev=latest.task,
                prev_version=latest.version,
                context=context,
            )
            record["competingCommit"] = {
                "before": repr(latest.version),
                "after": repr(committed),
                "persistedUserTurns": [
                    m.message_id
                    for m in latest.task.history
                    if m.role == Role.ROLE_USER
                ],
            }
            self.budget -= 1
        try:
            result = await super().save(
                task, event=event, prev=prev, prev_version=prev_version, context=context
            )
            record["resultVersion"] = repr(result)
            return result
        except ConcurrentTaskModificationError as error:
            record["nativeError"] = {
                "class": type(error).__name__,
                "module": type(error).__module__,
                "message": str(error),
            }
            raise
        finally:
            self.trace.append(record)


class RecordedHandler(DefaultRequestHandlerV2):
    """Retain exact native caller outcomes before native JSON-RPC translation."""

    def __init__(self, store, stream):
        super().__init__(
            agent_executor=InputAgent(),
            task_store=store,
            agent_card=AgentCard(capabilities=AgentCapabilities(streaming=True)),
            event_stream=stream,
        )
        self.outcomes = []

    async def on_message_send(self, params, context):
        try:
            task = await super().on_message_send(params, context)
            self.outcomes.append(
                {
                    "kind": "returned",
                    "class": type(task).__name__,
                    "taskProtoHex": task.SerializeToString().hex(),
                    "task": MessageToDict(task),
                }
            )
            return task
        except A2AError as error:
            self.outcomes.append(
                {
                    "kind": "raised",
                    "class": type(error).__name__,
                    "module": type(error).__module__,
                    "message": str(error),
                    "data": error.data,
                }
            )
            raise


def app(handler):
    """Use the SDK's actual JSON-RPC route and exception translation."""
    return Starlette(routes=create_jsonrpc_routes(handler, "/", FixtureContext()))


async def send(client, message_id, task_id="", context_id=""):
    """Retain literal caller request/reply at the real native ASGI boundary."""
    message = {
        "messageId": message_id,
        "role": "ROLE_USER",
        "parts": [{"text": "public fixture turn"}],
    }
    if task_id:
        message.update(taskId=task_id, contextId=context_id)
    candidate = {
        "jsonrpc": "2.0",
        "id": "rpc-" + message_id,
        "method": "SendMessage",
        "params": {"message": message},
    }
    raw = json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode()
    response = await client.post(
        "/",
        content=raw,
        headers={"content-type": "application/json", "A2A-Version": "1.0"},
    )
    return {
        "requestHex": raw.hex(),
        "requestHeaders": {"content-type": "application/json", "A2A-Version": "1.0"},
        "status": response.status_code,
        "responseHex": response.content.hex(),
        "parsed": response.json(),
    }


async def run_case(dsn, name, budget):
    """Run one native initial turn/follow-up and inspect committed rows independently."""
    engines = [create_async_engine(dsn) for _ in range(4)]
    ctx = ServerCallContext(user=FixtureUser())
    a, competitor, readback = [
        VersionedDatabaseTaskStore(engine=engines[i], create_table=False)
        for i in (0, 2, 3)
    ]
    b = ContendedStore(engines[1], competitor, budget, "followup-" + name)
    handlers = [
        RecordedHandler(
            store,
            DatabaseTaskEventStream(
                engine=engine, create_table=False, poll_interval_s=0.01
            ),
        )
        for store, engine in zip((a, b), engines[:2], strict=True)
    ]
    try:
        async with (
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app(handlers[0])),
                base_url="http://fixture.local",
                timeout=15,
            ) as ca,
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app(handlers[1])),
                base_url="http://fixture.local",
                timeout=15,
            ) as cb,
        ):
            initial = await asyncio.wait_for(send(ca, "initial-" + name), timeout=15)
            task = initial["parsed"]["result"]["task"]
            before = await readback.get(task["id"], ctx)
            followup = await asyncio.wait_for(
                send(cb, "followup-" + name, task["id"], task["contextId"]), timeout=15
            )
            final = await readback.get(task["id"], ctx)
            async with engines[3].connect() as conn:
                native = (
                    (
                        await conn.execute(
                            select(TaskModel.__table__).where(
                                TaskModel.id == task["id"]
                            )
                        )
                    )
                    .mappings()
                    .one()
                )
                versions = (
                    (
                        await conn.execute(
                            select(TaskVersionModel.__table__).where(
                                TaskVersionModel.task_id == task["id"]
                            )
                        )
                    )
                    .mappings()
                    .one()
                )
            row = {
                key: value.isoformat() if hasattr(value, "isoformat") else value
                for key, value in native.items()
            }
            return {
                "id": name,
                "conflictBudget": budget,
                "initial": initial,
                "followup": followup,
                "initialNativeCaller": handlers[0].outcomes,
                "followupNativeCaller": handlers[1].outcomes,
                "before": {
                    "taskProtoHex": before.task.SerializeToString().hex(),
                    "task": MessageToDict(before.task),
                    "version": repr(before.version),
                },
                "final": {
                    "taskProtoHex": final.task.SerializeToString().hex(),
                    "task": MessageToDict(final.task),
                    "version": repr(final.version),
                },
                "sqlRow": row,
                "sqlVersionRow": dict(versions),
                "nativeStoreTrace": b.trace,
                "remainingConflictBudget": b.budget,
            }
    finally:
        await cleanup(handlers, engines)


async def cleanup(handlers, engines):
    """Attempt every native handler and connection cleanup even if another fails."""
    try:
        closed = await asyncio.wait_for(
            asyncio.gather(
                *(handler.aclose() for handler in handlers), return_exceptions=True
            ),
            timeout=5,
        )
    finally:
        disposed = await asyncio.gather(
            *(engine.dispose() for engine in engines), return_exceptions=True
        )
    for error in closed + disposed:
        if isinstance(error, BaseException):
            raise error
