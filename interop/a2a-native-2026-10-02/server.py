"""Run the pinned SDK's JSON-RPC server in a separate loopback process."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path

import uvicorn
from a2a.helpers.proto_helpers import new_text_message
from a2a.server.agent_execution import AgentExecutor
from a2a.server.request_handlers import DefaultRequestHandlerV2
from a2a.server.routes.agent_card_routes import create_agent_card_routes
from a2a.server.routes.jsonrpc_routes import create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types.a2a_pb2 import AgentCard, AgentInterface, Task, TaskState, TaskStatus
from starlette.applications import Starlette


class ArithmeticAgent(AgentExecutor):
    def __init__(self, events):
        self.events = events

    async def execute(self, context, event_queue):
        text = context.get_user_input()
        with self.events.open("ab") as output:
            output.write(
                (
                    json.dumps(
                        {
                            "message_id": context.message.message_id,
                            "context_id": context.context_id,
                            "task_id": context.task_id,
                            "input": text,
                        },
                        sort_keys=True,
                    )
                    + "\n"
                ).encode()
            )
            output.flush()
            os.fsync(output.fileno())
        if text == "wait":
            await asyncio.Event().wait()
        elif text == "task-failed":
            await event_queue.enqueue_event(
                Task(
                    id=context.task_id,
                    context_id=context.message.context_id,
                    status=TaskStatus(state=TaskState.TASK_STATE_FAILED),
                    history=[context.message],
                )
            )
        elif text == "reject":
            raise ValueError("declared rejection control")
        else:
            left, right = text.split("+")
            message = new_text_message(str(int(left) + int(right)))
            message.message_id = "reply-" + context.message.message_id
            await event_queue.enqueue_event(message)

    async def cancel(self, context, event_queue):
        raise NotImplementedError("Cancellation is outside this finite profile")


def serve(port: int, events: Path) -> None:
    card = AgentCard(
        name="local-arithmetic-agent",
        version="deterministic-v1",
        supported_interfaces=[
            AgentInterface(
                url=f"http://127.0.0.1:{port}/rpc",
                protocol_binding="JSONRPC",
                protocol_version="1.0",
            )
        ],
    )
    handler = DefaultRequestHandlerV2(
        ArithmeticAgent(events), InMemoryTaskStore(), card
    )
    app = Starlette(
        routes=create_jsonrpc_routes(handler, "/rpc") + create_agent_card_routes(card)
    )
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--events", type=Path, required=True)
    args = parser.parse_args()
    serve(args.port, args.events)
