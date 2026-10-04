"""Actual installed AG2 transports, native SDK push sender and bounded target."""

import argparse
import asyncio
from dataclasses import asdict
from pathlib import Path

import httpx
from a2a.server.tasks import InMemoryPushNotificationConfigStore, InMemoryTaskStore
from a2a.server.tasks.base_push_notification_sender import BasePushNotificationSender
from a2a.types import TaskState
from a2a.utils.errors import InvalidParamsError
from a2a.utils.push_url_validator import validate_push_notification_url
from ag2 import Agent
from ag2.a2a import A2AConfig, A2AServer, build_card
from ag2.a2a.push import (A2APushAuthentication, A2APushConfig,
                          create_push_notification_config, list_push_notification_configs)
from ag2.a2a.tasks import get_task, list_tasks
from ag2.a2a.testing import pick_free_port
from ag2.testing import TestConfig, TrackingConfig
from starlette.applications import Starlette
from starlette.responses import Response
from starlette.routing import Route

from probity_observer.broker import Broker
from probity_observer.crypto import SigningKey
from probity_observer.history import Witness

from .capture import Capture, native
from .contract import (AUTH, CASES, CONTENT, TARGET, TEXT, TOKEN, UNSAFE, decode,
                       encode, json_original, plan, require, sha, store)


class URLPolicy:
    def __init__(self, mode):
        self.mode = mode
        self.calls = []

    async def __call__(self, url):
        accepted = (await validate_push_notification_url(url) if self.mode == "sdk"
                    else self.mode == "allow" and url == TARGET)
        self.calls.append({"sequence": len(self.calls), "url": url,
                           "accepted": accepted, "policy": self.mode})
        return accepted


class Target:
    def __init__(self, broker, task_id, denied):
        self.broker, self.task_id, self.denied = broker, task_id, denied
        self.records, self.effects = [], []

    async def receive(self, request):
        raw = await request.body()
        value = json_original(raw.hex())
        allowed = (not self.denied and request.headers.get("x-a2a-notification-token") == TOKEN
                   and request.headers.get("authorization") == "Bearer " + AUTH
                   and value.get("task", {}).get("id") == self.task_id)
        status = 200 if allowed else 403
        self.records.append({"sequence": len(self.records), "url": str(request.url),
                             "bodyJSONHex": raw.hex(), "bodySHA256": sha(raw),
                             "headers": {k: request.headers.get(k) for k in
                                         ("x-a2a-notification-token", "authorization", "content-type")},
                             "targetAccepted": allowed, "responseStatus": status})
        if allowed:
            result = self.broker.write(self.task_id, "/work/result.txt", CONTENT)
            self.effects.append({"requestId": self.task_id, "operator": "same-author-callback-target",
                                 "result": asdict(result), "callbackBodySHA256": sha(raw)})
        return Response(b"accepted" if allowed else b"denied", status_code=status)


async def execute_case(root, case):
    transport, variant = case.split("/")
    directory = root / "cases" / case
    directory.mkdir(parents=True)
    workspace = directory / "workspace"
    workspace.mkdir()
    observer, witness = SigningKey.generate(), SigningKey.generate()
    store(directory / "keys-before-run.json", {"observer": observer.public_hex,
                                                "witness": witness.public_hex})
    authority = {"intervalId": case, "scope": "/work", "operation": "write-file"}
    store(directory / "authority-before-run.json", authority)
    broker = Broker(workspace, directory / "history.jsonl", authority, observer,
                    Witness(directory / "witness-state.json", witness))
    store(directory / "begin-before-run.json", broker.begin())
    mode = "sdk" if variant == "sdk-policy-denied" else "allow"
    registration = URLPolicy(mode)
    dispatch = URLPolicy("deny" if variant == "dispatch-denied" else "allow")
    task_store, push_store = InMemoryTaskStore(), InMemoryPushNotificationConfigStore()
    model = TrackingConfig(TestConfig(TEXT))
    server_agent = Agent("server", config=model)
    server = A2AServer(server_agent, task_store=task_store, push_config_store=push_store,
                       push_url_validator=None if variant == "legacy-config-only" else registration)
    capture = Capture()
    listener = None
    if transport == "grpc":
        url = f"127.0.0.1:{pick_free_port()}"
        card = build_card(server_agent, url=url, transports=("grpc",), grpc_url=url,
                          push_notifications=True)
        listener = server.build_grpc(bind=url, grpc_url=url, card=card)
        await listener.start()
        config = A2AConfig(card_url=url, preset_card=card, prefer=transport, streaming=False,
                            httpx_client_factory=lambda: httpx.AsyncClient(trust_env=False),
                            interceptors=(capture,))
    else:
        url = "http://test"
        card = build_card(server_agent, url=url, transports=(transport,), push_notifications=True)
        app = (server.build_rest(url=url, card=card) if transport == "rest"
               else server.build_jsonrpc(url=url, card=card))
        boundary = httpx.ASGITransport(app=app)
        config = A2AConfig(card_url=url, preset_card=card, prefer=transport, streaming=False,
                            httpx_client_factory=lambda: httpx.AsyncClient(transport=boundary,
                                                                         base_url=url, trust_env=False),
                            interceptors=(capture,))
    try:
        client = Agent("client", config=config)
        reply = await client.ask("Create finite task")
        require(reply.response.content == TEXT, "native-agent-response")
        listed = await list_tasks(config)
        require(len(listed.tasks) == 1, "native-task-population")
        task = await get_task(config, listed.tasks[0].id)
        require(task.status.state == TaskState.TASK_STATE_COMPLETED, "native-task-terminal")
        store(directory / "native-task.json", native(task))
        store(directory / "native-agent.json", {"response": reply.response.content,
                                                  "nativeModelCalls": model.mock.call_count,
                                                  "nativePrompt": [list(c.prompt) for c in model.calls],
                                                  "agentTaskCompletedBeforeRegistration": True,
                                                  "providerRequests": 0, "toolBodyEffects": 0})
        operations = []
        attempted = list(UNSAFE) if variant == "sdk-policy-denied" else [
            UNSAFE[0] if variant in ("registration-denied", "legacy-config-only") else TARGET]
        for target in attempted:
            submitted = A2APushConfig(url=target, token=TOKEN,
                                     authentication=A2APushAuthentication(scheme="Bearer", credentials=AUTH))
            try:
                created = await create_push_notification_config(config, task.id, submitted)
                operations.append({"submitted": asdict(submitted), "outcome": "stored",
                                   "returned": asdict(created)})
            except InvalidParamsError as error:
                operations.append({"submitted": asdict(submitted), "outcome": "InvalidParamsError",
                                   "nativeExceptionType": type(error).__name__})
        stored = await list_push_notification_configs(config, task.id)
        store(directory / "push-operations.json", operations)
        store(directory / "stored-configs.json", [asdict(c) for c in stored])
        require(not list(workspace.iterdir()), "effect-before-explicit-dispatch")
        store(directory / "effect-before-dispatch.json", {"files": [], "targetCallbacks": 0})
        target = Target(broker, task.id, variant == "target-denied")
        target_app = Starlette(routes=[Route("/receipt", target.receive, methods=["POST"])])
        dispatched = variant != "legacy-config-only"
        if dispatched:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=target_app),
                                         trust_env=False, follow_redirects=False) as http:
                sender = BasePushNotificationSender(http, push_store, push_url_validator=dispatch)
                await sender.send_notification(task.id, task)
        store(directory / "dispatch.json", {"explicitHostCall": dispatched,
                                             "operator": "same-author-host-post-completion",
                                             "nativeMethod": "BasePushNotificationSender.send_notification",
                                             "event": native(task) if dispatched else None,
                                             "returnValue": None, "automaticTaskDispatch": False})
        store(directory / "url-policy.json", {"registration": registration.calls, "dispatch": dispatch.calls,
                                               "registrationMode": None if variant == "legacy-config-only" else mode,
                                               "dispatchMode": dispatch.mode})
        store(directory / "target-callbacks.json", target.records)
        store(directory / "target-effects.json", target.effects)
        store(directory / "native-callbacks.json", capture.close())
        packet = broker.seal()
        store(directory / "observer-packet.json", packet)
        return {"case": case, "nativeTasks": 1, "modelCalls": model.mock.call_count,
                "storedConfigs": len(stored), "targetCallbacks": len(target.records),
                "observedWrites": len(packet["claim"]["writes"]),
                "explicitDispatch": dispatched, "publicationDecision": None}
    finally:
        if listener is not None:
            await listener.stop(grace=0)


async def produce(root):
    selected = decode((root / "plan-before-run.json").read_bytes())
    require(selected == plan(selected["runId"]), "unselected-plan")
    rows = [await execute_case(root, case) for case in CASES]
    result = {"profile": selected["profile"], "rows": rows,
              "publicationDecision": None, "operator": "author-operated", "witnessScope": "PEER",
              "prospectiveEightTaskRun": "not-started"}
    store(root / "native-result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(encode(asyncio.run(produce(args.directory))).decode())
    return 0
