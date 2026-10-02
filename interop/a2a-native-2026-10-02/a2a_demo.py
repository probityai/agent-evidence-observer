"""Retain a real SDK client/server HTTP exchange and its common result packet."""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "evaluation-contract-2026-10-01"))
from a2a_contract import adapt, declaration, runtime_sources, verify
from evaluation_contract import digest, encode


async def exchange(url: str, case: dict, directory: Path) -> dict:
    import httpx
    from a2a.client.client import ClientCallContext
    from a2a.client.errors import A2AClientTimeoutError
    from a2a.client.transports.jsonrpc import JsonRpcTransport
    from a2a.types.a2a_pb2 import AgentCard, Message, Part, Role, SendMessageRequest
    from a2a.utils.errors import A2AError

    async def request_hook(request):
        (directory / "request.json").write_bytes(await request.aread())
        (directory / "request-metadata.json").write_bytes(
            encode(
                {
                    "method": request.method,
                    "url": str(request.url),
                    "a2a_version": request.headers.get("A2A-Version"),
                }
            )
        )

    async def response_hook(response):
        (directory / "response.json").write_bytes(await response.aread())
        (directory / "response-status.json").write_bytes(
            encode({"status": response.status_code})
        )

    async with httpx.AsyncClient(
        timeout=0.5,
        trust_env=False,
        event_hooks={"request": [request_hook], "response": [response_hook]},
    ) as client:
        transport = JsonRpcTransport(
            client, AgentCard(name="local-arithmetic-agent"), url
        )
        request = SendMessageRequest(
            message=Message(
                message_id=case["attempt_id"],
                role=Role.ROLE_USER,
                parts=[Part(text=case["input"])],
                context_id=case["logical_request_id"],
            )
        )
        started = time.perf_counter_ns()
        try:
            await transport.send_message(
                request,
                context=ClientCallContext(service_parameters={"A2A-Version": "1.0"}),
            )
            outcome = "returned"
        except (httpx.TimeoutException, A2AClientTimeoutError):
            outcome = "timeout"
        except (A2AError, httpx.RequestError) as error:
            # The SDK wraps transport timeouts. The native response, if present,
            # is the authority for protocol errors; absence is incomplete.
            outcome = "client-error"
            (directory / "client-error.json").write_bytes(
                encode({"type": type(error).__name__})
            )
        return {
            "attempt_id": case["attempt_id"],
            "event": "client-finished",
            "outcome": outcome,
            "elapsed_ns": time.perf_counter_ns() - started,
        }


def run(output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    url = f"http://127.0.0.1:{port}/rpc"
    sources = runtime_sources()
    native_plan = declaration(url)
    # Freeze the declaration and source bytes before launching either party.
    (output / "native-plan.json").write_bytes(encode(native_plan))
    for name, raw in sources.items():
        (output / name).write_bytes(raw)
    ledger = []
    log = (output / "server.log").open("wb")
    process = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "server.py"),
            "--port",
            str(port),
            "--events",
            str((output / "server-events.jsonl").resolve()),
        ],
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    try:
        ready = False
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("SDK server exited before readiness")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    ready = True
                    break
            except OSError:
                time.sleep(0.05)
        if not ready:
            raise RuntimeError("SDK server readiness deadline exceeded")
        import httpx

        card_response = httpx.get(
            f"http://127.0.0.1:{port}/.well-known/agent-card.json",
            trust_env=False,
            timeout=2,
        )
        card_response.raise_for_status()
        (output / "agent-card.json").write_bytes(card_response.content)
        for case in native_plan["attempts"]:
            directory = output / case["attempt_id"]
            directory.mkdir()
            if case["input"] == "not-launched":
                continue
            ledger.append({"attempt_id": case["attempt_id"], "event": "client-start"})
            (output / "launch-ledger.json").write_bytes(encode(ledger))
            ledger.append(asyncio.run(exchange(url, case, directory)))
            (output / "launch-ledger.json").write_bytes(encode(ledger))
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        log.close()
    raw = {
        "native-plan.json": encode(native_plan),
        "launch-ledger.json": encode(ledger),
        "agent-card.json": (output / "agent-card.json").read_bytes(),
        "server-events.jsonl": (output / "server-events.jsonl").read_bytes(),
    }
    for case in native_plan["attempts"]:
        for file in (output / case["attempt_id"]).iterdir():
            raw[f"{case['attempt_id']}-{file.name}"] = file.read_bytes()
    selected_pins = {name: digest(value) for name, value in raw.items()}
    plan, history, artifacts = adapt(native_plan, raw, sources, selected_pins)
    plan_raw, history_raw = encode(plan), encode(history)
    result = verify(
        native_plan,
        raw,
        sources,
        selected_pins,
        plan_raw,
        history_raw,
        artifacts,
        expected_plan_sha256=digest(plan_raw),
        expected_history_sha256=digest(history_raw),
    )
    common = output / "common"
    common.mkdir()
    for name, value in artifacts.items():
        (common / name).write_bytes(value)
    (common / "plan.json").write_bytes(plan_raw)
    (common / "history.json").write_bytes(history_raw)
    (output / "selected-native-pins.json").write_bytes(encode(selected_pins))
    (output / "report.json").write_bytes(encode(result))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    print(json.dumps(run(parser.parse_args().output), indent=2))
