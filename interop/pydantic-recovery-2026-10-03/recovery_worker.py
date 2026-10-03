"""Real native Pydantic deferral, hard exit and fresh result continuation."""
from __future__ import annotations

import argparse
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from probity_observer.authorization import ActionRequest, GrantPolicy, verify_grant
from probity_observer.crypto import VerificationError, canonical, strict_loads

from probity_pydantic_recovery.common import load, read, require, write
from probity_pydantic_recovery.gate import admit


def exchange(url: str, candidate: dict[str, Any] | None = None) -> tuple[int, bytes]:
    """Send bounded HTTP bytes without exposing any admin endpoint."""
    request = Request(url, data=None if candidate is None else canonical(candidate), headers={"Content-Type": "application/json"})
    try:
        response = urlopen(request, timeout=5)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read(2 * 1024 * 1024 + 1)
        require(len(raw) <= 2 * 1024 * 1024, "http-bound")
        return response.code, raw


def agent_for(case: dict[str, Any], *, resume: bool = False) -> Any:
    """Construct the actual native Agent with a disclosed fixed FunctionModel."""
    from pydantic_ai import Agent, CallDeferred, DeferredToolRequests
    from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
    from pydantic_ai.models.function import FunctionModel

    def model(messages: Any, info: Any) -> Any:
        if resume:
            return ModelResponse(parts=[TextPart("complete")])
        return ModelResponse(parts=[ToolCallPart("dispatch_ticket", {"content": "DONE"}, tool_call_id=case["id"] + "-call")])

    agent = Agent(FunctionModel(model), output_type=[str, DeferredToolRequests], retries=0)

    @agent.tool_plain
    def dispatch_ticket(content: str) -> str:
        require(content == "DONE", "native-tool-arguments")
        raise CallDeferred

    return agent


def first(case: dict[str, Any], endpoint: str, root: Path) -> None:
    """Persist native history before dispatch, then die after its real effect."""
    from pydantic_ai import DeferredToolRequests

    result = agent_for(case).run_sync("Execute the selected ticket update.")
    require(isinstance(result.output, DeferredToolRequests), "native-deferral-missing")
    require(len(result.output.calls) == 1 and not result.output.approvals, "native-deferred-population")
    write(root / "history.json", result.all_messages_json(), raw=True)
    write(root / "deferred.json", {"calls": [{"toolCallId": c.tool_call_id, "toolName": c.tool_name, "arguments": c.args} for c in result.output.calls]})
    candidate = {key: case[key] for key in ("request", "grant", "contentHex")}
    status, response = exchange(endpoint + "/dispatch", candidate)
    get_status, readback = exchange(endpoint + "/tickets/tenant/" + case["id"])
    require(status == get_status == 200, "first-effect-failed")
    if case["id"] != "crash-window":
        write(root / "prior-http.json", {"postStatus": status, "postRequestHex": canonical(candidate).hex(), "postResponseHex": response.hex(), "getStatus": get_status, "getResponseHex": readback.hex()})
    os._exit(74)


def prepare_continuation(case: dict[str, Any], history: bytes, accepted: dict[str, Any]) -> tuple[Any, Any, datetime]:
    """Recheck actual UTC immediately before constructing native result input."""
    from pydantic_ai import DeferredToolResults
    from pydantic_ai.messages import ModelMessagesTypeAdapter

    native = ModelMessagesTypeAdapter.validate_json(history)
    injected_at = datetime.now(UTC).replace(microsecond=0)
    verify_grant(case["grant"], ActionRequest(**case["request"]), GrantPolicy(**case["policy"]), now=injected_at)
    results = DeferredToolResults(calls={accepted["toolCallId"]: accepted["result"]})
    return native, results, injected_at


def continuation(case: dict[str, Any], prepared: tuple[Any, Any, datetime], root: Path) -> dict[str, Any]:
    """Run the new native Agent only after the result input passed admission."""
    native, results, injected_at = prepared
    result = agent_for(case, resume=True).run_sync(message_history=native, deferred_tool_results=results)
    write(root / "resumed-history.json", result.all_messages_json(), raw=True)
    require(result.output == "complete", "native-continuation-output")
    return {"status": "completed", "output": result.output, "providerCalls": 0, "nativeModelRequests": result.usage().requests, "nativeResultInjectedAt": injected_at.isoformat()}


def recover(case: dict[str, Any], endpoint: str, root: Path, current: dict[str, Any]) -> None:
    """Authenticate the host's selected evidence before native continuation."""
    live = None
    evaluated_at = datetime.now(UTC).replace(microsecond=0)
    try:
        require(current["targetReady"] is True, "current-target-not-ready")
        require((root / "prior-http.json").is_file(), "historical-http-journal-missing")
        status, raw = exchange(endpoint + "/tickets/tenant/" + case["id"])
        require(status == 200, "current-get-failed")
        live = strict_loads(raw)
        history = read(root / "recovery-history.json")
        evaluated_at = datetime.now(UTC).replace(microsecond=0)
        accepted = admit(case, history, load(root / "prior-http.json"), live, current, evaluated_at=evaluated_at)
        prepared = prepare_continuation(case, history, accepted)
    except VerificationError as error:
        write(root / "recovery.json", {"pid": os.getpid(), "evaluatedAt": evaluated_at.isoformat(), "status": "refused", "reason": str(error), "live": live, "releasedResult": False, "recoveryPosts": 0, "nativeModelRequests": 0})
        return
    completed = continuation(case, prepared, root)
    write(root / "accepted-host-receipt.json", accepted)
    write(root / "recovery.json", {"pid": os.getpid(), "evaluatedAt": evaluated_at.isoformat(), **completed, "live": live, "releasedResult": True, "recoveryPosts": 0})


def main() -> None:
    """Run one declared worker phase, never accepting arbitrary result input."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["first", "second"])
    parser.add_argument("case", type=Path)
    parser.add_argument("endpoint")
    parser.add_argument("root", type=Path)
    parser.add_argument("--current", type=Path)
    args = parser.parse_args()
    case = load(args.case)
    if args.phase == "first":
        first(case, args.endpoint, args.root)
    else:
        require(args.current is not None, "current-host-selection-required")
        recover(case, args.endpoint, args.root, load(args.current))


if __name__ == "__main__":
    main()
