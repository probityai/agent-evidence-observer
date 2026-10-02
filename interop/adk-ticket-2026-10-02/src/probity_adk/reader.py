"""Framework-free reconstruction of selected native ADK events and HTTP effects."""

from __future__ import annotations

import argparse
import copy
import math
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from probity_observer.authorization import ActionRequest, GrantPolicy, verify_grant
from probity_observer.crypto import VerificationError, digest
from probity_observer.ticket_service import (
    DOMAIN,
    _checked,
    _state_schema,
    verify_ticket_result,
)

from .contract import (
    AFTER_ERROR,
    BEFORE_ERROR,
    CASES,
    CONTENT,
    NONCLAIMS,
    PROFILE,
    PROMPT,
    VERSION,
    arguments,
    decode,
    encode,
    plugin_order,
    read,
    require,
    same,
    sha,
    tool_count,
)
from .native_defaults import DEFAULTS


def selected_packet(
    root: Path, selected: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], datetime]:
    """Authenticate exact files, source manifest and complete selected population."""
    same(
        sorted(selected),
        sorted(
            (
                "profile",
                "planSha256",
                "sourceManifestSha256",
                "artifactManifestSha256",
                "consumerTime",
            )
        ),
        "pins-fields",
    )
    same(selected["profile"], PROFILE, "selected-profile")
    bindings = {
        "plan-before-run.json": "planSha256",
        "source-manifest-before-run.json": "sourceManifestSha256",
        "artifact-manifest.json": "artifactManifestSha256",
    }
    values = {}
    for filename, field in bindings.items():
        raw = read(root, filename)
        same(sha(raw), selected[field], "selected-bytes")
        values[filename] = decode(raw)
    source = values["source-manifest-before-run.json"]
    require(
        isinstance(source, dict) and 100 <= len(source) <= 2000, "source-population"
    )
    actual = {
        str(p.relative_to(root / "sources"))
        for p in (root / "sources").rglob("*")
        if p.is_file()
    }
    same(sorted(actual), sorted(source), "source-files")
    for name, expected in source.items():
        same(sha(read(root / "sources", name)), expected, "source-bytes")
    same(
        decode(read(root / "sources", "distribution/versions.json"))["google-adk"],
        VERSION,
        "selected-sdk-version",
    )
    require(
        "distribution/LICENSE" in source and "distribution/METADATA" in source,
        "sdk-license-provenance",
    )
    manifest = values["artifact-manifest.json"]
    expected_names = [case + ".json" for case in CASES]
    same(sorted(manifest), sorted(expected_names), "artifact-population")
    same(
        sorted(p.name for p in (root / "artifacts").iterdir()),
        sorted(expected_names),
        "artifact-files",
    )
    artifacts = {}
    for name in expected_names:
        raw = read(root / "artifacts", name)
        same(sha(raw), manifest[name], "artifact-bytes")
        artifacts[name] = decode(raw)
    reference = datetime.fromisoformat(selected["consumerTime"])
    require(reference.tzinfo is not None, "consumer-clock")
    plan = values["plan-before-run.json"]
    same(
        plan["sourceManifestSha256"],
        selected["sourceManifestSha256"],
        "source-plan-binding",
    )
    return plan, artifacts, reference


def check_entry(entry: dict[str, Any], run_id: str, reference: datetime) -> None:
    """Join exact synthetic arguments, native request scope and initial signed row."""
    same(
        sorted(entry),
        sorted(
            (
                "id",
                "request",
                "policy",
                "serviceKey",
                "grant",
                "initial",
                "arguments",
                "pluginOrder",
                "plannedTools",
            )
        ),
        "entry-fields",
    )
    case = entry["id"]
    same(entry["arguments"], arguments(case), "selected-arguments")
    same(entry["plannedTools"], tool_count(case), "selected-tool-population")
    same(entry["pluginOrder"], plugin_order(case), "selected-plugin-order")
    expected_request = {
        "run_id": run_id,
        "attempt_id": case,
        "request_id": "request-" + case,
        "tenant_id": "tenant",
        "principal_id": "principal",
        "tool_id": "ticket-update",
        "target_path": "/work/tickets/" + case,
        "content_sha256": sha(CONTENT.encode()),
    }
    same(entry["request"], expected_request, "request-scope")
    verify_grant(
        entry["grant"],
        ActionRequest(**entry["request"]),
        GrantPolicy(**entry["policy"]),
        now=reference.replace(microsecond=0),
    )
    state = _checked(entry["initial"]["receipt"], entry["serviceKey"])
    _state_schema(state, receipt=True)
    configuration = digest(
        DOMAIN + "-configuration",
        {key: entry[key] for key in ("request", "policy", "serviceKey")},
    )
    same(
        {
            key: state[key]
            for key in (
                "configuration",
                "request",
                "authorityKey",
                "phase",
                "revision",
                "revoked",
                "witnessScope",
                "coverage",
            )
        },
        {
            "configuration": configuration,
            "request": entry["request"],
            "authorityKey": entry["policy"]["issuer_key"],
            "phase": "ready",
            "revision": 0,
            "revoked": case == "deny",
            "witnessScope": "PEER",
            "coverage": "one-native-ticket-row-and-service-events",
        },
        "initial-authority",
    )
    same(
        {
            key: entry["initial"][key]
            for key in ("tenantId", "ticketId", "contentHex", "revision", "effectId")
        },
        {
            "tenantId": "tenant",
            "ticketId": case,
            "contentHex": None,
            "revision": 0,
            "effectId": None,
        },
        "initial-row",
    )


def check_plan(plan: dict[str, Any], reference: datetime) -> datetime:
    """Refuse altered populations, plugin ordering, scope and resource budgets."""
    same(
        sorted(plan),
        sorted(
            (
                "profile",
                "sdkVersion",
                "sourceRevision",
                "selectedTime",
                "runId",
                "model",
                "modelQuality",
                "prompt",
                "capturePayloads",
                "telemetry",
                "budget",
                "sourceManifestSha256",
                "cases",
            )
        ),
        "plan-fields",
    )
    same(
        {
            key: plan[key]
            for key in (
                "profile",
                "sdkVersion",
                "model",
                "modelQuality",
                "prompt",
                "capturePayloads",
                "telemetry",
                "budget",
            )
        },
        {
            "profile": PROFILE,
            "sdkVersion": VERSION,
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
        },
        "plan-scope-budget",
    )
    same([entry["id"] for entry in plan["cases"]], list(CASES), "plan-population")
    require(
        isinstance(plan["sourceRevision"], str)
        and 1 <= len(plan["sourceRevision"]) <= 100,
        "source-revision",
    )
    require(
        re.fullmatch(r"adk-reference-[0-9a-f]{32}", plan["runId"]) is not None,
        "run-identity",
    )
    start = datetime.fromisoformat(plan["selectedTime"])
    require(start.tzinfo is not None and start <= reference, "selected-clock")
    for entry in plan["cases"]:
        check_entry(entry, plan["runId"], reference)
    return start


def terminal_for(case: str) -> dict[str, Any]:
    """A final callback or handled tool response never implies business success."""
    if case == "incomplete-close":
        return {"status": "incomplete", "exception": None}
    reason = {"unhandled-before": BEFORE_ERROR, "unhandled-after": AFTER_ERROR}.get(
        case
    )
    if case.startswith("exhausted-"):
        reason = (
            "Error in plugin 'probity_reflect_retry' during "
            "'on_tool_error_callback' callback: " + BEFORE_ERROR
        )
    if reason:
        return {
            "status": "error",
            "exception": {"type": "RuntimeError", "message": reason},
        }
    return {"status": "complete", "exception": None}


def raw_outcome(case: str, index: int) -> str:
    """Choose the original tool branch independently of the returned SDK response."""
    if case == "unhandled-before" or case.startswith("exhausted-"):
        return "before-error"
    if index == 0 and case.startswith("handled-"):
        return "before-error"
    if index == 0 and case.startswith("returned-error-"):
        return "returned-error"
    return "http"


def check_tools(
    entry: dict[str, Any], execution: dict[str, Any], reference: datetime
) -> list[dict[str, Any]]:
    """Authenticate raw tool invocations and service effects."""
    same(len(execution["toolCalls"]), tool_count(entry["id"]), "tool-population")
    same(execution["finalGetStatus"], 200, "final-get-status")
    final = decode(bytes.fromhex(execution["finalReadbackHex"]))
    outcomes = []
    for index, call in enumerate(execution["toolCalls"]):
        same(
            {key: call[key] for key in ("id", "arguments")},
            {"id": entry["id"] + "-" + str(index), "arguments": entry["arguments"]},
            "tool-identity",
        )
        outcomes.append(check_tool(entry, call, index, final, reference))
    if not any(outcome["revision"] for outcome in outcomes):
        same(final, entry["initial"], "unchanged-native-row")
    return outcomes


def check_tool(
    entry: dict[str, Any],
    call: dict[str, Any],
    index: int,
    final: Any,
    reference: datetime,
) -> dict[str, Any]:
    """Keep original error and returned isError values before plugin interpretation."""
    branch = raw_outcome(entry["id"], index)
    if branch == "before-error":
        same(sorted(call), ["arguments", "error", "id"], "raw-error-fields")
        same(
            call["error"],
            {"type": "RuntimeError", "message": BEFORE_ERROR},
            "raw-tool-error",
        )
        return {"revision": 0, "postStatus": None, "branch": branch}
    if branch == "returned-error":
        same(sorted(call), ["arguments", "id", "result"], "returned-error-fields")
        same(call["result"], DEFAULTS["returned_error"], "original-typed-mcp-error")
        return {"revision": 0, "postStatus": None, "branch": branch}
    return check_http(entry, call, final, reference)


def check_http(
    entry: dict[str, Any], call: dict[str, Any], final: Any, reference: datetime
) -> dict[str, Any]:
    """Join exact protected HTTP bytes with authenticated service read-back."""
    expected_keys = {"id", "arguments", "http", "result"} | (
        {"error"} if entry["id"] == "unhandled-after" else set()
    )
    same(sorted(call), sorted(expected_keys), "http-tool-fields")
    packet = call["http"]
    same(
        sorted(packet),
        sorted(
            (
                "endpoint",
                "postRequestHex",
                "postStatus",
                "postResponseHex",
                "getStatus",
                "getResponseHex",
            )
        ),
        "http-fields",
    )
    require(
        re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", packet["endpoint"]) is not None,
        "local-endpoint",
    )
    same(
        decode(bytes.fromhex(packet["postRequestHex"])),
        {
            "request": entry["request"],
            "grant": entry["grant"],
            "contentHex": entry["arguments"]["content"].encode().hex(),
        },
        "literal-http-request",
    )
    readback = decode(bytes.fromhex(packet["getResponseHex"]))
    same(readback, final, "final-native-join")
    status = 409 if entry["id"] in {"deny", "changed-arguments"} else 200
    same(packet["postStatus"], status, "post-status")
    same(packet["getStatus"], 200, "get-status")
    same(
        call["result"],
        {
            "httpSha256": sha(encode(packet)),
            "postStatus": status,
            "nativeRevision": readback["revision"],
        },
        "tool-http-join",
    )
    response = decode(bytes.fromhex(packet["postResponseHex"]))
    if status != 200:
        same(
            response,
            {
                "status": "refused",
                "reason": "ticket request, authority, state or framing differs",
            },
            "http-refusal",
        )
        return {"revision": 0, "postStatus": status, "branch": "http"}
    verify_ticket_result(
        response,
        readback,
        ActionRequest(**entry["request"]),
        GrantPolicy(**entry["policy"]),
        entry["serviceKey"],
        entry["grant"],
        now=reference.replace(microsecond=0),
    )
    if entry["id"] == "unhandled-after":
        same(
            call["error"],
            {"type": "RuntimeError", "message": AFTER_ERROR},
            "committed-error",
        )
    return {"revision": 1, "postStatus": status, "branch": "http"}


def content(kind: str, payload: Any) -> dict[str, Any]:
    """Reconstruct original typed genai content from fixed reader-owned defaults."""
    part = copy.deepcopy(DEFAULTS["part"])
    part[kind] = payload
    return {
        "role": "user" if kind in {"text", "function_response"} else "model",
        "parts": [part],
    }


def call_content(entry: dict[str, Any], index: int) -> dict[str, Any]:
    call = copy.deepcopy(DEFAULTS["function_call"])
    call.update(
        name="dispatch_ticket",
        args=entry["arguments"],
        id=entry["id"] + "-" + str(index),
    )
    return content("function_call", call)


def final_content() -> dict[str, Any]:
    value = content("text", "complete")
    value["role"] = "model"
    return value


def response_result(
    entry: dict[str, Any], execution: dict[str, Any], index: int
) -> Any:
    branch = raw_outcome(entry["id"], index)
    if branch == "before-error":
        return DEFAULTS["reflection_error"]
    if branch == "returned-error":
        return DEFAULTS["reflection_result"]
    return execution["toolCalls"][index]["result"]


def tool_content(
    entry: dict[str, Any], execution: dict[str, Any], index: int
) -> dict[str, Any]:
    response = copy.deepcopy(DEFAULTS["function_response"])
    response.update(
        name="dispatch_ticket",
        id=entry["id"] + "-" + str(index),
        response=response_result(entry, execution, index),
    )
    return content("function_response", response)


def native_value(wrapped: dict[str, Any]) -> Any:
    """Verify original SDK JSON bytes match retained interpreted fields exactly."""
    same(sorted(wrapped), ["jsonHex", "value"], "native-wrapper-fields")
    require(
        isinstance(wrapped["jsonHex"], str)
        and len(wrapped["jsonHex"]) <= 2 * 1024 * 1024,
        "native-json-bound",
    )
    parsed = decode(bytes.fromhex(wrapped["jsonHex"]))
    same(parsed, wrapped["value"], "native-original-byte-projection")
    return parsed


def model_count(case: str) -> int:
    extra = 0 if terminal_for(case)["status"] != "complete" else 1
    return tool_count(case) + extra


def check_models(entry: dict[str, Any], execution: dict[str, Any]) -> list[Any]:
    """Reconstruct actual model input histories, native responses and absent usage."""
    same(len(execution["modelCalls"]), model_count(entry["id"]), "model-population")
    histories = []
    history = [content("text", PROMPT)]
    for index, call in enumerate(execution["modelCalls"]):
        same(sorted(call), ["index", "request", "response"], "model-fields")
        same(call["index"], index, "model-order")
        expected = copy.deepcopy(DEFAULTS["request_model"])
        expected["contents"] = history
        same(native_value(call["request"]), expected, "actual-native-model-request")
        response = copy.deepcopy(DEFAULTS["response"])
        response["content"] = (
            call_content(entry, index)
            if index < tool_count(entry["id"])
            else final_content()
        )
        same(native_value(call["response"]), response, "actual-native-model-response")
        histories.append(copy.deepcopy(history))
        if index < tool_count(entry["id"]):
            history = history + [
                call_content(entry, index),
                tool_content(entry, execution, index),
            ]
    return histories


def uuid4(value: Any, *, invocation: bool = False) -> bool:
    if not isinstance(value, str):
        return False
    text = value[2:] if invocation and value.startswith("e-") else value
    try:
        parsed = UUID(text)
    except ValueError:
        return False
    return parsed.version == 4 and str(parsed) == text


def check_event(
    wrapped: Any,
    invocation: str,
    body: Any,
    *,
    error: Any,
    start: datetime,
    reference: datetime,
    user: bool = False,
) -> Any:
    """Refuse hidden partials/fabricated final status and retain tied native times."""
    event = native_value(wrapped)
    require(uuid4(event["id"]), "native-event-id")
    timestamp = event["timestamp"]
    require(
        type(timestamp) is float
        and math.isfinite(timestamp)
        and start.timestamp() <= timestamp <= reference.timestamp(),
        "native-event-clock",
    )
    expected = copy.deepcopy(DEFAULTS["event"])
    expected.update(
        invocation_id=invocation,
        id=event["id"],
        timestamp=timestamp,
        author="user" if user else "probity_ticket",
        content=body,
    )
    if user:
        expected["node_info"] = {
            "message_as_output": None,
            "output_for": None,
            "path": "",
        }
    if body and body["parts"][0]["function_call"]:
        expected["long_running_tool_ids"] = []
    if error:
        expected.update(error_code=error["type"], error_message=error["message"])
    same(event, expected, "native-event-fields")
    return event


def event_schedule(
    entry: dict[str, Any], execution: dict[str, Any]
) -> list[tuple[Any, Any]]:
    schedule = []
    error = terminal_for(entry["id"])["exception"]
    for index in range(tool_count(entry["id"])):
        schedule.append((call_content(entry, index), None))
        if error and index == tool_count(entry["id"]) - 1:
            schedule.append((None, error))
        else:
            schedule.append((tool_content(entry, execution, index), None))
    if terminal_for(entry["id"])["status"] == "complete":
        schedule.append((final_content(), None))
    return schedule


def check_events(
    entry: dict[str, Any],
    execution: dict[str, Any],
    start: datetime,
    reference: datetime,
) -> str:
    """Join plugin-visible, yielded and session events by sequence and IDs."""
    events = execution["events"]
    schedule = event_schedule(entry, execution)
    same(len(events), len(schedule), "yielded-event-population")
    same(len(execution["sessionEvents"]), len(events) + 1, "session-event-population")
    same(execution["sessionEvents"][1:], events, "session-yielded-byte-join")
    invocation = events[0]["value"]["invocation_id"]
    require(
        invocation.startswith("e-") and uuid4(invocation, invocation=True),
        "invocation-id",
    )
    user = check_event(
        execution["sessionEvents"][0],
        invocation,
        content("text", PROMPT),
        error=None,
        start=start,
        reference=reference,
        user=True,
    )
    previous = user["timestamp"]
    ids = {user["id"]}
    for wrapped, (body, error) in zip(events, schedule, strict=True):
        event = check_event(
            wrapped, invocation, body, error=error, start=start, reference=reference
        )
        require(
            event["timestamp"] >= previous and event["id"] not in ids,
            "native-event-order-identity",
        )
        previous = event["timestamp"]
        ids.add(event["id"])
    return invocation


def tool_callbacks(case: str, index: int) -> list[tuple[str, int]]:
    """Preserve original callback omissions caused by native plugin handling."""
    branch = raw_outcome(case, index)
    rows = []
    has_error = branch == "before-error" or case == "unhandled-after"
    if has_error and not case.endswith("-last"):
        rows.append(("tool-error", index))
    final_error = terminal_for(case)["exception"] and index == tool_count(case) - 1
    if not final_error and not (branch == "returned-error" and case.endswith("-last")):
        rows.append(("after-tool", index))
    return rows


def callback_schedule(entry: dict[str, Any]) -> list[tuple[str, int]]:
    """Select exact callback order independently of the retained trace."""
    case = entry["id"]
    rows = [("user-message", 0), ("before-run", 0), ("before-agent", 0)]
    for index in range(tool_count(case)):
        rows += [
            ("before-model", index),
            ("after-model", index),
            ("event", index * 2),
            ("before-tool", index),
        ]
        rows += tool_callbacks(case, index)
        if terminal_for(case)["exception"] and index == tool_count(case) - 1:
            return rows + [
                ("agent-error", 0),
                ("event", index * 2 + 1),
                ("run-error", 0),
            ]
        rows += [("event", index * 2 + 1)]
    if terminal_for(case)["status"] == "complete":
        count = tool_count(case)
        rows += [
            ("before-model", count),
            ("after-model", count),
            ("event", count * 2),
            ("after-agent", 0),
        ]
    return rows + [("after-run", 0)]


def check_callbacks(
    entry: dict[str, Any],
    execution: dict[str, Any],
    histories: list[Any],
    invocation: str,
) -> None:
    """Require declared callback coverage without inferring task success."""
    capture = execution["capture"]
    same(
        sorted(capture),
        ["capturePayloads", "closed", "failures", "records"],
        "capture-fields",
    )
    same(
        {key: capture[key] for key in ("capturePayloads", "closed", "failures")},
        {"capturePayloads": True, "closed": True, "failures": 0},
        "capture-completion",
    )
    schedule = callback_schedule(entry)
    same(len(capture["records"]), len(schedule), "callback-population")
    for sequence, ((kind, index), record) in enumerate(
        zip(schedule, capture["records"], strict=True)
    ):
        same(
            sorted(record),
            ["callback", "invocationId", "native", "sequence"],
            "callback-fields",
        )
        same(
            {key: record[key] for key in ("callback", "invocationId", "sequence")},
            {"callback": kind, "invocationId": invocation, "sequence": sequence},
            "callback-order-identity",
        )
        check_callback_payload(
            kind, index, record["native"], entry, execution, histories
        )


def check_callback_payload(
    kind: str, index: int, payload: Any, entry: Any, execution: Any, histories: Any
) -> None:
    """Match actual original native callback payloads against the profile's joins."""
    simple = {
        "before-run": {},
        "after-run": {},
        "before-agent": {"agent": "probity_ticket"},
        "after-agent": {"agent": "probity_ticket"},
    }
    if kind in simple:
        same(payload, simple[kind], "callback-native-data")
        return
    if kind == "before-model":
        expected = copy.deepcopy(DEFAULTS["request_before"])
        expected["contents"] = histories[index]
        same(native_value(payload), expected, "callback-before-model")
        return
    native_refs = {"after-model": execution["modelCalls"], "event": execution["events"]}
    if kind in native_refs:
        expected = native_refs[kind][index]
        same(
            payload,
            expected["response"] if kind == "after-model" else expected,
            "native-callback-byte-join",
        )
        return
    if kind == "user-message":
        same(native_value(payload), content("text", PROMPT), "user-message-callback")
        return
    check_tool_callback(kind, index, payload, entry, execution)


def check_tool_callback(
    kind: str, index: int, payload: Any, entry: Any, execution: Any
) -> None:
    error = terminal_for(entry["id"])["exception"]
    if kind == "agent-error":
        same(
            payload, {"agent": "probity_ticket", "error": error}, "agent-error-callback"
        )
        return
    if kind == "run-error":
        same(payload, {"error": error}, "run-error-callback")
        return
    expected = {
        "tool": "dispatch_ticket",
        "functionCallId": entry["id"] + "-" + str(index),
        "arguments": entry["arguments"],
    }
    if kind == "tool-error":
        expected["error"] = execution["toolCalls"][index]["error"]
    if kind == "after-tool":
        expected["result"] = (
            execution["toolCalls"][index]["result"]
            if raw_outcome(entry["id"], index) == "returned-error"
            else response_result(entry, execution, index)
        )
    same(payload, expected, "tool-callback-native-data")


def verify_case(
    entry: Any, execution: Any, start: datetime, reference: datetime
) -> dict[str, Any]:
    same(
        sorted(execution),
        sorted(
            (
                "modelCalls",
                "toolCalls",
                "events",
                "sessionEvents",
                "capture",
                "terminal",
                "finalGetStatus",
                "finalReadbackHex",
                "elapsedNs",
                "cpuNs",
            )
        ),
        "execution-fields",
    )
    same(execution["terminal"], terminal_for(entry["id"]), "terminal-outcome")
    require(
        type(execution["elapsedNs"]) is int
        and 0 < execution["elapsedNs"] <= 120_000_000_000,
        "elapsed-budget",
    )
    require(
        type(execution["cpuNs"]) is int
        and 0 <= execution["cpuNs"] <= execution["elapsedNs"],
        "cpu-budget",
    )
    outcomes = check_tools(entry, execution, reference)
    histories = check_models(entry, execution)
    invocation = check_events(entry, execution, start, reference)
    check_callbacks(entry, execution, histories, invocation)
    return {
        "case": entry["id"],
        "taskStatus": execution["terminal"]["status"],
        "nativeRevision": max(outcome["revision"] for outcome in outcomes),
        "modelCalls": len(histories),
        "toolCalls": len(outcomes),
        "httpPosts": sum(outcome["postStatus"] is not None for outcome in outcomes),
        "nativeEvents": len(execution["events"]),
        "capturedCallbacks": len(execution["capture"]["records"]),
        "observedOriginalToolErrorCallbacks": sum(
            row["callback"] == "tool-error" for row in execution["capture"]["records"]
        ),
        "pluginOrder": entry["pluginOrder"],
        "elapsedNs": execution["elapsedNs"],
        "cpuNs": execution["cpuNs"],
    }


def verify_saved(root: Path, selected: dict[str, Any]) -> dict[str, Any]:
    plan, artifacts, reference = selected_packet(root, selected)
    start = check_plan(plan, reference)
    records = [
        verify_case(entry, artifacts[entry["id"] + ".json"], start, reference)
        for entry in plan["cases"]
    ]
    resources = {
        key: sum(row[key] for row in records)
        for key in ("modelCalls", "toolCalls", "httpPosts", "elapsedNs", "cpuNs")
    }
    require(
        resources["elapsedNs"] <= 120_000_000_000
        and resources["modelCalls"] == 25
        and resources["toolCalls"] == 18,
        "population-resource-budget",
    )
    return {
        "profile": PROFILE,
        "status": "verified",
        "plannedAttempts": 12,
        "records": records,
        "resources": resources,
        "publicationDecision": "admit-complete-bounded-reference-population",
        "modelQuality": "not-evaluated",
        "custody": "same-operator; author-run synthetic HTTP service",
        "doesNotAssert": NONCLAIMS,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--pins-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify_saved(args.output, decode(args.pins_file.read_bytes()))
    except (VerificationError, ValueError, TypeError, KeyError, OSError):
        print(
            encode(
                {
                    "profile": PROFILE,
                    "status": "refused",
                    "reason": "selected-packet-invalid",
                }
            ).decode()
        )
        raise SystemExit(1) from None
    print(encode(report).decode())
