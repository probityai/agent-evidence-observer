"""Framework-free reader reconstructing a separately selected finite SDK packet."""

from __future__ import annotations

import argparse
import re
from datetime import datetime
from pathlib import Path
from typing import Any

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
    PROFILE,
    PROMPT,
    VERSION,
    arguments,
    decode,
    encode,
    read,
    require,
    same,
    sha,
)


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
        isinstance(source, dict) and 100 <= len(source) <= 1000, "source-population"
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
        decode(read(root / "sources", "distribution/versions.json"))["openai-agents"],
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


def check_plan(plan: dict[str, Any], reference: datetime) -> datetime:
    """Apply fixed scope and budgets even after digest reselection."""
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
                "defaultExporter",
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
                "defaultExporter",
                "budget",
            )
        },
        {
            "profile": PROFILE,
            "sdkVersion": VERSION,
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
        re.fullmatch(r"openai-reference-[0-9a-f]{32}", plan["runId"]) is not None,
        "run-identity",
    )
    start = datetime.fromisoformat(plan["selectedTime"])
    require(start.tzinfo is not None and start <= reference, "selected-clock")
    traces = [entry["traceId"] for entry in plan["cases"]]
    require(len(set(traces)) == len(CASES), "unique-traces")
    for entry in plan["cases"]:
        check_entry(entry, plan["runId"], reference)
    return start


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
                "traceId",
                "maxTurns",
            )
        ),
        "entry-fields",
    )
    case = entry["id"]
    same(entry["arguments"], arguments(case), "selected-arguments")
    same(
        entry["maxTurns"], 1 if case == "turns-exhausted" else 2, "selected-turn-budget"
    )
    require(
        re.fullmatch(r"trace_[0-9a-f]{32}", entry["traceId"]) is not None,
        "trace-identity",
    )
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


def terminal_for(case: str) -> dict[str, Any]:
    """Task status stays separate from successful native effects."""
    errors = {"producer-error": BEFORE_ERROR, "committed-effect-error": AFTER_ERROR}
    if case in errors:
        return {
            "status": "error",
            "output": None,
            "exception": {
                "type": "UserError",
                "message": "Error running tool dispatch_ticket: " + errors[case],
            },
        }
    if case == "turns-exhausted":
        return {
            "status": "incomplete",
            "output": None,
            "exception": {
                "type": "MaxTurnsExceeded",
                "message": "Max turns (1) exceeded",
            },
        }
    return {"status": "complete", "output": "complete", "exception": None}


def check_effect(
    entry: dict[str, Any], execution: dict[str, Any], reference: datetime
) -> tuple[dict[str, Any], int]:
    """Authenticate HTTP bytes, exact selected arguments and signed native read-back."""
    case = entry["id"]
    calls = execution["toolCalls"]
    same(len(calls), 1, "tool-call-population")
    call = calls[0]
    same(
        {key: call[key] for key in ("id", "arguments")},
        {"id": case + "-0", "arguments": entry["arguments"]},
        "tool-invocation",
    )
    same(execution["finalGetStatus"], 200, "final-get-status")
    final = decode(bytes.fromhex(execution["finalReadbackHex"]))
    if case == "producer-error":
        same(
            call,
            {"id": case + "-0", "arguments": entry["arguments"], "error": BEFORE_ERROR},
            "pre-dispatch-error",
        )
        same(final, entry["initial"], "pre-dispatch-native-state")
        return call, 0
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
    candidate = decode(bytes.fromhex(packet["postRequestHex"]))
    same(
        candidate,
        {
            "request": entry["request"],
            "grant": entry["grant"],
            "contentHex": entry["arguments"]["content"].encode().hex(),
        },
        "literal-http-request",
    )
    same(packet["getStatus"], 200, "http-get-status")
    readback = decode(bytes.fromhex(packet["getResponseHex"]))
    same(readback, final, "final-native-readback")
    status = {"deny": 409, "changed-arguments": 409}.get(case, 200)
    same(packet["postStatus"], status, "post-outcome")
    same(
        decode(call["result"].encode()),
        {
            "httpSha256": sha(encode(packet)),
            "postStatus": status,
            "nativeRevision": readback["revision"],
        },
        "tool-http-join",
    )
    expected_keys = {"id", "arguments", "http", "result"} | (
        {"error"} if case == "committed-effect-error" else set()
    )
    same(sorted(call), sorted(expected_keys), "tool-result-fields")
    if status != 200:
        same(readback, entry["initial"], "refused-native-state")
        same(
            decode(bytes.fromhex(packet["postResponseHex"])),
            {
                "status": "refused",
                "reason": "ticket request, authority, state or framing differs",
            },
            "http-refusal-reason",
        )
        return call, 0
    receipt = decode(bytes.fromhex(packet["postResponseHex"]))
    verified = verify_ticket_result(
        receipt,
        readback,
        ActionRequest(**entry["request"]),
        GrantPolicy(**entry["policy"]),
        entry["serviceKey"],
        entry["grant"],
        now=reference.replace(microsecond=0),
    )
    same(verified["nativeRevision"], 1, "authenticated-native-revision")
    if case == "committed-effect-error":
        same(call["error"], AFTER_ERROR, "committed-error")
    return call, 1


def response_for(entry: dict[str, Any], index: int) -> list[dict[str, Any]]:
    """Reconstruct native Responses items from the independently fixed script."""
    case = entry["id"]
    if index == 0:
        return [
            {
                "type": "function_call",
                "id": "item-" + case,
                "call_id": case + "-0",
                "name": "dispatch_ticket",
                "arguments": encode(entry["arguments"]).decode(),
                "status": "completed",
            }
        ]
    return [
        {
            "type": "message",
            "id": "final-" + case,
            "role": "assistant",
            "content": [{"type": "output_text", "text": "complete", "annotations": []}],
            "status": "completed",
        }
    ]


def check_models(
    entry: dict[str, Any], execution: dict[str, Any], call: dict[str, Any]
) -> int:
    """Verify SDK handoff without claiming model tokens or quality."""
    count = 2 if entry["id"] in CASES[:3] else 1
    same(len(execution["modelCalls"]), count, "model-population")
    prompt = [{"role": "user", "content": PROMPT}]
    for index, item in enumerate(execution["modelCalls"]):
        same(
            sorted(item), sorted(("index", "input", "output", "usage")), "model-fields"
        )
        expected_input = (
            prompt
            if index == 0
            else prompt
            + response_for(entry, 0)
            + [
                {
                    "type": "function_call_output",
                    "call_id": entry["id"] + "-0",
                    "output": call["result"],
                }
            ]
        )
        same(
            {key: item[key] for key in ("index", "input", "output")},
            {
                "index": index,
                "input": expected_input,
                "output": response_for(entry, index),
            },
            "native-model-handoff",
        )
        same(
            item["usage"],
            {
                "requests": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
                "output_tokens_details": {"reasoning_tokens": 0},
                "request_usage_entries": [],
            },
            "scripted-usage-not-inference",
        )
    return count


def span_data(
    label: str, entry: dict[str, Any], execution: dict[str, Any], *, end: bool
) -> dict[str, Any]:
    """Reconstruct advertised native span data rather than trusting omitted records."""
    if label == "task":
        return {
            "type": "custom",
            "name": "task",
            "data": {"sdk_span_type": "task", "name": "probity_synthetic_ticket"},
        }
    if label == "agent":
        return {
            "type": "agent",
            "name": "probity_synthetic_ticket",
            "handoffs": [],
            "tools": ["dispatch_ticket"] if end else [],
            "output_type": "str",
        }
    if label.startswith("turn"):
        return {
            "type": "custom",
            "name": "turn",
            "data": {
                "sdk_span_type": "turn",
                "turn": int(label[-1]),
                "agent_name": "probity_synthetic_ticket",
            },
        }
    if label == "function":
        call = execution["toolCalls"][0]
        output = (
            call.get("result")
            if entry["id"] not in {"producer-error", "committed-effect-error"}
            else None
        )
        return {
            "type": "function",
            "name": "dispatch_ticket",
            "input": encode(entry["arguments"]).decode() if end else None,
            "output": output if end else None,
            "mcp_data": None,
        }
    model = execution["modelCalls"][int(label[-1]) - 1]
    return {
        "type": "generation",
        "model": "probity-scripted-no-inference",
        "model_config": None,
        "input": model["input"] if end else None,
        "output": model["output"] if end else None,
        "usage": None,
    }


def span_error(label: str, case: str) -> Any:
    """Keep exact advertised error events with no success coercion."""
    reason = {
        "producer-error": BEFORE_ERROR,
        "committed-effect-error": AFTER_ERROR,
    }.get(case)
    if label == "function" and reason:
        return {
            "message": "Error running tool",
            "data": {"error": reason, "tool_name": "dispatch_ticket"},
        }
    if label == "agent" and reason:
        return {
            "message": "Error in agent run",
            "data": {"error": "Error running tool dispatch_ticket: " + reason},
        }
    if label == "agent" and case == "turns-exhausted":
        return {"message": "Max turns exceeded", "data": {"max_turns": 1}}
    return None


def lifecycle(count: int) -> list[tuple[str, str]]:
    """Select complete callback order for the fixed serial native run."""
    result = [
        ("span-start", "task"),
        ("span-start", "agent"),
        ("span-start", "turn1"),
        ("span-start", "generation1"),
        ("span-end", "generation1"),
        ("span-start", "function"),
        ("span-end", "function"),
        ("span-end", "turn1"),
    ]
    if count == 2:
        result += [
            ("span-start", "turn2"),
            ("span-start", "generation2"),
            ("span-end", "generation2"),
            ("span-end", "turn2"),
        ]
    return result + [("span-end", "agent"), ("span-end", "task")]


def check_trace(
    entry: dict[str, Any],
    execution: dict[str, Any],
    count: int,
    start: datetime,
    reference: datetime,
) -> int:
    """Require complete native lifecycle, chronology and parentage."""
    capture = execution["trace"]
    same(
        sorted(capture),
        sorted(
            ("capturePayloads", "events", "failures", "flushes", "shutdowns", "closed")
        ),
        "capture-fields",
    )
    same(
        {
            key: capture[key]
            for key in ("capturePayloads", "failures", "flushes", "shutdowns", "closed")
        },
        {
            "capturePayloads": True,
            "failures": 0,
            "flushes": 2,
            "shutdowns": 1,
            "closed": True,
        },
        "capture-completion",
    )
    events = capture["events"]
    schedule = lifecycle(count)
    same(len(events), len(schedule) + 2, "trace-population")
    expected_trace = {
        "object": "trace",
        "id": entry["traceId"],
        "workflow_name": "probity_synthetic_ticket",
        "group_id": None,
        "metadata": None,
    }
    same(
        events[0],
        {"sequence": 0, "event": "trace-start", "native": expected_trace},
        "trace-start",
    )
    same(
        events[-1],
        {"sequence": len(events) - 1, "event": "trace-end", "native": expected_trace},
        "trace-end",
    )
    seen: dict[str, dict[str, Any]] = {}
    stack: list[str] = []
    previous = start
    for index, ((kind, label), event) in enumerate(
        zip(schedule, events[1:-1], strict=True), 1
    ):
        same(sorted(event), sorted(("sequence", "event", "native")), "event-fields")
        same(
            {key: event[key] for key in ("sequence", "event")},
            {"sequence": index, "event": kind},
            "callback-order",
        )
        native = event["native"]
        previous = check_span(
            native, kind, label, entry, execution, seen, stack, previous, reference
        )
    require(not stack, "unclosed-native-spans")
    return len(seen)


def check_span(
    native: dict[str, Any],
    kind: str,
    label: str,
    entry: dict[str, Any],
    execution: dict[str, Any],
    seen: dict[str, dict[str, Any]],
    stack: list[str],
    previous: datetime,
    reference: datetime,
) -> datetime:
    """Match one native span against its fixed role and live stack."""
    same(
        sorted(native),
        sorted(
            (
                "object",
                "id",
                "trace_id",
                "parent_id",
                "started_at",
                "ended_at",
                "span_data",
                "error",
            )
        ),
        "native-span-fields",
    )
    end = kind == "span-end"
    require(
        re.fullmatch(r"span_[0-9a-f]{24}", native["id"]) is not None, "span-identity"
    )
    same(native["trace_id"], entry["traceId"], "span-trace-binding")
    same(native["object"], "trace.span", "native-span-object")
    same(
        native["span_data"],
        span_data(label, entry, execution, end=end),
        "native-span-data",
    )
    same(
        native["error"],
        span_error(label, entry["id"]) if end else None,
        "native-span-error",
    )
    timestamp = datetime.fromisoformat(
        native["ended_at"] if end else native["started_at"]
    )
    require(
        timestamp.tzinfo is not None and previous <= timestamp <= reference,
        "native-span-chronology",
    )
    if end:
        require(stack and stack[-1] == label, "native-span-stack")
        original = seen[label]
        same(
            {key: native[key] for key in ("id", "parent_id", "started_at")},
            {key: original[key] for key in ("id", "parent_id", "started_at")},
            "span-lifecycle-identity",
        )
        stack.pop()
    else:
        require(
            label not in seen
            and native["id"] not in {item["id"] for item in seen.values()},
            "duplicate-native-span",
        )
        same(
            native["parent_id"],
            seen[stack[-1]]["id"] if stack else None,
            "native-parentage",
        )
        same(native["ended_at"], None, "premature-native-completion")
        seen[label] = native
        stack.append(label)
    return timestamp


def verify_case(
    entry: dict[str, Any],
    execution: dict[str, Any],
    start: datetime,
    reference: datetime,
) -> dict[str, Any]:
    """Join execution and capture with authenticated native row outcomes."""
    same(
        sorted(execution),
        sorted(
            (
                "toolCalls",
                "modelCalls",
                "terminal",
                "trace",
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
        and 0 < execution["elapsedNs"] <= 90_000_000_000,
        "elapsed-budget",
    )
    require(
        type(execution["cpuNs"]) is int
        and 0 <= execution["cpuNs"] <= execution["elapsedNs"],
        "cpu-budget",
    )
    call, revision = check_effect(entry, execution, reference)
    count = check_models(entry, execution, call)
    spans = check_trace(entry, execution, count, start, reference)
    return {
        "case": entry["id"],
        "taskStatus": execution["terminal"]["status"],
        "dispatchStatus": call.get("http", {}).get("postStatus"),
        "nativeRevision": revision,
        "modelCalls": count,
        "toolCalls": 1,
        "completedSpans": spans,
        "elapsedNs": execution["elapsedNs"],
        "cpuNs": execution["cpuNs"],
    }


def verify_saved(root: Path, selected: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct finite records without assigning independent custody."""
    plan, artifacts, reference = selected_packet(root, selected)
    start = check_plan(plan, reference)
    records = [
        verify_case(entry, artifacts[entry["id"] + ".json"], start, reference)
        for entry in plan["cases"]
    ]
    elapsed = sum(record["elapsedNs"] for record in records)
    require(elapsed <= 90_000_000_000, "population-elapsed-budget")
    return {
        "profile": PROFILE,
        "status": "verified",
        "plannedAttempts": 6,
        "records": records,
        "resources": {
            "modelCalls": sum(record["modelCalls"] for record in records),
            "toolCalls": 6,
            "elapsedNs": elapsed,
            "cpuNs": sum(record["cpuNs"] for record in records),
        },
        "publicationDecision": "admit-complete-bounded-reference-population",
        "modelQuality": "not-evaluated",
        "custody": "same-operator; author-run synthetic HTTP service",
        "doesNotAssert": [
            "remote provider inference",
            "outside acceptance or recurring adoption",
            "independent effect custody",
            "production security or universal trace coverage",
            "target process restart or power-loss recovery",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--pins-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify_saved(args.output, decode(args.pins_file.read_bytes()))
    except (VerificationError, KeyError, ValueError, TypeError, OSError):
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
    print(encode(result).decode())
