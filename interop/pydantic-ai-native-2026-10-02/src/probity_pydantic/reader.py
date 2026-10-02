"""Installed offline reader requiring consumer-selected packet/source pins."""

from __future__ import annotations

import argparse
import json
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
    CASES,
    CONTENT,
    ERROR,
    LOGGER,
    PROFILE,
    PROMPT,
    RETRY,
    VERSION,
    decode,
    encode,
    expected_outcome,
    read,
    require,
    script,
    sha,
)


def same(actual: Any, expected: Any, reason: str) -> None:
    """Compare canonical typed JSON, refusing bool/integer equality coercion."""
    try:
        equal = encode(actual) == encode(expected)
    except VerificationError:
        equal = False
    require(equal, reason)


def selected_packet(
    output: Path, selected: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Authenticate exact finite file populations against out-of-packet pins.

    Parameters
    ----------
    output : Path
        Retained producer packet; no framework execution or HTTP occurs here.
    selected : dict[str, Any]
        Consumer-selected hashes and historical reference time. Never inferred
        from ``output/consumer-pins.json``. The demonstration writes that file
        for a caller to inspect and explicitly copy into its policy boundary.

    Returns
    -------
    tuple[dict[str, Any], dict[str, bytes]]
        Selected pre-run plan and authenticated exact native/HTTP artifact bytes.
    """
    require(
        output.is_dir() and not output.is_symlink(), "packet root missing or linked"
    )
    require(
        not any(path.is_symlink() for path in output.rglob("*")),
        "packet contains symlink",
    )
    require(
        set(selected)
        == {
            "planSha256",
            "sourceManifestSha256",
            "artifactManifestSha256",
            "evaluationTime",
        },
        "consumer pin fields differ",
    )
    values = {}
    for name, field in (
        ("plan-before-run.json", "planSha256"),
        ("source-manifest-before-run.json", "sourceManifestSha256"),
        ("artifact-manifest.json", "artifactManifestSha256"),
    ):
        raw = read(output, name)
        require(sha(raw) == selected[field], "external pin differs: " + field)
        values[name] = decode(raw)
    sources = values["source-manifest-before-run.json"]
    expected_sources = {
        str(path.relative_to(output / "sources"))
        for path in (output / "sources").rglob("*")
        if path.is_file()
    }
    require(set(sources) == expected_sources, "source file population differs")
    for name, pin in sources.items():
        require(
            name in expected_sources and sha(read(output / "sources", name)) == pin,
            "source bytes differ",
        )
    require(
        "pydantic_ai/agent/__init__.py" in sources
        and "pydantic_ai/models/function.py" in sources
        and "distribution/METADATA" in sources
        and "distribution/licenses/LICENSE" in sources,
        "framework sources missing",
    )
    require(
        decode(read(output / "sources", "distribution/versions.json"))[
            "pydantic-ai-slim"
        ]
        == VERSION,
        "retained framework version differs",
    )
    manifest = values["artifact-manifest.json"]
    actual = {path.name for path in (output / "artifacts").iterdir() if path.is_file()}
    expected = {
        case + suffix
        for case in CASES
        for suffix in ("-messages.json", "-execution.json")
    }
    expected |= {
        case + "-0-http.json" for case in ("permit", "deny", "changed-arguments")
    }
    expected.add("retry-1-http.json")
    require(set(manifest) == actual == expected, "artifact population differs")
    artifacts = {name: read(output / "artifacts", name) for name in expected}
    require(
        all(sha(raw) == manifest[name] for name, raw in artifacts.items()),
        "artifact bytes differ",
    )
    plan = values["plan-before-run.json"]
    require(
        plan["sourceManifestSha256"] == selected["sourceManifestSha256"],
        "plan source binding differs",
    )
    return plan, artifacts


def check_plan(plan: dict[str, Any], reference: datetime) -> None:
    """Refuse changed profile, scripts, invocation identities or model claims."""
    expected = {
        "profile": PROFILE,
        "frameworkVersion": VERSION,
        "model": "FunctionModel scripted local function",
        "modelQuality": "not-evaluated",
        "prompt": PROMPT,
        "retries": 1,
    }
    same(
        {name: plan[name] for name in expected}, expected, "frozen plan profile differs"
    )
    require(
        [entry["id"] for entry in plan["cases"]] == list(CASES),
        "frozen case population differs",
    )
    start = datetime.fromisoformat(plan["selectedTime"])
    require(
        reference.tzinfo is not None
        and start.tzinfo is not None
        and reference >= start,
        "consumer reference time differs",
    )
    for entry in plan["cases"]:
        case = entry["id"]
        same(entry["script"], script(case), "frozen tool script differs")
        request = ActionRequest(**entry["request"])
        require(
            request.run_id == plan["runId"]
            and request.attempt_id == case
            and request.request_id == "request-" + case,
            "request invocation identity differs",
        )
        require(
            request.tenant_id == "tenant"
            and request.principal_id == "principal"
            and request.tool_id == "ticket-update"
            and request.target_path == "/work/tickets/" + case,
            "request authority scope differs",
        )
        require(
            entry["contentHex"] == CONTENT.encode().hex()
            and request.content_sha256 == sha(CONTENT.encode()),
            "selected content differs",
        )
        verify_grant(
            entry["grant"],
            request,
            GrantPolicy(**entry["policy"]),
            now=reference.replace(microsecond=0),
        )
        state = signed_initial(entry)
        require(state["revoked"] == (case == "deny"), "selected revocation differs")


def signed_initial(entry: dict[str, Any]) -> dict[str, Any]:
    """Authenticate the selected initial row without treating absence as effect."""
    initial = entry["initial"]
    state = _checked(initial["receipt"], entry["serviceKey"])
    _state_schema(state, receipt=True)
    expected_configuration = digest(
        DOMAIN + "-configuration",
        {
            "request": entry["request"],
            "policy": entry["policy"],
            "serviceKey": entry["serviceKey"],
        },
    )
    require(
        state["configuration"] == expected_configuration
        and state["request"] == entry["request"]
        and state["authorityKey"] == entry["policy"]["issuer_key"],
        "initial authority binding differs",
    )
    same(
        {
            name: initial[name]
            for name in ("tenantId", "ticketId", "contentHex", "revision", "effectId")
        },
        {
            "tenantId": "tenant",
            "ticketId": entry["id"],
            "contentHex": None,
            "revision": 0,
            "effectId": None,
        },
        "initial native relation differs",
    )
    require(
        state["phase"] == "ready"
        and state["witnessScope"] == "PEER"
        and state["coverage"] == "one-native-ticket-row-and-service-events",
        "initial bounded state differs",
    )
    return state


def _unique_names(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse duplicate native JSON names while preserving original input bytes."""
    value: dict[str, Any] = {}
    for name, item in pairs:
        require(name not in value, "duplicate native JSON name")
        value[name] = item
    return value


def _invalid_constant(value: str) -> None:
    """Refuse non-JSON floating constants in original native serialization."""
    require(False, "nonfinite native JSON number")


def valid_run_id(value: Any) -> bool:
    """Accept only the native canonical UUID4 string, never a coerced boolean."""
    if type(value) is not str:
        return False
    try:
        parsed = UUID(value)
    except ValueError:
        return False
    return str(parsed) == value and parsed.version == 4


def check_part_time(part: dict[str, Any], start: datetime, reference: datetime) -> None:
    """Require original native part timestamps to remain inside selected bounds."""
    if part["part_kind"] in {"user-prompt", "retry-prompt", "tool-return"}:
        require("timestamp" in part, "native part timestamp missing")
    if "timestamp" in part:
        current = datetime.fromisoformat(part["timestamp"])
        require(
            current.tzinfo is not None and start <= current <= reference,
            "native part chronology differs",
        )


def native_parts(
    raw: bytes, plan: dict[str, Any], reference: datetime
) -> list[dict[str, Any]]:
    """Check native message alternation, run identity, model and bounded clock."""
    messages = json.loads(
        raw, object_pairs_hook=_unique_names, parse_constant=_invalid_constant
    )
    require(
        isinstance(messages, list) and 1 <= len(messages) <= 7,
        "native message population differs",
    )
    identities = {message["run_id"] for message in messages}
    require(
        len(identities) == 1 and all(valid_run_id(value) for value in identities),
        "native run identity differs",
    )
    parts = []
    previous = datetime.fromisoformat(plan["selectedTime"])
    for index, message in enumerate(messages):
        require(
            message["kind"] == ("request" if index % 2 == 0 else "response"),
            "native message order differs",
        )
        current = datetime.fromisoformat(message["timestamp"])
        require(
            current.tzinfo is not None and previous <= current <= reference,
            "native chronology differs",
        )
        previous = current
        require(len(message["parts"]) == 1, "native part population differs")
        part = message["parts"][0]
        check_part_time(part, datetime.fromisoformat(plan["selectedTime"]), reference)
        if message["kind"] == "response":
            require(
                message["model_name"] == "function:local_model:", "native model differs"
            )
        parts.append(part)
    require(
        parts[0]["part_kind"] == "user-prompt" and parts[0]["content"] == PROMPT,
        "native input differs",
    )
    return parts[1:]


def check_call(part: dict[str, Any], entry: dict[str, Any], index: int) -> None:
    """Require literal native typed arguments and original tool-call identity."""
    expected = {
        "part_kind": "tool-call",
        "tool_name": "dispatch_ticket",
        "args": {"content": entry["script"][index]},
        "tool_call_id": f"{entry['id']}-{index}",
    }
    same({name: part[name] for name in expected}, expected, "native tool call differs")


def http_effect(
    entry: dict[str, Any], packet_raw: bytes, content: str, reference: datetime
) -> tuple[str, dict[str, Any]]:
    """Join actual HTTP arguments, signed authorization and independent GET bytes.

    Parameters
    ----------
    entry : dict[str, Any]
        Frozen selected case with request, issuer pin and service public key.
    packet_raw : bytes
        Exact authenticated HTTP packet retained by the tool wrapper.
    content : str
        Native framework argument, compared to the actual POST bytes.
    reference : datetime
        Consumer-selected historical verification time within the grant window.

    Returns
    -------
    tuple[str, dict[str, Any]]
        Exact native tool return string and readback. Successful completion
        uses :func:`probity_observer.ticket_service.verify_ticket_result`.
    """
    packet = decode(packet_raw)
    require(
        set(packet)
        == {
            "endpoint",
            "postPath",
            "getPath",
            "postRequestHex",
            "postStatus",
            "postResponseHex",
            "getStatus",
            "getResponseHex",
        },
        "HTTP packet fields differ",
    )
    endpoint = packet["endpoint"]
    require(
        isinstance(endpoint, str)
        and endpoint.startswith("http://127.0.0.1:")
        and endpoint.removeprefix("http://127.0.0.1:").isdigit(),
        "HTTP local endpoint differs",
    )
    require(
        packet["postPath"] == "/dispatch"
        and packet["getPath"] == "/tickets/tenant/" + entry["id"],
        "HTTP route differs",
    )
    same(packet["getStatus"], 200, "HTTP read status differs")
    candidate = {
        "request": entry["request"],
        "grant": entry["grant"],
        "contentHex": content.encode().hex(),
    }
    require(
        bytes.fromhex(packet["postRequestHex"]) == encode(candidate),
        "native argument to HTTP binding differs",
    )
    response = decode(bytes.fromhex(packet["postResponseHex"]))
    readback = decode(bytes.fromhex(packet["getResponseHex"]))
    if entry["id"] in {"deny", "changed-arguments"}:
        same(packet["postStatus"], 409, "HTTP refusal status differs")
        same(
            response,
            {
                "status": "refused",
                "reason": "ticket request, authority, state or framing differs",
            },
            "HTTP refusal response differs",
        )
        same(readback, entry["initial"], "refused native row differs")
    else:
        same(packet["postStatus"], 200, "HTTP completion status differs")
        verify_ticket_result(
            response,
            readback,
            ActionRequest(**entry["request"]),
            GrantPolicy(**entry["policy"]),
            entry["serviceKey"],
            entry["grant"],
            now=reference.replace(microsecond=0),
        )
    result = encode(
        {
            "httpSha256": sha(packet_raw),
            "postStatus": packet["postStatus"],
            "nativeRevision": readback["revision"],
        }
    ).decode()
    return result, readback


def check_retry(part: dict[str, Any], trace: dict[str, Any], identity: str) -> None:
    """Refuse a missing or replaced native retry and its pre-dispatch trace."""
    same(
        {
            name: part[name]
            for name in ("part_kind", "tool_name", "tool_call_id", "content")
        },
        {
            "part_kind": "retry-prompt",
            "tool_name": "dispatch_ticket",
            "tool_call_id": identity,
            "content": RETRY,
        },
        "native retry differs",
    )
    same(
        trace,
        {
            "id": identity,
            "arguments": {"content": CONTENT},
            "outcome": "retry",
            "reason": RETRY,
        },
        "retry dispatch trace differs",
    )


def check_return(
    part: dict[str, Any],
    trace: dict[str, Any],
    entry: dict[str, Any],
    index: int,
    artifacts: dict[str, bytes],
    reference: datetime,
) -> dict[str, Any]:
    """Reconstruct the HTTP digest join rather than trusting producer summaries."""
    identity = f"{entry['id']}-{index}"
    filename = identity + "-http.json"
    result, readback = http_effect(
        entry, artifacts[filename], entry["script"][index], reference
    )
    same(
        {
            name: part[name]
            for name in ("part_kind", "tool_name", "tool_call_id", "content", "outcome")
        },
        {
            "part_kind": "tool-return",
            "tool_name": "dispatch_ticket",
            "tool_call_id": identity,
            "content": result,
            "outcome": "success",
        },
        "native HTTP return join differs",
    )
    same(
        trace,
        {
            "id": identity,
            "arguments": {"content": entry["script"][index]},
            "outcome": "return",
            "artifact": filename,
            "result": result,
        },
        "native dispatch trace differs",
    )
    return readback


def verify_case(
    entry: dict[str, Any],
    artifacts: dict[str, bytes],
    plan: dict[str, Any],
    reference: datetime,
) -> dict[str, Any]:
    """Recompute one declared native transcript and retain errors as errors."""
    case = entry["id"]
    parts = native_parts(artifacts[case + "-messages.json"], plan, reference)
    execution = decode(artifacts[case + "-execution.json"])
    trace = execution["trace"]
    require(len(trace) == len(entry["script"]), "native dispatch population differs")
    expected_count = 1 if case == "producer-error" else 2 * len(trace) + 1
    require(len(parts) == expected_count, "native transcript population differs")
    final_readback = entry["initial"]
    for index, record in enumerate(trace):
        require(
            record["outcome"] == expected_outcome(case, index),
            "frozen dispatch outcome differs",
        )
        check_call(parts[2 * index], entry, index)
        if record["outcome"] == "error":
            same(
                record,
                {
                    "id": "producer-error-0",
                    "arguments": {"content": CONTENT},
                    "outcome": "error",
                    "reason": ERROR,
                },
                "producer error trace differs",
            )
        elif record["outcome"] == "retry":
            require(case == "retry" and index == 0, "unexpected retry")
            check_retry(parts[2 * index + 1], record, f"{case}-{index}")
        else:
            final_readback = check_return(
                parts[2 * index + 1], record, entry, index, artifacts, reference
            )
    terminal = execution["terminal"]
    if case == "producer-error":
        same(
            terminal,
            {
                "status": "error",
                "output": None,
                "exception": {"type": "RuntimeError", "message": ERROR},
            },
            "producer error terminal differs",
        )
    else:
        same(
            terminal,
            {"status": "complete", "output": "complete", "exception": None},
            "native completion differs",
        )
        require(
            parts[-1]["part_kind"] == "text" and parts[-1]["content"] == "complete",
            "native final output differs",
        )
    same(
        decode(bytes.fromhex(execution["finalReadbackHex"])),
        final_readback,
        "final native readback differs",
    )
    outcome = (
        "verified-local-ticket-update"
        if final_readback["revision"] == 1
        else "not-recorded-local-row"
    )
    return {
        "attemptId": case,
        "executionStatus": terminal["status"],
        "effectOutcome": outcome,
        "nativeRevision": final_readback["revision"],
        "toolAttempts": len(trace),
        "retries": int(case == "retry"),
        "taskQuality": "not-evaluated",
    }


def verify_saved(output: Path, selected: dict[str, Any]) -> dict[str, Any]:
    """Verify a bounded packet offline without importing the agent framework.

    Parameters
    ----------
    output : Path
        Retained packet directory from the producer's installed CLI.
    selected : dict[str, Any]
        Pins selected outside the packet by the relying party, including an
        explicit historical reference time. Passing self-carried pins does
        not establish external selection, independent custody or freshness.

    Returns
    -------
    dict[str, Any]
        Five recomputed execution/effect records, with bounded scope labels.

    Raises
    ------
    VerificationError
        On pin, population, native transcript, authorization, effect/readback,
        retry, exception or typed argument inconsistencies. Errors never gain a
        successful task score. This is admission of a record, not permission to
        dispatch another HTTP effect.
    """
    try:
        plan, artifacts = selected_packet(output, selected)
        reference = datetime.fromisoformat(selected["evaluationTime"])
        check_plan(plan, reference)
        records = [
            verify_case(entry, artifacts, plan, reference) for entry in plan["cases"]
        ]
    except VerificationError as error:
        LOGGER.warning("pydantic consumer refused: %s", error)
        raise
    except (KeyError, TypeError, ValueError, IndexError, AttributeError) as error:
        require(False, "malformed bounded packet")
        raise AssertionError("unreachable") from error
    return {
        "profile": PROFILE,
        "status": "verified",
        "plannedAttempts": 5,
        "records": records,
        "providerCalls": "none-scripted-FunctionModel",
        "tokenAccounting": "FunctionModel estimates-not-measured-inference",
        "effectScope": "one-selected-local-ticket-per-attempt",
        "independentCustody": "not-established",
        "callerIdentity": "not-established",
        "captureCompleteness": "finite-selected-source-and-artifact-population",
        "priorSelection": "local-pre-run-plan-not-independent-witness",
    }


def main() -> None:
    """Read with mandatory externally supplied pins and report bounded refusals."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--pins-file", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = verify_saved(args.output, decode(args.pins_file.read_bytes()))
    except VerificationError as error:
        print(encode({"status": "refused", "reason": str(error)}).decode())
        raise SystemExit(1) from error
    print(encode(report).decode())
