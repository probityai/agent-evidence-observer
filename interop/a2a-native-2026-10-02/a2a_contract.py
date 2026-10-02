"""Recompute the bounded native SDK exchange before common-contract admission."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "evaluation-contract-2026-10-01"))
from evaluation_contract import (
    AXES,
    PROFILE,
    RESOURCES,
    ROLES,
    decode,
    digest,
    encode,
    require,
    validate,
)

SDK_VERSION = "1.2.1"
SDK_COMMIT = "041c17bbe8d5ced7a8f6c48761152ce01ffbfc14"
MAPPING = "probity-a2a-jsonrpc-native-v1"
MODULES = (
    "a2a.client.transports.jsonrpc",
    "a2a.server.routes.jsonrpc_routes",
    "a2a.server.routes.jsonrpc_dispatcher",
    "a2a.server.routes.agent_card_routes",
    "a2a.server.request_handlers.default_request_handler_v2",
    "a2a.server.agent_execution.agent_executor",
    "a2a.helpers.proto_helpers",
)


def ref(name: str, value: bytes, revision: str = MAPPING) -> dict:
    return {
        "name": name,
        "sha256": digest(value),
        "size_bytes": len(value),
        "media_type": "application/json",
        "source_revision": revision,
    }


def runtime_sources() -> dict[str, bytes]:
    """Retain selected installed SDK source octets and exact local mapper code."""
    require(importlib.metadata.version("a2a-sdk") == SDK_VERSION, "sdk_version")
    modules = {
        name: Path(importlib.util.find_spec(name).origin).read_text("utf-8")
        for name in MODULES
    }
    source = encode(modules)
    manifest = decode((ROOT / "sdk-source-pins.json").read_bytes())
    require(
        {name: digest(code.encode()) for name, code in modules.items()}
        == manifest["modules"],
        "sdk_source_mismatch",
    )
    return {
        "sdk-source.json": source,
        "sdk-source-pins.json": encode(manifest),
        "sdk-license.txt": (ROOT / "SDK-LICENSE").read_bytes(),
        "local-source.json": encode(
            {
                **{
                    name: (ROOT / name).read_text("utf-8")
                    for name in (
                        "a2a_contract.py",
                        "a2a_demo.py",
                        "a2a_verify.py",
                        "server.py",
                    )
                },
                "evaluation_contract.py": (
                    ROOT.parent
                    / "evaluation-contract-2026-10-01"
                    / "evaluation_contract.py"
                ).read_text("utf-8"),
            }
        ),
        "rubric.json": encode(
            {
                "rule": "single returned text equals predeclared expected decimal",
                "version": 1,
            }
        ),
        "policy.json": encode(
            {
                "scope": "loopback-native-SDK-contract",
                "authentication": "not-established",
                "custody": "same-operator",
            }
        ),
        "runtime.json": encode(
            {
                "python": sys.version.split()[0],
                "packages": {
                    name: importlib.metadata.version(name)
                    for name in ("a2a-sdk", "httpx", "uvicorn", "starlette", "protobuf")
                },
                "elapsed_clock": "client-perf_counter_ns-monotonic-wall-elapsed",
                "elapsed_unit": "ns",
                "precision": "clock-dependent-not-nanosecond-accuracy",
            }
        ),
    }


def declaration(url: str) -> dict:
    parsed = urlsplit(url)
    require(
        parsed.scheme == "http"
        and parsed.hostname == "127.0.0.1"
        and parsed.port is not None
        and parsed.path == "/rpc"
        and not parsed.query
        and not parsed.fragment
        and parsed.username is None,
        "loopback_endpoint",
    )
    rows = (
        ("pass", "2+3", "5"),
        ("rubric-fail", "2+3", "6"),
        ("error", "reject", None),
        ("task-failed", "task-failed", None),
        ("incomplete", "wait", None),
        ("missing", "not-launched", None),
    )
    return {
        "profile": MAPPING,
        "run_id": "a2a-native-001",
        "endpoint": url,
        "source_actor": "local-client-agent",
        "target_actor": "local-arithmetic-agent",
        "protocol_binding": "JSONRPC",
        "protocol_version": "1.0",
        "attempts": [
            {
                "attempt_id": "a2a-" + name,
                "logical_request_id": "request-" + name,
                "input": text,
                "expected": expected,
            }
            for name, text, expected in rows
        ],
    }


def adapt(
    native_plan: dict,
    raw: dict[str, bytes],
    sources: dict[str, bytes],
    selected_native_pins: dict[str, str],
    *,
    expected_sources_sha256: str | None = None,
) -> tuple[dict, dict, dict[str, bytes]]:
    """Join raw requests/responses to the selected finite declaration and rubric.

    Pins are consumer-selected inputs. Bundle self-pins do not authenticate the
    runner, SDK origin, server identity, prior commitment or external effects.
    """
    require(type(native_plan) is dict, "native_declaration_shape")
    require(
        native_plan == declaration(native_plan.get("endpoint", "")),
        "native_declaration_changed",
    )
    require(set(raw) == set(selected_native_pins), "native_population")
    require(
        all(digest(value) == selected_native_pins[name] for name, value in raw.items()),
        "native_pin_mismatch",
    )
    require(raw.get("native-plan.json") == encode(native_plan), "native_plan_pin")
    if expected_sources_sha256 is None:
        require(sources == runtime_sources(), "runtime_source_changed")
    else:
        # Explicit offline mode: the consumer selects retained producer source
        # bytes rather than installing that producer's SDK/runtime again.
        require(
            digest(encode({name: digest(value) for name, value in sources.items()}))
            == expected_sources_sha256,
            "retained_source_pin_mismatch",
        )
        # Recompute the pinned SDK release's retained source commitments without
        # importing the SDK. Retained runtime versions describe the producer.
        manifest = decode(sources["sdk-source-pins.json"])
        require(
            manifest == decode((ROOT / "sdk-source-pins.json").read_bytes()),
            "retained_sdk_manifest_changed",
        )
        modules = decode(sources["sdk-source.json"])
        require(
            type(modules) is dict
            and set(modules) == set(MODULES)
            and all(type(code) is str for code in modules.values())
            and {name: digest(code.encode()) for name, code in modules.items()}
            == manifest["modules"],
            "retained_sdk_source_changed",
        )
        require(
            sources["sdk-license.txt"] == (ROOT / "SDK-LICENSE").read_bytes(),
            "retained_sdk_license_changed",
        )
        require(
            decode(sources["runtime.json"])["packages"]["a2a-sdk"] == SDK_VERSION,
            "retained_sdk_runtime_version",
        )
    require(
        {
            "native-plan.json",
            "launch-ledger.json",
            "agent-card.json",
            "server-events.jsonl",
        }
        <= set(raw),
        "native_core_artifacts",
    )
    native_events = [decode(line) for line in raw["server-events.jsonl"].splitlines()]
    ledger = decode(raw["launch-ledger.json"])
    require(type(ledger) is list, "launch_ledger_shape")
    card = decode(raw["agent-card.json"])
    require(
        card
        == {
            "name": "local-arithmetic-agent",
            "version": "deterministic-v1",
            "supportedInterfaces": [
                {
                    "url": native_plan["endpoint"],
                    "protocolBinding": "JSONRPC",
                    "protocolVersion": "1.0",
                }
            ],
        },
        "agent_card_binding",
    )
    artifacts = {**sources, **raw}
    require(len(artifacts) == len(sources) + len(raw), "artifact_collision")
    config = encode(
        {
            "native_plan_sha256": digest(raw["native-plan.json"]),
            "runtime": ref("runtime.json", sources["runtime.json"]),
            "mapper": ref("local-source.json", sources["local-source.json"]),
            "sdk": ref(
                "sdk-source-pins.json", sources["sdk-source-pins.json"], SDK_COMMIT
            ),
        }
    )
    artifacts["mapping-config.json"] = config
    mapped_sources = {}
    for role, name, identity in (
        ("task", "native-plan.json", "local-arithmetic-tasks"),
        ("harness", "sdk-source.json", "a2a-sdk-" + SDK_VERSION),
        ("model", "local-source.json", "deterministic-no-model"),
        ("rubric", "rubric.json", "exact-decimal-response"),
        ("policy", "policy.json", "bounded-local-reader"),
        ("configuration", "mapping-config.json", MAPPING),
    ):
        mapped_sources[role] = {
            "identity": identity,
            "revision": MAPPING,
            "artifact": ref(name, artifacts[name]),
        }
    plan = {
        "profile": PROFILE,
        "run_id": native_plan["run_id"],
        "mode": "retained-native",
        "roles": {role: "same-local-operator" for role in ROLES},
        "sources": mapped_sources,
        "attempts": [],
    }
    records, starts, consumed = (
        [],
        [],
        {
            "native-plan.json",
            "launch-ledger.json",
            "agent-card.json",
            "server-events.jsonl",
        },
    )
    position = 0
    for case in native_plan["attempts"]:
        aid = case["attempt_id"]
        spec = {
            "identity": {
                "task_id": "arithmetic-task-" + aid,
                "logical_request_id": case["logical_request_id"],
                "attempt_id": aid,
                "interval_id": native_plan["run_id"],
                "catalog_authority_id": "declared-local-arithmetic-catalog",
                "capability_id": "decimal-addition",
                "runtime_target_id": native_plan["endpoint"],
                "effect_id": None,
                "consumer_decision_id": None,
            },
            "tier": "a2a",
            "parent_attempt_id": None,
        }
        plan["attempts"].append(spec)
        outcome, status, elapsed = "unknown", "start-unknown", None
        evidence = []
        gaps = [
            "external_effects_not_observed",
            "server_identity_not_authenticated",
            "native_transcript_completeness_not_established",
        ]
        if case["input"] == "not-launched":
            gaps.append("start_evidence_missing")
        else:
            require(position + 1 < len(ledger), "launch_pair_missing")
            require(
                ledger[position] == {"attempt_id": aid, "event": "client-start"},
                "launch_start_binding",
            )
            finish = ledger[position + 1]
            require(
                type(finish) is dict
                and set(finish) == {"attempt_id", "event", "outcome", "elapsed_ns"}
                and finish["attempt_id"] == aid
                and finish["event"] == "client-finished",
                "launch_finish_binding",
            )
            require(
                type(finish["elapsed_ns"]) is int
                and finish["elapsed_ns"] >= 0
                and finish["outcome"] in {"returned", "timeout", "client-error"},
                "launch_measurement",
            )
            elapsed, position = finish["elapsed_ns"], position + 2
            require(len(native_events) >= position // 2, "server_execution_missing")
            native_event = native_events[position // 2 - 1]
            require(
                type(native_event) is dict
                and set(native_event)
                == {"message_id", "context_id", "task_id", "input"}
                and native_event["message_id"] == aid
                and native_event["context_id"] == case["logical_request_id"]
                and native_event["input"] == case["input"]
                and type(native_event["task_id"]) is str
                and native_event["task_id"],
                "server_execution_binding",
            )
            starts.append(aid)
            metadata_name = aid + "-request-metadata.json"
            consumed.add(metadata_name)
            require(metadata_name in raw, "http_request_missing")
            require(
                decode(raw[metadata_name])
                == {
                    "method": "POST",
                    "url": native_plan["endpoint"],
                    "a2a_version": "1.0",
                },
                "http_request_binding",
            )
            name = aid + "-request.json"
            require(name in raw, "rpc_request_missing")
            request = decode(raw[name])
            consumed.add(name)
            require(
                type(request) is dict
                and set(request) == {"jsonrpc", "id", "method", "params"}
                and request["jsonrpc"] == "2.0"
                and type(request["id"]) is str
                and request["id"]
                and request["method"] == "SendMessage",
                "rpc_request_shape",
            )
            require(
                request["params"]
                == {
                    "message": {
                        "messageId": aid,
                        "contextId": case["logical_request_id"],
                        "role": "ROLE_USER",
                        "parts": [{"text": case["input"]}],
                    }
                },
                "request_semantic_binding",
            )
            evidence.append(ref(name, raw[name]))
            response_name = aid + "-response.json"
            if response_name not in raw:
                require(
                    finish["outcome"] != "returned",
                    "successful_command_without_response",
                )
                status = "incomplete"
                gaps.append("native_response_missing")
            else:
                consumed.add(response_name)
                http_name = aid + "-response-status.json"
                consumed.add(http_name)
                require(http_name in raw, "http_response_missing")
                require(
                    decode(raw[http_name]) == {"status": 200}, "http_response_status"
                )
                response = decode(raw[response_name])
                require(
                    type(response) is dict
                    and set(response)
                    in ({"id", "jsonrpc", "result"}, {"id", "jsonrpc", "error"})
                    and response["id"] == request["id"]
                    and response["jsonrpc"] == "2.0",
                    "rpc_response_binding",
                )
                result = response.get("result")
                if "error" in response:
                    require(
                        case["input"] == "reject"
                        and response["error"]
                        == {"code": -32603, "message": "declared rejection control"}
                        and finish["outcome"] == "client-error",
                        "rpc_error_binding",
                    )
                    status = "error"
                elif type(result) is dict and "message" in result:
                    require(set(result) == {"message"}, "message_result_shape")
                    message = result["message"]
                    require(
                        message
                        == {
                            "messageId": "reply-" + aid,
                            "role": "ROLE_AGENT",
                            "parts": [
                                {"text": str(sum(map(int, case["input"].split("+"))))}
                            ],
                        },
                        "response_semantic_binding",
                    )
                    require(finish["outcome"] == "returned", "response_client_outcome")
                    status = "complete"
                    outcome = (
                        "pass"
                        if message["parts"][0]["text"] == case["expected"]
                        else "fail"
                    )
                else:
                    require(
                        type(result) is dict
                        and set(result) == {"task"}
                        and case["input"] == "task-failed",
                        "task_result_binding",
                    )
                    task = result["task"]
                    require(
                        task
                        == {
                            "id": native_event["task_id"],
                            "contextId": case["logical_request_id"],
                            "status": {"state": "TASK_STATE_FAILED"},
                            "history": [
                                {
                                    **request["params"]["message"],
                                    "taskId": native_event["task_id"],
                                }
                            ],
                        }
                        and finish["outcome"] == "returned",
                        "task_error_binding",
                    )
                    status = "error"
                evidence.append(ref(response_name, raw[response_name]))
            error_name = aid + "-client-error.json"
            if error_name in raw:
                consumed.add(error_name)
                error = decode(raw[error_name])
                require(
                    type(error) is dict
                    and set(error) == {"type"}
                    and type(error["type"]) is str
                    and finish["outcome"] == "client-error",
                    "client_error_binding",
                )
        claims = {
            axis: {
                "status": "not-exercised",
                "reason_code": "native_profile_does_not_measure_axis",
                "native_reason": "Bounded same-operator HTTP protocol exercise",
                "profile": MAPPING,
                "evidence": [],
            }
            for axis in AXES
        }
        claims["task_outcome"] = {
            "status": outcome,
            "reason_code": "native_exact_decimal"
            if status == "complete"
            else "native_attempt_unscored",
            "native_reason": "Recomputed from original request/response and predeclared rubric",
            "profile": MAPPING,
            "evidence": evidence,
        }
        record = {
            "run_id": plan["run_id"],
            **spec,
            "harness_status": status,
            "resources": {**{key: None for key in RESOURCES}, "elapsed_ns": elapsed},
            "claims": claims,
            "capture": {
                "scope": "local-sdk-client-http-exchange",
                "complete": False,
                "gaps": gaps,
                "observed_effect_count": None,
            },
        }
        output_name = aid + "-mapped.json"
        artifacts[output_name] = encode(record)
        records.append({**record, "output": ref(output_name, artifacts[output_name])})
    require(
        position == len(ledger)
        and len(native_events) == len(starts)
        and consumed == set(raw),
        "undeclared_native_artifacts",
    )
    artifacts["mapped-start-ledger.json"] = encode(
        {"run_id": plan["run_id"], "starts": starts}
    )
    history = {
        "profile": PROFILE,
        "run_id": plan["run_id"],
        "plan_sha256": digest(encode(plan)),
        "start_ledger": starts,
        "history_head_ref": ref(
            "mapped-start-ledger.json", artifacts["mapped-start-ledger.json"]
        ),
        "records": records,
    }
    return plan, history, artifacts


def verify(
    native_plan,
    raw,
    sources,
    selected_native_pins,
    plan_bytes,
    history_bytes,
    artifacts,
    *,
    expected_plan_sha256,
    expected_history_sha256,
    expected_sources_sha256=None,
) -> dict:
    plan, history, retained = adapt(
        native_plan,
        raw,
        sources,
        selected_native_pins,
        expected_sources_sha256=expected_sources_sha256,
    )
    require(decode(plan_bytes) == plan, "native_plan_mapping_mismatch")
    require(decode(history_bytes) == history, "native_history_mapping_mismatch")
    require(artifacts == retained, "native_artifact_mapping_mismatch")
    report = validate(
        plan_bytes,
        history_bytes,
        artifacts,
        expected_plan_sha256=expected_plan_sha256,
        expected_history_sha256=expected_history_sha256,
    )
    return {
        **report,
        "mapping": MAPPING,
        "sdk_version": SDK_VERSION,
        "sdk_commit": SDK_COMMIT,
        "interpretation": "actual-local-SDK-HTTP-no-model-benchmark",
        "custody": "same-operator",
        "priorNativePlanCommitment": "local-file-written-before-launch-not-independently-witnessed",
        "priorCommonPlanCommitment": "not-established",
        "nativePinAuthority": "consumer-selected-digests-not-bundle-self-pins",
    }
