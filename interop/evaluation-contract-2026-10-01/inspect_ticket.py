"""Join native Inspect calls to selected AAE authority and HTTP ticket effects.

Controlled mock outputs exercise the real framework and service. A selected
pre-run plan and retained native bytes are trust inputs, not independent custody.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import uuid
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from evaluation_contract import decode, encode, require
from probity_observer.aae_enforce import enforce_check, native_digest
from probity_observer.aae_ticket import AaeTicketStore, ticket_transaction, verify_aae_ticket_result
from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant, utc_clock, verify_grant
from probity_observer.crypto import SigningKey, VerificationError, canonical, digest as domain_digest
from probity_observer.ticket_service import DOMAIN, MAX_BODY, _checked, _state_schema, running_server

PROFILE = "probity-inspect-aae-ticket-v0"
INSPECT_VERSION = "0.3.273"
CASES = (
    ("permit-pass", "allow", "DONE", "DONE", True, False),
    ("permit-task-fail", "allow", "wrong", "DONE", True, False),
    ("kernel-deny", "forbid", "DENIED", "DENIED", True, False),
    ("pending-effect", "allow", "INCOMPLETE", "INCOMPLETE", True, True),
    ("model-error-after-effect", "allow", None, "DONE", True, False),
    ("planned-unstarted", "allow", "DONE", "DONE", False, False),
)
SOURCE_FILES = (
    "interop/evaluation-contract-2026-10-01/inspect_ticket.py",
    "interop/evaluation-contract-2026-10-01/evaluation_contract.py",
    "src/probity_observer/aae_ticket.py", "src/probity_observer/aae_enforce.py",
    "src/probity_observer/ticket_service.py", "src/probity_observer/authorization.py",
    "src/probity_observer/crypto.py", "tests/fixtures/aae-enforce/source-manifest.json",
)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)


def read(root: Path, name: str) -> bytes:
    path = root / name
    cursor = path
    while cursor != root.parent:
        require(not cursor.is_symlink(), "ticket_packet_symlink")
        if cursor == root:
            break
        cursor = cursor.parent
    require(path.resolve().is_relative_to(root.resolve()) and not path.is_symlink(), "ticket_packet_path")
    with path.open("rb") as stream:
        raw = stream.read(8 * 1024 * 1024 + 1)
    require(len(raw) <= 8 * 1024 * 1024, "ticket_packet_size")
    return raw


def http_bytes(url: str, raw: bytes | None = None) -> tuple[int, bytes]:
    request = Request(url, data=raw, headers={"Content-Type": "application/json"})
    try:
        response = urlopen(request, timeout=5)
    except HTTPError as error:
        response = error
    with response:
        value = response.read(MAX_BODY + 1)
        require(len(value) <= MAX_BODY, "ticket_http_size")
        return response.code, value


def sources() -> dict[str, bytes]:
    import inspect_ai
    root = Path(__file__).resolve().parents[2]
    own = {name: (root / name).read_bytes() for name in SOURCE_FILES}
    installed = Path(inspect_ai.__file__).parent
    for name in ("_eval/eval.py", "agent/_react.py", "model/_providers/mockllm.py", "scorer/_match.py", "tool/_tool.py"):
        own["inspect/" + name] = (installed / name).read_bytes()
    distribution = importlib.metadata.distribution("inspect-ai")
    own["inspect/METADATA"] = distribution.read_text("METADATA").encode()
    own["inspect/LICENSE"] = Path(distribution.locate_file(f"inspect_ai-{INSPECT_VERSION}.dist-info/licenses/LICENSE")).read_bytes()
    own["inspect/runtime-files.json"] = encode({str(p.relative_to(installed)): sha(p.read_bytes()) for p in sorted(installed.rglob("*.py"))})
    return own


def prepare(output: Path, source_revision: str) -> tuple[dict, dict]:
    """Select all public authority inputs and source bytes before native calls."""
    output.mkdir(parents=True, exist_ok=False)
    require(importlib.metadata.version("inspect-ai") == INSPECT_VERSION, "ticket_inspect_version")
    run_id = "inspect-ticket-" + uuid.uuid4().hex
    now = utc_clock()
    hosts, cases = {}, []
    for name, disposition, final, target, launch, interrupt in CASES:
        folder = output / "stores" / name
        folder.mkdir(parents=True)
        issuer, key = SigningKey.generate(), SigningKey.generate()
        content = b'{"status":"DONE"}'
        request = ActionRequest(run_id, name, "request-" + name, "tenant", "principal", "ticket-update", "/work/tickets/" + name, sha(content))
        transaction = ticket_transaction(request)
        mandate = {"grants": [{"action_binding": native_digest("action", transaction["action"]), "type_fields": ["verb", "targetKind"], "disposition": disposition, "constraints": [{"type": "exact", "field": field, "value": value} for field, value in transaction.items() if field != "action"]}]}
        decision = {"mandate": mandate, "transaction": transaction, "record": enforce_check(mandate, transaction), "pinned_mandate_digest": native_digest("mandate", mandate)}
        policy = GrantPolicy(issuer.public_hex, max_validity_seconds=3600)
        grant = issue_grant(request, issuer, issued_at=now, expires_at=now + timedelta(seconds=3600))
        def fault(point: str, interrupted: bool = interrupt) -> None:
            if interrupted and point == "after-intent":
                raise VerificationError("declared interruption after durable intent")
        store = AaeTicketStore(folder / "store.sqlite", request, policy, key, crash_hook=fault, **decision)
        initial = store.initialize()
        case = {"id": name, "launch": launch, "final": final, "target": target, "interruptAfterIntent": interrupt, "request": asdict(request), "policy": asdict(policy), "serviceKey": key.public_hex, "grant": grant, "contentHex": content.hex(), "decision": decision, "configuration": store.configuration, "initial": initial}
        hosts[name] = store
        cases.append(case)
    retained = sources()
    for name, raw in retained.items():
        write(output / "sources" / name, raw)
    source_manifest = {name: sha(raw) for name, raw in retained.items()}
    write(output / "source-manifest-before-run.json", encode(source_manifest))
    plan = {"profile": PROFILE, "runId": run_id, "sourceRevision": source_revision, "sourceManifestSha256": sha(encode(source_manifest)), "inspectVersion": INSPECT_VERSION, "selectedTime": now.isoformat(), "input": "Run the one selected ticket dispatch.", "cases": cases}
    write(output / "plan-before-run.json", encode(plan))
    return plan, hosts


def execute(output: Path, plan: dict, case: dict, store: AaeTicketStore) -> dict:
    """Run real ReAct; its registered tool performs one native HTTP request."""
    import inspect_ai
    from inspect_ai.agent import react
    from inspect_ai.dataset import Sample
    from inspect_ai.model import ChatMessageAssistant, ModelOutput, ModelUsage, get_model
    from inspect_ai.scorer import match
    from inspect_ai.tool import ToolCall, tool

    with running_server(store) as server:
        @tool
        def dispatch_ticket():
            async def dispatch(content: str) -> str:
                """Dispatch the exact selected ticket update.

                Args:
                    content: Literal selected status, DONE.
                """
                require(content == "DONE", "ticket_native_tool_argument")
                request_raw = canonical({"request": case["request"], "grant": case["grant"], "contentHex": case["contentHex"]})
                status, response = http_bytes(server.url + "/dispatch", request_raw)
                read_status, readback = http_bytes(server.url + "/tickets/tenant/" + case["id"])
                packet = {"endpoint": server.url, "postPath": "/dispatch", "getPath": "/tickets/tenant/" + case["id"], "postRequestHex": request_raw.hex(), "postStatus": status, "postResponseHex": response.hex(), "getStatus": read_status, "getResponseHex": readback.hex()}
                packet_raw = encode(packet)
                write(output / "artifacts" / (case["id"] + "-http.json"), packet_raw)
                return canonical({"httpSha256": sha(packet_raw), "postStatus": status, "nativeRevision": decode(readback)["revision"]}).decode()
            return dispatch
        outputs = [ModelOutput.from_message(ChatMessageAssistant(content="", tool_calls=[ToolCall(id="call-" + case["id"], function="dispatch_ticket", arguments={"content": "DONE"})]), stop_reason="tool_calls")]
        if case["final"] is not None:
            outputs.append(ModelOutput.from_content(model="mockllm", content=case["final"]))
        for item in outputs:
            item.usage = ModelUsage(input_tokens=0, output_tokens=0, total_tokens=0)
        model = get_model("mockllm/model", custom_outputs=outputs)
        task = inspect_ai.Task(dataset=[Sample(id=case["id"], input=plan["input"], target=case["target"])], solver=react(tools=[dispatch_ticket()], submit=False), scorer=match(), name=case["id"], version=1, message_limit=12, metadata={"probity_ticket_profile": PROFILE, "probity_plan_sha256": sha(encode(plan))})
        log_dir = output / "native" / case["id"]
        inspect_ai.eval(task, model=model, display="none", log_format="json", log_dir=str(log_dir), epochs=1, retry_on_error=0, max_samples=1, fail_on_error=True)
    files = list(log_dir.glob("*.json"))
    require(len(files) == 1, "ticket_native_log_population")
    raw = files[0].read_bytes()
    write(output / "artifacts" / (case["id"] + "-native.json"), raw)
    native = decode(raw)
    return {"sha256": sha(raw), "runId": native["eval"]["run_id"], "evalId": native["eval"]["eval_id"]}


def signed_state(case: dict, snapshot: dict) -> dict:
    """Authenticate a native snapshot under the selected service configuration."""
    require(set(snapshot) == {"tenantId", "ticketId", "contentHex", "revision", "effectId", "receipt"}, "ticket_snapshot_fields")
    state = _checked(snapshot["receipt"], case["serviceKey"])
    _state_schema(state, receipt=True)
    require(snapshot["tenantId"] == "tenant" and snapshot["ticketId"] == case["id"], "ticket_snapshot_identity")
    require(state["request"] == case["request"] and state["authorityKey"] == case["policy"]["issuer_key"], "ticket_snapshot_request")
    require(state["configuration"] == domain_digest(DOMAIN + "-configuration", case["configuration"]), "ticket_snapshot_configuration")
    require(type(snapshot["revision"]) is int and snapshot["revision"] == state["revision"] and snapshot["effectId"] == state["effectId"], "ticket_snapshot_relation")
    require(state["witnessScope"] == "PEER" and state["coverage"] == "one-native-ticket-row-and-service-events", "ticket_snapshot_scope")
    if state["revision"] == 0:
        require(snapshot["contentHex"] is None, "ticket_snapshot_zero_content")
    return state


def _same(actual: object, expected: object, reason: str) -> None:
    require(encode(actual) == encode(expected), reason)


def native_sample(raw: bytes, selected: dict, plan: dict, case: dict, packet_raw: bytes) -> tuple[str, str]:
    """Reconstruct task status and join actual call/event/result IDs to HTTP bytes."""
    require(sha(raw) == selected["sha256"], "ticket_native_pin")
    log = decode(raw)
    require(log.get("version") == 2 and log.get("status") in {"success", "error", "started"}, "ticket_native_log")
    ev = log["eval"]
    require(ev["run_id"] == selected["runId"] and ev["eval_id"] == selected["evalId"], "ticket_native_identity")
    require(ev["task"] == case["id"] and type(ev["task_version"]) is int and ev["task_version"] == 1 and ev["model"] == "mockllm/model" and ev["packages"]["inspect_ai"] == INSPECT_VERSION, "ticket_native_task")
    _same(ev["metadata"], {"probity_ticket_profile": PROFILE, "probity_plan_sha256": sha(encode(plan))}, "ticket_native_plan")
    conf = ev["config"]
    require(all(type(conf[k]) is int and conf[k] == v for k, v in {"epochs": 1, "retry_on_error": 0, "max_samples": 1, "message_limit": 12}.items()) and conf["log_samples"] is True and conf["score_on_error"] is False, "ticket_native_config")
    require(ev["dataset"]["sample_ids"] == [case["id"]] and ev["dataset"]["samples"] == 1, "ticket_native_population")
    require(len(ev["scorers"]) == 1 and ev["scorers"][0]["name"] == "match" and ev["scorers"][0]["options"] == {}, "ticket_native_scorer")
    steps = log["plan"]["steps"]
    require(len(steps) == 1 and steps[0]["solver"] == "react", "ticket_native_solver")
    params = steps[0]["params"]
    require(params["submit"] is False and type(params["attempts"]) is int and params["attempts"] == 1 and params["truncation"] == "disabled", "ticket_native_solver_options")
    _same(params["tools"], [{"type": "tool", "name": "dispatch_ticket", "params": {}}], "ticket_native_tools")
    require(all(params.get(k) is None for k in ("model", "on_continue", "retry_refusals", "compaction", "approval", "review")), "ticket_native_solver_options")
    require(type(log["samples"]) is list and len(log["samples"]) == 1, "ticket_native_sample_population")
    sample = log["samples"][0]
    require(sample["id"] == case["id"] and type(sample["epoch"]) is int and sample["epoch"] == 1 and sample["input"] == plan["input"] and sample["target"] == case["target"] and sample.get("error_retries", []) == [], "ticket_native_sample")
    try:
        start = datetime.fromisoformat(sample["started_at"])
        end = None if sample.get("completed_at") is None else datetime.fromisoformat(sample["completed_at"])
    except (ValueError, TypeError):
        require(False, "ticket_native_timestamp")
    require(start.tzinfo is not None and (end is None or (end.tzinfo is not None and end >= start)), "ticket_native_timestamp")
    events = [e for e in sample["events"] if e.get("event") == "tool"]
    calls = [c for m in sample["messages"] if m["role"] == "assistant" for c in m.get("tool_calls", [])]
    replies = [m for m in sample["messages"] if m["role"] == "tool"]
    require(len(events) == len(calls) == len(replies) == 1, "ticket_native_call_population")
    event, call, reply = events[0], calls[0], replies[0]
    require(event["id"] == call["id"] == reply["tool_call_id"] == "call-" + case["id"] and event["function"] == call["function"] == reply["function"] == "dispatch_ticket", "ticket_native_call_identity")
    _same(event["arguments"], {"content": "DONE"}, "ticket_native_argument")
    _same(call["arguments"], event["arguments"], "ticket_native_argument")
    packet = decode(packet_raw)
    result = canonical({"httpSha256": sha(packet_raw), "postStatus": packet["postStatus"], "nativeRevision": decode(bytes.fromhex(packet["getResponseHex"]))["revision"]}).decode()
    require(event.get("error") is None and reply.get("error") is None and event["result"] == reply["content"] == result, "ticket_native_http_join")
    if sample.get("error") is not None:
        require(log["status"] == "error" and sample.get("scores") in ({}, None), "ticket_native_error_score")
        return "error", "unknown"
    if end is None:
        require(log["status"] != "success" and not sample.get("scores"), "ticket_native_incomplete_score")
        return "incomplete", "unknown"
    require(log["status"] == "success", "ticket_native_completion")
    scores = sample["scores"]
    require(set(scores) == {"match"} and scores["match"]["value"] in {"C", "I"}, "ticket_native_score")
    output = sample["output"]["choices"][0]["message"]["content"]
    require(output == case["final"], "ticket_native_output")
    expected = "C" if output == case["target"] else "I"
    require(scores["match"]["value"] == expected, "ticket_native_score_recomputed")
    return "complete", "pass" if expected == "C" else "fail"


def verify_saved(output: Path, selected: dict) -> dict:
    """Offline reader; selected pins must be carried separately from this packet."""
    require(not output.is_symlink() and not any(p.is_symlink() for p in output.rglob("*")), "ticket_packet_symlink")
    require(set(selected) == {"planSha256", "sourceManifestSha256", "artifactManifestSha256", "evaluationTime"}, "ticket_consumer_pins")
    plan_raw, source_raw, manifest_raw = (read(output, name) for name in ("plan-before-run.json", "source-manifest-before-run.json", "artifact-manifest.json"))
    for raw, field in ((plan_raw, "planSha256"), (source_raw, "sourceManifestSha256"), (manifest_raw, "artifactManifestSha256")):
        require(type(selected[field]) is str and sha(raw) == selected[field], "ticket_external_pin_" + field)
    plan, source_manifest, manifest = map(decode, (plan_raw, source_raw, manifest_raw))
    require(plan["profile"] == PROFILE and plan["inspectVersion"] == INSPECT_VERSION and plan["sourceManifestSha256"] == sha(source_raw), "ticket_plan_profile")
    expected_source_names = set(SOURCE_FILES) | {"inspect/" + n for n in ("_eval/eval.py", "agent/_react.py", "model/_providers/mockllm.py", "scorer/_match.py", "tool/_tool.py", "METADATA", "LICENSE", "runtime-files.json")}
    require(set(source_manifest) == expected_source_names, "ticket_source_population")
    for name, pin in source_manifest.items():
        require(sha(read(output / "sources", name)) == pin, "ticket_source_pin")
    require({str(p.relative_to(output / "sources")) for p in (output / "sources").rglob("*") if p.is_file()} == set(source_manifest), "ticket_source_population")
    require(set(manifest) == {"bindings", "artifacts"}, "ticket_manifest_fields")
    cases = plan["cases"]
    require([c["id"] for c in cases] == [c[0] for c in CASES], "ticket_plan_population")
    allowed = {c["id"] for c in cases if c["launch"]}
    require(set(manifest["bindings"]) <= allowed, "ticket_binding_population")
    require(set(manifest["artifacts"]) == {a + suffix for a in manifest["bindings"] for suffix in ("-native.json", "-http.json")}, "ticket_artifact_population")
    artifacts = {name: read(output / "artifacts", name) for name in manifest["artifacts"]}
    require({p.name for p in (output / "artifacts").iterdir()} == set(artifacts), "ticket_artifact_population")
    require(all(sha(raw) == manifest["artifacts"][name] for name, raw in artifacts.items()), "ticket_artifact_pin")
    native_root = output / "native"
    require(native_root.is_dir() and {p.name for p in native_root.iterdir()} == set(manifest["bindings"]), "ticket_original_native_population")
    for aid in manifest["bindings"]:
        folder = native_root / aid
        require(folder.is_dir(), "ticket_original_native_population")
        originals = list(folder.iterdir())
        require(len(originals) == 1 and originals[0].is_file() and originals[0].suffix == ".json", "ticket_original_native_population")
        require(read(output, str(originals[0].relative_to(output))) == artifacts[aid + "-native.json"], "ticket_original_native_bytes")
    now = datetime.fromisoformat(selected["evaluationTime"])
    require(now.tzinfo is not None and now >= datetime.fromisoformat(plan["selectedTime"]), "ticket_consumer_time")
    records = []
    for case, definition in zip(cases, CASES, strict=True):
        name, disposition, final, target, launch, interrupted = definition
        _same({k: case[k] for k in ("id", "launch", "final", "target", "interruptAfterIntent")}, {"id": name, "launch": launch, "final": final, "target": target, "interruptAfterIntent": interrupted}, "ticket_declared_case")
        request, policy = ActionRequest(**case["request"]), GrantPolicy(**case["policy"])
        require(request.run_id == plan["runId"] and request.attempt_id == name and request.request_id == "request-" + name and request.target_path == "/work/tickets/" + name, "ticket_request_identity")
        require(sha(bytes.fromhex(case["contentHex"])) == request.content_sha256, "ticket_selected_content")
        decision = case["decision"]
        require(native_digest("mandate", decision["mandate"]) == decision["pinned_mandate_digest"], "ticket_mandate_pin")
        _same(decision["transaction"], ticket_transaction(request), "ticket_transaction")
        actual = enforce_check(decision["mandate"], decision["transaction"])
        _same(decision["record"], actual, "ticket_decision_replay")
        require(actual["verdict"] == ("DENY" if disposition == "forbid" else "PERMIT"), "ticket_kernel_verdict")
        # Same strict commitment relation used by the host, including bounded DENY.
        from probity_observer.aae_ticket import _decision_commitment
        commitment = _decision_commitment(decision["mandate"], decision["transaction"], decision["record"], request, decision["pinned_mandate_digest"], require_permit=False)
        _same(case["configuration"], {"request": case["request"], "policy": case["policy"], "serviceKey": case["serviceKey"], "decisionDigest": commitment}, "ticket_selected_configuration")
        initial = signed_state(case, case["initial"])
        require(initial["phase"] == "ready" and initial["eventCount"] == 1 and initial["revoked"] is False, "ticket_selected_initial")
        authorized = verify_grant(case["grant"], request, policy, now=now)
        if name not in manifest["bindings"]:
            records.append({"attemptId": name, "status": "not-started" if not launch else "start-unknown", "taskOutcome": "unknown", "kernelVerdict": actual["verdict"], "effectOutcome": "unknown", "effectId": None})
            continue
        packet_raw = artifacts[name + "-http.json"]
        status, task_outcome = native_sample(artifacts[name + "-native.json"], manifest["bindings"][name], plan, case, packet_raw)
        packet = decode(packet_raw)
        require(set(packet) == {"endpoint", "postPath", "getPath", "postRequestHex", "postStatus", "postResponseHex", "getStatus", "getResponseHex"}, "ticket_http_fields")
        require(type(packet["endpoint"]) is str and packet["endpoint"].startswith("http://127.0.0.1:") and packet["endpoint"].removeprefix("http://127.0.0.1:").isdigit(), "ticket_http_endpoint")
        require(packet["postPath"] == "/dispatch" and packet["getPath"] == "/tickets/tenant/" + name and type(packet["getStatus"]) is int and packet["getStatus"] == 200 and type(packet["postStatus"]) is int, "ticket_http_route")
        require(bytes.fromhex(packet["postRequestHex"]) == canonical({"request": case["request"], "grant": case["grant"], "contentHex": case["contentHex"]}), "ticket_http_request")
        response, readback = (decode(bytes.fromhex(packet[k])) for k in ("postResponseHex", "getResponseHex"))
        state = signed_state(case, readback)
        if disposition == "forbid":
            require(packet["postStatus"] == 409 and response.get("status") == "refused", "ticket_deny_response")
            _same(readback, case["initial"], "ticket_denied_native_state")
            effect = "not-recorded-local-row"
        elif interrupted:
            require(packet["postStatus"] == 409 and response.get("status") == "refused" and state["phase"] == "pending" and state["revision"] == 0 and state["eventCount"] == 2 and not state["revoked"], "ticket_pending_effect")
            expected_effect = domain_digest(DOMAIN + "-effect", {"configuration": state["configuration"], "requestId": request.request_id, "grantDigest": authorized.grant_digest})
            require(state["effectId"] == expected_effect and state["grantDigest"] == authorized.grant_digest, "ticket_pending_identity")
            from probity_observer.ticket_service import _time
            verify_grant(case["grant"], request, policy, now=_time(state["intentTime"]))
            require(now >= _time(state["intentTime"]), "ticket_pending_time")
            effect = "incomplete-no-automatic-replay"
        else:
            require(packet["postStatus"] == 200, "ticket_completion_response")
            verify_aae_ticket_result(**decision, receipt=response, readback=readback, request=request, policy=policy, service_key=case["serviceKey"], grant=case["grant"], now=now)
            effect = "verified-local-ticket-update"
        records.append({"attemptId": name, "status": status, "taskOutcome": task_outcome, "kernelVerdict": actual["verdict"], "effectOutcome": effect, "effectId": state["effectId"]})
    return {"profile": PROFILE, "status": "verified", "plannedAttempts": len(records), "records": records, "providerCalls": "none-mock-provider", "taskScope": "controlled-native-match-score", "effectScope": "one-selected-local-ticket-per-attempt", "issuerAuthentication": "not-established", "independentCustody": "not-established", "priorSelection": "local-pre-run-plan-not-authenticated-witness", "coverage": "finite-declared-population-original-logs-and-retained-HTTP-bytes"}


def run(output: Path, source_revision: str = "working-tree") -> dict:
    plan, hosts = prepare(output, source_revision)
    bindings = {}
    for case in plan["cases"]:
        if case["launch"]:
            bindings[case["id"]] = execute(output, plan, case, hosts[case["id"]])
    manifest = {"bindings": bindings, "artifacts": {p.name: sha(p.read_bytes()) for p in (output / "artifacts").iterdir()}}
    write(output / "artifact-manifest.json", encode(manifest))
    selected = {"planSha256": sha(read(output, "plan-before-run.json")), "sourceManifestSha256": sha(read(output, "source-manifest-before-run.json")), "artifactManifestSha256": sha(encode(manifest)), "evaluationTime": utc_clock().isoformat()}
    write(output / "consumer-pins.json", encode(selected))
    report = verify_saved(output, selected)
    write(output / "report.json", encode(report))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--source-revision", default="working-tree")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--pins-file", type=Path)
    args = parser.parse_args()
    if args.verify:
        if args.pins_file is None:
            parser.error("--verify requires externally selected --pins-file")
        result = verify_saved(args.output, decode(args.pins_file.read_bytes()))
    else:
        if args.pins_file is not None:
            parser.error("--pins-file requires --verify")
        result = run(args.output, args.source_revision)
    print(json.dumps(result, indent=2))
