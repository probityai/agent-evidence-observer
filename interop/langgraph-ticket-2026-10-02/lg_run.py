"""Run six declared real LangGraph graphs against protected HTTP ticket rows."""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import platform
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, TypedDict
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from lg_common import CASES, PROFILE, VERSION, decode, encode, project, require, sha, write
from probity_observer.aae_enforce import enforce_check, native_digest
from probity_observer.aae_ticket import AaeTicketStore, ticket_transaction
from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant, utc_clock
from probity_observer.crypto import SigningKey, VerificationError, canonical
from probity_observer.ticket_service import MAX_BODY, running_server

SOURCES = ("aae_ticket.py", "aae_enforce.py", "authorization.py", "crypto.py", "ticket_service.py")


class GraphState(TypedDict):
    """Explicit graph channels, retained in native checkpoint snapshots."""
    contentHex: str
    result: dict[str, Any]


def evidence_clock() -> datetime:
    """Return the full-precision UTC clock for the native evidence interval.

    Native checkpoint timestamps retain fractional seconds. Their selection and
    evaluation envelope must therefore retain the same clock precision. This is
    separate from :func:`probity_observer.authorization.utc_clock`, whose whole
    seconds are required by the signed grant and ticket service profiles.
    """
    return datetime.now(timezone.utc)


def select_case(root: Path, run_id: str, name: str) -> tuple[dict[str, Any], AaeTicketStore]:
    """Freeze one exact authority, request and host configuration before running.

    Keys are distinct but belong to this Probity process. The unsigned native
    mandate remains unauthenticated; the signed grant binds one selected action.
    """
    now = utc_clock()
    content = b'{"status":"DONE"}'
    issuer, service = SigningKey.generate(), SigningKey.generate()
    request = ActionRequest(run_id, name, "request-" + name, "tenant", "principal", "ticket-update", "/work/tickets/" + name, sha(content))
    transaction = ticket_transaction(request)
    mandate = {"grants": [{"action_binding": native_digest("action", transaction["action"]), "type_fields": ["verb", "targetKind"], "disposition": "forbid" if name == "deny" else "allow", "constraints": [{"type": "exact", "field": field, "value": value} for field, value in transaction.items() if field != "action"]}]}
    decision = {"mandate": mandate, "transaction": transaction, "record": enforce_check(mandate, transaction), "pinned_mandate_digest": native_digest("mandate", mandate)}
    policy = GrantPolicy(issuer.public_hex, max_validity_seconds=3600)
    grant = issue_grant(request, issuer, issued_at=now, expires_at=now + timedelta(seconds=3600))
    def fault(point: str) -> None:
        if name == "pending-intent" and point == "after-intent":
            raise VerificationError("selected interruption after durable intent")
    store = AaeTicketStore(root / "stores" / (name + ".sqlite"), request, policy, service, crash_hook=fault, **decision)
    initial = store.initialize()
    case = {"id": name, "request": asdict(request), "policy": asdict(policy), "serviceKey": service.public_hex, "grant": grant, "decision": decision, "configuration": store.configuration, "initial": initial, "contentHex": content.hex(), "graphInputHex": b'{"status":"CHANGED"}'.hex() if name == "altered-argument" else content.hex()}
    return case, store


def retain_sources(root: Path) -> dict[str, str]:
    """Retain adapter/base source bytes plus installed distribution file hashes."""
    import probity_observer
    own = Path(__file__).parent
    base = Path(probity_observer.__file__).parent
    files = {"adapter/" + p.name: p.read_bytes() for p in sorted(own.glob("*.py"))}
    files.update({"observer/" + name: (base / name).read_bytes() for name in SOURCES})
    for name, raw in files.items():
        path = root / "sources" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    return {name: sha(raw) for name, raw in files.items()}


def environment() -> dict[str, Any]:
    """Account for installed dependency versions and literal distribution files."""
    distributions = sorted(importlib.metadata.distributions(), key=lambda d: d.metadata["Name"].lower())
    return {"python": platform.python_version(), "packages": {d.metadata["Name"]: {"version": d.version, "files": {str(p): sha(Path(d.locate_file(p)).read_bytes()) for p in (d.files or []) if Path(d.locate_file(p)).is_file() and "__pycache__" not in str(p)}} for d in distributions if d.metadata["Name"] != "agent-evidence-observer"}}


def exchange(url: str, candidate: dict[str, Any] | None = None) -> tuple[int, dict[str, Any], str]:
    """Retain literal finite HTTP response bytes alongside their parsed projection."""
    request = Request(url, data=None if candidate is None else canonical(candidate), headers={"Content-Type": "application/json"})
    try:
        response = urlopen(request, timeout=5)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read(MAX_BODY + 1)
        require(len(raw) <= MAX_BODY, "http-response-size")
        return response.code, decode(raw), raw.hex()


def execute(case: dict[str, Any], store: AaeTicketStore) -> dict[str, Any]:
    """Execute the real one-node graph and retain every native call boundary.

    ``resume-after-effect`` places the interrupt after HTTP dispatch. LangGraph
    re-executes that node on resume; the service checks fresh authority and returns
    its retained completed receipt. This only demonstrates this bounded service
    behavior. It is not a general exactly-once claim or a process-crash test.
    """
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.graph import END, START, StateGraph
    from langgraph.types import Command, interrupt
    calls: list[dict[str, Any]] = []
    with running_server(store) as server:
        def dispatch(state: GraphState) -> dict[str, Any]:
            if case["id"] == "interrupt-before":
                interrupt({"point": "before-dispatch", "caseId": case["id"]})
            candidate = {"request": case["request"], "grant": case["grant"], "contentHex": state["contentHex"]}
            status, response, response_hex = exchange(server.url + "/dispatch", candidate)
            get_status, readback, readback_hex = exchange(server.url + "/tickets/tenant/" + case["id"])
            packet = {"endpoint": server.url, "candidate": candidate, "postStatus": status, "response": response, "getStatus": get_status, "readback": readback, "postRequestHex": canonical(candidate).hex(), "postResponseHex": response_hex, "getResponseHex": readback_hex}
            calls.append(packet)
            if case["id"] == "resume-after-effect":
                interrupt({"point": "after-effect", "caseId": case["id"], "httpSha256": sha(encode(packet))})
            return {"result": {"httpSha256": sha(encode(packet)), "postStatus": status, "revision": readback["revision"]}}
        graph = StateGraph(GraphState)
        graph.add_node("dispatch", dispatch)
        graph.add_edge(START, "dispatch")
        graph.add_edge("dispatch", END)
        app = graph.compile(checkpointer=InMemorySaver())
        config = {"configurable": {"thread_id": case["request"]["run_id"] + "/" + case["id"]}, "recursion_limit": 4}
        boundaries: list[dict[str, Any]] = []
        started = time.perf_counter_ns()
        result = app.invoke({"contentHex": case["graphInputHex"], "result": {}}, config)
        boundaries.append({"operation": "invoke", "result": project(result), "snapshot": project(app.get_state(config)), "httpCalls": len(calls)})
        if case["id"] in {"interrupt-before", "resume-after-effect"}:
            result = app.invoke(Command(resume=True), config)
            boundaries.append({"operation": "resume", "result": project(result), "snapshot": project(app.get_state(config)), "httpCalls": len(calls)})
        final_status, final_readback, final_hex = exchange(server.url + "/tickets/tenant/" + case["id"])
        return {"config": config, "boundaries": boundaries, "history": project(list(app.get_state_history(config))), "http": calls, "finalStatus": final_status, "finalReadback": final_readback, "finalReadbackHex": final_hex, "elapsedNs": time.perf_counter_ns() - started}


def run(output: Path, revision: str) -> dict[str, Any]:
    """Freeze the finite plan, execute all attempts, and invoke the offline reader."""
    from lg_reader import verify_saved
    require(importlib.metadata.version("langgraph") == VERSION, "framework-version")
    output.mkdir(parents=True, exist_ok=False)
    run_id = "langgraph-" + uuid.uuid4().hex
    selections = [select_case(output, run_id, name) for name in CASES]
    sources = retain_sources(output)
    write(output / "sources-before-run.json", sources)
    write(output / "environment-before-run.json", environment())
    plan = {"profile": PROFILE, "frameworkVersion": VERSION, "runId": run_id, "sourceRevision": revision, "selectedTime": evidence_clock().isoformat(), "cases": [case for case, _ in selections], "sourcesSha256": sha(encode(sources)), "environmentSha256": sha((output / "environment-before-run.json").read_bytes()), "graph": {"nodes": ["dispatch"], "edges": [["__start__", "dispatch"], ["dispatch", "__end__"]], "checkpointer": "InMemorySaver", "recursionLimit": 4, "providerCalls": 0}}
    write(output / "plan-before-run.json", plan)
    for case, store in selections:
        write(output / "attempts" / (case["id"] + ".json"), execute(case, store))
    manifest = {p.name: sha(p.read_bytes()) for p in sorted((output / "attempts").iterdir())}
    write(output / "artifact-manifest.json", manifest)
    pins = {"planSha256": sha(encode(plan)), "artifactManifestSha256": sha(encode(manifest)), "evaluationTime": evidence_clock().isoformat()}
    write(output / "consumer-pins.json", pins)
    report = verify_saved(output, pins)
    write(output / "report.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--source-revision", default="working-tree")
    args = parser.parse_args()
    print(json.dumps(run(args.output, args.source_revision), indent=2))
