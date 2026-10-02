"""Fresh native SQLite worker joining target restart with current authority.

The recovery clock implementation is imported unchanged from merged authority
work. Dispatch and cached-result release both require the host's new selection.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "langgraph-recovery-authority-2026-10-02"))
sys.path.insert(0, str(BASE / "target-recovery-2026-10-02"))
from authority_worker import gate  # noqa: E402
from durable_worker import durable_write  # noqa: E402
from lg_common import project  # noqa: E402
from lg_run import GraphState  # noqa: E402
from target_run import exchange  # noqa: E402
from probity_observer.authorization import ActionRequest, GrantPolicy, verify_grant  # noqa: E402
from probity_observer.crypto import VerificationError, canonical  # noqa: E402
from joint_common import expected_authority, load, require, same, sha  # noqa: E402


def current_gate(conn: sqlite3.Connection, case: dict[str, Any], current: dict[str, Any], phase: str) -> dict[str, Any]:
    """Check the new host selection before invoking any recovery node.

    Parameters
    ----------
    conn : sqlite3.Connection
        Native checkpoint connection; merged ``gate`` serializes the durable
        recovery-clock table in this same database.
    case : dict
        Frozen original action, grant, key, policy and store identity.
    current : dict
        Newly supplied host authority, clock and target startup disposition.
    phase : str
        First invocation or a fresh second/third recovery process.

    Returns
    -------
    dict
        Original gate record plus current-selection disposition. Invalid
        selection never obtains a completion or sends a worker HTTP request.
    """
    same(sorted(current), sorted(["authority", "selection", "clockTime", "targetReady"]), "current-selection-schema")
    require(type(current["targetReady"]) is bool, "current-target-readiness-type")
    same(sorted(current["selection"]), sorted(["grantSha256", "issuerPolicy", "serviceKey", "storeIdentity"]), "current-selection-schema")
    checked = gate(conn, case, current["authority"], "first" if phase == "first" else "second")
    return selected_gate(conn, case, current, phase, checked)


def selected_gate(conn: sqlite3.Connection, case: dict[str, Any], current: dict[str, Any], phase: str, checked: dict[str, Any]) -> dict[str, Any]:
    """Preserve every rejected current selection in the reused denial anchor.

    A malformed host-selected key, store or grant cannot clear an equal-clock
    denial. The merged clock gate persists the additional host denial, and the
    complete denial record remains in the public worker receipt.
    """
    expected = {"grantSha256": sha(canonical(case["grant"])), "issuerPolicy": case["policy"], "serviceKey": case["serviceKey"], "storeIdentity": case["storeIdentity"]}
    if canonical(current["selection"]) != canonical(expected):
        checked["status"] = "refused-current-selection"
    if not current["targetReady"]:
        checked["status"] = "refused-target-startup" if checked["status"] == "authorized" else checked["status"]
    grant_status(case, current, checked)
    if checked["status"] in {"refused-current-selection", "refused-target-startup", "refused-current-grant"}:
        checked["selectionDenialAnchor"] = gate(conn, case, {**current["authority"], "revoked": True}, "first" if phase == "first" else "second")
    return checked


def grant_status(case: dict[str, Any], current: dict[str, Any], checked: dict[str, Any]) -> None:
    """Check signed grant validity at the new clock only after host admission."""
    if checked["status"] != "authorized":
        return
    try:
        verify_grant(case["grant"], ActionRequest(**case["request"]), GrantPolicy(**current["selection"]["issuerPolicy"]), now=datetime.fromisoformat(current["clockTime"]))
    except VerificationError as error:
        checked.update(status="refused-current-grant", grantReason=str(error))


def graph_for(case: dict[str, Any], endpoint: str, phase: str, output: Path, calls: list[dict[str, Any]], saver: Any) -> Any:
    """Compile the same interrupt/dispatch node in each native OS worker.

    LangGraph reruns the interrupted node. The merged target then authenticates
    the current grant before returning a cached effect or refuses pending work.
    """
    from langgraph.graph import END, START, StateGraph
    from langgraph.types import interrupt

    def dispatch(state: GraphState) -> dict[str, Any]:
        if case["id"].endswith("before"):
            interrupt({"point": "before-dispatch", "caseId": case["id"]})
        candidate = {"request": case["request"], "grant": case["grant"], "contentHex": state["contentHex"]}
        post = exchange(endpoint + "/dispatch", candidate)
        readback = exchange(endpoint + "/tickets/tenant/" + case["id"]) if post["status"] is not None else None
        item = {"post": post, "get": readback}
        calls.append(item)
        durable_write(output.parent / (phase + "-http.json"), calls)
        if case["id"].endswith("after"):
            interrupt({"point": "after-dispatch", "caseId": case["id"], "httpSha256": sha(canonical(item))})
        return {"result": {"httpSha256": sha(canonical(item)), "postStatus": post["status"]}}

    graph = StateGraph(GraphState)
    graph.add_node("dispatch", dispatch)
    graph.add_edge(START, "dispatch")
    graph.add_edge("dispatch", END)
    return graph.compile(checkpointer=saver)


def worker(case: dict[str, Any], endpoint: str, database: Path, phase: str, output: Path, current: dict[str, Any]) -> None:
    """Reopen real ``SqliteSaver`` state after worker and target exit.

    The worker captures the exact reopened snapshot, current grant/key/store/
    clock selection, all HTTP bytes and native parent history. A first worker
    exits with ``os._exit(73)`` only after synchronously persisted interruption.
    """
    from langgraph.checkpoint.sqlite import SqliteSaver
    from langgraph.types import Command
    calls: list[dict[str, Any]] = []
    with closing(sqlite3.connect(database, check_same_thread=False)) as conn:
        conn.execute("PRAGMA synchronous=FULL")
        app = graph_for(case, endpoint, phase, output, calls, SqliteSaver(conn))
        config = {"configurable": {"thread_id": case["request"]["run_id"] + "/" + case["id"]}, "recursion_limit": 4}
        loaded = project(app.get_state(config))
        checked = current_gate(conn, case, current, phase)
        record = {"pid": os.getpid(), "loaded": loaded, "authority": checked, "current": current, "http": calls}
        if checked["status"] != "authorized":
            durable_write(output, {**record, "status": checked["status"], "releasedResult": False})
            return
        require(phase == "first" or bool(loaded["next"]), "recovery-missing-checkpoint")
        data = {"contentHex": case["contentHex"], "result": {}} if phase == "first" else Command(resume=True)
        result = app.invoke(data, config, durability="sync")
        released = phase != "first" and calls[-1]["post"]["status"] == 200
        record.update(status="interrupted" if phase == "first" else "completed" if released else "refused-pending-effect", result=project(result), snapshot=project(app.get_state(config)), history=project(list(app.get_state_history(config))), releasedResult=released)
        durable_write(output, record)
        same(expected_authority(case["id"], phase), "authorized", "unexpected-worker-admission")
        if phase == "first":
            os._exit(73)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", type=Path)
    parser.add_argument("endpoint")
    parser.add_argument("database", type=Path)
    parser.add_argument("phase", choices=["first", "second", "third"])
    parser.add_argument("output", type=Path)
    parser.add_argument("current", type=Path)
    args = parser.parse_args()
    worker(load(args.case.parent, args.case.name), args.endpoint, args.database, args.phase, args.output, load(args.current.parent, args.current.name))
