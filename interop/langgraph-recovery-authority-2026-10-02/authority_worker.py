"""Fresh native SQLite graph worker with recovery authority checked before resume."""
from __future__ import annotations

import argparse
import os
import sqlite3
from contextlib import closing
from pathlib import Path

from authority_common import decode, encode, require, sha, validate
from durable_worker import durable_write
from lg_common import project
from lg_run import GraphState, exchange
from probity_observer.crypto import canonical


def checkpoint(saver, case, endpoint, phase, output, calls):
    """Native interrupt before or after selected protected HTTP dispatch."""
    from langgraph.graph import END, START, StateGraph
    from langgraph.types import interrupt

    def dispatch(state: GraphState) -> dict:
        if case["id"].endswith("before"):
            interrupt({"point": "before-dispatch", "caseId": case["id"]})
        candidate = {"request": case["request"], "grant": case["grant"], "contentHex": state["contentHex"]}
        status, response, response_hex = exchange(endpoint + "/dispatch", candidate)
        get_status, readback, readback_hex = exchange(endpoint + "/tickets/tenant/" + case["id"])
        item = {"endpoint": endpoint, "candidate": candidate, "postStatus": status, "response": response, "getStatus": get_status, "readback": readback, "postRequestHex": canonical(candidate).hex(), "postResponseHex": response_hex, "getResponseHex": readback_hex}
        calls.append(item)
        durable_write(output.parent / (phase + "-http.json"), calls)
        if case["id"].endswith("after"):
            interrupt({"point": "after-effect", "caseId": case["id"], "httpSha256": sha(encode(item))})
        return {"result": {"httpSha256": sha(encode(item)), "postStatus": status, "revision": readback["revision"]}}

    graph = StateGraph(GraphState)
    graph.add_node("dispatch", dispatch)
    graph.add_edge(START, "dispatch")
    graph.add_edge("dispatch", END)
    return graph.compile(checkpointer=saver)


def gate(conn, case, current, phase):
    """Serialize current authority against the durable per-action clock anchor."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        checked = locked_gate(conn, case, current, phase)
        conn.commit()
        return checked
    except Exception:
        conn.rollback()
        raise


def locked_gate(conn, case, current, phase):
    """Missing recovery anchor fails closed; initial selection creates it once."""
    conn.execute("CREATE TABLE IF NOT EXISTS recovery_clock (binding TEXT PRIMARY KEY, clock INTEGER NOT NULL, denied INTEGER NOT NULL)")
    binding = sha(encode({"request": case["request"], "grant": case["grant"]}))
    row = conn.execute("SELECT clock, denied FROM recovery_clock WHERE binding=?", (binding,)).fetchone()
    prior = checked_clock_row(row)
    status = validate(current, binding, prior)
    if phase == "second" and row is None:
        status = "refused-missing-clock-anchor"
    status = deny_stale_permit(current, row, status)
    if row is not None or (phase == "first" and status == "authorized"):
        conn.execute("INSERT OR REPLACE INTO recovery_clock VALUES (?, ?, ?)", (binding, max(prior, current["clock"]), denied_mark(current, row, status)))
    return {"current": current, "priorClock": prior, "status": status}


def checked_clock_row(row):
    """Corrupt recovery-clock metadata fails closed before authority evaluation."""
    if row is None:
        return 0
    require(type(row[0]) is int and row[0] >= 0 and type(row[1]) is int and row[1] in (0, 1), "recovery-clock-schema")
    return row[0]


def deny_stale_permit(current, row, status):
    """A denied observation cannot be resurrected by an equal-clock old permit."""
    if row is not None and row[1] and current["clock"] == row[0] and status == "authorized":
        return "refused-stale-authority"
    return status


def denied_mark(current, row, status):
    """Keep denial at the high-water clock until a strictly later host selection."""
    if row is not None and current["clock"] < row[0]:
        return row[1]
    return int(status != "authorized")


def worker(case, endpoint, database, phase, output, current_file):
    """Reopen native checkpoint; refuse before invoking any recovery node."""
    from langgraph.checkpoint.sqlite import SqliteSaver
    from langgraph.types import Command
    calls = []
    with closing(sqlite3.connect(database, check_same_thread=False)) as conn:
        conn.execute("PRAGMA synchronous=FULL")
        app = checkpoint(SqliteSaver(conn), case, endpoint, phase, output, calls)
        config = {"configurable": {"thread_id": case["request"]["run_id"] + "/" + case["id"]}, "recursion_limit": 4}
        loaded = project(app.get_state(config))
        checked = gate(conn, case, decode(current_file.read_bytes()), phase)
        record = {"pid": os.getpid(), "loaded": loaded, "authority": checked, "http": calls}
        if checked["status"] != "authorized":
            durable_write(output, {**record, "status": checked["status"]})
            return
        require(phase == "first" or bool(loaded["next"]), "recovery-missing-checkpoint")
        data = {"contentHex": case["graphInputHex"], "result": {}} if phase == "first" else Command(resume=True)
        result = app.invoke(data, config, durability="sync")
        record.update(status="interrupted" if phase == "first" else "completed", result=project(result), snapshot=project(app.get_state(config)), history=project(list(app.get_state_history(config))))
        durable_write(output, record)
        if phase == "first":
            os._exit(73)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", type=Path)
    parser.add_argument("endpoint")
    parser.add_argument("database", type=Path)
    parser.add_argument("phase", choices=["first", "second"])
    parser.add_argument("output", type=Path)
    parser.add_argument("current", type=Path)
    args = parser.parse_args()
    worker(decode(args.case.read_bytes()), args.endpoint, args.database, args.phase, args.output, args.current)
