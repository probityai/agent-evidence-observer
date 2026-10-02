"""One bounded LangGraph worker; deliberately exit without cleanup after capture."""
from __future__ import annotations

import argparse
import os
import sqlite3
from pathlib import Path
from typing import Any

from lg_common import decode, encode, project, sha, write
from lg_run import GraphState, exchange
from probity_observer.crypto import canonical

EXIT_INTERRUPTED = 73
EXIT_COMMITTED = 74


def durable_write(path: Path, value: Any) -> None:
    """Flush retained process evidence before the selected hard exit."""
    write(path, value)
    with path.open("rb") as stream:
        os.fsync(stream.fileno())


def graph_for(case: dict[str, Any], endpoint: str, phase: str, calls: list, output: Path, saver: Any) -> Any:
    """Compile the same dispatch node in each fresh OS process."""
    from langgraph.graph import END, START, StateGraph
    from langgraph.types import interrupt

    def dispatch(state: GraphState) -> dict[str, Any]:
        if case["id"] in {"restart-before", "missing-checkpoint", "wrong-thread"}:
            interrupt({"point": "before-dispatch", "caseId": case["id"]})
        candidate = {"request": case["request"], "grant": case["grant"], "contentHex": state["contentHex"]}
        status, response, response_hex = exchange(endpoint + "/dispatch", candidate)
        get_status, readback, readback_hex = exchange(endpoint + "/tickets/tenant/" + case["id"])
        packet = {"endpoint": endpoint, "candidate": candidate, "postStatus": status, "response": response, "getStatus": get_status, "readback": readback, "postRequestHex": canonical(candidate).hex(), "postResponseHex": response_hex, "getResponseHex": readback_hex}
        calls.append(packet)
        durable_write(output.parent / (phase + "-http.json"), calls)
        if case["id"] == "crash-after-effect" and phase == "first":
            os._exit(EXIT_COMMITTED)
        if case["id"] in {"restart-after", "restart-pending"}:
            interrupt({"point": "after-effect", "caseId": case["id"], "httpSha256": sha(encode(packet))})
        return {"result": {"httpSha256": sha(encode(packet)), "postStatus": status, "revision": readback["revision"]}}

    graph = StateGraph(GraphState)
    graph.add_node("dispatch", dispatch)
    graph.add_edge(START, "dispatch")
    graph.add_edge("dispatch", END)
    return graph.compile(checkpointer=saver)


def worker(case: dict[str, Any], endpoint: str, database: Path, phase: str, output: Path) -> None:
    """Reopen SQLite and refuse recovery without the exact interrupted checkpoint."""
    from langgraph.checkpoint.sqlite import SqliteSaver
    from langgraph.types import Command
    calls: list[dict[str, Any]] = []
    conn = sqlite3.connect(database, check_same_thread=False)
    conn.execute("PRAGMA synchronous=FULL")
    saver = SqliteSaver(conn)
    app = graph_for(case, endpoint, phase, calls, output, saver)
    thread = case["request"]["run_id"] + "/" + case["id"]
    if phase == "second" and case["id"] == "wrong-thread":
        thread += "/wrong"
    config = {"configurable": {"thread_id": thread}, "recursion_limit": 4}
    loaded = project(app.get_state(config))
    require_recovery = phase == "second"
    if require_recovery and not loaded["next"]:
        durable_write(output, {"pid": os.getpid(), "status": "refused-missing-checkpoint", "loaded": loaded, "http": calls})
        return
    if phase == "first":
        durable_write(output.parent / "first-loaded.json", {"pid": os.getpid(), "snapshot": loaded})
    data = {"contentHex": case["graphInputHex"], "result": {}} if phase == "first" else (None if case["id"] == "crash-after-effect" else Command(resume=True))
    result = app.invoke(data, config, durability="sync")
    durable_write(output, {"pid": os.getpid(), "status": "interrupted" if phase == "first" else "completed", "loaded": loaded, "result": project(result), "snapshot": project(app.get_state(config)), "history": project(list(app.get_state_history(config))), "http": calls})
    if phase == "first":
        os._exit(EXIT_INTERRUPTED)
    conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", type=Path)
    parser.add_argument("endpoint")
    parser.add_argument("database", type=Path)
    parser.add_argument("phase", choices=["first", "second"])
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    worker(decode(args.case.read_bytes()), args.endpoint, args.database, args.phase, args.output)
