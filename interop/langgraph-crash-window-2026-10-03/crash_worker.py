"""Native worker hard-exiting inside a node after its HTTP effect commits."""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "joint-recovery-2026-10-02"))
from joint_worker import current_gate  # noqa: E402
from durable_worker import durable_write  # noqa: E402
from lg_common import project  # noqa: E402
from lg_run import GraphState  # noqa: E402
from target_run import exchange  # noqa: E402
from crash_common import load, require, sha  # noqa: E402
from probity_observer.crypto import canonical  # noqa: E402


def graph_for(case: dict[str, Any], endpoint: str, phase: str, output: Path,
              saver: Any, config: dict[str, Any], record: dict[str, Any]) -> Any:
    """Compile the real node whose first execution exits after its HTTP commit.

    Parameters
    ----------
    case : dict
        Frozen action, grant and target identities selected before launch.
    endpoint, phase : str
        Actual target endpoint and first or second distinct process phase.
    output : pathlib.Path
        Fresh original worker capture path, outside private key storage.
    saver : SqliteSaver
        Native synchronous SQLite checkpoint implementation.
    config, record : dict
        Frozen thread configuration and original process/authority capture.

    Returns
    -------
    CompiledStateGraph
        Native graph. Its first dispatch never returns or commits node output;
        the fresh second graph may replay the pending task after admission.
    """
    from langgraph.graph import END, START, StateGraph

    def dispatch(state: GraphState) -> dict[str, Any]:
        """Retain a committed HTTP exchange before the selected hard exit.

        Parameters
        ----------
        state : GraphState
            Native content channel from the selected checkpoint.

        Returns
        -------
        dict
            Second-phase native result bound to the literal cached exchange.
            First-phase execution calls ``os._exit(74)`` before any return.
        """
        candidate = {"request": case["request"], "grant": case["grant"], "contentHex": state["contentHex"]}
        item = {"post": exchange(endpoint + "/dispatch", candidate),
                "get": exchange(endpoint + "/tickets/tenant/" + case["id"])}
        record["http"].append(item)
        durable_write(output.parent / (phase + "-http.json"), record["http"])
        require(item["post"]["status"] == 200, "crash-window-effect-not-committed")
        if phase == "first":
            durable_write(output, {**record, "status": "crashed-after-commit-before-node-return",
                                  "releasedResult": False, "snapshot": project(app.get_state(config)),
                                  "history": project(list(app.get_state_history(config)))})
            os._exit(74)
        return {"result": {"httpSha256": sha(canonical(item)), "postStatus": 200}}

    graph = StateGraph(GraphState)
    graph.add_node("dispatch", dispatch)
    graph.add_edge(START, "dispatch")
    graph.add_edge("dispatch", END)
    app = graph.compile(checkpointer=saver)
    return app


def worker(case: dict[str, Any], endpoint: str, database: Path, phase: str,
           output: Path, current: dict[str, Any]) -> None:
    """Reopen an unfinished native task only after current host admission.

    Parameters
    ----------
    case : dict
        Frozen original action and signed grant.
    endpoint : str
        Actual first or restarted target HTTP address.
    database : pathlib.Path
        Native checkpoint store reopened by the distinct second worker.
    phase : str
        First hard-exit execution or second recovery execution.
    output : pathlib.Path
        Fresh original public process capture.
    current : dict
        Host-selected current grant/key/store/clock/authority policy.

    Returns
    -------
    None
        Writes original native/HTTP evidence. Denied recovery performs no
        graph invocation, HTTP dispatch or cached result release.
    """
    from langgraph.checkpoint.sqlite import SqliteSaver
    with closing(sqlite3.connect(database, check_same_thread=False)) as connection:
        connection.execute("PRAGMA synchronous=FULL")
        config = {"configurable": {"thread_id": case["request"]["run_id"] + "/" + case["id"]}, "recursion_limit": 4}
        record = {"pid": os.getpid(), "current": current, "http": []}
        app = graph_for(case, endpoint, phase, output, SqliteSaver(connection), config, record)
        record.update(loaded=project(app.get_state(config)), authority=current_gate(connection, case, current, phase))
        if record["authority"]["status"] != "authorized":
            durable_write(output, {**record, "status": record["authority"]["status"], "releasedResult": False})
            return
        require(phase == "first" or bool(record["loaded"]["next"]), "crash-window-missing-native-task")
        data = {"contentHex": case["contentHex"], "result": {}} if phase == "first" else None
        result = app.invoke(data, config, durability="sync")
        durable_write(output, {**record, "status": "completed", "result": project(result),
                              "snapshot": project(app.get_state(config)),
                              "history": project(list(app.get_state_history(config))), "releasedResult": True})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", type=Path)
    parser.add_argument("endpoint")
    parser.add_argument("database", type=Path)
    parser.add_argument("phase", choices=["first", "second"])
    parser.add_argument("output", type=Path)
    parser.add_argument("current", type=Path)
    args = parser.parse_args()
    worker(load(args.case.parent, args.case.name), args.endpoint, args.database,
           args.phase, args.output, load(args.current.parent, args.current.name))
