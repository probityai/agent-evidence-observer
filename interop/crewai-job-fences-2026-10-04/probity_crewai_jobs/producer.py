"""Run finite CrewAI job fences and native threaded flow effects without providers."""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict
from pathlib import Path
from threading import Lock
import sys
import time

from .contract import CASES, DIRECT_CASES, PAYLOAD, decode, encode, require, save


def original(value):
    raw = value.model_dump_json().encode() if hasattr(value, "model_dump_json") else encode(value)
    return {"jsonHex": raw.hex(), "value": decode(raw)}


def direct(root):
    from crewai.experimental.flow_jobs import JobUpdate, add_job, commit_job_update
    from .native_types import Record, State

    results = []
    for name in DIRECT_CASES:
        directory = root / "direct" / name
        directory.mkdir(parents=True)
        state = State(id="session:" + name)
        job = Record(session_id=state.id, job_id="job:" + name, question="Retain public fixture")
        admission = original(job)
        require(add_job(state, job), "native-register")
        setup = JobUpdate(session_id=state.id, job_id=job.job_id,
                          revision=1, attempt=1, seq=1, kind="started")
        require(commit_job_update(state, setup), "native-start")
        setups = [{"update": original(setup), "accepted": True}]
        baseline = original(state)
        details = dict(session_id=state.id, job_id=job.job_id, revision=1,
                       attempt=1, seq=2, kind="stage_completed",
                       stage="collect", outputs={"notes": ["Public fact"]})
        if name == "foreign-owner":
            details["session_id"] = "foreign"
        elif name == "missing-job":
            details["job_id"] = "absent"
        elif name == "stale-revision":
            details["revision"] = 2
        elif name == "stale-attempt":
            details["attempt"] = 2
        elif name == "duplicate-sequence":
            details["seq"] = 1
        elif name == "sequence-gap":
            details["seq"] = 9
        elif name == "wrong-stage":
            details["stage"] = "write"
        elif name == "uncommitted-next-stage":
            details.update(kind="stage_started", stage="write", outputs={})
        elif name == "overwrite-input":
            details["outputs"] = {"question": "Replaced"}
        elif name == "overwrite-lifecycle":
            details["outputs"] = {"status": "completed"}
        elif name == "invalid-output-type":
            details["outputs"] = {"notes": "not a list"}
        elif name == "nonstage-output":
            details.update(kind="completed", stage="")
        elif name == "premature-completion":
            details.update(kind="completed", stage="", outputs={})
        elif name == "postterminal":
            finish = JobUpdate(session_id=state.id, job_id=job.job_id,
                               revision=1, attempt=1, seq=2, kind="failed", error="Finite failure")
            require(commit_job_update(state, finish), "native-terminal-setup")
            setups.append({"update": original(finish), "accepted": True})
            baseline = original(state)
            details["seq"] = 3
        elif name == "regressing-sequence":
            advance = JobUpdate(session_id=state.id, job_id=job.job_id, revision=1, attempt=1,
                                seq=3, kind="stage_completed", stage="collect",
                                outputs={"notes": ["Public fact"]})
            require(commit_job_update(state, advance), "native-regression-setup")
            setups.append({"update": original(advance), "accepted": True})
            baseline = original(state)
            details.update(seq=2, kind="stage_started", stage="write", outputs={})
        elif name == "strict-boolean-sequence":
            details["seq"] = True
        save(directory / "inputs-before-call.json", {"admission": admission, "setups": setups,
                                                    "candidate": details})
        validation = None
        submitted = None
        try:
            update = JobUpdate(**details)
            submitted = original(update)
        except Exception as failure:
            validation = {"type": type(failure).__name__, "message": str(failure)}
        if submitted is None:
            accepted = None
        else:
            accepted = commit_job_update(state, update)
        after = original(state)
        row = {"case": name, "before": baseline, "submitted": submitted,
               "validation": validation, "accepted": accepted, "after": after,
               "recordIdentityPreserved": state.jobs[job.job_id] is job,
               "nativeToolBodyEffects": 0, "publicationDecision": None}
        save(directory / "native-call.json", row)
        expected = name in {"valid-stage", "sequence-gap"}
        require((accepted is True) == expected, "native-direct-return:" + name)
        require((baseline == after) if not expected else (baseline != after), "native-state-mutation:" + name)
        require(validation is None if name != "strict-boolean-sequence" else validation is not None,
                "native-model-admission:" + name)
        results.append({"case": name, "accepted": accepted, "validationRejected": validation is not None,
                        "stateChanged": baseline != after, "nativeToolBodyEffects": 0})
    return results


async def runner_case(root, name):
    from crewai.experimental.flow_jobs import JobRunner, add_job
    from probity_observer.broker import Broker
    from probity_observer.crypto import SigningKey
    from probity_observer.history import Witness
    from .native_types import Record, State, StatusFlow, Work

    directory = root / "cases" / name
    directory.mkdir(parents=True)
    workspace = directory / "workspace"
    workspace.mkdir()
    observer, witness = SigningKey.generate(), SigningKey.generate()
    save(directory / "keys-before-run.json", {"observer": observer.public_hex, "witness": witness.public_hex})
    authority = {"intervalId": name, "scope": "/work", "operation": "write-file"}
    save(directory / "authority-before-run.json", authority)
    broker = Broker(workspace, directory / "history.jsonl", authority, observer,
                    Witness(directory / "witness-state.json", witness))
    save(directory / "begin-before-run.json", broker.begin())

    records, effects, snapshots, worker_events = [], [], [], []
    lock = Lock()
    queue = asyncio.Queue()
    def capture(kind, value):
        with lock:
            row = {"sequence": len(records) + 1, "kind": kind, "time": time.time(), **value}
            records.append(row)
    async def on_update(snapshot):
        wrapped = original(snapshot)
        snapshots.append(wrapped)
        capture("on_update", {"snapshot": wrapped})
        await queue.put(snapshot)
    def on_worker_event(kind, job):
        item = {"kind": kind, "job": original(job)}
        worker_events.append(item)
        capture("on_worker_event", {"workerEvent": kind, "job": item["job"]})

    def make(job, inputs, publish):
        def captured_publish(update):
            submitted = update
            injected = ((name == "refusal-before-body" and update.kind == "stage_started" and update.stage == "write")
                        or (name == "effect-before-refusal" and update.kind == "stage_completed" and update.stage == "write"))
            if injected:
                submitted = update.model_copy(update={"revision": update.revision + 1})
            capture("proposal-before-native-commit", {"original": original(update),
                                                     "submitted": original(submitted),
                                                     "fault": "harness-stale-revision" if injected else None})
            accepted = publish(submitted)
            capture("native-commit-receipt", {"submitted": original(submitted), "accepted": accepted})
            return accepted

        def body(work_job, seq):
            request_id = work_job.job_id + ":body:" + str(seq)
            content = PAYLOAD.encode()
            result = broker.write(request_id, "/work/result.txt", content)
            item = {"requestId": request_id, "job": original(work_job), "workerSeq": seq,
                    "result": asdict(result), "operator": "native-JobWorkFlow-body",
                    "contentSHA256": __import__("hashlib").sha256(content).hexdigest()}
            effects.append(item)
            capture("body-effect", item)
            return "Public answer"

        return Work(job, captured_publish, body)

    state = State(id="session:" + name)
    flow = StatusFlow(initial_state=state, suppress_flow_events=True, tracing=False)
    job = Record(session_id=flow.state.id, job_id="job:" + name,
                 origin_turn_id="turn:admit", question="Retain public fixture")
    runner = JobRunner(flow.state, make, on_update=on_update, on_worker_event=on_worker_event)
    save(directory / "job-before-run.json", original(job))
    save(directory / "native-state-before-run.json", original(flow.state))
    try:
        async with runner.state_lock:
            require(add_job(flow.state, job), "native-runner-register")
            runner.submit(job, ["Public input"])
        while True:
            snapshot = await asyncio.wait_for(queue.get(), 10)
            if snapshot["jobs"][0]["status"] in {"completed", "failed"}:
                break
        await asyncio.wait_for(asyncio.gather(*runner.tasks.values()), 10)
        async with runner.state_lock:
            before_publication = original(flow.state)
            require(not flow.state.messages, "no-automatic-publication")
            reply = await asyncio.to_thread(flow.handle_turn, "Status please")
            after_publication = original(flow.state)
        save(directory / "manual-publication.json", {"userInput": "Status please", "reply": reply,
                 "before": before_publication, "after": after_publication,
                 "operator": "explicit-author-foreground-turn", "sdkAutoPublication": False})
    finally:
        await runner.aclose()
        flow.finalize_session_traces(discard=True)
        save(directory / "native-state-after-run.json", original(flow.state))
        save(directory / "callbacks.json", records)
        save(directory / "snapshots.json", snapshots)
        save(directory / "worker-events.json", worker_events)
        save(directory / "body-effects.json", effects)
        save(directory / "observer-packet.json", broker.seal())
        save(directory / "runner-after-close.json", {"closed": runner.closed,
                 "tasksSettled": all(task.done() for task in runner.tasks.values()),
                 "pendingReceipts": len(runner._receipts)})
    require(len(effects) == (0 if name == "refusal-before-body" else 1), "native-body-count")
    require(job.status == ("completed" if name == "valid-runner" else "failed"), "native-final-status")
    require(job.answer == ("Public answer" if name == "valid-runner" else ""), "native-output-status")
    return {"case": name, "nativeStatus": job.status, "nativeBodyEffects": len(effects),
            "committedAnswer": job.answer, "manualPublicationMessages": len(flow.state.messages),
            "nativeProviderCalls": 0}


async def produce(root):
    selection = decode((root / "plan-before-run.json").read_bytes())
    require(selection["directCases"] == list(DIRECT_CASES) and selection["runnerCases"] == list(CASES),
            "unselected-population")
    direct_rows = direct(root)
    runner_rows = []
    for name in CASES:
        runner_rows.append(await runner_case(root, name))
    result = {"directRows": direct_rows, "runnerRows": runner_rows, "providerRequests": 0,
              "operator": "author-operated", "witnessScope": "PEER",
              "prospectiveEightTaskRun": "not-started", "older16Rows": "unchanged"}
    save(root / "native-result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    args = parser.parse_args()
    blocked = []
    def offline(event, values):
        if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto"}:
            target = values[1] if event == "socket.connect" and len(values) > 1 else values[:2]
            blocked.append({"event": event, "target": str(target)})
            save(args.packet / "network-refusals.json", blocked)
            raise RuntimeError("Finite native profile has no network authority")
    sys.addaudithook(offline)
    result = asyncio.run(produce(args.packet))
    require(not blocked, "unexpected-native-network-attempt")
    print(encode(result).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
