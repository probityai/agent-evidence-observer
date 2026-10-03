"""Installed, framework-free reconstruction of the selected crash-window run."""
from __future__ import annotations

import argparse
import json
import sqlite3
from contextlib import closing
from pathlib import Path

import joint_common
import joint_reader
from joint_reader import authenticate_dispatch, current_record, http_record, native_store, signed_state, worker_original
from probity_observer.crypto import VerificationError, canonical
from crash_common import CASES, NONCLAIMS, POLICY, PROFILE, child_environment, load, packet_files, read, require, same, sha


def selections(root, pins, names):
    """Bind the complete literal plan, source and artifact population externally."""
    same(sorted(pins), ["artifactManifestSha256", "planSha256", "profile"], "crash-window-pins-fields")
    same(pins["profile"], PROFILE, "crash-window-profile")
    for field, name in (("planSha256", "plan-before-run.json"), ("artifactManifestSha256", "artifact-manifest.json")):
        same(sha(read(root, name)), pins[field], "consumer-" + field)
    plan = load(root, "plan-before-run.json")
    same(plan["profile"], PROFILE, "crash-window-profile")
    same(plan["hostPolicy"], POLICY, "crash-window-policy")
    same(plan["witnessScope"], "PEER", "witness-scope")
    same(plan["doesNotAssert"], NONCLAIMS, "nonclaims")
    same([case["id"] for case in plan["cases"]], list(CASES), "planned-population")
    require(isinstance(plan["sourceRevision"], str) and len(plan["sourceRevision"]) == 40 and all(c in "0123456789abcdef" for c in plan["sourceRevision"]), "source-revision")
    same([plan["environment"]["packages"][name] for name in ("langgraph", "langgraph-checkpoint-sqlite", "agent-evidence-observer")], ["1.0.10", "3.1.1", "0.0.1"], "framework-version")
    manifest = load(root, "artifact-manifest.json")
    actual = names - {"artifact-manifest.json", "consumer-pins.json", "report.json"}
    same(sorted(manifest), sorted(actual), "artifact-population")
    for name, digest in manifest.items():
        same(sha(read(root, name)), digest, "artifact-digest")
    source_contract(plan, manifest)
    return plan


def source_contract(plan, manifest):
    """Require the declared sources and the selected installed verifier bytes."""
    groups = {"joint": ["joint_common", "joint_run", "joint_worker", "joint_target", "joint_reader", "joint_host_gate"],
              "authority": ["authority_worker", "authority_common"],
              "langgraph": ["lg_common", "lg_run", "durable_worker"],
              "target": ["target_common", "target_run"],
              "observer": ["authorization", "crypto", "ticket_service"],
              "crash": ["crash_common", "crash_run", "crash_worker", "crash_reader"]}
    same(sorted(plan["sources"]), sorted("sources/" + group + "/" + name + ".py" for group, names in groups.items() for name in names), "declared-source-population")
    same(sorted(plan["sources"]), sorted(name for name in manifest if name.startswith("sources/")), "source-population")
    for name, digest in plan["sources"].items():
        same(manifest[name], digest, "source-digest")
    for module, name in ((joint_common, "sources/joint/joint_common.py"), (joint_reader, "sources/joint/joint_reader.py")):
        same(sha(Path(module.__file__).read_bytes()), plan["sources"][name], "selected-installed-dependency-source")
    for name in ("crash_common.py", "crash_reader.py"):
        same(sha(Path(__file__).with_name(name).read_bytes()), plan["sources"]["sources/crash/" + name], "selected-installed-reader-source")


def snapshot(case, value, step, unfinished):
    """Check the public native checkpoint identity without deserializing binaries."""
    thread = case["request"]["run_id"] + "/" + case["id"]
    same(value["config"]["configurable"]["thread_id"], thread, "native-thread")
    same(value["config"]["configurable"]["checkpoint_ns"], "", "native-namespace")
    require(isinstance(value["config"]["configurable"]["checkpoint_id"], str) and bool(value["config"]["configurable"]["checkpoint_id"]), "native-checkpoint-id")
    same(value["metadata"]["step"], step, "native-step")
    same(value["next"], ["__start__"] if step == -1 else ["dispatch"] if unfinished else [], "native-pending-task")
    same(value["interrupts"], [], "native-no-interrupt")
    if step >= 0:
        same(value["values"]["contentHex"], case["contentHex"], "native-content")
    if unfinished:
        same(value["values"].get("result", {}), {}, "native-node-has-not-returned")


def history(case, record, completed):
    """Require every native parent link and exact finite checkpoint population."""
    observed = record["history"]
    same(len(observed), 3 if completed else 2, "native-history-population")
    same(record["snapshot"], observed[0], "native-latest-snapshot")
    for index, value in enumerate(observed):
        step = (1 if completed else 0) - index
        snapshot(case, value, step, step == 0)
        parent = observed[index + 1]["config"] if index + 1 < len(observed) else None
        same(value["parent_config"], parent, "native-parent-link")


def metadata_object(pairs):
    """Refuse duplicate native metadata names without requiring JCS encoding."""
    result = dict(pairs)
    require(len(result) == len(pairs), "native-sqlite-duplicate-metadata")
    return result


def native_metadata(raw):
    """Give malformed or excessively nested native JSON a stable refusal."""
    require(len(raw) <= 1024, "native-sqlite-metadata")
    try:
        value = json.loads(raw, object_pairs_hook=metadata_object,
                           parse_constant=lambda _: require(False, "native-sqlite-nonfinite-metadata"))
    except VerificationError:
        raise
    except (json.JSONDecodeError, RecursionError, OverflowError):
        require(False, "native-sqlite-metadata")
    require(type(value) is dict and sorted(value) == ["parents", "source", "step"], "native-sqlite-metadata")
    require(type(value["source"]) is str and value["source"] in {"input", "loop"} and type(value["step"]) is int and value["parents"] == {}, "native-sqlite-metadata")
    return value


def checkpoint_rows(root, name, case, observed, before):
    """Join public IDs/parents/steps to read-only original native SQLite rows."""
    require(read(root, name).startswith(b"SQLite format 3\x00"), "native-sqlite-header")
    path = root / name
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)) as connection:
        rows = connection.execute("SELECT thread_id,checkpoint_ns,checkpoint_id,parent_checkpoint_id,metadata FROM checkpoints").fetchall()
        clocks = connection.execute("SELECT binding,clock,denied FROM recovery_clock").fetchall()
    expected = []
    for value in observed:
        config = value["config"]["configurable"]
        parent = value["parent_config"]
        expected.append([config["thread_id"], config["checkpoint_ns"], config["checkpoint_id"], None if parent is None else parent["configurable"]["checkpoint_id"]])
    same(sorted([list(row[:4]) for row in rows]), sorted(expected), "native-sqlite-checkpoint-join")
    metadata = {row[2]: native_metadata(row[4]) for row in rows}
    for value in observed:
        same(metadata[value["config"]["configurable"]["checkpoint_id"]]["step"], value["metadata"]["step"], "native-sqlite-step")
    if before:
        from joint_common import authority
        same([list(row) for row in clocks], [[authority(case)["actionSha256"], 100, 0]], "native-before-recovery-clock")


def processes(root, plan, case, value):
    """Bind distinct original processes to precise frozen commands and captures."""
    same([w["phase"] for w in value["workers"]], ["first", "second"], "worker-population")
    same([t["ordinal"] for t in value["targets"]], [1, 2], "target-population")
    pids = []
    for worker, target in zip(value["workers"], value["targets"], strict=True):
        phase, record, process = worker["phase"], worker["record"], worker["process"]
        folder = Path(plan["captureRoot"]) / "workers" / case["id"]
        endpoint = target["result"]["url"]
        command = [plan["pythonExecutable"], str(Path(plan["adapterRoot"]) / "crash_worker.py"), str(Path(plan["captureRoot"]) / "cases" / (case["id"] + ".json")), endpoint, str(Path(plan["hostPrivateRoot"]) / case["id"] / "checkpoints.sqlite"), phase, str(folder / (phase + ".json")), str(folder / (phase + "-current.json"))]
        same(process["command"], command, "worker-launch-argv")
        same(process["environment"], child_environment(), "worker-environment")
        same(process["pid"], record["pid"], "worker-parent-process-identity")
        same([process["timedOut"], process["exitCode"], process["stdoutHex"], process["stderrHex"]], [False, 74 if phase == "first" else 0, "", ""], "worker-process-outcome")
        require(type(process["elapsedNs"]) is int and 0 < process["elapsedNs"] <= POLICY["workerTimeoutSeconds"] * 1_000_000_000, "worker-resource")
        worker_original(root, case, worker)
        same(load(root, "targets/" + case["id"] + "/" + phase + ".json"), target, "target-original-binding")
        expected_command = [plan["pythonExecutable"], str(Path(plan["adapterRoot"]).parent / "joint-recovery-2026-10-02/joint_target.py"), str(Path(plan["hostPrivateRoot"]) / case["id"] / ("target-" + str(target["ordinal"]) + "-private.json")), "--fault", "none"]
        same(target["command"], expected_command, "target-launch-argv")
        same(target["environment"], child_environment(), "target-environment")
        same([target["fault"], target["returncode"], target["stdoutHex"], target["stderrHex"]], ["none", -15, "", ""], "target-process-outcome")
        same(target["result"]["pid"], target["pid"], "target-process-identity")
        same(target["selectedServiceKey"], case["serviceKey"], "target-service-key")
        pids.extend([record["pid"], target["pid"]])
    require(all(type(pid) is int and pid > 0 for pid in pids) and len(set(pids)) == 4, "distinct-processes")
    return pids


def effects(case, value, authorized):
    """Authenticate both literal HTTP exchanges and the cached signed receipt."""
    first, second = [worker["record"] for worker in value["workers"]]
    same([len(first["http"]), len(second["http"])], [1, int(authorized)], "recovery-dispatch-population")
    for worker, target in zip(value["workers"], value["targets"], strict=True):
        for item in worker["record"]["http"]:
            response = http_record(item["post"], case, target["result"]["url"], True)
            readback = http_record(item["get"], case, target["result"]["url"], False)
            same([item["post"]["status"], item["get"]["status"]], [200, 200], "effect-http-status")
            authenticate_dispatch(case, item, response, readback)
            same(readback, value["prior"], "effect-http-prior-state")
    if authorized:
        same(second["http"][0]["post"]["responseHex"], first["http"][0]["post"]["responseHex"], "completed-receipt-replayed")
        same(second["result"]["result"], {"httpSha256": sha(canonical(second["http"][0])), "postStatus": 200}, "recovered-result-http-join")
        same(second["snapshot"]["values"]["result"], second["result"]["result"], "recovered-native-result-join")


def verify_attempt(root, plan, case):
    """Separate authenticated earlier effect from permission to replay a task."""
    name = case["id"]
    same(load(root, "cases/" + name + ".json"), case, "case-original-binding")
    value = load(root, "attempts/" + name + ".json")
    pids = processes(root, plan, case, value)
    first, second = [worker["record"] for worker in value["workers"]]
    for worker in value["workers"]:
        current_record(case, worker, False, case["serviceKey"])
    same(first["status"], "crashed-after-commit-before-node-return", "first-native-crash")
    same(first["releasedResult"], False, "first-no-result-release")
    same([first["loaded"]["next"], first["loaded"]["values"]], [[], {}], "first-empty-native-state")
    history(case, first, False)
    same(second["loaded"], first["snapshot"], "native-reopened-unfinished-task")
    same(value["beforeRecoverySnapshot"], "native/" + name + "-before-recovery.sqlite", "native-before-recovery-name")
    checkpoint_rows(root, value["beforeRecoverySnapshot"], case, first["history"], True)
    authorized = name == "valid-after"
    same(second["releasedResult"], authorized, "current-result-release")
    same(second["status"], "completed" if authorized else second["authority"]["status"], "current-worker-status")
    if authorized:
        history(case, second, True)
        checkpoint_rows(root, value["checkpointSnapshot"], case, second["history"], False)
    else:
        require(not any(key in second for key in ("result", "snapshot", "history")), "denied-native-invocation")
        checkpoint_rows(root, value["checkpointSnapshot"], case, first["history"], False)
    effects(case, value, authorized)
    same(value["targets"][0]["result"]["initial"], case["initial"], "first-target-initial")
    same(value["targets"][1]["result"]["initial"], value["prior"], "target-reopened-committed-effect")
    for retained in (value["prior"], value["final"]):
        signed_state(retained, case)
        same(retained["revision"], 1, "committed-effect-revision")
    same(value["final"], value["prior"], "prior-committed-effect-preserved")
    native_store(root, case, value)
    return {"id": name, "firstWorkerExitCode": 74, "targetProcesses": 2, "workerProcesses": 2,
            "priorAuthenticEffect": True, "nativeTaskUnfinishedAtCrash": True,
            "currentAuthority": second["authority"]["status"], "releasedResult": authorized,
            "recoveryDispatches": int(authorized), "physicalPostCalls": 1 + int(authorized),
            "newRecoveryEffects": 0, "nativeRevision": 1}, pids


def verify_saved(root, pins):
    """Authenticate a complete selected run; refusal cases remain refused."""
    names = packet_files(root.absolute())
    root = root.resolve()
    plan = selections(root, pins, names)
    rows, pids = [], []
    for case in plan["cases"]:
        row, identities = verify_attempt(root, plan, case)
        rows.append(row)
        pids.extend(identities)
    require(len(set(pids)) == 16, "within-run-pid-reuse")
    return {"profile": PROFILE, "status": "verified", "plannedAttempts": 4, "workerProcesses": 8,
            "targetProcesses": 8, "priorAuthenticEffects": 4, "releasedResults": 1,
            "recoveryRefusals": 3, "physicalPostCalls": 5, "newRecoveryEffects": 0,
            "records": rows, "witnessScope": "PEER", "doesNotAssert": NONCLAIMS,
            "crashScope": POLICY["crashPoint"], "independentCustody": "not-established", "providerCalls": 0}


def main():
    """Read outside-selected pins and emit the finite canonical report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--pins-file", type=Path, required=True)
    args = parser.parse_args()
    pins = args.pins_file.resolve(strict=True)
    require(not pins.is_relative_to(args.packet.resolve()), "selection-must-be-outside-packet")
    print(canonical(verify_saved(args.packet, load(pins.parent, pins.name))).decode(), end="")


if __name__ == "__main__":
    main()
