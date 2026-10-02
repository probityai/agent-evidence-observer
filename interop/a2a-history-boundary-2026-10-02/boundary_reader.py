"""Read complete selected native caller/SQL receipts without running SQL or ASGI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from google.protobuf.json_format import MessageToDict

import a2a_history_pb2 as a2a_pb2
from boundary_common import (
    CASES,
    IMAGE,
    NONCLAIMS,
    PROFILE,
    SDK_FILES,
    SOURCE_HEAD,
    SOURCE_DIGESTS,
    decode,
    same,
    sha,
)


def require(condition, label):
    """Refuse instead of guessing a missing semantic join."""
    if not condition:
        raise ValueError(label)


def packet_files(packet, pins):
    """Require the complete literal selected population, with safe ordinary paths."""
    same(set(pins), {"profile", "files"}, "pins-fields")
    same(pins["profile"], PROFILE, "pins-profile")
    observed = {
        str(path.relative_to(packet)) for path in packet.rglob("*") if path.is_file()
    }
    same(sorted(observed), sorted(pins["files"]), "pins-population")
    for name, digest in pins["files"].items():
        target = packet / name
        require(
            not target.is_symlink()
            and target.resolve().is_relative_to(packet.resolve()),
            "unsafe-packet-path",
        )
        same(sha(target.read_bytes()), digest, "selected-bytes-differ")


def proto(receipt):
    """Use only the selected native protobuf type to join bytes and retained JSON."""
    task = a2a_pb2.Task.FromString(bytes.fromhex(receipt["taskProtoHex"]))
    task.DiscardUnknownFields()
    same(
        task.SerializeToString().hex(),
        receipt["taskProtoHex"],
        "native-protobuf-canonical-bytes",
    )
    same(MessageToDict(task), receipt["task"], "native-protobuf-json-differs")
    return receipt["task"]


def users(task):
    """Preserve order and repeated user turns rather than reducing to a set."""
    return [
        message["messageId"]
        for message in task["history"]
        if message["role"] == "ROLE_USER"
    ]


def rpc(receipt, message_id):
    """Join literal request/reply and expected real JSON-RPC method/id."""
    same(
        receipt["requestHeaders"],
        {"content-type": "application/json", "A2A-Version": "1.0"},
        "caller-protocol-headers",
    )
    same(receipt["status"], 200, "caller-http-status")
    value = decode(bytes.fromhex(receipt["responseHex"]))
    same(value, receipt["parsed"], "caller-response-bytes")
    request = decode(bytes.fromhex(receipt["requestHex"]))
    same(request["jsonrpc"], "2.0", "rpc-version")
    same(request["id"], "rpc-" + message_id, "rpc-request-id")
    same(request["method"], "SendMessage", "rpc-method")
    same(request["params"]["message"]["messageId"], message_id, "rpc-message-id")
    same(request["params"]["message"]["role"], "ROLE_USER", "rpc-user-role")
    same(value["id"], request["id"], "rpc-response-id")
    same(value["jsonrpc"], "2.0", "rpc-response-version")
    return request["params"]["message"], value


def sql(case, task):
    """Join an independent connection's native readback to actual SQL row/version."""
    row, version = case["sqlRow"], case["sqlVersionRow"]
    same(row["id"], task["id"], "sql-task-id")
    same(row["context_id"], task["contextId"], "sql-context-id")
    same(row["owner"], "probity-fixture", "sql-owner")
    same(row["protocol_version"], "1.0", "sql-protocol")
    for name in ["status", "history"]:
        same(row[name], task[name], "sql-" + name)
    same(row["artifacts"], task.get("artifacts", []), "sql-artifacts")
    same(row["metadata"], task.get("metadata"), "sql-metadata")
    same(
        version,
        {
            "task_id": task["id"],
            "owner": "probity-fixture",
            "version": 5 if case["conflictBudget"] == 1 else 4,
        },
        "sql-version-row",
    )
    same(
        case["final"]["version"],
        "TaskVersion(" + str(version["version"]) + ")",
        "native-version-sql-join",
    )


def trace(case, task_id):
    """Require actual selected CAS failure/retry and competing unchanged commits."""
    budget = case["conflictBudget"]
    rows = case["nativeStoreTrace"]
    require(len(rows) == 3, "native-store-trace-population")
    message = f"Task {task_id} was modified concurrently by another writer"
    expected_error = {
        "class": "ConcurrentTaskModificationError",
        "module": "a2a.server.cluster.task_store",
        "message": message,
    }
    ids = ["initial-" + case["id"], "followup-" + case["id"]]
    for index, row in enumerate(rows):
        same(row["candidateUserTurns"], ids, "candidate-user-turns")
        same(
            row["eventClass"],
            "Task" if index < 2 else "TaskStatusUpdateEvent",
            "native-event-class",
        )
        same(
            row["expectedVersion"],
            f"TaskVersion({2 + index if budget == 1 else min(2 + index, 3)})",
            "expected-native-version",
        )
        conflict = index < budget
        expected = (
            {
                "before": f"TaskVersion({2 + index})",
                "after": f"TaskVersion({3 + index})",
                "persistedUserTurns": ids[:1],
            }
            if conflict
            else None
        )
        same(row["competingCommit"], expected, "competing-native-commit")
        failed = conflict or budget == 2
        same(row["nativeError"], expected_error if failed else None, "native-cas-error")
        same(
            set(row),
            {
                "candidateUserTurns",
                "expectedVersion",
                "competingCommit",
                "nativeError",
                "eventClass",
            }
            if failed
            else {
                "candidateUserTurns",
                "expectedVersion",
                "competingCommit",
                "nativeError",
                "eventClass",
                "resultVersion",
            },
            "native-trace-fields",
        )
        if not failed:
            same(
                row["resultVersion"], f"TaskVersion({3 + index})", "native-save-result"
            )


def accepted(case, reply, final):
    """Successful native caller result must contain the durably committed follow-up."""
    same(set(reply), {"result", "id", "jsonrpc"}, "accepted-rpc-fields")
    same(reply["result"], {"task": final}, "accepted-result-durable-task")
    same(len(case["followupNativeCaller"]), 1, "native-caller-population")
    caller = case["followupNativeCaller"][0]
    same(caller["kind"], "returned", "accepted-native-kind")
    same(caller["class"], "Task", "accepted-native-class")
    same(proto(caller), final, "accepted-native-return")
    same(
        users(final),
        ["initial-" + case["id"], "followup-" + case["id"]],
        "accepted-history",
    )


def rejected(case, reply, final):
    """Refusal requires native InternalError and actual absent follow-up history."""
    message = f"Task {final['id']} was modified concurrently by another writer"
    same(set(reply), {"error", "id", "jsonrpc"}, "rejected-rpc-fields")
    same(
        reply["error"],
        {
            "code": -32603,
            "message": message,
            "data": [
                {
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": "INTERNAL_ERROR",
                    "domain": "a2a-protocol.org",
                    "metadata": {},
                }
            ],
        },
        "native-internal-error-rpc",
    )
    same(
        case["followupNativeCaller"],
        [
            {
                "kind": "raised",
                "class": "InternalError",
                "module": "a2a.utils.errors",
                "message": message,
                "data": None,
            }
        ],
        "native-internal-error-class",
    )
    same(final, case["before"]["task"], "rejected-task-preserves-initial")
    same(users(final), ["initial-" + case["id"]], "rejected-followup-absent")


def check_case(case, name, budget):
    """Join initial acceptance, selected follow-up disposition and SQL state."""
    same(case["id"], name, "case-id")
    same(case["conflictBudget"], budget, "selected-conflict-budget")
    same(case["remainingConflictBudget"], 0, "consumed-conflict-budget")
    initial_message, initial_reply = rpc(case["initial"], "initial-" + name)
    same(set(initial_reply), {"result", "id", "jsonrpc"}, "initial-accepted")
    before, final = proto(case["before"]), proto(case["final"])
    same(initial_reply["result"], {"task": before}, "initial-caller-readback")
    same(len(case["initialNativeCaller"]), 1, "initial-native-caller-population")
    initial_caller = case["initialNativeCaller"][0]
    same(initial_caller["kind"], "returned", "initial-native-kind")
    same(initial_caller["class"], "Task", "initial-native-class")
    same(proto(initial_caller), before, "initial-native-return")
    same(users(before), ["initial-" + name], "initial-user-history")
    same(case["before"]["version"], "TaskVersion(2)", "initial-native-version")
    require("taskId" not in initial_message, "initial-new-task")
    message, reply = rpc(case["followup"], "followup-" + name)
    same(message["taskId"], before["id"], "followup-task-id")
    same(message["contextId"], before["contextId"], "followup-context-id")
    same(final["id"], before["id"], "final-task-id")
    same(final["contextId"], before["contextId"], "final-context-id")
    trace(case, before["id"])
    sql(case, final)
    (accepted if budget == 1 else rejected)(case, reply, final)
    return {
        "id": name,
        "decision": "accepted-and-persisted"
        if budget == 1
        else "rejected-and-absent-with-InternalError",
        "taskId": before["id"],
    }


def manifest_contract(packet, manifest):
    """Pin source, resources, complete population and the measured substrate."""
    same(manifest["profile"], PROFILE, "manifest-profile")
    same(manifest["status"], "captured", "manifest-incomplete")
    same(manifest["witnessScope"], "PEER", "scope")
    same(manifest["doesNotAssert"], NONCLAIMS, "nonclaims")
    same(manifest["sourceHead"], SOURCE_HEAD, "native-source-head")
    same(manifest["mysqlImage"], IMAGE, "selected-mysql-image")
    container = manifest["container"]
    same(container["image"], IMAGE, "measured-container-image")
    same(container["memoryBytes"], 536870912, "measured-mysql-memory")
    same(container["nanoCPUs"], 1000000000, "measured-mysql-cpus")
    same(container["pidsLimit"], 128, "measured-mysql-pids")
    same(container["running"], True, "measured-container-running")
    require(
        len(container["id"]) == 64 and container["imageId"].startswith("sha256:"),
        "native-container-identity",
    )
    same(
        [v["HostIp"] for v in container["bindings"]],
        ["127.0.0.1"],
        "measured-mysql-loopback",
    )
    same(manifest["mysqlVersion"], "8.0.46", "native-mysql-version")
    same(manifest["plannedAttempts"], 20, "native-population")
    same(
        manifest["asgiSubstrate"], "httpx-ASGITransport-in-process", "native-substrate"
    )
    require(
        type(manifest["elapsedSeconds"]) in (float, int)
        and 0 <= manifest["elapsedSeconds"] <= 120,
        "run-resource-bound",
    )
    same(
        manifest["resources"],
        {
            "wholeRunSeconds": 120,
            "requestSeconds": 15,
            "mysqlMemoryMiB": 512,
            "mysqlCPUs": 1,
            "replicasPerCase": 2,
            "separateSQLConnectionsPerCase": 4,
        },
        "selected-resources",
    )
    same(
        manifest["records"],
        [{"id": name, "path": "cases/" + name + ".json"} for name, _ in CASES],
        "planned-case-population",
    )
    selected = SOURCE_DIGESTS
    same(manifest["sdkSources"], selected, "reviewed-native-source-selection")
    same(sorted(selected), sorted(SDK_FILES), "selected-sdk-source-population")
    for name, digest in selected.items():
        same(
            sha((packet / "sources" / "sdk" / name).read_bytes()),
            digest,
            "native-source-file",
        )
    same(
        sha(Path(a2a_pb2.__file__).read_bytes()),
        selected["src/a2a/types/a2a_pb2.py"],
        "installed-protobuf-source",
    )
    same(manifest["dependencies"]["PyMySQL"], "1.1.2", "source-locked-driver")
    same(manifest["dependencies"]["SQLAlchemy"], "2.0.48", "source-locked-sqlalchemy")


def read(packet, pins_file):
    """Return a finite offline decision for a host-selected retained packet."""
    packet_files(packet, decode(pins_file.read_bytes()))
    manifest = decode((packet / "manifest.json").read_bytes())
    manifest_contract(packet, manifest)
    records = [
        check_case(
            decode((packet / ("cases/" + name + ".json")).read_bytes()), name, budget
        )
        for name, budget in CASES
    ]
    require(
        len({row["taskId"] for row in records}) == 20, "distinct-native-task-population"
    )
    return {
        "profile": PROFILE,
        "status": "verified",
        "witnessScope": "PEER",
        "doesNotAssert": NONCLAIMS,
        "plannedAttempts": 20,
        "acceptedAndPersisted": 10,
        "rejectedAndAbsentInternalError": 10,
        "records": records,
    }


def main():
    """Run without any SQL connection, server, model or native task execution."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--pins-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = read(args.packet, args.pins_file)
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(
            json.dumps({"profile": PROFILE, "status": "refused", "reason": str(error)})
        )
        raise SystemExit(1) from error
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
