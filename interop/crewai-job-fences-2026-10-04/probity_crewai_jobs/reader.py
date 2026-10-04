"""Reconstruct retained job decisions, callback order, signed effects and publication offline."""

from __future__ import annotations

import argparse
from copy import deepcopy
from pathlib import Path

from probity_observer.history import read_history
from probity_observer.verify import verify_packet

from .contract import (CASES, DIRECT_CASES, PAYLOAD, PROFILE, SOURCE,
                       decode, encode, original, plan, require, selected_files, sha)


def host_policy(root):
    return {"profile": PROFILE, "sourceRevision": SOURCE,
            "files": {p: sha((root / p).read_bytes()) for p in selected_files()},
            "keys": {c: decode((root / "cases" / c / "keys-before-run.json").read_bytes())
                     for c in CASES}}


def wrapped(value):
    if isinstance(value, dict):
        if "jsonHex" in value and "value" in value:
            original(value)
        for item in value.values():
            wrapped(item)
    elif isinstance(value, list):
        for item in value:
            wrapped(item)


def direct_case(root, name):
    directory = root / "direct" / name
    inputs = decode((directory / "inputs-before-call.json").read_bytes())
    result = decode((directory / "native-call.json").read_bytes())
    wrapped(inputs)
    wrapped(result)
    admission = original(inputs["admission"])
    before, after = original(result["before"]), original(result["after"])
    job_id = "job:" + name
    old_job, new_job = before["jobs"][job_id], after["jobs"][job_id]
    require(admission["session_id"] == before["id"] == after["id"] == "session:" + name and
            admission["job_id"] == old_job["job_id"] == new_job["job_id"] == job_id,
            "direct-native-job-identity")
    require(admission["status"] == "queued" and admission["question"] == "Retain public fixture" and
            admission["revision"] == admission["attempt"] == 1 and
            all(row["accepted"] is True for row in inputs["setups"]),
            "direct-native-admission")
    candidate = inputs["candidate"]
    require(set(candidate) == {"session_id", "job_id", "revision", "attempt", "seq", "kind", "stage", "outputs"},
            "selected-caller-request-fields")
    require(result["case"] == name and result["recordIdentityPreserved"] is True and
            result["nativeToolBodyEffects"] == 0 and result["publicationDecision"] is None,
            "direct-native-scope")
    accepted = name in {"valid-stage", "sequence-gap"}
    if name == "strict-boolean-sequence":
        require(candidate["seq"] is True and result["submitted"] is None and result["accepted"] is None and
                result["validation"]["type"] == "ValidationError", "strict-native-model-admission")
    else:
        # Pinned JobUpdate.model_dump_json() includes its omitted nullable default.
        materialized = {**candidate, "error": None}
        require(result["validation"] is None and original(result["submitted"]) == materialized and
                result["accepted"] is accepted, "native-direct-receipt")
    if not accepted:
        require(result["before"] == result["after"], "rejected-native-update-must-not-mutate-state")
    else:
        require(new_job["notes"] == ["Public fact"] and new_job["committed_stages"] == ["collect"] and
                new_job["last_update_seq"] == (9 if name == "sequence-gap" else 2) and
                after["job_sequence"] == before["job_sequence"] + 1,
                "accepted-stage-output-and-sequence")
        fixed = deepcopy(after)
        fixed["job_sequence"] = before["job_sequence"]
        for key in ("notes", "committed_stages", "last_update_seq", "updated_at"):
            fixed["jobs"][job_id][key] = old_job[key]
        require(fixed == before, "accepted-native-update-bounded-state-change")
    checks = {
        "foreign-owner": lambda: candidate["session_id"] != before["id"],
        "missing-job": lambda: candidate["job_id"] not in before["jobs"],
        "stale-revision": lambda: candidate["revision"] != old_job["revision"],
        "stale-attempt": lambda: candidate["attempt"] != old_job["attempt"],
        "duplicate-sequence": lambda: candidate["seq"] == old_job["last_update_seq"],
        "regressing-sequence": lambda: candidate["seq"] < old_job["last_update_seq"],
        "sequence-gap": lambda: candidate["seq"] > old_job["last_update_seq"] + 1,
        "wrong-stage": lambda: candidate["stage"] != old_job["stage"],
        "uncommitted-next-stage": lambda: candidate["kind"] == "stage_started" and old_job["stage"] not in old_job["committed_stages"],
        "overwrite-input": lambda: candidate["outputs"] == {"question": "Replaced"},
        "overwrite-lifecycle": lambda: candidate["outputs"] == {"status": "completed"},
        "invalid-output-type": lambda: candidate["outputs"] == {"notes": "not a list"},
        "nonstage-output": lambda: candidate["kind"] != "stage_completed" and bool(candidate["outputs"]),
        "premature-completion": lambda: candidate["kind"] == "completed" and old_job["stage"] not in old_job["committed_stages"],
        "postterminal": lambda: old_job["status"] == "failed",
    }
    require(name not in checks or checks[name](), "direct-fault-classification")
    return {"case": name, "accepted": result["accepted"],
            "validationRejected": result["validation"] is not None,
            "stateChanged": result["before"] != result["after"], "nativeToolBodyEffects": 0}


def runner_case(root, name, keys):
    directory = root / "cases" / name
    get = lambda filename: decode((directory / filename).read_bytes())
    records, effects, snapshots = get("callbacks.json"), get("body-effects.json"), get("snapshots.json")
    wrapped(records)
    wrapped(effects)
    wrapped(snapshots)
    require([r["sequence"] for r in records] == list(range(1, len(records) + 1)), "callback-order")
    require(all(type(r["time"]) in (int, float) for r in records), "same-host-capture-clock")
    proposals = [r for r in records if r["kind"] == "proposal-before-native-commit"]
    receipts = [r for r in records if r["kind"] == "native-commit-receipt"]
    require(len(proposals) == len(receipts) == (4 if name == "refusal-before-body" else 5),
            "native-update-population")
    require([r["submitted"] for r in proposals] == [r["submitted"] for r in receipts], "native-proposal-receipt-join")
    require([r["snapshot"] for r in records if r["kind"] == "on_update"] == snapshots,
            "native-parent-snapshot-callbacks")
    workers = [r for r in records if r["kind"] == "on_worker_event"]
    require([{"kind": r["workerEvent"], "job": r["job"]} for r in workers] == get("worker-events.json") and
            [r["kind"] for r in get("worker-events.json")] == ["started", "settled"],
            "actual-native-worker-lifecycle")
    rejected = []
    for index, (proposal, receipt) in enumerate(zip(proposals, receipts)):
        original_update, submitted = original(proposal["original"]), original(proposal["submitted"])
        require(original_update["session_id"] == submitted["session_id"] == "session:" + name and
                original_update["job_id"] == submitted["job_id"] == "job:" + name and
                original_update["revision"] == original_update["attempt"] == submitted["attempt"] == 1 and
                original_update["seq"] == index + 1 and
                proposal["sequence"] < receipt["sequence"], "native-update-identity")
        if proposal["fault"] is None:
            require(submitted == original_update and receipt["accepted"] is True, "unmodified-native-proposal")
        else:
            require(name != "valid-runner" and index == (2 if name == "refusal-before-body" else 3) and
                    proposal["fault"] == "harness-stale-revision" and
                    submitted == {**original_update, "revision": 2} and receipt["accepted"] is False,
                    "native-stale-revision-refusal")
            rejected.append(receipt)
    require(len(rejected) == (0 if name == "valid-runner" else 1), "finite-fault-count")
    expected_kinds = ["started", "stage_completed", "stage_started"]
    expected_kinds += ["failed"] if name == "refusal-before-body" else ["stage_completed", "completed" if name == "valid-runner" else "failed"]
    require([original(r["original"])["kind"] for r in proposals] == expected_kinds, "native-stage-boundaries")
    packet = get("observer-packet.json")
    require(packet["authority"] == get("authority-before-run.json") ==
            {"intervalId": name, "scope": "/work", "operation": "write-file"}, "selected-broker-authority")
    require(get("begin-before-run.json") == {"commitment": packet["commitment"], "checkpoint": packet["startCheckpoint"]},
            "observer-before-run-commitment")
    claim = verify_packet(packet, directory / "history.jsonl", keys["observer"], keys["witness"], directory / "workspace")
    expected_effects = 0 if name == "refusal-before-body" else 1
    writes = claim["writes"]
    require(claim["witnessScope"] == "PEER" and claim["coverage"]["noDetectedGap"] is True and
            len(writes) == len(effects) == expected_effects, "signed-finite-body-effects")
    body_events = [r for r in records if r["kind"] == "body-effect"]
    require(len(body_events) == expected_effects, "native-body-callback-count")
    for write, effect, record in zip(writes, effects, body_events):
        worker_job = original(effect["job"])
        require({k: record[k] for k in effect} == effect and worker_job["job_id"] == "job:" + name and
                effect["requestId"] == write["requestId"] == effect["result"]["request_id"] ==
                    "job:" + name + ":body:3" and effect["workerSeq"] == 3 and
                write["path"] == effect["result"]["path"] == "/work/result.txt" and
                write["contentDigest"] == effect["contentSHA256"] == sha(PAYLOAD.encode()) and
                effect["result"]["replayed"] is False and effect["operator"] == "native-JobWorkFlow-body",
                "native-job-call-broker-effect-binding")
        require((directory / "workspace" / "result.txt").read_bytes() == PAYLOAD.encode(), "current-body-file-readback")
        stage_receipt = receipts[2]
        require(stage_receipt["accepted"] is True and stage_receipt["sequence"] < record["sequence"],
                "native-stage-admitted-before-effect")
        if rejected:
            require(record["sequence"] < rejected[0]["sequence"], "effect-persists-before-later-refusal")
    require(len([e for e in read_history(directory / "history.jsonl") if e["event"]["kind"] == "write"]) == expected_effects,
            "signed-history-body-population")
    workspace = directory / "workspace"
    require({p.name for p in workspace.iterdir()} == ({"result.txt"} if expected_effects else set()), "finite-workspace-population")
    before, after = original(get("native-state-before-run.json")), original(get("native-state-after-run.json"))
    publication = get("manual-publication.json")
    prepub, postpub = original(publication["before"]), original(publication["after"])
    require(not before["messages"] and not prepub["messages"] and postpub == after and
            publication["operator"] == "explicit-author-foreground-turn" and publication["sdkAutoPublication"] is False,
            "native-job-output-not-automatic-publication")
    job = prepub["jobs"]["job:" + name]
    expected_status = "completed" if name == "valid-runner" else "failed"
    expected_answer = "Public answer" if name == "valid-runner" else ""
    require(job["status"] == expected_status and job["answer"] == expected_answer and
            job["question"] == "Retain public fixture" and job["notes"] == ["Public fact"] and
            job["committed_stages"] == (["collect", "write"] if name == "valid-runner" else ["collect"]) and
            job["last_update_seq"] == len(proposals) and prepub["job_sequence"] == len(snapshots),
            "native-committed-state")
    expected_reply = expected_status + ": Public fact" + ("; Public answer" if expected_answer else "")
    # Pinned ConversationMessage serializes all seven fields, including its defaults.
    defaults = {"name": None, "tool_call_id": None, "tool_calls": None,
                "files": None, "metadata": {}}
    expected_messages = [{"role": "user", "content": "Status please", **defaults},
                         {"role": "assistant", "content": expected_reply, **defaults}]
    expected_published_state = {**prepub, "current_user_message": "Status please",
                                "last_user_message": "Status please", "last_intent": "converse",
                                "messages": expected_messages}
    require(set(publication) == {"userInput", "reply", "before", "after", "operator", "sdkAutoPublication"} and
            publication["userInput"] == "Status please" and publication["reply"] == expected_reply and
            postpub == expected_published_state, "explicit-foreground-publication")
    require(all(original(r)["jobs"][0]["status"] in {"queued", "running", "completed", "failed"} for r in snapshots) and
            original(snapshots[-1])["jobs"][0] == job, "final-native-parent-snapshot")
    require(get("runner-after-close.json") == {"closed": True, "tasksSettled": True, "pendingReceipts": 0},
            "native-owned-worker-settlement")
    return {"case": name, "nativeStatus": expected_status, "nativeBodyEffects": expected_effects,
            "committedAnswer": expected_answer, "manualPublicationMessages": len(after["messages"]),
            "nativeProviderCalls": 0}


def read(root, policy_raw, policy_sha):
    require(sha(policy_raw) == policy_sha, "selected-host-policy")
    policy = decode(policy_raw)
    require(policy["profile"] == PROFILE and policy["sourceRevision"] == SOURCE and
            set(policy["files"]) == set(selected_files()) and set(policy["keys"]) == set(CASES),
            "selected-native-source-and-population")
    for name, expected in policy["files"].items():
        path = root / name
        require(path.is_file() and not path.is_symlink() and not any(p.is_symlink() for p in path.parents),
                "regular-selected-original")
        require(sha(path.read_bytes()) == expected, "selected-original-bytes")
    chosen = decode((root / "plan-before-run.json").read_bytes())
    require(chosen == plan(chosen["runId"]), "finite-before-run-plan")
    direct_rows = [direct_case(root, name) for name in DIRECT_CASES]
    runner_rows = [runner_case(root, name, policy["keys"][name]) for name in CASES]
    native = decode((root / "native-result.json").read_bytes())
    require(native["directRows"] == direct_rows and native["runnerRows"] == runner_rows and
            native["providerRequests"] == 0 and native["operator"] == "author-operated" and native["witnessScope"] == "PEER",
            "native-result-not-publication-authority")
    return {"status": "verified", "profile": PROFILE, "sourceRevision": SOURCE, "runId": chosen["runId"],
            "directRows": direct_rows, "runnerRows": runner_rows,
            "sequenceGaps": "accepted-native-contract", "effectBeforeRefusedCommit": "retained",
            "publication": "explicit-foreground-turn-only", "operator": "author-operated",
            "witnessScope": "PEER", "outsideOperator": False, "older16Rows": "unchanged",
            "prospectiveEightTaskRun": "not-started", "providerRequests": 0,
            "doesNotAssert": ["provider-inference", "model-quality", "outside-custody", "host-adoption",
                              "external-effect-authorization-by-job-commit", "effect-rollback",
                              "contiguous-sequence", "unmediated-effects", "trusted-timestamps"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = encode(read(args.packet, args.policy.read_bytes(), args.policy_sha256))
    args.output.write_bytes(result)
    print(result.decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
