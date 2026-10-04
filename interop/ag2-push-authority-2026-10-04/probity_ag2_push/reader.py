"""SDK-free reconstruction of URL admission, native dispatch and Observer effects."""

import argparse
from pathlib import Path

from probity_observer.history import read_history
from probity_observer.verify import verify_packet

from .contract import (AUTH, CASES, CONTENT, PROFILE, SDK, SOURCE, TARGET, TEXT, TOKEN,
                       UNSAFE, decode, encode, json_original, plan, require, selected_files, sha)


def host_policy(root):
    return {"profile": PROFILE, "ag2Revision": SOURCE, "a2aSDKRevision": SDK,
            "files": {p: sha((root / p).read_bytes()) for p in selected_files()},
            "keys": {case: decode((root / "cases" / case / "keys-before-run.json").read_bytes())
                     for case in CASES}}


def original(value):
    require(set(value) == {"protobufJSONHex", "protobufHex", "protobufType"},
            "native-protobuf-capture-fields")
    require(bool(bytes.fromhex(value["protobufHex"])), "missing-native-protobuf-bytes")
    return json_original(value["protobufJSONHex"])


def camel(value):
    """Mirror the selected SDK's default protobuf JSON names for comparison.

    Original native JSON and serialized protobuf bytes remain separate. This
    reader checks captured JSON semantics; it does not decode protobuf wire data.
    """
    if isinstance(value, list):
        return [camel(v) for v in value]
    if isinstance(value, dict):
        pairs = [(k.split("_")[0] + "".join(p.title() for p in k.split("_")[1:]), camel(v))
                 for k, v in value.items()]
        require(len(set(k for k, _ in pairs)) == len(pairs), "native-json-name-collision")
        return dict(pairs)
    return value


def expected_config(raw):
    auth = raw.get("authentication")
    return {"url": raw["url"], "id": raw["id"], "token": raw["token"],
            "authentication": {"scheme": auth["scheme"], "credentials": auth["credentials"]}}


def read_case(root, case, keys):
    transport, variant = case.split("/")
    directory = root / "cases" / case
    get = lambda n: decode((directory / n).read_bytes())
    task = original(get("native-task.json"))
    task_id = task["id"]
    require(bool(task_id) and task["status"]["state"] == "TASK_STATE_COMPLETED",
            "native-completed-task")
    agent = get("native-agent.json")
    require(agent["response"] == TEXT and agent["nativeModelCalls"] == 1 and
            agent["agentTaskCompletedBeforeRegistration"] is True and
            agent["providerRequests"] == 0 and agent["toolBodyEffects"] == 0,
            "native-agent-task-boundary")
    capture = get("native-callbacks.json")
    require(capture["closed"] is True and capture["failures"] == 0 and
            capture["mutatesRequests"] is False, "native-capture-completion")
    records = capture["records"]
    require([r["sequence"] for r in records] == list(range(len(records))), "native-callback-sequence")
    require(all(r["phase"] in ("before", "after") for r in records), "native-callback-phase")
    fetched = [original(r["native"]) for r in records
               if r["phase"] == "after" and r["method"] == "get_task"]
    require(fetched and fetched[-1] == task and
            all(t["id"] == task_id and t["context_id"] == task["context_id"] and
                t["status"]["state"] in ("TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_COMPLETED")
                for t in fetched), "callback-fetched-task")
    require(task["status"]["message"]["parts"] == [{"text": TEXT}], "native-task-response-text")
    submissions = [original(r["native"]) for r in records
                   if r["phase"] == "before" and r["method"] == "create_task_push_notification_config"]
    returned = [original(r["native"]) for r in records
                if r["phase"] == "after" and r["method"] == "create_task_push_notification_config"]
    operations, stored = get("push-operations.json"), get("stored-configs.json")
    attempted = list(UNSAFE) if variant == "sdk-policy-denied" else [
        UNSAFE[0] if variant in ("registration-denied", "legacy-config-only") else TARGET]
    require(len(submissions) == len(operations) == len(attempted), "registration-population")
    denied = variant in ("registration-denied", "sdk-policy-denied")
    for native, operation, url in zip(submissions, operations, attempted):
        submitted = {"url": url, "id": None, "token": TOKEN,
                     "authentication": {"scheme": "Bearer", "credentials": AUTH}}
        require(operation["submitted"] == submitted and native["task_id"] == task_id and
                native["url"] == url and native["token"] == TOKEN and
                native["authentication"] == submitted["authentication"], "native-registration-binding")
        require(set(native) == {"task_id", "url", "token", "authentication"},
                "native-registration-field-population")
        require(operation["outcome"] == ("InvalidParamsError" if denied else "stored"),
                "registration-refusal-or-admission")
    require(len(stored) == len(returned) == (0 if denied else 1), "stored-config-population")
    if stored:
        created = operations[0]["returned"]
        require(bool(created["id"]) and created == {**operations[0]["submitted"], "id": created["id"]}
                and stored == [created], "server-issued-config-id")
        require(expected_config(returned[0]) == created and returned[0]["task_id"] == task_id,
                "callback-stored-config-binding")
    policies = get("url-policy.json")
    mode = "sdk" if variant == "sdk-policy-denied" else "allow"
    require(policies["registrationMode"] == (None if variant == "legacy-config-only" else mode),
            "selected-registration-policy")
    expected_registration = ([] if variant == "legacy-config-only" else [
        {"sequence": i, "url": url, "accepted": not denied, "policy": mode}
        for i, url in enumerate(attempted)])
    require(policies["registration"] == expected_registration, "registration-policy-calls")
    dispatch_mode = "deny" if variant == "dispatch-denied" else "allow"
    require(policies["dispatchMode"] == dispatch_mode, "selected-dispatch-policy")
    expected_dispatch = ([] if denied or variant == "legacy-config-only" else [
        {"sequence": 0, "url": TARGET, "accepted": variant != "dispatch-denied", "policy": dispatch_mode}])
    require(policies["dispatch"] == expected_dispatch, "dispatch-rechecks-url-policy")
    dispatch = get("dispatch.json")
    called = variant != "legacy-config-only"
    require(dispatch["explicitHostCall"] is called and
            dispatch["operator"] == "same-author-host-post-completion" and
            dispatch["automaticTaskDispatch"] is False and dispatch["returnValue"] is None and
            dispatch["nativeMethod"] == "BasePushNotificationSender.send_notification",
            "host-dispatch-not-agent-tool-or-delivery-ack")
    require(original(dispatch["event"]) == task if called else dispatch["event"] is None,
            "dispatch-event-task-binding")
    require(get("effect-before-dispatch.json") == {"files": [], "targetCallbacks": 0},
            "configuration-not-callback-or-effect")
    callbacks, effects = get("target-callbacks.json"), get("target-effects.json")
    reached = variant in ("accepted", "target-denied")
    require(len(callbacks) == (1 if reached else 0), "target-callback-population")
    if callbacks:
        callback = callbacks[0]
        raw = bytes.fromhex(callback["bodyJSONHex"])
        require(callback["sequence"] == 0 and callback["url"] == TARGET and
                callback["bodySHA256"] == sha(raw) and json_original(raw.hex()) == {"task": camel(task)},
                "native-callback-task-and-byte-binding")
        require(callback["headers"] == {"x-a2a-notification-token": TOKEN,
                "authorization": "Bearer " + AUTH, "content-type": "application/json"},
                "native-callback-credentials")
        require(callback["targetAccepted"] is (variant == "accepted") and
                callback["responseStatus"] == (200 if variant == "accepted" else 403),
                "target-authority-decision")
    packet = get("observer-packet.json")
    require(packet["authority"] == get("authority-before-run.json") ==
            {"intervalId": case, "scope": "/work", "operation": "write-file"}, "broker-authority")
    require(get("begin-before-run.json") == {"commitment": packet["commitment"],
            "checkpoint": packet["startCheckpoint"]}, "prior-observer-commitment")
    claim = verify_packet(packet, directory / "history.jsonl", keys["observer"], keys["witness"],
                          directory / "workspace")
    require(claim["witnessScope"] == "PEER" and claim["coverage"]["noDetectedGap"] is True,
            "bounded-peer-coverage")
    writes = claim["writes"]
    require(len(writes) == len(effects) == (1 if variant == "accepted" else 0),
            "accepted-target-effect-population")
    if writes:
        require(writes[0]["requestId"] == task_id and writes[0]["path"] == "/work/result.txt" and
                writes[0]["contentDigest"] == sha(CONTENT) and
                (directory / "workspace/result.txt").read_bytes() == CONTENT, "target-effect-bytes")
        require(effects[0]["requestId"] == task_id and
                effects[0]["operator"] == "same-author-callback-target" and
                effects[0]["callbackBodySHA256"] == callbacks[0]["bodySHA256"],
                "target-effect-operator-and-callback")
    else:
        require(not list((directory / "workspace").iterdir()), "refused-target-no-effect")
    require(len([r for r in read_history(directory / "history.jsonl")
                 if r["event"]["kind"] == "write"]) == len(writes), "observed-history-write-count")
    return {"case": case, "nativeTasks": 1, "modelCalls": 1, "storedConfigs": len(stored),
            "targetCallbacks": len(callbacks), "observedWrites": len(writes), "explicitDispatch": called}


def read(root, policy_raw, policy_sha):
    require(sha(policy_raw) == policy_sha, "selected-host-policy")
    policy = decode(policy_raw)
    require(policy["profile"] == PROFILE and policy["ag2Revision"] == SOURCE and
            policy["a2aSDKRevision"] == SDK, "selected-source-and-profile")
    require(set(policy["files"]) == set(selected_files()) and set(policy["keys"]) == set(CASES),
            "selected-packet-population")
    for name, expected in policy["files"].items():
        p = root / name
        require(p.is_file() and not p.is_symlink() and
                all(not parent.is_symlink() for parent in p.parents), "selected-regular-input")
        require(sha(p.read_bytes()) == expected, "selected-original-bytes")
    selected = decode((root / "plan-before-run.json").read_bytes())
    require(selected == plan(selected["runId"]), "fixed-finite-before-run-plan")
    rows = [read_case(root, c, policy["keys"][c]) for c in CASES]
    result = decode((root / "native-result.json").read_bytes())
    require(result["rows"] == [{**r, "publicationDecision": None} for r in rows] and
            result["publicationDecision"] is None, "native-result-not-publication-decision")
    return {"status": "verified", "profile": PROFILE, "ag2Revision": SOURCE, "a2aSDKRevision": SDK,
            "runId": selected["runId"], "rows": rows,
            "publicationDecision": "admit-this-finite-reference-only", "operator": "author-operated",
            "witnessScope": "PEER", "outsideOperator": False, "modelQuality": "not-evaluated",
            "prospectiveEightTaskRun": "not-started", "older16Rows": "unchanged",
            "doesNotAssert": ["provider-inference", "real-model-quality", "outside-custody",
                              "automatic-native-task-callbacks", "network-callback-delivery",
                              "global-URL-safety", "unmediated-effects", "host-adoption"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = encode(read(args.packet, args.policy.read_bytes(), args.policy_sha256))
    args.output.write_bytes(raw)
    print(raw.decode())
    return 0
