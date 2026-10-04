"""SDK-free reconstruction of nested config, callbacks, lifecycle and writes."""

import argparse
from collections import Counter
from pathlib import Path

from probity_observer.history import read_history
from probity_observer.verify import verify_packet

from .contract import (CASES, PAYLOAD, PROFILE, SOURCE, decode, encode, original, plan,
                       require, selected_files, sha)


def host_policy(root):
    """Select output bytes and keys in the author host; not outside custody."""
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


def request_text(request):
    return " ".join((p.get("text") or "") for c in request["contents"] for p in (c.get("parts") or []))


def event_parts(event, name):
    return [p[name] for p in (event.get("content") or {}).get("parts", []) if p.get(name)]


def read_case(root, case, keys):
    directory = root / "cases" / case
    get = lambda n: decode((directory / n).read_bytes())
    before, after = get("plugin-before-parent-close.json"), get("plugin-after-parent-close.json")
    require(before["capturePayloads"] is True and before["closed"] is False and
            before["closeCalls"] == 0 and before["failures"] == 0, "plugin-live-through-nested-runs")
    require(after["closed"] is True and after["closeCalls"] == 1 and after["failures"] == 0 and
            after["records"][:-1] == before["records"], "parent-closes-shared-plugin-once")
    records = after["records"]
    require([r["sequence"] for r in records] == list(range(len(records))), "callback-sequence")
    wrapped(records)
    closes = [r for r in records if r["callback"] == "plugin-close"]
    require(len(closes) == 1 and closes[0] == records[-1] and
            closes[0]["native"]["phase"] == "parent-close" and
            closes[0]["native"]["ordinal"] == 1 and
            closes[0]["native"]["closedBefore"] is False, "actual-parent-close-boundary")
    configs = [r for r in records if r["callback"] == "config-before-run"]
    covered = case != "token-no-plugins"
    roles = ["root", "middle", "leaf", "middle", "leaf"] if covered else ["root"]
    require([r["native"]["rootAgent"] for r in configs] == roles, "nested-config-population")
    require(len({r["invocationId"] for r in configs}) == len(configs) and
            len({r["native"]["sessionId"] for r in configs}) == len(configs), "fresh-nested-invocations-and-sessions")
    parent_raw = get("parent-config-before.json")["json"]
    require(get("parent-config-after.json")["json"] == parent_raw, "parent-config-unchanged")
    parent = None if parent_raw is None else decode(parent_raw)
    expected_parent = (None if case == "no-config" else
        {"compaction_interval": 1 if case == "window-only" else 10000, "overlap_size": 0,
         "token_threshold": None if case == "window-only" else 100,
         "event_retention_size": None if case == "window-only" else 0})
    require(parent == expected_parent, "selected-parent-config")
    nested = ({**parent, "compaction_interval": None, "overlap_size": None}
              if case.startswith("token") else None)
    invocation_agents = {}
    for i, record in enumerate(configs):
        value = record["native"]
        require(value["sessionId"] == case if i == 0 else value["sessionId"] != case,
                "separate-nested-session")
        require(value["runStartedAt"] <= closes[0]["native"]["closedAt"], "plugin-time-boundary")
        config = decode(bytes.fromhex(value["configJSONHex"])) if value["configJSONHex"] is not None else None
        require(config == (parent if i == 0 else nested), "nested-token-config-without-window-trigger")
        require(value["sharesParentSummarizer"] is (config is not None), "selected-summarizer-sharing-observation")
        invocation_agents[record["invocationId"]] = value["rootAgent"]
    for callback in ("before-run", "after-run", "before-agent", "after-agent"):
        selected = [r for r in records if r["callback"] == callback]
        require(Counter(r["invocationId"] for r in selected) == Counter(invocation_agents.keys()),
                "all-registered-invocations-completed")
    requests = get("model-requests.json")
    require(set(requests) == {"root", "middle", "leaf", "summarizer"}, "native-model-population")
    expected_counts = {"root": 3, "middle": 4, "leaf": 8,
                       "summarizer": 9 if case.startswith("token") else (1 if case == "window-only" else 0)}
    models = {agent: [original(r) for r in rows] for agent, rows in requests.items()}
    require({agent: len(rows) for agent, rows in models.items()} == expected_counts, "native-model-call-counts")
    grouped = {agent: [] for agent in roles}
    for record in records:
        if record["callback"] == "before-model":
            agent = invocation_agents[record["invocationId"]]
            value = original(record["native"])
            require(value["config"]["labels"] is None, "native-before-label-boundary")
            grouped[agent].append({**value, "config": {**value["config"], "labels": {"adk_agent_name": agent}}})
    require(all(grouped[agent] == models[agent] for agent in grouped), "callbacks-bind-native-model-entry")
    require(sum(r["callback"] == "after-model" for r in records) == (15 if covered else 3),
            "after-model-callback-population")
    require(all(r["config"]["labels"] is None for r in models["summarizer"]),
            "direct-summarizer-source-boundary")
    leaf = models["leaf"]
    require(len(leaf[4]["contents"]) == 1 and "NESTED SUMMARY" not in request_text(leaf[4]),
            "second-leaf-run-fresh-history")
    require(all(("NESTED SUMMARY" in request_text(leaf[i])) is case.startswith("token") for i in (3, 7)),
            "both-leaf-runs-token-compaction")
    yielded = [original(e) for e in get("yielded-root-events.json")]
    root_session = original(get("root-session.json"))
    require(len(yielded) == 5 and all(e["author"] == "root" for e in yielded) and
            [p["text"] for e in yielded for p in (e.get("content") or {}).get("parts", []) if p.get("text")] == ["root answer"],
            "root-terminal-result")
    require([e for e in root_session["events"] if e["author"] == "root"] == yielded,
            "root-retained-session")
    captured = [original(r["native"]) for r in records if r["callback"] == "event"]
    require([e for e in captured if e["author"] == "root"] == yielded and
            Counter(e["author"] for e in captured) == ({"root": 5, "middle": 6, "leaf": 14} if covered else {"root": 5}),
            "finite-native-callback-event-population")
    packet = get("observer-packet.json")
    require(packet["authority"] == get("authority-before-run.json") ==
            {"intervalId": case, "scope": "/work", "operation": "write-file"}, "broker-authority")
    require(get("begin-before-run.json") == {"commitment": packet["commitment"], "checkpoint": packet["startCheckpoint"]},
            "observer-prior-commitment")
    claim = verify_packet(packet, directory / "history.jsonl", keys["observer"], keys["witness"], directory / "workspace")
    writes, effects = claim["writes"], get("tool-effects.json")
    require(claim["witnessScope"] == "PEER" and claim["coverage"]["noDetectedGap"] is True and
            len(writes) == len(effects) == 6, "bounded-native-body-effects")
    require(len({e["functionCallId"] for e in effects}) == 6 and
            Counter(e["invocationId"] for e in effects).most_common()[0][1] == 3 and
            len({e["invocationId"] for e in effects}) == 2, "two-distinct-leaf-effect-invocations")
    body_calls = [r for r in records if r["callback"] == "before-tool" and r["native"]["tool"] == "read_large_file"]
    body_responses = [r for r in records if r["callback"] == "after-tool" and r["native"]["tool"] == "read_large_file"]
    require(len(body_calls) == len(body_responses) == (6 if covered else 0), "declared-leaf-tool-callback-coverage")
    for index, (write, effect) in enumerate(zip(writes, effects)):
        require(write["requestId"] == effect["functionCallId"] == effect["result"]["request_id"] and
                write["path"] == effect["result"]["path"] == f"/work/chapter-{index}.txt" and
                write["contentDigest"] == effect["contentSHA256"] == sha(PAYLOAD.encode()) and
                effect["operator"] == "native-tool-body" and effect["result"]["replayed"] is False,
                "native-call-authority-effect-join")
        require((directory / "workspace" / f"chapter-{index}.txt").read_bytes() == PAYLOAD.encode(), "current-file-readback")
        if covered:
            call, response = body_calls[index], body_responses[index]
            require(call["native"] == {"tool": "read_large_file", "arguments": {}, "functionCallId": write["requestId"]} and
                    call["invocationId"] == response["invocationId"] == effect["invocationId"] and
                    response["native"] == {**call["native"], "result": PAYLOAD}, "native-tool-callback-effect-binding")
            native_calls = [c for e in captured if e["author"] == "leaf" and e["invocation_id"] == effect["invocationId"]
                            for c in event_parts(e, "function_call") if c["id"] == write["requestId"]]
            require(len(native_calls) == 1 and native_calls[0]["name"] == "read_large_file" and native_calls[0]["args"] == {},
                    "native-event-issued-call")
    require(len([e for e in read_history(directory / "history.jsonl") if e["event"]["kind"] == "write"]) == 6 and
            {p.name for p in (directory / "workspace").iterdir()} == {f"chapter-{i}.txt" for i in range(6)},
            "signed-history-and-finite-workspace")
    return {"case": case, "rootCalls": 3, "middleCalls": 4, "leafCalls": 8,
            "summaryCalls": len(models["summarizer"]), "nativeToolEffects": 6,
            "capturedInvocationConfigs": len(configs), "pluginCloseCalls": 1,
            "captureFailures": 0, "nestedPluginCoverage": covered, "parentConfigUnchanged": True,
            "publicationDecision": "admit-this-covered-case-only" if covered else "hold-nested-plugin-coverage"}


def read(root, policy_raw, policy_sha):
    require(sha(policy_raw) == policy_sha, "selected-host-policy")
    policy = decode(policy_raw)
    require(policy["profile"] == PROFILE and policy["sourceRevision"] == SOURCE and
            set(policy["files"]) == set(selected_files()) and set(policy["keys"]) == set(CASES), "selected-source-and-population")
    for name, expected in policy["files"].items():
        p = root / name
        require(p.is_file() and not p.is_symlink() and all(not q.is_symlink() for q in p.parents), "regular-selected-input")
        require(sha(p.read_bytes()) == expected, "selected-original-bytes")
    selected = decode((root / "plan-before-run.json").read_bytes())
    require(selected == plan(selected["runId"]), "finite-before-run-plan")
    rows = [read_case(root, c, policy["keys"][c]) for c in CASES]
    native = decode((root / "native-result.json").read_bytes())
    require(native["rows"] == [{**r, "publicationDecision": None} for r in rows] and native["publicationDecision"] is None,
            "native-result-not-publication-authority")
    return {"status": "verified", "profile": PROFILE, "sourceRevision": SOURCE, "runId": selected["runId"],
            "rows": rows, "publicationDecision": "admit-three-covered-cases-hold-unobserved-nested-case",
            "operator": "author-operated", "witnessScope": "PEER", "outsideOperator": False,
            "prospectiveEightTaskRun": "not-started", "older16Rows": "unchanged", "modelQuality": "not-evaluated",
            "summarizerCallbackCoverage": "not-exercised-direct-SDK-summarizer-model-requests-retained-separately",
            "doesNotAssert": ["provider-inference", "real-model-quality", "outside-custody", "host-adoption",
                              "complete-application-callbacks", "unmediated-effects", "trusted-timestamps"]}


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
