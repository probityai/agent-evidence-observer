"""Run the installed Verify event-absence adapter on retained ADK routing events."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

CASES = ("approval-granted", "approval-denied", "long-running-completed")
SOURCE = "86a47f6974bae349a5c9ea15a74a4b450614ae42"
VERIFY = "e835ce2bd6a960e7a1cc2fa6522f16d55dce728a"
PROBE = r'''
import hashlib, importlib.metadata as md, json, sys
from pathlib import Path
d=md.distribution("probity-verify");root=Path(d.locate_file("probity_verify"))
files={};forbidden=[]
for p in sorted(root.rglob("*")):
 if p.is_symlink() or p.suffix in (".pyc",".pyo",".so",".pyd"):
  forbidden.append(str(p))
 if p.is_file() and p.suffix==".py":
  raw=p.read_bytes();files[str(p.relative_to(root))]=hashlib.sha1(
   b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
framework=False
try:md.distribution("google-adk");framework=True
except md.PackageNotFoundError:pass
print(json.dumps(dict(files=files,version=d.version,forbidden=forbidden,
 sdkPresent=framework,pythonVersion=list(sys.version_info[:3])),sort_keys=True))
'''


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def encode(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def decode(raw: bytes) -> object:
    def unique(pairs: list[tuple[str, object]]) -> dict:
        value = {}
        for key, item in pairs:
            require(key not in value, "duplicate-json-member")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, "nonfinite-json"))


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def native(record: dict) -> dict:
    value = decode(bytes.fromhex(record["jsonHex"]))
    require(value == record["value"], "native-original-byte-mismatch")
    return value


def instant(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def child(argv: list[str], prefix: Path, cwd: Path) -> tuple[int, bytes]:
    environment = {k: v for k, v in os.environ.items()
                   if not k.startswith(("PYTHON", "PIP")) and not any(
                       word in k.upper() for word in
                       ("TOKEN", "SECRET", "CREDENTIAL", "API_KEY", "PASSWORD"))}
    try:
        result = subprocess.run(argv, cwd=cwd, env=environment, check=False,
                                capture_output=True, timeout=120)
        status, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as failure:
        status, stdout, stderr = None, failure.stdout or b"", failure.stderr or b""
    prefix.with_suffix(".stdout").write_bytes(stdout)
    prefix.with_suffix(".stderr").write_bytes(stderr)
    prefix.with_suffix(".status.json").write_bytes(encode(
        {"returncode": status, "timeout": status is None}))
    require(status is not None, "verify-consumer-timeout")
    return status, stdout


def bindings(directory: Path, case_id: str, capability: dict,
             observation: dict, event_type: str) -> tuple[dict, dict]:
    directory.mkdir(parents=True, exist_ok=True)
    artifacts, witnesses = {}, {}
    for name, value in (("capability", capability), ("observation", observation)):
        raw = encode(value)
        (directory / (name + ".json")).write_bytes(raw)
        artifacts[name] = {"path": name + ".json", "length": len(raw), "sha256": sha(raw)}
        witnesses[name] = {"artifact": name, "sha256": sha(raw),
                           "authority": "Author-operated ADK CapturePlugin derived record"}
    case = {"schema_version": "probity-case/v1", "case_id": case_id,
            "artifacts": artifacts}
    policy = {"schema_version": "probity-policy/v1", "witnesses": witnesses,
              "assessments": {case_id: {"claim_type": "event_absence/v1",
                  "event_type": event_type, "invocation_id": observation["invocation_id"],
                  "scope": observation["scope"], "capability_witness": "capability",
                  "observation_witness": "observation"}}}
    (directory / "case.json").write_bytes(encode(case))
    (directory / "policy.json").write_bytes(encode(policy))
    return case, policy


def invoke(reader: Path, directory: Path, prefix: Path, cwd: Path) -> tuple[int, bytes]:
    return child([str(reader), "-I", "-B", "-c",
                  "from probity_verify.cli import main; raise SystemExit(main())",
                  str(directory / "case.json"), "--policy", str(directory / "policy.json"),
                  "--json"], prefix, cwd)


def launch(reader: Path, source: Path, wheel: Path, packet: Path,
           policy_path: Path, policy_sha: str, output: Path) -> dict:
    require(not output.exists(), "output-already-exists")
    output.mkdir(parents=True)
    cwd = output / "empty-cwd"
    cwd.mkdir()
    selected_raw = Path(__file__).with_name("verify-source-selection.json").read_bytes()
    selected = decode(selected_raw)
    require(selected["revision"] == VERIFY and selected["adapter"] == "event_absence/v1",
            "unselected-verify-source")
    (output / "verify-source-selection.json").write_bytes(selected_raw)
    for name, expected in selected["pythonGitBlobs"].items():
        original = source / "src" / "probity_verify" / name
        raw = original.read_bytes()
        require(not original.is_symlink() and hashlib.sha1(
            b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == expected,
            "verify-checkout-source")
        retained = output / "verify-source" / "src" / "probity_verify" / name
        retained.parent.mkdir(parents=True, exist_ok=True)
        retained.write_bytes(raw)
    for name in ("LICENSE", "pyproject.toml", "README.md", "AGENTS.md"):
        shutil.copyfile(source / name, output / "verify-source" / name)
    require(wheel.name == "probity_verify-0.1.0-py3-none-any.whl", "verify-wheel-name")
    shutil.copyfile(wheel, output / wheel.name)
    status, probe_raw = child([str(reader), "-I", "-B", "-c", PROBE],
                              output / "verify-installation", cwd)
    probe = decode(probe_raw)
    require(status == 0 and probe["files"] == selected["pythonGitBlobs"] and
            probe["version"] == "0.1.0" and not probe["forbidden"] and
            not probe["sdkPresent"], "installed-verify-source")

    policy_raw = policy_path.read_bytes()
    require(sha(policy_raw) == policy_sha, "unselected-native-host-policy")
    native_policy = decode(policy_raw)
    require(native_policy["sourceRevision"] == SOURCE, "unselected-adk-source")
    plan_raw = (packet / "plan-before-run.json").read_bytes()
    require(sha(plan_raw) == native_policy["files"]["plan-before-run.json"], "unselected-plan")
    plan = decode(plan_raw)
    require(plan["cases"] == list(CASES) and plan["sourceRevision"] == SOURCE and
            plan["prospectiveEightTaskRun"] == "not-started", "native-population")
    rows, derivations = [], []
    first_case = None
    for name in CASES:
        originals = {}
        inputs = {}
        for filename in ("callbacks.json", "turns.json", "session.json"):
            path = f"cases/{name}/{filename}"
            raw = (packet / path).read_bytes()
            require(sha(raw) == native_policy["files"][path], "unselected-native-bytes")
            inputs[path] = {"sha256": sha(raw), "length": len(raw)}
            originals[filename] = decode(raw)
        capture = originals["callbacks.json"]
        turns = [[native(e) for e in turn] for turn in originals["turns.json"]]
        captured = [native(r["native"]) for r in capture["records"] if r["callback"] == "event"]
        require(capture["closed"] and capture["capturePayloads"] and not capture["failures"]
                and len(turns) == 3 and captured == [e for turn in turns for e in turn],
                "captured-native-event-population")
        require(sum(r["callback"] == "before-run" for r in capture["records"]) == 3 and
                sum(r["callback"] == "after-run" for r in capture["records"]) == 3,
                "captured-native-turn-boundaries")
        session_events = native(originals["session.json"])["events"]
        require([e for e in session_events if e["author"] != "user"] == captured,
                "native-session-event-population")
        for index, purpose, wrong_author in (
                (1, "user-response", "root"), (2, "later-plain-text", "issuer")):
            events = turns[index]
            require(events and all(e["author"] in {"root", "issuer"} for e in events),
                    "native-turn-event-population")
            invocations = {e["invocation_id"] for e in events}
            require(len(invocations) == 1, "native-turn-invocation")
            case_id = name + "/" + purpose
            scope = {"id": plan["runId"] + "/" + case_id,
                     "start": instant(min(e["timestamp"] for e in events)),
                     "end": instant(max(e["timestamp"] for e in events))}
            capability = {"schema_version": "probity-capabilities/v1", "claim_id": case_id,
                          "invocation_id": next(iter(invocations)),
                          "producer": "author-operated-payload-enabled-adk-capture",
                          "visible_event_types": ["root-native-output", "issuer-native-output"]}
            observation = {"schema_version": "probity-observation/v1", "claim_id": case_id,
                           "invocation_id": capability["invocation_id"],
                           "producer": capability["producer"], "scope": scope,
                           "coverage": "complete", "events": [
                               {"id": e["id"], "type": e["author"] + "-native-output",
                                "time": instant(e["timestamp"])} for e in events]}
            event_type = wrong_author + "-native-output"
            directory = output / "cases" / name / purpose
            bindings(directory, case_id, capability, observation, event_type)
            repeated = []
            for attempt in (1, 2):
                status, decision = invoke(reader, directory, directory / f"verify-{attempt}", cwd)
                require(status == 0 and decode(decision)["decision"] == "supported",
                        "genuine-verify-routing-decision")
                repeated.append(decision)
            require(repeated[0] == repeated[1], "verify-repeat-byte-difference")
            rows.append({"case": case_id, "claimType": "event_absence/v1",
                         "absentEventType": event_type, "decision": "supported",
                         "literalRepeat": True, "nativeEvents": len(events),
                         "decisionSHA256": sha(repeated[0])})
            derivations.append({"case": case_id, "nativeInputs": inputs, "turnIndex": index,
                "eventProjection": "native id, author + '-native-output', native timestamp truncated to UTC seconds for Verify v1",
                "scopeClock": "same-host native Event timestamps; no trusted timestamp claim",
                "coverage": "yielded events delivered to this registered plugin in this finite turn",
                "custody": "author-operated PEER"})
            if first_case is None:
                first_case = (case_id, capability, observation, event_type)

    control_rows = []
    case_id, capability, original_observation, event_type = first_case
    for name, expected in (("event-present", "contradicted"),
                           ("coverage-unknown", "not_established")):
        observation = copy.deepcopy(original_observation)
        if name == "event-present":
            observation["events"].append({"id": "finite-control-event", "type": event_type,
                                           "time": observation["scope"]["start"]})
        else:
            observation["coverage"] = "unknown"
        directory = output / "controls" / name
        bindings(directory, case_id, capability, observation, event_type)
        status, decision = invoke(reader, directory, directory / "verify", cwd)
        require(status == 0 and decode(decision)["decision"] == expected, "verify-control-decision")
        control_rows.append({"control": name, "decision": expected, "reselectedBytes": True})
    directory = output / "controls" / "malformed-duplicate"
    bindings(directory, case_id, capability, original_observation, event_type)
    (directory / "case.json").write_bytes(b'{"case_id":"a","case_id":"b"}')
    status, decision = invoke(reader, directory, directory / "verify", cwd)
    require(status == 2 and not decision, "malformed-verify-input-must-have-no-verdict")
    control_rows.append({"control": "malformed-duplicate", "exitStatus": 2, "verdictBytes": 0})
    (output / "derivation.json").write_bytes(encode(derivations))
    receipt = {"status": "installed-verify-consumer-passed", "adkRevision": SOURCE,
               "verifyRevision": VERIFY, "verifyPythonFiles": len(selected["pythonGitBlobs"]),
               "verifyWheelSHA256": sha(wheel.read_bytes()), "nativeHostPolicySHA256": policy_sha,
               "rows": rows, "controls": control_rows, "frameworkFree": True,
               "operator": "author-operated", "witnessScope": "PEER",
               "outsideOperator": False, "prospectiveEightTaskRun": "not-started",
               "scope": "absence of wrong-agent output in the plugin's six retained native turns",
               "component": "probityai/probity-verify event_absence/v1; custom routing reader remains separate"}
    (output / "verify-consumer-receipt.json").write_bytes(encode(receipt))
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("reader", "source", "wheel", "packet", "policy", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    args = parser.parse_args()
    print(encode(launch(args.reader, args.source, args.wheel, args.packet,
                        args.policy, args.policy_sha256, args.output)).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
