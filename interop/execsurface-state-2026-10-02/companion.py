"""Same-operator metadata capture joined to separately retained state bytes."""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
LIMITS = ["same-operator custody", "metadata trace does not contain written bytes",
          "endpoint snapshots do not prove absence of intermediate writes",
          "no typed collection-health envelope", "no independent authority or adoption"]
PACKET_FILES = {"before.bin", "after.bin", "authority.json", "plan.json", "commitment.json",
                "observation.json", "observation.stderr", "invocation.json", "statement.json", "envelope.json",
                "producer-baseline.json", "producer-policy.json", "producer-comparison.json", "calibration.json",
                "learn.stdout", "learn.stderr", "check.stdout", "check.stderr"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode()


def write_json(path: Path, value) -> None:
    path.write_bytes(encode(value) + b"\n")


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError(code)


def strict_json(data: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate-member")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("nonfinite-json")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def selected_reader(pins):
    source = (HERE / "source-pins.json").read_bytes()
    require(sha(source) == pins["sourcePinsSha256"], "source-pins-mismatch")
    selection = strict_json(source)
    for name, digest in selection["files"].items():
        require(sha((HERE / "vendor" / name).read_bytes()) == digest, "reference-source-mismatch")
    for name, digest in selection.get("ownedFiles", {}).items():
        require(sha((HERE / name).read_bytes()) == digest, "adapter-source-mismatch")
    path = HERE / "vendor/vectors-observed-effect/check_vectors.py"
    spec = importlib.util.spec_from_file_location("execsurface_predicate_reader", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, selection


def state_root(path: str, contents: bytes) -> str:
    """SHA256 of the declared single-path state map, not a trace digest."""
    return sha(encode({"algorithm": "probity-single-file-state-v1", "entries": [
        {"path": path, "sha256": sha(contents), "size": len(contents)}]}))


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def advance(second: str) -> str:
    deadline = time.monotonic() + 2
    while now() <= second:
        require(time.monotonic() < deadline, "clock-did-not-advance")
        time.sleep(.01)
    return now()


def signed_statement(statement, key, reader):
    payload = reader.canonical_bytes(statement)
    kind = "application/vnd.in-toto+json"
    return {"payloadType": kind, "payload": base64.b64encode(payload).decode(),
            "signatures": [{"keyid": key.public_key().public_bytes_raw().hex(),
                            "sig": base64.b64encode(key.sign(reader.pae(kind, payload))).decode()}]}


def build_statement(plan, before, after, commitment, opened, sealed, reader):
    target = plan["path"]
    pred = {"intervalId": plan["intervalId"], "tier": "voluntary", "mutation": "observed",
            "hashAlgorithm": "sha256", "authorityDigest": plan["authorityDigest"],
            "codeDigest": {"sha256": plan["workloadSha256"]}, "issuedAt": sealed,
            "interval": {"beforeRoot": before, "afterRoot": after, "baseResolution": "supplied",
                         "openedAt": opened, "sealedAt": sealed}, "pathScope": [target],
            "observation": {"vantage": "peer", "origin": "log-import", "observedSigners": [],
                            "runtime": {"platform": "software-only"}, "priorCommitment": commitment,
                            "coverage": {"scopeComplete": False, "gaps": [target]}},
            "reads": [], "writes": [{"path": target, "preStateDigest": before,
                                       "postStateDigest": after, "inScope": True}],
            "dualValues": [], "doesNotAssert": LIMITS}
    return {"_type": "https://in-toto.io/Statement/v1", "predicateType": reader.PREDICATE_TYPE,
            "subject": [{"name": target, "digest": {"sha256": after}}], "predicate": pred}


def execute(packet: Path, binary: Path, revision: str):
    packet.mkdir(parents=True, exist_ok=False)
    source = (HERE / "source-pins.json").read_bytes()
    selection = strict_json(source)
    require(sha(binary.read_bytes()) == selection["binarySha256"], "binary-mismatch")
    target = (packet / "target.bin").resolve()
    target.write_bytes(b"before00\n")
    before = target.read_bytes()
    (packet / "before.bin").write_bytes(before)
    key = Ed25519PrivateKey.generate()
    authority = {"operator": "Probity", "permittedOperation": "one nine-byte overwrite",
                 "path": str(target), "expectedBeforeSha256": sha(before),
                 "expectedAfterSha256": sha(b"updated1\n"), "scope": "same-operator native test"}
    write_json(packet / "authority.json", authority)
    plan = {"profile": "execsurface-single-write-v1", "sourceRevision": revision,
            "intervalId": os.urandom(16).hex(), "path": str(target),
            "authorityDigest": sha((packet / "authority.json").read_bytes()),
            "workloadSha256": sha((HERE / "workload.py").read_bytes()),
            "binarySha256": selection["binarySha256"], "interpreterSha256": sha(Path(sys.executable).read_bytes()),
            "command": [str(binary.resolve()), "observe", "--", sys.executable,
                        str((HERE / "workload.py").resolve()), str(target)]}
    write_json(packet / "plan.json", plan)
    commitment_body = {"authorityDigest": plan["authorityDigest"],
                       "beforeRoot": state_root(str(target), before), "intervalId": plan["intervalId"],
                       "witnessNonce": os.urandom(16).hex()}
    commitment = {"committedAt": now(), "witnessNonce": commitment_body["witnessNonce"],
                  "commitmentDigest": sha(encode(commitment_body)),
                  "keyid": key.public_key().public_bytes_raw().hex(), "sig": key.sign(encode(commitment_body)).hex()}
    write_json(packet / "commitment.json", commitment)
    opened = advance(commitment["committedAt"])
    result = subprocess.run(plan["command"], capture_output=True, timeout=30)
    (packet / "observation.json").write_bytes(result.stdout)
    (packet / "observation.stderr").write_bytes(result.stderr)
    write_json(packet / "invocation.json", {"returncode": result.returncode})
    after = target.read_bytes()
    (packet / "after.bin").write_bytes(after)
    sealed = advance(opened)
    pins = {"sourcePinsSha256": sha(source), "planSha256": sha((packet / "plan.json").read_bytes()),
            "observerPublicKey": key.public_key().public_bytes_raw().hex()}
    reader, _ = selected_reader(pins)
    statement = build_statement(plan, state_root(str(target), before), state_root(str(target), after),
                                commitment, opened, sealed, reader)
    write_json(packet / "statement.json", statement)
    write_json(packet / "envelope.json", signed_statement(statement, key, reader))
    calibrate(packet, plan, sealed)
    files = [p for p in packet.iterdir() if p.is_file() and p.name != "target.bin"]
    write_json(packet / "manifest.json", {p.name: sha(p.read_bytes()) for p in files})
    pins["manifestSha256"] = sha((packet / "manifest.json").read_bytes())
    return pins


def calibrate(packet, plan, sealed):
    """Separate post-interval learn/check executions; never extend the claimed interval."""
    policy = packet / "producer-policy.json"
    write_json(policy, {"schema_version": 1, "default_action": "review", "rules": []})
    binary, _, _, *command = plan["command"]
    baseline = packet / "producer-baseline.json"
    calls = {"learn": [binary, "learn", "--output", str(baseline), "--", *command],
             "check": [binary, "check", "--baseline", str(baseline), "--policy", str(policy),
                       "--json-output", str(packet / "producer-comparison.json"), "--", *command]}
    outcomes = {}
    for name, args in calls.items():
        result = subprocess.run(args, capture_output=True, timeout=30)
        (packet / (name + ".stdout")).write_bytes(result.stdout)
        (packet / (name + ".stderr")).write_bytes(result.stderr)
        outcomes[name] = {"command": args, "returncode": result.returncode}
    write_json(packet / "calibration.json", {"outsideClaimedInterval": True,
                "claimedIntervalSealedAt": sealed, "calls": outcomes,
                "note": "two additional declared same-byte writes for producer baseline comparison"})
    require(outcomes["learn"]["returncode"] == 0 and outcomes["check"]["returncode"] == 0,
            "producer-calibration-failed")


def pinned_files(packet, pins):
    raw = (packet / "manifest.json").read_bytes()
    require(sha(raw) == pins["manifestSha256"], "manifest-mismatch")
    manifest = strict_json(raw)
    require(set(manifest) == PACKET_FILES, "packet-file-set")
    for name, digest in manifest.items():
        path = packet / name
        require(path.is_file() and not path.is_symlink(), "packet-file-boundary")
        require(path.stat().st_size <= 5 * 1024 * 1024, "packet-file-budget")
        require(sha(path.read_bytes()) == digest, "packet-bytes-mismatch")
    require(sha((packet / "plan.json").read_bytes()) == pins["planSha256"], "plan-mismatch")
    return manifest


def joined_statement(packet, plan, observation):
    require(type(observation["schema_version"]) is int and observation["schema_version"] == 2
            and type(observation["complete"]) is bool, "trace-schema")
    require(observation["complete"] is True and observation["warnings"] == [], "native-capture-incomplete")
    require(type(observation["outcome"]["exit_code"]) is int
            and observation["outcome"] == {"exit_code": 0, "signal": None}, "native-workload-failed")
    invocation = strict_json((packet / "invocation.json").read_bytes())
    require(type(invocation["returncode"]) is int and invocation == {"returncode": 0}, "native-invocation-failed")
    sequences = [e["sequence"] for e in observation["events"]]
    require(all(type(n) is int and n > 0 for n in sequences)
            and sequences == sorted(set(sequences)), "trace-order")
    rows = [e for e in observation["events"] if e.get("event_type") == "file_descriptor_access"
            and e.get("operation") == "write" and e.get("path") == plan["path"]]
    require(len(rows) == 1, "declared-write-not-single")
    process_binding(plan, observation, rows[0])
    before = (packet / "before.bin").read_bytes()
    after = (packet / "after.bin").read_bytes()
    authority = strict_json((packet / "authority.json").read_bytes())
    require(sha((packet / "authority.json").read_bytes()) == plan["authorityDigest"], "authority-join")
    require(authority["path"] == plan["path"] and authority["expectedBeforeSha256"] == sha(before)
            and authority["expectedAfterSha256"] == sha(after) and before == b"before00\n"
            and after == b"updated1\n", "state-authority-join")
    statement = strict_json((packet / "statement.json").read_bytes())
    pred = statement["predicate"]
    require(pred["interval"]["beforeRoot"] == state_root(plan["path"], before)
            and pred["interval"]["afterRoot"] == state_root(plan["path"], after), "snapshot-root-join")
    require(pred["authorityDigest"] == plan["authorityDigest"] and pred["intervalId"] == plan["intervalId"], "interval-plan-join")
    require(pred["pathScope"] == [plan["path"]] and pred["writes"] == [{"path": plan["path"],
            "preStateDigest": pred["interval"]["beforeRoot"], "postStateDigest": pred["interval"]["afterRoot"],
            "inScope": True}] and pred["reads"] == [], "state-write-join")
    require(pred["doesNotAssert"] == LIMITS, "scope-limit-join")
    require(pred["observation"]["priorCommitment"] == strict_json((packet / "commitment.json").read_bytes()), "prior-commitment-join")
    require(pred["observation"]["coverage"] == {"scopeComplete": False, "gaps": [plan["path"]]}, "health-mapping-gap")
    require(pred["observation"]["origin"] == "log-import" and pred["observation"]["vantage"] == "peer"
            and pred["tier"] == "voluntary", "import-authority-promotion")
    return statement


def process_binding(plan, observation, write):
    command = plan["command"]
    require(len(command) == 6 and command[1:3] == ["observe", "--"]
            and command[5] == plan["path"] and Path(command[4]).name == "workload.py", "declared-command-shape")
    execs = [e for e in observation["events"] if e["event_type"] == "process_exec"]
    require(len(execs) == 1 and execs[0]["path"] == command[3], "root-executable-join")
    require(type(write["tid"]) is int and write["tid"] == execs[0]["tid"], "write-process-join")
    reads = [e for e in observation["events"] if e.get("event_type") == "file_descriptor_access"
             and e.get("operation") == "read" and e.get("path") == command[4]
             and e["tid"] == write["tid"] and execs[0]["sequence"] < e["sequence"] < write["sequence"]]
    require(bool(reads), "workload-read-join")


def publication_gate(report, policy):
    require(set(policy) == {"profile", "requiredTier", "requiredTypedHealth"}, "publication-policy-shape")
    require(policy["profile"] == "probity-execsurface-state-v0" and policy["requiredTier"] in
            {"voluntary", "authoritative"} and type(policy["requiredTypedHealth"]) is bool,
            "publication-policy-value")
    if policy["requiredTier"] != report["tier"]:
        return {"publish": False, "reason": "selected-tier-not-established", "evidenceValid": True}
    if policy["requiredTypedHealth"]:
        return {"publish": False, "reason": "typed-health-not-established", "evidenceValid": True}
    return {"publish": True, "reason": "selected-limited-evidence-established", "evidenceValid": True}


def read_packet(packet: Path, pins):
    reader, selection = selected_reader(pins)
    manifest = pinned_files(packet, pins)
    plan = strict_json((packet / "plan.json").read_bytes())
    require(plan["binarySha256"] == selection["binarySha256"], "plan-binary-join")
    require(plan["workloadSha256"] == sha((HERE / "workload.py").read_bytes()), "workload-source-join")
    observation = strict_json((packet / "observation.json").read_bytes())
    statement = joined_statement(packet, plan, observation)
    raw = (packet / "envelope.json").read_bytes()
    envelope = strict_json(raw)
    require(strict_json(base64.b64decode(envelope["payload"], validate=True)) == statement, "envelope-statement-join")
    verdict, codes = reader.verify(raw, pins["observerPublicKey"], expected_code_digest=plan["workloadSha256"])
    require(verdict == "valid", "predicate:" + ",".join(codes))
    producer = read_comparison(packet, statement)
    return {"profile": "probity-execsurface-state-v0", "evidenceValid": True,
            "predicateVerdict": verdict, "tier": "voluntary", "origin": "log-import",
            "nativeComplete": observation["complete"], "nativeWarnings": observation["warnings"],
            "nativeOutcome": observation["outcome"], "backend": observation["backend"],
            "collectionHealth": "unknown-no-typed-envelope", "scopeComplete": False,
            "gaps": [plan["path"]], "stateRootAlgorithm": "probity-single-file-state-v1",
            "afterRoot": statement["predicate"]["interval"]["afterRoot"], "carriedWrites": 1,
            "nativeWriteByteCount": "not-carried-in-schema-v2", "companionAfterBytes": 9,
            "successfulWriteBinding": "source-pinned-positive-byte-fd-event-and-separate-snapshot",
            "producerDriftVerdict": producer["verdict"], "producerComparisonOutsideInterval": True,
            "producerComparison": producer, "manifestSha256": pins["manifestSha256"],
            "retainedFiles": len(manifest), "doesNotAssert": LIMITS}


def read_comparison(packet, statement):
    calibration = strict_json((packet / "calibration.json").read_bytes())
    require(calibration["outsideClaimedInterval"] is True and calibration["claimedIntervalSealedAt"] ==
            statement["predicate"]["interval"]["sealedAt"], "calibration-interval-join")
    require(all(type(calibration["calls"][n]["returncode"]) is int and
                calibration["calls"][n]["returncode"] == 0 for n in ["learn", "check"]), "calibration-outcome")
    result = strict_json((packet / "producer-comparison.json").read_bytes())
    require(result["schema_version"] == 2 and result["verdict"] == "pass" and
            result["target"] == {"exit_code": 0, "signal": None} and result["error"] is None,
            "producer-comparison-result")
    policy = strict_json((packet / "producer-policy.json").read_bytes())
    require(policy == {"schema_version": 1, "default_action": "review", "rules": []}, "producer-policy-join")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("packet", type=Path)
    run.add_argument("--binary", type=Path, required=True)
    run.add_argument("--source-revision", required=True)
    run.add_argument("--write-pins", type=Path, required=True)
    read = commands.add_parser("read")
    read.add_argument("packet", type=Path)
    read.add_argument("--pins-file", type=Path, required=True)
    read.add_argument("--policy-file", type=Path)
    read.add_argument("--policy-sha256")
    args = parser.parse_args()
    if args.command == "run":
        pins = execute(args.packet, args.binary, args.source_revision)
        write_json(args.write_pins, pins)
    else:
        require(not args.pins_file.resolve().is_relative_to(args.packet.resolve()), "pins-inside-packet")
        pins = strict_json(args.pins_file.read_bytes())
    report = read_packet(args.packet, pins)
    if args.command == "read" and args.policy_file:
        require(not args.policy_file.resolve().is_relative_to(args.packet.resolve()), "policy-inside-packet")
        raw = args.policy_file.read_bytes()
        require(args.policy_sha256 and sha(raw) == args.policy_sha256, "selected-policy-mismatch")
        report["publication"] = publication_gate(report, strict_json(raw))
    print(json.dumps(report, sort_keys=True))
    if "publication" in report and not report["publication"]["publish"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
