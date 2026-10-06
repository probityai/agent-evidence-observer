"""Run real protected effects with separate job-owned keys, processes and stores."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from probity_observer.authorization import ActionRequest, GrantPolicy
from probity_observer.broker import tree_root
from probity_observer.crypto import SigningKey, canonical, strict_loads
from probity_witness_operator.protocol import FORMAT as NATIVE_FORMAT, request_bytes as native_request, require, sha

from .protocol import FORMAT, request_bytes as authorization_request
from .worker import BUNDLE_FILES

UIDS = {"issuer": 65529, "gateway": 65530, "witness": 65531, "consumer": 65533, "workload": 65534}
CONTENT = b"one permitted operator effect\n"


def _drop(uid: int) -> None:
    """Use a job-local kernel identity without creating shared users or groups."""
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)


def _owned_directory(path: Path, uid: int, mode: int = 0o700) -> None:
    """Create one fresh role directory with explicit owner and permissions."""
    path.mkdir(mode=mode)
    os.chown(path, uid, uid)
    path.chmod(mode)


def _owned_file(path: Path, raw: bytes, uid: int, mode: int = 0o600) -> None:
    """Create fresh job bytes exclusively under the selected role owner."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
    os.chown(path, uid, uid)
    path.chmod(mode)


def _private_key(path: Path, uid: int) -> str:
    """Bootstrap fresh job keys with explicit custody; never emit secret bytes."""
    key = SigningKey.generate()
    raw = key.private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    _owned_file(path, raw, uid)
    return key.public_hex


@dataclass
class Run:
    """Keep full original process outputs before deriving a bounded result."""

    output: Path
    python: dict[str, str]
    sequence: int = 0

    def launch(self, argv: list[str], uid: int, raw_input: bytes | None = None) -> subprocess.Popen[bytes]:
        """Retain exact input before starting an isolated role with finite output pipes."""
        self.sequence += 1
        tag = f"{self.sequence:04d}"
        if raw_input is not None:
            (self.output / "inputs" / (tag + ".json")).write_bytes(raw_input)
        environment = {name: os.environ[name] for name in ("PATH", "LANG", "LC_ALL", "BOX_RUN_JOB", "WORKSTATION_HEAVY_GATE_HOLDER") if name in os.environ}
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=lambda: _drop(uid), env=environment)
        process.capture_tag = tag
        process.selected_uid = uid
        process.selected_environment = environment
        return process

    def capture(self, process: subprocess.Popen[bytes]) -> dict[str, Any]:
        """Save both original output streams and the final status before parsing."""
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
        tag = process.capture_tag
        (self.output / "processes" / (tag + ".stdout.original")).write_bytes(stdout)
        (self.output / "processes" / (tag + ".stderr.original")).write_bytes(stderr)
        value = {"argv": process.args, "pid": process.pid, "selectedUid": process.selected_uid, "selectedGid": process.selected_uid, "environment": process.selected_environment, "returncode": process.returncode, "timedOut": timed_out, "stdoutSha256": sha(stdout), "stderrSha256": sha(stderr), "capture": tag}
        with (self.output / "process-results.jsonl").open("ab") as stream:
            stream.write(canonical(value) + b"\n")
        return {**value, "value": strict_loads(stdout) if stdout else None}

    def stop(self, process: subprocess.Popen[bytes]) -> dict[str, Any]:
        """Stop an owned live process and retain its actual exit and output."""
        if process.poll() is None:
            process.terminate()
        return self.capture(process)


@dataclass
class Case:
    """One exact action; authoritative and consumer stores have different owners."""

    name: str
    root: Path
    output: Path
    run: Run
    dispatch: dict[str, Any]
    native_configuration: Path
    authorization_configuration: Path
    native_retained: Path
    authorization_retained: Path
    native_head: dict[str, Any]
    authorization_checkpoint: dict[str, Any]
    grant: dict[str, Any]
    processes: dict[str, subprocess.Popen[bytes]] = field(default_factory=dict)
    config_sequence: int = 0

    @property
    def workspace(self) -> Path:
        """Return the gateway-owned target tree for this one logical action."""
        return self.root / "gateway/work"

    @property
    def state(self) -> Path:
        """Return the gateway's durable journal and result directory."""
        return self.root / "gateway/state"

    def command(self, role: str, config: dict[str, Any], operation: str = "run", uid: int | None = None) -> subprocess.Popen[bytes]:
        """Freeze host input and select an installed role environment and kernel UID."""
        self.config_sequence += 1
        path = self.root / "inputs" / f"{self.config_sequence:04d}.json"
        raw = canonical(config)
        path.write_bytes(raw)
        path.chmod(0o644)
        owner = "witness" if role in {"native-witness", "authorization-witness", "fork"} else "consumer" if role == "check-fork" else "workload" if role in {"probe", "peer-probe"} else role
        uid = UIDS[owner] if uid is None else uid
        python = self.run.python[owner]
        argv = [python, "-I", "-B", "-m", "probity_protected_operator.worker", role, "--operation", operation, "--config", str(path), "--config-sha256", sha(raw)]
        return self.run.launch(argv, uid, raw)

    def execute(self, role: str, config: dict[str, Any], operation: str = "run", uid: int | None = None) -> dict[str, Any]:
        """Run and capture one finite role action before continuing the dependency graph."""
        return self.run.capture(self.command(role, config, operation, uid))


def _wait(path: Path, process: subprocess.Popen[bytes]) -> None:
    """Wait for a fresh private bind acknowledgment, never a stale socket path."""
    end = time.monotonic() + 15
    while not path.exists():
        require(process.poll() is None and time.monotonic() < end, "operator endpoint did not start")
        time.sleep(0.02)
    ready = strict_loads(path.read_bytes())
    require(ready["pid"] == process.pid and ready["uid"] == process.selected_uid, "operator bind acknowledgment differs")


def _cli(case: Case, kind: str, command: str) -> dict[str, Any]:
    """Use installed witness commands under exact external configuration/head pins."""
    path = case.native_configuration if kind == "native" else case.authorization_configuration
    module = "probity_witness_operator.cli" if kind == "native" else "probity_protected_operator.cli"
    argv = [case.run.python["witness"], "-I", "-B", "-m", module, command, "--config", str(path), "--config-sha256", sha(path.read_bytes())]
    if command != "init":
        retained = case.native_retained if kind == "native" else case.authorization_retained
        flag = "--retained-head" if kind == "native" else "--retained-checkpoint"
        argv.extend([flag, str(retained), "--retained-sha256", sha(retained.read_bytes())])
    return case.run.capture(case.run.launch(argv, UIDS["witness"], path.read_bytes()))


def _create(run: Run, runtime: Path, name: str) -> Case:
    """Bootstrap fresh key/store owners and obtain an actual issuer grant."""
    root = runtime / name
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    output = run.output / "cases" / name
    output.mkdir()
    output.chmod(0o755)
    for directory in ("target-readbacks", "wire-replies"):
        (output / directory).mkdir()
        (output / directory).chmod(0o755)
    for role, uid in UIDS.items():
        _owned_directory(root / role, uid)
    (root / "inputs").mkdir(mode=0o755)
    (root / "inputs").chmod(0o755)
    _owned_directory(root / "witness-endpoints", UIDS["witness"], 0o755)
    _owned_directory(root / "gateway-endpoint", UIDS["gateway"], 0o755)
    _owned_directory(root / "gateway/work", UIDS["gateway"])
    issuer = _private_key(root / "issuer/key.raw", UIDS["issuer"])
    observer = _private_key(root / "gateway/key.raw", UIDS["gateway"])
    witness = _private_key(root / "witness/key.raw", UIDS["witness"])
    request = ActionRequest("operator-" + name, "attempt-1", "effect-1", "tenant-selected", "principal-selected", "file-write", "/work/result.txt", sha(CONTENT))
    dispatch = {"request": asdict(request), "policy": asdict(GrantPolicy(issuer)), "observerKey": observer, "witnessKey": witness, "executionDigest": None}
    native_path = root / "witness/native-config.json"
    auth_path = root / "witness/authorization-config.json"
    native = {"format": NATIVE_FORMAT, "keyPath": str(root / "witness/key.raw"), "storePath": str(root / "witness/native-state"), "socketPath": str(root / "witness-endpoints/native.sock"), "observerKey": observer, "witnessKey": witness, "clientUid": UIDS["gateway"]}
    authorization = {"format": FORMAT, "keyPath": native["keyPath"], "storePath": str(root / "witness/authorization-state"), "socketPath": str(root / "witness-endpoints/authorization.sock"), "clientUid": UIDS["gateway"], "dispatchConfiguration": dispatch, "beforeRoot": tree_root(root / "gateway/work")}
    _owned_file(native_path, canonical(native), UIDS["witness"])
    _owned_file(auth_path, canonical(authorization), UIDS["witness"])
    case = Case(name, root, output, run, dispatch, native_path, auth_path, root / "witness/native-retained.json", root / "witness/authorization-retained.json", {}, {}, {})
    native_initial, auth_initial = _cli(case, "native", "init"), _cli(case, "authorization", "init")
    require(native_initial["returncode"] == auth_initial["returncode"] == 0, "explicit witness initialization failed")
    case.native_head, case.authorization_checkpoint = native_initial["value"], auth_initial["value"]
    _owned_file(case.native_retained, canonical(case.native_head), UIDS["witness"])
    _owned_file(case.authorization_retained, canonical(case.authorization_checkpoint), UIDS["witness"])
    issued = case.execute("issuer", {"keyPath": str(root / "issuer/key.raw"), "issuerKey": issuer, "request": asdict(request)})
    require(issued["returncode"] == 0, "issuer process did not create grant")
    case.grant = issued["value"]["grant"]
    (output / "host-selection.json").write_bytes(canonical({"dispatchConfiguration": dispatch, "beforeRoot": authorization["beforeRoot"], "initialNativeHead": case.native_head, "initialAuthorizationCheckpoint": case.authorization_checkpoint, "roleUids": UIDS}))
    return case


def _witness(case: Case, kind: str, fault_count: int | None = None) -> None:
    """Start a selected private witness and wait for its fresh bind acknowledgment."""
    configuration = case.native_configuration if kind == "native" else case.authorization_configuration
    retained = case.native_retained if kind == "native" else case.authorization_retained
    endpoint = case.root / "witness-endpoints" / (kind + ".sock")
    ready = case.root / "witness" / f"ready-{case.config_sequence + 1}.json"
    config = {"configurationPath": str(configuration), "configurationSha256": sha(configuration.read_bytes()), "retainedPath": str(retained), "retainedSha256": sha(retained.read_bytes()), "faultCount": fault_count, "removeStaleSocket": endpoint.exists(), "readyPath": str(ready)}
    process = case.command(kind + "-witness", config, "serve")
    case.processes[kind] = process
    _wait(ready, process)


def _gateway_config(case: Case, fault: str | None = None) -> dict[str, Any]:
    """Select the exact gateway action, public witness clients and host-only fault."""
    return {"dispatchConfiguration": case.dispatch, "observerKeyPath": str(case.root / "gateway/key.raw"), "authorizationSocket": str(case.root / "witness-endpoints/authorization.sock"), "nativeSocket": str(case.root / "witness-endpoints/native.sock"), "witnessUid": UIDS["witness"], "authorizationCheckpoint": case.authorization_checkpoint, "nativeHead": case.native_head, "workspace": str(case.workspace), "stateDir": str(case.state), "gatewaySocket": str(case.root / "gateway-endpoint/action.sock"), "workloadUid": UIDS["workload"], "fault": fault, "removeStaleSocket": (case.root / "gateway-endpoint/action.sock").exists()}


def _gateway(case: Case, fault: str | None = None) -> None:
    """Start the gateway after both selected witness endpoints are ready."""
    ready = case.root / "gateway" / f"ready-{case.config_sequence + 1}.json"
    process = case.command("gateway", {**_gateway_config(case, fault), "readyPath": str(ready)}, "serve")
    case.processes["gateway"] = process
    _wait(ready, process)


def _consumer_config(case: Case) -> dict[str, Any]:
    """Select public policy and consumer-owned state outside the candidate bundle."""
    return {"dispatchConfiguration": case.dispatch, "authorizationCheckpoint": case.authorization_checkpoint, "nativeHead": case.native_head, "beforeRoot": strict_loads(case.authorization_configuration.read_bytes())["beforeRoot"], "statePath": str(case.root / "consumer/admission.json"), "retentionPath": str(case.root / "consumer/retention.json"), "bundle": str(case.output / "bundle"), "candidateHeads": str(case.output / "candidate-heads.json")}


def _bootstrap(case: Case, native: bool = True, auth_fault: int | None = None, native_fault: int | None = None) -> None:
    """Initialize gateway and consumer state before any workload effect."""
    _witness(case, "authorization", auth_fault)
    if native:
        _witness(case, "native", native_fault)
    initialized = case.execute("gateway", _gateway_config(case), "init")
    require(initialized["returncode"] == 0, "gateway explicit initialization failed")
    case.authorization_checkpoint = initialized["value"]["authorizationCheckpoint"]
    case.authorization_retained.write_bytes(canonical(case.authorization_checkpoint))
    consumer = case.execute("consumer", _consumer_config(case), "init")
    require(consumer["returncode"] == 0, "consumer explicit initialization failed")
    (case.output / "initial-outside-heads.json").write_bytes(canonical({"authorization": case.authorization_checkpoint, "native": case.native_head}))


def _invoke(case: Case, phase: str, candidate: dict[str, Any] | None = None, operation: str = "run", uid: int | None = None) -> dict[str, Any]:
    """Capture target, workload and raw reply outcomes before any qualification assertion."""
    before = _target_capture(case, phase + "-before")
    selected = candidate if candidate is not None else {"request": case.dispatch["request"], "grant": case.grant, "contentHex": CONTENT.hex()}
    result, failure, wire = None, None, None
    try:
        result = case.execute("workload", {"gatewaySocket": str(case.root / "gateway-endpoint/action.sock"), "candidate": selected}, operation, uid)
        value = result.get("value")
        if isinstance(value, dict) and isinstance(value.get("replyHex"), str):
            wire = case.output / "wire-replies" / (phase + ".bin")
            with wire.open("xb") as stream:
                stream.write(bytes.fromhex(value["replyHex"]))
    except BaseException as error:
        failure = repr(error)
        raise
    finally:
        after = _target_capture(case, phase + "-after")
        value = result.get("value") if result is not None else None
        response = value.get("response") if isinstance(value, dict) else None
        response_outcome = "unavailable"
        if isinstance(response, dict) and type(response.get("ok")) is bool:
            response_outcome = "accepted" if response["ok"] else "refused"
        elif isinstance(value, dict) and value.get("protocolError") is not None:
            response_outcome = "malformed"
        target_outcome = "unknown" if before.get("readError") or after.get("readError") else "unchanged" if before == after else "changed"
        record = {"phase": phase, "targetBefore": before, "targetAfter": after, "targetOutcome": target_outcome,
                  "workload": result, "workloadFailure": failure,
                  "workloadOutcome": "exception" if failure else "completed" if result["returncode"] == 0 else "failed",
                  "responseOutcome": response_outcome, "wirePath": str(wire.relative_to(case.output)) if wire else None}
        with (case.output / "action-attempts.jsonl").open("ab") as stream:
            stream.write(canonical(record) + b"\n")
    return {**result, "targetBefore": before, "targetAfter": after, "targetOutcome": target_outcome, "responseOutcome": response_outcome}


def _effect(case: Case) -> dict[str, Any]:
    """Read the actual local target bytes and inode through the bootstrap administrator."""
    path = case.workspace / "result.txt"
    if not path.exists():
        return {"exists": False}
    metadata = path.stat()
    raw = path.read_bytes()
    return {"exists": True, "sha256": sha(raw), "bytesHex": raw.hex(), "inode": metadata.st_ino, "bytes": len(raw)}


def _target_capture(case: Case, phase: str) -> dict[str, Any]:
    """Retain an actual target read, or its actual read failure, before synthesis."""
    try:
        value = _effect(case)
    except OSError as error:
        value = {"readError": repr(error)}
    with (case.output / "target-readbacks" / (phase + ".json")).open("xb") as stream:
        stream.write(canonical(value))
    return value


def _bundle(case: Case, name: str = "bundle") -> None:
    """Copy existing public proof files and retain an actual target read-back."""
    target = case.output / name
    target.mkdir()
    target.chmod(0o755)
    for selected in BUNDLE_FILES:
        path = case.state / selected
        if path.exists():
            (target / selected).write_bytes(path.read_bytes())
            (target / selected).chmod(0o644)
    (target / "actual-target-readback.json").write_bytes(canonical(_effect(case)))


def _heads(case: Case) -> dict[str, Any]:
    """Retain complete public witness exports through the separate host channel."""
    native, authorization = _cli(case, "native", "export"), _cli(case, "authorization", "export")
    require(native["returncode"] == authorization["returncode"] == 0, "host could not acquire current public heads")
    directory = case.output / "witness-exports"
    directory.mkdir(exist_ok=True)
    directory.chmod(0o755)
    for result, field, name in ((native, "ledgerHex", "native-ledger.jsonl"), (authorization, "historyHex", "authorization.jsonl")):
        path = directory / (result["capture"] + "-" + name)
        path.write_bytes(bytes.fromhex(result["value"][field]))
        path.chmod(0o644)
    case.native_head, case.authorization_checkpoint = native["value"]["head"], authorization["value"]["checkpoint"]
    return {"authorization": case.authorization_checkpoint, "native": case.native_head}


def _consumer_capture(case: Case, phase: str) -> dict[str, str]:
    """Retain exact public fixture retention/admission state without a role key."""
    hashes = {}
    for name in ("retention.json", "admission.json"):
        raw = (case.root / "consumer" / name).read_bytes()
        path = case.output / ("consumer-" + phase + "-" + name)
        path.write_bytes(raw)
        path.chmod(0o644)
        hashes[name] = sha(raw)
    return hashes


def _stop(case: Case, selected: str | None = None) -> list[dict[str, Any]]:
    """Close only this case's owned service processes, retaining every final status."""
    result = []
    for name in list(case.processes):
        if selected is None or name == selected:
            result.append(case.run.stop(case.processes.pop(name)))
    return result


def _probes(case: Case) -> list[dict[str, Any]]:
    """Check real forbidden key/store reads under all five selected identities."""
    paths = {"issuerKey": str(case.root / "issuer/key.raw"), "observerKey": str(case.root / "gateway/key.raw"), "witnessKey": str(case.root / "witness/key.raw"), "gatewayState": str(case.state / "dispatch-state.json"), "nativeStore": str(case.root / "witness/native-state/ledger.jsonl"), "authorizationStore": str(case.root / "witness/authorization-state/state.json"), "consumerState": str(case.root / "consumer/admission.json")}
    excluded = {"issuer": {"issuerKey"}, "gateway": {"observerKey", "gatewayState"}, "witness": {"witnessKey", "nativeStore", "authorizationStore"}, "consumer": {"consumerState"}, "workload": set()}
    results = []
    for role, uid in UIDS.items():
        config = {"deniedPaths": {name: path for name, path in paths.items() if name not in excluded[role]}}
        process = case.command("probe", config, uid=uid)
        result = case.run.capture(process)
        require(result["returncode"] == 0, "actual role key/store denial failed")
        results.append({"selectedRole": role, **result})
    return results


def _refusal_controls(case: Case) -> list[dict[str, Any]]:
    """Send altered approvals/actions and a wrong peer before the target exists."""
    base = {"request": case.dispatch["request"], "grant": case.grant, "contentHex": CONTENT.hex()}
    controls = []
    for field in ("tenant_id", "principal_id", "tool_id", "request_id", "content_sha256"):
        request = {**base["request"], field: "0" * 64 if field == "content_sha256" else "different"}
        result = _invoke(case, "wrong-" + field, {**base, "request": request})
        require(result["returncode"] == 0, "wrong-action workload process failed")
        require(result["responseOutcome"] == "refused", "wrong-action gateway response was not a valid refusal")
        require(result["targetBefore"].get("exists") is False and result["targetAfter"].get("exists") is False, "wrong action target was not observed absent before and after")
        controls.append({"control": "wrong-" + field, **result})
    for name, candidate in (("wrong-issuer-key", {**base, "grant": {**case.grant, "issuerKey": "0" * 64}}), ("changed-content", {**base, "contentHex": b"changed".hex()})):
        result = _invoke(case, name, candidate)
        require(result["returncode"] == 0, "wrong-grant/content workload process failed")
        require(result["responseOutcome"] == "refused", "wrong-grant/content gateway response was not a valid refusal")
        require(result["targetBefore"].get("exists") is False and result["targetAfter"].get("exists") is False, "wrong grant/content target was not observed absent before and after")
        controls.append({"control": name, **result})
    wrong_peer = _invoke(case, "wrong-gateway-peer", uid=UIDS["consumer"])
    require(wrong_peer["returncode"] == 0 and wrong_peer["responseOutcome"] == "unavailable", "wrong kernel peer received an action response")
    require(wrong_peer["targetBefore"].get("exists") is False and wrong_peer["targetAfter"].get("exists") is False, "wrong kernel peer target was not observed absent before and after")
    controls.append({"control": "wrong-gateway-peer", **wrong_peer})
    return controls


def _happy(case: Case) -> dict[str, Any]:
    """Check actual completion, custody mechanics, retained admission and safe restart."""
    _bootstrap(case)
    probes = _probes(case)
    _gateway(case)
    refusals = _refusal_controls(case)
    accepted = _invoke(case, "permitted")
    require(accepted["value"]["response"]["ok"] is True and accepted["value"]["response"]["replayed"] is False, "permitted action did not complete")
    target = accepted["targetAfter"]
    require(target["exists"] and target["sha256"] == sha(CONTENT), "actual target bytes differ")
    witness_peers = []
    before_heads = _heads(case)
    for kind, request in (("native", native_request("checkpoint", (case.state / "history.jsonl").read_bytes())), ("authorization", authorization_request("checkpoint", (case.state / "authorization.jsonl").read_bytes()))):
        before_target = _target_capture(case, kind + "-wrong-peer-before")
        probe = case.execute("peer-probe", {"socketPath": str(case.root / "witness-endpoints" / (kind + ".sock")), "serverUid": UIDS["witness"], "requestHex": request.hex()})
        after_target = _target_capture(case, kind + "-wrong-peer-after")
        after_heads = _heads(case)
        record = {"service": kind, **probe, "headsBefore": before_heads, "headsAfter": after_heads, "targetBefore": before_target, "targetAfter": after_target}
        with (case.output / "wrong-witness-peers.jsonl").open("ab") as stream:
            stream.write(canonical(record) + b"\n")
        require(probe["returncode"] == 0, "wrong-witness-peer workload probe failed")
        require(after_heads == before_heads, "wrong witness peer changed retained heads")
        require(before_target == after_target == target, "wrong witness peer changed the target")
        witness_peers.append(record)
    duplicate = _invoke(case, "duplicate")
    require(duplicate["value"]["response"]["replayed"] is True and duplicate["targetAfter"] == target, "duplicate changed target")
    second = case.execute("issuer", {"keyPath": str(case.root / "issuer/key.raw"), "issuerKey": case.dispatch["policy"]["issuer_key"], "request": case.dispatch["request"], "validitySeconds": 239})
    require(second["returncode"] == 0 and second["value"]["grant"] != case.grant, "second valid grant control did not differ")
    second_grant = _invoke(case, "second-grant", {"request": case.dispatch["request"], "grant": second["value"]["grant"], "contentHex": CONTENT.hex()})
    require(second_grant["value"]["response"]["ok"] is False and second_grant["targetAfter"] == target, "different valid grant repeated one logical effect")
    lost_ack = _invoke(case, "lost-acknowledgment", operation="lost-ack")
    require(lost_ack["value"]["acknowledged"] is False, "client acknowledged lost-reply control")
    _stop(case, "gateway")
    _bundle(case)
    heads = _heads(case)
    (case.output / "candidate-heads.json").write_bytes(canonical(heads))
    (case.output / "candidate-heads.json").chmod(0o644)
    retained = case.execute("consumer", _consumer_config(case), "retain")
    require(retained["returncode"] == 0, "consumer did not retain separately acquired heads")
    wrong_policy = _consumer_config(case)
    wrong_policy["dispatchConfiguration"] = {**case.dispatch, "policy": {**case.dispatch["policy"], "issuer_key": "0" * 64}}
    consumer_before = _consumer_capture(case, "before-policy-control")
    refused_policy = case.execute("consumer", wrong_policy, "admit")
    require(refused_policy["returncode"] == 2, "wrong consumer policy admitted candidate")
    consumer_after_policy = _consumer_capture(case, "after-policy-control")
    require(consumer_after_policy == consumer_before, "wrong consumer policy changed state")
    admitted = case.execute("consumer", _consumer_config(case), "admit")
    consumer_admitted = _consumer_capture(case, "after-admission")
    replay = case.execute("consumer", _consumer_config(case), "admit")
    require(admitted["returncode"] == 0 and replay["returncode"] == 2, "consumer admission/replay result differs")
    consumer_after_replay = _consumer_capture(case, "after-replay-control")
    require(consumer_after_replay == consumer_admitted, "refused replay changed consumer state")
    case.native_retained.write_bytes(canonical(case.native_head))
    case.authorization_retained.write_bytes(canonical(case.authorization_checkpoint))
    _stop(case)
    _witness(case, "authorization")
    _witness(case, "native")
    _gateway(case)
    restarted = _invoke(case, "restart")
    require(restarted["value"]["response"]["replayed"] is True and restarted["targetAfter"] == target, "restart changed target effect")
    _stop(case)
    faults = _store_controls(case)
    fork = _signed_fork(case)
    return {"permitted": accepted, "duplicate": duplicate, "secondGrantIssued": second, "secondGrantRefused": second_grant, "lostAcknowledgment": lost_ack, "restart": restarted, "refusals": refusals, "accessDenials": probes, "wrongWitnessPeers": witness_peers, "consumerRetention": retained, "consumerWrongPolicy": refused_policy, "consumerAdmission": admitted, "consumerReplay": replay, "consumerStateSha256": {"beforePolicyControl": consumer_before, "afterPolicyControl": consumer_after_policy, "afterAdmission": consumer_admitted, "afterReplayControl": consumer_after_replay}, "target": target, "storeControls": faults, "signedFork": fork}


def _wait_completed(case: Case) -> None:
    """Observe durable local completion after the first workload closes its reply."""
    deadline = time.monotonic() + 15
    while strict_loads((case.state / "dispatch-state.json").read_bytes())["payload"]["phase"] != "complete":
        require(case.processes["gateway"].poll() is None, "gateway exited before lost-reply completion")
        require(time.monotonic() < deadline, "lost workload reply did not complete")
        time.sleep(0.01)


def _first_reply_lost(case: Case) -> dict[str, Any]:
    """Lose the first permitted reply, then qualify the real retained completion."""
    _bootstrap(case)
    _gateway(case)
    lost = _invoke(case, "first-lost-reply", operation="lost-ack")
    require(lost["returncode"] == 0 and lost["value"]["acknowledged"] is False, "first workload reply was acknowledged")
    _wait_completed(case)
    target = _target_capture(case, "first-lost-reply-completed")
    require(target["exists"] and target["sha256"] == sha(CONTENT), "lost first reply target bytes differ")
    _stop(case, "gateway")
    _bundle(case)
    heads = _heads(case)
    (case.output / "candidate-heads.json").write_bytes(canonical(heads))
    retained = case.execute("consumer", _consumer_config(case), "retain")
    admitted = case.execute("consumer", _consumer_config(case), "admit")
    require(retained["returncode"] == admitted["returncode"] == 0, "lost first reply lacked complete consumer evidence")
    consumer = _consumer_capture(case, "after-admission")
    case.native_retained.write_bytes(canonical(case.native_head))
    case.authorization_retained.write_bytes(canonical(case.authorization_checkpoint))
    _stop(case)
    _witness(case, "authorization")
    _witness(case, "native")
    _gateway(case)
    replay = _invoke(case, "first-lost-reply-restart")
    require(replay["value"]["response"]["ok"] is True and replay["value"]["response"]["replayed"] is True, "lost first reply restart did not replay completion")
    require(replay["targetAfter"] == target, "lost first reply restart repeated target replacement")
    return {"lostFirstReply": lost, "consumerRetention": retained, "consumerAdmission": admitted,
            "consumerStateSha256": consumer, "restart": replay, "target": target, "targetAfterRestart": replay["targetAfter"], "heads": heads}


def _store_controls(case: Case) -> list[dict[str, Any]]:
    """Retain failed store/key outcomes before restoring exact fresh job-owned bytes."""
    results = []
    for kind, path in (("native", case.root / "witness/native-state/ledger.jsonl"), ("authorization", case.root / "witness/authorization-state/state.json")):
        saved = path.read_bytes()
        (case.output / (kind + "-store-before-controls.original")).write_bytes(saved)
        for control in ("missing", "truncated", "rollback"):
            if control == "missing":
                path.unlink()
            elif control == "truncated":
                path.write_bytes(saved[:-1])
            elif kind == "native":
                path.write_bytes(saved.splitlines(keepends=True)[0])
            else:
                value = strict_loads(saved)
                value["historyHex"] = ""
                value["checkpoint"] = strict_loads((case.output / "host-selection.json").read_bytes())["initialAuthorizationCheckpoint"]
                path.write_bytes(canonical(value))
            selected = path.read_bytes() if path.exists() else None
            if selected is not None:
                (case.output / (kind + "-store-" + control + ".original")).write_bytes(selected)
            result = _cli(case, kind, "head")
            require(result["returncode"] == 2, "witness accepted missing/truncated/rolled-back store")
            results.append({"service": kind, "control": control, "originalSha256": sha(saved),
                            "controlExists": selected is not None, "controlSha256": sha(selected) if selected is not None else None, **result})
            if not path.exists():
                _owned_file(path, saved, UIDS["witness"])
            else:
                path.write_bytes(saved)
            require(sha(path.read_bytes()) == sha(saved), "job-owned control restoration differs")
    key_path = case.root / "witness/key.raw"
    saved_key = key_path.read_bytes()
    key_path.write_bytes(b"0" * 32)
    for kind in ("native", "authorization"):
        result = _cli(case, kind, "head")
        require(result["returncode"] == 2, "witness accepted replacement private key")
        results.append({"service": kind, "control": "wrong-private-key", **result})
    key_path.write_bytes(saved_key)
    require(key_path.read_bytes() == saved_key, "fresh job key restoration differs")
    return results


def _signed_fork(case: Case) -> dict[str, Any]:
    """Separate valid alternate witness signatures from the held-prefix refusal."""
    signed = case.execute("fork", {"keyPath": str(case.root / "witness/key.raw"), "witnessKey": case.dispatch["witnessKey"], "ledgerPath": str(case.root / "witness/native-state/ledger.jsonl")})
    require(signed["returncode"] == 0, "witness could not sign diagnostic fork")
    path = case.output / "signed-fork.jsonl"
    path.write_bytes(bytes.fromhex(signed["value"]["ledgerHex"]))
    path.chmod(0o644)
    checked = case.execute("check-fork", {"forkPath": str(path), "witnessKey": case.dispatch["witnessKey"], "retentionPath": str(case.root / "consumer/retention.json")})
    require(checked["returncode"] == 0 and checked["value"]["signedReceiptsValid"] is True and checked["value"]["retainedPrefixRefused"] is True, "signed fork control differs")
    return {"signed": signed, "checked": checked}


def _interrupted(case: Case, auth_fault: int | None = None, native_fault: int | None = None, target_fault: str | None = None, native_available: bool = True) -> dict[str, Any]:
    """Check real process faults and preserve uncertain histories without repeating effects."""
    _bootstrap(case, native_available, auth_fault, native_fault)
    _gateway(case, target_fault)
    initial = _invoke(case, "interrupted-initial")
    target = initial["targetAfter"]
    expected_effect = target_fault == "after-target" or auth_fault == 3 or native_fault == 2
    require(target["exists"] is expected_effect, "interrupted target effect differs")
    stops = _stop(case)
    exits = [result["returncode"] for result in stops]
    if auth_fault is not None or native_fault is not None:
        require(73 in exits, "witness lost-ack process did not actually exit")
    if target_fault is not None:
        require(74 in exits, "gateway fault process did not actually exit")
    _bundle(case)
    heads = _heads(case)
    (case.output / "candidate-heads.json").write_bytes(canonical(heads))
    (case.output / "candidate-heads.json").chmod(0o644)
    consumer = case.execute("consumer", _consumer_config(case), "admit")
    require(consumer["returncode"] == 2, "consumer admitted an incomplete interrupted dispatch")
    case.native_retained.write_bytes(canonical(case.native_head))
    case.authorization_retained.write_bytes(canonical(case.authorization_checkpoint))
    _witness(case, "authorization")
    _witness(case, "native")
    _gateway(case)
    retry = _invoke(case, "interrupted-restart")
    require(retry["value"]["response"]["ok"] is False and retry["targetAfter"] == target, "interrupted restart repeated an effect")
    _stop(case)
    _bundle(case, "after-restart-bundle")
    return {"initial": initial, "processStops": stops, "consumerRefusal": consumer, "retry": retry, "target": target, "targetAfterRetry": retry["targetAfter"], "heads": heads, "automaticRecovery": "refused; operator review required"}


def run(output: Path, python: dict[str, str]) -> None:
    """Qualify the declared fixed controls; no deployment or prospective study is run."""
    require(os.getuid() == 0, "native operator qualification requires job-local root to select isolated UIDs")
    output.mkdir()
    output.chmod(0o755)
    for name in ("processes", "inputs", "cases"):
        (output / name).mkdir()
        (output / name).chmod(0o755)
    execution = Run(output, python)
    cases = {}
    with tempfile.TemporaryDirectory(prefix="ppa-") as temporary:
        runtime = Path(temporary)
        runtime.chmod(0o755)
        happy = _create(execution, runtime, "completion")
        try:
            cases["completion"] = _happy(happy)
            lost_reply = _create(execution, runtime, "first-workload-reply-lost")
            try:
                cases["first-workload-reply-lost"] = _first_reply_lost(lost_reply)
            finally:
                _stop(lost_reply)
            controls = {"authorization-lost-ack-before-effect": {"auth_fault": 2}, "authorization-lost-ack-after-effect": {"auth_fault": 3}, "native-lost-ack-before-effect": {"native_fault": 1}, "native-lost-ack-after-effect": {"native_fault": 2}, "target-crash-before-effect": {"target_fault": "before-target"}, "target-crash-after-effect": {"target_fault": "after-target"}, "native-unavailable-before-effect": {"native_available": False}}
            for name, settings in controls.items():
                case = _create(execution, runtime, name)
                try:
                    cases[name] = _interrupted(case, **settings)
                finally:
                    _stop(case)
        finally:
            _stop(happy)
    report = {"format": "probity-protected-operator-run-v0", "status": "passed", "cases": cases, "roleUids": UIDS, "witnessScope": "PEER", "evidenceVantage": "artifact", "outsideHumanOperators": 0, "actualSubstrate": "local-file-replacement", "doesNotAssert": ["independent-human-operation", "independent-custody", "target-truth-from-witness-signature", "clock-truth", "complete-unmediated-effects", "global-exactly-once", "provider-refund", "paid-customer", "service-SLA"]}
    (output / "report.json").write_bytes(canonical(report))
    print(canonical({"status": "passed", "cases": list(cases), "processes": execution.sequence, "outsideHumanOperators": 0}).decode())


def main() -> None:
    """Run the fixed native qualification from five explicitly selected installed environments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    for role in UIDS:
        parser.add_argument("--" + role + "-python", required=True)
    arguments = parser.parse_args()
    python = {role: getattr(arguments, role + "_python") for role in UIDS}
    run(arguments.output, python)


if __name__ == "__main__":
    main()
