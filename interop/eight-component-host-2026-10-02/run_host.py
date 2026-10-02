"""Execute the finite eight-component chain under external host selection.

All source, installed code, tool, policy and key bytes are selected before the
first child. The accepted Rust-returned AEE payload reaches installed Vectors,
pinned OPA, vocabulary, original Atlas validation and installed Verify. Only
then does a separate host issuer grant one exact installed Observer HTTP effect.
Every child stream, failure and native restart artifact is retained unchanged.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from trust import HostRefusal, read_json, refuse, sha256, validate_host, write_json

LOGGER = logging.getLogger("probity.eight_component.host")
SCENARIOS = ("completed", "after-intent", "inside-effect-transaction", "after-effect",
             "revoked-after", "expired-after", "rollback-after", "store-rollback")


def child_environment() -> dict[str, str]:
    """Select a finite child environment without candidate Python/loader hooks."""
    retained = ("PATH", "LANG", "LC_ALL", "SYSTEMROOT", "TMPDIR")
    return {key: os.environ[key] for key in retained if key in os.environ}


def run_child(command: list[str], output: Path, *, timeout: float = 20) -> dict[str, Any]:
    """Run a bounded selected child and retain exact streams on every outcome.

    Parameters
    ----------
    command : list[str]
        Explicit host-selected argument vector. Keys are file paths, never
        private seed values or candidate-selected executable commands.
    output : Path
        New child artifact prefix; stdout/stderr stay raw bytes.
    timeout : float, default=20
        Finite wall budget. Partial streams from an expired child are retained.

    Returns
    -------
    dict[str, Any]
        Command, actual exit code or timeout, elapsed seconds and stream hashes.
        No nonzero or incomplete child is converted to a successful gate.
    """
    started = time.monotonic()
    try:
        process = subprocess.run(command, capture_output=True, timeout=timeout, env=child_environment())
        stdout, stderr = process.stdout, process.stderr
        code, timed_out = process.returncode, False
    except subprocess.TimeoutExpired as error:
        stdout, stderr = error.stdout or b"", error.stderr or b""
        code, timed_out = None, True
    (output.with_suffix(".stdout")).write_bytes(stdout)
    (output.with_suffix(".stderr")).write_bytes(stderr)
    receipt = {"command": command, "returnCode": code, "timedOut": timed_out,
               "wallSeconds": round(time.monotonic() - started, 6),
               "stdoutSha256": sha256(stdout), "stderrSha256": sha256(stderr),
               "stdoutBytes": len(stdout), "stderrBytes": len(stderr)}
    write_json(output.with_suffix(".process.json"), receipt)
    return receipt


def require_child(receipt: dict[str, Any], reason: str) -> None:
    """Refuse a nonzero or timed-out child before parsing any optimistic output."""
    if receipt["timedOut"] or receipt["returnCode"] != 0:
        refuse(reason)


@dataclass
class HostRun:
    """A validated external selection and one new retained candidate snapshot.

    Parameters
    ----------
    manifest : dict[str, Any]
        Result of :func:`trust.validate_host` before any subprocess starts.
    root : Path
        New scratch/output directory containing public run data only.

    Notes
    -----
    Native target control files retain host-selected seed paths but never seed
    bytes. Raw artifact upload excludes these control files and installation
    manifests because private keys stay in the separate external host folder.
    """

    manifest: dict[str, Any]
    root: Path
    children: int = 0
    dispatches: int = 0
    gates: list[dict[str, Any]] = field(default_factory=list)

    @property
    def python(self) -> str:
        """Use the selected normal installation environment, retaining its venv."""
        selected = self.manifest["python"]
        return selected.get("invocationPath", selected["path"])

    @property
    def policy(self) -> dict[str, Any]:
        """Read previously authenticated host policy from its protected path."""
        return read_json(Path(self.manifest["policy"]["path"]))

    def native(self, operation: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        """Launch one installed gate with its frozen explicit host configuration."""
        config = {"sources": self.manifest["sources"], "run": str(self.root),
                  "payload": str(self.root / "verified-payload.json"), "policy": self.policy,
                  "seedFiles": self.manifest["seedFiles"], **(extra or {})}
        path = self.root / (operation + ".config.json")
        write_json(path, config)
        prefix = self.root / operation
        command = [self.python, "-I", "-B", str(Path(self.manifest["profile"]) / "native_gate.py"), operation, str(path)]
        self.children += 1
        receipt = run_child(command, prefix)
        report = read_json(prefix.with_suffix(".stdout"))
        self.gates.append(report)
        require_child(receipt, operation + " gate refused or did not complete")
        if report.get("admitted") is not True:
            refuse(operation + " gate did not admit")
        return report

    def byte_gate(self) -> None:
        """Admit raw AEE, sign it, and use only DSSE's returned verified payload."""
        tool = self.manifest["tools"]["byteGate"]["path"]
        sign = [tool, "admit-sign", str(self.root / "raw-aee.json"),
                self.manifest["seedFiles"]["envelope"]["path"], str(self.root / "envelope.json")]
        verify = [tool, "verify", str(self.root / "envelope.json"),
                  self.manifest["publicFiles"]["envelope"]["path"], str(self.root / "verified-payload.json")]
        for name, command in (("byte-sign", sign), ("byte-verify", verify)):
            self.children += 1
            require_child(run_child(command, self.root / name), name + " refused or did not complete")
        signed = read_json(self.root / "byte-sign.stdout")
        verified = read_json(self.root / "byte-verify.stdout")
        expected = sha256((self.root / "verified-payload.json").read_bytes())
        links = (signed["rawSha256"] == sha256((self.root / "raw-aee.json").read_bytes()),
                 signed["canonicalSha256"] == verified["verifiedPayloadSha256"] == expected,
                 signed["envelopeSha256"] == verified["envelopeSha256"] == sha256((self.root / "envelope.json").read_bytes()))
        if not all(links):
            refuse("raw canonical envelope returned-payload linkage differs")
        self.gates.append({"gate": "jcs-dsse", "admitted": True, "rawSha256": signed["rawSha256"],
                           "verifiedPayloadSha256": expected, "payloadSource": "DSSE-returned-verified-bytes"})

    def opa(self) -> None:
        """Evaluate actual pinned Rego with independently selected consumer anchors."""
        path = self.root / "opa-consumer.json"
        write_json(path, self.policy["opa"])
        command = [self.manifest["tools"]["opa"]["path"], "eval", "--format=json",
                   "--input", str(self.root / "verified-payload.json"), "--data", str(path),
                   "--data", str(Path(self.manifest["sources"]) / "agent-evidence-admission/rego/execution_evidence.rego"),
                   '{"admitted":data.sigstore.isCompliant,"errors":data.sigstore.errors}']
        self.children += 1
        require_child(run_child(command, self.root / "opa"), "OPA did not complete")
        report = read_json(self.root / "opa.stdout")
        try:
            verdict = report["result"][0]["expressions"][0]["value"]
        except (KeyError, IndexError, TypeError):
            refuse("OPA selected decision is absent or malformed")
        self.gates.append({"gate": "admission-opa", **verdict, "cryptographicVerification": "preceding-installed-Vectors"})
        if verdict.get("admitted") is not True or verdict.get("errors") != []:
            refuse("OPA consumer admission refused")


def snapshot_candidate(candidate: Path, run: HostRun) -> None:
    """Retain candidate bytes without reading candidate-supplied trust selection."""
    for name in ("raw-aee.json", "coverage-case.json", "record.txt"):
        path = candidate / name
        if path.is_symlink() or path.stat().st_size > 8 * 1024 * 1024:
            refuse("candidate input path or byte budget differs")
        (run.root / name).write_bytes(path.read_bytes())
    witness = Path(run.manifest["sources"]) / "agent-evidence-atlas/experiments/authority-recovery-2026-10-02/provenance.json"
    (run.root / "source.txt").write_bytes(witness.read_bytes())
    retain_reference(run)


def retain_reference(run: HostRun) -> None:
    """Retain exact selected public reference data and policy without private seeds."""
    folder = run.root / "selected-reference"
    folder.mkdir()
    sources = Path(run.manifest["sources"])
    atlas = "agent-evidence-atlas/experiments/authority-recovery-2026-10-02/"
    files = {
        "vocabulary.yaml": "agent-evidence-vocabulary/vocabulary.yaml",
        "admission.rego": "agent-evidence-admission/rego/execution_evidence.rego",
        "atlas-register.json": "agent-evidence-atlas/data/lab-register.json",
        "atlas-provenance.json": atlas + "provenance.json",
        "atlas-original.zip": atlas + "original-artifact.zip",
        "atlas-report.json": atlas + "report.json",
    }
    for name, relative in files.items():
        (folder / name).write_bytes((sources / relative).read_bytes())
    profile = Path(run.manifest["profile"])
    (folder / "SOURCE-SELECTION.json").write_bytes((profile / "SOURCE-SELECTION.json").read_bytes())
    (folder / "host-policy.json").write_bytes(Path(run.manifest["policy"]["path"]).read_bytes())
    write_json(folder / "public-installation.json", {
        "componentHeads": run.manifest["componentHeads"], "componentVersions": run.manifest["componentVersions"],
        "sourceSelectionSha256": run.manifest["sourceSelectionSha256"],
        "tools": run.manifest["tools"], "programs": run.manifest["programs"], "wheels": run.manifest["wheels"],
        "omissionMap": [{"selection": "private authority seed bytes and installation seed-file bindings",
                         "reason": "host-only authority; fresh public keys and signed records retained; no independent custody claim"}],
    })


def http_exchange(url: str, candidate: dict[str, Any] | None, prefix: Path) -> dict[str, Any]:
    """Perform actual HTTP and retain raw request/response bytes or connection loss."""
    raw = None if candidate is None else json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode()
    (prefix.with_suffix(".request")).write_bytes(raw or b"")
    request = Request(url, data=raw, headers={"Content-Type": "application/json"})
    try:
        response = urlopen(request, timeout=5)
    except HTTPError as error:
        response = error
    except (URLError, OSError) as error:
        result = {"status": None, "connectionOutcome": type(error).__name__}
        write_json(prefix.with_suffix(".http.json"), result)
        return result
    with response:
        body = response.read(2 * 1024 * 1024)
        (prefix.with_suffix(".response")).write_bytes(body)
        result = {"status": response.status, "response": json.loads(body), "responseSha256": sha256(body)}
    write_json(prefix.with_suffix(".http.json"), result)
    return result


def wait_endpoint(process: subprocess.Popen[bytes], endpoint: Path) -> dict[str, Any]:
    """Wait at most thirty seconds for a real listener, refusing early worker exit."""
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if endpoint.is_file():
            return read_json(endpoint)
        if process.poll() is not None:
            refuse("native HTTP target exited before readiness")
        time.sleep(0.02)
    refuse("native HTTP target readiness timed out")


def target_config(run: HostRun, grant: dict[str, Any], number: int, scenario: str,
                  retained: dict[str, Any] | None) -> dict[str, Any]:
    """Select native restart controls exclusively from the trusted host scenario."""
    faults = {"after-intent", "inside-effect-transaction", "after-effect"}
    return {"database": str(run.root / "native-ticket.sqlite"), "request": grant["request"],
            "grantPolicy": grant["grantPolicy"], "serviceSeed": run.manifest["seedFiles"]["service"]["path"],
            "clock": str(run.root / "host-clock.txt"), "initialize": number == 1,
            "fault": scenario if number == 1 and scenario in faults else None,
            "retainedHead": retained, "recover": number > 1,
            "revoke": number > 1 and scenario == "revoked-after"}


def start_target(run: HostRun, config: dict[str, Any], number: int) -> tuple[subprocess.Popen[bytes], dict[str, Any]]:
    """Launch one actual installed native target with selected startup bytes."""
    prefix = run.root / ("target-" + str(number))
    path = prefix.with_suffix(".config.json")
    write_json(path, config)
    endpoint = prefix.with_suffix(".endpoint.json")
    command = [run.python, "-I", "-B", str(Path(run.manifest["profile"]) / "target_worker.py"),
               str(path), sha256(path.read_bytes()), str(endpoint)]
    with prefix.with_suffix(".stdout").open("wb") as stdout, prefix.with_suffix(".stderr").open("wb") as stderr:
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr, env=child_environment())
    run.children += 1
    write_json(prefix.with_suffix(".command.json"), {"command": command})
    try:
        ready = wait_endpoint(process, endpoint)
    except HostRefusal:
        stop_target(process, prefix)
        raise
    return process, ready


def stop_target(process: subprocess.Popen[bytes], prefix: Path) -> None:
    """Close an actual target and preserve its native hard-exit or signal code."""
    if process.poll() is None:
        process.terminate()
    try:
        code = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        code = process.wait(timeout=5)
    write_json(prefix.with_suffix(".exit.json"), {"returnCode": code})


def change_current_time(run: HostRun, scenario: str) -> str:
    """Apply a host-only current authority clock selection before target reopening."""
    current = datetime.fromisoformat(run.policy["referenceTime"].replace("Z", "+00:00"))
    current += timedelta(seconds=run.policy["effectOffsetSeconds"])
    shifts = {"expired-after": 61, "rollback-after": -1}
    value = (current + timedelta(seconds=shifts.get(scenario, 0))).isoformat().replace("+00:00", "Z")
    (run.root / "host-clock.txt").write_text(value + "\n")
    return value


def dispatch_once(run: HostRun, ready: dict[str, Any], grant: dict[str, Any], prefix: str) -> dict[str, Any]:
    """Send the exact host-issued grant and accepted payload over native HTTP."""
    candidate = {"request": grant["request"], "grant": grant["grant"],
                 "contentHex": (run.root / "verified-payload.json").read_bytes().hex()}
    run.dispatches += 1
    return http_exchange(ready["url"] + "/dispatch", candidate, run.root / prefix)


def native_effect(run: HostRun, scenario: str) -> dict[str, Any]:
    """Issue, dispatch, read back, reopen and recover the selected HTTP effect.

    Recovery decisions preserve native incomplete work and prior committed
    revisions. Revocation, expiration, clock rollback and signed store rollback
    never authorize another effect. No successful completion is claimed for
    incomplete or refused recovery.
    """
    grant = run.native("issue")
    write_json(run.root / "host-grant.json", grant)
    change_current_time(run, "completed")
    first, ready = start_target(run, target_config(run, grant, 1, scenario, None), 1)
    shutil.copyfile(run.root / "native-ticket.sqlite", run.root / "prior-ready.sqlite")
    try:
        post = dispatch_once(run, ready, grant, "first-post")
    finally:
        stop_target(first, run.root / "target-1")
    prior_head = ready["startup"]["receipt"]
    current = change_current_time(run, scenario)
    second, reopened = start_target(run, target_config(run, grant, 2, scenario, prior_head), 2)
    try:
        route = "/tickets/" + grant["request"]["tenant_id"] + "/eight-component"
        get = http_exchange(reopened["url"] + route, None, run.root / "reopened-get")
        retry = dispatch_once(run, reopened, grant, "recovery-post")
    finally:
        stop_target(second, run.root / "target-2")
    readback = get["response"]
    write_json(run.root / "retained-readback.json", readback)
    effect = {"scenario": scenario, "postStatus": post["status"], "recoveryPostStatus": retry["status"],
              "nativeRevision": readback["revision"], "phase": readback["receipt"]["payload"]["phase"],
              "revoked": readback["receipt"]["payload"]["revoked"], "targetProcesses": 2}
    write_json(run.root / "effect.json", effect)
    if scenario == "store-rollback":
        shutil.copyfile(run.root / "prior-ready.sqlite", run.root / "native-ticket.sqlite")
        config = target_config(run, grant, 3, scenario, readback["receipt"])
        third, _ = start_target(run, config, 3)
        stop_target(third, run.root / "target-3")
        refuse("native store rollback unexpectedly started")
    receipt = post.get("response", readback["receipt"])
    run.native("verify-effect", {"receipt": receipt, "readback": readback, "currentTime": current})
    return effect


def execute(manifest_path: Path, manifest_sha256: str, candidate: Path,
            output: Path, scenario: str = "completed") -> dict[str, Any]:
    """Execute all selected boundaries, retaining a bounded refusal at any stage.

    Parameters
    ----------
    manifest_path, manifest_sha256
        Separate externally selected host inputs to :func:`trust.validate_host`.
    candidate : Path
        Directory with raw AEE and Verify case/record bytes. It supplies no
        trusted executable, component revision, key, source, or consumer policy.
    output : Path
        New retained public run directory. Creation is exclusive.
    scenario : str, default="completed"
        Explicit host-only native process/recovery control from :data:`SCENARIOS`.

    Returns
    -------
    dict[str, Any]
        Exact chain outcome, child/HTTP counts, component decisions and bounded
        effect state. Passing measurement is distinct from acceptance, adoption
        and custody, all of which remain unestablished here.
    """
    output = output.resolve()
    output.mkdir()
    run: HostRun | None = None
    decision: dict[str, Any] = {"schema": "probity-eight-component-host-run-v1",
                                "status": "refused", "scenario": scenario}
    try:
        manifest = validate_host(manifest_path, manifest_sha256)
        run = HostRun(manifest, output)
        snapshot_candidate(candidate.resolve(), run)
        run.byte_gate()
        run.native("vectors")
        run.opa()
        for gate in ("vocabulary", "atlas", "verify"):
            run.native(gate)
        decision["effect"] = native_effect(run, scenario)
        decision["status"] = "measured"
        decision["componentHeads"] = manifest["componentHeads"]
        decision["doesNotAssert"] = run.policy["doesNotAssert"]
    except (HostRefusal, OSError, ValueError, KeyError, TypeError) as error:
        decision["reason"] = str(error)
        LOGGER.warning("eight-component run retained refusal: %s", error)
        if (output / "effect.json").is_file():
            decision["effect"] = read_json(output / "effect.json")
    decision.update(childProcesses=0 if run is None else run.children,
                    httpDispatchRequests=0 if run is None else run.dispatches,
                    gates=[] if run is None else run.gates,
                    acceptance="not-established", adoption="not-established", custody="not-established")
    write_json(output / "decision.json", decision)
    return decision


def main() -> None:
    """Execute an explicitly selected host chain with finite native recovery scope."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--installation-sha256", required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scenario", choices=SCENARIOS, default="completed")
    args = parser.parse_args()
    result = execute(args.installation, args.installation_sha256, args.candidate, args.output, args.scenario)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["status"] == "measured" else 1)


if __name__ == "__main__":
    main()
