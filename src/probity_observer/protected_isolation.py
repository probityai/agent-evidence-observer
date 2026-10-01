"""Run exact signed actions through the host socket from a Linux namespace."""

from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path
from typing import Any

from .admission import AdmissionPolicy, AdmissionStore
from .authorization import ActionRequest, GrantPolicy, issue_grant, utc_clock
from .crypto import (
    SigningKey,
    VerificationError,
    canonical,
    digest,
    strict_loads,
    verify_signature,
)
from .history import read_history, verify_checkpoint
from .isolation import _run_child, launch_command, observer_build_digest, sha256
from .ledger import LedgerWitness
from .protected_dispatch import (
    ProtectedDispatcher,
    ProtectedWriteServer,
    verify_dispatch_bundle,
)

PROBE = Path(__file__).with_name("protected_probe.py")
LAUNCH_DOMAIN = "probity-protected-isolation-launch-v0"
REPORT_DOMAIN = "probity-protected-isolation-report-v0"
EXPECTED = frozenset(
    {
        "directWriteRefused",
        "keyReadRefused",
        "processSignalRefused",
        "networkRefused",
        "changed-run_id",
        "changed-attempt_id",
        "changed-request_id",
        "changed-tenant_id",
        "changed-principal_id",
        "changed-tool_id",
        "changed-target_path",
        "changed-content_sha256",
        "malformedJson",
        "missingNewline",
        "oversized",
        "duplicateMember",
        "nativeBypass",
        "callerClock",
        "wrongIssuer",
        "wrongSignature",
        "expiredGrant",
        "futureGrant",
        "changedContent",
        "lostResponseReplay",
        "repeatReplay",
        "changedRetry",
    }
)


def protected_launch_command(
    bwrap: Path,
    socket_dir: Path,
    interpreter: Path,
    host_pid: int,
    probe: Path,
    invocation: Path,
) -> list[str]:
    """Mount only public input and the exact protected socket into the child."""
    command = launch_command(bwrap, socket_dir, interpreter, host_pid, probe)
    separator = command.index("--")
    return (
        command[:separator]
        + ["--ro-bind", str(invocation), "/agent/invocation.json"]
        + command[separator:]
    )


def _inputs(
    output: Path,
) -> tuple[ActionRequest, GrantPolicy, dict[str, Any], bytes, SigningKey, SigningKey]:
    """Retain public fixture grants while keeping private keys in memory."""
    now = utc_clock()
    issuer, observer, witness = (SigningKey.generate() for _ in range(3))
    content = b"isolated protected effect\n"
    request = ActionRequest(
        "protected-isolation-1",
        "attempt-1",
        "effect-1",
        "tenant-1",
        "principal-1",
        "file-write",
        "/work/effect.txt",
        hashlib.sha256(content).hexdigest(),
    )
    policy = GrantPolicy(issuer.public_hex)
    grant = issue_grant(
        request,
        issuer,
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(seconds=180),
    )
    expired = issue_grant(
        request,
        issuer,
        issued_at=now - timedelta(seconds=61),
        expires_at=now - timedelta(seconds=1),
    )
    future = issue_grant(
        request,
        issuer,
        issued_at=now + timedelta(seconds=180),
        expires_at=now + timedelta(seconds=240),
    )
    invocation = {
        "invocation": {
            "request": asdict(request),
            "grant": grant,
            "contentHex": content.hex(),
        },
        "expiredGrant": expired,
        "futureGrant": future,
    }
    (output / "invocation.json").write_bytes(canonical(invocation))
    (output / "trusted-keys.json").write_bytes(
        canonical(
            {
                "issuer": issuer.public_hex,
                "observer": observer.public_hex,
                "witness": witness.public_hex,
            }
        )
    )
    return request, policy, grant, content, observer, witness


def _launch(
    output: Path, bwrap: Path, interpreter: Path
) -> tuple[list[str], dict[str, Any], str]:
    """Fix source bytes, public inputs, and exact launch policy before dispatch."""
    probe = output / "agent-probe.py"
    probe.write_bytes(PROBE.read_bytes())
    command = protected_launch_command(
        bwrap,
        output / "socket",
        interpreter,
        os.getpid(),
        probe,
        output / "invocation.json",
    )
    policy = {
        "argv": command,
        "probeSha256": sha256(probe),
        "invocationSha256": sha256(output / "invocation.json"),
        "interpreterSha256": sha256(interpreter),
        "bwrapSha256": sha256(bwrap) if bwrap.is_file() else "0" * 64,
        "observerBuildDigest": observer_build_digest(),
        "mountProfile": "public-input-and-protected-socket-only",
    }
    (output / "launch-policy.json").write_bytes(canonical(policy))
    return command, policy, digest(LAUNCH_DOMAIN, policy)


def _child(
    command: list[str], socket_path: Path, dispatcher: ProtectedDispatcher
) -> tuple[int, bytes, bytes]:
    """Attempt the real boundary and preserve permission or launch failures."""
    try:
        with ProtectedWriteServer(socket_path, dispatcher) as server:
            os.chmod(socket_path, 0o666)
            return _run_child(command, server)
    except OSError as exc:
        return -1, b"", str(exc).encode("ascii", errors="backslashreplace")
    finally:
        socket_path.unlink(missing_ok=True)


def _attempts(stdout: bytes, returncode: int) -> dict[str, Any] | None:
    """Parse the fixed child's complete result population without guessing."""
    if returncode != 0:
        return None
    try:
        results = strict_loads(stdout.strip(b"\n"))
    except ValueError:
        return None
    return results if isinstance(results, dict) else None


def _report_head(
    dispatcher: ProtectedDispatcher, initial: dict[str, Any], report: dict[str, Any]
) -> dict[str, Any]:
    """Retain a signed failure even when partial state cannot export a new head."""
    try:
        return dispatcher.retained_head()
    except (ValueError, OSError) as exc:
        report.update(
            status="incomplete",
            reason="protected retained state is incomplete",
            retainedStateError=str(exc),
            restartReplayed=False,
            consumerStatus="not-admitted",
        )
        return initial


def _consumer(
    output: Path,
    dispatcher: ProtectedDispatcher,
    request: ActionRequest,
    policy: GrantPolicy,
    observer: SigningKey,
    witness: SigningKey,
    execution_digest: str,
) -> dict[str, Any]:
    """Check retained evidence, reopen the producer, and record consumer admission."""
    directory = output / "producer"
    head = dispatcher.retained_head()
    verified = verify_dispatch_bundle(
        directory,
        request,
        policy,
        observer.public_hex,
        witness.public_hex,
        head,
        workspace=output / "workspace",
        execution_digest=execution_digest,
    )
    (output / "consumer" / "retained-authorization-head.json").write_bytes(
        canonical(head)
    )
    (output / "consumer" / "verification.json").write_bytes(canonical(verified))
    restarted = ProtectedDispatcher(
        output / "workspace",
        directory,
        request,
        policy,
        observer,
        witness,
        retained_authorization_head=head,
        execution_digest=execution_digest,
    )
    invocation = strict_loads((output / "invocation.json").read_bytes())["invocation"]
    replayed = restarted.write(
        request, invocation["grant"], bytes.fromhex(invocation["contentHex"])
    ).replayed
    native_witness = LedgerWitness(
        directory / "witness-ledger.jsonl", witness, observer.public_hex
    )
    packet = strict_loads((directory / "packet.json").read_bytes())
    admission_policy = AdmissionPolicy(
        request.run_id,
        digest("probity-authority-v0", packet["authority"]),
        observer.public_hex,
        witness.public_hex,
        native_witness.signed_head(),
    )
    store = AdmissionStore(output / "consumer" / "admission-state.json")
    store.initialize(observer.public_hex, witness.public_hex)
    decision = store.admit(
        packet,
        directory / "history.jsonl",
        directory / "witness-ledger.jsonl",
        admission_policy,
    )
    (output / "consumer" / "admission-policy.json").write_bytes(
        canonical(asdict(admission_policy))
    )
    (output / "consumer" / "decision.json").write_bytes(canonical(decision))
    return {
        "restartReplayed": replayed,
        "consumerStatus": decision["status"],
        "authorizationHead": head,
    }


def run_protected_isolation(
    output: Path,
    *,
    bwrap: Path | None = None,
    interpreter: Path = Path("/usr/bin/python3"),
) -> dict[str, Any]:
    """Retain an actual isolated authorized dispatch or an explicit incomplete run.

    Parameters
    ----------
    output : Path
        New or empty bundle directory. ``workspace`` and ``producer`` remain on
        the host; the child sees only a read-only probe, public invocation, and
        host socket. Private key material is never written into the bundle.
    bwrap : Path | None, optional
        Explicit bubblewrap binary, otherwise discovered on the host PATH.
    interpreter : Path, default=Path('/usr/bin/python3')
        System Python available in the read-only Linux runtime mounts.

    Returns
    -------
    dict[str, Any]
        Signed-report payload and raw output digests. ``probe-passed`` requires
        all 26 child checks, one matching host-recorded write, grant ordering,
        restart replay, and consumer admission. A permission denial, absent
        binary, timeout, false assertion, or verification failure is retained
        as ``incomplete``, never counted as a passing boundary result.

    Notes
    -----
    One operator controls the three keys, clock, launch, witness, and consumer.
    This demonstrates a measured namespace launch and bounded local behavior;
    it does not claim native APS/MCP/A2A conformance, independent custody,
    arbitrary malicious-program coverage, or global exactly-once execution.
    """
    output.mkdir(parents=True, exist_ok=True)
    output = output.resolve(strict=True)
    if any(output.iterdir()):
        raise ValueError("protected isolation output directory must be empty")
    for name in ("workspace", "socket", "consumer"):
        (output / name).mkdir()
    request, policy, grant, content, observer, witness = _inputs(output)
    bwrap = bwrap or Path(shutil.which("bwrap") or "/usr/bin/bwrap")
    command, launch, execution_digest = _launch(output, bwrap, interpreter)
    dispatcher = ProtectedDispatcher(
        output / "workspace",
        output / "producer",
        request,
        policy,
        observer,
        witness,
        execution_digest=execution_digest,
    )
    initial_head = dispatcher.initialize()
    (output / "consumer" / "initial-authorization-head.json").write_bytes(
        canonical(initial_head)
    )
    returncode, stdout, stderr = _child(
        command, output / "socket" / "write.sock", dispatcher
    )
    (output / "probe-stdout.bin").write_bytes(stdout)
    (output / "probe-stderr.bin").write_bytes(stderr)
    results = _attempts(stdout, returncode)
    report = {
        "status": "incomplete",
        "reason": "isolation setup failed"
        if returncode != 0
        else "protected boundary probes failed",
        "exitCode": returncode,
        "attempts": results,
        "launchDigest": execution_digest,
        "stdoutSha256": hashlib.sha256(stdout).hexdigest(),
        "stderrSha256": hashlib.sha256(stderr).hexdigest(),
        "witnessScope": "PEER",
        "evidence_vantage": "artifact",
        "restartReplayed": False,
        "consumerStatus": "not-admitted",
    }
    passed = (
        returncode == 0
        and isinstance(results, dict)
        and set(results) == EXPECTED
        and all(value is True for value in results.values())
    )
    if passed:
        report.update(
            _complete(
                output,
                dispatcher,
                request,
                policy,
                observer,
                witness,
                execution_digest,
                content,
            )
        )
    retained_head = _report_head(dispatcher, initial_head, report)
    (output / "protected-isolation-report.json").write_bytes(canonical(report))
    payload = {
        "reportDigest": digest(REPORT_DOMAIN, report),
        "launchDigest": digest(LAUNCH_DOMAIN, launch),
        "authorizationHead": retained_head,
    }
    (output / "protected-isolation-attestation.json").write_bytes(
        canonical(
            {
                "payload": payload,
                "keyid": observer.public_hex,
                "signature": observer.sign(REPORT_DOMAIN, payload),
            }
        )
    )
    manifest = {
        path.relative_to(output).as_posix(): sha256(path)
        for path in sorted(output.rglob("*"))
        if path.is_file()
    }
    (output / "manifest.json").write_bytes(canonical(manifest))
    return report


def _complete(
    output: Path,
    dispatcher: ProtectedDispatcher,
    request: ActionRequest,
    policy: GrantPolicy,
    observer: SigningKey,
    witness: SigningKey,
    execution_digest: str,
    content: bytes,
) -> dict[str, Any]:
    """Require target bytes and one recorded effect before accepting child claims."""
    target = output / "workspace" / "effect.txt"
    if not target.is_file() or target.read_bytes() != content:
        return {"reason": "protected target bytes differ"}
    entries = read_history(output / "producer" / "history.jsonl")
    if len([entry for entry in entries if entry["event"]["kind"] == "write"]) != 1:
        return {"reason": "protected host effect population differs"}
    try:
        consumer = _consumer(
            output, dispatcher, request, policy, observer, witness, execution_digest
        )
    except (ValueError, OSError) as exc:
        return {
            "reason": "protected consumer verification failed",
            "verificationError": str(exc),
        }
    if (
        consumer["restartReplayed"] is not True
        or consumer["consumerStatus"] != "admitted"
    ):
        return {"reason": "protected restart or admission failed", **consumer}
    return {"status": "probe-passed", "reason": None, **consumer}


def _verify_retained_bytes(
    output: Path, report: dict[str, Any], launch: dict[str, Any]
) -> None:
    """Compare every retained raw input/output population with its signed digest."""
    for path, expected in (
        ("agent-probe.py", launch["probeSha256"]),
        ("invocation.json", launch["invocationSha256"]),
        ("probe-stdout.bin", report["stdoutSha256"]),
        ("probe-stderr.bin", report["stderrSha256"]),
    ):
        if sha256(output / path) != expected:
            raise VerificationError(
                "retained protected launch bytes differ from the signed result"
            )


def _verify_probe_result(output: Path, report: dict[str, Any]) -> None:
    """Require an actual successful exit and the exact retained child assertions."""
    if report["status"] != "probe-passed":
        raise VerificationError("protected isolation run is incomplete")
    if (
        report["exitCode"] != 0
        or report["restartReplayed"] is not True
        or report["consumerStatus"] != "admitted"
    ):
        raise VerificationError("protected isolation success omits a required gate")
    attempts = _attempts((output / "probe-stdout.bin").read_bytes(), report["exitCode"])
    if attempts != report["attempts"] or not isinstance(attempts, dict):
        raise VerificationError("protected probe output differs from the signed result")
    if set(attempts) != EXPECTED or not all(
        value is True for value in attempts.values()
    ):
        raise VerificationError(
            "protected isolation report has failed or missing probes"
        )


def _verify_authorization_head(
    output: Path, report: dict[str, Any], payload: dict[str, Any], witness: str
) -> None:
    """Bind the report and observer signature to the actual final witness head."""
    state = strict_loads((output / "producer" / "dispatch-state.json").read_bytes())[
        "payload"
    ]
    head = state["checkpoint"]
    if report.get("authorizationHead") != head or payload["authorizationHead"] != head:
        raise VerificationError(
            "protected report head differs from the completed journal"
        )
    verify_checkpoint(
        read_history(output / "producer" / "authorization.jsonl"), head, witness
    )


def verify_protected_isolation_bundle(
    output: Path,
    expected_request: ActionRequest,
    policy: GrantPolicy,
    observer_key: str,
    witness_key: str,
    retained_head: dict[str, Any],
    *,
    expected_launch_digest: str,
) -> dict[str, Any]:
    """Authenticate exact launch bytes and action with external consumer pins.

    The expected request, issuer policy, launch digest, role keys, and retained
    head must be acquired outside this candidate. The current bundle cannot
    select its own action or trusted launch. A passing result remains local
    PEER/artifact evidence, not an independent run or global recovery claim.
    """
    report = strict_loads((output / "protected-isolation-report.json").read_bytes())
    launch = strict_loads((output / "launch-policy.json").read_bytes())
    attestation = strict_loads(
        (output / "protected-isolation-attestation.json").read_bytes()
    )
    payload = {
        "reportDigest": digest(REPORT_DOMAIN, report),
        "launchDigest": digest(LAUNCH_DOMAIN, launch),
        "authorizationHead": attestation["payload"]["authorizationHead"],
    }
    if (
        attestation["keyid"] != observer_key
        or attestation["payload"] != payload
        or report["launchDigest"] != payload["launchDigest"]
        or report["launchDigest"] != expected_launch_digest
    ):
        raise VerificationError(
            "protected isolation attestation differs from the pinned result"
        )
    verify_signature(observer_key, REPORT_DOMAIN, payload, attestation["signature"])
    if report["witnessScope"] != "PEER" or report["evidence_vantage"] != "artifact":
        raise VerificationError(
            "protected isolation report claims an unsupported vantage"
        )
    _verify_retained_bytes(output, report, launch)
    _verify_probe_result(output, report)
    _verify_authorization_head(output, report, payload, witness_key)
    invocation = strict_loads((output / "invocation.json").read_bytes())["invocation"]
    if invocation["request"] != asdict(expected_request):
        raise VerificationError("protected invocation differs from the consumer action")
    verify_dispatch_bundle(
        output / "producer",
        expected_request,
        policy,
        observer_key,
        witness_key,
        retained_head,
        workspace=output / "workspace",
        execution_digest=report["launchDigest"],
    )
    return report
