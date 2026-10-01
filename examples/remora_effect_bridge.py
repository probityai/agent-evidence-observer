"""Run local file-effect probes against the pinned REMORA post-approval cases."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant
from probity_observer.crypto import SigningKey, VerificationError, canonical, strict_loads, verify_signature
from probity_observer.history import read_history, verify_checkpoint
from probity_observer.protected_dispatch import STATE_DOMAIN, ProtectedDispatcher, verify_dispatch_bundle

REMORA_COMMIT = "b25e735d36590154ff53768b4d245ad4c7996f64"
VECTOR_PATH = "conformance/autoreview-to-effect-v1/vectors.json"
VECTOR_SHA256 = "f896178eac35aab8843f0902934f1433eb6dccb2a212fc4139a67890faaabd27"
IDS = ("AR-00", "AR-01", "AR-02", "AR-03", "AR-04", "AR-05")
CONTENT = b"approved local state: 100\n"
LATER_CONTENT = b"current local state: 10\n"
def _clock() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _save(path: Path, value: object) -> None:
    path.write_bytes(canonical(value))


def _refusal(action) -> str:
    try:
        action()
    except VerificationError as exc:
        return str(exc)
    raise AssertionError("a substituted action reached the protected effect path")


def _native_writes(state: Path) -> int:
    history = state / "history.jsonl"
    if not history.exists():
        return 0
    return sum(entry["event"]["kind"] == "write" for entry in read_history(history))


def _case(root: Path, vector: dict) -> dict:
    case_id = vector["id"]
    directory = root / case_id
    directory.mkdir()
    workspace = directory / "workspace"
    workspace.mkdir()
    state = directory / "state"
    issuer, observer, witness = (SigningKey.generate() for _ in range(3))
    now = _clock()
    request = ActionRequest(
        f"remora-{case_id}", "attempt-1", "request-1", "tenant-1",
        "svc-payments", "transfer_funds", "/work/acct-2.txt", _sha(CONTENT),
    )
    policy = GrantPolicy(issuer.public_hex)
    grant = issue_grant(
        request, issuer, issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(seconds=120),
    )
    old_policy = _sha(b"local-policy-A")
    dispatcher = ProtectedDispatcher(
        workspace, state, request, policy, observer, witness,
        clock=_clock, execution_digest=old_policy,
    )
    initial = dispatcher.initialize()
    _save(directory / "approved-request.json", asdict(request))
    _save(directory / "grant.json", grant)
    _save(directory / "consumer-pins.json", {
        "request": asdict(request), "policy": asdict(policy),
        "observerKey": observer.public_hex, "witnessKey": witness.public_hex,
        "initialAuthorizationHead": initial, "executionDigest": old_policy,
    })

    if case_id == "AR-00":
        response = dispatcher.write(request, grant, CONTENT)
        attempt = {"request": asdict(request), "executionDigest": old_policy, "response": asdict(response)}
        checked = verify_dispatch_bundle(
            state, request, policy, observer.public_hex, witness.public_hex,
            initial, workspace=workspace, execution_digest=old_policy,
        )
        assert response.replayed is False
        assert checked["orderingEvidence"] == "local-witnessed-grant-before-host-dispatch"
        assert (workspace / "acct-2.txt").read_bytes() == CONTENT
        observed, scope = "EFFECT_VERIFIED", "current local file and retained PEER packet"
        detail = "The approved exact file write completed and its current bytes agree."
    elif case_id == "AR-01":
        changed = replace(
            request, target_path="/work/" + vector["steps"][1]["arguments"]["to"] + ".txt"
        )
        reason = _refusal(lambda: dispatcher.write(changed, grant, CONTENT))
        assert reason == "invocation differs from the expected action"
        attempt = {"request": asdict(changed), "executionDigest": old_policy, "refusal": reason}
        observed, scope = "CALL_BINDING_MISMATCH", "local target-path substitution"
        detail = reason
    elif case_id == "AR-02":
        changed = replace(request, principal_id=vector["steps"][1]["actor"])
        reason = _refusal(lambda: dispatcher.write(changed, grant, CONTENT))
        assert reason == "invocation differs from the expected action"
        attempt = {"request": asdict(changed), "executionDigest": old_policy, "refusal": reason}
        observed, scope = "IDENTITY_MISMATCH", "signed principal label, no external identity proof"
        detail = reason
    elif case_id == "AR-03":
        changed = replace(request, tool_id=vector["steps"][2]["tool"])
        reason = _refusal(lambda: dispatcher.write(changed, grant, CONTENT))
        assert reason == "invocation differs from the expected action"
        attempt = {
            "request": asdict(changed), "executionDigest": old_policy,
            "registeredAlternate": False, "refusal": reason,
        }
        observed, scope = "UNSUPPORTED", "tool-label substitution only"
        detail = "The changed label is refused, but this path has no registered reachable alternate tool."
    elif case_id == "AR-04":
        current_policy = _sha(b"local-policy-B")
        reopened = ProtectedDispatcher(
            workspace, state, request, policy, observer, witness,
            clock=_clock, execution_digest=current_policy,
        )
        reason = _refusal(lambda: reopened.write(request, grant, CONTENT))
        assert reason == "dispatch configuration differs from the retained action"
        attempt = {"request": asdict(request), "executionDigest": current_policy, "refusal": reason}
        observed, scope = "CONTEXT_CHANGED", "explicitly changed consumer policy digest"
        detail = "A supplied new policy pin refuses the old store; no automatic bundle discovery is tested."
    else:
        response = dispatcher.write(request, grant, CONTENT)
        assert response.replayed is False
        (workspace / "acct-2.txt").write_bytes(LATER_CONTENT)
        reason = _refusal(lambda: verify_dispatch_bundle(
            state, request, policy, observer.public_hex, witness.public_hex,
            initial, workspace=workspace, execution_digest=old_policy,
        ))
        assert reason == "current workspace root differs from the claim"
        attempt = {
            "request": asdict(request), "executionDigest": old_policy,
            "response": asdict(response), "currentContentSha256": _sha(LATER_CONTENT),
            "readBackRefusal": reason,
        }
        observed, scope = "EFFECT_MISMATCH", "same-operator current file read-back"
        detail = "The saved success response cannot establish the later current bytes; an unmediated change is detected."

    executions = _native_writes(state)
    assert executions == vector["executions"]
    if case_id in {"AR-01", "AR-02", "AR-03", "AR-04"}:
        assert list(workspace.iterdir()) == []
        assert not (state / "history.jsonl").exists()
    (directory / "approved-content.bin").write_bytes(CONTENT)
    _save(directory / "attempt.json", attempt)
    return {
        "id": case_id,
        "sourceExpectation": vector["expect"],
        "sourceToolBodies": vector["executions"],
        "localOutcome": observed,
        "nativeWriteEvents": executions,
        "scope": scope,
        "detail": detail,
        "relationship": "unsupported-exact-vector" if case_id == "AR-03" else "bounded-local-file-analogue",
    }


def run(output: Path, source: Path) -> dict:
    raw = source.read_bytes()
    if _sha(raw) != VECTOR_SHA256:
        raise ValueError("REMORA vector bytes differ from the pinned source")
    suite = json.loads(raw)
    vectors = suite["vectors"]
    if suite["suite"] != "autoreview-to-effect-v1" or tuple(v["id"] for v in vectors) != IDS:
        raise ValueError("REMORA vector identities differ from the pinned suite")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("output directory must be empty")
    results = [_case(output, vector) for vector in vectors]
    pins = {
        "upstream": "darklordVirtual/REMORA-research", "commit": REMORA_COMMIT,
        "path": VECTOR_PATH, "sha256": VECTOR_SHA256,
        "observerSource": "probityai/agent-evidence-observer",
        "observerBase": "133ddad46d1c1ba2fd5855ddc215e234852f3c6a",
        "runnerSha256": _sha(Path(__file__).read_bytes()),
        "effectSourceSha256": {
            name: _sha((Path(__file__).resolve().parents[1] / "src" / "probity_observer" / name).read_bytes())
            for name in (
                "authorization.py", "broker.py", "crypto.py", "history.py",
                "protected_dispatch.py", "verify.py",
            )
        },
    }
    _save(output / "source-pins.json", pins)
    report = {
        "profile": "probity-remora-local-effect-crosswalk-v0",
        "runKind": "same-operator-local-probe",
        "source": pins,
        "results": results,
        "limits": [
            "The source transfer-funds tool and authoritative account ledger were not run.",
            "A changed tool label is not a registered reachable alternate tool.",
            "Policy freshness requires a trusted caller to supply the new digest.",
            "Current file bytes are read locally; external authoritative custody is not established.",
            "Direct host invocation does not establish child isolation or route completeness.",
        ],
    }
    _save(output / "run-report.json", report)
    files = {
        path.relative_to(output).as_posix(): _sha(path.read_bytes())
        for path in sorted(output.rglob("*")) if path.is_file()
    }
    _save(output / "file-hashes.json", files)
    return report


def verify_run(output: Path, source: Path) -> dict:
    if _sha(source.read_bytes()) != VECTOR_SHA256:
        raise ValueError("REMORA vector bytes differ from the pinned source")
    expected = strict_loads((output / "file-hashes.json").read_bytes())
    actual = {
        path.relative_to(output).as_posix(): _sha(path.read_bytes())
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "file-hashes.json"
    }
    if expected != actual:
        raise ValueError("retained bridge files differ from the saved hash list")
    report = strict_loads((output / "run-report.json").read_bytes())
    pins = strict_loads((output / "source-pins.json").read_bytes())
    if report["source"] != pins or pins["sha256"] != VECTOR_SHA256 or pins["commit"] != REMORA_COMMIT:
        raise ValueError("retained source pins differ from the expected source")
    if pins["runnerSha256"] != _sha(Path(__file__).read_bytes()):
        raise ValueError("bridge runner differs from the retained source pin")
    for name, sha in pins["effectSourceSha256"].items():
        path = Path(__file__).resolve().parents[1] / "src" / "probity_observer" / name
        if _sha(path.read_bytes()) != sha:
            raise ValueError(f"effect source differs from the retained pin: {name}")
    vectors = json.loads(source.read_bytes())["vectors"]
    if tuple(item["id"] for item in report["results"]) != IDS:
        raise ValueError("retained case population differs from the source")
    for item, vector in zip(report["results"], vectors, strict=True):
        if item["sourceExpectation"] != vector["expect"] or item["sourceToolBodies"] != vector["executions"]:
            raise ValueError("retained source expectation differs from the pinned vector")
        directory = output / item["id"]
        state_dir = directory / "state"
        consumer = strict_loads((directory / "consumer-pins.json").read_bytes())
        attempt = strict_loads((directory / "attempt.json").read_bytes())
        request = ActionRequest(**consumer["request"])
        policy = GrantPolicy(**consumer["policy"])
        observer = consumer["observerKey"]
        witness = consumer["witnessKey"]
        initial = consumer["initialAuthorizationHead"]
        workspace = directory / "workspace"
        if _sha((directory / "approved-content.bin").read_bytes()) != request.content_sha256:
            raise ValueError("approved content differs from the exact request")
        submitted = ActionRequest(**attempt["request"])
        expected_request = request
        if item["id"] == "AR-01":
            expected_request = replace(request, target_path="/work/" + vector["steps"][1]["arguments"]["to"] + ".txt")
        elif item["id"] == "AR-02":
            expected_request = replace(request, principal_id=vector["steps"][1]["actor"])
        elif item["id"] == "AR-03":
            expected_request = replace(request, tool_id=vector["steps"][2]["tool"])
            if attempt.get("registeredAlternate") is not False:
                raise ValueError("alternate-tool support differs from the retained scope")
        if submitted != expected_request:
            raise ValueError("submitted request differs from the pinned case")
        expected_policy = _sha(b"local-policy-B") if item["id"] == "AR-04" else consumer["executionDigest"]
        if attempt["executionDigest"] != expected_policy:
            raise ValueError("submitted policy digest differs from the pinned case")
        if _native_writes(state_dir) != item["nativeWriteEvents"]:
            raise ValueError("native write count differs from the retained report")
        if item["id"] in {"AR-00", "AR-05"}:
            verify_dispatch_bundle(
                state_dir, request, policy, observer, witness, initial,
                workspace=workspace if item["id"] == "AR-00" else None,
                execution_digest=consumer["executionDigest"],
            )
            if item["id"] == "AR-05":
                if _sha((workspace / "acct-2.txt").read_bytes()) != attempt["currentContentSha256"]:
                    raise ValueError("retained current bytes differ from the read-back")
                reason = _refusal(lambda: verify_dispatch_bundle(
                    state_dir, request, policy, observer, witness, initial,
                    workspace=workspace, execution_digest=consumer["executionDigest"],
                ))
                if reason != "current workspace root differs from the claim":
                    raise ValueError("current read-back did not detect the changed bytes")
                if attempt["readBackRefusal"] != reason:
                    raise ValueError("retained read-back result differs from the checked result")
            if attempt["response"] != strict_loads((state_dir / "dispatch-state.json").read_bytes())["payload"]["result"]:
                raise ValueError("reported success differs from the signed dispatch result")
        else:
            expected_refusal = (
                "dispatch configuration differs from the retained action"
                if item["id"] == "AR-04" else "invocation differs from the expected action"
            )
            if attempt["refusal"] != expected_refusal:
                raise ValueError("retained refusal differs from the protected dispatch result")
            signed = strict_loads((state_dir / "dispatch-state.json").read_bytes())
            if signed["keyid"] != observer or signed["payload"]["phase"] != "ready":
                raise ValueError("refused case has no authenticated ready state")
            verify_signature(observer, STATE_DOMAIN, signed["payload"], signed["signature"])
            verify_checkpoint(read_history(state_dir / "authorization.jsonl"), initial, witness)
            if list(workspace.iterdir()) or (state_dir / "history.jsonl").exists():
                raise ValueError("refused case has a native effect")
    return {"status": "retained-cases-checked", "cases": list(IDS), "witnessScope": "PEER"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--remora-vectors", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    result = verify_run(args.output, args.remora_vectors) if args.verify else run(args.output, args.remora_vectors)
    print(json.dumps(result, sort_keys=True))
