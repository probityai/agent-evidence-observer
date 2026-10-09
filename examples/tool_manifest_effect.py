"""Retain a pinned static tool binding as a protected local file effect."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant
from probity_observer.crypto import SigningKey, VerificationError, canonical
from probity_observer.protected_dispatch import (
    ProtectedDispatcher,
    verify_dispatch_bundle,
)
from probity_observer.tool_manifest import (
    ToolGate,
    require_served_tool,
    tool_digest,
    tool_key,
    verify_tool_grade,
)

SOURCE_COMMIT = "36426cfd5152bba6a27766febfac8aaef47b6f34"
FIXTURE_SHA256 = "488496079155830caf83593be0cafcb21367f72cd70ea363c2400f40eda72647"
FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/agentavow-tool-manifest-v1/tool-manifest-digest-v1-vectors.json"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_fixture(path: Path = FIXTURE) -> dict[str, Any]:
    """Require the unchanged contributor fixture before creating output."""
    data = path.read_bytes()
    if _sha(data) != FIXTURE_SHA256:
        raise VerificationError("AgentAvow fixture bytes differ from the pinned source")
    return json.loads(data)


def _save(path: Path, value: Any) -> None:
    path.write_bytes(canonical(value))


def _clock() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _binding(fixture: dict[str, Any], vector: dict[str, Any], jws: str,
             served: dict[str, Any], run_time: str) -> dict[str, Any]:
    gate = ToolGate(**vector["gate"])
    grade = require_served_tool(jws, fixture["issuer"]["jwk"], gate, served)
    run_grade = verify_tool_grade(jws, fixture["issuer"]["jwk"], replace(gate, evaluation_time=run_time))
    return {
        "profile": "probity-agentavow-local-binding-retention-v1",
        "sourceCommit": SOURCE_COMMIT, "fixtureSha256": FIXTURE_SHA256,
        "jwsSha256": _sha(jws.encode("ascii")), "gate": asdict(gate), "axes": grade.axes(),
        "runEvaluationTime": run_time, "runGradeAxes": run_grade.axes(),
        "localEffect": "retain-static-grade-binding-file",
        "remoteExecution": "not-observed", "actionSafety": "not-established",
    }


def _retain(directory: Path, binding: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    directory.mkdir()
    workspace = directory / "workspace"
    workspace.mkdir()
    content = canonical(binding)
    issuer, observer, witness = (SigningKey.generate() for _ in range(3))
    request = ActionRequest("manifest-retention", "attempt-1", "request-1", "local-demo",
                            "fixture-reader", "retain-static-grade-binding", "/work/binding.json", _sha(content))
    policy = GrantPolicy(issuer.public_hex)
    decision_digest = _sha(content)
    dispatcher = ProtectedDispatcher(workspace, directory / "state", request, policy, observer,
                                     witness, clock=_clock, decision_digest=decision_digest)
    initial = dispatcher.initialize()
    pins = {"request": asdict(request), "policy": asdict(policy), "observerKey": observer.public_hex,
            "witnessKey": witness.public_hex, "initialAuthorizationHead": initial,
            "decisionDigest": decision_digest}
    _save(directory / "consumer-pins.json", pins)
    now = _clock()
    grant = issue_grant(request, issuer, issued_at=now - timedelta(seconds=1),
                        expires_at=now + timedelta(seconds=120))
    response = dispatcher.write(request, grant, content)
    _save(directory / "grant.json", grant)
    return ({"nativeWriteEvents": 1, "replayed": response.replayed,
             "localEffect": binding["localEffect"], "remoteExecution": binding["remoteExecution"]}, pins)


def _verify_retention(directory: Path, binding: dict[str, Any], pins: dict[str, Any]) -> dict[str, Any]:
    content = canonical(binding)
    request = ActionRequest(**pins["request"])
    if request.content_sha256 != _sha(content) or pins["decisionDigest"] != _sha(content):
        raise VerificationError("retained request differs from the recomputed grade binding")
    checked = verify_dispatch_bundle(directory / "state", request, GrantPolicy(**pins["policy"]),
                                     pins["observerKey"], pins["witnessKey"],
                                     pins["initialAuthorizationHead"], workspace=directory / "workspace",
                                     decision_digest=_sha(content))
    if (directory / "workspace/binding.json").read_bytes() != content:
        raise VerificationError("retained file differs from the recomputed grade binding")
    if (directory / "consumer-pins.json").read_bytes() != canonical(pins):
        raise VerificationError("retained consumer selection differs from the selected pins")
    return {"localEffectVerified": True, "orderingEvidence": checked["orderingEvidence"],
            "witnessScope": checked["witnessScope"], "remoteExecution": "not-observed"}


def _fixture_results(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    signed = fixture["attestation"]["toolDigests"]
    observed = {tool_key(t["name"]): tool_digest(t) for t in fixture["observed_tools"]}
    if observed != signed:
        raise VerificationError("served definitions differ from the fixture's signed tool set")
    positive = fixture["vectors"][0]["gate"]
    for served in fixture["observed_tools"]:
        gate = ToolGate(positive["subject_id"], served["name"], tool_digest(served), positive["evaluation_time"])
        require_served_tool(fixture["attestation"]["jws"], fixture["issuer"]["jwk"], gate, served)
    for item in fixture["key_encoding"]:
        if tool_key(item["name"]) != item["key"]:
            raise VerificationError("tool-map key differs from the contributor vector")
    results = []
    for vector in fixture["vectors"]:
        jws = fixture["attestation"]["jws"] if vector["jws"] == "reference" else vector["jws"]
        axes = verify_tool_grade(jws, fixture["issuer"]["jwk"], ToolGate(**vector["gate"])).axes()
        if axes != vector["expect"]:
            raise VerificationError("consumer axes differ from the original vector expectation")
        results.append({"name": vector["name"], "axes": axes, "nativeWriteEvents": 0})
    return results


def _report(binding: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, Any]:
    return {"profile": binding["profile"], "contributor": "kenneives / AgentAvow",
            "sourceCommit": SOURCE_COMMIT, "fixtureSha256": FIXTURE_SHA256,
            "historicalFixtureReplay": True, "results": results,
            "runEvaluationTime": binding["runEvaluationTime"],
            "runGradeAxes": binding["runGradeAxes"],
            "remoteExecution": "not-observed", "actionSafety": "not-established"}


def run(directory: Path, fixture_path: Path = FIXTURE, *, now: datetime | None = None) -> dict[str, Any]:
    """Replay the fixture and retain only its positive historical binding locally."""
    fixture = load_fixture(fixture_path)
    results = _fixture_results(fixture)
    positive = next(v for v in fixture["vectors"] if v["name"] == "tool-match")
    served = next(t for t in fixture["observed_tools"] if t["name"] == positive["gate"]["tool_name"])
    jws = fixture["attestation"]["jws"]
    run_time = (now or datetime.now(UTC)).isoformat()
    binding = _binding(fixture, positive, jws, served, run_time)
    directory.mkdir()
    local, pins = _retain(directory / "tool-match", binding)
    results[0].update(local)
    for result in results[1:]:
        (directory / result["name"]).mkdir()
        _save(directory / result["name"] / "refusal.json", result)
    report = _report(binding, results)
    _save(directory / "results.json", report)
    verify_run(directory, fixture_path, consumer_pins=pins)
    return report


def verify_run(directory: Path, fixture_path: Path = FIXTURE, *, consumer_pins: dict[str, Any]) -> dict[str, Any]:
    """Recheck the recorded assessment and refuse changed bytes, requests or source."""
    fixture = load_fixture(fixture_path)
    results = _fixture_results(fixture)
    positive = fixture["vectors"][0]
    served = fixture["observed_tools"][0]
    report = json.loads((directory / "results.json").read_bytes())
    binding = _binding(fixture, positive, fixture["attestation"]["jws"], served, report["runEvaluationTime"])
    local = _verify_retention(directory / "tool-match", binding, consumer_pins)
    for result in results[1:]:
        case = directory / result["name"]
        if (case / "refusal.json").read_bytes() != canonical(result) or set(case.iterdir()) != {case / "refusal.json"}:
            raise VerificationError("refused case contains changed bytes or a local effect")
    results[0].update({"nativeWriteEvents": 1, "replayed": False, "localEffect": binding["localEffect"],
                       "remoteExecution": "not-observed"})
    if (directory / "results.json").read_bytes() != canonical(_report(binding, results)):
        raise VerificationError("retained report differs from the recomputed case results")
    return {"status": "retained-local-binding-checked", **local, "runEvaluationTime": binding["runEvaluationTime"],
            "runGradeAxes": binding["runGradeAxes"],
            "actionSafety": "not-established"}


def main() -> None:
    """Run or check the local example; preserve refusal output and a nonzero exit."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--fixture", type=Path, default=FIXTURE)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--consumer-pins", type=Path, help="Original public selection retained before the local write")
    args = parser.parse_args()
    if args.verify:
        if args.consumer_pins is None:
            parser.error("--verify needs --consumer-pins selected outside the candidate bundle")
        pins = json.loads(args.consumer_pins.read_bytes())
        result = verify_run(args.directory, args.fixture, consumer_pins=pins)
    else:
        result = run(args.directory, args.fixture)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
