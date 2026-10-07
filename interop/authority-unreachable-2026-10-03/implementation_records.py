"""Read each implementation's published records against the comparison contract.

Every check re-derives its answer from the implementation's own raw bytes:
JSONL events, checksum files and run reports. Summaries and manifests are
compared against that derivation rather than trusted. A check either passes,
fails with the exact contradiction, or is reported as not performed with the
reason; a check that could not run is never reported as a pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

SCHEMA = "authority-unreachable-implementation-records/1"
SOURCES_SCHEMA = "authority-unreachable-implementation-sources/1"
MINTID_MANIFEST_SCHEMA = "mintid-trace-manifest/2"
MINTID_PRESENTATION_LIFETIME = {
    "seconds": 10,
    "evidenceClass": "source-inspection",
    "source": "identity-proof-core/holder/src/lib.rs PRESENTATION_LIFETIME_SECONDS at public-v2026-10-07",
    "inRecord": False,
}
ALAKRIS_SOURCE_SHA256 = "3a928ff97f2eb13d2138809d1aebbacd645a07210663d74e2d77bae7fa1002df"
ALAKRIS_SOURCE_FILE = "core/agent-core/src/core/content/publication_jobs.py"
REFERENCE_PROJECTION = ("caseId", "effectObserved", "effectStatus", "nativeRevision", "nativePhase",
                        "nativeRevoked", "authorityStatus", "taskTerminal", "publicationReady",
                        "attemptCount", "dispatchDecisions")


@dataclass
class Checks:
    """Ordered check results for one implementation row."""

    rows: list[dict[str, Any]] = field(default_factory=list)

    def add(self, check_id: str, passed: bool, detail: str) -> bool:
        """Record a performed check and return its outcome."""
        self.rows.append({"id": check_id, "result": "pass" if passed else "fail", "detail": detail})
        return passed

    def skip(self, check_id: str, reason: str) -> None:
        """Record a check that could not be performed, with its reason."""
        self.rows.append({"id": check_id, "result": "not-performed", "detail": reason})

    def failed(self) -> list[str]:
        """Return the identifiers of failed checks."""
        return [row["id"] for row in self.rows if row["result"] == "fail"]


def sha256(data: bytes) -> str:
    """Return the hexadecimal SHA-256 of exact bytes."""
    return hashlib.sha256(data).hexdigest()


def unix(stamp: str) -> float:
    """Convert a record's ISO-8601 UTC timestamp to Unix seconds."""
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()


def verify_sources(root: Path) -> Checks:
    """Require every vendored file to match the size and digest pinned in SOURCES.json."""
    checks = Checks()
    sources = json.loads((root / "SOURCES.json").read_bytes())
    checks.add("sources-schema", sources.get("schema") == SOURCES_SCHEMA, f"schema {sources.get('schema')}")
    for key, entry in sorted(sources["implementations"].items()):
        present = {path.name for path in (root / key).iterdir() if path.name != ".gitattributes"}
        checks.add(f"sources-{key}-complete", present == set(entry["files"]),
                   f"{len(entry['files'])} pinned, {len(present)} present")
        for name, pin in sorted(entry["files"].items()):
            data = (root / key / name).read_bytes() if (root / key / name).is_file() else b""
            checks.add(f"sources-{key}-{name}", sha256(data) == pin["sha256"] and len(data) == pin["bytes"],
                       f"{pin['url']} sha256 {sha256(data)[:16]}")
    return checks


def check_upstream(root: Path, fetch=None) -> Checks:
    """Re-fetch every pinned URL and require its bytes to equal the vendored copy."""
    import urllib.request

    fetch = fetch or (lambda url: urllib.request.urlopen(url, timeout=60).read())
    checks = Checks()
    sources = json.loads((root / "SOURCES.json").read_bytes())
    for key, entry in sorted(sources["implementations"].items()):
        for name, pin in sorted(entry["files"].items()):
            remote = fetch(pin["url"])
            checks.add(f"upstream-{key}-{name}", sha256(remote) == pin["sha256"], pin["url"])
    return checks


def _mintid_events(raw: bytes) -> list[dict[str, Any]]:
    """Parse the MintID JSONL trace strictly, one object per line."""
    return [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]


def _mintid_decisions(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Join each decision with the verifier's own decision-log line by session."""
    lines = {event["session_id"]: event["line"] for event in events if event["kind"] == "decision_log_line"}
    joined = []
    for event in (e for e in events if e["kind"] == "decision"):
        line = lines.get(event["session_id"], {})
        joined.append({"utc": event["utc"], "path": event["path"], "agent": event["agent"],
                       "attempt": event["attempt"], "accepted": event["accepted"],
                       "reason_code": event["reason_code"], "condition": line.get("condition"),
                       "root_epoch": line.get("root_epoch"), "root_height": line.get("root_height"),
                       "root_age_seconds": line.get("root_age_seconds"),
                       "chain_height_after": event.get("chain_height_after"),
                       "logAgrees": line.get("accepted") == event["accepted"]
                       and line.get("reason_code") == event["reason_code"]})
    return joined


def _mintid_t0(path: dict[str, Any], triggers: dict[str, dict[str, Any]]) -> float | None:
    """Re-derive a path's trigger instant from the trigger event, per the manifest's definition."""
    trigger = triggers.get(path["path"], {})
    if path["path"] in {"issuer", "emergency"}:
        return unix(trigger["response_utc"]) if "response_utc" in trigger else None
    if path["path"] == "kill_switch":
        return unix(trigger["recorded_utc"]) if "recorded_utc" in trigger else None
    root = path.get("root_carrying_revocation") or {}
    return float(root["generated_at_unix"]) if "generated_at_unix" in root else None


def _mintid_path(path: dict[str, Any], decisions: list[dict[str, Any]], triggers: dict[str, dict[str, Any]],
                 refreshes: dict[str, str], checks: Checks) -> dict[str, Any]:
    """Check one revocation path's first refusal, bound, monotonic denial and attribution."""
    agent = path.get("agent") or (path.get("attribution") or {}).get("revoked", {}).get("agent")
    name = f"{path['path']}:{agent}"
    t0 = _mintid_t0(path, triggers)
    checks.add(f"mintid-{name}-t0", t0 is not None and abs(t0 - path["t0_unix"]) < 0.01,
               f"trigger-derived t0 {t0} against manifest {path['t0_unix']}")
    own = [d for d in decisions if d["path"] == path["path"] and d["agent"] == agent]
    refused = next((d for d in own if not d["accepted"] and d["attempt"] != "baseline"), None)
    if not checks.add(f"mintid-{name}-refused", refused is not None, "a forced presentation was refused"):
        return {"path": path["path"], "agent": agent}
    seconds = round(unix(refused["utc"]) - path["t0_unix"], 1)
    checks.add(f"mintid-{name}-first-refusal", seconds == path["first_refused"]["seconds_after_t0"],
               f"derived +{seconds} s against manifest +{path['first_refused']['seconds_after_t0']} s")
    later = [d for d in own if unix(d["utc"]) > unix(refused["utc"]) and d["accepted"]]
    checks.add(f"mintid-{name}-stays-denied", not later, f"{len(later)} acceptances after the first refusal")
    if path["path"] == "emergency":
        root_height = path["root_carrying_revocation"]["finalized_height"]
        checks.add(f"mintid-{name}-within-bound", refused["chain_height_after"] <= root_height + 1,
                   f"refused at head {refused['chain_height_after']}, emergency root in block {root_height}")
    else:
        checks.add(f"mintid-{name}-within-bound", seconds <= path["bound_seconds"],
                   f"+{seconds} s against the {path['bound_seconds']} s bound ({path['bound_formula']})")
    revoked_refresh = refreshes.get(agent)
    checks.add(f"mintid-{name}-attributed", revoked_refresh == "credential_revoked",
               f"holder refresh outcome {revoked_refresh}")
    control = (path.get("attribution") or {}).get("control") or {}
    rollover = bool(control) and control["refused"]["decision_log"]["root_epoch"] == refused["root_epoch"]
    accepted_before = [d for d in own if d["accepted"] and unix(d["utc"]) < unix(refused["utc"])]
    return {"path": path["path"], "agent": agent, "triggerUnix": path["t0_unix"],
            "triggerDefinition": path["t0_definition"],
            "lastAcceptedSecondsAfterTrigger": round(unix(accepted_before[-1]["utc"]) - path["t0_unix"], 1)
            if accepted_before and unix(accepted_before[-1]["utc"]) >= path["t0_unix"] else None,
            "firstRefusalSecondsAfterTrigger": seconds,
            "firstRefusal": {k: refused[k] for k in ("reason_code", "condition", "root_epoch", "root_height")},
            "requiredDenyPoint": {"boundSeconds": path["bound_seconds"], "formula": path["bound_formula"]},
            "revocationAttributedBy": "holder refresh refused credential_revoked" if revoked_refresh else None,
            "firstRefusalAlsoRefusedNeverRevokedControl": rollover}


def read_mintid(directory: Path) -> dict[str, Any]:
    """Map the MintID testnet trace onto the contract and re-derive its manifest claims."""
    checks = Checks()
    manifests = sorted(directory.glob("*.manifest.json"))
    if len(manifests) != 1:
        raise ValueError(f"expected exactly one MintID trace manifest in {directory}, found {len(manifests)}")
    record = manifests[0].name.removesuffix(".manifest.json")
    raw = (directory / f"{record}.jsonl").read_bytes()
    manifest = json.loads(manifests[0].read_bytes())
    checks.add("mintid-record-name", manifest["record"] == record, f"manifest names {manifest['record']}")
    checks.add("mintid-manifest-schema", manifest["schema"] == MINTID_MANIFEST_SCHEMA and manifest["derived"] is False,
               f"{manifest['schema']} derived={manifest['derived']}")
    for name, digest in sorted(manifest["files"].items()):
        present = (directory / name).is_file()
        checks.add(f"mintid-digest-{name}", present and sha256((directory / name).read_bytes()) == digest,
                   f"manifest {digest[:16]}" if present else "file named by the manifest is absent")
    events = _mintid_events(raw)
    decisions = _mintid_decisions(events)
    checks.add("mintid-decision-log-agrees", all(d["logAgrees"] for d in decisions),
               f"{sum(not d['logAgrees'] for d in decisions)} decisions differ from the verifier log line")
    projected = [{k: d[k] for k in ("utc", "path", "agent", "attempt", "accepted", "reason_code", "condition",
                                    "root_epoch", "root_height", "root_age_seconds")} for d in decisions]
    checks.add("mintid-manifest-decisions-rebuild", projected == manifest["decisions"],
               f"{len(projected)} decisions derived from JSONL, {len(manifest['decisions'])} in the manifest")
    triggers = {e["path"]: e for e in events if e["kind"] == "trigger"}
    refreshes = {e["agent"]: e["outcome"] for e in events if e["kind"] == "holder_refresh" and e["outcome"] != "refreshed"}
    paths = [_mintid_path(p, decisions, triggers, refreshes, checks) for p in manifest["paths"]]
    deployment = manifest["deployment"]
    return {
        "implementation": "MintID",
        "evidenceClass": "implementation-owned-runtime-trace",
        "custody": "author-operated public testnet; not independently reproduced",
        "contract": {
            "implementationAndSource": {"release": manifest["source"]["public_tags"],
                                        "sourceRevision": manifest["source"]["revision"],
                                        "trackedChanges": manifest["source"]["tracked_changes"]},
            "authorityEvidence": {"source": "issuer status root on chain, proven at the decision",
                                  "maxRootAgeSeconds": deployment["max_root_age_seconds"],
                                  "heartbeatSeconds": deployment["heartbeat_seconds"],
                                  "chainId": deployment["chain_id"], "policySha256": manifest["policy"]["sha256"]},
            "presentationLifetime": MINTID_PRESENTATION_LIFETIME,
            "temporalRevocation": paths,
            "dispatchDecision": "accept or refuse with reason code and deciding condition; no indeterminate",
            "observedEffect": "not applicable: no executor; ends at the relying party's decision",
            "taskAndRecovery": "not applicable for the task; control recovery after refresh is measured",
            "lostResponse": "outside the implementation: committed effect belongs to the relying party",
            "plannedOrUnavailable": {"fundedRecourse": "planned", "subDelegation": "unavailable"},
        },
        "checks": checks.rows,
        "failed": checks.failed(),
    }


def _sums(directory: Path) -> dict[str, str]:
    """Parse a sha256sum-format file into name to digest."""
    rows = {}
    for line in (directory / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        if line.strip():
            digest, name = line.split(maxsplit=1)
            rows[name.lstrip("*")] = digest
    return rows


def _crlf_diagnosis(data: bytes, expected: str) -> str:
    """Name the line-ending form whose digest matches a published one, if any."""
    lf = data.replace(b"\r\n", b"\n")
    if sha256(lf.replace(b"\n", b"\r\n")) == expected:
        return "published digest is the CRLF form; published bytes use LF"
    if sha256(lf) == expected:
        return "published digest is the LF form; published bytes use CRLF"
    return "no line-ending form of the published bytes matches"


def _unique_case_results(cases: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Reject ambiguous case summaries before selecting or projecting their fields."""
    by_id = {}
    for case in cases:
        case_id = case["case_id"]
        if case_id in by_id:
            raise ValueError(f"duplicate Proofable result case_id: {case_id}")
        by_id[case_id] = case
    return by_id


def read_proofable(directory: Path) -> dict[str, Any]:
    """Map the Proofable package onto the contract and test each claim against its trace."""
    checks = Checks()
    manifest = json.loads((directory / "manifest.json").read_bytes())
    results = json.loads((directory / "authority-effect-results.json").read_bytes())
    cases = _unique_case_results(results["cases"])
    trace_bytes = (directory / "trace.jsonl").read_bytes()
    for name, digest in sorted(_sums(directory).items()):
        data = (directory / name).read_bytes()
        ok = sha256(data) == digest
        checks.add(f"proofable-sha256sums-{name}", ok, "matches" if ok else _crlf_diagnosis(data, digest))
    published = manifest["public_trace"]["sha256"]
    checks.add("proofable-manifest-trace-digest", sha256(trace_bytes) == published,
               "matches" if sha256(trace_bytes) == published else _crlf_diagnosis(trace_bytes, published))
    trace = [json.loads(line) for line in trace_bytes.decode("utf-8").splitlines() if line.strip()]
    checks.add("proofable-trace-count", len(trace) == manifest["public_trace"]["record_count"],
               f"{len(trace)} records, manifest says {manifest['public_trace']['record_count']}")
    denials = [r for r in trace if r["observed"].get("dispatch_decision") == "DENY"]
    checks.add("proofable-denials-carry-reason", all(r["observed"].get("code") for r in denials),
               "denied without a reason code: " + ", ".join(r["case_id"] for r in denials if not r["observed"].get("code")))
    # This published schema contains neither a revocation event nor dispatch ordering.
    # Matching a delegation hash or moving a line cannot establish the required boundary.
    revocation_detail = (
        "the stated deny point is the next dispatch after revocation; the published schema "
        "provides no revocation event time or dispatch sequence, so that boundary is not observed"
    )
    checks.add("proofable-post-dispatch-deny-point-observed", False, revocation_detail)
    receipts = [r["terminal_receipt"] for r in trace if r.get("terminal_receipt")]
    public = [r for r in receipts if r.get("visibility") != "private"]
    if public:
        checks.add("proofable-receipts-public", True, f"{len(public)} public receipts")
    else:
        checks.skip("proofable-receipt-envelope-verified",
                    f"all {len(receipts)} terminal receipts are private; only their qHash is published, "
                    "so the CAIP-380 envelope check the manifest names cannot run from the package")
    effects = {case_id: case["observed_effect"]["state"] for case_id, case in cases.items()}
    unreachable = cases.get("unreachable")
    return {
        "implementation": "Proofable",
        "evidenceClass": "implementation-owned-runtime-results",
        "custody": manifest["custody"],
        "contract": {
            "implementationAndSource": {"deployedRevision": manifest["deployed_revision"], "runId": manifest["run_id"],
                                        "sourceRecordVisibility": manifest["source_record_visibility"]},
            "authorityEvidence": {"source": "local authority state evaluated at dispatch",
                                  "policyDigest": manifest["reader_appraisal"]["policy_digest"]},
            "dispatchDecision": {case_id: case["dispatch_decision"]["decision"] for case_id, case in cases.items()},
            "observedEffect": effects,
            "temporalRevocation": revocation_detail,
            "unreachableAuthority": unreachable["result"] if unreachable is not None else None,
            "lostResponse": "not exercised in the published package",
        },
        "checks": checks.rows,
        "failed": checks.failed(),
    }


def _junit_counts(path: Path) -> dict[str, int]:
    """Count tests, failures and errors from a JUnit report without trusting its summary."""
    cases = list(ElementTree.parse(path).getroot().iter("testcase"))
    failed = sum(1 for case in cases if case.find("failure") is not None or case.find("error") is not None)
    return {"tests": len(cases), "failed": failed, "passed": len(cases) - failed}


def _projection(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Keep the reader fields that do not depend on per-run keys or digests."""
    return {row["caseId"]: {k: row.get(k) for k in REFERENCE_PROJECTION} for row in report["results"]}


def read_alakris(directory: Path, reference_report: Path | None, discriminator_report: Path | None) -> dict[str, Any]:
    """Map the Alakris package and its rerun of this profile onto the contract."""
    checks = Checks()
    for name, digest in sorted(_sums(directory).items()):
        checks.add(f"alakris-sha256sums-{name}", sha256((directory / name).read_bytes()) == digest, digest[:16])
    source = {row["path"]: row["sha256"] for row in json.loads((directory / "source-manifest.json").read_bytes())["files"]}
    checks.add("alakris-source-pin", source.get(ALAKRIS_SOURCE_FILE) == ALAKRIS_SOURCE_SHA256,
               f"{ALAKRIS_SOURCE_FILE} {source.get(ALAKRIS_SOURCE_FILE, 'absent')[:16]}")
    theirs = json.loads((directory / "reader-report.json").read_bytes())
    if reference_report is None:
        checks.skip("alakris-rerun-reproduced", "no reader report from this run was supplied")
    else:
        ours = _projection(json.loads(reference_report.read_bytes()))
        differing = sorted(k for k in set(ours) | set(_projection(theirs)) if ours.get(k) != _projection(theirs).get(k))
        checks.add("alakris-rerun-reproduced", not differing,
                   f"{len(ours) - len(differing)} of {len(ours)} cases match the 2026-10-04 operator rerun"
                   + (f"; differing: {', '.join(differing)}" if differing else ""))
    theirs_discriminator = json.loads((directory / "source-discriminator-report.json").read_bytes())
    if discriminator_report is None:
        checks.skip("alakris-discriminator-reproduced", "no discriminator report from this run was supplied")
    else:
        ours_discriminator = json.loads(discriminator_report.read_bytes())
        checks.add("alakris-discriminator-reproduced", ours_discriminator["results"] == theirs_discriminator["results"],
                   "six controlled fingerprint inputs")
    native = _junit_counts(directory / "native-tests.xml")
    lost = next(row for row in theirs["results"] if row["caseId"] == "effect-committed-response-lost")
    return {
        "implementation": "Alakris",
        "evidenceClass": "source package, original tests and a rerun of this profile; no deployed-path trace",
        "custody": "author-operated",
        "contract": {
            "implementationAndSource": {"sourceCommit": "68054425873b9b373ce07359f8e994b817bee210",
                                        "publicationJobsSha256": source.get(ALAKRIS_SOURCE_FILE)},
            "approvedAction": {row["caseId"]: row["fingerprintChanged"] for row in theirs_discriminator["results"]},
            "originalTests": native,
            "dispatchDecision": "not measured on the deployed path",
            "observedEffect": "not measured on the deployed path",
            "lostResponse": {"referenceShape": {"effectObserved": lost["effectObserved"],
                                                "taskTerminal": lost["taskTerminal"],
                                                "publicationReady": lost["publicationReady"]},
                             "deployedPath": "stated by the implementer: a retry after a lost response can duplicate"},
        },
        "checks": checks.rows,
        "failed": checks.failed(),
    }


def read_all(root: Path, reference_report: Path | None = None,
             discriminator_report: Path | None = None) -> dict[str, Any]:
    """Return the comparison record for all three implementations, with every check."""
    sources = verify_sources(root)
    rows = [read_mintid(root / "mintid"), read_proofable(root / "proofable"),
            read_alakris(root / "alakris", reference_report, discriminator_report)]
    return {"schema": SCHEMA, "sources": sources.rows, "sourcesFailed": sources.failed(), "implementations": rows}


READERS = {
    "mintid": lambda directory, args: read_mintid(directory),
    "proofable": lambda directory, args: read_proofable(directory),
    "alakris": lambda directory, args: read_alakris(directory, args.reference_report, args.discriminator_report),
}


def main() -> None:
    """Write the implementation-records report selected by the caller."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("records", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--reference-report", type=Path)
    parser.add_argument("--discriminator-report", type=Path)
    parser.add_argument("--check-upstream", action="store_true", help="re-fetch every pinned URL instead")
    parser.add_argument("--only", choices=sorted(READERS),
                        help="read RECORDS as one implementation's own record directory, without SOURCES.json")
    args = parser.parse_args()
    if args.only:
        row = READERS[args.only](args.records, args)
        args.output.write_text(json.dumps(row, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return
    if args.check_upstream:
        upstream = check_upstream(args.records)
        args.output.write_text(json.dumps(upstream.rows, indent=2) + "\n", encoding="utf-8")
        if upstream.failed():
            raise SystemExit("upstream bytes differ from SOURCES.json: " + ", ".join(upstream.failed()))
        return
    report = read_all(args.records, args.reference_report, args.discriminator_report)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if report["sourcesFailed"]:
        raise SystemExit("vendored records differ from SOURCES.json: " + ", ".join(report["sourcesFailed"]))


if __name__ == "__main__":
    main()
