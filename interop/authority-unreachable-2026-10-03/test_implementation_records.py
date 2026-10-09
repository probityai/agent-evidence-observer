"""Checks over the three implementations' published records, with a refusal control for each."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from implementation_records import check_upstream, read_alakris, read_all, read_mintid, read_proofable, verify_sources
from producer import produce
from reader import read_run

RECORDS = Path(__file__).resolve().parent / "implementation-records"
MINTID_JSONL = "revocation-trace-testnet-20261006T073712Z.jsonl"
MINTID_MANIFEST = "revocation-trace-testnet-20261006T073712Z.manifest.json"
PROOFABLE_KNOWN_FAILURES = ["proofable-sha256sums-trace.jsonl", "proofable-manifest-trace-digest",
                            "proofable-denials-carry-reason", "proofable-post-dispatch-deny-point-observed"]


def result(row: dict, check_id: str) -> str:
    """Return one check's result, failing the test if the check is absent."""
    matches = [check["result"] for check in row["checks"] if check["id"] == check_id]
    assert len(matches) == 1, check_id
    return matches[0]


@pytest.fixture
def records(tmp_path):
    """Give each refusal control its own writable copy of the pinned records."""
    target = tmp_path / "records"
    shutil.copytree(RECORDS, target)
    return target


def edit_json(path: Path, change) -> None:
    """Rewrite a JSON file after applying an in-place change."""
    data = json.loads(path.read_bytes())
    change(data)
    path.write_text(json.dumps(data), encoding="utf-8")


def edit_jsonl(path: Path, change) -> None:
    """Rewrite a JSONL file after applying a change to its parsed events."""
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    events = change(events)
    path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")


@pytest.fixture(scope="module")
def reference_report(tmp_path_factory):
    """Produce and read this profile's eighteen cases once for the rerun comparison."""
    run = tmp_path_factory.mktemp("reference") / "run"
    produce(run, "local-uncommitted")
    report = read_run(run, json.loads((run / "consumer-pins.json").read_text()))
    path = run / "reader-report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


class TestPinnedRecords:
    def test_vendored_bytes_match_sources(self):
        checks = verify_sources(RECORDS)
        assert checks.failed() == [] and len(checks.rows) == 21

    def test_mintid_trace_rederives_every_manifest_claim(self):
        row = read_mintid(RECORDS / "mintid")
        assert row["failed"] == []
        paths = {(p["path"], p["agent"]): p for p in row["contract"]["temporalRevocation"]}
        assert {k: p["firstRefusalSecondsAfterTrigger"] for k, p in paths.items()} == {
            ("issuer", "agent_issuer"): 9.3, ("kill_switch", "agent_kill_switch"): 36.8,
            ("cascade", "cascade_agent_1"): 156.1, ("cascade", "cascade_agent_2"): 35.1,
            ("emergency", "agent_emergency"): 4.5}
        assert paths[("issuer", "agent_issuer")]["firstRefusalAlsoRefusedNeverRevokedControl"] is True
        assert row["contract"]["presentationLifetime"]["seconds"] == 10
        assert row["contract"]["presentationLifetime"]["inRecord"] is False
        assert [p["requiredDenyPoint"]["boundSeconds"] for p in paths.values()] == [185, 245, 395, 395, 0]

    def test_proofable_package_fails_exactly_its_four_contradictions(self):
        row = read_proofable(RECORDS / "proofable")
        assert row["failed"] == PROOFABLE_KNOWN_FAILURES
        digest = next(c for c in row["checks"] if c["id"] == "proofable-manifest-trace-digest")
        assert digest["detail"] == "published digest is the CRLF form; published bytes use LF"
        assert result(row, "proofable-receipt-envelope-verified") == "not-performed"

    def test_alakris_rerun_matches_this_profile(self, reference_report):
        row = read_alakris(RECORDS / "alakris", reference_report, None)
        assert row["failed"] == []
        assert result(row, "alakris-rerun-reproduced") == "pass"
        rerun = next(c for c in row["checks"] if c["id"] == "alakris-rerun-reproduced")
        assert rerun["detail"].startswith("18 of 18 cases match the 2026-10-04 operator rerun")
        assert rerun["detail"].endswith("added after that rerun, not rerun by the implementer: delegation-hop-amplified")
        assert result(row, "alakris-discriminator-reproduced") == "not-performed"
        assert row["contract"]["originalTests"] == {"tests": 37, "failed": 2, "passed": 35}
        assert row["contract"]["lostResponse"]["referenceShape"] == {
            "effectObserved": True, "taskTerminal": "failed", "publicationReady": False}

    def test_unsupplied_reports_are_not_reported_as_passes(self):
        report = read_all(RECORDS)
        alakris = report["implementations"][2]
        assert {c["id"]: c["result"] for c in alakris["checks"] if c["result"] != "pass"} == {
            "alakris-rerun-reproduced": "not-performed", "alakris-discriminator-reproduced": "not-performed"}


class TestRefusalControls:
    def test_changed_vendored_byte_fails_sources(self, records):
        path = records / "mintid" / MINTID_JSONL
        path.write_bytes(path.read_bytes().replace(b"agent_issuer", b"agent_issuex", 1))
        assert "sources-mintid-" + MINTID_JSONL in verify_sources(records).failed()
        assert "mintid-digest-" + MINTID_JSONL in read_mintid(records / "mintid")["failed"]

    def test_missing_vendored_file_fails_completeness(self, records):
        (records / "proofable" / "README.md").unlink()
        assert "sources-proofable-complete" in verify_sources(records).failed()

    def test_acceptance_after_first_refusal_fails(self, records):
        def accept_late(events):
            first = next(e for e in events if e["kind"] == "decision" and e["agent"] == "agent_issuer"
                         and e["accepted"] is False)
            late = {**first, "utc": "2026-10-06T07:39:40.000Z", "session_id": "late", "accepted": True,
                    "reason_code": "accepted"}
            return events + [late, {"kind": "decision_log_line", "session_id": "late",
                                    "line": {"accepted": True, "reason_code": "accepted", "condition": 9}}]
        edit_jsonl(records / "mintid" / MINTID_JSONL, accept_late)
        assert "mintid-issuer:agent_issuer-stays-denied" in read_mintid(records / "mintid")["failed"]

    def test_refusal_past_bound_fails(self, records):
        def tighten(manifest):
            manifest["paths"][1]["bound_seconds"] = 30
        edit_json(records / "mintid" / MINTID_MANIFEST, tighten)
        assert "mintid-kill_switch:agent_kill_switch-within-bound" in read_mintid(records / "mintid")["failed"]

    def test_emergency_refusal_after_next_block_fails(self, records):
        def earlier_root(manifest):
            manifest["paths"][4]["root_carrying_revocation"]["finalized_height"] = 68090
        edit_json(records / "mintid" / MINTID_MANIFEST, earlier_root)
        assert "mintid-emergency:agent_emergency-within-bound" in read_mintid(records / "mintid")["failed"]

    def test_manifest_first_refusal_that_jsonl_contradicts_fails(self, records):
        def claim_sooner(manifest):
            manifest["paths"][0]["first_refused"]["seconds_after_t0"] = 2.0
        edit_json(records / "mintid" / MINTID_MANIFEST, claim_sooner)
        assert "mintid-issuer:agent_issuer-first-refusal" in read_mintid(records / "mintid")["failed"]

    def test_trigger_that_contradicts_manifest_t0_fails(self, records):
        def move_trigger(events):
            for event in events:
                if event["kind"] == "trigger" and event["path"] == "issuer":
                    event["response_utc"] = "2026-10-06T07:38:40.000Z"
            return events
        edit_jsonl(records / "mintid" / MINTID_JSONL, move_trigger)
        assert "mintid-issuer:agent_issuer-t0" in read_mintid(records / "mintid")["failed"]

    def test_decision_log_disagreement_fails(self, records):
        def disagree(events):
            for event in events:
                if event["kind"] == "decision_log_line":
                    event["line"]["reason_code"] = "proof_invalid"
                    break
            return events
        edit_jsonl(records / "mintid" / MINTID_JSONL, disagree)
        failed = read_mintid(records / "mintid")["failed"]
        assert "mintid-decision-log-agrees" in failed

    def test_manifest_decision_not_in_jsonl_fails(self, records):
        def drop(manifest):
            manifest["decisions"].pop()
        edit_json(records / "mintid" / MINTID_MANIFEST, drop)
        assert "mintid-manifest-decisions-rebuild" in read_mintid(records / "mintid")["failed"]

    def test_unattributed_refusal_fails(self, records):
        edit_jsonl(records / "mintid" / MINTID_JSONL,
                   lambda events: [e for e in events if not (e["kind"] == "holder_refresh" and e["agent"] == "agent_kill_switch")])
        assert "mintid-kill_switch:agent_kill_switch-attributed" in read_mintid(records / "mintid")["failed"]

    def test_crlf_trace_satisfies_the_published_digest(self, records):
        path = records / "proofable" / "trace.jsonl"
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
        row = read_proofable(records / "proofable")
        assert result(row, "proofable-sha256sums-trace.jsonl") == "pass"
        assert result(row, "proofable-manifest-trace-digest") == "pass"

    def test_reasoned_denials_pass(self, records):
        path = records / "proofable" / "trace.jsonl"
        lines = path.read_text(encoding="utf-8").splitlines()
        records_ = [json.loads(line) for line in lines]
        for record in records_:
            if record["case_id"] == "stale_authority":
                record["observed"]["code"] = "DELEGATION_PROOF_DENIED"
        path.write_text("".join(json.dumps(r) + "\n" for r in records_), encoding="utf-8")
        assert result(read_proofable(records / "proofable"), "proofable-denials-carry-reason") == "pass"

    @pytest.mark.parametrize("position", ["before", "after"])
    @pytest.mark.parametrize("decision", ["ALLOW", "DENY"])
    def test_same_delegation_does_not_establish_revocation_order(self, records, position, decision):
        path = records / "proofable" / "trace.jsonl"
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        post = next(r for r in rows if r["case_id"] == "post_dispatch_revoke")
        dispatch = {"case_id": "another_dispatch", "observed": {"dispatch_decision": decision, "code": "REVOKED"},
                    "delegation_qHash": post["delegation_qHash"], "terminal_receipt": None}
        rows.insert(0 if position == "before" else len(rows), dispatch)
        path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        row = read_proofable(records / "proofable")
        assert result(row, "proofable-post-dispatch-deny-point-observed") == "fail"
        assert "no revocation event time or dispatch sequence" in row["contract"]["temporalRevocation"]

    def test_missing_delegation_hash_does_not_establish_revocation_order(self, records):
        def remove_hashes(rows):
            for row in rows:
                row.pop("delegation_qHash", None)
            return rows
        edit_jsonl(records / "proofable" / "trace.jsonl", remove_hashes)
        assert result(read_proofable(records / "proofable"), "proofable-post-dispatch-deny-point-observed") == "fail"

    def test_unreachable_case_is_selected_by_identity(self, records):
        edit_json(records / "proofable" / "authority-effect-results.json",
                  lambda document: document["cases"].reverse())
        assert read_proofable(records / "proofable")["contract"]["unreachableAuthority"] == "NOT_APPLICABLE_CURRENT_PATH"

    def test_absent_unreachable_case_does_not_select_another_result(self, records):
        def remove_case(document):
            document["cases"] = [case for case in document["cases"] if case["case_id"] != "unreachable"]
        edit_json(records / "proofable" / "authority-effect-results.json", remove_case)
        assert read_proofable(records / "proofable")["contract"]["unreachableAuthority"] is None

    @pytest.mark.parametrize("reverse", [False, True])
    def test_conflicting_duplicate_case_summaries_are_refused(self, records, reverse):
        def duplicate_case(document):
            unreachable = next(case for case in document["cases"] if case["case_id"] == "unreachable")
            document["cases"].append({**unreachable, "result": "SUPPORTED"})
            if reverse:
                document["cases"].reverse()
        edit_json(records / "proofable" / "authority-effect-results.json", duplicate_case)
        with pytest.raises(ValueError, match="duplicate Proofable result case_id: unreachable"):
            read_proofable(records / "proofable")

    def test_rerun_that_differs_from_this_profile_fails(self, records, reference_report, tmp_path):
        ours = json.loads(reference_report.read_bytes())
        lost = next(row for row in ours["results"] if row["caseId"] == "effect-committed-response-lost")
        lost["publicationReady"] = True
        changed = tmp_path / "changed.json"
        changed.write_text(json.dumps(ours), encoding="utf-8")
        assert "alakris-rerun-reproduced" in read_alakris(records / "alakris", changed, None)["failed"]

    def test_discriminator_that_differs_fails(self, records, tmp_path):
        theirs = json.loads((records / "alakris" / "source-discriminator-report.json").read_bytes())
        theirs["results"][3]["fingerprintChanged"] = True
        changed = tmp_path / "discriminator.json"
        changed.write_text(json.dumps(theirs), encoding="utf-8")
        assert "alakris-discriminator-reproduced" in read_alakris(records / "alakris", None, changed)["failed"]

    def test_upstream_bytes_that_differ_fail(self):
        sources = json.loads((RECORDS / "SOURCES.json").read_bytes())
        local = {pin["url"]: (RECORDS / key / name).read_bytes()
                 for key, entry in sources["implementations"].items() for name, pin in entry["files"].items()}
        assert check_upstream(RECORDS, local.__getitem__).failed() == []
        moved = next(url for url in local if url.endswith("trace.jsonl"))
        changed = {**local, moved: local[moved] + b"\n"}
        assert check_upstream(RECORDS, changed.__getitem__).failed() == ["upstream-proofable-trace.jsonl"]

    def test_renamed_mintid_record_still_needs_a_matching_manifest(self, records):
        directory = records / "mintid"
        for path in directory.glob("revocation-trace-testnet-20261006T073712Z.*"):
            path.rename(directory / path.name.replace("20261006T073712Z", "20261107T000000Z"))
        row = read_mintid(directory)
        assert row["failed"] == ["mintid-record-name", "mintid-digest-" + MINTID_JSONL,
                                 "mintid-digest-revocation-trace-testnet-20261006T073712Z.md"]

    def test_two_mintid_manifests_are_refused(self, records):
        directory = records / "mintid"
        shutil.copy(directory / MINTID_MANIFEST, directory / "second.manifest.json")
        with pytest.raises(ValueError, match="exactly one"):
            read_mintid(directory)

    def test_alakris_report_that_differs_from_its_checksum_fails(self, records):
        path = records / "alakris" / "source-discriminator-report.json"
        path.write_bytes(path.read_bytes() + b"\n")
        failed = read_alakris(records / "alakris", None, None)["failed"]
        assert failed == ["alakris-sha256sums-source-discriminator-report.json"]

    def test_alakris_source_pin_change_fails(self, records):
        def repin(manifest):
            manifest["files"][0]["sha256"] = "0" * 64
        edit_json(records / "alakris" / "source-manifest.json", repin)
        assert "alakris-source-pin" in read_alakris(records / "alakris", None, None)["failed"]
