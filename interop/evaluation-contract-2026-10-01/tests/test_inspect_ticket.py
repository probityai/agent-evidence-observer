"""Actual native execution plus selected-pin and cross-artifact controls."""
from __future__ import annotations

import copy
import json
import shutil
import sys
from pathlib import Path

import pytest

pytest.importorskip("inspect_ai")
pytest.importorskip("rfc8785")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import inspect_ticket as bridge
from evaluation_contract import ContractError, decode, encode
from probity_observer.crypto import VerificationError, canonical


@pytest.fixture(scope="module")
def native_packet(tmp_path_factory):
    root = tmp_path_factory.mktemp("native-ticket") / "run"
    report = bridge.run(root, "test-checkout")
    return root, decode((root / "consumer-pins.json").read_bytes()), report


@pytest.fixture
def packet(native_packet, tmp_path):
    source, pins, _ = native_packet
    root = tmp_path / "copy"
    shutil.copytree(source, root)
    return root, copy.deepcopy(pins)


def rewrite(root, pins, name, transform, *, join_http=False):
    """Reselect altered artifact bytes to test semantic joins beyond hash checks."""
    file = root / "artifacts" / name
    value = decode(file.read_bytes())
    transform(value)
    file.write_bytes(encode(value))
    manifest = decode((root / "artifact-manifest.json").read_bytes())
    manifest["artifacts"][name] = bridge.sha(file.read_bytes())
    if name.endswith("-native.json"):
        aid = name.removesuffix("-native.json")
        originals = list((root / "native" / aid).iterdir())
        originals[0].write_bytes(file.read_bytes())
        manifest["bindings"][name.removesuffix("-native.json")]["sha256"] = bridge.sha(file.read_bytes())
    if join_http:
        aid = name.removesuffix("-http.json")
        native_name = aid + "-native.json"
        native_path = root / "artifacts" / native_name
        native = decode(native_path.read_bytes())
        result = canonical({"httpSha256": bridge.sha(file.read_bytes()), "postStatus": value["postStatus"], "nativeRevision": decode(bytes.fromhex(value["getResponseHex"]))["revision"]}).decode()
        sample = native["samples"][0]
        for event in sample["events"]:
            if event.get("event") == "tool":
                event["result"] = result
        for message in sample["messages"]:
            if message["role"] == "tool":
                message["content"] = result
        native_path.write_bytes(encode(native))
        next((root / "native" / aid).iterdir()).write_bytes(native_path.read_bytes())
        manifest["artifacts"][native_name] = bridge.sha(native_path.read_bytes())
        manifest["bindings"][aid]["sha256"] = bridge.sha(native_path.read_bytes())
    manifest_raw = encode(manifest)
    (root / "artifact-manifest.json").write_bytes(manifest_raw)
    pins["artifactManifestSha256"] = bridge.sha(manifest_raw)


def refused(root, pins, reason):
    with pytest.raises((ContractError, VerificationError), match=reason):
        bridge.verify_saved(root, pins)


def test_actual_native_task_authority_and_effect_axes(native_packet):
    root, pins, report = native_packet
    assert bridge.verify_saved(root, pins) == report
    records = {r["attemptId"]: r for r in report["records"]}
    assert len(records) == 6
    assert records["permit-task-fail"]["taskOutcome"] == "fail"
    assert records["permit-task-fail"]["effectOutcome"] == "verified-local-ticket-update"
    assert records["kernel-deny"]["taskOutcome"] == "pass"
    assert records["kernel-deny"]["kernelVerdict"] == "DENY"
    assert records["kernel-deny"]["effectOutcome"] == "not-recorded-local-row"
    assert records["pending-effect"]["effectOutcome"] == "incomplete-no-automatic-replay"
    assert records["model-error-after-effect"]["status"] == "error"
    assert records["model-error-after-effect"]["effectOutcome"] == "verified-local-ticket-update"
    assert records["planned-unstarted"]["status"] == "not-started"
    assert report["independentCustody"] == "not-established"


@pytest.mark.parametrize("name,pin", [("plan-before-run.json", "planSha256"), ("source-manifest-before-run.json", "sourceManifestSha256"), ("artifact-manifest.json", "artifactManifestSha256")])
def test_external_pins_refuse_replaced_inputs(packet, name, pin):
    root, pins = packet
    (root / name).write_bytes(b"{}")
    refused(root, pins, "ticket_external_pin_" + pin)


def test_rehashed_native_score_must_match_original_output(packet):
    root, pins = packet
    rewrite(root, pins, "permit-task-fail-native.json", lambda log: log["samples"][0]["scores"]["match"].update(value="C"))
    refused(root, pins, "ticket_native_score_recomputed")


def test_rehashed_native_tool_argument_refused(packet):
    root, pins = packet
    rewrite(root, pins, "permit-pass-native.json", lambda log: next(e for e in log["samples"][0]["events"] if e.get("event") == "tool")["arguments"].update(content="ALTERED"))
    refused(root, pins, "ticket_native_argument")


def test_rehashed_native_http_link_refused(packet):
    root, pins = packet
    rewrite(root, pins, "permit-pass-native.json", lambda log: next(e for e in log["samples"][0]["events"] if e.get("event") == "tool").update(result="{}"))
    refused(root, pins, "ticket_native_http_join")


def test_original_error_cannot_acquire_score(packet):
    root, pins = packet
    rewrite(root, pins, "model-error-after-effect-native.json", lambda log: log["samples"][0].update(scores={"match": {"value": "C"}}))
    refused(root, pins, "ticket_native_error_score")


@pytest.mark.parametrize("timestamp", [True, "garbage", "2026-10-02T00:00:00", "2020-01-01T00:00:00+00:00"])
def test_native_timestamp_refuses_boolean_malformed_naive_and_backwards(packet, timestamp):
    root, pins = packet
    rewrite(root, pins, "permit-pass-native.json", lambda log: log["samples"][0].update(completed_at=timestamp))
    refused(root, pins, "ticket_native_timestamp")


def test_incomplete_native_selection_keeps_effect_separate(packet):
    root, pins = packet
    def incomplete(log):
        log["status"] = "started"
        log["samples"][0]["completed_at"] = None
        log["samples"][0]["scores"] = {}
    rewrite(root, pins, "permit-pass-native.json", incomplete)
    record = bridge.verify_saved(root, pins)["records"][0]
    assert record["status"] == "incomplete"
    assert record["taskOutcome"] == "unknown"
    assert record["effectOutcome"] == "verified-local-ticket-update"


def test_rehashed_request_packet_and_native_hash_join_do_not_replace_request(packet):
    root, pins = packet
    def changed(value):
        request = decode(bytes.fromhex(value["postRequestHex"]))
        request["request"]["request_id"] = "another-request"
        value["postRequestHex"] = canonical(request).hex()
    rewrite(root, pins, "permit-pass-http.json", changed, join_http=True)
    refused(root, pins, "ticket_http_request")


def test_other_attempt_receipt_cannot_be_rehashed_into_this_attempt(packet):
    root, pins = packet
    other = decode((root / "artifacts/permit-task-fail-http.json").read_bytes())
    rewrite(root, pins, "permit-pass-http.json", lambda p: p.update(postResponseHex=other["postResponseHex"], getResponseHex=other["getResponseHex"]), join_http=True)
    refused(root, pins, "ticket key differs")


def test_rehashed_readback_content_refused(packet):
    root, pins = packet
    def changed(value):
        readback = decode(bytes.fromhex(value["getResponseHex"]))
        readback["contentHex"] = b"ALTERED".hex()
        value["getResponseHex"] = canonical(readback).hex()
    rewrite(root, pins, "permit-pass-http.json", changed, join_http=True)
    refused(root, pins, "ticket native read-back content differs")


def test_signed_readback_substitution_refused_even_after_rehash(packet):
    root, pins = packet
    def changed(value):
        readback = decode(bytes.fromhex(value["getResponseHex"]))
        readback["receipt"]["payload"]["phase"] = "ready"
        value["getResponseHex"] = canonical(readback).hex()
    rewrite(root, pins, "permit-pass-http.json", changed, join_http=True)
    refused(root, pins, "signature")


def test_boolean_http_status_refused(packet):
    root, pins = packet
    rewrite(root, pins, "permit-pass-http.json", lambda p: p.update(getStatus=True), join_http=True)
    refused(root, pins, "ticket_http_route")


def test_extra_artifact_not_silently_ignored(packet):
    root, pins = packet
    (root / "artifacts/extra.json").write_bytes(b"{}")
    refused(root, pins, "ticket_artifact_population")


def test_source_substitution_refused(packet):
    root, pins = packet
    (root / "sources" / bridge.SOURCE_FILES[0]).write_bytes(b"changed")
    refused(root, pins, "ticket_source_pin")


def test_source_symlink_refused(packet):
    root, pins = packet
    original = root / "sources" / bridge.SOURCE_FILES[0]
    saved = root / "selected-source"
    original.rename(saved)
    original.symlink_to(saved)
    refused(root, pins, "ticket_packet_symlink")


def test_missing_started_attempt_stays_unknown_in_population(packet):
    root, pins = packet
    manifest = decode((root / "artifact-manifest.json").read_bytes())
    del manifest["bindings"]["permit-pass"]
    shutil.rmtree(root / "native" / "permit-pass")
    for suffix in ("-native.json", "-http.json"):
        name = "permit-pass" + suffix
        del manifest["artifacts"][name]
        (root / "artifacts" / name).unlink()
    raw = encode(manifest)
    (root / "artifact-manifest.json").write_bytes(raw)
    pins["artifactManifestSha256"] = bridge.sha(raw)
    report = bridge.verify_saved(root, pins)
    assert report["plannedAttempts"] == 6
    assert report["records"][0]["status"] == "start-unknown"
    assert report["records"][0]["effectOutcome"] == "unknown"


def test_reader_invokes_neither_framework_nor_network(native_packet, monkeypatch):
    root, pins, report = native_packet
    monkeypatch.setattr(bridge, "http_bytes", lambda *a: pytest.fail("offline reader made HTTP request"))
    monkeypatch.setattr(bridge, "execute", lambda *a: pytest.fail("offline reader executed framework"))
    assert bridge.verify_saved(root, pins) == report


def test_extra_original_native_log_refused(packet):
    root, pins = packet
    (root / "native" / "permit-pass" / "extra.json").write_bytes(b"{}")
    refused(root, pins, "ticket_original_native_population")


def test_replaced_original_native_log_refused(packet):
    root, pins = packet
    next((root / "native" / "permit-pass").iterdir()).write_bytes(b"{}")
    refused(root, pins, "ticket_original_native_bytes")


def test_extra_native_attempt_directory_refused(packet):
    root, pins = packet
    (root / "native" / "undeclared").mkdir()
    refused(root, pins, "ticket_original_native_population")


def test_parent_source_directory_symlink_refused(packet):
    root, pins = packet
    source = root / "sources" / "inspect"
    target = root / "retained-inspect"
    source.rename(target)
    source.symlink_to(target, target_is_directory=True)
    refused(root, pins, "ticket_packet_symlink")
