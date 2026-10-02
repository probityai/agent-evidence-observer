"""Real-framework reproduction and selected-pin semantic mutation controls."""
from __future__ import annotations

import copy
import shutil
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from lg_common import CASES, PacketError, decode, encode, read, sha
from lg_reader import verify_saved
from lg_run import run


@pytest.fixture(scope="module")
def native_packet(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    """Run six real LangGraph graphs once; no import skip or placeholder fixture."""
    root = tmp_path_factory.mktemp("langgraph") / "run"
    report = run(root, "pytest-selected-source")
    return root, decode(read(root, "consumer-pins.json")), report


@pytest.fixture
def packet(native_packet: tuple, tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    """Copy immutable native outputs so each mutation has a separate directory."""
    source, pins, _ = native_packet
    root = tmp_path / "packet"
    shutil.copytree(source, root)
    return root, copy.deepcopy(pins)


def rewrite(root: Path, pins: dict[str, Any], name: str, mutate: Callable[[dict[str, Any]], None]) -> None:
    """Reselect altered artifact hashes to exercise semantic invariants beyond SHA."""
    path = root / "attempts" / (name + ".json")
    value = decode(path.read_bytes())
    mutate(value)
    path.write_bytes(encode(value))
    manifest_path = root / "artifact-manifest.json"
    manifest = decode(manifest_path.read_bytes())
    manifest[path.name] = sha(path.read_bytes())
    manifest_path.write_bytes(encode(manifest))
    pins["artifactManifestSha256"] = sha(manifest_path.read_bytes())


def retime(attempt: dict[str, Any], convert: Callable[[str], str]) -> None:
    """Change every native timestamp while keeping boundary projections joined."""
    snapshots = [*attempt["history"], *(record["snapshot"] for record in attempt["boundaries"])]
    for snapshot in snapshots:
        snapshot["created_at"] = convert(snapshot["created_at"])


def refuse(root: Path, pins: dict[str, Any], reason: str, caplog: pytest.LogCaptureFixture) -> None:
    """Assert the exact error and corresponding bounded, credential-free log."""
    caplog.clear()
    with pytest.raises(PacketError) as caught:
        verify_saved(root, pins)
    assert str(caught.value) == reason
    assert caplog.messages == ["LangGraph packet refused: " + reason]


MUTATIONS = [
    ("permit", lambda a: a["history"][0]["metadata"].update(source="input"), "native-metadata"),
    ("permit", lambda a: a["history"][1]["tasks"][0].update(path=["other"]), "native-task-path"),
    ("interrupt-before", lambda a: a["history"][1]["interrupts"][0].update(id="other"), "native-history-interrupt"),
    ("interrupt-before", lambda a: a["boundaries"][0]["snapshot"]["tasks"][0].update(id="other"), "native-interrupted-snapshot"),
    ("permit", lambda a: a["history"].pop(), "native-history-population"),
    ("permit", lambda a: a["history"][0]["metadata"].update(step=True), "native-step"),
    ("permit", lambda a: a["history"][0]["parent_config"]["configurable"].update(checkpoint_id="other"), "native-history-parent"),
    ("permit", lambda a: a["history"][0]["config"]["configurable"].update(thread_id="other"), "native-thread"),
    ("permit", lambda a: a["history"][1]["values"].update(contentHex="00"), "native-input-values"),
    ("permit", lambda a: a["history"][0]["values"]["result"].update(httpSha256="0" * 64), "native-http-join"),
    ("permit", lambda a: a["history"][1]["tasks"][0].update(name="other"), "native-dispatch-task"),
    ("permit", lambda a: a["history"][1]["tasks"][0]["result"]["result"].update(revision=0), "native-task-result"),
    ("permit", lambda a: a["config"].update(recursion_limit=5), "native-config"),
    ("permit", lambda a: a["http"][0]["candidate"].update(contentHex="00"), "http-argument-binding"),
    ("permit", lambda a: a["http"][0].update(endpoint="https://example.com"), "http-loopback"),
    ("permit", lambda a: a["http"][0].update(getStatus=True), "http-readback-status"),
    ("permit", lambda a: a["http"][0].update(postRequestHex="7b7d"), "http-request-bytes"),
    ("permit", lambda a: a["http"][0].update(postResponseHex="7b7d"), "http-response-bytes"),
    ("permit", lambda a: a["http"][0].update(getResponseHex="7b7d"), "http-readback-bytes"),
    ("permit", lambda a: a.update(finalStatus=409), "http-final-status"),
    ("permit", lambda a: a.update(finalReadbackHex="7b7d"), "http-final-bytes"),
    ("permit", lambda a: a.update(elapsedNs=True), "resource-elapsed"),
    ("interrupt-before", lambda a: a["boundaries"].pop(0), "native-boundary-population"),
    ("interrupt-before", lambda a: a["boundaries"][0].update(httpCalls=1), "native-interrupt-call-count"),
    ("interrupt-before", lambda a: a["boundaries"][-1].update(operation="invoke"), "native-resume-operation"),
    ("interrupt-before", lambda a: a["boundaries"][0]["snapshot"]["interrupts"][0]["value"].update(point="after-effect"), "native-interrupt-http-join"),
    ("interrupt-before", lambda a: a["boundaries"][0]["result"].update(contentHex="00"), "native-interrupt-result"),
    ("resume-after-effect", lambda a: a["http"].pop(), "http-population"),
    ("resume-after-effect", lambda a: a["boundaries"][0]["snapshot"]["interrupts"][0]["value"].update(httpSha256="0" * 64), "native-interrupt-http-join"),
    ("deny", lambda a: a["history"][0]["values"]["result"].update(postStatus=200), "native-http-join"),
    ("pending-intent", lambda a: a["history"][0]["values"]["result"].update(revision=1), "native-http-join"),
]


class TestLangGraphPacket:
    """Separate accepting native cases from refused evidence substitutions."""

    class TestPassingCases:
        @pytest.mark.parametrize("case_name", CASES)
        def test_actual_framework_case(self, native_packet: tuple, case_name: str) -> None:
            root, pins, report = native_packet
            assert verify_saved(root, pins) == report
            records = {record["attemptId"]: record for record in report["records"]}
            record = records[case_name]
            assert record["status"] == "complete"
            assert record["httpCalls"] == (2 if case_name == "resume-after-effect" else 1)
            assert record["nativeRevision"] == (0 if case_name in {"deny", "altered-argument", "pending-intent"} else 1)
            assert report["independentCustody"] == report["exactlyOnce"] == "not-established"
            assert report["providerCalls"] == report["inputTokens"] == report["outputTokens"] == 0

        def test_producer_evidence_clock_preserves_fractional_seconds(self, monkeypatch: pytest.MonkeyPatch) -> None:
            import lg_run
            instant = datetime(2026, 10, 2, 12, 0, 0, 987654, tzinfo=timezone.utc)
            class FixedClock:
                @staticmethod
                def now(zone: Any) -> datetime:
                    assert zone is timezone.utc
                    return instant
            monkeypatch.setattr(lg_run, "datetime", FixedClock)
            assert lg_run.evidence_clock() == instant
            assert lg_run.evidence_clock().microsecond == 987654

        def test_subsecond_checkpoint_inside_precise_envelope(self, packet: tuple) -> None:
            root, pins = packet
            floor = datetime.fromisoformat(pins["evaluationTime"]).replace(microsecond=0)
            checkpoint = floor + timedelta(microseconds=500000)
            for name in CASES:
                rewrite(root, pins, name, lambda attempt: retime(attempt, lambda _: checkpoint.isoformat()))
            pins["evaluationTime"] = (floor + timedelta(microseconds=750000)).isoformat()
            assert verify_saved(root, pins)["status"] == "verified"

        @pytest.mark.parametrize("endpoint", ["selectedTime", "evaluationTime"])
        def test_inclusive_checkpoint_time_boundaries(self, packet: tuple, endpoint: str) -> None:
            root, pins = packet
            plan = decode(read(root, "plan-before-run.json"))
            timestamp = plan["selectedTime"] if endpoint == "selectedTime" else pins["evaluationTime"]
            for name in CASES:
                rewrite(root, pins, name, lambda attempt: retime(attempt, lambda _: timestamp))
            assert verify_saved(root, pins)["status"] == "verified"

        def test_equivalent_timezone_offset_is_an_aware_instant(self, packet: tuple) -> None:
            root, pins = packet
            offset = timezone(timedelta(hours=-4))
            for name in CASES:
                rewrite(root, pins, name, lambda attempt: retime(attempt, lambda value: datetime.fromisoformat(value).astimezone(offset).isoformat()))
            assert verify_saved(root, pins)["status"] == "verified"

        def test_reader_without_framework_import_or_network(self, native_packet: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
            import builtins
            import urllib.request
            original = builtins.__import__
            def guarded(name: str, *args: Any, **kwargs: Any) -> Any:
                assert not name.startswith("langgraph"), "reader imported framework"
                return original(name, *args, **kwargs)
            def network_forbidden(*args: Any, **kwargs: Any) -> None:
                raise AssertionError("reader issued network request")
            monkeypatch.setattr(builtins, "__import__", guarded)
            monkeypatch.setattr(urllib.request, "urlopen", network_forbidden)
            root, pins, report = native_packet
            assert verify_saved(root, pins) == report

    class TestFailingCases:
        @pytest.mark.parametrize("case_name,mutate,reason", MUTATIONS)
        def test_reselected_native_mutation(self, packet: tuple, case_name: str, mutate: Callable, reason: str, caplog: pytest.LogCaptureFixture) -> None:
            root, pins = packet
            rewrite(root, pins, case_name, mutate)
            refuse(root, pins, reason, caplog)

        @pytest.mark.parametrize("pin", ["planSha256", "artifactManifestSha256"])
        def test_external_pin_is_required(self, packet: tuple, pin: str, caplog: pytest.LogCaptureFixture) -> None:
            root, pins = packet
            pins[pin] = "0" * 64
            reason = "consumer-plan-pin" if pin == "planSha256" else "consumer-artifact-pin"
            refuse(root, pins, reason, caplog)

        def test_missing_attempt_cannot_disappear(self, packet: tuple, caplog: pytest.LogCaptureFixture) -> None:
            root, pins = packet
            (root / "attempts" / "permit.json").unlink()
            refuse(root, pins, "artifact-file-population", caplog)

        def test_extra_attempt_cannot_enter(self, packet: tuple, caplog: pytest.LogCaptureFixture) -> None:
            root, pins = packet
            (root / "attempts" / "extra.json").write_text("{}")
            refuse(root, pins, "artifact-file-population", caplog)

        def test_symlink_refused(self, packet: tuple, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
            root, pins = packet
            link = tmp_path / "link"
            link.symlink_to(root, target_is_directory=True)
            refuse(link, pins, "packet-symlink", caplog)

        def test_duplicate_json_name_refused(self, caplog: pytest.LogCaptureFixture) -> None:
            caplog.clear()
            with pytest.raises(PacketError) as caught:
                decode(b'{"status":1,"status":2}')
            assert str(caught.value) == "duplicate-json-name"
            assert caplog.messages == ["LangGraph packet refused: duplicate-json-name"]

        def test_floored_evaluation_time_refuses_later_subsecond_checkpoint(self, packet: tuple, caplog: pytest.LogCaptureFixture) -> None:
            root, pins = packet
            floor = datetime.fromisoformat(pins["evaluationTime"]).replace(microsecond=0)
            checkpoint = floor + timedelta(microseconds=500000)
            for name in CASES:
                rewrite(root, pins, name, lambda attempt: retime(attempt, lambda _: checkpoint.isoformat()))
            pins["evaluationTime"] = floor.isoformat()
            refuse(root, pins, "native-checkpoint-window", caplog)

        @pytest.mark.parametrize("direction", ["past", "future"])
        def test_reselected_outside_plan_time_window_refused(self, packet: tuple, direction: str, caplog: pytest.LogCaptureFixture) -> None:
            root, pins = packet
            plan = decode(read(root, "plan-before-run.json"))
            endpoint = datetime.fromisoformat(plan["selectedTime"] if direction == "past" else pins["evaluationTime"])
            timestamp = (endpoint + timedelta(days=-365 if direction == "past" else 365)).isoformat()
            for name in CASES:
                rewrite(root, pins, name, lambda attempt: retime(attempt, lambda _: timestamp))
            refuse(root, pins, "native-checkpoint-window", caplog)

        @pytest.mark.parametrize("bad_time", [None, "2026-10-02T11:00:00", "2026-10-02T11:00:00+25:00", "2026-10-02T11:00:00WRONGZONE"])
        def test_missing_naive_wrong_zone_time_refused(self, packet: tuple, bad_time: Any, caplog: pytest.LogCaptureFixture) -> None:
            root, pins = packet
            rewrite(root, pins, "permit", lambda attempt: attempt["history"][0].update(created_at=bad_time))
            refuse(root, pins, "native-checkpoint-time", caplog)

        def test_absent_checkpoint_time_refused(self, packet: tuple, caplog: pytest.LogCaptureFixture) -> None:
            root, pins = packet
            rewrite(root, pins, "permit", lambda attempt: attempt["history"][0].pop("created_at"))
            refuse(root, pins, "native-checkpoint-time", caplog)

        @pytest.mark.parametrize("boundary", [0, 1])
        def test_future_boundary_snapshot_refused(self, packet: tuple, boundary: int, caplog: pytest.LogCaptureFixture) -> None:
            root, pins = packet
            timestamp = (datetime.fromisoformat(pins["evaluationTime"]) + timedelta(days=365)).isoformat()
            rewrite(root, pins, "interrupt-before", lambda attempt: attempt["boundaries"][boundary]["snapshot"].update(created_at=timestamp))
            refuse(root, pins, "native-checkpoint-window", caplog)

        @settings(max_examples=30, suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=None)
        @given(content=st.binary(min_size=0, max_size=128).filter(lambda value: value != b'{"status":"DONE"}'))
        def test_arbitrary_argument_substitution_refused(self, packet: tuple, content: bytes, caplog: pytest.LogCaptureFixture) -> None:
            root, pins = packet
            rewrite(root, pins, "permit", lambda a: a["http"][0]["candidate"].update(contentHex=content.hex()))
            refuse(root, pins, "http-argument-binding", caplog)

        @settings(max_examples=20, suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=None)
        @given(step=st.integers().filter(lambda value: value != 1))
        def test_arbitrary_checkpoint_step_refused(self, packet: tuple, step: int, caplog: pytest.LogCaptureFixture) -> None:
            root, pins = packet
            rewrite(root, pins, "permit", lambda a: a["history"][0]["metadata"].update(step=step))
            refuse(root, pins, "native-step", caplog)
