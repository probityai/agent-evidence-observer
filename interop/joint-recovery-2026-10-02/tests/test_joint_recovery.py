"""Actual native populations and semantic controls after full byte reselection."""
from __future__ import annotations

import builtins
import copy
import logging
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import urllib.request
from contextlib import closing
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings, strategies as st
from probity_observer.crypto import VerificationError, canonical

from joint_common import CASES, child_environment, load, sha
from joint_reader import verify_saved
from joint_run import current
from joint_worker import current_gate
from lg_common import PacketError


@pytest.fixture
def copied(fresh: tuple[Path, dict[str, Any], dict[str, Any]], tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    """Isolate one mutation while preserving every original retained byte."""
    root = tmp_path / "packet"
    shutil.copytree(fresh[0], root)
    return root, copy.deepcopy(fresh[1])


def reselect(root: Path, pins: dict[str, Any]) -> None:
    """Select changed bytes again so semantic controls cannot pass on hash drift."""
    manifest = load(root, "artifact-manifest.json")
    for name in manifest:
        manifest[name] = sha((root / name).read_bytes())
    (root / "artifact-manifest.json").write_bytes(canonical(manifest))
    pins.update(planSha256=sha((root / "plan-before-run.json").read_bytes()), artifactManifestSha256=sha(canonical(manifest)))


def replace(root: Path, name: str, mutation: Callable[[Any], Any]) -> None:
    """Change one canonical projection before explicit consumer reselection."""
    value = load(root, name)
    mutation(value)
    (root / name).write_bytes(canonical(value))


def sync_originals(root: Path, name: str) -> None:
    """Reselect duplicate captures to exercise deeper semantic controls.

    Original-only contradiction controls deliberately do not call this helper.
    It allows the remaining mutations to test authority, signatures, native
    snapshots and process semantics beyond duplicate-byte joins.
    """
    if not name.startswith("attempts/"):
        return
    value = load(root, name)
    case_id = Path(name).stem
    for phase, target in zip(("first", "second"), value["targets"], strict=True):
        (root / "targets" / case_id / (phase + ".json")).write_bytes(canonical(target))
    for worker in value["workers"]:
        sync_worker_originals(root, case_id, worker)
    (root / name).write_bytes(canonical(value))


def sync_worker_originals(root: Path, case_id: str, worker: dict[str, Any]) -> None:
    """Preserve intentional relationships while selecting a semantic mutant."""
    folder = root / "workers" / case_id
    phase, record = worker["phase"], worker["record"]
    worker["process"]["pid"] = record["pid"]
    for suffix, item in [(".json", record), (".process.json", worker["process"]), ("-current.json", record["current"])]:
        (folder / (phase + suffix)).write_bytes(canonical(item))
    http = folder / (phase + "-http.json")
    if record["http"]:
        http.write_bytes(canonical(record["http"]))
        return
    if http.exists():
        http.unlink()
        manifest = load(root, "artifact-manifest.json")
        manifest.pop(str(http.relative_to(root)))
        (root / "artifact-manifest.json").write_bytes(canonical(manifest))


def rebind_http_projection(root: Path, name: str) -> None:
    """Reselect dependent unsigned native projections to reach HTTP semantics."""
    value = load(root, name)
    for worker in value["workers"]:
        rebind_worker(worker["record"], worker["phase"])
    for worker in value["workers"][1:]:
        worker["record"]["loaded"] = copy.deepcopy(value["workers"][0]["record"]["snapshot"])
    (root / name).write_bytes(canonical(value))


def rebind_worker(record: dict[str, Any], phase: str) -> None:
    """Update the dependent hash while leaving signed service receipts untouched."""
    if not record["http"]:
        return
    digest = sha(canonical(record["http"][0]))
    if phase != "first":
        record["result"]["result"]["httpSha256"] = digest
        record["result"]["result"]["postStatus"] = record["http"][0]["post"]["status"]
        record["snapshot"]["values"]["result"]["httpSha256"] = digest
        record["snapshot"]["values"]["result"]["postStatus"] = record["http"][0]["post"]["status"]
        return
    for snapshot in [record["snapshot"], *record["history"]]:
        for interrupt in snapshot["interrupts"]:
            interrupt["value"]["httpSha256"] = digest


MUTATIONS = [
    ("attempts/valid-before.json", lambda value: value["workers"][1]["record"].update(pid=True), "distinct-processes"),
    ("attempts/valid-before.json", lambda value: value["targets"][1].update(pid=value["targets"][0]["pid"]), "distinct-processes"),
    ("attempts/valid-before.json", lambda value: value["targets"][0].update(returncode=0), "target-process-exit"),
    ("attempts/pending-intent-after.json", lambda value: value["targets"][0].update(returncode=75), "target-process-exit"),
    ("attempts/valid-before.json", lambda value: value["workers"][0]["process"].update(exitCode=False), "worker-process-exit"),
    ("attempts/valid-before.json", lambda value: value["workers"][1]["process"].update(elapsedNs=True), "worker-resource"),
    ("attempts/valid-before.json", lambda value: value["workers"][1]["process"].update(stdoutHex="00"), "worker-process-streams"),
    ("attempts/valid-before.json", lambda value: value["workers"][0]["record"]["loaded"].update(values={"other": 1}), "first-native-state"),
    ("attempts/valid-before.json", lambda value: value["workers"][1]["record"]["loaded"].update(next=[]), "native-reopened-checkpoint"),
    ("attempts/valid-before.json", lambda value: value["workers"][0]["record"]["history"].pop(), "native-history-population"),
    ("attempts/valid-before.json", lambda value: value["workers"][1]["record"]["http"].clear(), "worker-dispatch-population"),
    ("attempts/revoked-after.json", lambda value: value["workers"][1]["record"].update(releasedResult=True), "worker-result-release"),
    ("attempts/revoked-after.json", lambda value: value["workers"][1]["record"].update(result={}), "denied-no-result"),
    ("attempts/expired-after.json", lambda value: value["workers"][1]["record"]["authority"].update(status="authorized"), "current-authority"),
    ("attempts/sticky-after.json", lambda value: value["workers"][2]["record"]["authority"].update(status="authorized"), "current-authority"),
    ("attempts/target-key-after.json", lambda value: value["workers"][1]["record"]["current"]["selection"].update(serviceKey="1" * 64), "current-selection"),
    ("attempts/target-key-after.json", lambda value: value["targets"][1].update(selectedServiceKey=value["targets"][0]["selectedServiceKey"]), "target-launch-key"),
    ("attempts/valid-before.json", lambda value: value["workers"][1]["record"]["http"][0]["post"].update(url="http://127.0.0.1:1/dispatch"), "http-endpoint"),
    ("attempts/valid-before.json", lambda value: value["workers"][1]["record"]["http"][0]["post"].update(requestHex="7b7d"), "http-request"),
    ("attempts/valid-before.json", lambda value: value["workers"][1]["record"]["http"][0]["post"].update(startedNs=True), "http-interval"),
    ("attempts/valid-before.json", lambda value: value["workers"][1]["record"]["http"][0]["post"].update(status=False), "http-status"),
    ("attempts/pending-intent-after.json", lambda value: value["workers"][0]["record"]["http"][0]["post"].update(error="TimeoutError"), "http-crash-error"),
    ("attempts/pending-intent-after.json", lambda value: value.update(pendingRecovery=None), "pending-terminal-recovery"),
    ("attempts/valid-before.json", lambda value: value["final"].update(revision=False), "readback-identity"),
    ("attempts/valid-before.json", lambda value: value["final"].update(contentHex="00"), "readback-content"),
    ("attempts/valid-after.json", lambda value: value["final"]["receipt"]["payload"].update(witnessScope="HOST"), "signature does not verify under the pinned key"),
    ("attempts/target-rollback-after.json", lambda value: value["targets"][1]["result"].update(reason="different"), "target-startup-refusal"),
    ("attempts/target-store-after.json", lambda value: value.update(targetSnapshot="native/valid-before-target.sqlite"), "missing-store-snapshot"),
    ("attempts/valid-before.json", lambda value: value.update(checkpointSnapshot="native/valid-after-checkpoints.sqlite"), "checkpoint-snapshot-name"),
    ("attempts/concurrent-before.json", lambda value: value["concurrentProbes"].pop(), "concurrent-population"),
    ("attempts/concurrent-before.json", lambda value: value["concurrentProbes"][0].update(startedNs=value["concurrentProbes"][0]["endedNs"]), "http-interval"),
    ("plan-before-run.json", lambda value: value.update(witnessScope="HOST"), "witness-scope"),
    ("plan-before-run.json", lambda value: value["doesNotAssert"].pop(), "nonclaims"),
    ("plan-before-run.json", lambda value: value["cases"].pop(), "planned-population"),
    ("plan-before-run.json", lambda value: value["hostPolicy"].update(automaticPendingReplay=True), "host-policy"),
    ("plan-before-run.json", lambda value: value.update(sourceRevision="working-tree"), "source-revision"),
]


class TestJointReader:
    """Selected reader checks keep native execution and evidence scope separate."""

    class TestPassingCases:
        def test_relative_native_output_freezes_absolute_launch_roots(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]]) -> None:
            root = fresh[0]
            plan = load(root, "plan-before-run.json")
            assert plan["captureRoot"] == str(root.resolve())
            assert Path(plan["hostPrivateRoot"]).is_absolute()
            for name in CASES:
                value = load(root, "attempts/" + name + ".json")
                assert all(Path(target["command"][2]).is_absolute() for target in value["targets"])
                assert all(Path(worker["process"]["command"][2]).is_absolute() and Path(worker["process"]["command"][6]).is_absolute() for worker in value["workers"])

        def test_actual_cli_emits_canonical_report(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]]) -> None:
            script = Path(__file__).resolve().parents[1] / "joint_reader.py"
            process = subprocess.run([sys.executable, str(script), str(fresh[0]), "--pins-file", str(fresh[0] / "consumer-pins.json")], capture_output=True, timeout=15, check=False, env=child_environment())
            assert process.returncode == 0
            assert process.stderr == b""
            assert process.stdout == canonical(fresh[2])

        @pytest.mark.parametrize("name", CASES)
        def test_real_selected_case(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]], name: str) -> None:
            _, _, report = fresh
            row = next(item for item in report["records"] if item["id"] == name)
            assert row["targetProcesses"] == 2
            assert row["releasedResult"] is (name in {"valid-before", "valid-after", "concurrent-before"})
            assert row["recoveryDispatches"] == int(name in {"valid-before", "valid-after", "pending-intent-after", "pending-transaction-after", "concurrent-before"})

        def test_complete_native_population(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]]) -> None:
            root, _, report = fresh
            assert {key: report[key] for key in ("plannedAttempts", "workerProcesses", "targetProcesses", "releasedResults", "priorAuthenticEffects", "pendingRefusals", "startupRefusals")} == {"plannedAttempts": 19, "workerProcesses": 40, "targetProcesses": 38, "releasedResults": 3, "priorAuthenticEffects": 11, "pendingRefusals": 2, "startupRefusals": 3}
            assert report["independentCustody"] == "not-established"
            assert verify_saved(root, fresh[1]) == report
            assert not list(root.rglob("*private.json"))

        def test_offline_reader_refuses_active_framework_and_network(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]], monkeypatch: pytest.MonkeyPatch) -> None:
            original = builtins.__import__

            def guarded(name: str, *args: Any, **kwargs: Any) -> Any:
                assert not name.startswith("langgraph")
                return original(name, *args, **kwargs)

            def forbidden(*args: Any, **kwargs: Any) -> None:
                raise AssertionError("offline reader attempted network")

            monkeypatch.setattr(builtins, "__import__", guarded)
            monkeypatch.setattr(urllib.request, "urlopen", forbidden)
            assert verify_saved(fresh[0], fresh[1]) == fresh[2]

    class TestFailingCases:
        @pytest.mark.parametrize("name,mutation,reason", MUTATIONS)
        def test_reselected_semantic_refusal(self, copied: tuple[Path, dict[str, Any]], caplog: pytest.LogCaptureFixture, name: str, mutation: Callable[[dict[str, Any]], Any], reason: str) -> None:
            root, pins = copied
            replace(root, name, mutation)
            if reason.startswith("http-"):
                rebind_http_projection(root, name)
            sync_originals(root, name)
            reselect(root, pins)
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^" + reason + "$") as raised:
                verify_saved(root, pins)
            assert str(raised.value) == reason
            assert "Joint recovery refused: " + reason in caplog.messages

        @pytest.mark.parametrize("name,mutation,reason", [
            ("workers/revoked-after/second.json", lambda value: value.update(releasedResult=True), "worker-original-binding"),
            ("attempts/valid-before.json", lambda value: value["workers"][1]["process"]["command"].__setitem__(5, "first"), "worker-process-original-binding"),
            ("attempts/valid-before.json", lambda value: value["workers"][1]["record"].update(pid=value["workers"][1]["record"]["pid"] + 1_000_000), "worker-original-binding"),
            ("workers/valid-before/second-http.json", lambda value: value[0]["post"].update(status=403), "worker-http-original-binding"),
        ])
        def test_reselected_original_contradiction_refused(self, copied: tuple[Path, dict[str, Any]], caplog: pytest.LogCaptureFixture, name: str, mutation: Callable[[Any], Any], reason: str) -> None:
            root, pins = copied
            replace(root, name, mutation)
            reselect(root, pins)
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^" + reason + "$"):
                verify_saved(root, pins)
            assert "Joint recovery refused: " + reason in caplog.messages

        @pytest.mark.parametrize("index,replacement", [(0, "/different/python"), (1, "/different/worker.py"), (2, "/different/case.json"), (3, "http://127.0.0.1:1"), (4, "/different/checkpoints.sqlite"), (5, "first"), (6, "/different/output.json"), (7, "/different/current.json")])
        def test_reselected_consistent_wrong_argv_refused(self, copied: tuple[Path, dict[str, Any]], caplog: pytest.LogCaptureFixture, index: int, replacement: str) -> None:
            root, pins = copied
            name = "attempts/valid-before.json"
            replace(root, name, lambda value: value["workers"][1]["process"]["command"].__setitem__(index, replacement))
            sync_originals(root, name)
            reselect(root, pins)
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^worker-launch-argv$"):
                verify_saved(root, pins)
            assert "Joint recovery refused: worker-launch-argv" in caplog.messages

        def test_reselected_parent_and_worker_pid_disagreement_refused(self, copied: tuple[Path, dict[str, Any]], caplog: pytest.LogCaptureFixture) -> None:
            root, pins = copied
            name = "attempts/valid-before.json"
            replace(root, name, lambda value: value["workers"][1]["process"].update(pid=value["workers"][1]["process"]["pid"] + 1_000_000))
            process = load(root, name)["workers"][1]["process"]
            (root / "workers/valid-before/second.process.json").write_bytes(canonical(process))
            reselect(root, pins)
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^worker-parent-process-identity$"):
                verify_saved(root, pins)
            assert "Joint recovery refused: worker-parent-process-identity" in caplog.messages

        def test_reselected_pid_reused_across_cases_refused(self, copied: tuple[Path, dict[str, Any]], caplog: pytest.LogCaptureFixture) -> None:
            root, pins = copied
            name = "attempts/valid-after.json"
            value = load(root, name)
            pid = load(root, "attempts/valid-before.json")["targets"][0]["pid"]
            value["targets"][0]["pid"] = value["targets"][0]["result"]["pid"] = pid
            (root / name).write_bytes(canonical(value))
            sync_originals(root, name)
            reselect(root, pins)
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^within-run-pid-reuse$"):
                verify_saved(root, pins)
            assert "Joint recovery refused: within-run-pid-reuse" in caplog.messages

        @pytest.mark.parametrize("field", ["planSha256", "artifactManifestSha256"])
        def test_wrong_external_selection(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]], caplog: pytest.LogCaptureFixture, field: str) -> None:
            pins = {**fresh[1], field: "0" * 64}
            reason = "consumer-" + field
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^" + reason + "$"):
                verify_saved(fresh[0], pins)
            assert "Joint recovery refused: " + reason in caplog.messages

        @pytest.mark.parametrize("sql,reason", [("UPDATE recovery_clock SET denied=0", "native-clock-anchor"), ("DELETE FROM checkpoints", "native-checkpoint-population")])
        def test_reselected_native_clock_and_checkpoint_mutation(self, copied: tuple[Path, dict[str, Any]], caplog: pytest.LogCaptureFixture, sql: str, reason: str) -> None:
            root, pins = copied
            with closing(sqlite3.connect(root / "native/sticky-after-checkpoints.sqlite")) as connection:
                connection.execute(sql)
                connection.commit()
            reselect(root, pins)
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^" + reason + "$"):
                verify_saved(root, pins)
            assert "Joint recovery refused: " + reason in caplog.messages


class TestCurrentGate:
    """Merged clock gate remains durable across new host selection refusals."""

    class TestPassingCases:
        @settings(max_examples=20, deadline=None)
        @given(clock=st.integers(min_value=101, max_value=199))
        def test_strictly_later_selection_clears_denial(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]], clock: int) -> None:
            case = load(fresh[0], "cases/valid-before.json")
            first = current(case, "first", True)
            denied = {**first, "authority": {**first["authority"], "revoked": True}}
            with tempfile.TemporaryDirectory() as folder, sqlite3.connect(Path(folder) / "clock.sqlite") as connection:
                assert current_gate(connection, case, first, "first")["status"] == "authorized"
                assert current_gate(connection, case, denied, "second")["status"] == "refused-revoked"
                assert current_gate(connection, case, first, "second")["status"] == "refused-stale-authority"
                later = {**first, "authority": {**first["authority"], "clock": clock}}
                assert current_gate(connection, case, later, "second")["status"] == "authorized"

        @pytest.mark.parametrize("field,value", [("grantSha256", "0" * 64), ("serviceKey", "0" * 64), ("storeIdentity", "0" * 32)])
        def test_selection_denial_is_sticky_at_same_clock(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]], tmp_path: Path, field: str, value: str) -> None:
            case = load(fresh[0], "cases/valid-before.json")
            first = current(case, "first", True)
            denied = {**first, "selection": {**first["selection"], field: value}}
            with sqlite3.connect(tmp_path / "clock.sqlite") as connection:
                current_gate(connection, case, first, "first")
                assert current_gate(connection, case, denied, "second")["status"] == "refused-current-selection"
                assert current_gate(connection, case, first, "second")["status"] == "refused-stale-authority"

    class TestFailingCases:
        @pytest.mark.parametrize("field,value,reason", [("clock", True, "authority-types"), ("expires", False, "authority-types"), ("revoked", 0, "authority-types"), ("actionSha256", "0" * 64, "authority-action")])
        def test_malformed_authority_refuses_without_anchor(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]], tmp_path: Path, caplog: pytest.LogCaptureFixture, field: str, value: Any, reason: str) -> None:
            case = load(fresh[0], "cases/valid-before.json")
            selected = current(case, "first", True)
            selected["authority"][field] = value
            with sqlite3.connect(tmp_path / "clock.sqlite") as connection, caplog.at_level(logging.WARNING), pytest.raises(PacketError, match="^" + reason + "$"):
                current_gate(connection, case, selected, "first")
            assert "LangGraph packet refused: " + reason in caplog.messages

        def test_boolean_target_readiness_refuses(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]], tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
            case = load(fresh[0], "cases/valid-before.json")
            selected = {**current(case, "first", True), "targetReady": 1}
            with sqlite3.connect(tmp_path / "clock.sqlite") as connection, caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^current-target-readiness-type$"):
                current_gate(connection, case, selected, "first")
            assert "Joint recovery refused: current-target-readiness-type" in caplog.messages
