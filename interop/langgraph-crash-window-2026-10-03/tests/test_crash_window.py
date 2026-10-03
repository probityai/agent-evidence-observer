"""Actual native crash-window reconstruction and reselected semantic refusals."""
from __future__ import annotations

import builtins
import copy
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
import urllib.request
from contextlib import closing
from pathlib import Path

import pytest
from hypothesis import given, strategies as st

from crash_common import CASES, child_environment, load, sha
from crash_reader import metadata_object, native_metadata, verify_saved
from crash_run import run
from probity_observer.crypto import VerificationError, canonical


@pytest.fixture(scope="session")
def fresh(tmp_path_factory):
    """Execute all four real cases once, with a relative caller output root."""
    root = tmp_path_factory.mktemp("crash-native") / "packet"
    report = run(Path(os.path.relpath(root)), "0" * 40)
    return root, load(root, "consumer-pins.json"), report


@pytest.fixture
def copied(fresh, tmp_path):
    root = tmp_path / "packet"
    shutil.copytree(fresh[0], root)
    return root, copy.deepcopy(fresh[1])


def reselect(root, pins):
    """Reselect all changed artifact bytes to reach semantics beyond digests."""
    manifest = {str(path.relative_to(root)): sha(path.read_bytes()) for path in root.rglob("*")
                if path.is_file() and path.name not in {"artifact-manifest.json", "consumer-pins.json", "report.json"}}
    (root / "artifact-manifest.json").write_bytes(canonical(manifest))
    pins.update(planSha256=sha((root / "plan-before-run.json").read_bytes()), artifactManifestSha256=sha(canonical(manifest)))


def synchronize(root, name, value):
    """Reselect projected original files consistently for semantic mutations."""
    (root / "attempts" / (name + ".json")).write_bytes(canonical(value))
    for worker in value["workers"]:
        phase, record = worker["phase"], worker["record"]
        folder = root / "workers" / name
        (folder / (phase + ".json")).write_bytes(canonical(record))
        (folder / (phase + ".process.json")).write_bytes(canonical(worker["process"]))
        (folder / (phase + "-current.json")).write_bytes(canonical(record["current"]))
        if record["http"]:
            (folder / (phase + "-http.json")).write_bytes(canonical(record["http"]))
    for target, phase in zip(value["targets"], ("first", "second"), strict=True):
        (root / "targets" / name / (phase + ".json")).write_bytes(canonical(target))


class TestCrashWindow:
    """Four first workers really hard-exit before committing node results."""

    class TestPassingCases:
        @pytest.mark.parametrize("name", CASES)
        def test_real_worker_target_effect_gap(self, fresh, name):
            value = load(fresh[0], "attempts/" + name + ".json")
            first, second = [worker["record"] for worker in value["workers"]]
            assert value["workers"][0]["process"]["exitCode"] == 74
            assert first["snapshot"]["next"] == ["dispatch"]
            assert first["snapshot"]["interrupts"] == []
            assert first["snapshot"]["values"]["result"] == {}
            assert second["loaded"] == first["snapshot"]
            assert value["prior"]["revision"] == value["final"]["revision"] == 1
            assert second["releasedResult"] is (name == "valid-after")
            assert len(second["http"]) == int(name == "valid-after")
            assert len({t["pid"] for t in value["targets"]} | {w["record"]["pid"] for w in value["workers"]}) == 4

        def test_complete_population_and_literal_cli(self, fresh, tmp_path):
            report = fresh[2]
            assert {k: report[k] for k in ("plannedAttempts", "workerProcesses", "targetProcesses", "priorAuthenticEffects", "releasedResults", "recoveryRefusals", "providerCalls")} == {"plannedAttempts": 4, "workerProcesses": 8, "targetProcesses": 8, "priorAuthenticEffects": 4, "releasedResults": 1, "recoveryRefusals": 3, "providerCalls": 0}
            pins = tmp_path / "selected.json"
            pins.write_bytes(canonical(fresh[1]))
            script = Path(__file__).resolve().parents[1] / "crash_reader.py"
            env = {**child_environment(), "PYTHONPATH": str(script.parent.parent / "joint-recovery-2026-10-02")}
            result = subprocess.run([sys.executable, str(script), str(fresh[0]), "--pins-file", str(pins)], capture_output=True, timeout=15, check=False, env=env)
            assert result.returncode == 0
            assert result.stderr == b""
            assert result.stdout == canonical(report)

        def test_reader_does_not_import_framework_or_call_network(self, fresh, monkeypatch):
            original = builtins.__import__
            def guarded(name, *args, **kwargs):
                assert not name.startswith("langgraph")
                return original(name, *args, **kwargs)
            def forbidden(*args, **kwargs):
                raise AssertionError("offline reader attempted network")
            monkeypatch.setattr(builtins, "__import__", guarded)
            monkeypatch.setattr(urllib.request, "urlopen", forbidden)
            assert verify_saved(fresh[0], fresh[1]) == fresh[2]

        @given(st.dictionaries(st.text(min_size=1, max_size=20), st.integers(), max_size=10))
        def test_native_metadata_unique_pairs_are_preserved(self, value):
            assert metadata_object(list(value.items())) == value

    class TestFailingCases:
        @pytest.mark.parametrize("name,mutation,reason", [
            ("valid-after", lambda v: v["workers"][0]["process"].update(exitCode=73), "worker-process-outcome"),
            ("valid-after", lambda v: v["workers"][0]["record"].update(status="interrupted"), "first-native-crash"),
            ("valid-after", lambda v: v["workers"][0]["record"].update(releasedResult=True), "first-no-result-release"),
            ("valid-after", lambda v: v["workers"][1]["record"]["loaded"].update(next=[]), "native-reopened-unfinished-task"),
            ("revoked-after", lambda v: v["workers"][1]["record"].update(releasedResult=True), "current-result-release"),
            ("revoked-after", lambda v: v["workers"][1]["record"].update(result={}), "denied-native-invocation"),
            ("expired-after", lambda v: v["workers"][1]["record"]["authority"].update(status="authorized"), "current-authority"),
            ("valid-after", lambda v: v["targets"][1].update(returncode=0), "target-process-outcome"),
            ("valid-after", lambda v: v["workers"][0]["process"]["command"].__setitem__(5, "second"), "worker-launch-argv"),
            ("valid-after", lambda v: v["workers"][0]["process"].update(elapsedNs=30_000_000_001), "worker-resource"),
            ("valid-after", lambda v: v["workers"][0]["record"]["http"][0]["post"].update(requestHex="7b7d"), "http-request"),
            ("valid-after", lambda v: v["workers"][1]["record"]["result"]["result"].update(httpSha256="0" * 64), "recovered-result-http-join"),
            ("valid-after", lambda v: v["targets"][1]["result"].update(initial=v["targets"][0]["result"]["initial"]), "target-reopened-committed-effect"),
        ])
        def test_reselected_consistent_semantics_refuse(self, copied, caplog, name, mutation, reason):
            root, pins = copied
            value = load(root, "attempts/" + name + ".json")
            mutation(value)
            synchronize(root, name, value)
            reselect(root, pins)
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^" + reason + "$"):
                verify_saved(root, pins)
            assert "Joint recovery refused: " + reason in caplog.messages

        @pytest.mark.parametrize("name", ["plan-before-run.json", "workers/valid-after/first.json", "native/valid-after-before-recovery.sqlite"])
        def test_selected_fifo_promptly_refuses_before_packet_reads(self, copied, tmp_path, name):
            root, pins = copied
            path = root / name
            path.unlink()
            os.mkfifo(path)
            selected = tmp_path / "outside-pins.json"
            selected.write_bytes(canonical(pins))
            script = Path(__file__).resolve().parents[1] / "crash_reader.py"
            env = {**child_environment(), "PYTHONPATH": str(script.parent.parent / "joint-recovery-2026-10-02")}
            try:
                result = subprocess.run([sys.executable, str(script), str(root), "--pins-file", str(selected)], capture_output=True, timeout=2, check=False, env=env)
                assert result.returncode == 1
                assert b"Joint recovery refused: packet-regular-file" in result.stderr
                assert result.stdout == b""
            finally:
                path.unlink()
                path.write_bytes(b"controlled FIFO refusal fixture retired")

        @pytest.mark.parametrize("kind", ["cycle", "empty-directory-link", "broken-link"])
        def test_symlink_population_cannot_hide(self, copied, kind):
            root, pins = copied
            path = root / "unselected-link"
            target = root if kind == "cycle" else root / "absent" if kind == "broken-link" else root / "empty"
            if kind == "empty-directory-link":
                target.mkdir()
            path.symlink_to(target)
            try:
                with pytest.raises(VerificationError, match="^packet-regular-file$"):
                    verify_saved(root, pins)
            finally:
                path.unlink()

        @pytest.mark.parametrize("raw", [b"not JSON", b"[" * 2000 + b"]" * 2000], ids=["invalid-json", "deep-nesting"])
        def test_native_malformed_or_deep_metadata_refuses(self, raw, caplog):
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^native-sqlite-metadata$"):
                native_metadata(raw)
            assert "Joint recovery refused: native-sqlite-metadata" in caplog.messages

        @pytest.mark.parametrize("suffix,sql,reason", [
            ("before-recovery", "DELETE FROM checkpoints", "native-sqlite-checkpoint-join"),
            ("before-recovery", "UPDATE recovery_clock SET denied=1", "native-before-recovery-clock"),
            ("checkpoints", "UPDATE recovery_clock SET clock=99", "native-clock-anchor"),
            ("before-recovery", "UPDATE checkpoints SET metadata=replace(CAST(metadata AS TEXT),'\"step\": 0','\"step\": true')", "native-sqlite-metadata"),
        ])
        def test_reselected_native_store_mutation_refuses(self, copied, caplog, suffix, sql, reason):
            root, pins = copied
            with closing(sqlite3.connect(root / "native" / ("valid-after-" + suffix + ".sqlite"))) as connection:
                connection.execute(sql)
                connection.commit()
            reselect(root, pins)
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^" + reason + "$"):
                verify_saved(root, pins)
            assert "Joint recovery refused: " + reason in caplog.messages

        @pytest.mark.parametrize("raw", [b"not JSON", b'{"step":0,"unused":' + b"[" * 2000 + b"]" * 2000 + b"}"], ids=["invalid-json", "deep-nesting"])
        def test_reselected_native_metadata_errors_have_stable_refusal(self, copied, raw, caplog):
            root, pins = copied
            with closing(sqlite3.connect(root / "native/valid-after-before-recovery.sqlite")) as connection:
                connection.execute("UPDATE checkpoints SET metadata=? WHERE parent_checkpoint_id IS NOT NULL", (raw,))
                connection.commit()
            reselect(root, pins)
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^native-sqlite-metadata$"):
                verify_saved(root, pins)
            assert "Joint recovery refused: native-sqlite-metadata" in caplog.messages

        def test_depth_bound_precedes_reader_access(self, copied):
            root, pins = copied
            root.joinpath(*(["deep"] * 13)).mkdir(parents=True)
            with pytest.raises(VerificationError, match="^packet-depth-bound$"):
                verify_saved(root, pins)

        @pytest.mark.parametrize("kind", ["files", "entries"])
        def test_entry_population_bounds_precede_reader_access(self, copied, kind):
            root, pins = copied
            reason = "packet-population-bound" if kind == "files" else "packet-entry-bound"
            for number in range(513 if kind == "files" else 1025):
                path = root / ("population-" + str(number))
                path.write_bytes(b"") if kind == "files" else path.mkdir()
            with pytest.raises(VerificationError, match="^" + reason + "$"):
                verify_saved(root, pins)

        @pytest.mark.parametrize("kind", ["member-bytes", "total-bytes"])
        def test_byte_bounds_precede_reader_access(self, copied, kind):
            root, pins = copied
            reason = "packet-size" if kind == "member-bytes" else "packet-population-bound"
            for number in range(1 if kind == "member-bytes" else 5):
                with (root / ("sparse-" + str(number))).open("wb") as stream:
                    stream.truncate((17 if kind == "member-bytes" else 16) * 1024 * 1024)
            with pytest.raises(VerificationError, match="^" + reason + "$"):
                verify_saved(root, pins)

        def test_deep_externally_selected_plan_has_stable_cli_refusal(self, copied, tmp_path):
            root, pins = copied
            (root / "plan-before-run.json").write_bytes(b'{"unused":' + b"[" * 2000 + b"]" * 2000 + b"}")
            reselect(root, pins)
            selected = tmp_path / "outside-pins.json"
            selected.write_bytes(canonical(pins))
            script = Path(__file__).resolve().parents[1] / "crash_reader.py"
            env = {**child_environment(), "PYTHONPATH": str(script.parent.parent / "joint-recovery-2026-10-02")}
            result = subprocess.run([sys.executable, str(script), str(root), "--pins-file", str(selected)], capture_output=True, timeout=2, check=False, env=env)
            assert result.returncode == 1
            assert b"Joint recovery refused: packet-json-bound" in result.stderr

        @pytest.mark.parametrize("raw", [b"[" * 65 + b"0" + b"]" * 65, b"[" + b",".join([b"0"] * 16384) + b"]"], ids=["depth-65", "values-16385"])
        def test_explicit_json_bounds_independent_of_recursion_limit(self, tmp_path, raw, caplog):
            (tmp_path / "bounded.json").write_bytes(raw)
            with caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^packet-json-bound$"):
                load(tmp_path, "bounded.json")
            assert "Joint recovery refused: packet-json-bound" in caplog.messages

        @pytest.mark.parametrize("field", ["planSha256", "artifactManifestSha256"])
        def test_outside_wrong_pin_refuses(self, fresh, field):
            with pytest.raises(VerificationError, match="^consumer-" + field + "$"):
                verify_saved(fresh[0], {**fresh[1], field: "0" * 64})

        @given(st.text(min_size=1, max_size=30))
        def test_native_duplicate_metadata_refuses(self, name):
            with pytest.raises(VerificationError, match="^native-sqlite-duplicate-metadata$"):
                metadata_object([(name, 1), (name, 2)])
