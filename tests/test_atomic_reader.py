"""Schema/refusal controls; real Rust execution is a separate installed CI step."""

import copy
import json
from pathlib import Path

import pytest

from probity_observer import atomic_reader as reader


def write(path, value):
    path.write_text(json.dumps(value) + "\n")


@pytest.fixture
def packet(tmp_path):
    root = tmp_path / "packet"
    root.mkdir()
    binary = "delegation_restart-synthetic-never-executed"
    for name in (*reader.SOURCE_FILES, "source.diff", "build.stdout", "build.stderr", binary):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"" if name == "source.diff" else b"schema fixture, not a native run\n")
    (root / "population.txt").write_text("\n".join(f"{case}: test" for case in (*reader.CASES, "delegation_lookup_worker")) + "\n")
    (root / "build.stdout").write_text(json.dumps({
        "reason": "compiler-artifact", "target": {"name": "delegation_restart", "kind": ["test"]},
        "profile": {"test": True}, "executable": "/native/" + binary,
    }) + '\n{"reason":"build-finished","success":true}\n')
    shapes = (
        ((1, 1, 0, True), (1, 1, 0, True)),
        ((1, 1, 0, True), (1, 1, 1, False), (2, 2, 1, True), (2, 2, 1, True)),
        ((1, 1, 0, False), (3, 1, 0, False), (3, 1, 0, False), (4, 2, 0, True)),
        ((1, 1, 0, True), (2, 1, 0, True)),
    )
    results = []
    for number, case in enumerate(reader.CASES):
        observations = []
        for index, (stored, verified, revoked, active) in enumerate(shapes[number]):
            observations.append({
                "pid": index + 100, "stored": stored, "verified_for_delegate": verified,
                "locally_revoked": revoked, "active_id": ("B" * 52 if number == 1 and index >= 2 else "A" * 52) if active else None,
                "scope": copy.deepcopy(reader.SCOPE) if active else None,
                "allows_record": active, "allows_staging": active, "allows_push": False,
                "allows_production": False, "allows_other_project": False, "allows_other_view": False,
                "coverage": "local-store-selection-only",
            })
        result = {
            "argv": ["/native/" + binary, "--exact", case, "--nocapture"],
            "case": case, "returncode": 0, "timed_out": False, "wall_seconds": 0.1,
            "stdout": f"case-{number}.stdout", "stderr": f"case-{number}.stderr",
            "observations": observations, "passed": True,
        }
        stdout = "\n".join("ATOMIC_NATIVE_LOOKUP=" + json.dumps(value) for value in observations)
        stdout += f"\ntest {case} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.1s\n"
        (root / result["stdout"]).write_text(stdout)
        (root / result["stderr"]).write_text("")
        results.append(result)
    report = {
        "schema": reader.REPORT, "source": {"commit": "a" * 40, "status": ""},
        "build": {"argv": ["cargo", "test", "--locked", "-p", "atomic-canonical", "--test", "delegation_restart", "--no-run", "--message-format=json", "-j", "2"],
                  "returncode": 0, "timed_out": False, "wall_seconds": 0.5, "stdout": "build.stdout", "stderr": "build.stderr"},
        "binary": {"filename": binary, "sha256": reader.sha(root / binary)},
        "declared_cases": list(reader.CASES), "results": results, "passed": True,
        "coverage": reader.COVERAGE,
        "artifacts": {str(path.relative_to(root)): {"sha256": reader.sha(path), "bytes": path.stat().st_size}
                      for path in root.rglob("*") if path.is_file()},
    }
    write(root / "report.json", report)
    return root


def select(packet, tmp_path):
    path = tmp_path / "selection.json"
    write(path, reader.describe(packet))
    return path, reader.sha(path)


def modify_report(packet, change):
    path = packet / "report.json"
    value = json.loads(path.read_text())
    change(value)
    write(path, value)


def test_consistent_selected_schema_does_not_claim_execution(packet, tmp_path, monkeypatch):
    # This synthetic fixture deliberately cannot authenticate or prove capture.
    monkeypatch.setattr("subprocess.run", lambda *a, **k: pytest.fail("must not execute"))
    selection, pin = select(packet, tmp_path)
    result = reader.verify(packet, selection, pin)
    assert result["accepted"] and result["worker_observations"] == 12
    # PID reuse across case executions is allowed; the receipt derives the
    # distinct value count instead of calling all observations unique workers.
    assert result["distinct_worker_pid_count"] == 4
    assert result["observed_worker_pids"] == [100, 101, 102, 103]
    assert result["coverage"]["external_effects"] == "not observed"
    assert "not rerun" in result["assessment"]


@pytest.mark.parametrize("name", ["source/Cargo.lock", "source/atomic-canonical/tests/delegation_restart.rs", "case-0.stdout", "delegation_restart-synthetic-never-executed"])
def test_changed_selected_bytes_refused(packet, tmp_path, name):
    selection, pin = select(packet, tmp_path)
    with (packet / name).open("ab") as stream:
        stream.write(b"altered")
    with pytest.raises(ValueError, match="artifact_pin_mismatch"):
        reader.verify(packet, selection, pin)


@pytest.mark.parametrize("change,reason", [
    (lambda r: r["results"].pop(), "case_population"),
    (lambda r: r["declared_cases"].pop(), "declared_case_population"),
    (lambda r: r["source"].update(commit="b" * 40), "source_commit"),
    (lambda r: r["source"].update(status=" M test.rs"), "source_commit"),
    (lambda r: r["build"].update(returncode=1), "native_process_failed"),
    (lambda r: r["results"][1].update(timed_out=True), "native_process_failed"),
    (lambda r: r["results"][0].update(argv=["/other/binary", "--exact", reader.CASES[0], "--nocapture"]), "case_command"),
    (lambda r: r["results"][0]["observations"][0].update(allows_push=True), "stdout_observation_binding"),
    (lambda r: r["coverage"].update(server_authorization="established"), "coverage_changed"),
])
def test_reselected_report_still_must_match_native_contract(packet, tmp_path, change, reason):
    original = reader.describe(packet)
    modify_report(packet, change)
    # Retain independently chosen commit/artifact pins; select changed report
    # bytes to exercise validation beyond simply noticing its digest changed.
    original["report_sha256"] = reader.sha(packet / "report.json")
    selection = tmp_path / "selection.json"
    write(selection, original)
    with pytest.raises(ValueError, match=reason):
        reader.verify(packet, selection, reader.sha(selection))


def test_missing_log_and_symlink_refused(packet, tmp_path):
    selection, pin = select(packet, tmp_path)
    (packet / "case-0.stderr").unlink()
    with pytest.raises(ValueError, match="artifact_size_or_missing"):
        reader.verify(packet, selection, pin)
    target = tmp_path / "elsewhere"
    target.write_bytes(b"")
    (packet / "case-0.stderr").symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        reader.verify(packet, selection, pin)


def test_selection_must_be_external_and_digest_selected(packet, tmp_path):
    selection, pin = select(packet, tmp_path)
    with pytest.raises(ValueError, match="selection_pin_mismatch"):
        reader.verify(packet, selection, "0" * 64)
    internal = packet / "selection.json"
    internal.write_bytes(selection.read_bytes())
    with pytest.raises(ValueError, match="selection_inside_packet"):
        reader.verify(packet, internal, pin)


def test_duplicate_members_refused():
    with pytest.raises(ValueError, match="duplicate_json_member"):
        reader.decode(b'{"accepted":true,"accepted":false}')
    with pytest.raises(ValueError, match="nonfinite"):
        reader.decode(b'{"duration":NaN}')


def test_reader_installation_is_selected(packet, tmp_path):
    value = reader.describe(packet)
    value["reader_sha256"] = "0" * 64
    selection = tmp_path / "selection.json"
    write(selection, value)
    with pytest.raises(ValueError, match="installed_reader_pin_mismatch"):
        reader.verify(packet, selection, reader.sha(selection))


def test_path_traversal_refused(packet):
    for value in ("../outside", "/outside", "source/../report.json", "source//Cargo.lock"):
        with pytest.raises(ValueError, match="artifact_path"):
            reader._file(packet, value)


@pytest.mark.parametrize("change,reason", [
    (lambda values: values[0].update(allows_push=True), "scope_widened"),
    (lambda values: values[1].update(pid=values[0]["pid"]), "worker_pid_population"),
    (lambda values: values[0].update(stored=True), "native_store_control"),
])
def test_changed_native_observations_refused_even_when_reselected(packet, tmp_path, change, reason):
    report_path = packet / "report.json"
    report = json.loads(report_path.read_text())
    change(report["results"][0]["observations"])
    stdout = packet / "case-0.stdout"
    lines = stdout.read_text().splitlines()
    observations = iter(report["results"][0]["observations"])
    stdout.write_text("\n".join("ATOMIC_NATIVE_LOOKUP=" + json.dumps(next(observations))
                              if line.startswith("ATOMIC_NATIVE_LOOKUP=") else line for line in lines) + "\n")
    report["artifacts"]["case-0.stdout"] = {"sha256": reader.sha(stdout), "bytes": stdout.stat().st_size}
    write(report_path, report)
    selection, pin = select(packet, tmp_path)
    with pytest.raises(ValueError, match=reason):
        reader.verify(packet, selection, pin)


@pytest.mark.parametrize("target", ["report", "selection"])
def test_oversized_json_refused_before_allocating(packet, tmp_path, monkeypatch, target):
    selection, pin = select(packet, tmp_path)
    path = packet / "report.json" if target == "report" else selection
    with path.open("wb") as stream:
        stream.truncate(reader.MAX_JSON + 1)
    original = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes", lambda p: pytest.fail("oversized JSON must not be allocated")
                        if p == path else original(p))
    with pytest.raises(ValueError, match="json_size_or_missing"):
        reader.verify(packet, selection, pin)
    if target == "report":
        with pytest.raises(ValueError, match="json_size_or_missing"):
            reader.describe(packet)
