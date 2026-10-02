"""Exercise launch-contract failures with real child processes and files."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("five_tier_launcher", Path(__file__).resolve().parents[1] / "examples/five_tier_demo.py")
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


def test_child_failure_refuses_even_a_new_report(tmp_path):
    report = tmp_path / "report.json"
    command = [sys.executable, "-c", "import sys;from pathlib import Path;Path(sys.argv[1]).write_text('{\"status\":\"complete\"}');raise SystemExit(9)", str(report)]
    result = launcher._launch(command, tmp_path, report, timeout=5)
    assert report.is_file()
    assert result == {"status": "error", "reason": "child_failed", "exit_code": 9}


def test_zero_exit_without_report_refuses(tmp_path):
    result = launcher._launch([sys.executable, "-c", "pass"], tmp_path, tmp_path / "report.json", timeout=5)
    assert result == {"status": "error", "reason": "fresh_report_missing", "exit_code": 0}


def test_stale_report_refuses_before_child_launch(tmp_path):
    report = tmp_path / "report.json"
    report.write_text('{"status":"complete"}')
    sentinel = tmp_path / "executed"
    command = [sys.executable, "-c", "import sys;from pathlib import Path;Path(sys.argv[1]).touch()", str(sentinel)]
    assert launcher._launch(command, tmp_path, report, timeout=5)["reason"] == "report_already_exists"
    assert not sentinel.exists()


@pytest.mark.parametrize("body", ["not-json", "[]", "{}", '{"value":NaN}', '{"value":1e999}', '{"status":"refused","status":"complete"}'])
def test_unusable_report_refuses(tmp_path, body):
    report = tmp_path / "report.json"
    command = [sys.executable, "-c", "import sys;from pathlib import Path;Path(sys.argv[1]).write_text(sys.argv[2])", str(report), body]
    assert launcher._launch(command, tmp_path, report, timeout=5)["reason"] == "report_unreadable"


def test_child_timeout_is_retained(tmp_path):
    result = launcher._launch([sys.executable, "-c", "import time;time.sleep(10)"], tmp_path, tmp_path / "report.json", timeout=0.05)
    assert result["status"] == "timeout" and result["reason"] == "child_timeout"


def test_child_success_binds_fresh_report_bytes(tmp_path):
    report = tmp_path / "report.json"
    command = [sys.executable, "-c", "import sys;from pathlib import Path;Path(sys.argv[1]).write_text('{\"status\":\"complete\"}')", str(report)]
    result = launcher._launch(command, tmp_path, report, timeout=5)
    assert result["status"] == "complete"
    assert result["report_sha256"] == launcher._hash(report.read_bytes())


@pytest.mark.parametrize("status", ["refused", "failed", "incomplete", "error"])
def test_zero_exit_does_not_override_report_refusal(tmp_path, status):
    report = tmp_path / "report.json"
    command = [sys.executable, "-c", "import sys,json;from pathlib import Path;Path(sys.argv[1]).write_text(json.dumps({'status':sys.argv[2]}))", str(report), status]
    result = launcher._launch(command, tmp_path, report, timeout=5)
    assert result["status"] == "refused" and result["declared_status"] == status
    assert result["report_sha256"] == launcher._hash(report.read_bytes())


def test_success_with_unrecognized_native_profile_refuses(tmp_path):
    report = tmp_path / "report.json"
    command = [sys.executable, "-c", "import sys;from pathlib import Path;Path(sys.argv[1]).write_text('{\"status\":\"complete\"}')", str(report)]
    assert launcher._launch(command, tmp_path, report, timeout=5, expected_profile="a2a")["reason"] == "child_report_profile_differs"


def test_missing_sources_preserve_declared_launches(tmp_path, monkeypatch):
    monkeypatch.setattr(launcher, "ROOT", tmp_path / "unavailable-source")
    report = launcher.run(tmp_path / "packet")
    assert report["declared_launches"] == 3 and report["completed_launches"] == 0
    assert report["status"] == "incomplete"
    assert all(result["status"] == "not-started" for result in report["launch_results"])
    assert report["tiers"] == ["a2a", "agents", "reasoning", "tools", "workloads"]


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
def test_invalid_timeout_refuses_before_creating_output(tmp_path, timeout):
    output = tmp_path / "packet"
    with pytest.raises(ValueError):
        launcher.run(output, timeout=timeout)
    assert not output.exists()
