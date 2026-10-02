import json
import subprocess
import sys

import pytest

from probity_observer.native_reader import _child, _common, decode, run


def common():
    return {
        "profile": "probity-five-tier-result-reference-v0",
        "planned": 6,
        "started": 5,
        "complete": 2,
        "scored": 2,
        "task_passed": 1,
        "task_failed": 1,
        "failed": 2,
        "missing": 0,
        "unknown_start": 1,
        "incomplete": 1,
    }


@pytest.mark.parametrize(
    "body,reason",
    [
        ("raise SystemExit(3)", "reader_child_failure"),
        ("pass", "json_size"),
        ("print('{}')", "json_object"),
        ('print(\'{"profile":"other"}\')', "reader_report_profile"),
        ('print(\'{"a":1,"a":2}\')', "duplicate_json_member"),
        ("print('{\"a\":NaN}')", "nonfinite_json"),
    ],
)
def test_real_child_failure_controls(tmp_path, body, reason):
    script = tmp_path / "child.py"
    script.write_text(body)
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(ValueError, match=reason):
        _child([sys.executable, str(script)], tmp_path, out, 3)
    assert (out / "reader-stderr.txt").is_file()
    assert decode((out / "child-status.json").read_bytes()) == {
        "status": "exited",
        "exit_code": 3 if reason == "reader_child_failure" else 0,
    }


def test_real_child_keeps_failure_denominators(tmp_path):
    script = tmp_path / "child.py"
    script.write_text("print(" + repr(json.dumps(common())) + ")")
    out = tmp_path / "out"
    out.mkdir()
    assert _child([sys.executable, str(script)], tmp_path, out, 3) == common()


def test_real_timeout(tmp_path):
    script = tmp_path / "child.py"
    script.write_text("import time; time.sleep(20)")
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(ValueError, match="reader_timeout"):
        _child([sys.executable, str(script)], tmp_path, out, 0.1)
    assert decode((out / "child-status.json").read_bytes())["status"] == "timeout"


def test_child_cannot_reuse_stale_stdout(tmp_path):
    (tmp_path / "reader-stdout.json").write_text(json.dumps(common()))
    with pytest.raises(FileExistsError):
        _child([sys.executable, "-c", "pass"], tmp_path, tmp_path, 1)


def test_existing_output_refuses(tmp_path):
    packet = tmp_path / "packet"
    packet.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(ValueError, match="output_already_exists"):
        run(tmp_path, packet, tmp_path / "selection", out, selection_sha256="0" * 64)


def test_packet_symlink_keeps_refusal_receipt(tmp_path):
    packet = tmp_path / "packet"
    packet.mkdir()
    (packet / "link").symlink_to(tmp_path / "anything")
    out = tmp_path / "out"
    receipt = run(
        tmp_path, packet, tmp_path / "selection", out, selection_sha256="0" * 64
    )
    assert receipt["status"] == "refused" and receipt["reason"] == "packet_symlink"
    assert decode((out / "report.json").read_bytes()) == receipt


def test_manifest_must_be_outside_packet(tmp_path):
    packet = tmp_path / "packet"
    packet.mkdir()
    receipt = run(
        tmp_path,
        packet,
        packet / "selection.json",
        tmp_path / "out",
        selection_sha256="0" * 64,
    )
    assert receipt["status"] == "refused" and "inside_packet" in receipt["reason"]


def test_manifest_digest_is_required(tmp_path):
    packet = tmp_path / "packet"
    packet.mkdir()
    selection = tmp_path / "selection.json"
    selection.write_text('{"format":"anything"}')
    receipt = run(
        tmp_path, packet, selection, tmp_path / "out", selection_sha256="0" * 64
    )
    assert receipt["reason"] == "selection_pin_mismatch"


def test_install_failure_never_calls_reader(tmp_path):
    # The composite action's install/read steps both use set -euo pipefail.
    # Exercise the same stop rule using a genuinely nonexistent local wheel.
    marker = tmp_path / "reader-called"
    command = [
        "bash",
        "-c",
        'set -euo pipefail\n"$1" -m pip install --no-index "$2"\n"$1" -c "import pathlib,sys; pathlib.Path(sys.argv[1]).touch()" "$3"',
        "test-install",
        sys.executable,
        str(tmp_path / "nonexistent.whl"),
        str(marker),
    ]
    result = subprocess.run(command, capture_output=True, check=False)
    assert result.returncode != 0
    assert not marker.exists()


@pytest.mark.parametrize(
    "field,value",
    [("planned", True), ("scored", 8), ("status", "refused"), ("started", 9)],
)
def test_report_must_retain_valid_population(field, value):
    report = common()
    report[field] = value
    with pytest.raises(ValueError):
        _common(report)
