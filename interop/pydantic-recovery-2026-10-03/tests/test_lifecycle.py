"""Native signal cleanup and exclusive publication before ready-file visibility."""
from __future__ import annotations

import os
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from probity_pydantic_recovery import common


def test_ready_publication_exposes_only_complete_private_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The target's readiness poll cannot see the intermediate JSON write."""
    ready = tmp_path / "ready.json"
    original = os.link
    publication = []

    def before_publish(source: str, destination: Path) -> None:
        assert not ready.exists()
        assert common.load(Path(source)) == {"ready": True, "payload": "x" * 65536}
        assert stat.S_IMODE(Path(source).stat().st_mode) == 0o600
        publication.append(source)
        original(source, destination)

    monkeypatch.setattr(common.os, "link", before_publish)
    common.write(ready, {"ready": True, "payload": "x" * 65536})
    assert len(publication) == 1 and common.load(ready)["ready"] is True
    assert list(tmp_path.iterdir()) == [ready]


def test_exclusive_publication_preserves_existing_bytes_and_cleans_temp(tmp_path: Path) -> None:
    ready = tmp_path / "ready.json"
    ready.write_bytes(b"retained original")
    with pytest.raises(FileExistsError):
        common.write(ready, {"changed": True})
    assert ready.read_bytes() == b"retained original"
    assert list(tmp_path.iterdir()) == [ready]


SIGNAL_CONTROL = """
import sys, time
from datetime import UTC, datetime
from pathlib import Path
import recovery_run
from probity_pydantic_recovery.common import write

def hold(root, private, revision):
    case, store = recovery_run.selection(private, 'signal-control', 'permit', datetime.now(UTC).replace(microsecond=0))
    process, command, ready = recovery_run.target(private, store, case['initial']['receipt'], 'first', case['historicalTime'])
    write(root / 'control-ready.json', {'targetPid': process.pid})
    while True:
        time.sleep(0.05)

recovery_run.prepare_and_execute = hold
recovery_run.run(Path(sys.argv[1]), 'signal-control')
"""


def await_control(path: Path, process: subprocess.Popen) -> dict:
    """Prove the owned target exists before sending the parent's SIGTERM."""
    deadline = time.monotonic() + 10
    while not path.exists():
        assert process.poll() is None and time.monotonic() < deadline
        time.sleep(0.02)
    return common.load(path)


def test_sigterm_reaps_owned_target_and_removes_private_keys(tmp_path: Path) -> None:
    root = tmp_path / "interrupted"
    process = subprocess.Popen([sys.executable, "-c", SIGNAL_CONTROL, str(root)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    private = tmp_path / "interrupted-private"
    try:
        control = await_control(root / "control-ready.json", process)
        target_pid = control["targetPid"]
        os.kill(target_pid, 0)
        assert stat.S_IMODE(private.stat().st_mode) == 0o700
        assert stat.S_IMODE((private / "first-config.json").stat().st_mode) == 0o600
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 143, (stdout, stderr)
        assert not private.exists()
        with pytest.raises(ProcessLookupError):
            os.kill(target_pid, 0)
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=10)
