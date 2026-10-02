"""Replay the original authenticated successful Ubuntu artifact after expiry."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from probity_adk.contract import decode, encode
from probity_adk.reader import verify_saved

PROFILE_ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_SHA256 = "4602b83d1b3e52d6aea8def21eff28f5b18b78c04da9213e4187ee2c1abf31e6"


def test_retained_original_native_ci_bytes(tmp_path: Path) -> None:
    archive = PROFILE_ROOT / "native-fixture-37058694970.zip"
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == ORIGINAL_SHA256
    with zipfile.ZipFile(archive) as retained:
        names = retained.namelist()
        assert len(names) == len(set(names)) == 838
        assert all(
            not Path(name).is_absolute() and ".." not in Path(name).parts
            for name in names
        )
        retained.extractall(tmp_path)
    original = tmp_path / "fresh-run"
    packet = original / "packet"
    report = verify_saved(packet, decode((packet / "consumer-pins.json").read_bytes()))
    expected = (packet / "report.json").read_bytes()
    assert encode(report) == expected
    assert (original / "producer-stdout.json").read_bytes().rstrip(b"\n") == expected
    assert (original / "reader-stdout.json").read_bytes().rstrip(b"\n") == expected
