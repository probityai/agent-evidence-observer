"""Build a deterministic dependency-free reader wheel from selected Git source.

The caller supplies a source-contract digest selected outside the packet.
The installed reader includes frozen native source only for custody comparison;
verification never imports that runtime or performs model inference.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import subprocess
import zipfile

PACKAGE = "probity_tool_arguments_reader"
WHEEL = PACKAGE + "-0.1.0-py3-none-any.whl"
DIST = PACKAGE + "-0.1.0.dist-info"
READER_MARKER = b'{"installationRole":"model-free-reader","modelDispatch":false}\n'


def hash_record(raw: bytes) -> str:
    """Return the wheel RECORD's URL-safe unpadded SHA-256."""
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def build(repository: Path, output: Path, contract: dict) -> dict:
    """Build only exact selected blobs without setuptools or dependency access."""
    entries = {PACKAGE + "/__init__.py": b'"""Frozen model-free authored tool-argument reader."""\n', PACKAGE + "/reader-mode.json": READER_MARKER}
    for name, selected in contract["files"].items():
        raw = subprocess.run(["git", "show", contract["sourceCommit"] + ":" + contract["profilePath"] + "/" + name], cwd=repository, check=True, capture_output=True, timeout=10).stdout
        if hashlib.sha256(raw).hexdigest() != selected:
            raise ValueError("selected reader Git blob changed")
        entries[PACKAGE + "/" + name] = raw
    entries[DIST + "/METADATA"] = b"Metadata-Version: 2.1\nName: probity-tool-arguments-reader\nVersion: 0.1.0\nSummary: Frozen finite tool-argument model-free evidence reader\nRequires-Python: >=3.12\nLicense: Apache-2.0\n\n"
    entries[DIST + "/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: probity-stdlib-reader-builder\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    entries[DIST + "/entry_points.txt"] = b"[console_scripts]\nprobity-tool-arguments-reader = probity_tool_arguments_reader.task_matrix:main\n"
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for name, raw in sorted(entries.items()):
        writer.writerow([name, hash_record(raw), len(raw)])
    writer.writerow([DIST + "/RECORD", "", ""])
    entries[DIST + "/RECORD"] = record.getvalue().encode()
    output.mkdir(parents=True, exist_ok=True)
    wheel = output / WHEEL
    with zipfile.ZipFile(wheel, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, raw in sorted(entries.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, raw)
    receipt = {"sourceCommit": contract["sourceCommit"], "profilePath": contract["profilePath"], "selectedFiles": contract["files"], "wheel": WHEEL, "bytes": wheel.stat().st_size, "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(), "dependencyTransfers": 0, "modelCalls": 0, "generatedReaderRoleMarkerSHA256": hashlib.sha256(READER_MARKER).hexdigest()}
    (output / "build-receipt.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    return receipt


def main() -> None:
    """Require a separately supplied source contract and its original digest."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--contract-sha256", required=True)
    args = parser.parse_args()
    raw = args.contract.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.contract_sha256:
        raise ValueError("selected reader source contract changed")
    print(json.dumps(build(args.repository, args.output, json.loads(raw)), sort_keys=True))


if __name__ == "__main__":
    main()
