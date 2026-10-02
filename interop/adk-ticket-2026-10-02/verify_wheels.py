"""Prove both wheel source populations match the selected byte contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verify(wheels: Path, selection: Path) -> dict:
    contract = json.loads(selection.read_bytes())
    actual = {}
    records = []
    paths = sorted(wheels.glob("*.whl"))
    assert len(paths) == 2, "wheel population differs"
    for path in paths:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            assert len(names) == len(set(names)), "duplicate wheel entries"
            sources = {
                name: sha(archive.read(name)) for name in names if name.endswith(".py")
            }
            assert not (set(actual) & set(sources)), "duplicate source package"
            actual.update(sources)
            metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
            assert len(metadata) == 1
            raw = archive.read(metadata[0])
            sdk_lines = [
                line
                for line in raw.splitlines()
                if line.startswith(
                    (
                        b"Requires-Dist: google-adk",
                        b"Requires-Dist: google-genai",
                        b"Requires-Dist: mcp",
                    )
                )
            ]
            assert all(
                line
                in (
                    b'Requires-Dist: google-adk==2.11.0; extra == "producer"',
                    b'Requires-Dist: mcp==2.2.0; extra == "producer"',
                )
                for line in sdk_lines
            ), "reader default dependency includes producer SDK"
            records.append(
                {
                    "name": path.name,
                    "sha256": sha(path.read_bytes()),
                    "metadataSha256": sha(raw),
                    "pythonSourceCount": len(sources),
                }
            )
    assert actual == contract["pythonSources"], "selected source bytes differ"
    return {
        "status": "verified",
        "selectionSha256": sha(selection.read_bytes()),
        "wheels": records,
        "pythonSourceCount": len(actual),
        "sdkRequiredByReader": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheels", type=Path)
    parser.add_argument("--selection", type=Path, required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            verify(args.wheels, args.selection), sort_keys=True, separators=(",", ":")
        )
    )


if __name__ == "__main__":
    main()
