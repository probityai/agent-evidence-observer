"""Build only the reviewed source bytes into a normal standard-library reader wheel."""

from __future__ import annotations
import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def build(checkout, contract_path, output):
    contract = json.loads(contract_path.read_bytes())
    if output.exists():
        raise ValueError("build output already exists")
    selected = {}
    for target, pin in contract["files"].items():
        source = checkout / pin["path"]
        if not source.resolve().is_relative_to(checkout.resolve()) or any(
            path.is_symlink() for path in (source, *source.parents)
        ):
            raise ValueError("source path escapes checkout or contains a symlink")
        raw = source.read_bytes()
        if digest(raw) != pin["sha256"]:
            raise ValueError("source differs from reviewed contract: " + pin["path"])
        if Path(target).name != target:
            raise ValueError("wheel destination must be a simple filename")
        selected[target] = raw
    output.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="model-reader-") as temporary:
        stage = Path(temporary)
        for target, raw in selected.items():
            (stage / target).write_bytes(raw)
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-index",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                str(output.resolve()),
                str(stage),
            ],
            check=True,
        )
    wheels = list(output.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("build did not retain exactly one wheel")
    with zipfile.ZipFile(wheels[0]) as archive:
        for target, raw in selected.items():
            if target.endswith(".py") and archive.read(target) != raw:
                raise ValueError("built wheel changes selected source")
    record = {
        "schema": "probity-model-reader-build-v1",
        "sourceContractSha256": digest(contract_path.read_bytes()),
        "sources": {name: digest(raw) for name, raw in selected.items()},
        "wheel": {
            "name": wheels[0].name,
            "bytes": wheels[0].stat().st_size,
            "sha256": digest(wheels[0].read_bytes()),
        },
    }
    (output / "build-record.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--contract",
        type=Path,
        default=Path(__file__).with_name("source-contract.json"),
    )
    args = parser.parse_args()
    print(json.dumps(build(args.checkout, args.contract, args.output), indent=2))


if __name__ == "__main__":
    main()
