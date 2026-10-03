"""Build a normal offline reader wheel from separately selected reviewed sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

PACKAGE = "probity_policy_vocabulary_reader"
TARGETS = {
    "pyproject.toml",
    "LICENSE",
    *{
        f"{PACKAGE}/{name}"
        for name in (
            "__init__.py",
            "cli.py",
            "task_matrix.py",
            "schema_contract.py",
            "protocol.json",
            "prepare_boundary.py",
            "build_protocol.py",
        )
    },
}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def select(
    checkout: Path, contract_raw: bytes, contract_sha256: str
) -> dict[str, bytes]:
    if digest(contract_raw) != contract_sha256:
        raise ValueError("source contract differs from host selection")
    contract = json.loads(contract_raw)
    if (
        contract.get("schema") != "probity-policy-vocabulary-reader-source-v1"
        or contract.get("version") != "0.1.0"
        or set(contract.get("files", {})) != TARGETS
    ):
        raise ValueError("source contract has unsupported identity or population")
    selected = {}
    for target, pin in contract["files"].items():
        if set(pin) != {"path", "sha256", "commit"}:
            raise ValueError("source pin must include path, digest and reviewed commit")
        if not re.fullmatch(r"[0-9a-f]{40}", pin["commit"]):
            raise ValueError("source pin must name a full reviewed commit")
        relative = Path(pin["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("source selection escapes checkout")
        path = checkout / relative
        if not path.resolve().is_relative_to(checkout.resolve()) or any(
            parent.is_symlink() for parent in (path, *path.parents)
        ):
            raise ValueError("source selection contains a symlink or escapes checkout")
        raw = path.read_bytes()
        if digest(raw) != pin["sha256"]:
            raise ValueError("source differs from reviewed digest: " + pin["path"])
        frozen = subprocess.check_output(
            ["git", "-C", str(checkout), "show", f"{pin['commit']}:{pin['path']}"]
        )
        if frozen != raw:
            raise ValueError("source differs from reviewed commit: " + pin["path"])
        selected[target] = raw
    return selected


def build(
    checkout: Path, contract_path: Path, contract_sha256: str, output: Path
) -> dict:
    selected = select(checkout, contract_path.read_bytes(), contract_sha256)
    if output.exists():
        raise ValueError("build output already exists")
    output.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="policy-vocabulary-reader-") as temporary:
        stage = Path(temporary)
        for target, raw in selected.items():
            path = stage / target
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
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
            if target.startswith(PACKAGE + "/") and archive.read(target) != raw:
                raise ValueError("installed wheel changes selected source: " + target)
    record = {
        "schema": "probity-policy-vocabulary-reader-build-v1",
        "sourceContractSha256": contract_sha256,
        "sources": {name: digest(raw) for name, raw in selected.items()},
        "wheel": {
            "name": wheels[0].name,
            "bytes": wheels[0].stat().st_size,
            "sha256": digest(wheels[0].read_bytes()),
        },
    }
    (output / "build-record.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--contract-sha256", required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            build(args.checkout, args.contract, args.contract_sha256, args.output),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
