"""Build a normal offline reader wheel from separately selected reviewed sources."""

from __future__ import annotations

import argparse
import base64
import configparser
import csv
import hashlib
import importlib.metadata
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from email.parser import BytesParser
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


def git(checkout: Path, *args: str) -> bytes:
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    return subprocess.check_output(
        ["git", "--no-replace-objects", "-C", str(checkout), *args], env=environment
    )


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
    repository = Path(git(checkout, "rev-parse", "--show-toplevel").decode().strip())
    if repository.resolve() != checkout.resolve():
        raise ValueError("checkout is not the selected repository root")
    selected = {}
    for target, pin in contract["files"].items():
        if set(pin) != {"path", "sha256", "commit"}:
            raise ValueError("source pin must include path, digest and reviewed commit")
        if not re.fullmatch(r"[0-9a-f]{40}", pin["commit"]):
            raise ValueError("source pin must name a full reviewed commit")
        if (
            git(checkout, "rev-parse", "--verify", pin["commit"] + "^{commit}")
            .decode()
            .strip()
            != pin["commit"]
        ):
            raise ValueError("source pin does not name the reviewed commit object")
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
        frozen = git(checkout, "show", f"{pin['commit']}:{pin['path']}")
        if frozen != raw:
            raise ValueError("source differs from reviewed commit: " + pin["path"])
        selected[target] = raw
    return selected


def verify_wheel(wheel: Path, selected: dict[str, bytes]) -> None:
    """Refuse additional code, redirected entry points or changed wheel members."""
    metadata_root = PACKAGE + "-0.1.0.dist-info/"
    package_files = {name for name in selected if name.startswith(PACKAGE + "/")}
    metadata_files = {
        metadata_root + name
        for name in ("METADATA", "WHEEL", "RECORD", "entry_points.txt", "top_level.txt")
    }
    license_choices = {metadata_root + "LICENSE", metadata_root + "licenses/LICENSE"}
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        name_set = set(names)
        licenses = name_set & license_choices
        if (
            len(names) != len(name_set)
            or len(licenses) != 1
            or name_set != package_files | metadata_files | licenses
        ):
            raise ValueError("wheel member population differs from selected package")
        for target in package_files:
            if archive.read(target) != selected[target]:
                raise ValueError("installed wheel changes selected source: " + target)
        if archive.read(next(iter(licenses))) != selected["LICENSE"]:
            raise ValueError("installed wheel changes selected license")
        metadata = BytesParser().parsebytes(archive.read(metadata_root + "METADATA"))
        if (
            metadata.get("Name") != "probity-policy-vocabulary-reader"
            or metadata.get("Version") != "0.1.0"
            or metadata.get_all("Requires-Dist")
        ):
            raise ValueError("wheel distribution identity or dependencies differ")
        entry = configparser.ConfigParser(interpolation=None)
        entry.read_string(archive.read(metadata_root + "entry_points.txt").decode())
        if entry.sections() != ["console_scripts"] or dict(
            entry["console_scripts"]
        ) != {"probity-policy-vocabulary-reader": PACKAGE + ".cli:main"}:
            raise ValueError("wheel entry point differs from selected reader")
        records = list(
            csv.reader(io.StringIO(archive.read(metadata_root + "RECORD").decode()))
        )
        if (
            any(len(row) != 3 for row in records)
            or len(records) != len(names)
            or {row[0] for row in records} != name_set
        ):
            raise ValueError("wheel RECORD population differs")
        for name, expected_hash, expected_bytes in records:
            if name == metadata_root + "RECORD":
                if expected_hash or expected_bytes:
                    raise ValueError("wheel RECORD must not hash itself")
                continue
            raw = archive.read(name)
            actual_hash = "sha256=" + base64.urlsafe_b64encode(
                hashlib.sha256(raw).digest()
            ).decode().rstrip("=")
            if actual_hash != expected_hash or str(len(raw)) != expected_bytes:
                raise ValueError("wheel RECORD commitment differs: " + name)


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
                "--check-build-dependencies",
                "--wheel-dir",
                str(output.resolve()),
                str(stage),
            ],
            check=True,
            env=dict(os.environ, SOURCE_DATE_EPOCH="1767225600"),
        )
    wheels = list(output.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("build did not retain exactly one wheel")
    verify_wheel(wheels[0], selected)
    record = {
        "schema": "probity-policy-vocabulary-reader-build-v1",
        "sourceContractSha256": contract_sha256,
        "sourceDateEpoch": 1767225600,
        "toolchain": {
            name: importlib.metadata.version(name)
            for name in ("pip", "setuptools", "wheel")
        },
        "reproducibility": "Selected source bytes and ZIP timestamps fixed; complete wheel output also depends on the recorded toolchain.",
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
