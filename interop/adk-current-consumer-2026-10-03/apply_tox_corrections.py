"""Select the exact corrected ADK source for full tox, before its sample overlay."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path


def git_output(checkout: Path, *arguments: str) -> str:
    """Use the selected checkout without inherited repository/config selection."""
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_TERMINAL_PROMPT="0")
    return subprocess.check_output(
        ["git", "-C", str(checkout), *arguments],
        env=environment, text=True,
    ).strip()


def check_files(root: Path, selected: dict[str, str]) -> None:
    """Refuse missing, redirected or changed selected file bytes."""
    for name, expected in selected.items():
        path = root / name
        if not path.resolve().is_relative_to(root) or path.is_symlink():
            raise SystemExit("source selection refused: redirected file: " + name)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit("source selection refused: selected bytes differ: " + name)


def apply_selection(checkout: Path, profile: Path) -> dict:
    """Join a clean base, licensed patch bytes and the complete selected Git tree."""
    checkout, profile = checkout.resolve(), profile.resolve()
    selection_bytes = (profile / "full-tox-source-selection.json").read_bytes()
    selected = json.loads(selection_bytes)
    if selected["schemaVersion"] != "probity.adk-full-tox-source.v1":
        raise SystemExit("source selection refused: unsupported source contract")
    if Path(git_output(checkout, "rev-parse", "--show-toplevel")).resolve() != checkout:
        raise SystemExit("source selection refused: wrong owning repository")
    if git_output(checkout, "rev-parse", "HEAD") != selected["baseCommit"]:
        raise SystemExit("source selection refused: wrong base commit")
    if git_output(checkout, "status", "--porcelain=v1"):
        raise SystemExit("source selection refused: checkout is not clean")
    check_files(profile, {selected["patchFile"]: selected["patchSHA256"],
                          selected["licenseFile"]: selected["licenseSHA256"],
                          selected["nativeSourceSelection"]["file"]:
                          selected["nativeSourceSelection"]["sha256"]})
    check_files(checkout, selected["originalFileSHA256"] | selected["unchangedFileSHA256"])
    check_files(profile / "upstream-sample", selected["sampleOverlaySHA256"])
    patch = str(profile / selected["patchFile"])
    git_output(checkout, "apply", "--check", "--index", "--whitespace=error-all", patch)
    git_output(checkout, "apply", "--index", "--whitespace=error-all", patch)
    actual_tree = git_output(checkout, "write-tree")
    if actual_tree != selected["patchedSourceTree"]:
        raise SystemExit("source selection refused: patched tree differs")
    check_files(checkout, selected["patchedFileSHA256"] | selected["unchangedFileSHA256"])
    return {"schemaVersion": selected["schemaVersion"],
            "sourceSelectionSHA256": hashlib.sha256(selection_bytes).hexdigest(),
            "baseCommit": selected["baseCommit"], "patchedSourceTree": actual_tree,
            "patchedSourceCommits": selected["patchedSourceCommits"],
            "patchSHA256": selected["patchSHA256"], "license": selected["license"],
            "unchangedFileSHA256": selected["unchangedFileSHA256"],
            "sampleOverlaySHA256": selected["sampleOverlaySHA256"],
            "nativeConsumerSDKCommit": selected["nativeSourceSelection"]["commit"],
            "scope": selected["scope"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    parser.add_argument("receipt", type=Path)
    arguments = parser.parse_args()
    if arguments.receipt.exists() or arguments.receipt.is_symlink():
        raise SystemExit("source selection refused: receipt already exists")
    receipt = apply_selection(arguments.checkout, Path(__file__).resolve().parent)
    with arguments.receipt.open("x") as output:
        output.write(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
