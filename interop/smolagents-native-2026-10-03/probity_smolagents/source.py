"""Authenticate installed selected source before native framework imports."""
from __future__ import annotations

import importlib.metadata
from pathlib import Path
from typing import Any

from .contract import SDK_SOURCE, SDK_VERSION, encode, exact, load, require, sha

DISTRIBUTIONS = (
    ("probity-smolagents-reference", "probity_smolagents/"),
    ("agent-evidence-observer", "probity_observer/"),
)


def sdk_selection() -> dict[str, Any]:
    """Read the package's primary-source selection, independent of smolagents.

    Returns
    -------
    dict
        Complete Python and YAML source hashes derived from the official SDK
        Git tree. This reader does not import or require the framework.
    """
    selected = load(Path(__file__).with_name("sdk-source-selection.json"))
    exact(selected["commit"], SDK_SOURCE, "SDK source selection differs")
    exact(selected["version"], SDK_VERSION, "SDK version selection differs")
    return selected


def installed_files(distribution: str, prefix: str) -> dict[str, Path]:
    """Find regular selected files and refuse pre-existing package bytecode."""
    installed = importlib.metadata.distribution(distribution)
    result: dict[str, Path] = {}
    for member in installed.files or []:
        name = str(member)
        if name.startswith(prefix) and name.endswith((".py", ".yaml", ".yml", ".json")):
            path = Path(installed.locate_file(member))
            require(path.is_file() and not path.is_symlink(), "installed source is not regular")
            result[name] = path
    require(bool(result), "installed source population is empty")
    # Distribution metadata may omit caches; scan the actual selected package.
    roots = {path.parents[len(name.split("/")) - 2] for name, path in result.items()}
    require(
        all(not list(root.rglob("*.pyc")) for root in roots),
        "unselected installed bytecode",
    )
    return result


def qualify_sdk() -> dict[str, Path]:
    """Check every installed SDK Python/YAML file against immutable Git bytes.

    This must run before native imports. Dependency packages and the Python
    interpreter remain explicitly trusted by this finite profile.
    """
    exact(importlib.metadata.version("smolagents"), SDK_VERSION, "installed SDK version differs")
    files = installed_files("smolagents", "smolagents/")
    selected = sdk_selection()["files"]
    exact(sorted(files), sorted(selected), "installed SDK source population differs")
    for name, path in files.items():
        exact(sha(path.read_bytes()), selected[name]["sha256"], "installed SDK source bytes differ")
    return files


def expected_sources() -> dict[str, str]:
    """Get trusted reader/core hashes plus primary selected SDK source hashes."""
    result = {
        name: metadata["sha256"] for name, metadata in sdk_selection()["files"].items()
    }
    for distribution, prefix in DISTRIBUTIONS:
        for name, path in installed_files(distribution, prefix).items():
            result[name] = sha(path.read_bytes())
    return result


def snapshot_sources(root: Path) -> dict[str, str]:
    """Retain the complete selected source population before framework imports."""
    files = qualify_sdk()
    for distribution, prefix in DISTRIBUTIONS:
        files.update(installed_files(distribution, prefix))
    hashes: dict[str, str] = {}
    for name, path in files.items():
        raw = path.read_bytes()
        destination = root / "source" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        hashes[name] = sha(raw)
    (root / "source-before-run.json").write_bytes(encode(hashes))
    return hashes
