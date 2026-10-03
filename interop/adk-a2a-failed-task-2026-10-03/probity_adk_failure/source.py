"""Authenticate installed selected source before native framework imports."""
from __future__ import annotations

import importlib.metadata
from pathlib import Path
from typing import Any

from .contract import A2A_SOURCE, A2A_VERSION, REVISIONS, SDK_VERSION, encode, exact, load, require, sha

DISTRIBUTIONS = (
    ("probity-adk-failure-reference", "probity_adk_failure/"),
    ("agent-evidence-observer", "probity_observer/"),
)
SOURCE_SUFFIXES = (".py", ".json")


def sdk_selection() -> dict[str, Any]:
    """Read the package's primary-source selection, independent of smolagents.

    Returns
    -------
    dict
        Complete ADK Python hashes from both pinned Git trees and exact
        A2A release wheel Python hashes. This reader needs neither framework.
    """
    selected = load(Path(__file__).with_name("sdk-source-selection.json"))
    exact(selected["revisions"], REVISIONS, "SDK source selection differs")
    exact(selected["versions"], {"google-adk": SDK_VERSION, "a2a-sdk": A2A_VERSION},
          "SDK version selection differs")
    exact(selected["a2aSource"], {"repository": "a2aproject/a2a-python",
          "commit": A2A_SOURCE, "tag": "v1.2.1"}, "A2A source selection differs")
    return selected


def installed_files(distribution: str, prefix: str) -> dict[str, Path]:
    """Find regular selected files and refuse pre-existing package bytecode."""
    installed = importlib.metadata.distribution(distribution)
    result: dict[str, Path] = {}
    suffixes = (".py",) if prefix in {"google/adk/", "a2a/"} else SOURCE_SUFFIXES
    for member in installed.files or []:
        name = str(member)
        if name.startswith(prefix) and name.endswith(suffixes):
            path = Path(installed.locate_file(member))
            require(path.is_file() and not path.is_symlink(), "installed source is not regular")
            result[name] = path
    require(bool(result), "installed source population is empty")
    # Distribution metadata may omit caches; scan the actual selected package.
    root = Path(installed.locate_file(prefix.rstrip("/")))
    physical = list(root.rglob("*"))
    require(
        not root.is_symlink() and all(not path.is_symlink() for path in physical),
        "installed source is not regular",
    )
    require(
        not any(path.suffix in {".pyc", ".so", ".pyd"} for path in physical),
        "unselected installed bytecode",
    )
    physical_names = [
        prefix + path.relative_to(root).as_posix()
        for path in physical if path.is_file() and path.name.endswith(suffixes)
    ]
    exact(sorted(physical_names), sorted(result), "unlisted installed source")
    return result


def qualify_sdk(variant: str) -> dict[str, Path]:
    """Check both installed native SDKs against independently selected bytes.

    This must run before native imports. Dependency packages and the Python
    interpreter remain explicitly trusted by this finite profile.
    """
    require(variant in REVISIONS, "unknown SDK variant")
    files: dict[str, Path] = {}
    selected = sdk_selection()
    for distribution, prefix, version, hashes in (
        ("google-adk", "google/adk/", SDK_VERSION, selected["adk"][variant]),
        ("a2a-sdk", "a2a/", A2A_VERSION, selected["a2a"]),
    ):
        exact(importlib.metadata.version(distribution), version, "installed SDK version differs")
        members = installed_files(distribution, prefix)
        exact(sorted(members), sorted(hashes), "installed SDK source population differs")
        for name, path in members.items():
            exact(sha(path.read_bytes()), hashes[name], "installed SDK source bytes differ")
        files.update(members)
    return files


def expected_sources(variant: str) -> dict[str, str]:
    """Get trusted reader/core hashes plus primary selected SDK source hashes."""
    require(variant in REVISIONS, "unknown SDK variant")
    selected = sdk_selection()
    result = {**selected["adk"][variant], **selected["a2a"]}
    for distribution, prefix in DISTRIBUTIONS:
        for name, path in installed_files(distribution, prefix).items():
            result[name] = sha(path.read_bytes())
    return result


def snapshot_sources(root: Path, variant: str) -> dict[str, str]:
    """Retain the complete selected source population before framework imports."""
    files = qualify_sdk(variant)
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
