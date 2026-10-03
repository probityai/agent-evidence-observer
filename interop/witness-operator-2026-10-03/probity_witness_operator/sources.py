"""Retain the selected installed core/profile source population only."""

from __future__ import annotations

import importlib.metadata as metadata
from pathlib import Path

from .protocol import require, sha

PACKAGES = ("agent-evidence-observer", "probity-witness-operator-reference")


def installed_sources() -> dict[str, Path]:
    """Return every installed Python source file owned by the two selected wheels.

    Returns
    -------
    dict
        Relative installed module names and resolved source paths. Dependency
        and interpreter source are outside this selected population.
    """
    sources: dict[str, Path] = {}
    for name in PACKAGES:
        distribution = metadata.distribution(name)
        require(distribution.files is not None, "installed source population is missing")
        selected = {str(item): Path(distribution.locate_file(item)).resolve()
                    for item in distribution.files if str(item).endswith(".py")}
        require(bool(selected), "selected wheel has no installed Python source")
        sources.update(selected)
    return sources


def installed_map() -> dict[str, str]:
    """Hash exact source bytes for the selected installed wheel population."""
    return {name: sha(path.read_bytes()) for name, path in installed_sources().items()}


def retain_sources(directory: Path) -> dict[str, str]:
    """Copy selected installed source bytes before launching the producer."""
    sources = installed_sources()
    directory.mkdir()
    for name, path in sources.items():
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
    return {name: sha(path.read_bytes()) for name, path in sources.items()}


def verify_sources(directory: Path, expected: dict[str, str]) -> None:
    """Refuse changes or additions to the retained physical source population."""
    found = {str(path.relative_to(directory)) for path in directory.rglob("*") if path.is_file()}
    require(found == set(expected), "retained source population differs")
    for name, digest in expected.items():
        path = directory / name
        require(not path.is_symlink(), "retained source is a symlink")
        require(path.resolve().is_relative_to(directory.resolve()), "retained source escapes directory")
        require(sha(path.read_bytes()) == digest, "retained source bytes differ")
