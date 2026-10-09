"""Check current-source runtime locks against mandatory Observer metadata.

Run from the repository root with the owning test environment. These locks
serve the current source, not separately pinned historical Observer builds.
Installed environments must also pass their own pip check before a reader runs.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

LOCKS = (
    "pydantic-ai-native-2026-10-02/requirements.lock",
    "pydantic-ai-native-2026-10-02/requirements-reader.lock",
    "pydantic-recovery-2026-10-03/requirements.lock",
    "pydantic-recovery-2026-10-03/requirements-reader.lock",
    "joint-recovery-2026-10-02/requirements.lock",
    "joint-recovery-2026-10-02/requirements-reader.lock",
    "target-recovery-2026-10-02/requirements.lock",
    "langgraph-ticket-2026-10-02/requirements.lock",
    "langgraph-ticket-2026-10-02/requirements-restart.lock",
    "adk-a2a-failed-task-2026-10-03/requirements.lock",
    "adk-a2a-failed-task-2026-10-03/requirements-reader.lock",
    "aps-durable-refund-2026-10-05/requirements.lock",
    "pic-aps-refund-reader-2026-10-09/requirements.lock",
    "haystack-native-2026-10-03/requirements.lock",
    "haystack-native-2026-10-03/requirements-reader.lock",
    "smolagents-native-2026-10-03/requirements.lock",
    "smolagents-native-2026-10-03/requirements-reader.lock",
    "witness-operator-2026-10-03/requirements.lock",
    "witness-operator-2026-10-03/requirements-reader.lock",
    "witnessed-run-selection-2026-10-04/requirements.lock",
    "witnessed-run-selection-2026-10-04/requirements-reader.lock",
)


def main() -> None:
    """Refuse a missing or incompatible core pin before native qualification."""
    root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    requirements = [Requirement(value) for value in project["dependencies"]]
    for relative in LOCKS:
        path = root / "interop" / relative
        selected = dict(re.findall(r"^([A-Za-z0-9_.-]+)==([^\s;]+)", path.read_text(), re.MULTILINE))
        selected = {canonicalize_name(name): Version(version) for name, version in selected.items()}
        for requirement in requirements:
            if requirement.url is not None:
                raise SystemExit("core URL needs an explicit source decision: " + str(requirement))
            if requirement.marker is not None:
                raise SystemExit("core marker needs an explicit profile decision: " + str(requirement))
            version = selected.get(canonicalize_name(requirement.name))
            if version is None or version not in requirement.specifier:
                raise SystemExit(f"{path.relative_to(root)} omits core requirement {requirement}")
    print(f"{len(LOCKS)} current-source runtime locks contain every mandatory Observer requirement")


if __name__ == "__main__":
    main()
