"""One shared actual native population for joint reader and host gate controls."""
import os
from pathlib import Path
from typing import Any

import pytest

from joint_common import load
from joint_run import run


@pytest.fixture(scope="session")
def fresh(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    """Run the real population through a relative caller-selected output path.

    The workflow and CLI may supply a relative root. Every literal native
    launch path must still join the plan's selected absolute capture roots.
    """
    root = tmp_path_factory.mktemp("joint-native") / "packet"
    report = run(Path(os.path.relpath(root)), "0" * 40)
    return root, load(root, "consumer-pins.json"), report
