"""One shared actual native population for joint reader and host gate controls."""
from pathlib import Path
from typing import Any

import pytest

from joint_common import load
from joint_run import run


@pytest.fixture(scope="session")
def fresh(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    """Run all native processes once; no prerecorded synthetic substitute."""
    root = tmp_path_factory.mktemp("joint-native") / "packet"
    report = run(root, "0" * 40)
    return root, load(root, "consumer-pins.json"), report
