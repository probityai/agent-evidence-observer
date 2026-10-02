"""One fresh installed ADK population shared by semantic controls."""

from pathlib import Path
from typing import Any

import pytest

from probity_adk.producer import run


@pytest.fixture(scope="session")
def packet(tmp_path_factory: Any) -> Path:
    path = tmp_path_factory.mktemp("native-adk") / "packet"
    run(path)
    return path
