"""Fresh actual-framework packet shared only as immutable test input."""

from pathlib import Path

import pytest

from probity_pydantic.producer import run


@pytest.fixture(scope="session")
def original_packet(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Run seven actual native-tool/HTTP cases once; retain exact bytes for tests."""
    output = tmp_path_factory.mktemp("pydantic-fixture") / "packet"
    run(output, "pytest-local-reference")
    return output
