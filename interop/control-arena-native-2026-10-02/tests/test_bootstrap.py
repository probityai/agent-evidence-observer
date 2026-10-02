"""Adversarial controls for verifying installed code before it can execute."""

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest


@pytest.fixture(scope="session")
def bootstrap() -> ModuleType:
    source = Path(__file__).resolve().parents[1] / "run_selected_host.py"
    spec = importlib.util.spec_from_file_location("selected_bootstrap", source)
    if spec is None or spec.loader is None:
        raise RuntimeError("Selected bootstrap source is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def selected_wheel() -> Path:
    selected = os.environ.get("CONTROL_ARENA_WHEEL")
    if not selected:
        raise RuntimeError("CONTROL_ARENA_WHEEL must select the reviewed actual wheel")
    return Path(selected)


class TestInstalledReaderBootstrap:
    class TestFailingCases:
        def test_changed_wheel_refuses_before_starting_a_process(
            self, tmp_path: Path, bootstrap: ModuleType
        ) -> None:
            changed = tmp_path / "changed.whl"
            changed.write_bytes(b"candidate-selected wheel")
            output = tmp_path / "probe.json"
            with pytest.raises(
                ValueError, match="^Wheel differs from the reviewed byte selection$"
            ):
                bootstrap.verify_installed_reader(
                    tmp_path / "nonexistent-python", changed, output, {}
                )
            assert not output.exists()

        def test_changed_installed_module_never_executes(
            self, tmp_path: Path, bootstrap: ModuleType, selected_wheel: Path
        ) -> None:
            environment = tmp_path / "changed-reader"
            subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-m",
                    "venv",
                    "--without-pip",
                    str(environment),
                ],
                check=True,
                env=bootstrap.clean_environment(),
                capture_output=True,
            )
            python = environment / "bin/python"
            packages = Path(
                subprocess.check_output(
                    [
                        str(python),
                        "-I",
                        "-c",
                        "import sysconfig;print(sysconfig.get_path('purelib'))",
                    ],
                    text=True,
                    env=bootstrap.clean_environment(),
                ).strip()
            )
            marker = tmp_path / "unverified-code-executed"
            (packages / "probity_control_arena_reader.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed')\n"
            )
            metadata = packages / "probity_control_arena_reader-0.0.1.dist-info"
            metadata.mkdir()
            (metadata / "METADATA").write_text(
                "Metadata-Version: 2.1\n"
                "Name: probity-control-arena-reader\n"
                "Version: 0.0.1\n"
            )
            with pytest.raises(
                ValueError,
                match="^Installed reader bytes or isolation differ from selection$",
            ):
                bootstrap.verify_installed_reader(
                    python,
                    selected_wheel,
                    tmp_path / "installed-probe.json",
                    bootstrap.clean_environment(),
                )
            assert not marker.exists()
