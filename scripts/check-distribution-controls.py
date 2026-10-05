"""Exercise install-route and wheel substitutions against the distribution gate."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from zipfile import ZipFile


def run(wheel: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    wheel = wheel.resolve()
    with tempfile.TemporaryDirectory(prefix="observer-distribution-controls-") as temp:
        selected = Path(temp) / "source"
        selected.mkdir()
        for name in ("pyproject.toml", "README.md", "LICENSE"):
            shutil.copyfile(root / name, selected / name)
        for name in ("src", "scripts", "docs"):
            shutil.copytree(root / name, selected / name, ignore=shutil.ignore_patterns("__pycache__"))
        for manifest in (root / "interop").glob("*/pyproject.toml"):
            target = selected / manifest.relative_to(root).parent
            target.mkdir(parents=True)
            for name in ("pyproject.toml", "README.md"):
                shutil.copyfile(manifest.parent / name, target / name)
        command = [sys.executable, str(selected / "scripts/check-distribution.py")]

        def expect(name: str, artifact: Path, passed: bool) -> None:
            result = subprocess.run(command + [str(artifact)], capture_output=True)
            if (result.returncode == 0) != passed:
                raise RuntimeError(f"{name}: unexpected status {result.returncode}\n" + result.stdout.decode() + result.stderr.decode())
            print(f"{name}: {'accepted' if passed else 'refused'}")

        expect("original-wheel-and-routes", wheel, True)
        guide = selected / "docs/INSTALLATION.md"
        original = guide.read_text()
        row = next(line for line in original.splitlines() if line.startswith("| [adk-user-responses-2026-10-04]"))
        for name, before, after in (
            ("wrong-profile-python", "`>=3.12`", "`>=3.13`"),
            ("wrong-profile-name", "`probity-adk-user-responses`", "`unrelated-package`"),
            ("missing-profile-command", "`probity-adk-responses-read`", "`unrelated-command`"),
        ):
            assert before in row
            guide.write_text(original.replace(row, row.replace(before, after)))
            expect(name, wheel, False)
            guide.write_text(original)
        with ZipFile(wheel) as archive:
            members = {info.filename: (info, archive.read(info)) for info in archive.infolist()}
        metadata = next(name for name in members if name.endswith(".dist-info/METADATA"))
        license_path = next(name for name in members if name.endswith(".dist-info/licenses/LICENSE"))
        for name, changed in (
            ("changed-wheel-module", "probity_observer/__init__.py"),
            ("changed-wheel-license", license_path),
            ("changed-wheel-readme", metadata),
        ):
            controlled = Path(temp) / f"{name}.whl"
            with ZipFile(controlled, "w") as archive:
                for filename, (info, raw) in members.items():
                    archive.writestr(info, raw + b"\nsubstituted bytes\n" if filename == changed else raw)
            expect(name, controlled, False)
        print("six distribution substitutions refused")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    run(parser.parse_args().wheel)
