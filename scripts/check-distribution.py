"""Check the root wheel and public install routes against their source files."""

from __future__ import annotations

import argparse
from email.parser import BytesParser
from pathlib import Path
import tomllib
from zipfile import ZipFile


def profile_guides(root: Path) -> dict[Path, Path]:
    """Select the maintained guide for each separately installed source unit."""
    overrides = {"langgraph-crash-window-2026-10-03": "PROFILE.md"}
    return {
        manifest: manifest.parent / overrides.get(manifest.parent.name, "README.md")
        for manifest in sorted((root / "interop").glob("*/pyproject.toml"))
    }


def check(wheel: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    guide = (root / "docs/INSTALLATION.md").read_text()
    routes = profile_guides(root)
    rows = [line for line in guide.splitlines() if line.startswith("| [")]
    assert len(rows) == len(routes), "profile route population"
    for manifest, profile_guide in routes.items():
        profile = tomllib.loads(manifest.read_text())["project"]
        prefix = f"| [{manifest.parent.name}]"
        rows = [line for line in guide.splitlines() if line.startswith(prefix)]
        assert len(rows) == 1, f"missing or repeated install route: {manifest}"
        row = rows[0]
        assert f"`{profile['name']}`" in row, f"distribution identity: {manifest}"
        assert f"`{profile['requires-python']}`" in row, f"Python constraint: {manifest}"
        assert profile_guide.is_file(), f"profile guide: {manifest}"
        url = "https://github.com/probityai/agent-evidence-observer/blob/main/"
        url += profile_guide.relative_to(root).as_posix()
        assert f"{prefix}({url})" in row, f"profile guide URL: {manifest}"
        for command in profile.get("scripts", {}):
            assert f"`{command}`" in row, f"console command: {manifest}"

    with ZipFile(wheel) as archive:
        names = archive.namelist()
        metadata_paths = [name for name in names if name.endswith(".dist-info/METADATA")]
        assert len(metadata_paths) == 1, "wheel metadata population"
        metadata_path = metadata_paths[0]
        info = metadata_path.rsplit("/", 1)[0]
        metadata = BytesParser().parsebytes(archive.read(metadata_path))
        assert metadata["Name"] == project["name"], "wheel name"
        assert metadata["Version"] == project["version"], "wheel version"
        assert metadata["Summary"] == project["description"], "wheel summary"
        assert metadata["Requires-Python"] == project["requires-python"], "wheel Python"
        assert metadata["License-Expression"] == "Apache-2.0", "wheel license expression"
        assert metadata["Description-Content-Type"] == "text/markdown", "wheel readme type"
        assert metadata.get_payload().rstrip() == (root / project["readme"]).read_text().rstrip(), "wheel readme bytes"
        assert set(metadata.get_all("Project-URL", [])) == {
            f"{label}, {url}" for label, url in project["urls"].items()
        }, "wheel project URLs"
        assert archive.read(f"{info}/licenses/LICENSE") == (root / "LICENSE").read_bytes(), "wheel license bytes"
        installed = {
            name for name in names if name.startswith("probity_observer/")
        }
        expected = {
            str(path.relative_to(root / "src"))
            for path in (root / "src/probity_observer").glob("*.py")
        }
        assert installed == expected, "root module population"
        for name in sorted(expected):
            assert archive.read(name) == (root / "src" / name).read_bytes(), f"wheel module bytes: {name}"
        assert not any(name.startswith(("interop/", "tests/")) for name in names), "unexpected profile or test payload"
        print(f"wheel metadata, license and {len(expected)} source modules match; profile routes match")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    check(parser.parse_args().wheel)
