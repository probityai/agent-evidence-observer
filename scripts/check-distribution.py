"""Check the root wheel and public install routes against their source files."""

from __future__ import annotations

import argparse
import base64
from collections import Counter
from configparser import ConfigParser
import csv
from email.parser import BytesParser
import hashlib
import io
from pathlib import Path, PurePosixPath
import stat
import tomllib
from zipfile import ZipFile

from packaging.markers import Marker
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version


def require(condition: bool, message: str) -> None:
    """Keep distribution refusals active when Python runs with optimization."""
    if not condition:
        raise ValueError(message)


def profile_guides(root: Path) -> dict[Path, Path]:
    """Use declared readme files, or the existing profiles' README convention."""
    routes = {}
    for manifest in sorted((root / "interop").glob("*/pyproject.toml")):
        readme = tomllib.loads(manifest.read_text())["project"].get("readme", "README.md")
        if isinstance(readme, dict):
            require(set(readme) == {"file", "content-type"}, f"file-backed readme table: {manifest}")
            content_type = readme["content-type"]
            require(isinstance(content_type, str) and bool(content_type.strip()), f"readme content type: {manifest}")
            readme = readme["file"]
        require(isinstance(readme, str) and bool(readme), f"file-backed profile guide: {manifest}")
        relative = Path(readme)
        require(not relative.is_absolute() and ".." not in relative.parts, f"relative profile guide: {manifest}")
        guide = manifest.parent / relative
        require(guide.resolve().is_relative_to(manifest.parent.resolve()), f"profile guide escapes: {manifest}")
        require(guide.is_file(), f"profile guide: {manifest}")
        routes[manifest] = guide
    return routes


def requirements(project: dict) -> Counter:
    """Compare PEP 508 requirements without losing repeated source records."""
    expected = [Requirement(value) for value in project.get("dependencies", [])]
    for extra, values in project.get("optional-dependencies", {}).items():
        for value in values:
            requirement = Requirement(value)
            marker = f'extra == "{canonicalize_name(extra)}"'
            if requirement.marker is not None:
                marker = f"({requirement.marker}) and {marker}"
            requirement.marker = Marker(marker)
            expected.append(requirement)
    return Counter(expected)


def check_entry_points(archive: ZipFile, info: str, project: dict) -> None:
    expected = dict(project.get("entry-points", {}))
    for key, group in (("scripts", "console_scripts"), ("gui-scripts", "gui_scripts")):
        if project.get(key):
            require(group not in expected, f"ambiguous source entry points: {group}")
            expected[group] = project[key]
    entry_points = ConfigParser(interpolation=None, strict=True)
    entry_points.optionxform = str
    entry_points.read_string(archive.read(f"{info}/entry_points.txt").decode("utf-8"))
    require(not entry_points.defaults(), "wheel entry-point defaults")
    actual = {group: dict(entry_points[group]) for group in entry_points.sections()}
    require(actual == expected, "wheel entry points")


def check_record(archive: ZipFile, names: list[str], info: str) -> None:
    """Check every supported wheel member's own size and secure RECORD hash."""
    record = f"{info}/RECORD"
    rows = list(csv.reader(io.StringIO(archive.read(record).decode("utf-8"))))
    require(all(len(row) == 3 for row in rows), "wheel RECORD columns")
    require(len(rows) == len(names) and {row[0] for row in rows} == set(names), "wheel RECORD population")
    for name, digest, size in rows:
        if name == record:
            require(digest == size == "", "wheel RECORD self-reference")
            continue
        algorithm, separator, encoded = digest.partition("=")
        require(separator == "=" and algorithm in {"sha256", "sha384", "sha512"}, f"wheel RECORD algorithm: {name}")
        raw = archive.read(name)
        expected = base64.urlsafe_b64encode(hashlib.new(algorithm, raw).digest()).rstrip(b"=").decode("ascii")
        require(encoded == expected and size == str(len(raw)), f"wheel RECORD bytes: {name}")


def check(wheel: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    guide = (root / "docs/INSTALLATION.md").read_text()
    routes = profile_guides(root)
    rows = [line for line in guide.splitlines() if line.startswith("| [")]
    require(len(rows) == len(routes), "profile route population")
    for manifest, profile_guide in routes.items():
        profile = tomllib.loads(manifest.read_text())["project"]
        prefix = f"| [{manifest.parent.name}]"
        rows = [line for line in guide.splitlines() if line.startswith(prefix)]
        require(len(rows) == 1, f"missing or repeated install route: {manifest}")
        row = rows[0]
        require(f"`{profile['name']}`" in row, f"distribution identity: {manifest}")
        require(f"`{profile['requires-python']}`" in row, f"Python constraint: {manifest}")
        url = "https://github.com/probityai/agent-evidence-observer/blob/main/"
        url += profile_guide.relative_to(root).as_posix()
        require(f"{prefix}({url})" in row, f"profile guide URL: {manifest}")
        for command in profile.get("scripts", {}):
            require(f"`{command}`" in row, f"console command: {manifest}")

    with ZipFile(wheel) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "duplicate wheel member")
        for member in archive.infolist():
            path = PurePosixPath(member.filename)
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in member.filename
                    and path.as_posix() == member.filename, "wheel member path")
            mode = stat.S_IFMT(member.external_attr >> 16)
            require(not member.is_dir() and mode in {0, stat.S_IFREG}, "wheel regular-file payload")
        metadata_paths = [name for name in names if name.endswith(".dist-info/METADATA")]
        require(len(metadata_paths) == 1, "wheel metadata population")
        metadata_path = metadata_paths[0]
        info = metadata_path.rsplit("/", 1)[0]
        expected_info = f"{canonicalize_name(project['name']).replace('-', '_')}-{Version(project['version'])}.dist-info"
        require(info == expected_info, "wheel metadata location")
        metadata = BytesParser().parsebytes(archive.read(metadata_path))
        require(not metadata.defects, "wheel metadata syntax")
        for field in ("Name", "Version", "Summary", "Requires-Python", "License-Expression", "Description-Content-Type"):
            require(len(metadata.get_all(field, [])) == 1, f"wheel singleton metadata: {field}")
        require(metadata["Name"] == project["name"], "wheel name")
        require(metadata["Version"] == project["version"], "wheel version")
        require(metadata["Summary"] == project["description"], "wheel summary")
        require(metadata["Requires-Python"] == project["requires-python"], "wheel Python")
        require(metadata["License-Expression"] == "Apache-2.0", "wheel license expression")
        require(metadata["Description-Content-Type"] == "text/markdown", "wheel readme type")
        require(not metadata.get_all("Content-Transfer-Encoding", []), "wheel literal readme encoding")
        require(metadata.get_payload(decode=True) == (root / project["readme"]).read_bytes(), "wheel readme bytes")
        project_urls = metadata.get_all("Project-URL", [])
        require(len(project_urls) == len(project["urls"]) and set(project_urls) == {
            f"{label}, {url}" for label, url in project["urls"].items()
        }, "wheel project URLs")
        extras = metadata.get_all("Provides-Extra", [])
        require(Counter(canonicalize_name(value) for value in extras) == Counter(
            canonicalize_name(value) for value in project.get("optional-dependencies", {})
        ), "wheel extras")
        require(Counter(Requirement(value) for value in metadata.get_all("Requires-Dist", [])) == requirements(project),
                "wheel dependencies")
        check_entry_points(archive, info, project)
        require(archive.read(f"{info}/licenses/LICENSE") == (root / "LICENSE").read_bytes(), "wheel license bytes")
        installed = {
            name for name in names if name.startswith("probity_observer/")
        }
        expected = {
            str(path.relative_to(root / "src"))
            for path in (root / "src/probity_observer").glob("*.py")
        }
        require(installed == expected, "root module population")
        for name in sorted(expected):
            require(archive.read(name) == (root / "src" / name).read_bytes(), f"wheel module bytes: {name}")
        require(all(name in expected or name.startswith(info + "/") for name in names), "unowned wheel install payload")
        wheel_metadata = BytesParser().parsebytes(archive.read(f"{info}/WHEEL"))
        for field, value in (("Wheel-Version", "1.0"), ("Root-Is-Purelib", "true"), ("Tag", "py3-none-any")):
            require(wheel_metadata.get_all(field, []) == [value], f"supported root wheel: {field}")
        check_record(archive, names, info)
        print(f"wheel metadata, commands, dependencies, license and {len(expected)} source modules match; "
              "all member sizes and hashes and profile routes match")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    check(parser.parse_args().wheel)
