"""Exercise install-route and wheel substitutions against the distribution gate."""

from __future__ import annotations

import argparse
import base64
import csv
from email.parser import BytesParser
import hashlib
import io
import json
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
from zipfile import ZipFile

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def equivalent_core_requirement(raw_metadata: bytes) -> bytes:
    """Change the actual selected core requirement, never a stale fixture string."""
    metadata = BytesParser().parsebytes(raw_metadata)
    selected = []
    for value in metadata.get_all("Requires-Dist", []):
        requirement = Requirement(value)
        if canonicalize_name(requirement.name) == "cryptography" and requirement.marker is None:
            selected.append((value, requirement))
    if len(selected) != 1 or selected[0][1].url is not None:
        raise RuntimeError("Equivalent control needs one ordinary core cryptography requirement")
    value, requirement = selected[0]
    specifiers = ", ".join(reversed(sorted(str(item) for item in requirement.specifier)))
    before = ("Requires-Dist: " + value).encode()
    after = ("Requires-Dist: Cryptography " + specifiers).encode()
    if before == after or raw_metadata.count(before) != 1:
        raise RuntimeError("Equivalent control input is missing, repeated or unchanged")
    return raw_metadata.replace(before, after, 1)


def run(wheel: Path, optimized: bool) -> None:
    root = Path(__file__).resolve().parent.parent
    wheel = wheel.resolve()
    with tempfile.TemporaryDirectory(prefix="observer-distribution-controls-") as temp:
        selected = Path(temp) / "source"
        selected.mkdir()
        for name in ("pyproject.toml", "README.md", "LICENSE"):
            shutil.copyfile(root / name, selected / name)
        for name in ("src", "scripts", "docs"):
            shutil.copytree(root / name, selected / name, ignore=shutil.ignore_patterns("__pycache__"))
        routes = runpy.run_path(str(root / "scripts/check-distribution.py"))["profile_guides"](root)
        for manifest, profile_guide in routes.items():
            target = selected / manifest.relative_to(root).parent
            target.mkdir(parents=True)
            shutil.copyfile(manifest, target / manifest.name)
            copied_guide = selected / profile_guide.relative_to(root)
            copied_guide.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(profile_guide, copied_guide)
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.append(str(selected / "scripts/check-distribution.py"))
        receipts = []

        def expect(name: str, artifact: Path, passed: bool) -> None:
            result = subprocess.run(command + [str(artifact)], capture_output=True)
            print(json.dumps({"control": name, "optimized": optimized,
                              "argv": command + [str(artifact)], "actualExit": result.returncode,
                              "expectedAccepted": passed,
                              "stdout": result.stdout.decode(), "stderr": result.stderr.decode()}))
            if (result.returncode == 0) != passed:
                raise RuntimeError(f"{name}: unexpected status {result.returncode}\n" + result.stdout.decode() + result.stderr.decode())
            receipts.append(passed)
            print(f"{name}: {'accepted' if passed else 'refused'}")

        expect("original-wheel-and-routes", wheel, True)
        guide = selected / "docs/INSTALLATION.md"
        original = guide.read_text()
        row = next(line for line in original.splitlines() if line.startswith("| [adk-user-responses-2026-10-04]"))
        for name, before, after in (
            ("wrong-profile-python", "`>=3.12`", "`>=3.13`"),
            ("wrong-profile-name", "`probity-adk-user-responses`", "`unrelated-package`"),
            ("missing-profile-command", "`probity-adk-responses-read`", "`unrelated-command`"),
            ("dead-profile-guide", "/README.md)", "/MISSING.md)"),
        ):
            if before not in row:
                raise RuntimeError(f"Control input is missing: {name}")
            guide.write_text(original.replace(row, row.replace(before, after)))
            expect(name, wheel, False)
            guide.write_text(original)
        for name, changed in (("missing-profile-route", original.replace(row + "\n", "")),
                              ("repeated-profile-route", original + row + "\n")):
            guide.write_text(changed)
            expect(name, wheel, False)
            guide.write_text(original)
        manifest = selected / "interop/protected-action-operator-2026-10-06/pyproject.toml"
        original_manifest = manifest.read_text()
        declared = 'readme = "PROFILE.md"'
        if declared not in original_manifest:
            raise RuntimeError("Protected operator guide is not declared")
        for name, replacement in (
            ("empty-declared-guide", 'readme = ""'),
            ("missing-declared-guide", 'readme = "MISSING.md"'),
            ("parent-declared-guide", 'readme = "../PROFILE.md"'),
            ("absolute-declared-guide", 'readme = ' + json.dumps(str(manifest.parent / "PROFILE.md"))),
            ("inline-declared-guide", 'readme = {text = "inline", content-type = "text/markdown"}'),
            ("file-and-text-declared-guide", 'readme = {file = "PROFILE.md", text = "inline", content-type = "text/markdown"}'),
            ("missing-readme-content-type", 'readme = {file = "PROFILE.md"}'),
            ("empty-readme-content-type", 'readme = {file = "PROFILE.md", content-type = ""}'),
            ("wrong-readme-content-type", 'readme = {file = "PROFILE.md", content-type = 1}'),
            ("unknown-readme-table-key", 'readme = {file = "PROFILE.md", content-type = "text/markdown", unknown = "x"}'),
        ):
            manifest.write_text(original_manifest.replace(declared, replacement))
            expect(name, wheel, False)
            manifest.write_text(original_manifest)
        manifest.write_text(original_manifest.replace(declared, 'readme = {file = "PROFILE.md", content-type = "text/markdown"}'))
        expect("file-table-declared-guide", wheel, True)
        manifest.write_text(original_manifest)
        nested_guide = manifest.parent / "docs/PROFILE.md"
        nested_guide.parent.mkdir()
        shutil.copyfile(manifest.parent / "PROFILE.md", nested_guide)
        manifest.write_text(original_manifest.replace(declared, 'readme = "docs/PROFILE.md"'))
        protected_row = next(line for line in original.splitlines() if line.startswith("| [protected-action-operator-2026-10-06]"))
        guide.write_text(original.replace(protected_row, protected_row.replace("/PROFILE.md)", "/docs/PROFILE.md)")))
        expect("nested-file-declared-guide", wheel, True)
        guide.write_text(original)
        manifest.write_text(original_manifest)
        external = Path(temp) / "external-guide.md"
        external.write_text("External guide control\n")
        link = manifest.parent / "external.md"
        link.symlink_to(external)
        manifest.write_text(original_manifest.replace(declared, 'readme = "external.md"'))
        expect("symlink-declared-guide-escape", wheel, False)
        manifest.write_text(original_manifest)
        link.unlink()
        with ZipFile(wheel) as archive:
            if len(archive.namelist()) != len(set(archive.namelist())):
                raise RuntimeError("Original wheel has repeated member names")
            members = {info.filename: (info, archive.read(info)) for info in archive.infolist()}
        metadata = next(name for name in members if name.endswith(".dist-info/METADATA"))
        info = metadata.rsplit("/", 1)[0]
        license_path = next(name for name in members if name.endswith(".dist-info/licenses/LICENSE"))

        def controlled_wheel(name: str, replacements: dict[str, bytes], *, added=None, removed=(), rehash=True) -> Path:
            """Keep substituted artifacts installable up to the tested source boundary."""
            payload = {filename: raw for filename, (_, raw) in members.items() if filename not in removed}
            payload.update(replacements)
            payload.update(added or {})
            record = f"{info}/RECORD"
            if rehash:
                rows = []
                for filename, raw in payload.items():
                    if filename == record:
                        rows.append((filename, "", ""))
                    else:
                        digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode("ascii")
                        rows.append((filename, "sha256=" + digest, str(len(raw))))
                output = io.StringIO(newline="")
                csv.writer(output).writerows(rows)
                payload[record] = output.getvalue().encode("utf-8")
            controlled = Path(temp) / f"{name}.whl"
            with ZipFile(controlled, "w") as archive:
                for filename, raw in payload.items():
                    archive.writestr(members[filename][0] if filename in members else filename, raw)
            return controlled

        for name, changed in (
            ("changed-wheel-module", "probity_observer/__init__.py"),
            ("changed-wheel-license", license_path),
            ("changed-wheel-readme", metadata),
        ):
            expect(name, controlled_wheel(name, {changed: members[changed][1] + b"\nsubstituted bytes\n"}), False)
        for name, extra in (("duplicate-wheel-member", b""), ("contradictory-wheel-member", b"\nsubstitution\n")):
            controlled = Path(temp) / (name + ".whl")
            with ZipFile(controlled, "w") as archive:
                for member, raw in members.values():
                    archive.writestr(member, raw)
                archive.writestr("probity_observer/__init__.py", members["probity_observer/__init__.py"][1] + extra)
            expect(name, controlled, False)
        raw_metadata = members[metadata][1]
        for name, header in (("repeated-wheel-version", b"Version: 0.0.1\n"),
                             ("conflicting-wheel-version", b"Version: 0.0.2\n"),
                             ("repeated-wheel-project-url", b"Project-URL: Source, https://github.com/probityai/agent-evidence-observer\n"),
                             ("repeated-wheel-extra", b"Provides-Extra: test\n"),
                             ("repeated-wheel-dependency", b"Requires-Dist: cryptography>=46,<47\n"),
                             ("invalid-wheel-dependency", b"Requires-Dist: not a requirement\n")):
            expect(name, controlled_wheel(name, {metadata: header + raw_metadata}), False)
        for name, field in (("missing-required-dependency", rb"^Requires-Dist: cryptography[^\n]*\n"),
                            ("missing-extra-dependency", rb'^Requires-Dist: pytest[^\n]*\n'),
                            ("missing-declared-extra", rb"^Provides-Extra: test\n")):
            changed, count = re.subn(field, b"", raw_metadata, flags=re.MULTILINE)
            if count != 1:
                raise RuntimeError(f"Control input is missing or repeated: {name}")
            expect(name, controlled_wheel(name, {metadata: changed}), False)
        expect("wrong-extra-marker", controlled_wheel("wrong-extra-marker", {
            metadata: raw_metadata.replace(b'extra == "test"', b'extra == "unrelated"')
        }), False)
        expect("trailing-readme-whitespace", controlled_wheel("trailing-readme-whitespace", {
            metadata: raw_metadata + b" \t\n"
        }), False)
        headers, separator, body = raw_metadata.partition(b"\n\n")
        if separator != b"\n\n" or body != (root / "README.md").read_bytes():
            raise RuntimeError("Literal README control input differs from supported backend framing")
        expect("transfer-encoded-readme", controlled_wheel("transfer-encoded-readme", {
            metadata: b"Content-Transfer-Encoding: base64\n" + headers + separator + base64.encodebytes(body)
        }), False)
        entry_points = f"{info}/entry_points.txt"
        raw_entry_points = members[entry_points][1]
        command_line = b"agent-evidence-admit = probity_observer.admission:main\n"
        if command_line not in raw_entry_points:
            raise RuntimeError("Declared command control input is missing")
        for name, changed in (
            ("missing-console-command", raw_entry_points.replace(command_line, b"")),
            ("redirected-console-command", raw_entry_points.replace(command_line, b"agent-evidence-admit = probity_observer.cli:main\n")),
            ("repeated-console-command", raw_entry_points + command_line),
            ("undeclared-entry-point-group", raw_entry_points + b"\n[unrelated_group]\nextra = unrelated.module:main\n"),
            ("entry-point-defaults", b"[DEFAULT]\nhidden = unrelated.module:main\n" + raw_entry_points),
        ):
            expect(name, controlled_wheel(name, {entry_points: changed}), False)
        expect("missing-entry-point-file", controlled_wheel("missing-entry-point-file", {}, removed=(entry_points,)), False)
        for name, added in (
            ("unowned-wheel-module", {"unowned/__init__.py": b""}),
            ("unowned-wheel-script", {info.replace(".dist-info", ".data") + "/scripts/unowned": b"#!python\n"}),
            ("traversal-wheel-member", {info + "/../unowned.py": b""}),
        ):
            expect(name, controlled_wheel(name, {}, added=added), False)
        for name, field in (("wrong-wheel-install-scheme", b"Root-Is-Purelib: true"),
                            ("wrong-wheel-compatibility-tag", b"Tag: py3-none-any")):
            wheel_metadata = f"{info}/WHEEL"
            raw = members[wheel_metadata][1]
            if field not in raw:
                raise RuntimeError(f"Control input is missing: {name}")
            expect(name, controlled_wheel(name, {wheel_metadata: raw.replace(field, field + b"-substitution")}), False)
        record = f"{info}/RECORD"
        expect("missing-wheel-record", controlled_wheel("missing-wheel-record", {}, removed=(record,), rehash=False), False)
        expect("repeated-wheel-record-row", controlled_wheel("repeated-wheel-record-row", {
            record: members[record][1] + members[record][1].splitlines(keepends=True)[0]
        }, rehash=False), False)
        expect("wrong-wheel-record-hash", controlled_wheel("wrong-wheel-record-hash", {
            record: members[record][1].replace(b"sha256=", b"sha1=", 1)
        }, rehash=False), False)
        expect("unbound-wheel-metadata-extension", controlled_wheel("unbound-wheel-metadata-extension", {},
            added={info + "/sboms/control.json": b"{}\n"}, rehash=False), False)
        expect("supported-wheel-metadata-extension", controlled_wheel("supported-wheel-metadata-extension", {},
            added={info + "/sboms/control.json": b"{}\n"}), True)
        expect("equivalent-wheel-dependency-specifiers", controlled_wheel("equivalent-wheel-dependency-specifiers", {
            metadata: equivalent_core_requirement(raw_metadata)
        }), True)
        print(f"{receipts.count(False)} distribution substitutions refused; {receipts.count(True)} valid forms accepted; optimized={optimized}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    wheel = parser.parse_args().wheel
    for optimized in (False, True):
        run(wheel, optimized)
