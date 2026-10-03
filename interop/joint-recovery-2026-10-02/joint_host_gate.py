"""Host-selected publication gate invoking a separately installed joint reader."""
from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
from pathlib import Path
from email.parser import BytesParser
from typing import Any

from joint_common import CASES, NONCLAIMS, PROFILE, child_environment, expected_authority, expected_revision, load, phases, require, same, sha, write
from probity_observer.crypto import VerificationError


MAX_INSTALL_FILE = 64 * 1024 * 1024
MAX_INSTALL_BYTES = 512 * 1024 * 1024
MAX_INSTALL_FILES = 4096
MAX_INSTALL_ENTRIES = 8192
MAX_INSTALL_DEPTH = 32


def selected_contents(path: Path) -> tuple[bytes, os.stat_result]:
    """Hash a bounded regular installation member without blocking on a FIFO.

    Parameters
    ----------
    path : pathlib.Path
        Host-selected file, including an explicitly selected interpreter link.

    Returns
    -------
    tuple of bytes and os.stat_result
        Bounded contents and opened descriptor metadata. The descriptor is
        checked before reading; changed-size and excessive members refuse.

    Raises
    ------
    VerificationError
        If the member is not regular or exceeds the per-file limit. Concurrent
        filesystem replacement remains a local OS custody assumption.
    """
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode), "reader-install-regular-file")
        require(metadata.st_size <= MAX_INSTALL_FILE, "reader-install-file-bound")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(metadata.st_size + 1)
        require(len(raw) == metadata.st_size, "reader-install-file-size-changed")
    finally:
        os.close(descriptor)
    return raw, metadata


def selected_file(path: Path) -> dict[str, Any]:
    """Return mode, size and digest from bounded :func:`selected_contents`."""
    raw, metadata = selected_contents(path)
    return {"mode": metadata.st_mode & 0o777, "size": len(raw), "sha256": sha(raw)}


def file_digest(path: Path) -> str:
    """Return the digest from :func:`selected_file` without importing code."""
    return selected_file(path)["sha256"]


def installed_member(path: Path) -> dict[str, Any]:
    """Record an installed file or symlink, including resolved binary bytes.

    Parameters
    ----------
    path : pathlib.Path
        One member of the selected reader environment. Directory symlinks are
        recorded, never traversed; interpreter symlinks additionally bind the
        literal resolved executable bytes outside the virtual environment.

    Returns
    -------
    dict
        Exact file type, mode, size and SHA256, or selected link and target.
    """
    if path.is_symlink():
        target = path.resolve(strict=True)
        require(not target.is_dir(), "reader-install-directory-link")
        return {"type": "symlink", "link": os.readlink(path), "target": str(target), **selected_file(target)}
    return {"type": "file", **selected_file(path)}


def installed_names(prefix: Path) -> list[Path]:
    """Enumerate the whole selected environment, including injection surfaces.

    The population includes package sources, extensions, metadata, bytecode,
    ``.pth`` files, launchers and virtual-environment configuration. Added files
    are changes to the selected closure even if no distribution owns them.
    """
    names, pending, entries = [], [(prefix, 0)], 0
    while pending:
        directory, depth = pending.pop()
        require(depth <= MAX_INSTALL_DEPTH, "reader-install-depth-bound")
        with os.scandir(directory) as children:
            for child in children:
                entries += 1
                require(entries <= MAX_INSTALL_ENTRIES, "reader-install-entry-bound")
                path = Path(child.path)
                if child.is_dir(follow_symlinks=False):
                    pending.append((path, depth + 1))
                else:
                    require(len(names) < MAX_INSTALL_FILES, "reader-closure-population-limit")
                    names.append(path)
    return sorted(names)


def directory_link(path: Path, prefix: Path) -> dict[str, Any]:
    """Select only the standard lib64-to-lib alias without duplicate reads."""
    require(path == prefix / "lib64" and path.readlink() == Path("lib"), "reader-install-directory-link")
    require((prefix / "lib").is_dir() and not (prefix / "lib").is_symlink(), "reader-install-library-directory")
    return {"type": "symlink", "link": "lib", "target": str(prefix / "lib")}


def installation_inventory(prefix: Path) -> dict[str, Any]:
    """Select complete bounded bytes; a directory alias contributes no bytes."""
    files, total = {}, 0
    for path in installed_names(prefix):
        if path.is_symlink() and path.is_dir():
            member = directory_link(path, prefix)
        else:
            member = installed_member(path)
        total += member.get("size", 0)
        require(total <= MAX_INSTALL_BYTES, "reader-install-byte-bound")
        files[str(path.relative_to(prefix))] = member
    return files


def validate_environment_config(prefix: Path) -> None:
    """Require CPython isolation and absence of a bin-directory override.

    The include-system-site-packages key must occur exactly once with value
    false. Hashing a configuration that enables outside imports does not
    select the complete installed environment.
    """
    require(not os.path.lexists(prefix / "bin/pyvenv.cfg"), "reader-config-override")
    config = selected_contents(prefix / "pyvenv.cfg")[0].decode("utf-8")
    settings = [value.strip().lower() for line in config.splitlines()
                for key, separator, value in [line.partition("=")]
                if separator and key.strip().lower() == "include-system-site-packages"]
    require(settings == ["false"], "reader-system-packages")


def installed_versions(site: Path) -> dict[str, str]:
    """Parse bounded wheel metadata without importing selected packages."""
    versions = {}
    for path in sorted(site.glob("*.dist-info/METADATA")):
        metadata = BytesParser().parsebytes(selected_contents(path)[0])
        name, version = metadata.get("Name"), metadata.get("Version")
        require(isinstance(name, str) and isinstance(version, str) and name not in versions,
                "reader-installed-metadata")
        versions[name] = version
    return versions


def reader_closure(reader: Path) -> dict[str, Any]:
    """Select normal installed package files and interpreter before execution.

    Parameters
    ----------
    reader : pathlib.Path
        Host-selected console entry point in ``<venv>/bin``. Selection is made
        by the host from normal wheel installation, outside the packet.

    Returns
    -------
    dict
        Exact environment file population, package versions, absolute prefix,
        selected launcher and interpreter. No selected module is imported or
        executed while constructing or checking this closure. The host's OS
        and underlying standard library remain local custody assumptions.
    """
    reader = reader.absolute()
    prefix = reader.parent.parent.absolute()
    require(prefix.is_dir() and not prefix.is_symlink(), "reader-environment-directory")
    require(reader.parent.name == "bin" and (prefix / "pyvenv.cfg").is_file(), "reader-normal-environment")
    validate_environment_config(prefix)
    sites = sorted(prefix.glob("lib/python*/site-packages"))
    require(len(sites) == 1, "reader-installed-site")
    inventory = installation_inventory(prefix)
    packages = installed_versions(sites[0])
    require(packages.get("probity-joint-recovery-reader") in {"0.0.1", "0.0.2"} and packages.get("agent-evidence-observer") == "0.0.1", "reader-installed-versions")
    interpreter = prefix / "bin/python"
    raw = selected_contents(reader)[0]
    require(bool(raw), "reader-installed-shebang")
    line = raw.splitlines()[0]
    require(line.startswith(b"#!"), "reader-installed-shebang")
    selected = Path(line[2:].decode("utf-8"))
    require(selected.parent.resolve(strict=True) == prefix / "bin" and selected.resolve(strict=True) == interpreter.resolve(strict=True), "reader-installed-shebang")
    return {"prefix": str(prefix), "reader": str(reader), "shebangInterpreter": str(selected), "interpreter": str(interpreter.resolve(strict=True)), "interpreterSha256": file_digest(interpreter), "packages": packages, "files": inventory}


def select(packet: Path, pins: Path, policy: Path, digest: str, reader: Path, output: Path) -> None:
    """Freeze externally supplied byte pins, publication policy and reader.

    Parameters
    ----------
    packet : pathlib.Path
        Original packet under assessment.
    pins, policy : pathlib.Path
        Host-owned files outside ``packet``. Copying candidate pins is an
        author-operated selection and does not establish independent adoption.
    digest : str
        Host-selected SHA256 of the literal policy file.
    reader : pathlib.Path
        Normally installed reader executable selected by the host.
    output : pathlib.Path
        Fresh immutable gate-receipt directory.
    """
    root = packet.resolve(strict=True)
    require(not pins.resolve(strict=True).is_relative_to(root) and not policy.resolve(strict=True).is_relative_to(root), "selection-must-be-outside-packet")
    raw_policy, raw_pins = policy.read_bytes(), pins.read_bytes()
    require(sha(raw_policy) == digest, "host-policy-digest")
    selected = load(policy.parent, policy.name)
    same(sorted(selected), sorted(["profile", "pinsSha256", "plannedAttempts", "readerSha256", "readerClosure"]), "host-policy-fields")
    same([selected["profile"], selected["pinsSha256"], selected["plannedAttempts"], selected["readerSha256"]], [PROFILE, sha(raw_pins), len(CASES), file_digest(reader)], "host-selection")
    require(not reader.parent.parent.resolve(strict=True).is_relative_to(root), "reader-must-be-outside-packet")
    same(reader_closure(reader), selected["readerClosure"], "reader-installed-closure")
    load(pins.parent, pins.name)
    (output / "host-policy.json").write_bytes(raw_policy)
    (output / "selected-pins.json").write_bytes(raw_pins)
    (output / "selected-pins.json").chmod(0o400)


def admit(raw: bytes) -> None:
    """Require the complete finite reader output and its explicit bounded scope."""
    from probity_observer.crypto import strict_loads
    value = strict_loads(raw)
    same([value["profile"], value["status"], value["witnessScope"], value["doesNotAssert"]], [PROFILE, "verified", "PEER", NONCLAIMS], "reader-scope")
    counters = {"plannedAttempts": 19, "workerProcesses": 40, "targetProcesses": 38, "releasedResults": 3, "priorAuthenticEffects": 11, "pendingRefusals": 2, "startupRefusals": 3, "concurrentCallers": 8}
    for name, expected in counters.items():
        same(value[name], expected, "reader-population")
    same([row["id"] for row in value["records"]], list(CASES), "reader-case-population")
    for name, row in zip(CASES, value["records"], strict=True):
        same(row, report_row(name), "reader-case-disposition")


def report_row(name: str) -> dict[str, Any]:
    """Declare the host-selected finite row contract, including release denial.

    Aggregate counters alone cannot admit a report whose revoked row releases
    an effect. This publication policy checks each declared native disposition
    after the independently installed reader has authenticated its evidence.
    """
    pending = name.startswith("pending-")
    released = name in {"valid-before", "valid-after", "concurrent-before"}
    revision = expected_revision(name)
    return {"id": name, "workerProcesses": len(phases(name)), "targetProcesses": 2, "currentAuthority": expected_authority(name, phases(name)[-1]), "releasedResult": released, "priorAuthenticEffect": name.endswith("after") and not pending, "nativeRevision": revision, "nativePhase": "incomplete" if pending else "completed" if revision else "ready", "targetStartup": "refused" if name in {"target-key-after", "target-store-after", "target-rollback-after"} else "reopened", "recoveryDispatches": int(released or pending)}


def execute(packet: Path, reader: Path, output: Path) -> int:
    """Bound reader runtime while preserving complete stdout/stderr files."""
    command = [str(reader.parent / "python"), "-I", str(reader.absolute()), str(packet.resolve(strict=True)), "--pins-file", str((output / "selected-pins.json").resolve())]
    write(output / "launch.json", {"command": command, "maximumSeconds": 15, "environment": child_environment()})
    with (output / "reader.stdout").open("xb") as stdout, (output / "reader.stderr").open("xb") as stderr:
        try:
            process = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=15, check=False, env=child_environment())
            return process.returncode
        except subprocess.TimeoutExpired:
            return 124


def gate(packet: Path, pins: Path, policy: Path, digest: str, reader: Path, output: Path) -> dict[str, Any]:
    """Retain publication permission independently from dispatch/result authority.

    Returns
    -------
    dict
        A ``publish`` decision means that the selected report is complete and
        authentic under this profile. Refused execution cases remain refusals;
        publishing them grants no permission to dispatch or release a result.
    """
    output.mkdir(parents=True, exist_ok=False)
    result: dict[str, Any] = {"profile": PROFILE, "decision": "refuse", "reason": None, "readerReturncode": None, "policySha256": digest}
    try:
        select(packet, pins, policy, digest, reader, output)
        result["readerReturncode"] = execute(packet, reader, output)
        require(result["readerReturncode"] == 0, "reader-refused")
        admit((output / "reader.stdout").read_bytes())
        result.update(decision="publish", reason="selected-complete-bounded-report")
    except (VerificationError, OSError, ValueError, TypeError, KeyError) as error:
        result["reason"] = str(error)
    write(output / "gate-report.json", result)
    return result


def main() -> None:
    """Evaluate an explicit host policy through the separate installed reader."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--pins-file", type=Path, required=True)
    parser.add_argument("--policy-file", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--reader", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    decision = gate(args.packet, args.pins_file, args.policy_file, args.policy_sha256, args.reader, args.output)
    print(json.dumps(decision, indent=2))
    raise SystemExit(0 if decision["decision"] == "publish" else 1)


if __name__ == "__main__":
    main()
