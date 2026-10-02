"""Host-selected publication gate invoking a separately installed joint reader."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from joint_common import CASES, NONCLAIMS, PROFILE, child_environment, expected_authority, expected_revision, load, phases, require, same, sha, write
from probity_observer.crypto import VerificationError


def file_digest(path: Path) -> str:
    """Hash selected installed bytes without loading a verification module."""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


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
        result = {"type": "symlink", "link": os.readlink(path), "target": str(target)}
        if target.is_file():
            result["sha256"] = file_digest(target)
        return result
    return {"type": "file", "mode": path.stat().st_mode & 0o777, "size": path.stat().st_size, "sha256": file_digest(path)}


def installed_names(prefix: Path) -> list[Path]:
    """Enumerate the whole selected environment, including injection surfaces.

    The population includes package sources, extensions, metadata, bytecode,
    ``.pth`` files, launchers and virtual-environment configuration. Added files
    are changes to the selected closure even if no distribution owns them.
    """
    names = []
    for folder, directories, files in os.walk(prefix, followlinks=False):
        names.extend(Path(folder) / name for name in files)
        links = [Path(folder) / name for name in directories if (Path(folder) / name).is_symlink()]
        require(all(path.resolve(strict=True).is_relative_to(prefix) for path in links), "reader-external-directory-link")
        names.extend(links)
    require(len(names) <= 10_000, "reader-closure-population-limit")
    return sorted(names)


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
    prefix = reader.parent.parent.resolve(strict=True)
    require(reader.parent.name == "bin" and (prefix / "pyvenv.cfg").is_file(), "reader-normal-environment")
    sites = sorted(prefix.glob("lib/python*/site-packages"))
    require(len(sites) == 1, "reader-installed-site")
    packages = {item.metadata["Name"]: item.version for item in importlib.metadata.distributions(path=[str(sites[0])])}
    same([packages.get("probity-joint-recovery-reader"), packages.get("agent-evidence-observer")], ["0.0.1", "0.0.1"], "reader-installed-versions")
    interpreter = prefix / "bin/python"
    line = reader.read_bytes().splitlines()[0]
    require(line.startswith(b"#!"), "reader-installed-shebang")
    selected = Path(line[2:].decode("utf-8"))
    require(selected.parent.resolve(strict=True) == prefix / "bin" and selected.resolve(strict=True) == interpreter.resolve(strict=True), "reader-installed-shebang")
    return {"prefix": str(prefix), "reader": str(reader), "shebangInterpreter": str(selected), "interpreter": str(interpreter.resolve(strict=True)), "interpreterSha256": file_digest(interpreter), "packages": packages, "files": {str(path.relative_to(prefix)): installed_member(path) for path in installed_names(prefix)}}


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
    same([selected["profile"], selected["pinsSha256"], selected["plannedAttempts"], selected["readerSha256"]], [PROFILE, sha(raw_pins), len(CASES), sha(reader.read_bytes())], "host-selection")
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
    command = [str(reader.resolve(strict=True)), str(packet.resolve(strict=True)), "--pins-file", str((output / "selected-pins.json").resolve())]
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
