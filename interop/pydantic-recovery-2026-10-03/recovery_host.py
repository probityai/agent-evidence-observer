"""Separate installed-reader selection and bounded publication decision."""
from __future__ import annotations

import argparse
import hashlib
import os
import stat
import subprocess
from pathlib import Path
from typing import Any

from probity_observer.crypto import VerificationError, canonical, strict_loads

from probity_pydantic_recovery.common import (
    CASES,
    PROFILE,
    child_environment,
    read,
    require,
    sha,
    write,
)

MAX_INSTALL_FILE = 64 * 1024 * 1024
MAX_INSTALL_BYTES = 512 * 1024 * 1024
MAX_INSTALL_FILES = 4096
MAX_INSTALL_ENTRIES = 8192
MAX_INSTALL_DEPTH = 32


def select_file(path: Path) -> dict[str, Any]:
    """Hash only a bounded opened regular file, including selected symlink targets."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError as error:
        raise VerificationError("host-install-file-open") from error
    digest = hashlib.sha256()
    total = 0
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode), "host-install-regular-file")
        require(metadata.st_size <= MAX_INSTALL_FILE, "host-install-file-bound")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while chunk := stream.read(min(1024 * 1024, MAX_INSTALL_FILE - total + 1)):
                total += len(chunk)
                require(total <= MAX_INSTALL_FILE, "host-install-file-bound")
                digest.update(chunk)
        require(total == metadata.st_size, "host-install-file-size-changed")
    finally:
        os.close(descriptor)
    return {"sha256": digest.hexdigest(), "bytes": total}


def installation_paths(environment: Path):
    """Bound all entries and depth without following directory symlinks."""
    pending = [(environment, 0)]
    count = 0
    while pending:
        directory, depth = pending.pop()
        require(depth <= MAX_INSTALL_DEPTH, "host-install-depth-bound")
        with os.scandir(directory) as entries:
            for entry in entries:
                count += 1
                require(count <= MAX_INSTALL_ENTRIES, "host-install-entry-bound")
                if entry.is_dir(follow_symlinks=False):
                    pending.append((Path(entry.path), depth + 1))
                else:
                    yield Path(entry.path)


def validate_environment_config(environment: Path) -> None:
    """Require the single isolation setting CPython uses, without a bin override."""
    require(not os.path.lexists(environment / "bin/pyvenv.cfg"), "reader-config-override")
    try:
        config = read(environment / "pyvenv.cfg").decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError("reader-config-encoding") from error
    settings = []
    for line in config.splitlines():
        key, _, value = line.partition("=")
        if key.strip().lower() == "include-system-site-packages":
            settings.append(value.strip().lower())
    require(settings == ["false"], "reader-system-packages")


def select_directory_link(path: Path, environment: Path) -> dict[str, str]:
    """Bind CPython's required lib64-to-lib link without following it twice."""
    require(path == environment / "lib64" and path.readlink() == Path("lib"), "host-install-directory-link")
    library = environment / "lib"
    require(library.is_dir() and not library.is_symlink(), "host-install-library-directory")
    return {"symlink": "lib", "target": "lib"}


def reader_closure(executable: Path) -> dict[str, Any]:
    """Select the whole isolated install, including metadata and injection surfaces.

    The resolved interpreter is selected separately. Host OS and standard
    library remain local custody assumptions, rather than independent proof.
    """
    executable = executable.absolute()
    environment = executable.parent.parent
    require(environment.is_dir() and not environment.is_symlink(), "reader-environment-directory")
    require(executable.parent.name == "bin" and (environment / "pyvenv.cfg").is_file(), "reader-isolated-environment")
    validate_environment_config(environment)
    files = {}
    directory_links = {}
    total = 0
    for path in installation_paths(environment):
        if path.is_symlink() and path.is_dir():
            directory_links[str(path.relative_to(environment))] = select_directory_link(path, environment)
            continue
        require(len(files) < MAX_INSTALL_FILES, "host-install-file-population")
        selected = select_file(path)
        total += selected["bytes"]
        require(total <= MAX_INSTALL_BYTES, "host-install-byte-bound")
        files[str(path.relative_to(environment))] = {**selected, "symlink": str(path.readlink()) if path.is_symlink() else None}
    python = environment / "bin/python"
    interpreter = select_file(python.resolve())
    return {"environment": str(environment), "files": files, "directoryLinks": directory_links, "interpreter": str(python.resolve()), "interpreterSha256": interpreter["sha256"], "interpreterBytes": interpreter["bytes"]}


def select_policy(pins: Path, executable: Path) -> dict[str, Any]:
    """Make a concrete local host selection outside the candidate packet."""
    return {"profile": PROFILE, "pinsSha256": sha(read(pins)), "readerSha256": select_file(executable)["sha256"], "readerClosure": reader_closure(executable), "plannedAttempts": len(CASES), "releasedResults": 1, "recoveryPosts": 0}


def decide(report: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    """Publish a checked refusal population without approving denied actions."""
    require(report["profile"] == policy["profile"] == PROFILE and report["status"] == "verified", "publication-profile")
    require(all(type(policy[key]) is int for key in ("plannedAttempts", "releasedResults", "recoveryPosts")), "publication-policy-count-types")
    require(type(report["plannedAttempts"]) is int and report["plannedAttempts"] == policy["plannedAttempts"] == len(CASES), "publication-denominator")
    require([row["id"] for row in report["records"]] == list(CASES), "publication-case-population")
    require(all(type(row["releasedResult"]) is bool and type(row["recoveryPosts"]) is int for row in report["records"]), "publication-row-types")
    require([row["releasedResult"] for row in report["records"]] == [True] + [False] * (len(CASES) - 1), "publication-result-dispositions")
    require(sum(row["releasedResult"] for row in report["records"]) == policy["releasedResults"] == 1, "publication-result-count")
    require(sum(row["recoveryPosts"] for row in report["records"]) == policy["recoveryPosts"] == 0, "publication-effect-count")
    return {"decision": "publish-scoped-recovery-report", "dispatchDecision": "no-additional-dispatch-authorized", "releasedResults": 1, "withheldResults": len(CASES) - 1, "recoveryPosts": 0, "reportSha256": sha(canonical(report)), "policySha256": sha(canonical(policy)), "pinsSha256": policy["pinsSha256"]}


def gate(packet: Path, pins: Path, policy_file: Path, policy_sha256: str, executable: Path, output: Path) -> dict[str, Any]:
    """Require selected reader closure before launching an installed consumer."""
    policy_raw = read(policy_file)
    require(sha(policy_raw) == policy_sha256, "host-policy-digest")
    policy = strict_loads(policy_raw)
    require(policy == select_policy(pins, executable), "host-reader-selection")
    output.mkdir(parents=True, exist_ok=False)
    write(output / "selected-host-policy.json", policy)
    write(output / "selected-pins.json", read(pins), raw=True)
    command = [str(executable.absolute()), str(packet.absolute()), "--pins-file", str(pins.absolute())]
    environment = reader_environment()
    result = subprocess.run(command, capture_output=True, timeout=30, env=environment, cwd=output, check=False)
    write(output / "reader.stdout", result.stdout, raw=True)
    write(output / "reader.stderr", result.stderr, raw=True)
    write(output / "reader-process.json", {"argv": command, "returncode": result.returncode, "environment": environment})
    require(result.returncode == 0, "installed-reader-refused")
    report = strict_loads(result.stdout.rstrip(b"\n"))
    receipt = {**decide(report, policy), "policyFileSha256": policy_sha256, "readerStdoutSha256": sha(result.stdout)}
    write(output / "host-decision.json", receipt)
    return receipt


def reader_environment() -> dict[str, str]:
    """Prevent inherited Python paths and user sites from escaping the closure."""
    selected = {key: value for key, value in child_environment().items() if key not in {"PYTHONPATH", "PYTHONHOME"}}
    return {**selected, "PYTHONNOUSERSITE": "1", "PYTHONSAFEPATH": "1"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--pins-file", type=Path, required=True)
    parser.add_argument("--policy-file", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--reader", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(canonical(gate(args.packet, args.pins_file, args.policy_file, args.policy_sha256, args.reader, args.output)).decode())
