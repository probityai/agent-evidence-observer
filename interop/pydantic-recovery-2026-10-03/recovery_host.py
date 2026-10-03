"""Separate installed-reader selection and bounded publication decision."""
from __future__ import annotations

import argparse
import hashlib
import subprocess
from pathlib import Path
from typing import Any

from probity_observer.crypto import canonical, strict_loads

from probity_pydantic_recovery.common import (
    CASES,
    PROFILE,
    child_environment,
    load,
    require,
    sha,
    write,
)


def file_hash(path: Path) -> str:
    """Hash host-selected runtime files without loading a large extension at once."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def reader_closure(executable: Path) -> dict[str, Any]:
    """Select the whole isolated install, including metadata and injection surfaces.

    The resolved interpreter is selected separately. Host OS and standard
    library remain local custody assumptions, rather than independent proof.
    """
    executable = executable.absolute()
    environment = executable.parent.parent
    require(executable.parent.name == "bin" and (environment / "pyvenv.cfg").is_file(), "reader-isolated-environment")
    config = (environment / "pyvenv.cfg").read_text()
    require("include-system-site-packages = false" in config.lower(), "reader-system-packages")
    files = {}
    for path in sorted(environment.rglob("*")):
        if path.is_file():
            files[str(path.relative_to(environment))] = {"sha256": file_hash(path), "symlink": str(path.readlink()) if path.is_symlink() else None}
    python = environment / "bin/python"
    return {"environment": str(environment), "files": files, "interpreter": str(python.resolve()), "interpreterSha256": file_hash(python.resolve())}


def select_policy(pins: Path, executable: Path) -> dict[str, Any]:
    """Make a concrete local host selection outside the candidate packet."""
    return {"profile": PROFILE, "pinsSha256": sha(pins.read_bytes()), "readerSha256": file_hash(executable), "readerClosure": reader_closure(executable), "plannedAttempts": len(CASES), "releasedResults": 1, "recoveryPosts": 0}


def decide(report: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    """Publish a checked refusal population without approving denied actions."""
    require(report["profile"] == policy["profile"] == PROFILE and report["status"] == "verified", "publication-profile")
    require(report["plannedAttempts"] == policy["plannedAttempts"] == len(CASES), "publication-denominator")
    require([row["id"] for row in report["records"]] == list(CASES), "publication-case-population")
    require([row["releasedResult"] for row in report["records"]] == [True] + [False] * (len(CASES) - 1), "publication-result-dispositions")
    require(sum(row["releasedResult"] for row in report["records"]) == policy["releasedResults"] == 1, "publication-result-count")
    require(sum(row["recoveryPosts"] for row in report["records"]) == policy["recoveryPosts"] == 0, "publication-effect-count")
    return {"decision": "publish-scoped-recovery-report", "dispatchDecision": "no-additional-dispatch-authorized", "releasedResults": 1, "withheldResults": len(CASES) - 1, "recoveryPosts": 0}


def gate(packet: Path, pins: Path, policy_file: Path, policy_sha256: str, executable: Path, output: Path) -> dict[str, Any]:
    """Require selected reader closure before launching an installed consumer."""
    require(sha(policy_file.read_bytes()) == policy_sha256, "host-policy-digest")
    policy = load(policy_file)
    require(policy == select_policy(pins, executable), "host-reader-selection")
    output.mkdir(parents=True, exist_ok=False)
    write(output / "selected-host-policy.json", policy)
    write(output / "selected-pins.json", pins.read_bytes(), raw=True)
    command = [str(executable.absolute()), str(packet.absolute()), "--pins-file", str(pins.absolute())]
    environment = reader_environment()
    result = subprocess.run(command, capture_output=True, timeout=30, env=environment, cwd=output, check=False)
    write(output / "reader.stdout", result.stdout, raw=True)
    write(output / "reader.stderr", result.stderr, raw=True)
    write(output / "reader-process.json", {"argv": command, "returncode": result.returncode, "environment": environment})
    require(result.returncode == 0, "installed-reader-refused")
    report = strict_loads(result.stdout.rstrip(b"\n"))
    receipt = decide(report, policy)
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
