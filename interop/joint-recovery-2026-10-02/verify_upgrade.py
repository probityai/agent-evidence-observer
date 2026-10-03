"""Normally install and upgrade the joint reader against a retained native packet.

The caller supplies a separately selected baseline source directory. Hosted CI
checks out the literal prior merge before invoking this script. Source files,
wheel bytes, installation manifests, child streams and the fresh host decisions
are retained; no raw native state or credentials are printed.
"""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import logging
import subprocess
import sys
import venv
from pathlib import Path
from typing import Any

from joint_common import CASES, PROFILE, child_environment, sha, write
from joint_host_gate import gate, reader_closure

SOURCE_NAMES = ("pyproject.toml", "joint_common.py", "joint_reader.py", "joint_host_gate.py")
MAX_COMMAND_SECONDS = 180
LOGGER = logging.getLogger(__name__)


def command(argv: list[str], output: Path, name: str, expected: int = 0) -> bytes:
    """Retain actual process streams and require the declared command outcome.

    Parameters
    ----------
    argv : list of str
        Literal selected build, installation or reader invocation.
    output : pathlib.Path
        Fresh receipt folder outside the candidate packet.
    name : str
        Unique record stem for this command.
    expected : int, default 0
        Required process exit status; reader refusals remain explicit outcomes.

    Returns
    -------
    bytes
        Complete stdout retained alongside stderr and process metadata.
    """
    timed_out = False
    try:
        process = subprocess.run(argv, capture_output=True, timeout=MAX_COMMAND_SECONDS, check=False,
                                 env=child_environment())
    except subprocess.TimeoutExpired as error:
        timed_out = True
        process = subprocess.CompletedProcess(argv, 124, error.stdout or b"", error.stderr or b"")
    (output / (name + ".stdout")).write_bytes(process.stdout)
    (output / (name + ".stderr")).write_bytes(process.stderr)
    write(output / (name + ".process.json"),
          {"argv": argv, "returncode": process.returncode,
           "environment": child_environment(), "maximumSeconds": MAX_COMMAND_SECONDS,
           "timedOut": timed_out})
    if process.returncode != expected:
        message = "upgrade-command-outcome: " + name
        LOGGER.warning("Joint upgrade refused: %s", message)
        raise ValueError(message)
    return process.stdout


def wheel(source: Path, output: Path, name: str) -> Path:
    """Build normal wheel bytes with the current recorded build toolchain."""
    target = output / name
    target.mkdir()
    command([sys.executable, "-m", "pip", "wheel", "--no-index", "--no-deps",
             "--no-build-isolation", "--wheel-dir", str(target), str(source)],
            output, name)
    wheels = list(target.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("upgrade-wheel-population: " + name)
    return wheels[0]


def policy(pins: Path, reader: Path) -> dict[str, Any]:
    """Freeze complete installed bytes and independent host policy selection."""
    return {"profile": PROFILE, "pinsSha256": sha(pins.read_bytes()),
            "plannedAttempts": len(CASES), "readerSha256": sha(reader.read_bytes()),
            "readerClosure": reader_closure(reader)}


def verify(baseline: Path, packet: Path, output: Path, dependencies: Path) -> dict[str, Any]:
    """Keep original evidence byte-exact across a normal 0.0.1-to-0.0.2 upgrade.

    Parameters
    ----------
    baseline : pathlib.Path
        Host-selected prior profile directory from the immutable baseline
        checkout. Candidate packet contents never select this source.
    packet : pathlib.Path
        Complete original native packet, authenticated by separately selected
        pins in the author-operated demonstration.
    output : pathlib.Path
        Fresh outside-packet artifact root. It retains source hashes, wheels,
        installation manifests, process streams and host gate receipts.
    dependencies : pathlib.Path
        Separately prepared wheel folder. The reader lock authenticates every
        installed dependency; the clean environment installs offline.

    Returns
    -------
    dict
        Exact stdout compatibility and separate old/new gate outcomes.
        The same-operator replay establishes no outside acceptance or custody.
    """
    current = Path(__file__).resolve().parent
    root = current.parents[1]
    baseline, packet, output = baseline.resolve(), packet.resolve(), output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    sources = {label: {name: sha((folder / name).read_bytes()) for name in SOURCE_NAMES}
               for label, folder in (("baseline", baseline), ("candidate", current))}
    write(output / "selected-sources.json", sources)
    observer = wheel(root, output, "observer-wheel")
    original = wheel(baseline, output, "baseline-wheel")
    candidate = wheel(current, output, "candidate-wheel")
    environment = output / "reader-environment"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / "bin/python"
    reader = environment / "bin/probity-read-joint-recovery"
    pins = output / "selected-pins.json"
    pins.write_bytes((packet / "consumer-pins.json").read_bytes())
    command([str(python), "-I", "-m", "pip", "--isolated", "install", "--require-hashes",
             "--no-index", "--find-links", str(dependencies.resolve()),
             "--only-binary=:all:", "-r", str(current / "requirements-reader.lock")],
            output, "reader-dependencies")
    command([str(python), "-I", "-m", "pip", "--isolated", "install", "--no-deps",
             "--no-index", str(observer), str(original)], output, "baseline-install")
    invocation = [str(python), "-I", str(reader), str(packet), "--pins-file", str(pins)]
    before = command(invocation, output, "baseline-reader")
    baseline_policy = output / "baseline-policy.json"
    write(baseline_policy, policy(pins, reader))
    baseline_gate = gate(packet, pins, baseline_policy, sha(baseline_policy.read_bytes()),
                         reader, output / "baseline-gate")
    command([str(python), "-I", "-m", "pip", "--isolated", "install", "--no-deps",
             "--no-index", "--upgrade", str(candidate)], output, "candidate-upgrade")
    after = command(invocation, output, "candidate-reader")
    if before != after:
        raise ValueError("upgrade-changed-original-reader-stdout")
    stale_gate = gate(packet, pins, baseline_policy, sha(baseline_policy.read_bytes()),
                      reader, output / "stale-selection-gate")
    if stale_gate["readerReturncode"] is not None or stale_gate["decision"] != "refuse":
        raise ValueError("upgrade-stale-selection-executed-reader")
    candidate_policy = output / "candidate-policy.json"
    write(candidate_policy, policy(pins, reader))
    candidate_gate = gate(packet, pins, candidate_policy, sha(candidate_policy.read_bytes()),
                          reader, output / "candidate-gate")
    if baseline_gate["decision"] != "publish" or candidate_gate["decision"] != "publish":
        raise ValueError("upgrade-current-selection-did-not-publish")
    report = {"schema": "probity-joint-installed-upgrade-v1", "sources": sources,
              "toolchain": {name: importlib.metadata.version(name)
                            for name in ("pip", "setuptools", "wheel")},
              "wheels": {name: {"file": path.name, "bytes": path.stat().st_size,
                                "sha256": sha(path.read_bytes())}
                         for name, path in (("observer", observer), ("baseline", original),
                                            ("candidate", candidate))},
              "originalStdoutSha256": sha(before), "stdoutExact": before == after,
              "baselineGate": baseline_gate, "staleSelectionGate": stale_gate,
              "candidateGate": candidate_gate, "nativeCalls": 0,
              "scope": "Same-operator installed replay; no outside adoption or independent custody."}
    write(output / "upgrade-report.json", report)
    return report


def main() -> None:
    """Run the normal upgrade against explicitly selected baseline and packet."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dependency-wheels", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.baseline, args.packet, args.output, args.dependency_wheels), indent=2))


if __name__ == "__main__":
    main()
