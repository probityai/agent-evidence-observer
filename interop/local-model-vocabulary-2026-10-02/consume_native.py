"""Install a selected model-free reader and retain its actual packet decisions.

The packet and pins remain separate inputs. This verifier does not infer or
authorize effects. Its process owns installation and replay; another process
must supply the source-selected wheel and independently held packet pins.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

LOGGER = logging.getLogger(__name__)


def process_environment(additions: dict[str, str] | None = None) -> dict[str, str]:
    """Remove inherited Python and pip configuration from child processes.

    ``additions`` supports an explicit hostile-environment control before
    sanitization. Isolation also uses the interpreter's ``-I`` flag; this
    filter alone does not establish protection from hostile host software.
    """
    selected = dict(os.environ)
    selected.update(additions or {})
    return {name: value for name, value in selected.items() if not name.startswith(("PYTHON", "PIP"))}


def sha256(path: Path) -> str:
    """Return the SHA-256 commitment to a regular file's original bytes."""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def invoke(reader: Path, packet: Path, pins: Path, output: Path, *, evidence_only: bool = False, environment_additions: dict[str, str] | None = None, cwd: Path | None = None) -> tuple[int, dict[str, Any]]:
    """Invoke the installed reader and retain its unmodified JSON response.

    Parameters
    ----------
    reader, packet, pins, output : pathlib.Path
        Installed console entry point, original packet, separately selected
        four-hash pins, and an exclusive output path respectively.
    evidence_only : bool, optional
        Select exit status on evidence validity while retaining the strict
        host's independent quality decision. No score or threshold changes.

    Returns
    -------
    tuple of int and dict
        Actual subprocess exit status and parsed original response.

    Raises
    ------
    subprocess.TimeoutExpired
        If the offline replay exceeds sixty seconds.
    ValueError
        If the installed reader produces invalid JSON.
    """
    command = [str(reader.with_name("python")), "-I", str(reader), str(packet), "--pins-file", str(pins)]
    if evidence_only:
        command.append("--evidence-only")
    result = subprocess.run(command, capture_output=True, timeout=60, check=False, env=process_environment(environment_additions), cwd=cwd)
    output.write_bytes(result.stdout)
    output.with_suffix(".stderr.txt").write_bytes(result.stderr)
    return result.returncode, json.loads(result.stdout)


def hostile_launch_control(reader: Path, packet: Path, pins: Path, output: Path, expected: dict[str, Any], expected_code: int) -> dict[str, Any]:
    """Require an actual installed replay to ignore hostile PATH and CWD code.

    Native packet arguments remain absolute. The hostile directory includes
    ``sitecustomize`` and a shadow package, while environment selection adds
    Python home/path/user configuration. No hostile file may execute.
    """
    hostile = output / "hostile-startup"
    hostile.mkdir()
    marker = hostile / "executed.txt"
    payload = f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\nraise RuntimeError('hostile startup executed')\n"
    (hostile / "sitecustomize.py").write_text(payload)
    package = hostile / "probity_policy_vocabulary_reader"
    package.mkdir()
    (package / "__init__.py").write_text(payload)
    additions = {"PYTHONPATH": str(hostile), "PYTHONHOME": str(hostile), "PYTHONUSERBASE": str(hostile)}
    code, result = invoke(reader, packet, pins, output / "hostile-launch.json", environment_additions=additions, cwd=hostile)
    require(code == expected_code and result == expected and not marker.exists(), "hostile launch changed installed consumer")
    return {"ignoredPythonPathHomeUserBaseAndCWD": True, "hostileMarkerAbsent": True, "consumerExact": True, "scope": "selected hostile Python configuration only; protected host interpreter and installed environment remain trusted"}


def require(condition: bool, message: str) -> None:
    """Refuse a violated consumer invariant with a stable logged diagnostic."""
    if not condition:
        LOGGER.error("%s", message)
        raise ValueError(message)


def refuse_mutation(reader: Path, packet: Path, pins: Path, output: Path, *, resign_helper: bool) -> dict[str, Any]:
    """Require installed-reader refusal on a copied original packet.

    A changed response keeps the held pins. A changed helper updates only its
    manifest commitment and the separately supplied manifest pin; the frozen
    protocol remains the reader's authority. Retained candidate code is never
    executed. See :func:`consume` for clean installation and positive replay.
    """
    name = "resigned-helper" if resign_helper else "changed-response"
    destination = output / name
    shutil.copytree(packet, destination)
    relative = "sources/schema_contract.py" if resign_helper else next((destination / "calls").glob("*-returned.json")).relative_to(destination).as_posix()
    changed = destination / relative
    changed.write_bytes(changed.read_bytes() + b"\n")
    selections = json.loads(pins.read_bytes())
    expected = "original retained bytes changed"
    if resign_helper:
        manifest = json.loads((destination / "manifest.json").read_bytes())
        manifest[relative] = sha256(changed)
        (destination / "manifest.json").write_text(json.dumps(manifest) + "\n")
        selections["manifest"]["sha256"] = sha256(destination / "manifest.json")
        expected = "retained schema helper differs from selected protocol"
    selected = output / (name + "-pins.json")
    selected.write_text(json.dumps(selections) + "\n")
    code, result = invoke(reader, destination, selected, output / (name + ".json"))
    require(code == 1 and result.get("consumerDecision") == "hold-evidence" and result.get("error", {}).get("message") == expected, "installed reader did not refuse selected corruption")
    return {"case": name, "exitCode": code, "consumerDecision": result["consumerDecision"], "error": result["error"]}


def consume(wheel: Path, packet: Path, pins: Path, output: Path, *, expected_report: Path | None = None) -> dict[str, Any]:
    """Install without dependencies and repeat actual packet quality decisions.

    Parameters
    ----------
    wheel : pathlib.Path
        Wheel already verified against the independently held source contract.
    packet : pathlib.Path
        Original finite native packet. This function never imports its code.
    pins : pathlib.Path
        Four source-selected artifact commitments supplied outside the packet.
    output : pathlib.Path
        Fresh exclusive directory for environment and original receipts.
    expected_report : pathlib.Path, optional
        Separately held original report to require exact recomputation equality.

    Returns
    -------
    dict
        Clean-installation, repeated-decision and corruption-refusal receipt.
        An evidence-valid quality hold is a successful verification result,
        while the retained strict consumer exit status remains one.
    """
    output.mkdir(parents=True, exist_ok=False)
    environment = output / "environment"
    subprocess.run([sys.executable, "-I", "-m", "venv", str(environment)], check=True, timeout=60, env=process_environment())
    python = environment / "bin/python"
    subprocess.run([str(python), "-I", "-m", "pip", "--isolated", "install", "--no-index", "--no-deps", str(wheel)], check=True, timeout=60, env=process_environment())
    reader = environment / "bin/probity-policy-vocabulary-reader"
    code, result = invoke(reader, packet, pins, output / "strict.json")
    repeat_code, repeat = invoke(reader, packet, pins, output / "repeat.json")
    evidence_code, evidence = invoke(reader, packet, pins, output / "evidence-only.json", evidence_only=True)
    require(result == repeat == evidence and code == repeat_code, "installed reader decision changed on repeat")
    require((output / "strict.json").read_bytes() == (output / "repeat.json").read_bytes() and (output / "strict.stderr.txt").read_bytes() == (output / "repeat.stderr.txt").read_bytes(), "installed reader original streams changed on repeat")
    require(result.get("evidenceDecision") == "accept-scoped-evidence" and evidence_code == 0, "installed reader did not accept selected native evidence")
    expected_code = 0 if result["consumerDecision"] == "admit-scoped-quality" else 1
    require(code == expected_code, "strict consumer exit differs from quality decision")
    if expected_report is not None:
        require(result["report"] == json.loads(expected_report.read_bytes()), "installed native report differs from selected original")
    controls = [refuse_mutation(reader, packet, pins, output, resign_helper=mode) for mode in (False, True)]
    hostile = hostile_launch_control(reader, packet, pins, output, result, code)
    packages = subprocess.check_output([str(python), "-I", "-c", "import importlib.metadata,json; print(json.dumps(sorted(d.metadata['Name'] for d in importlib.metadata.distributions())))"], text=True, timeout=60, env=process_environment())
    names = json.loads(packages)
    require(set(names) <= {"pip", "setuptools", "probity-policy-vocabulary-reader"}, "clean reader environment contains unselected dependencies")
    receipt = {"schema": "probity-vocabulary-installed-native-consumer-v1", "wheelSHA256": sha256(wheel), "wheelBytes": wheel.stat().st_size, "pinsSHA256": sha256(pins), "strictExitCode": code, "evidenceOnlyExitCode": evidence_code, "evidenceDecision": result["evidenceDecision"], "qualityDecision": result["qualityDecision"], "consumerDecision": result["consumerDecision"], "qualityFailureRows": len(result["qualityFailures"]), "repeatExact": True, "originalStdoutStderrRepeatExact": True, "expectedReportExact": expected_report is not None, "installedDistributions": names, "corruptionControls": controls, "hostileLaunchControl": hostile, "scope": "same operator installed offline replay and mutation controls; no new inference, effects, outside acceptance/adoption or independent custody"}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def main() -> None:
    """Read separate source-selected inputs and print a complete receipt."""
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("wheel", "packet", "pins", "output"):
        parser.add_argument(argument, type=Path)
    parser.add_argument("--expected-report", type=Path)
    args = parser.parse_args()
    print(json.dumps(consume(args.wheel.resolve(), args.packet.resolve(), args.pins.resolve(), args.output.resolve(), expected_report=args.expected_report), indent=2))


if __name__ == "__main__":
    main()
