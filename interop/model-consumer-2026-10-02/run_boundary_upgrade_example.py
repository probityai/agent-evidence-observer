"""Retain the normal 0.0.3-to-0.0.4 upgrade against original frozen outputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

from run_format_upgrade_example import prepare_format
from run_upgrade_example import prepare, run

ROOT = Path(__file__).resolve().parent


def digest(raw: bytes) -> str:
    """Return SHA256 of retained bytes without JSON reserialization."""
    return hashlib.sha256(raw).hexdigest()


def prepare_boundary(output: Path) -> None:
    """Authenticate and materialize every original compact-artifact member.

    Parameters
    ----------
    output : pathlib.Path
        Fresh packet directory outside the retained source checkout.

    Raises
    ------
    ValueError
        If ZIP transport, complete/unique/safe member population or a member
        digest differs from the selected original artifact provenance.
    """
    provenance = json.loads((ROOT / "boundary-fixture-provenance.json").read_bytes())
    fixture = ROOT / provenance["fixturePath"]
    if digest(fixture.read_bytes()) != provenance["fixtureSha256"]:
        raise ValueError("boundary original artifact transport differs")
    with zipfile.ZipFile(fixture) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or set(names) != set(provenance["members"]):
            raise ValueError("boundary original artifact member population differs")
        output.mkdir(parents=True, exist_ok=False)
        for name in names:
            path = output / name
            if not path.resolve().is_relative_to(output.resolve()):
                raise ValueError("boundary original artifact member escapes packet")
            raw = archive.read(name)
            if digest(raw) != provenance["members"][name]:
                raise ValueError("boundary original artifact member bytes changed")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)


def installation(python: Path, expected: str) -> dict[str, Any]:
    """Verify a clean, ordinary installation and absence of model/framework imports.

    Parameters
    ----------
    python : pathlib.Path
        Python executable in a clean consumer virtual environment.
    expected : str
        Selected distribution version, either 0.0.3 or 0.0.4.

    Returns
    -------
    dict
        Actual installed version and module-presence record.

    Raises
    ------
    ValueError
        If a version or framework-free installation differs.
    """
    source = (
        "import importlib.metadata as m, importlib.util as u, json; "
        'print(json.dumps({"version":m.version("probity-model-task-reader"),'
        '"frameworkModules":{name:u.find_spec(name) is not None for name in '
        '["llama_cpp","inspect_ai","langgraph","pydantic_ai","agents","google"]}}))'
    )
    details = json.loads(subprocess.check_output([str(python), "-c", source]))
    if details["version"] != expected or any(details["frameworkModules"].values()):
        raise ValueError("normal boundary reader installation differs")
    return details


def _baseline_refusal(python: Path, packet: Path, output: Path) -> dict[str, Any]:
    """Retain old-reader refusal before the new source can execute."""
    policy = json.loads((ROOT / "boundary-evidence-policy.json").read_bytes())
    command = [
        str(python.parent / "probity-model-task-read"),
        str(packet),
        "--pins-file",
        str(ROOT / "boundary-native-pins.json"),
        "--reader-sha256",
        policy["readerSha256"],
    ]
    child = subprocess.run(command, capture_output=True, timeout=60, check=False)
    (output / "baseline-reader.stdout").write_bytes(child.stdout)
    (output / "baseline-reader.stderr").write_bytes(child.stderr)
    expected = "installed reader source differs from host selection"
    if child.returncode != 1 or json.loads(child.stdout).get("reason") != expected:
        raise ValueError("baseline reader did not refuse unsupported boundary source")
    return dict(
        command=command, exit=child.returncode, stdoutSha256=digest(child.stdout)
    )


def _preserved_reports(output: Path) -> dict[str, str]:
    """Require prior 48, 96 and 192 CLI report bytes to survive the upgrade exactly."""
    preserved: dict[str, str] = {}
    for name in ("original", "comparison", "format"):
        old = (output / f"baseline-{name}/reader.stdout").read_bytes()
        new = (output / f"candidate-{name}/reader.stdout").read_bytes()
        if old != new:
            raise ValueError(
                "historical native report changed after boundary upgrade: " + name
            )
        preserved[name] = digest(old)
    return preserved


def _boundary_original(output: Path) -> dict[str, str]:
    """Require reconstructed reader output to equal the immutable native report.

    The original member uses canonical JSON; the installed CLI uses indentation.
    Both the parsed report and canonical bytes must agree, so CLI serialization
    changes cannot be mistaken for a rewritten original experimental result.
    """
    original = (output / "boundary-packet/report.json").read_bytes()
    stdout = (output / "candidate-boundary/reader.stdout").read_bytes()
    report = json.loads(stdout)
    canonical = (
        json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode()
    if report != json.loads(original) or canonical != original:
        raise ValueError("installed boundary report differs from immutable original")
    return dict(
        originalMemberSha256=digest(original),
        installedStdoutSha256=digest(stdout),
        canonicalBytesEqualOriginal=True,
    )


def execute(output: Path, baseline: Path, candidate: Path) -> dict[str, Any]:
    """Execute installed baseline/candidate gates without rerunning inference.

    Parameters
    ----------
    output : pathlib.Path
        Fresh directory retaining every command, child stdout/stderr and receipt.
    baseline, candidate : pathlib.Path
        Normally installed 0.0.3 and upgraded 0.0.4 environment executables.

    Returns
    -------
    dict
        Exact version checks, prior-report preservation, selected evidence
        publication, separate per-row quality holds and a native mutation refusal.

    Raises
    ------
    ValueError
        If an installed decision, row failure, report byte or mutation control
        differs. All already-produced raw command receipts remain retained.
    """
    output.mkdir(parents=True, exist_ok=False)
    packets: dict[str, Path] = {}
    preparers = dict(
        original=lambda p: prepare("original", p),
        comparison=lambda p: prepare("comparison", p),
        format=prepare_format,
        boundary=prepare_boundary,
    )
    for name, preparer in preparers.items():
        packets[name] = output / (name + "-packet")
        preparer(packets[name])
    results: dict[str, Any] = {}
    profiles = dict(
        original=("evidence-policy.json", "selected-native-pins.json"),
        comparison=("comparison-evidence-policy.json", "comparison-native-pins.json"),
        format=("format-evidence-policy.json", "format-native-pins.json"),
        boundary=("boundary-evidence-policy.json", "boundary-native-pins.json"),
    )
    for python, prefix, version in (
        (baseline, "baseline", "0.0.3"),
        (candidate, "candidate", "0.0.4"),
    ):
        results[prefix + "-installation"] = installation(python, version)
        for name, (policy, pins) in profiles.items():
            results[prefix + "-" + name] = run(
                python,
                packets[name],
                policy,
                pins,
                output / (prefix + "-" + name),
                int(name == "boundary" and prefix == "baseline"),
            )
    results["preservedReports"] = _preserved_reports(output)
    results["boundaryOriginal"] = _boundary_original(output)
    results["baseline-reader"] = _baseline_refusal(
        baseline, packets["boundary"], output
    )
    results["candidate-boundary-quality"] = run(
        candidate,
        packets["boundary"],
        "boundary-quality-policy.json",
        "boundary-native-pins.json",
        output / "candidate-boundary-quality",
        1,
    )
    failures = results["candidate-boundary-quality"]["gate"]["policyFailures"]
    identities = {
        (
            failure["row"]["model"],
            failure["row"]["configuration"],
            failure["row"]["family"],
        )
        for failure in failures
    }
    if len(failures) != 16 or len(identities) != 8:
        raise ValueError("boundary quality holds no longer retain all eight weak rows")
    mutant = output / "mutant-packet"
    shutil.copytree(packets["boundary"], mutant)
    (mutant / "terminal.json").write_bytes(b"{}")
    results["candidate-mutant"] = run(
        candidate,
        mutant,
        "boundary-evidence-policy.json",
        "boundary-native-pins.json",
        output / "candidate-mutant",
        1,
    )
    (output / "upgrade-result.json").write_text(json.dumps(results, indent=2) + "\n")
    return results


def main() -> None:
    """Run :func:`execute` for selected ordinary installed Python environments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--baseline-python", type=Path, required=True)
    parser.add_argument("--candidate-python", type=Path, required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            execute(args.output, args.baseline_python, args.candidate_python), indent=2
        )
    )


if __name__ == "__main__":
    main()
