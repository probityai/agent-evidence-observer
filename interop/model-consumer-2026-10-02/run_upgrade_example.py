"""Retain actual ordinary0.0.1->0.0.2 command behavior without new model execution."""

from __future__ import annotations
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def prepare(name, output):
    fixture = ROOT / (("comparison-" if name == "comparison" else "") + "run.zip")
    if name == "original":
        fixture = ROOT / "original-run.zip"
    metadata = ROOT / (
        ("comparison-" if name == "comparison" else "") + "fixture-provenance.json"
    )
    provenance = json.loads(metadata.read_bytes())
    if digest(fixture.read_bytes()) != provenance["fixtureSha256"]:
        raise ValueError("native fixture transport differs")
    output.mkdir()
    with zipfile.ZipFile(fixture) as archive:
        if set(archive.namelist()) != set(provenance["members"]):
            raise ValueError("native fixture member population differs")
        for name in archive.namelist():
            path = output / name
            if not path.resolve().is_relative_to(output.resolve()):
                raise ValueError("native fixture escapes packet")
            raw = archive.read(name)
            if digest(raw) != provenance["members"][name]:
                raise ValueError("native fixture member changed")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)


def run(python, packet, policy_name, pins_name, output, expected):
    policy = ROOT / policy_name
    command = [
        str(python.parent / "probity-model-publication-gate"),
        str(packet),
        str(output),
        "--pins-file",
        str(ROOT / pins_name),
        "--policy-file",
        str(policy),
        "--policy-sha256",
        digest(policy.read_bytes()),
    ]
    env = os.environ.copy()
    env["PATH"] = str(python.parent) + os.pathsep + env["PATH"]
    child = subprocess.run(
        command, env=env, capture_output=True, timeout=90, check=False
    )
    (output.parent / (output.name + ".stdout")).write_bytes(child.stdout)
    (output.parent / (output.name + ".stderr")).write_bytes(child.stderr)
    if child.returncode != expected:
        raise ValueError("installed gate decision differs: " + output.name)
    receipt = json.loads((output / "gate.json").read_bytes())
    return {"command": command, "exit": child.returncode, "gate": receipt}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--baseline-python", type=Path, required=True)
    parser.add_argument("--candidate-python", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    packets = {}
    for name in ("original", "comparison"):
        packet = args.output / (name + "-packet")
        prepare(name, packet)
        packets[name] = packet
    results = {}
    for python, prefix in (
        (args.baseline_python, "baseline"),
        (args.candidate_python, "candidate"),
    ):
        version = (
            subprocess.check_output(
                [
                    str(python),
                    "-c",
                    'import importlib.metadata; print(importlib.metadata.version("probity-model-task-reader"))',
                ]
            )
            .decode()
            .strip()
        )
        results[prefix + "-version"] = version
        results[prefix + "-original"] = run(
            python,
            packets["original"],
            "evidence-policy.json",
            "selected-native-pins.json",
            args.output / (prefix + "-original"),
            0,
        )
        results[prefix + "-comparison-evidence"] = run(
            python,
            packets["comparison"],
            "comparison-evidence-policy.json",
            "comparison-native-pins.json",
            args.output / (prefix + "-comparison-evidence"),
            1 if prefix == "baseline" else 0,
        )
    if (
        results["baseline-version"] != "0.0.1"
        or results["candidate-version"] != "0.0.2"
    ):
        raise ValueError("actual normally installed upgrade versions differ")
    original_streams = [
        (args.output / (prefix + "-original") / "reader.stdout").read_bytes()
        for prefix in ("baseline", "candidate")
    ]
    if original_streams[0] != original_streams[1]:
        raise ValueError("original profile report changed after installed upgrade")
    results["originalReportSha256"] = digest(original_streams[0])
    results["candidate-comparison-quality"] = run(
        args.candidate_python,
        packets["comparison"],
        "comparison-quality-policy.json",
        "comparison-native-pins.json",
        args.output / "candidate-comparison-quality",
        1,
    )
    mutant = args.output / "mutant-packet"
    shutil.copytree(packets["comparison"], mutant)
    (mutant / "terminal.json").write_bytes(b"{}")
    results["candidate-mutant"] = run(
        args.candidate_python,
        mutant,
        "comparison-evidence-policy.json",
        "comparison-native-pins.json",
        args.output / "candidate-mutant",
        1,
    )
    (args.output / "upgrade-result.json").write_text(
        json.dumps(results, indent=2) + "\n"
    )
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
