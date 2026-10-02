"""Retain normal 0.0.2-to-0.0.3 upgrade; schema validity and semantic policy stay separate."""

from __future__ import annotations
import argparse
import hashlib
import json
import shutil
import subprocess
import zipfile
from pathlib import Path
from run_upgrade_example import prepare, run

ROOT = Path(__file__).resolve().parent


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def prepare_format(output):
    provenance = json.loads((ROOT / "format-fixture-provenance.json").read_bytes())
    fixture = ROOT / "format-run.zip"
    if digest(fixture.read_bytes()) != provenance["fixtureSha256"]:
        raise ValueError("format fixture transport differs")
    output.mkdir()
    with zipfile.ZipFile(fixture) as archive:
        if set(archive.namelist()) != set(provenance["members"]):
            raise ValueError("format native member population differs")
        for name in archive.namelist():
            path = output / name
            if not path.resolve().is_relative_to(output.resolve()):
                raise ValueError("format fixture escapes packet")
            raw = archive.read(name)
            if digest(raw) != provenance["members"][name]:
                raise ValueError("format native member changed")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--baseline-python", type=Path, required=True)
    parser.add_argument("--candidate-python", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    packets = {}
    for name in ("original", "comparison", "format"):
        packet = args.output / (name + "-packet")
        if name == "format":
            prepare_format(packet)
        else:
            prepare(name, packet)
        packets[name] = packet
    results = {}
    for python, prefix in (
        (args.baseline_python, "baseline"),
        (args.candidate_python, "candidate"),
    ):
        details = json.loads(
            subprocess.check_output(
                [
                    str(python),
                    "-c",
                    'import importlib.metadata as m,importlib.util as u,json; print(json.dumps({"version":m.version("probity-model-task-reader"),"frameworkModules":{x:u.find_spec(x) is not None for x in ["llama_cpp","inspect_ai","langgraph","pydantic_ai","agents"]}}))',
                ]
            )
        )
        results[prefix + "-installation"] = details
        if details["version"] != ("0.0.2" if prefix == "baseline" else "0.0.3") or any(
            details["frameworkModules"].values()
        ):
            raise ValueError(
                "normal installed versions or framework-free environment differ"
            )
        for name, policy, pins in (
            ("original", "evidence-policy.json", "selected-native-pins.json"),
            (
                "comparison",
                "comparison-evidence-policy.json",
                "comparison-native-pins.json",
            ),
            ("format", "format-evidence-policy.json", "format-native-pins.json"),
        ):
            results[prefix + "-" + name] = run(
                python,
                packets[name],
                policy,
                pins,
                args.output / (prefix + "-" + name),
                1 if name == "format" and prefix == "baseline" else 0,
            )
    results["preservedReports"] = {}
    for name in ("original", "comparison"):
        streams = [
            (args.output / (prefix + "-" + name) / "reader.stdout").read_bytes()
            for prefix in ("baseline", "candidate")
        ]
        if streams[0] != streams[1]:
            raise ValueError("previous native report bytes changed: " + name)
        results["preservedReports"][name] = digest(streams[0])
    policy = json.loads((ROOT / "format-evidence-policy.json").read_bytes())
    command = [
        str(args.baseline_python.parent / "probity-model-task-read"),
        str(packets["format"]),
        "--pins-file",
        str(ROOT / "format-native-pins.json"),
        "--reader-sha256",
        policy["readerSha256"],
    ]
    old_reader = subprocess.run(command, capture_output=True, timeout=60, check=False)
    (args.output / "baseline-reader.stdout").write_bytes(old_reader.stdout)
    (args.output / "baseline-reader.stderr").write_bytes(old_reader.stderr)
    if (
        old_reader.returncode != 1
        or "source differs" not in json.loads(old_reader.stdout)["reason"]
    ):
        raise ValueError("baseline reader did not refuse unselected new source")
    results["baseline-reader"] = {
        "command": command,
        "exit": old_reader.returncode,
        "stdoutSha256": digest(old_reader.stdout),
    }
    results["candidate-format-quality"] = run(
        args.candidate_python,
        packets["format"],
        "format-quality-policy.json",
        "format-native-pins.json",
        args.output / "candidate-format-quality",
        1,
    )
    failures = results["candidate-format-quality"]["gate"]["policyFailures"]
    if len(failures) != 2 or any(
        x["row"]["decoder"] != "schema"
        or x["row"]["model"] != "smol360-q4"
        or x["row"]["family"] != "policy-decision"
        or x["field"] != "correct"
        or x["measured"] != 1
        or x["minimum"] != 3
        for x in failures
    ):
        raise ValueError("selected semantic refusal differs despite valid schemas")
    mutant = args.output / "mutant-packet"
    shutil.copytree(packets["format"], mutant)
    (mutant / "terminal.json").write_bytes(b"{}")
    results["candidate-mutant"] = run(
        args.candidate_python,
        mutant,
        "format-evidence-policy.json",
        "format-native-pins.json",
        args.output / "candidate-mutant",
        1,
    )
    (args.output / "upgrade-result.json").write_text(
        json.dumps(results, indent=2) + "\n"
    )
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
