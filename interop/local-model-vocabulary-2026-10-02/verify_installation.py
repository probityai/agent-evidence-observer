"""Build and install the reader, then exercise synthetic consumer/refusal controls."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

from build_installed_reader import build
from task_matrix import digest, encode, population, protocol

CONTRACT_SHA256 = "4a3a47b14308f726af505ac489c9cb4c482cd48c09eacd3881c2fafe44f14ff7"
ROOT = Path(__file__).resolve().parent


def verify_installation(checkout: Path, output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    build_record = build(
        checkout,
        ROOT / "reader-source-contract.json",
        CONTRACT_SHA256,
        output / "wheel",
    )
    second = build(
        checkout,
        ROOT / "reader-source-contract.json",
        CONTRACT_SHA256,
        output / "repeat-wheel",
    )
    if build_record["wheel"] != second["wheel"]:
        raise ValueError("repeated build changes the selected wheel")
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    venv = output / "isolated-env"
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv)], check=True, env=environment
    )
    python = venv / "bin/python"
    wheel = output / "wheel" / build_record["wheel"]["name"]
    subprocess.run(
        [str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)],
        check=True,
        env=environment,
    )
    subprocess.run(
        [
            str(python),
            "-c",
            "import importlib.util; assert importlib.util.find_spec('llama_cpp') is None",
        ],
        check=True,
        env=environment,
    )
    source = ROOT / "tests/test_vocabulary_runtime.py"
    spec = importlib.util.spec_from_file_location("selected_synthetic_controls", source)
    controls = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(controls)
    packet = output / "synthetic-packet"
    pins = controls.fixture(packet)
    pins_file = output / "selected-synthetic-pins.json"

    def invoke(name, expected_code, expected_decision, *extra):
        pins_file.write_bytes(encode(pins))
        child = subprocess.run(
            [
                str(venv / "bin/probity-policy-vocabulary-reader"),
                str(packet),
                "--pins-file",
                str(pins_file),
                *extra,
            ],
            capture_output=True,
            check=False,
            env=environment,
            cwd=output,
            timeout=30,
        )
        (output / (name + ".stdout.json")).write_bytes(child.stdout)
        (output / (name + ".stderr.txt")).write_bytes(child.stderr)
        result = json.loads(child.stdout)
        if (
            child.returncode != expected_code
            or result["consumerDecision"] != expected_decision
        ):
            raise ValueError("installed consumer decision differs: " + name)
        return result

    valid = invoke("valid", 0, "admit-scoped-quality")
    p = protocol((ROOT / "protocol.json").read_bytes())
    ident, _, case = population(p)[0]
    returned = packet / ("calls/" + ident + "-returned.json")
    response = json.loads(returned.read_bytes())
    response["response"]["choices"][0]["text"] = json.dumps(
        {"decision": "publish" if case["target"]["decision"] == "hold" else "hold"}
    )
    returned.write_bytes(encode(response))
    pins = controls.repin(packet)
    weak = invoke("weak", 1, "hold-quality")
    repeated = invoke("weak-repeat", 1, "hold-quality")
    if weak != repeated or weak["evidenceDecision"] != "accept-scoped-evidence":
        raise ValueError(
            "repeated host decision or evidence/quality separation differs"
        )
    invoke("weak-evidence-only", 0, "hold-quality", "--evidence-only")
    helper = packet / "sources/schema_contract.py"
    helper.write_bytes(helper.read_bytes() + b"\n# candidate-only change\n")
    pins = controls.repin(packet)
    tampered = invoke("tampered-helper", 1, "hold-evidence")
    record = {
        "schema": "probity-policy-vocabulary-installation-controls-v1",
        "build": build_record,
        "repeatedWheelExact": True,
        "isolatedInstall": True,
        "modelRuntimeInstalled": False,
        "validSyntheticDecision": valid["consumerDecision"],
        "weakSyntheticDecision": weak["consumerDecision"],
        "repeatConsumerExact": weak == repeated,
        "resignedChangedHelperDecision": tampered["consumerDecision"],
        "controlsSourceSHA256": digest(source.read_bytes()),
        "scope": "Synthetic authored byte controls only; no model calls, producer acceptance, recurring outside adoption, effects or independent custody established.",
    }
    (output / "installation-record.json").write_bytes(encode(record))
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(
        json.dumps(
            verify_installation(args.checkout.resolve(), args.output.resolve()),
            indent=2,
        )
    )
