"""Exercise an installed Atomic reader on a real operator-retained native run.

This demonstration intentionally selects local operator bytes. It is neither
external capture nor producer acceptance. Never execute the retained binary.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve()
    packet = args.packet.resolve()
    candidate = subprocess.run(["agent-evidence-read-atomic", "describe", "--packet", str(packet)], capture_output=True, check=True)
    selected = output / "selected-inputs.json"
    selected.write_bytes(candidate.stdout)
    selection_pin = digest(selected)

    def check(name, target, selection=selected, pin=selection_pin):
        result = subprocess.run([
            "agent-evidence-read-atomic", "verify", "--packet", str(target),
            "--selection", str(selection), "--selection-sha256", pin,
            "--output", str(output / (name + ".json")),
        ], capture_output=True)
        (output / (name + ".stdout")).write_bytes(result.stdout)
        (output / (name + ".stderr")).write_bytes(result.stderr)
        return result.returncode

    outcomes = {"selected_native_run": check("selected_native_run", packet)}
    controls = ("missing_log", "altered_binary", "wrong_source", "dropped_case", "changed_scope", "changed_population")
    for name in controls:
        changed = output / "controlled-packet"
        shutil.copytree(packet, changed)
        report_path = changed / "report.json"
        report = json.loads(report_path.read_text())
        if name == "missing_log":
            (changed / "case-0.stdout").unlink()
        elif name == "altered_binary":
            with (changed / report["binary"]["filename"]).open("ab") as stream:
                stream.write(b"altered binary")
        elif name == "wrong_source":
            with (changed / "source/Cargo.lock").open("ab") as stream:
                stream.write(b"altered source")
        elif name == "dropped_case":
            report["results"].pop()
            report_path.write_text(json.dumps(report))
        elif name == "changed_scope":
            report["results"][0]["observations"][0]["allows_push"] = True
            report_path.write_text(json.dumps(report))
        else:
            with (changed / "population.txt").open("a") as stream:
                stream.write("unselected_additional_case: test\n")
        outcomes[name] = check(name, changed)
        shutil.rmtree(changed)
    outcomes["wrong_selection_digest"] = check("wrong_selection_digest", packet, pin="0" * 64)
    passed = outcomes["selected_native_run"] == 0 and all(value != 0 for key, value in outcomes.items() if key != "selected_native_run")
    result = {
        "passed": passed, "returncodes": outcomes, "selection_sha256": selection_pin,
        "custody": "same operator retained native bundle and selected consumer inputs",
        "native_rerun": False, "external_acceptance": "not established",
    }
    (output / "controls.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
