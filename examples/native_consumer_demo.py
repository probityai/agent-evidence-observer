"""Exercise an installed consumer reader against existing controlled packets.

This demo deliberately selects the producer packet's convenience pins and our
local source hashes. It is a same-operator reproduction and refusal test, not an
independent relying party's selection or an external result.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from probity_observer.native_reader import FORMAT, decode, describe_sources, sha


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-checkout", type=Path, required=True)
    parser.add_argument("--native-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, native, output = (
        path.resolve() for path in (args.source_checkout, args.native_root, args.output)
    )
    output.mkdir()
    results = []
    for profile, packet in (
        ("inspect-execution", native / "inspect-execution" / "native"),
        ("a2a", native / "a2a" / "native"),
    ):
        folder = output / profile
        folder.mkdir()
        copy = folder / "packet-copy"
        shutil.copytree(packet, copy)
        if profile == "inspect-execution":
            pins = decode((copy / "packet/consumer-pins.json").read_bytes())
            mutation = copy / "packet/history.json"
        else:
            pins = {
                "artifacts": decode((copy / "selected-native-pins.json").read_bytes()),
                "plan_sha256": sha((copy / "common/plan.json").read_bytes()),
                "history_sha256": sha((copy / "common/history.json").read_bytes()),
                "sources_sha256": sha(
                    json.dumps(
                        {
                            name: sha((copy / "common" / name).read_bytes())
                            for name in (
                                "sdk-source.json",
                                "sdk-source-pins.json",
                                "sdk-license.txt",
                                "local-source.json",
                                "rubric.json",
                                "policy.json",
                                "runtime.json",
                            )
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ).encode()
                ),
            }
            mutation = copy / "common/history.json"
        selection = {
            "format": FORMAT,
            "profile": profile,
            "selection_id": "same-operator-demo-selected-convenience-pins",
            "reader_revision": subprocess.check_output(
                ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
            ).strip(),
            "python_minor": "3.12",
            "native_pins": pins,
            **describe_sources(source, profile),
        }
        selected = folder / "external-selection.json"
        selected.write_text(json.dumps(selection, sort_keys=True, indent=2) + "\n")
        # Use the installed console script (no module __main__ assumption).
        command = [
            str(Path(sys.executable).parent / "agent-evidence-read-native"),
            "--source-checkout",
            str(source),
            "--packet",
            str(copy),
            "--selection",
            str(selected),
            "--selection-sha256",
            sha(selected.read_bytes()),
        ]
        controls = []

        def check(
            name: str,
            expected: int,
            output_name: str | None = None,
            *,
            command=command,
            folder=folder,
            profile=profile,
            controls=controls,
        ) -> None:
            result = subprocess.run(
                command + ["--output", str(folder / (output_name or name))],
                cwd=output,
                capture_output=True,
                check=False,
            )
            (folder / (name + ".stdout.txt")).write_bytes(result.stdout)
            (folder / (name + ".stderr.txt")).write_bytes(result.stderr)
            if (result.returncode == 0) != (expected == 0):
                raise RuntimeError(
                    f"{profile}:{name}:unexpected-exit-{result.returncode}"
                )
            controls.append({"control": name, "exit_code": result.returncode})

        check("accepted", 0)
        original = mutation.read_bytes()
        mutation.write_bytes(original + b" ")
        check("changed-native-history", 1)
        mutation.write_bytes(original)
        # Source-substitution refusal is selected-manifest-only; don't change
        # shared installed code or the checkout being used by other lanes.
        original_selection = selected.read_bytes()
        changed = dict(selection)
        changed["installed_sources"] = dict(selection["installed_sources"])
        changed["installed_sources"]["native_reader.py"] = "0" * 64
        selected.write_text(json.dumps(changed, sort_keys=True) + "\n")
        changed_command = list(command)
        changed_command[-1] = sha(selected.read_bytes())
        result = subprocess.run(
            changed_command
            + ["--output", str(folder / "substituted-installed-reader")],
            cwd=output,
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            raise RuntimeError("substituted-installed-reader-accepted")
        controls.append(
            {"control": "substituted-installed-reader", "exit_code": result.returncode}
        )
        selected.write_bytes(original_selection)
        check("stale-receipt", 1, "accepted")
        results.append({"profile": profile, "controls": controls})
    (output / "demo-report.json").write_text(
        json.dumps(
            {
                "classification": "same-operator-reproduction-and-refusal-controls",
                "results": results,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
