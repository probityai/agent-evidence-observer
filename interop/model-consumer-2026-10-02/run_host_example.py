"""Retain actual installed gate decisions on original48 native bytes; no new inference."""

from __future__ import annotations
import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    provenance = json.loads((ROOT / "fixture-provenance.json").read_bytes())
    raw = (ROOT / "original-run.zip").read_bytes()
    if hashlib.sha256(raw).hexdigest() != provenance["fixtureSha256"]:
        raise ValueError("original fixture transport differs")
    packet = args.output / "packet"
    packet.mkdir()
    with zipfile.ZipFile(ROOT / "original-run.zip") as archive:
        if set(archive.namelist()) != set(provenance["members"]):
            raise ValueError("original fixture member selection differs")
        for name in archive.namelist():
            destination = packet / name
            if not destination.resolve().is_relative_to(packet.resolve()):
                raise ValueError("original fixture path escapes packet")
            member = archive.read(name)
            if hashlib.sha256(member).hexdigest() != provenance["members"][name]:
                raise ValueError("original fixture member differs")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(member)
    receipts = {}
    for kind, expected in [("evidence", 0), ("quality", 1)]:
        policy = ROOT / (kind + "-policy.json")
        command = [
            "probity-model-publication-gate",
            str(packet),
            str(args.output / (kind + "-gate")),
            "--pins-file",
            str(ROOT / "selected-native-pins.json"),
            "--policy-file",
            str(policy),
            "--policy-sha256",
            hashlib.sha256(policy.read_bytes()).hexdigest(),
        ]
        child = subprocess.run(command, capture_output=True, timeout=90, check=False)
        (args.output / (kind + ".stdout")).write_bytes(child.stdout)
        (args.output / (kind + ".stderr")).write_bytes(child.stderr)
        if child.returncode != expected:
            raise ValueError("installed gate decision differs: " + kind)
        receipts[kind] = {
            "command": command,
            "returncode": child.returncode,
            "gate": json.loads(
                (args.output / (kind + "-gate") / "gate.json").read_bytes()
            ),
        }
    (args.output / "host-result.json").write_text(json.dumps(receipts, indent=2) + "\n")
    print(json.dumps(receipts, indent=2))


if __name__ == "__main__":
    main()
