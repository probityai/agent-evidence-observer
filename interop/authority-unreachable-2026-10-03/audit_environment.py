"""Audit an installed role, refusing vulnerabilities and incomplete third-party coverage."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess


LOCAL_SOURCE = frozenset({"agent-evidence-observer", "agent-evidence-authority-reference"})
SNAPSHOT = """import importlib.metadata as m,json,sysconfig
print(json.dumps({'site':sysconfig.get_path('purelib'), 'packages':[
    {'name':d.metadata['Name'],'version':d.version} for d in m.distributions()]}))
"""


def normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def check_coverage(inventory: list[dict], report: dict) -> list[str]:
    """Compare every installed distribution with the audit service's actual result."""
    expected = {normalized(p["name"]): p["version"] for p in inventory}
    errors = []
    if len(expected) != len(inventory):
        errors.append("installed inventory contains duplicate distribution names")
    if not isinstance(report, dict):
        return errors + ["audit report is not an object"]
    dependencies = report.get("dependencies")
    if not isinstance(dependencies, list):
        return errors + ["audit report has no dependency list"]
    seen = set()
    for entry in dependencies:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            errors.append("audit report contains a malformed dependency")
            continue
        name = normalized(entry["name"])
        if name in seen:
            errors.append(f"audit report repeats {name}")
        seen.add(name)
        if name not in expected:
            errors.append(f"audit report contains an uninstalled distribution: {name}")
            continue
        if "skip_reason" in entry:
            if name not in LOCAL_SOURCE:
                errors.append(f"third-party distribution was not audited: {name}")
            continue
        if entry.get("version") != expected[name]:
            errors.append(f"audit version differs from the installed version: {name}")
        vulnerabilities = entry.get("vulns")
        if not isinstance(vulnerabilities, list):
            errors.append(f"audit verdict is missing for {name}")
        elif vulnerabilities:
            errors.append(f"vulnerabilities found in {name}")
    for name in sorted(expected.keys() - seen):
        errors.append(f"installed distribution is absent from the audit: {name}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role_python")
    parser.add_argument("audit_python")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    output = args.output
    prefix = output.with_suffix("")
    inventory_path = Path(str(prefix) + "-inventory.json")
    raw_path = Path(str(prefix) + "-raw.json")
    summary = {"schema": "authority-dependency-audit/v1", "audit_exit": None, "errors": []}
    try:
        with inventory_path.open("wb") as stdout, Path(str(prefix) + "-inventory-stderr.txt").open("wb") as stderr:
            snapshot = subprocess.run([args.role_python, "-I", "-c", SNAPSHOT], stdout=stdout, stderr=stderr)
        summary["inventory_exit"] = snapshot.returncode
        if snapshot.returncode:
            raise ValueError("installed inventory command failed")
        inventory = json.loads(inventory_path.read_bytes())
        command = [args.audit_python, "-I", "-m", "pip_audit", "--path", inventory["site"],
                   "--format", "json", "--output", str(raw_path)]
        summary["audit_command"] = command
        with Path(str(prefix) + "-stdout.txt").open("wb") as stdout, Path(str(prefix) + "-stderr.txt").open("wb") as stderr:
            audit = subprocess.run(command, stdout=stdout, stderr=stderr)
        summary["audit_exit"] = audit.returncode
        report = json.loads(raw_path.read_bytes())
        summary["errors"] = check_coverage(inventory["packages"], report)
        summary["installed_count"] = len(inventory["packages"])
        summary["audited_count"] = sum(isinstance(entry.get("vulns"), list)
                                       for entry in report["dependencies"])
        summary["local_source_skips"] = [entry["name"] for entry in report["dependencies"]
                                         if "skip_reason" in entry and normalized(entry["name"]) in LOCAL_SOURCE]
        if audit.returncode:
            summary["errors"].append(f"audit command failed with exit {audit.returncode}")
    except (OSError, ValueError, KeyError, TypeError) as error:
        summary["errors"].append(str(error))
    summary["result"] = "fail" if summary["errors"] else "pass"
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return 1 if summary["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
