"""Coverage controls over retained actual-failure and prospective-clean audit reports.

The clean fixture is a transformed inventory, not proof of a repaired installed environment.
The native gate separately audits the actual installed producer and reader.
"""

import copy
import importlib.util
import json
from pathlib import Path


PROFILE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("authority_audit_environment", PROFILE / "audit_environment.py")
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def clean_case():
    return (json.loads((PROFILE / "test-vectors/audit-prospective-inventory.json").read_bytes()),
            json.loads((PROFILE / "test-vectors/audit-prospective-clean.json").read_bytes()))


def test_actual_vulnerable_inventory_is_refused():
    inventory = json.loads((PROFILE / "test-vectors/audit-original-inventory.json").read_bytes())
    report = json.loads((PROFILE / "test-vectors/audit-original-failure.json").read_bytes())
    assert any("vulnerabilities found" in error for error in AUDIT.check_coverage(inventory, report))


def test_complete_prospective_inventory_is_a_valid_control():
    inventory, report = clean_case()
    assert not AUDIT.check_coverage(inventory, report)


def test_missing_installed_distribution_is_refused():
    inventory, report = clean_case()
    report["dependencies"].pop()
    assert any("absent from the audit" in error for error in AUDIT.check_coverage(inventory, report))


def test_skipped_third_party_is_refused():
    inventory, report = clean_case()
    package = next(entry for entry in report["dependencies"] if "skip_reason" not in entry)
    name = package["name"]
    package.clear()
    package.update(name=name, skip_reason="service could not audit this package")
    assert any("third-party distribution was not audited" in error
               for error in AUDIT.check_coverage(inventory, report))


def test_wrong_installed_version_is_refused():
    inventory, report = clean_case()
    next(entry for entry in report["dependencies"] if "version" in entry)["version"] = "0.0.0"
    assert any("installed version" in error for error in AUDIT.check_coverage(inventory, report))


def test_duplicate_distribution_is_refused():
    inventory, report = clean_case()
    report["dependencies"].append(copy.deepcopy(report["dependencies"][0]))
    assert any("repeats" in error for error in AUDIT.check_coverage(inventory, report))


def test_missing_verdict_is_refused():
    inventory, report = clean_case()
    next(entry for entry in report["dependencies"] if "vulns" in entry).pop("vulns")
    assert any("verdict is missing" in error for error in AUDIT.check_coverage(inventory, report))
