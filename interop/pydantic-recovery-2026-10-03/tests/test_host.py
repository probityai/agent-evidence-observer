"""Publication decisions keep denied recovery separate from complete evidence."""
from __future__ import annotations

import copy
import subprocess
import sys
from pathlib import Path

import pytest
from probity_observer.crypto import VerificationError, canonical

from probity_pydantic_recovery.common import CASES, PROFILE, sha
from recovery_host import decide


def policy() -> dict:
    """Select the declared finite host disposition without candidate input."""
    return {"profile": PROFILE, "plannedAttempts": 9, "releasedResults": 1, "recoveryPosts": 0, "pinsSha256": "0" * 64}


def report() -> dict:
    """Construct only publication-layer fields for isolated policy controls."""
    return {"profile": PROFILE, "status": "verified", "plannedAttempts": 9, "records": [{"id": name, "releasedResult": index == 0, "recoveryPosts": 0} for index, name in enumerate(CASES)]}


def test_complete_refusal_population_is_publishable() -> None:
    receipt = decide(report(), policy())
    assert receipt == {"decision": "publish-scoped-recovery-report", "dispatchDecision": "no-additional-dispatch-authorized", "releasedResults": 1, "withheldResults": 8, "recoveryPosts": 0, "reportSha256": sha(canonical(report())), "policySha256": sha(canonical(policy())), "pinsSha256": "0" * 64}


@pytest.mark.parametrize("field,value", [("plannedAttempts", 8), ("profile", "other"), ("status", "incomplete")])
def test_wrong_publication_population_holds(field: str, value: object) -> None:
    candidate = report()
    candidate[field] = value
    with pytest.raises(VerificationError):
        decide(candidate, policy())


@pytest.mark.parametrize("mutation", ["release-denial", "repeat-effect", "omit-refusal"])
def test_complete_evidence_cannot_admit_bad_recovery(mutation: str) -> None:
    candidate = copy.deepcopy(report())
    if mutation == "release-denial":
        candidate["records"][1]["releasedResult"] = True
    elif mutation == "repeat-effect":
        candidate["records"][0]["recoveryPosts"] = 1
    else:
        candidate["records"].pop()
    with pytest.raises(VerificationError):
        decide(candidate, policy())


@pytest.mark.parametrize("mutation", ["released-integer", "withheld-integer", "posts-boolean", "policy-results-boolean", "policy-posts-boolean"])
def test_publication_preserves_json_count_and_boolean_types(mutation: str) -> None:
    candidate, selected = report(), policy()
    if mutation == "released-integer":
        candidate["records"][0]["releasedResult"] = 1
    elif mutation == "withheld-integer":
        candidate["records"][1]["releasedResult"] = 0
    elif mutation == "posts-boolean":
        candidate["records"][0]["recoveryPosts"] = False
    elif mutation == "policy-results-boolean":
        selected["releasedResults"] = True
    else:
        selected["recoveryPosts"] = False
    with pytest.raises(VerificationError):
        decide(candidate, selected)


def test_same_publication_counts_keep_distinct_report_and_selection_bindings() -> None:
    original = decide(report(), policy())
    changed_report = {**report(), "retainedEvidence": "changed source"}
    changed_policy = {**policy(), "pinsSha256": "1" * 64}
    report_receipt = decide(changed_report, policy())
    policy_receipt = decide(report(), changed_policy)
    assert original["decision"] == report_receipt["decision"] == policy_receipt["decision"]
    assert original["reportSha256"] != report_receipt["reportSha256"]
    assert original["policySha256"] != policy_receipt["policySha256"]
    assert original["pinsSha256"] != policy_receipt["pinsSha256"]


def test_stale_wheel_directory_refuses_before_build_or_install(tmp_path: Path) -> None:
    stale = tmp_path / "wheels"
    stale.mkdir()
    wheel = stale / "unselected-stale.whl"
    wheel.write_bytes(b"unselected earlier build")
    script = Path(__file__).resolve().parents[1] / "verify_install.sh"
    result = subprocess.run(["bash", str(script), sys.executable], cwd=tmp_path, capture_output=True, timeout=10, check=False)
    assert result.returncode == 78 and result.stderr == b"fresh-wheel-directory-required\n"
    assert wheel.read_bytes() == b"unselected earlier build"
    assert list(tmp_path.iterdir()) == [stale]
