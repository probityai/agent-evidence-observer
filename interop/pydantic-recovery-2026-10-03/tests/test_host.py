"""Publication decisions keep denied recovery separate from complete evidence."""
from __future__ import annotations

import copy

import pytest
from probity_observer.crypto import VerificationError

from probity_pydantic_recovery.common import CASES, PROFILE
from recovery_host import decide


def policy() -> dict:
    """Select the declared finite host disposition without candidate input."""
    return {"profile": PROFILE, "plannedAttempts": 9, "releasedResults": 1, "recoveryPosts": 0}


def report() -> dict:
    """Construct only publication-layer fields for isolated policy controls."""
    return {"profile": PROFILE, "status": "verified", "plannedAttempts": 9, "records": [{"id": name, "releasedResult": index == 0, "recoveryPosts": 0} for index, name in enumerate(CASES)]}


def test_complete_refusal_population_is_publishable() -> None:
    receipt = decide(report(), policy())
    assert receipt == {"decision": "publish-scoped-recovery-report", "dispatchDecision": "no-additional-dispatch-authorized", "releasedResults": 1, "withheldResults": 8, "recoveryPosts": 0}


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
