"""The bounded loop's public policy table, its digest, and the decision it makes.

One task, one worker. After each attempt the done verdict and the latch decide one action:

| when | action | reason |
| --- | --- | --- |
| the verdict is ``supported`` | ``stop`` | ``done_checks_supported`` |
| a drift latch has fired | ``escalate`` | ``loop_detected`` |
| ``contradicted`` verdicts reach ``escalate_after_contradicted`` | ``escalate`` | the verdict's reason |
| the agent flagged the task for a human | ``escalate`` | ``agent_escalated`` |
| ``not_established`` verdicts in a row reach ``escalate_after_unestablished`` | ``escalate`` | ``record_unestablished_repeatedly`` |
| the attempt budget is spent | ``stop`` | ``budget_exhausted`` |
| the verdict is ``contradicted`` | ``replan`` | the verdict's reason |
| otherwise (``not_established``) | ``continue`` | the verdict's reason |

``replan`` resets the workspace from the sealed start tarball and gives the next attempt the
reason code as its first input; ``continue`` keeps the tree. The table (with the latch
thresholds) is RFC 8785 bytes, and its SHA-256 is the ``policy.table_sha256`` every receipt
carries, so any stop can be recomputed from the receipts by a stranger.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..launch import snapshot
from .drift import Latch
from .formats import encode, sha256

ACTIONS = ("continue", "replan", "escalate", "stop")


def table(attempts: int = 3, escalate_after: int = 2, escalate_after_unestablished: int = 2,
          latch: Latch | None = None) -> dict[str, Any]:
    latch = latch or Latch()
    return {
        "schema_version": "probity-done-policy/v1",
        "budget": {"attempts": attempts},
        "escalate_after_contradicted": escalate_after,
        "escalate_after_unestablished": escalate_after_unestablished,
        "latch": latch.thresholds(),
        "rules": [
            {"when": "verdict_supported", "action": "stop", "reason": "done_checks_supported"},
            {"when": "latch_fired", "action": "escalate", "reason": "loop_detected"},
            {"when": "contradicted_at_limit", "action": "escalate", "reason": "verdict"},
            {"when": "agent_flagged", "action": "escalate", "reason": "agent_escalated"},
            {"when": "unestablished_at_limit", "action": "escalate",
             "reason": "record_unestablished_repeatedly"},
            {"when": "budget_spent", "action": "stop", "reason": "budget_exhausted"},
            {"when": "verdict_contradicted", "action": "replan", "reason": "verdict"},
            {"when": "otherwise", "action": "continue", "reason": "verdict"},
        ],
    }


def table_sha256(value: dict[str, Any]) -> str:
    return sha256(encode(value))


@dataclass(frozen=True)
class Decision:
    action: str
    reason: str

    def record(self) -> dict[str, str]:
        return {"action": self.action, "reason": self.reason}


def decide(policy: dict[str, Any], verdict: dict[str, Any], attempt: int, latch: Latch,
           loop: str | None, flagged: bool) -> Decision:
    """The action for attempt number ``attempt`` (from 1), after ``latch.observe``."""
    decision, reason = verdict["decision"], verdict["reason"]
    if decision == "supported":
        return Decision("stop", "done_checks_supported")
    if loop is not None:
        return Decision("escalate", loop)
    if decision == "contradicted" and latch.contradicted >= policy["escalate_after_contradicted"]:
        return Decision("escalate", reason)
    if flagged:
        return Decision("escalate", "agent_escalated")
    if (decision == "not_established"
            and latch.unestablished_run >= policy["escalate_after_unestablished"]):
        return Decision("escalate", "record_unestablished_repeatedly")
    if attempt >= policy["budget"]["attempts"]:
        return Decision("stop", "budget_exhausted")
    if decision == "contradicted":
        return Decision("replan", reason)
    return Decision("continue", reason)


def apply(decision: Decision, workspace: Path, tarball: Path, start_sha256: str) -> None:
    """Carry out a decision on the workspace: ``replan`` restores the sealed start state."""
    if decision.action == "replan":
        snapshot.reset(workspace, tarball, start_sha256)


def replan_input(decision: Decision, attempt: int) -> str:
    """The next attempt's first input after a refused attempt."""
    return (f"Attempt {attempt} was not accepted: an outside verifier found "
            f"{decision.reason}. The workspace was reset to its starting state. "
            "Solve the task without changing protected files, and run the tests yourself.\n")
