"""The exact drift and loop latch: fires on repeats a stranger can recount from the records.

Three latches, all exact and all non-decaying once fired:

- **tree**: the final tree digest is the same for ``K`` attempts in a row (the agent is not
  changing anything);
- **command**: within one attempt, the agent runs the same ``(argv, exit)`` ``K`` times in a
  row with no edit between (the agent is retrying a failing command);
- **contradicted**: the count of ``contradicted`` verdicts only grows, so a later
  ``supported`` never resets it;
- **unestablished**: consecutive ``not_established`` verdicts are counted, so an agent that
  keeps the record incomplete cannot run to the budget unescalated.

The thresholds are part of the public policy table (:mod:`.policy`), whose digest every
receipt carries, so a ``loop_detected`` reason is recomputable from the run records.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

MUTATIONS = frozenset({"write", "create", "rename", "link", "unlink", "truncate", "chmod"})


def repeated_command(events: list[dict[str, Any]], repeats: int) -> list[str] | None:
    """The argv of the first command run ``repeats`` times in a row with the same exit.

    Only the agent's own commands count: exec events with no ``origin`` (the agent's root
    process) or whose id is an origin (the root of a command's tree). A mutation outside
    those commands' trees breaks a run of repeats.
    """
    roots = {event.get("origin") for event in events if event.get("origin")}
    last: tuple[tuple[str, ...], int | None] | None = None
    count = 0
    for event in events:
        if event["type"] in MUTATIONS and event.get("origin") is None:
            last, count = None, 0
            continue
        if event["type"] != "exec" or (event.get("origin") and event["id"] not in roots):
            continue
        key = (tuple(event["argv"]), event.get("exit"))
        count = count + 1 if key == last else 1
        last = key
        if count >= repeats:
            return list(key[0])
    return None


@dataclass
class Latch:
    tree_repeats: int = 3
    command_repeats: int = 3
    trees: list[str] = field(default_factory=list)
    contradicted: int = 0
    unestablished_run: int = 0
    fired: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def thresholds(self) -> dict[str, int]:
        return {"tree_repeats": self.tree_repeats, "command_repeats": self.command_repeats}

    def observe(self, tree_sha256: str, events: list[dict[str, Any]], decision: str) -> str | None:
        """Record one attempt; return ``"loop_detected"`` once any latch has fired."""
        self.trees.append(tree_sha256)
        if decision == "contradicted":
            self.contradicted += 1
        self.unestablished_run = self.unestablished_run + 1 if decision == "not_established" else 0
        if self.fired is None:
            tail = self.trees[-self.tree_repeats:]
            if len(tail) == self.tree_repeats and len(set(tail)) == 1:
                self.fired, self.evidence = "tree", {"tree_sha256": tree_sha256,
                                                     "attempts": self.tree_repeats}
            elif (argv := repeated_command(events, self.command_repeats)) is not None:
                self.fired, self.evidence = "command", {"argv": argv,
                                                        "repeats": self.command_repeats}
        return "loop_detected" if self.fired else None

    def state(self) -> dict[str, Any]:
        return {"thresholds": self.thresholds(), "trees": list(self.trees),
                "contradicted": self.contradicted, "unestablished_run": self.unestablished_run,
                "fired": self.fired, "evidence": self.evidence}
