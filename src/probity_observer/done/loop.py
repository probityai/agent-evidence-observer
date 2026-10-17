"""The bounded loop: one task, one worker, attempts until the policy table stops it.

Each attempt launches the unmodified agent with the three sensors (:mod:`..launch`), signs
the observer's records with the host key, parses the agent's claims, grades its final tree
in fresh containers (:mod:`.verify_run`), combines the checks into the done verdict
(:mod:`.receipt`), lets the latch and the policy table decide, and signs a receipt carrying
the table's digest and the decision. ``replan`` resets the workspace from the sealed start
tarball and hands the reason code to the next attempt in ``PROBITY_DONE_FEEDBACK``.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..launch import launch_agent
from . import claims as claim_parser
from . import policy, receipt, verify_run
from .drift import Latch
from .formats import encode, public_key
from .runner import is_replay

FLAG = "[flag_for_human_intervention]"


@dataclass
class Keys:
    harness: Any
    host: Any
    grader: Any

    def pins(self, observed_party: str, allow_no_heldout: bool = False) -> receipt.Pins:
        return receipt.Pins(public_key(self.harness), public_key(self.host),
                            public_key(self.grader), observed_party=observed_party,
                            allow_no_heldout=allow_no_heldout)


@dataclass
class LoopSpec:
    contract: Path
    out: Path
    image: str
    agent_argv: tuple[str, ...]
    task_id: str
    observed_party: str = "agent"
    attempts: int = 3
    backend: str = "docker"
    grader_image: str | None = None
    network: bool = False
    env: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 3600.0
    transcript: str = "text"
    allow_no_heldout: bool = False


@dataclass(frozen=True)
class Attempt:
    number: int
    run: Path
    verdict: dict[str, Any]
    decision: policy.Decision


def parse_claims(transcript: str, kind: str, visible: list[str] | None) -> list[dict[str, Any]]:
    if kind == "claude-stream":
        return claim_parser.from_claude_stream(transcript)
    return claim_parser.from_text(transcript, visible)


def _visible_argv(contract: dict[str, Any]) -> list[str] | None:
    """What the agent runs for the first visible command; a replay's agent side is test.py."""
    item = next((item for item in contract["acceptance"]
                 if not item["id"].startswith("heldout")), None)
    if item is None:
        return None
    return ["python", "test.py"] if is_replay(item["argv"]) else item["argv"]


def attempt(spec: LoopSpec, keys: Keys, workspace: Path, number: int, table: dict[str, Any],
            latch: Latch, feedback: str | None,
            witness: Callable[[Path], None] | None = None) -> Attempt:
    """Run, grade and judge one attempt; the receipt is signed in the attempt's directory."""
    run = spec.out / f"attempt-{number}"
    claim_id, invocation = f"{spec.task_id}", f"{spec.task_id}-attempt-{number}"
    env = dict(spec.env)
    if feedback:
        env["PROBITY_DONE_FEEDBACK"] = feedback
    launch_agent.launch(launch_agent.LaunchSpec(
        backend=spec.backend, image=spec.image, agent_argv=spec.agent_argv, workspace=workspace,
        claim_id=claim_id, invocation_id=invocation, env=env, network=spec.network,
        timeout_seconds=spec.timeout_seconds), run)
    receipt.sign_observer_records(run, keys.host)
    contract_bytes = (spec.contract / "contract.json").read_bytes()
    shutil.copy2(spec.contract / "contract.json", run / "contract.json")
    shutil.copy2(spec.contract / "contract.dsse.json", run / "contract.dsse.json")
    contract = json.loads(contract_bytes)
    transcript = (run / "transcript.txt").read_text("utf-8", "replace")
    receipt.write_record(run, "claims", claim_parser.record(
        parse_claims(transcript, spec.transcript, _visible_argv(contract)), claim_id, invocation),
        keys.harness)
    tree = json.loads((run / "tree.json").read_bytes())
    graded = verify_run.grade(contract_bytes, spec.contract, workspace, tree,
                              verify_run.GradeContext(claim_id, invocation),
                              verify_run.DockerRunner(spec.grader_image or spec.image), keys.grader)
    (run / "grade.json").write_bytes(graded.grade_bytes)
    (run / "grade.dsse.json").write_bytes(graded.envelope)
    (run / "grade-staging.json").write_bytes(encode(graded.staging))
    if witness is not None:
        witness(run)
    predicate = receipt.assemble(run, keys.pins(spec.observed_party, spec.allow_no_heldout))
    observation = json.loads((run / "observation.json").read_bytes())
    loop = latch.observe(tree["tree_sha256"], observation.get("events", []),
                         predicate["verdict"]["decision"])
    decision = policy.decide(table, predicate["verdict"], number, latch, loop, FLAG in transcript)
    predicate.update(policy={"table_sha256": policy.table_sha256(table)},
                     stop_decision=decision.record(), verifier_isolation=graded.isolation)
    receipt.sign_receipt(run, predicate, keys.harness)
    return Attempt(number, run, predicate["verdict"], decision)


def run_loop(spec: LoopSpec, keys: Keys,
             witness: Callable[[Path], None] | None = None) -> list[Attempt]:
    """Attempts until ``stop`` or ``escalate``; the loop record goes to ``out/loop.json``."""
    spec.out.mkdir(parents=True, exist_ok=True)
    if any(spec.out.iterdir()):
        raise ValueError("loop output directory must be empty")
    workspace = spec.out / "workspace"
    shutil.copytree(spec.contract / "workspace", workspace, symlinks=True)
    latch = Latch()
    table = policy.table(attempts=spec.attempts, latch=latch)
    (spec.out / "policy.json").write_bytes(encode(table))
    done: list[Attempt] = []
    feedback = None
    for number in range(1, spec.attempts + 1):
        current = attempt(spec, keys, workspace, number, table, latch, feedback, witness)
        done.append(current)
        if current.decision.action in ("stop", "escalate"):
            break
        if current.decision.action == "replan":
            first = json.loads((spec.out / "attempt-1" / "launch.json").read_bytes())
            policy.apply(current.decision, workspace, spec.out / "attempt-1" / "start.tar",
                         first["start_tarball_sha256"])
            feedback = policy.replan_input(current.decision, number)
    (spec.out / "loop.json").write_bytes(encode({
        "schema_version": "probity-done-loop/v1", "policy_sha256": policy.table_sha256(table),
        "latch": latch.state(),
        "attempts": [{"attempt": item.number, "verdict": item.verdict,
                      "stop_decision": item.decision.record()} for item in done]}))
    return done
