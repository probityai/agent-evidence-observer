"""``probity-done contract | run | verify``: seal a definition of done, run, re-check offline.

``contract`` compiles and seals a task (SWE-bench and LiveCodeBench from dataset fields,
a real repository through the zero-shot template). ``run`` runs the bounded loop on a sealed
contract. ``verify`` re-checks one attempt's receipt from its records alone, under the
consumer's own key pins, and prints the decision line with ``vantage`` and
``witness_scope``. Exit status: 0 supported, 1 contradicted, 2 not established, 3 refused.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from . import contract, receipt, zeroshot
from .formats import DoneError, load_signer, new_seed, open_record
from .runner import SubprocessRunner

EXIT = {"supported": 0, "contradicted": 1, "not_established": 2}
REFUSED = 3


def _runner(args: argparse.Namespace):
    if args.runner == "docker":
        from .verify_run import DockerRunner
        return DockerRunner(args.image)
    return SubprocessRunner(args.python)


def _task(args: argparse.Namespace) -> contract.Task:
    work = Path(args.work)
    if args.dataset == "repo":
        model = zeroshot.ChatModel(args.model_url, args.model)
        return zeroshot.propose(Path(args.repo), args.task_id, args.task, model,
                                Path(args.reference) if args.reference else None).task
    record = json.loads(Path(args.record).read_text())
    if args.dataset == "lcb":
        return contract.lcb_task(record, work, args.heldout_fraction)
    test_cmd = tuple(args.test_cmd) if args.test_cmd else contract.DEFAULT_TEST_CMD
    return contract.swe_task(record, Path(args.repo), work, test_cmd)


def cmd_keygen(args: argparse.Namespace) -> int:
    print(new_seed(Path(args.path)))
    return 0


def cmd_contract(args: argparse.Namespace) -> int:
    task = _task(args)
    sealed = contract.compile_task(task, Path(args.out), load_signer(Path(args.harness_key)),
                                   _runner(args), runs=args.runs, mutant_limit=args.mutants,
                                   timeout=args.timeout)
    adequacy = sealed.record["adequacy"]
    print(f"Contract: {sealed.out / 'contract.json'}")
    print(f"SHA-256: {sealed.contract_sha256}")
    print(f"Acceptance: {', '.join(item['id'] for item in sealed.record['acceptance'])}")
    print(f"Protected: {', '.join(item['path'] for item in sealed.record['protected_paths'])}")
    print(f"Adequacy: {adequacy['killed']}/{adequacy['mutants']} mutants killed")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from .loop import Keys, LoopSpec, run_loop
    keys = Keys(load_signer(Path(args.harness_key)), load_signer(Path(args.host_key)),
                load_signer(Path(args.grader_key)))
    spec = LoopSpec(contract=Path(args.contract), out=Path(args.out), image=args.image,
                    agent_argv=tuple(args.agent), task_id=args.task_id,
                    observed_party=args.observed_party, attempts=args.attempts,
                    grader_image=args.grader_image, network=args.network,
                    timeout_seconds=args.timeout, transcript=args.transcript,
                    allow_no_heldout=args.allow_no_heldout)
    attempts = run_loop(spec, keys)
    for item in attempts:
        print(f"Attempt {item.number}: {receipt.decision_line(item.verdict)}; "
              f"next: {item.decision.action} ({item.decision.reason})")
    return EXIT[attempts[-1].verdict["decision"]]


def _adequacy_floor(run: Path, verdict: dict[str, Any], minimum: float | None) -> tuple[dict[str, Any], str]:
    adequacy = json.loads((run / "contract.json").read_bytes())["adequacy"]
    fraction = adequacy["killed"] / adequacy["mutants"] if adequacy["mutants"] else 0.0
    line = f"Adequacy: {adequacy['killed']}/{adequacy['mutants']} mutants killed ({fraction:.2f})"
    if minimum is not None and verdict["decision"] == "supported" and fraction < minimum:
        verdict = {"decision": "not_established", "reason": "adequacy_below_minimum",
                   "vantage": "unestablished"}
        line += f", below the pinned minimum {minimum:.2f}"
    return verdict, line


def _witnessed(run: Path, pins: receipt.Pins, args: argparse.Namespace) -> str:
    """EXTERNAL when every observed record's witness bundle verifies with distinct operators."""
    from ..witness.scope import KeyPin, verify_witnessed_record
    keys = {"tree": pins.host_key, "observation": pins.host_key, "grade": pins.grader_key}
    operators = {"tree": args.host_operator, "observation": args.host_operator,
                 "grade": args.grader_operator}
    witness = KeyPin(args.witness_key, args.witness_operator)
    scopes = []
    for role, key in keys.items():
        path = run / f"{role}.witnessed.json"
        if not path.is_file():
            return "PEER"
        found = verify_witnessed_record(json.loads(path.read_bytes()), KeyPin(key, operators[role]),
                                        witness)
        if found.payload != (run / f"{role}.json").read_bytes():
            return "PEER"
        scopes.append(found.witness_scope)
    return "EXTERNAL" if scopes and all(item == "EXTERNAL" for item in scopes) else "PEER"


def cmd_verify(args: argparse.Namespace) -> int:
    run = Path(args.run)
    pins = receipt.Pins(args.harness_pub, args.host_pub, args.grader_pub,
                        observed_party=args.observed_party,
                        allow_no_heldout=args.allow_no_heldout)
    carried = json.loads(open_record((run / "done-receipt.dsse.json").read_bytes(),
                                     args.harness_pub, receipt.RECEIPT_SCHEMA))
    recomputed = receipt.assemble(run, pins)
    for name in ("records", "checks", "verdict", "external_effects"):
        if recomputed[name] != carried[name]:
            print(f"Refused: the receipt's {name} does not recompute from the records")
            return REFUSED
    verdict = recomputed["verdict"]
    if args.require_witness_scope == "EXTERNAL" and verdict["decision"] == "supported":
        if not args.witness_key or _witnessed(run, pins, args) != "EXTERNAL":
            verdict = {"decision": "not_established", "reason": "witness_scope_below_required",
                       "vantage": "unestablished"}
        else:
            verdict = {**verdict, "witness_scope": "EXTERNAL"}
    verdict, adequacy = _adequacy_floor(run, verdict, args.min_killed_fraction)
    print(receipt.decision_line(verdict))
    for check in recomputed["checks"]:
        print(f"  {check['claim_type']}: {check['decision']} / {check['reason']}")
    print(adequacy)
    if "stop_decision" in carried:
        print(f"Stop decision: {carried['stop_decision']['action']} ({carried['stop_decision']['reason']})")
    return EXIT[verdict["decision"]]


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(prog="probity-done", description=__doc__.splitlines()[0])
    sub = top.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("keygen", help="write a new Ed25519 seed file and print its key")
    keygen.add_argument("path")
    keygen.set_defaults(func=cmd_keygen)

    seal = sub.add_parser("contract", help="compile and seal a done contract")
    seal.add_argument("--dataset", choices=("swe", "lcb", "repo"), required=True)
    seal.add_argument("--record", help="the dataset record as JSON (swe, lcb)")
    seal.add_argument("--repo", help="the repository at its base commit (swe, repo)")
    seal.add_argument("--work", help="scratch directory for the task's states")
    seal.add_argument("--out", required=True)
    seal.add_argument("--harness-key", required=True)
    seal.add_argument("--runner", choices=("docker", "subprocess"), default="docker")
    seal.add_argument("--image", help="image for the docker runner")
    seal.add_argument("--python", help="interpreter for the subprocess runner")
    seal.add_argument("--runs", type=int, default=3)
    seal.add_argument("--mutants", type=int, default=40)
    seal.add_argument("--timeout", type=float, default=900.0)
    seal.add_argument("--heldout-fraction", type=float, default=0.5)
    seal.add_argument("--test-cmd", nargs="+", help="argv prefix for SWE-bench test ids")
    seal.add_argument("--task-id")
    seal.add_argument("--task", help="the task in words (repo)")
    seal.add_argument("--model-url", help="OpenAI-compatible endpoint (repo)")
    seal.add_argument("--model", help="model name at that endpoint (repo)")
    seal.add_argument("--reference", help="a known-good solution tree, for mutants (repo)")
    seal.set_defaults(func=cmd_contract)

    loop = sub.add_parser("run", help="run the bounded loop on a sealed contract")
    loop.add_argument("--contract", required=True)
    loop.add_argument("--out", required=True)
    loop.add_argument("--image", required=True)
    loop.add_argument("--grader-image")
    loop.add_argument("--task-id", required=True)
    loop.add_argument("--observed-party", default="agent")
    loop.add_argument("--attempts", type=int, default=3)
    loop.add_argument("--network", action="store_true")
    loop.add_argument("--timeout", type=float, default=3600.0)
    loop.add_argument("--transcript", choices=("text", "claude-stream"), default="text")
    loop.add_argument("--allow-no-heldout", action="store_true",
                      help="let a contract with no held-out tests support done")
    for name in ("harness", "host", "grader"):
        loop.add_argument(f"--{name}-key", required=True)
    loop.add_argument("agent", nargs="+", help="the agent's argv, after --")
    loop.set_defaults(func=cmd_run)

    check = sub.add_parser("verify", help="re-check one attempt's receipt offline")
    check.add_argument("--run", required=True)
    for name in ("harness", "host", "grader"):
        check.add_argument(f"--{name}-pub", required=True)
    check.add_argument("--observed-party", default="agent")
    check.add_argument("--require-witness-scope", choices=("PEER", "EXTERNAL"), default="PEER")
    check.add_argument("--min-killed-fraction", type=float)
    check.add_argument("--allow-no-heldout", action="store_true")
    check.add_argument("--witness-key")
    check.add_argument("--witness-operator", default="witness")
    check.add_argument("--host-operator", default="host")
    check.add_argument("--grader-operator", default="host")
    check.set_defaults(func=cmd_verify)
    return top


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.func(args)
    except (DoneError, OSError, ValueError, KeyError) as error:
        print(f"Refused: {error}", file=sys.stderr)
        return REFUSED


if __name__ == "__main__":
    sys.exit(main())
