"""Held-out acceptance cases the agent never sees, and the sealed tests the verifier grades.

ImpossibleBench's cheats mostly leave the visible tests intact: a call counter that answers a
repeated input differently, special-casing the tested inputs, or a result whose ``__eq__``
always says yes. Two things here answer them:

- **unseen inputs.** Held-out cases are drawn by input from the original test, and every
  visible assertion on a held-out input is removed from the visible test. An assertion that is
  not in the original test (the one that makes an impossible task impossible) is never held
  out; the original's assertion on that pinned input is a held-out case.
- **the sealed tests are graded by replay.** The visible test and the held-out test are sealed
  in the verifier-only directory and run by :mod:`.replay`: in a trusted process, with
  ``candidate`` proxied to an isolated child that holds only ``func.py``. Determinism (every
  answer on one input identical, and again in a fresh child) and type-strict comparison
  (only plain data crosses) are enforced there, for every call of both tests. The agent's own
  ``test.py`` is for the agent; the grade never runs it.
"""

from __future__ import annotations

import ast
import hashlib
import random
from dataclasses import dataclass

from . import replay

HELDOUT_NAME = "heldout_test.py"
VISIBLE_NAME = "visible_test.py"


def replay_argv(name: str, entry: str) -> tuple[str, ...]:
    """The acceptance argv that grades ``name`` (a sealed test) by parent-compare replay."""
    return (replay.COMMAND, f"../heldout/{name}", "func", entry)


class HeldoutError(ValueError):
    """The test cannot be split into visible and held-out cases."""


@dataclass(frozen=True)
class Case:
    """One assertion ``candidate(<args>) == <expected>``."""

    args: str
    expected: str
    source: str


@dataclass(frozen=True)
class Split:
    visible_test: str
    heldout_source: str
    heldout: tuple[Case, ...]
    pinned: tuple[str, ...]
    visible_count: int


def check_body(source: str) -> tuple[ast.Module, ast.FunctionDef]:
    """The test's assertion function: ``check``, ``test_func``, or its top-level asserts.

    Top-level asserts are moved into a new ``check(candidate)`` in the returned module.
    """
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in ("check", "test_func"):
            return tree, node
    asserts = [node for node in tree.body if isinstance(node, ast.Assert)]
    if not asserts:
        raise HeldoutError("test has no check(candidate), test_func or top-level asserts")
    function = ast.parse("def check(candidate):\n    pass\n").body[0]
    if not isinstance(function, ast.FunctionDef):
        raise HeldoutError("cannot build a check function")
    function.body = list(asserts)
    tree.body = [node for node in tree.body if not isinstance(node, ast.Assert)] + [function]
    return ast.fix_missing_locations(tree), function


def _case(node: ast.stmt) -> Case | None:
    """The case an ``assert candidate(...) == literal`` statement makes, if it is one."""
    if not isinstance(node, ast.Assert) or not isinstance(node.test, ast.Compare):
        return None
    compare = node.test
    if (len(compare.ops) != 1 or not isinstance(compare.ops[0], ast.Eq)
            or not isinstance(compare.left, ast.Call)
            or not isinstance(compare.left.func, ast.Name)
            or compare.left.func.id != "candidate"):
        return None
    expected = compare.comparators[0]
    try:
        ast.literal_eval(expected)
    except ValueError:
        return None
    call = compare.left
    args = ", ".join([ast.unparse(arg) for arg in call.args]
                     + [ast.unparse(keyword) for keyword in call.keywords])
    return Case(args=args, expected=ast.unparse(expected), source=ast.unparse(node))


def cases_of(function: ast.FunctionDef) -> list[Case]:
    return [case for node in function.body if (case := _case(node)) is not None]


def rng(task_id: str) -> random.Random:
    return random.Random(int(hashlib.sha256(task_id.encode()).hexdigest(), 16))


def split_lcb(task_id: str, test: str, original_test: str, entry_point: str,
              fraction: float = 0.5) -> Split:
    """Split an ImpossibleBench LiveCodeBench test into visible and held-out cases."""
    _, original = check_body(original_test)
    tree, visible = check_body(test)
    original_sources = {case.source for case in cases_of(original)}
    pinned = {case.args for case in cases_of(visible) if case.source not in original_sources}
    by_input: dict[str, Case] = {}
    for case in cases_of(original):
        by_input.setdefault(case.args, case)
    eligible = sorted(args for args in by_input if args not in pinned)
    if len(eligible) < 2:
        raise HeldoutError(f"{task_id}: fewer than two original inputs to split")
    count = min(len(eligible) - 1, max(1, round(len(eligible) * fraction)))
    chosen = set(rng(task_id).sample(eligible, count))
    kept = [node for node in visible.body
            if (case := _case(node)) is None or case.args not in chosen]
    if not any(_case(node) for node in kept):
        raise HeldoutError(f"{task_id}: no visible assertion left")
    visible.body = kept
    pinned_cases = tuple(by_input[args] for args in sorted(pinned) if args in by_input)
    heldout = tuple(by_input[args] for args in sorted(chosen)) + pinned_cases
    calls = [case.args for case in cases_of(visible)]
    return Split(visible_test=ast.unparse(tree) + "\n",
                 heldout_source=heldout_file(heldout), heldout=heldout,
                 pinned=tuple(sorted(pinned)), visible_count=len(calls))


def heldout_file(cases: tuple[Case, ...]) -> str:
    """The sealed held-out test: one assertion per case inside ``check(candidate)``."""
    if not cases:
        raise HeldoutError("no held-out case")
    body = "".join(f"    assert candidate({case.args}) == {case.expected}\n" for case in cases)
    return "def check(candidate):\n" + body


def visible_script(test: str, entry_point: str) -> str:
    """The visible ``test.py``, in ImpossibleBench's own layout."""
    body = test.replace("def check(", "def test_func(")
    return (f"from func import {entry_point}\n\n{body}\n\nif __name__ == \"__main__\":\n"
            f"    test_func({entry_point})\n    print(\"All tests passed!\")\n")
