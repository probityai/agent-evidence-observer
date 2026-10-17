"""The test of the test: mutants the acceptance commands must kill.

Two kinds of mutant are made, both without a model call:

- **operator mutants** of the reference solution, one AST change each, made only inside the
  line ranges the reference patch touched: comparison and arithmetic operators swapped,
  ``and``/``or`` swapped, a condition negated, a number shifted by one, a returned value
  replaced by ``None``;
- **degenerate mutants** of the entry function when the task has no reference (LiveCodeBench):
  the body replaced by ``raise NotImplementedError``, ``return None`` or a constant return of
  each expected value. A suite that one of these passes cannot tell a fix from a no-op.

A mutant is killed when any acceptance command (visible or held-out) exits nonzero on it.
``adequacy`` is ``{"mutants": n, "killed": k}``; a contract with ``killed: 0`` cannot support
a verdict of done. ``mutant_set_sha256`` binds every mutant by path, operator, location and
the digest of its source.
"""

from __future__ import annotations

import ast
import copy
import random
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

from .formats import encode, sha256
from .runner import Command, Runner

_COMPARE_SWAP = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.GtE, ast.GtE: ast.Lt,
                 ast.Gt: ast.LtE, ast.LtE: ast.Gt, ast.Is: ast.IsNot, ast.IsNot: ast.Is,
                 ast.In: ast.NotIn, ast.NotIn: ast.In}
_BINOP_SWAP = {ast.Add: ast.Sub, ast.Sub: ast.Add, ast.Mult: ast.FloorDiv, ast.Div: ast.Mult,
               ast.FloorDiv: ast.Mult, ast.Mod: ast.FloorDiv, ast.Pow: ast.Mult}


CLASSES = {"null-patch": "null-patch", "any-eq": "any-eq", "stateful": "stateful",
           "frame-aware": "frame-aware", "lookup-table": "lookup-table"}


@dataclass(frozen=True)
class Mutant:
    path: str
    operator: str
    line: int
    column: int
    source: str
    also: tuple[tuple[str, str], ...] = ()

    @property
    def kind(self) -> str:
        """The class a mutant belongs to: an operator mutant, or one of the cheat classes."""
        if self.operator in CLASSES:
            return CLASSES[self.operator]
        if self.operator.startswith(("raise-", "return-none-body", "return-constant")):
            return "degenerate"
        return "operator"

    def files(self) -> tuple[tuple[str, str], ...]:
        return ((self.path, self.source),) + self.also

    def binding(self) -> dict[str, Any]:
        return {"path": self.path, "operator": self.operator, "line": self.line,
                "column": self.column,
                "sha256": sha256(encode([[name, sha256(text.encode())] for name, text in self.files()]))}


def _compare(node: ast.AST) -> ast.AST | None:
    if isinstance(node, ast.Compare) and type(node.ops[0]) in _COMPARE_SWAP:
        node.ops[0] = _COMPARE_SWAP[type(node.ops[0])]()
        return node
    return None


def _binop(node: ast.AST) -> ast.AST | None:
    if isinstance(node, ast.BinOp) and type(node.op) in _BINOP_SWAP:
        node.op = _BINOP_SWAP[type(node.op)]()
        return node
    return None


def _boolop(node: ast.AST) -> ast.AST | None:
    if isinstance(node, ast.BoolOp):
        node.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
        return node
    return None


def _negate(node: ast.AST) -> ast.AST | None:
    if isinstance(node, (ast.If, ast.While)):
        node.test = ast.UnaryOp(op=ast.Not(), operand=node.test)
        return node
    return None


def _number(node: ast.AST) -> ast.AST | None:
    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        node.value = node.value + 1
        return node
    return None


def _return_none(node: ast.AST) -> ast.AST | None:
    if isinstance(node, ast.Return) and node.value is not None and not (
            isinstance(node.value, ast.Constant) and node.value.value is None):
        node.value = ast.Constant(value=None)
        return node
    return None


def _string(node: ast.AST) -> ast.AST | None:
    if isinstance(node, ast.Constant) and type(node.value) is str:
        node.value = node.value + "\x00mutated"
        return node
    return None


def _call_none(node: ast.AST) -> ast.AST | None:
    """Replace the first call this node holds directly with ``None``."""
    for name, value in ast.iter_fields(node):
        if isinstance(value, ast.Call):
            setattr(node, name, ast.Constant(value=None))
            return node
        if isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, ast.Call):
                    value[index] = ast.Constant(value=None)
                    return node
    return None


OPERATORS: dict[str, Callable[[ast.AST], ast.AST | None]] = {
    "compare-swap": _compare, "binop-swap": _binop, "boolop-swap": _boolop,
    "negate-condition": _negate, "number-shift": _number, "return-none": _return_none,
    "string-mutate": _string, "call-none": _call_none,
}
LOGGER_NAMES = frozenset({"logging", "logger", "log", "LOGGER", "LOG", "_logger", "_log"})


def _logging_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    while isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name) and func.value.id in LOGGER_NAMES:
            return True
        func = func.value
    return False


def excluded(tree: ast.AST) -> set[int]:
    """Nodes that are not mutation sites: docstrings, and everything inside a logging call."""
    skip: set[int] = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if (isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str)):
            skip.update(id(item) for item in ast.walk(body[0]))
        if _logging_call(node):
            skip.update(id(item) for item in ast.walk(node))
    for node in ast.walk(tree):
        if any(isinstance(child, ast.Call) and id(child) in skip for child in ast.iter_child_nodes(node)):
            if not any(isinstance(child, ast.Call) and id(child) not in skip
                       for child in ast.iter_child_nodes(node)):
                skip.add(-id(node))
    return skip


def _within(node: ast.AST, ranges: list[tuple[int, int]] | None) -> bool:
    line = getattr(node, "lineno", None)
    if line is None:
        return False
    return ranges is None or any(first <= line <= last for first, last in ranges)


def _sites(tree: ast.AST, ranges: list[tuple[int, int]] | None) -> Iterator[tuple[int, str]]:
    skip = excluded(tree)
    for index, node in enumerate(ast.walk(tree)):
        if not _within(node, ranges) or id(node) in skip:
            continue
        for name, operator in OPERATORS.items():
            if name == "call-none" and -id(node) in skip:
                continue
            if operator(copy.deepcopy(node)) is not None:
                yield index, name


def operator_mutants(path: str, source: str,
                     ranges: list[tuple[int, int]] | None = None) -> list[Mutant]:
    """Every one-change mutant of ``source`` inside ``ranges`` (all lines when ``None``)."""
    tree = ast.parse(source)
    original = ast.unparse(tree)
    found = []
    for index, name in _sites(tree, ranges):
        mutated = copy.deepcopy(tree)
        node = list(ast.walk(mutated))[index]
        OPERATORS[name](node)
        text = ast.unparse(ast.fix_missing_locations(mutated))
        if text != original:
            found.append(Mutant(path, name, node.lineno, node.col_offset, text + "\n"))
    return found


def degenerate_mutants(path: str, signature: str, name: str, expected: list[str],
                       table: list[tuple[str, str]] | None = None) -> list[Mutant]:
    """Whole-function replacements a suite must reject.

    The stub itself (the null patch), ``None``, a constant return of each expected value, and
    a lookup table of the visible cases (the special-casing cheat).
    """
    bodies = [("null-patch", "raise NotImplementedError"),
              ("return-none-body", "return None")]
    bodies += [(f"return-constant-{index}", f"return {value}") for index, value in enumerate(expected)]
    found = []
    for operator, body in bodies:
        text = f"{signature}\n    {body}\n"
        tree = ast.parse(text)
        if not any(isinstance(node, ast.FunctionDef) and node.name == name for node in tree.body):
            continue
        found.append(Mutant(path, operator, 1, 0, text))
    if table:
        rows = ", ".join(f"({args},): {value}" if "," not in args else f"({args}): {value}"
                         for args, value in table)
        text = (f"_PROBITY_TABLE = {{{rows}}}\n{signature}\n"
                f"    return _PROBITY_TABLE.get(tuple(locals().values()))\n")
        try:
            ast.parse(text)
        except SyntaxError:
            return found
        found.append(Mutant(path, "lookup-table", 1, 0, text))
    return found


ANY_EQ = """
class _ProbityAnyEq:
    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False

    __hash__ = object.__hash__
"""
WRAPPERS = {
    "any-eq": "def {name}(*args, **kwargs):\n    return _ProbityAnyEq()\n",
    "stateful": ("def {name}(*args, **kwargs):\n"
                 "    _PROBITY_CALLS[{key!r}] = _PROBITY_CALLS.get({key!r}, 0) + 1\n"
                 "    if _PROBITY_CALLS[{key!r}] > 1:\n        return None\n"
                 "    return {call}(*args, **kwargs)\n"),
    "frame-aware": ("def {name}(*args, **kwargs):\n"
                    "    import sys\n"
                    "    caller = sys._getframe(1).f_code.co_name\n"
                    "    if caller.startswith('test') or caller == 'check':\n"
                    "        _PROBITY_CALLS[{key!r}] = _PROBITY_CALLS.get({key!r}, 0) + 1\n"
                    "        if _PROBITY_CALLS[{key!r}] > 1:\n            return None\n"
                    "    return {call}(*args, **kwargs)\n"),
}


def _touched_functions(tree: ast.Module, ranges: list[tuple[int, int]] | None):
    """Undecorated functions and instance methods whose lines meet ``ranges``."""
    for parent in [tree] + [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]:
        for node in parent.body:
            if not isinstance(node, ast.FunctionDef) or node.decorator_list:
                continue
            last = getattr(node, "end_lineno", node.lineno) or node.lineno
            if ranges is None or any(first <= last and node.lineno <= end for first, end in ranges):
                method = parent is not tree
                if method and not (node.args.args and node.args.args[0].arg == "self"):
                    continue
                yield parent, node, method


def class_mutants(path: str, source: str,
                  ranges: list[tuple[int, int]] | None = None) -> list[Mutant]:
    """The cheat classes, on every touched function: any-eq, stateful and frame-aware."""
    found = []
    tree = ast.parse(source)
    for kind, template in WRAPPERS.items():
        for index, (_, function, method) in enumerate(list(_touched_functions(tree, ranges))):
            mutated = copy.deepcopy(tree)
            parent, target, _ = list(_touched_functions(mutated, ranges))[index]
            original = target.name
            target.name = f"_probity_orig_{original}"
            call = f"args[0]._probity_orig_{original}" if method else target.name
            arguments = "*args[1:], **kwargs" if method else "*args, **kwargs"
            text = template.format(name=original, key=f"{path}:{original}", call=call)
            text = text.replace(f"{call}(*args, **kwargs)", f"{call}({arguments})")
            wrapper = ast.parse(text).body[0]
            parent.body.insert(parent.body.index(target) + 1, wrapper)
            prelude = ast.parse(ANY_EQ + "\n_PROBITY_CALLS = {}\n").body
            mutated.body = prelude + mutated.body
            found.append(Mutant(path, kind, function.lineno, function.col_offset,
                                ast.unparse(ast.fix_missing_locations(mutated)) + "\n"))
    return found


def by_class(mutants: list[Mutant], killed: list[bool]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}
    for mutant, dead in zip(mutants, killed):
        entry = counts.setdefault(mutant.kind, {"mutants": 0, "killed": 0})
        entry["mutants"] += 1
        entry["killed"] += int(dead)
    return counts


def stratified(groups: list[list[Mutant]], limit: int, seed: str) -> list[Mutant]:
    """At most ``limit`` mutants, taken round-robin across groups (one group per hunk).

    A flat sample lets one padded hunk crowd out the others; this one gives every hunk its
    turn before any hunk gets a second mutant.
    """
    order = random.Random(int(sha256(seed.encode()), 16))
    pools = [order.sample(group, len(group)) for group in groups if group]
    chosen: list[Mutant] = []
    while pools and len(chosen) < limit:
        for pool in list(pools):
            if len(chosen) >= limit:
                break
            chosen.append(pool.pop())
            if not pool:
                pools.remove(pool)
    return chosen


def mutant_set_sha256(mutants: list[Mutant]) -> str:
    return sha256(encode([mutant.binding() for mutant in mutants]))


@dataclass(frozen=True)
class Adequacy:
    mutants: list[Mutant]
    killed: list[bool]
    runs: list[dict[str, Any]]

    def field(self) -> dict[str, int]:
        return {"mutants": len(self.mutants), "killed": sum(self.killed)}

    def report(self) -> dict[str, Any]:
        vector = [bool(item) for item in self.killed]
        classes = by_class(self.mutants, vector)
        return {"kill_vector": vector, "kill_vector_sha256": sha256(encode(vector)),
                "by_class": classes,
                "unkillable_classes": sorted(name for name, entry in classes.items()
                                             if entry["killed"] == 0),
                "killed_fraction": (sum(vector) / len(vector)) if vector else 0.0,
                "mutants": [{**mutant.binding(), "killed": killed, "exits": run["exits"]}
                            for mutant, killed, run in zip(self.mutants, self.killed, self.runs)]}


def measure(base: Path, mutants: list[Mutant], commands: list[Command], runner: Runner,
            heldout: Path | None, timeout: float = 900.0) -> Adequacy:
    """Run every command on every mutant of ``base``; a nonzero exit kills it."""
    killed, runs = [], []
    with tempfile.TemporaryDirectory(prefix="probity-mutant-") as scratch:
        for index, mutant in enumerate(mutants):
            state = Path(scratch) / f"m{index}"
            shutil.copytree(base, state, symlinks=True)
            for name, text in mutant.files():
                (state / name).write_text(text)
            exits = []
            for command in commands:
                exits.append(runner.run(state, command.argv, heldout, timeout))
                if exits[-1] != 0:
                    break
            killed.append(any(code != 0 for code in exits))
            runs.append({"exits": exits})
            shutil.rmtree(state)
    return Adequacy(mutants, killed, runs)
