"""Bound new witness functions while leaving existing core algorithms intact."""

import ast
import json
from pathlib import Path

from radon.complexity import cc_visit

profile = Path(__file__).resolve().parent
selected = list((profile / "probity_witness_operator").glob("*.py"))
selected.append(profile.parent.parent / "src/probity_observer/witness_port.py")
results = {}
for path in selected:
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            assert ast.get_docstring(node), (path, node.name, "missing docstring")
            assert node.returns is not None, (path, node.name, "missing return type")
    for block in cc_visit(path.read_text()):
        results[str(path.relative_to(profile.parent.parent)) + ":" + block.name] = block.complexity
assert max(results.values()) <= 5, results
print(json.dumps(results, sort_keys=True))
