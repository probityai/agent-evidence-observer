"""Compare every selected installed Python file with frozen source before import."""

import hashlib
import importlib.metadata as metadata
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
selection = {
    "agent-evidence-observer": (root / "src", "probity_observer"),
    "probity-witness-operator-reference": (root / "interop/witness-operator-2026-10-03", "probity_witness_operator"),
    "probity-protected-operator-reference": (root / "interop/protected-action-operator-2026-10-06", "probity_protected_operator"),
}
result = {"sourceHead": subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip(),
          "python": sys.version, "pythonExecutableSha256": hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest(), "packages": {}}
for name, (base, package) in selection.items():
    distribution = metadata.distribution(name)
    expected = {str(path.relative_to(base)): path for path in (base / package).rglob("*.py")}
    installed = {str(path): Path(distribution.locate_file(path)) for path in distribution.files if str(path).endswith(".py")}
    if set(expected) != set(installed):
        raise SystemExit("installed source population differs: " + name)
    hashes = {}
    for path, source in expected.items():
        raw = source.read_bytes()
        if raw != installed[path].read_bytes():
            raise SystemExit("installed source bytes differ: " + path)
        hashes[path] = hashlib.sha256(raw).hexdigest()
    result["packages"][name] = {"version": distribution.version, "source": hashes}
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
