#!/bin/bash
# Run from this profile after creating fresh-run in the selected native environment.
set -euo pipefail
native_python=$1
reader_root=$(mktemp -d)
trap 'rm -rf "$reader_root"' EXIT
"$native_python" -m pip wheel --no-deps --no-build-isolation --wheel-dir wheels ../.. .
sha256sum wheels/*.whl > wheels-sha256.txt
"$native_python" -m venv "$reader_root/venv"
"$reader_root/venv/bin/python" -m pip install --require-hashes --only-binary=:all: -r requirements-reader.lock --report reader-install-report.json
"$reader_root/venv/bin/python" -m pip install --no-deps wheels/*.whl
"$reader_root/venv/bin/python" -m pip check
"$reader_root/venv/bin/python" -c 'import importlib.util; assert importlib.util.find_spec("pydantic_ai") is None'
cp fresh-run/consumer-pins.json "$reader_root/selected-pins.json"
"$native_python" - "$reader_root" <<'PY'
import sys
import os
from pathlib import Path
from probity_pydantic_recovery.common import sha, write
from recovery_host import gate, select_policy
from probity_observer.crypto import VerificationError, strict_loads

root = Path(sys.argv[1])
pins, policy = root / "selected-pins.json", root / "selected-policy.json"
reader = root / "venv/bin/probity-read-pydantic-recovery"
write(policy, select_policy(pins, reader))
first = gate(Path("fresh-run"), pins, policy, sha(policy.read_bytes()), reader, Path("host-receipts"))
poison = root / "poison"
poison.mkdir()
marker = root / "injection-executed"
(poison / "probity_pydantic_recovery").mkdir()
(poison / "probity_pydantic_recovery/__init__.py").write_text("from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('executed')\nraise RuntimeError('unselected module ran')\n")
old_pythonpath = os.environ.get("PYTHONPATH")
os.environ["PYTHONPATH"] = str(poison)
try:
    second = gate(Path("fresh-run"), pins, policy, sha(policy.read_bytes()), reader, Path("host-repeat"))
finally:
    if old_pythonpath is None:
        os.environ.pop("PYTHONPATH", None)
    else:
        os.environ["PYTHONPATH"] = old_pythonpath
assert not marker.exists()
write(Path("host-receipts/hostile-pythonpath-control.json"), {"unselectedModuleExecuted": False, "readerEnvironmentClearsPythonPath": True, "reportEqual": first == second})
assert first == second
assert strict_loads(Path("fresh-report.json").read_bytes().rstrip(b"\n")) == strict_loads(Path("host-receipts/reader.stdout").read_bytes().rstrip(b"\n"))
assert strict_loads(Path("host-repeat/reader.stdout").read_bytes().rstrip(b"\n")) == strict_loads(Path("host-receipts/reader.stdout").read_bytes().rstrip(b"\n"))
helper = next((root / "venv/lib").glob("python*/site-packages/probity_pydantic_recovery/gate.py"))
original = helper.read_bytes()
try:
    helper.write_bytes(original + b"\n# changed installed helper\n")
    try:
        gate(Path("fresh-run"), pins, policy, sha(policy.read_bytes()), reader, Path("changed-reader-receipts"))
    except VerificationError as error:
        assert str(error) == "host-reader-selection"
        write(Path("host-receipts/changed-helper-refusal.json"), {"status": "refused", "reason": str(error), "launcherUnchanged": True})
    else:
        raise AssertionError("changed helper gained admission")
finally:
    helper.write_bytes(original)
print("EXACT_INSTALLED_NATIVE_REPLAY_AND_HELPER_REFUSAL_PASS")
PY
