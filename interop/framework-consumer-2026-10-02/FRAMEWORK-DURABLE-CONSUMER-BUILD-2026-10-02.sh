#!/usr/bin/env bash
# Build the explicitly selected additive reader wheel; never overwrite output.
set -euo pipefail
if [[ $# -ne 2 ]]; then
  printf '%s\n' 'usage: FRAMEWORK-DURABLE-CONSUMER-BUILD-2026-10-02.sh OBSERVER_CHECKOUT NEW_OUTPUT_DIR' >&2
  exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
checkout=$(cd -- "$1" && pwd -P)
output=$2
if [[ -e "$output" || -L "$output" ]]; then
  printf '%s\n' 'build refused: output already exists' >&2
  exit 1
fi
stage=$(mktemp -d "${TMPDIR:-$PWD}/durable-reader-build.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
python3 - "$checkout" "$script_dir/FRAMEWORK-DURABLE-CONSUMER-CONTRACT-2026-10-02.json" "$stage/selected" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
contract = json.loads(Path(sys.argv[2]).read_bytes())
selected = Path(sys.argv[3])
for name, pin in contract['source_files'].items():
    path = root / name
    if not path.resolve().is_relative_to(root):
        raise SystemExit('source selection refused: path escapes checkout')
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise SystemExit('source selection refused: symlink: ' + name)
    if not path.is_file():
        raise SystemExit('source selection refused: bytes differ: ' + name)
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin['sha256']:
        raise SystemExit('source selection refused: bytes differ: ' + name)
    destination = selected / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('xb') as stream:
        stream.write(raw)
print('selected durable reader source/metadata bytes verified', file=sys.stderr)
PY
checkout=$stage/selected
mkdir -p -- "$output" "$stage/observer/src" "$stage/langgraph"
cp -- "$checkout/pyproject.toml" "$checkout/LICENSE" "$stage/observer/"
cp -R -- "$checkout/src/probity_observer" "$stage/observer/src/"
cp -- "$checkout/LICENSE" "$stage/langgraph/"
selected_profile=$checkout/interop/framework-consumer-2026-10-02
cp -- "$selected_profile/FRAMEWORK-LANGGRAPH-DURABLE-READER-2026-10-02.toml" "$stage/langgraph/pyproject.toml"
cp -- "$selected_profile/probity_langgraph_reader_cli.py" "$selected_profile/probity_langgraph_durable_reader_cli.py" "$stage/langgraph/"
for module in lg_common lg_reader durable_reader; do
  cp -- "$checkout/interop/langgraph-ticket-2026-10-02/$module.py" "$stage/langgraph/"
done
for project in observer langgraph; do
  python3 -m pip wheel --no-index --no-deps --no-build-isolation --wheel-dir "$output" "$stage/$project"
done
python3 - "$output" "$script_dir/FRAMEWORK-DURABLE-CONSUMER-CONTRACT-2026-10-02.json" <<'PY'
import hashlib
import importlib.metadata
import json
import platform
import sys
from pathlib import Path

root = Path(sys.argv[1])
record = {
    'schema_version': 'probity.framework-reader-build.v1',
    'source_contract_sha256': hashlib.sha256(Path(sys.argv[2]).read_bytes()).hexdigest(),
    'python': platform.python_version(),
    'build_packages': {name: importlib.metadata.version(name) for name in ('setuptools', 'wheel')},
    'wheels': {p.name: {'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'bytes': p.stat().st_size} for p in sorted(root.glob('*.whl'))},
    'scope': 'source-selected framework-free historical/durable reader wheels; replay and adoption require separate records',
}
with (root / 'build-record.json').open('x') as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write('\n')
PY
