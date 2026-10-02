#!/usr/bin/env bash
# Build source-selected reader candidates from exact public source bytes, without network.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  printf '%s\n' 'usage: FRAMEWORK-CONSUMER-BUILD-2026-10-02.sh OBSERVER_CHECKOUT NEW_OUTPUT_DIR' >&2
  exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
checkout=$(cd -- "$1" && pwd -P)
output=$2
if [[ -e "$output" || -L "$output" ]]; then
  printf '%s\n' 'build refused: output already exists' >&2
  exit 1
fi

stage=$(mktemp -d "${TMPDIR:-$PWD}/framework-reader-build.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT

# The committed host policy selects all included source bytes before packaging.
python3 - "$checkout" "$script_dir/FRAMEWORK-CONSUMER-CONTRACT-2026-10-02.json" "$stage/selected" <<'PY'
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
print('selected source bytes verified', file=sys.stderr)
PY

checkout=$stage/selected
mkdir -p -- "$output" "$stage/observer/src" "$stage/langgraph" "$stage/pydantic/src/probity_pydantic"
cp -- "$checkout/pyproject.toml" "$checkout/LICENSE" "$stage/observer/"
cp -R -- "$checkout/src/probity_observer" "$stage/observer/src/"
for project in langgraph pydantic; do
  cp -- "$checkout/LICENSE" "$stage/$project/"
done
cp -- "$script_dir/FRAMEWORK-LANGGRAPH-READER-2026-10-02.toml" "$stage/langgraph/pyproject.toml"
cp -- "$script_dir/FRAMEWORK-PYDANTIC-READER-2026-10-02.toml" "$stage/pydantic/pyproject.toml"
cp -- "$script_dir/probity_langgraph_reader_cli.py" "$stage/langgraph/"
cp -- "$checkout/interop/langgraph-ticket-2026-10-02/lg_common.py" "$checkout/interop/langgraph-ticket-2026-10-02/lg_reader.py" "$stage/langgraph/"
for module in __init__ contract reader; do
  cp -- "$checkout/interop/pydantic-ai-native-2026-10-02/src/probity_pydantic/$module.py" "$stage/pydantic/src/probity_pydantic/"
done

# Standard wheels; no editable installs, native producer or agent dependencies.
for project in observer langgraph pydantic; do
  python3 -m pip wheel --no-index --no-deps --no-build-isolation --wheel-dir "$output" "$stage/$project"
done

python3 - "$output" "$script_dir/FRAMEWORK-CONSUMER-CONTRACT-2026-10-02.json" <<'PY'
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
    'scope': 'locally built source-selected reader candidates; no native replay or host adoption inferred',
}
with (root / 'build-record.json').open('x') as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write('\n')
PY
