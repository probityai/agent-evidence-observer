#!/usr/bin/env bash
# Resolve the selected wheels' declared dependencies, retaining publisher pins
# except the rich pin that contradicts instructor's declared upper bound.
set -euo pipefail
if [[ $# -ne 3 ]]; then
  printf '%s\n' 'usage: compile-runtime-locks.sh CREWAI_CHECKOUT WHEEL_DIR NEW_OUTPUT_DIR' >&2
  exit 2
fi
sdk=$(cd -- "$1" && pwd -P)
wheels=$(cd -- "$2" && pwd -P)
output=$3
if [[ -e "$output" || -L "$output" ]]; then
  printf '%s\n' 'lock generation refused: output already exists' >&2
  exit 1
fi
mkdir -- "$output"
uv export --quiet --project "$sdk" --frozen --package crewai --no-dev \
  --no-editable --no-emit-workspace --format requirements-txt \
  --output-file "$output/publisher-dependencies.lock"
python3 -I -B - "$output" "$sdk/uv.lock" "$wheels" <<'PY'
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import sys
import tomllib
import zipfile

output = Path(sys.argv[1])
raw = (output / 'publisher-dependencies.lock').read_text()
retained = []
removed = []
skip = False
for line in raw.splitlines(keepends=True):
    if line.strip() and not line[0].isspace() and not line.startswith('#'):
        skip = line.startswith('rich==')
    (removed if skip else retained).append(line)
if not any(line.startswith('rich==15.0.0') for line in removed):
    raise SystemExit('selected conflicting publisher rich pin differs')
lock = tomllib.loads(Path(sys.argv[2]).read_text())
onnx = [item for item in lock['package'] if item['name'] == 'onnxruntime']
if len(onnx) != 1 or onnx[0]['version'] != '1.23.2':
    raise SystemExit('selected publisher onnxruntime pin differs')
# The publisher override makes this dependency conditional on Python<3.11,
# but chromadb's actual wheel requires it unconditionally on Python3.13.
retained.append('\nonnxruntime==1.23.2\n')
(output / 'native-constraints.txt').write_text(''.join(retained))
(output / 'removed-conflicting-rich.txt').write_text(''.join(removed))
(output / 'dependency-repair.json').write_text(json.dumps({
    'publisherSource': '738c8e19e35c2888d8e0663bc5cc45c5acf6ac2d',
    'resolveFrom': 'actual selected wheel metadata',
    'removedConstraint': 'rich==15.0.0 contradicts instructor rich<15',
    'restoredRequirement': 'chromadb onnxruntime>=1.14.1',
    'onnxruntimePublisherPin': '1.23.2',
    'cryptographyPublisherPin': '50.0.0 retained',
    'otherPublisherConstraints': 'unchanged',
}, indent=2) + '\n')
expected = {'crewai', 'crewai-core', 'crewai-cli',
            'agent-evidence-observer', 'probity-crewai-job-fences'}
wheel_inputs = {}
metadata = {}
for path in sorted(Path(sys.argv[3]).glob('*.whl')):
    if path.is_symlink():
        raise SystemExit('selected wheel is a symlink')
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist()
                 if name.endswith('.dist-info/METADATA')]
        if len(names) != 1:
            raise SystemExit('selected wheel metadata population differs')
        info = BytesParser().parsebytes(archive.read(names[0]))
    name = info['Name']
    if name not in expected or name in wheel_inputs:
        raise SystemExit('selected wheel distribution population differs')
    wheel_inputs[name] = name + ' @ ' + path.resolve().as_uri() + '\n'
    metadata[name] = {'version': info['Version'],
                      'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                      'requiresDist': info.get_all('Requires-Dist', [])}
if set(wheel_inputs) != expected:
    raise SystemExit('selected wheel distribution population incomplete')
(output / 'wheel-inputs.in').write_text(''.join(wheel_inputs.values()))
(output / 'reader-wheel-inputs.in').write_text(''.join(
    wheel_inputs[name] for name in
    ('agent-evidence-observer', 'probity-crewai-job-fences')))
(output / 'wheel-input-metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
PY
uv pip compile "$output/wheel-inputs.in" --python-version 3.13 --generate-hashes \
  --constraint "$output/native-constraints.txt" \
  --no-emit-package crewai --no-emit-package crewai-core \
  --no-emit-package crewai-cli --no-emit-package agent-evidence-observer \
  --no-emit-package probity-crewai-job-fences \
  --output-file "$output/requirements-native.lock"
uv pip compile "$output/reader-wheel-inputs.in" \
  --python-version 3.13 --generate-hashes \
  --constraint "$output/requirements-native.lock" \
  --no-emit-package agent-evidence-observer \
  --no-emit-package probity-crewai-job-fences \
  --output-file "$output/requirements-runtime-reader.lock"
