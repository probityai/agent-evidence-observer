#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1 SOURCE_DATE_EPOCH=946684800
profile=$(cd "$(dirname "$0")" && pwd)
source_root=$(cd "$profile/../.." && pwd)
evidence=$1
sdk_root=$(cd "$2" && pwd)
mkdir "$evidence"
test "$(git -C "$sdk_root" rev-parse HEAD)" = c30b115286e000e98711fae5e85993547b73d826
uv venv "$evidence/producer" --python 3.13
uv venv "$evidence/reader" --python 3.13
# Initial qualification retains resolved hashes. Subsequent runs use the
# checked-in locks, so a new resolution requires a reviewed change.
if test -f "$profile/requirements.lock"; then
  cp "$profile/requirements.lock" "$evidence/requirements.lock"
else
  uv pip compile "$profile/requirements.in" "$sdk_root/pyproject.toml" --python-version 3.13 --generate-hashes --output-file "$evidence/requirements.lock"
fi
if test -f "$profile/requirements-reader.lock"; then
  cp "$profile/requirements-reader.lock" "$evidence/requirements-reader.lock"
else
  uv pip compile "$profile/requirements-reader.in" --python-version 3.13 --generate-hashes --output-file "$evidence/requirements-reader.lock"
fi
uv pip install --python "$evidence/producer/bin/python" --require-hashes -r "$evidence/requirements.lock"
uv pip install --python "$evidence/reader/bin/python" --require-hashes -r "$evidence/requirements-reader.lock"
"$evidence/producer/bin/python" -I -B -m build --wheel --no-isolation --outdir "$evidence/wheels" "$source_root"
"$evidence/producer/bin/python" -I -B -m build --wheel --no-isolation --outdir "$evidence/wheels" "$profile"
"$evidence/producer/bin/python" -I -B -m build --wheel --no-isolation --outdir "$evidence/wheels" "$sdk_root"
uv pip install --python "$evidence/producer/bin/python" --no-deps "$evidence"/wheels/*.whl
uv pip install --python "$evidence/reader/bin/python" --no-deps "$evidence"/wheels/agent_evidence_observer-*.whl "$evidence"/wheels/probity_smolagents_reference-*.whl
export SMOLAGENTS_READER_PYTHON="$evidence/reader/bin/python"
"$evidence/producer/bin/python" -I -B -m pytest -c /dev/null "$source_root/tests" -q -p no:cacheprovider --junitxml="$evidence/core-tests.xml"
"$evidence/producer/bin/python" -I -B -m pytest -c /dev/null "$profile/test_native.py" -q -p no:cacheprovider --junitxml="$evidence/native-tests.xml"
"$evidence/producer/bin/python" -I -B -m probity_smolagents.producer "$evidence/native"
policy_sha=$(sha256sum "$evidence/native/host-policy.json" | cut -d' ' -f1)
"$evidence/reader/bin/python" -I -B -m probity_smolagents.reader "$evidence/native/packet" --host-policy "$evidence/native/host-policy.json" --policy-sha256 "$policy_sha" > "$evidence/reader-report.json"
"$evidence/reader/bin/python" -I -B -m probity_smolagents.reader "$evidence/native/packet" --host-policy "$evidence/native/host-policy.json" --policy-sha256 "$policy_sha" > "$evidence/reader-repeat-report.json"
cmp "$evidence/reader-report.json" "$evidence/reader-repeat-report.json"
"$evidence/reader/bin/python" -I -B -m probity_smolagents.reader "$evidence/native/packet" --host-policy "$evidence/native/host-policy.json" --policy-sha256 "$policy_sha" --publish "$evidence/publication" > "$evidence/publication-report.json"
uv pip freeze --python "$evidence/producer/bin/python" > "$evidence/producer-install.txt"
uv pip freeze --python "$evidence/reader/bin/python" > "$evidence/reader-install.txt"
git -C "$source_root" rev-parse HEAD > "$evidence/frozen-source-sha.txt"
git -C "$sdk_root" rev-parse HEAD > "$evidence/sdk-source-sha.txt"
"$evidence/producer/bin/python" -I -B -c 'import importlib.util,platform; print(platform.python_version()); print(importlib.util.find_spec("smolagents").origin)' > "$evidence/runtime.txt"
cat "$evidence/reader-report.json" "$evidence/publication-report.json"
# Preserve the initial resolved locks in the CI log as a UTF-8 primary response
# in addition to their complete artifact bytes.
printf '\nSMOLAGENTS_PRODUCER_LOCK_BEGIN\n'
cat "$evidence/requirements.lock"
printf '\nSMOLAGENTS_PRODUCER_LOCK_END\nSMOLAGENTS_READER_LOCK_BEGIN\n'
cat "$evidence/requirements-reader.lock"
printf '\nSMOLAGENTS_READER_LOCK_END\n'

