#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1 HAYSTACK_TELEMETRY_ENABLED=false SOURCE_DATE_EPOCH=946684800
profile=$(cd "$(dirname "$0")" && pwd)
source_root=$(cd "$profile/../.." && pwd)
evidence=${1:?new output directory required}
mkdir "$evidence"
uv venv "$evidence/producer" --python 3.13
uv venv "$evidence/reader" --python 3.13
uv pip install --python "$evidence/producer/bin/python" --require-hashes -r "$profile/requirements.lock"
uv pip install --python "$evidence/reader/bin/python" --require-hashes -r "$profile/requirements-reader.lock"
"$evidence/producer/bin/python" -m build --wheel --no-isolation --outdir "$evidence/wheels" "$source_root"
"$evidence/producer/bin/python" -m build --wheel --no-isolation --outdir "$evidence/wheels" "$profile"
uv pip install --python "$evidence/producer/bin/python" --no-deps "$evidence"/wheels/*.whl
uv pip check --python "$evidence/producer/bin/python"
uv pip install --python "$evidence/reader/bin/python" --no-deps "$evidence"/wheels/*.whl
uv pip check --python "$evidence/reader/bin/python"
export HAYSTACK_READER_PYTHON="$evidence/reader/bin/python"
"$evidence/producer/bin/python" -I -B -m pytest -c /dev/null "$profile/test_native.py" -q -p no:cacheprovider --junitxml="$evidence/native-tests.xml"
"$evidence/producer/bin/python" -I -B -m probity_haystack.producer "$evidence/packet"
policy_sha=$(sha256sum "$evidence/packet/host-policy.json" | cut -d' ' -f1)
"$evidence/reader/bin/python" -I -B -m probity_haystack.reader "$evidence/packet" --host-policy "$evidence/packet/host-policy.json" --policy-sha256 "$policy_sha" > "$evidence/reader-report.json"
"$evidence/reader/bin/python" -I -B -m probity_haystack.reader "$evidence/packet" --host-policy "$evidence/packet/host-policy.json" --policy-sha256 "$policy_sha" --publish "$evidence/publication" > "$evidence/publication-report.json"
uv pip freeze --python "$evidence/producer/bin/python" > "$evidence/producer-install.txt"
uv pip freeze --python "$evidence/reader/bin/python" > "$evidence/reader-install.txt"
git -C "$source_root" rev-parse HEAD > "$evidence/frozen-source-sha.txt"
