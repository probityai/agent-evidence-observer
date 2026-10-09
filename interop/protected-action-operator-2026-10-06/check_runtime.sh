#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1 SOURCE_DATE_EPOCH=946684800
profile=$(cd "$(dirname "$0")" && pwd)
source_root=$(cd "$profile/../.." && pwd)
evidence=$1
mkdir "$evidence"
uv venv "$evidence/runtime" --python 3.12
uv pip install --python "$evidence/runtime/bin/python" --require-hashes -r "$source_root/interop/witness-operator-2026-10-03/requirements.lock"
for package in "$source_root" "$source_root/interop/witness-operator-2026-10-03" "$profile"; do
  "$evidence/runtime/bin/python" -I -B -m build --wheel --no-isolation --outdir "$evidence/wheels" "$package"
done
uv pip install --python "$evidence/runtime/bin/python" --no-deps "$evidence"/wheels/*.whl
uv pip check --python "$evidence/runtime/bin/python"
uv pip freeze --python "$evidence/runtime/bin/python" > "$evidence/runtime-install.txt"
"$evidence/runtime/bin/python" -I -B "$profile/qualify_install.py" "$source_root" > "$evidence/installed-source-before.json"
"$evidence/runtime/bin/python" -I -B -m pytest -c /dev/null "$source_root/tests" -q -p no:cacheprovider --junitxml="$evidence/core-tests.xml"
"$evidence/runtime/bin/python" -I -B -m pytest -c /dev/null "$source_root/interop/witness-operator-2026-10-03/test_operator.py" "$source_root/interop/witness-operator-2026-10-03/test_retention.py" "$source_root/interop/witness-operator-2026-10-03/test_reader_fork.py" "$profile/test_authorization_operator.py" --import-mode=importlib -q -p no:cacheprovider --junitxml="$evidence/operator-tests.xml"
