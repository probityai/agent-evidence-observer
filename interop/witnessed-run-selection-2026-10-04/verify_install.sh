#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1 SOURCE_DATE_EPOCH=946684800
profile=$(cd "$(dirname "$0")" && pwd)
source_root=$(cd "$profile/../.." && pwd)
evidence=$1
mkdir "$evidence"
cp "$profile"/*.lock "$evidence/"
for role in producer reader; do
  uv venv "$evidence/$role" --python 3.12
done
uv pip install --python "$evidence/producer/bin/python" --require-hashes -r "$evidence/requirements.lock" -r "$evidence/requirements-tools.lock"
uv pip install --python "$evidence/reader/bin/python" --require-hashes -r "$evidence/requirements-reader.lock"
"$evidence/producer/bin/python" -I -B -m build --wheel --no-isolation --outdir "$evidence/wheels" "$source_root"
for role in producer reader; do
  uv pip install --python "$evidence/$role/bin/python" --no-deps "$evidence"/wheels/*.whl
  uv pip freeze --python "$evidence/$role/bin/python" > "$evidence/$role-install.txt"
  "$evidence/$role/bin/python" -I -B -c 'import platform; print(platform.python_version())' > "$evidence/$role-runtime.txt"
done
export COVERAGE_FILE="$evidence/.coverage"
"$evidence/producer/bin/python" -I -B -m coverage run --source=probity_observer.run_selection,probity_observer.selection_profile -m pytest -c /dev/null "$source_root/tests" -q -p no:cacheprovider --junitxml="$evidence/core-tests.xml"
"$evidence/producer/bin/python" -I -B -m coverage report > "$evidence/coverage.txt"
"$evidence/producer/bin/python" -I -B -m coverage json -o "$evidence/coverage.json"
"$evidence/producer/bin/python" -I -B -m ruff check --isolated --select E,F,I,B "$source_root/src/probity_observer/run_selection.py" "$source_root/src/probity_observer/selection_profile.py" "$source_root/tests/test_run_selection.py" "$source_root/tests/test_selection_profile.py"
"$evidence/producer/bin/python" -I -B -m ruff format --isolated --check "$source_root/src/probity_observer/run_selection.py" "$source_root/src/probity_observer/selection_profile.py" "$source_root/tests/test_run_selection.py" "$source_root/tests/test_selection_profile.py"
"$evidence/producer/bin/python" -I -B -m probity_observer.selection_profile --output-dir "$evidence/native" > "$evidence/producer-report.json"
witness_key=$("$evidence/reader/bin/python" -I -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["witnessPublicKey"])' "$evidence/producer-report.json")
reader_args=(--read-dir "$evidence/native" --opening-checkpoint "$evidence/native/consumer-opening.json" --final-checkpoint "$evidence/native/consumer-final.json" --witness-key "$witness_key" --operator local-installed-profile)
"$evidence/reader/bin/python" -I -B -m probity_observer.selection_profile "${reader_args[@]}" > "$evidence/reader-report.json"
"$evidence/reader/bin/python" -I -B -m probity_observer.selection_profile "${reader_args[@]}" > "$evidence/reader-repeat-report.json"
cmp "$evidence/reader-report.json" "$evidence/reader-repeat-report.json"
git -C "$source_root" rev-parse HEAD > "$evidence/source-sha.txt"
sha256sum "$evidence"/wheels/*.whl > "$evidence/wheel-sha.txt"
cat "$evidence/coverage.txt" "$evidence/reader-report.json"
