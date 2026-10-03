#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1 SOURCE_DATE_EPOCH=946684800
profile=$(cd "$(dirname "$0")" && pwd)
source_root=$(cd "$profile/../.." && pwd)
evidence=$1
baseline_root=$(cd "$2" && pwd)
fixed_root=$(cd "$3" && pwd)
test "$(git -C "$baseline_root" rev-parse HEAD)" = 63aed55113d4fe78245d3d6667b6e87569888bf5
test "$(git -C "$fixed_root" rev-parse HEAD)" = 23d253f2587ac090412394fe1a71ef5694fe2eda
mkdir "$evidence"
cp "$profile/requirements.lock" "$profile/requirements-reader.lock" "$evidence/"
uv venv "$evidence/baseline-producer" --python 3.12
uv venv "$evidence/proposed-fix-producer" --python 3.12
uv venv "$evidence/reader" --python 3.12
uv pip install --python "$evidence/baseline-producer/bin/python" --require-hashes -r "$evidence/requirements.lock"
uv pip install --python "$evidence/proposed-fix-producer/bin/python" --require-hashes -r "$evidence/requirements.lock"
uv pip install --python "$evidence/reader/bin/python" --require-hashes -r "$evidence/requirements-reader.lock"
build_python="$evidence/baseline-producer/bin/python"
"$build_python" -I -B -m build --wheel --no-isolation --outdir "$evidence/wheels" "$source_root"
"$build_python" -I -B -m build --wheel --no-isolation --outdir "$evidence/wheels" "$profile"
"$build_python" -I -B -m build --wheel --no-isolation --outdir "$evidence/baseline-sdk-wheel" "$baseline_root"
"$build_python" -I -B -m build --wheel --no-isolation --outdir "$evidence/proposed-fix-sdk-wheel" "$fixed_root"
for variant in baseline proposed-fix; do
  producer="$evidence/$variant-producer/bin/python"
  uv pip install --python "$producer" --no-deps "$evidence"/wheels/*.whl
  uv pip install --python "$producer" --no-deps --reinstall "$evidence/$variant-sdk-wheel"/*.whl
done
uv pip install --python "$evidence/reader/bin/python" --no-deps "$evidence"/wheels/*.whl
export ADK_FAILURE_READER_PYTHON="$evidence/reader/bin/python"
"$build_python" -I -B -m pytest -c /dev/null "$source_root/tests" -q -p no:cacheprovider --junitxml="$evidence/core-tests.xml"
for variant in baseline proposed-fix; do
  producer="$evidence/$variant-producer/bin/python"
  ADK_FAILURE_VARIANT="$variant" "$producer" -I -B -m pytest -c /dev/null "$profile/test_native.py" --import-mode=importlib -q -p no:cacheprovider --junitxml="$evidence/$variant-native-tests.xml"
  "$producer" -I -B -m probity_adk_failure.producer "$evidence/native-$variant" --variant "$variant"
  policy_sha=$(sha256sum "$evidence/native-$variant/host-policy.json" | cut -d' ' -f1)
  reader_args=("$evidence/native-$variant/packet" --host-policy "$evidence/native-$variant/host-policy.json" --policy-sha256 "$policy_sha")
  "$ADK_FAILURE_READER_PYTHON" -I -B -m probity_adk_failure.reader "${reader_args[@]}" > "$evidence/$variant-reader-report.json"
  "$ADK_FAILURE_READER_PYTHON" -I -B -m probity_adk_failure.reader "${reader_args[@]}" > "$evidence/$variant-reader-repeat-report.json"
  cmp "$evidence/$variant-reader-report.json" "$evidence/$variant-reader-repeat-report.json"
  "$ADK_FAILURE_READER_PYTHON" -I -B -m probity_adk_failure.reader "${reader_args[@]}" --publish "$evidence/$variant-publication" > "$evidence/$variant-publication-report.json"
  uv pip freeze --python "$producer" > "$evidence/$variant-producer-install.txt"
  cat "$evidence/$variant-reader-report.json" "$evidence/$variant-publication-report.json"
done
uv pip freeze --python "$ADK_FAILURE_READER_PYTHON" > "$evidence/reader-install.txt"
git -C "$source_root" rev-parse HEAD > "$evidence/profile-source-sha.txt"
git -C "$baseline_root" rev-parse HEAD > "$evidence/baseline-sdk-source-sha.txt"
git -C "$fixed_root" rev-parse HEAD > "$evidence/proposed-fix-sdk-source-sha.txt"
"$ADK_FAILURE_READER_PYTHON" -I -B -c 'import importlib.metadata as m,platform; print(platform.python_version()); print(sorted(d.metadata["Name"] for d in m.distributions()))' > "$evidence/reader-runtime.txt"
