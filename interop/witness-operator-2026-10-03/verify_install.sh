#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1 SOURCE_DATE_EPOCH=946684800
profile=$(cd "$(dirname "$0")" && pwd)
source_root=$(cd "$profile/../.." && pwd)
evidence=$1
mkdir "$evidence"
native_runtime=$(mktemp -d /tmp/probity-witness-native.XXXXXXXX)
chmod 755 "$native_runtime"
trap 'sudo rm -rf -- "$native_runtime"' EXIT
declare -A environments=(
  [operator]="$evidence/operator"
  [producer]="$native_runtime/producer"
  [reader]="$evidence/reader"
)
cp "$profile"/requirements*.lock "$evidence/"
for role in operator producer reader; do
  uv venv "${environments[$role]}" --python 3.12
done
uv pip install --python "$evidence/operator/bin/python" --require-hashes -r "$evidence/requirements.lock"
for role in producer reader; do
  uv pip install --python "${environments[$role]}/bin/python" --require-hashes -r "$evidence/requirements-reader.lock"
done
"$evidence/operator/bin/python" -I -B -m build --wheel --no-isolation --outdir "$evidence/wheels" "$source_root"
"$evidence/operator/bin/python" -I -B -m build --wheel --no-isolation --outdir "$evidence/wheels" "$profile"
for role in operator producer reader; do
  uv pip install --python "${environments[$role]}/bin/python" --no-deps "$evidence"/wheels/*.whl
  uv pip check --python "${environments[$role]}/bin/python"
  uv pip freeze --python "${environments[$role]}/bin/python" > "$evidence/$role-install.txt"
done
"$evidence/operator/bin/python" -I -B -m pytest -c /dev/null "$source_root/tests" -q -p no:cacheprovider --junitxml="$evidence/core-tests.xml"
"$evidence/operator/bin/python" -I -B -m pytest -c /dev/null "$profile/test_operator.py" "$profile/test_retention.py" "$profile/test_reader_fork.py" --import-mode=importlib -q -p no:cacheprovider --junitxml="$evidence/operator-tests.xml"
"$evidence/operator/bin/python" -I -B "$profile/check_complexity.py" > "$evidence/complexity.json"
sudo "$evidence/operator/bin/python" -I -B -m probity_witness_operator.native run "$evidence/native" --private-state "$native_runtime/private" --producer-python "${environments[producer]}/bin/python" --reader-python "$evidence/reader/bin/python"
policy_sha=$(sha256sum "$evidence/native/host-policy.json" | cut -d' ' -f1)
reader_args=("$evidence/native/packet" --host-policy "$evidence/native/host-policy.json" --policy-sha256 "$policy_sha")
"$evidence/reader/bin/python" -I -B -m probity_witness_operator.reader "${reader_args[@]}" > "$evidence/reader-report.json"
"$evidence/reader/bin/python" -I -B -m probity_witness_operator.reader "${reader_args[@]}" > "$evidence/reader-repeat-report.json"
cmp "$evidence/reader-report.json" "$evidence/reader-repeat-report.json"
git -C "$source_root" rev-parse HEAD > "$evidence/source-sha.txt"
"$evidence/reader/bin/python" -I -B -c 'import importlib.metadata as m, platform; print(platform.python_version()); print(sorted(d.metadata["Name"] for d in m.distributions()))' > "$evidence/reader-runtime.txt"
cat "$evidence/reader-report.json"
