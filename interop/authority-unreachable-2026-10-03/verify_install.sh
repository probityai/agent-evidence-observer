#!/usr/bin/env bash
set -euo pipefail

profile_dir="$(cd "$(dirname "$0")" && pwd)"
repository_dir="$(cd "$profile_dir/../.." && pwd)"
run_dir="${1:?new absolute output directory required}"
source_revision="${2:?immutable source revision or local-uncommitted required}"
alakris_source="${3:-}"
authority_python="${AUTHORITY_PROFILE_PYTHON:-python}"
[[ "$run_dir" == /* ]] || { echo "output directory must be absolute" >&2; exit 2; }
# A fixed build time makes wheel hashes comparable between independent reruns of the same revision.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-315532800}"

mkdir -p "$run_dir/wheels" "$run_dir/empty"
"$authority_python" -m build --no-isolation --wheel --outdir "$run_dir/wheels" "$repository_dir"
"$authority_python" -m build --no-isolation --wheel --outdir "$run_dir/wheels" "$profile_dir"
sha256sum "$run_dir"/wheels/*.whl > "$run_dir/wheel-sha256.txt"

for role in producer reader; do
  "$authority_python" -m venv "$run_dir/$role-env"
  "$run_dir/$role-env/bin/python" -m pip install -r "$profile_dir/requirements.txt" "$run_dir"/wheels/*.whl > "$run_dir/$role-install.txt"
done

cd "$run_dir/empty"
env -u PYTHONPATH ALAKRIS_SOURCE="$alakris_source" "$run_dir/producer-env/bin/python" -m pytest "$profile_dir/test_authority_profile.py" --import-mode=importlib --junitxml="$run_dir/tests.xml"
env -u PYTHONPATH "$run_dir/producer-env/bin/python" -m producer "$run_dir/native" --source-revision "$source_revision"
env -u PYTHONPATH "$run_dir/reader-env/bin/python" -m reader "$run_dir/native" --pins "$run_dir/native/consumer-pins.json" --output "$run_dir/reader-report.json"
if [[ -n "$alakris_source" ]]; then
  env -u PYTHONPATH "$run_dir/reader-env/bin/python" -m source_discriminator "$alakris_source" "$run_dir/source-discriminator-report.json"
fi
"$run_dir/reader-env/bin/python" -c 'import authority_profile,probity_observer,sys;print(sys.version);print(authority_profile.__file__);print(probity_observer.__file__)' > "$run_dir/installed-reader-location.txt"
