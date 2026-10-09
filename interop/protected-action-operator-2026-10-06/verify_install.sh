#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1 SOURCE_DATE_EPOCH=946684800 TERM=dumb
profile=$(cd "$(dirname "$0")" && pwd)
source_root=$(cd "$profile/../.." && pwd)
evidence=$1
mode=${2:-standalone}
if [ "$mode" != standalone ] && [ "$mode" != --root-coordinator ]; then
  printf '%s\n' 'Unknown qualification mode' >&2
  exit 2
fi
mkdir "$evidence"
chmod 755 "$evidence"
native_runtime=$(mktemp -d /tmp/probity-protected-envs.XXXXXXXX)
chmod 755 "$native_runtime"
preserve_capture() {
  status=$?
  trap - EXIT
  for name in native existing-native; do
    if [ -d "$native_runtime/$name" ]; then
      cp -r -- "$native_runtime/$name" "$evidence/$name" || status=1
    fi
  done
  if [ "$mode" = --root-coordinator ]; then
    rm -rf -- "$native_runtime" || status=1
  else
    sudo rm -rf -- "$native_runtime" || status=1
  fi
  exit "$status"
}
trap preserve_capture EXIT
declare -A environments
uv python install --install-dir "$native_runtime/python" --no-bin --no-registry 3.12.14
selected_python=$(UV_PYTHON_INSTALL_DIR="$native_runtime/python" uv python find --managed-python 3.12.14)
for role in issuer gateway witness consumer workload; do
  environments[$role]="$native_runtime/$role"
  uv venv "${environments[$role]}" --python "$selected_python"
done
uv pip install --python "${environments[witness]}/bin/python" --link-mode copy --require-hashes -r "$source_root/interop/witness-operator-2026-10-03/requirements.lock"
for role in issuer gateway consumer workload; do
  uv pip install --python "${environments[$role]}/bin/python" --link-mode copy --require-hashes -r "$source_root/interop/witness-operator-2026-10-03/requirements-reader.lock"
done
for package in "$source_root" "$source_root/interop/witness-operator-2026-10-03" "$profile"; do
  "${environments[witness]}/bin/python" -I -B -m build --wheel --no-isolation --outdir "$evidence/wheels" "$package"
done
for role in issuer gateway witness consumer workload; do
  uv pip install --python "${environments[$role]}/bin/python" --link-mode copy --no-deps "$evidence"/wheels/*.whl
  uv pip check --python "${environments[$role]}/bin/python"
  chmod -R a+rX "${environments[$role]}"
  uv pip freeze --python "${environments[$role]}/bin/python" > "$evidence/$role-install.txt"
  "${environments[$role]}/bin/python" -I -B "$profile/qualify_install.py" "$source_root" > "$evidence/$role-source-before.json"
done
chmod -R a+rX "$native_runtime/python"
"${environments[witness]}/bin/python" -I -B -m radon cc -j "$profile/probity_protected_operator" "$profile/coordinate_root.py" > "$evidence/protected-operator-complexity.json"
"${environments[witness]}/bin/python" -I -B -m pytest -c /dev/null "$source_root/tests" -q -p no:cacheprovider --junitxml="$evidence/core-tests.xml"
"${environments[witness]}/bin/python" -I -B -m pytest -c /dev/null "$source_root/interop/witness-operator-2026-10-03/test_operator.py" "$source_root/interop/witness-operator-2026-10-03/test_retention.py" "$source_root/interop/witness-operator-2026-10-03/test_reader_fork.py" "$profile/test_authorization_operator.py" --import-mode=importlib -q -p no:cacheprovider --junitxml="$evidence/operator-tests.xml"
"${environments[witness]}/bin/python" -I -B "$source_root/interop/witness-operator-2026-10-03/check_complexity.py" > "$evidence/existing-witness-complexity.json"
if [ "$mode" = --root-coordinator ]; then
  "${environments[witness]}/bin/python" -I -B "$profile/coordinate_root.py" prepare "$source_root" "$evidence" "$native_runtime"
  "${environments[witness]}/bin/python" -I -B "$profile/coordinate_root.py" wait "$evidence/root-request.json"
else
  sudo "${environments[witness]}/bin/python" -I -B -m probity_protected_operator.native "$native_runtime/native" \
    --issuer-python "${environments[issuer]}/bin/python" \
    --gateway-python "${environments[gateway]}/bin/python" \
    --witness-python "${environments[witness]}/bin/python" \
    --consumer-python "${environments[consumer]}/bin/python" \
    --workload-python "${environments[workload]}/bin/python"
  sudo "${environments[witness]}/bin/python" -I -B -m probity_witness_operator.native run "$native_runtime/existing-native" \
    --private-state "$native_runtime/existing-private" \
    --producer-python "${environments[workload]}/bin/python" \
    --reader-python "${environments[consumer]}/bin/python"
fi
policy_sha=$(sha256sum "$native_runtime/existing-native/host-policy.json" | cut -d' ' -f1)
reader_args=("$native_runtime/existing-native/packet" --host-policy "$native_runtime/existing-native/host-policy.json" --policy-sha256 "$policy_sha")
"${environments[consumer]}/bin/python" -I -B -m probity_witness_operator.reader "${reader_args[@]}" > "$evidence/existing-reader-report.json"
"${environments[consumer]}/bin/python" -I -B -m probity_witness_operator.reader "${reader_args[@]}" > "$evidence/existing-reader-repeat-report.json"
cmp "$evidence/existing-reader-report.json" "$evidence/existing-reader-repeat-report.json"
"${environments[witness]}/bin/python" -I -B "$source_root/examples/ticket_service_demo.py" "$evidence/http-target-companion"
for role in issuer gateway witness consumer workload; do
  "${environments[$role]}/bin/python" -I -B "$profile/qualify_install.py" "$source_root" > "$evidence/$role-source-after.json"
  cmp "$evidence/$role-source-before.json" "$evidence/$role-source-after.json"
done
