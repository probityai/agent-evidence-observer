#!/usr/bin/env bash
set -euo pipefail
umask 022
export SOURCE_DATE_EPOCH=946684800
export TERM=dumb PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
profile=$(cd "$(dirname "$0")" && pwd)
source_root=$(cd "$profile/../.." && pwd)
aps_profile="$source_root/interop/aps-durable-refund-2026-10-05"
evidence=$1
mkdir "$evidence"
evidence=$(cd "$evidence" && pwd)
step() {
    name=$1
    shift
    if "$@" > "$evidence/$name.stdout" 2> "$evidence/$name.stderr"; then
        printf '0\n' > "$evidence/$name.exit"
    else
        status=$?
        printf '%s\n' "$status" > "$evidence/$name.exit"
        cat "$evidence/$name.stderr" >&2
        exit "$status"
    fi
}
finish() {
    status=$?
    trap - EXIT
    printf '%s\n' "$status" > "$evidence/final.exit"
    exit "$status"
}
trap finish EXIT
step native-npm bash -ec 'cd "$1"; npm ci --ignore-scripts; npm ls --json' _ "$aps_profile"
node --version > "$evidence/node-version.txt"
uv venv "$evidence/.venv" --python 3.12
python="$evidence/.venv/bin/python"
step locked-dependencies uv pip install --python "$python" --require-hashes -r "$profile/requirements.lock"
step build-locked-source "$python" -I -B - "$evidence/PIC-source" <<'PY'
import os, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
revision = "330fdd817ef81d43461ea1787939e0d1cc87d589"
environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
environment.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
for command in (["git", "init", "-q", str(root)],
                ["git", "-C", str(root), "fetch", "--depth=1", "https://github.com/pic-standard/pic-standard.git", revision],
                ["git", "-C", str(root), "checkout", "--detach", "--quiet", "FETCH_HEAD"]):
    subprocess.run(command, env=environment, check=True)
actual = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], env=environment, text=True).strip()
if actual != revision:
    raise SystemExit("native PIC checkout source differs")
print(actual)
PY
mkdir "$evidence/wheels"
for source in "$source_root" "$aps_profile" "$evidence/PIC-source" "$profile"; do
    name=$(basename "$source")
    step "wheel-$name" env -u PYTHONDONTWRITEBYTECODE "$python" -I -B -m build --wheel --no-isolation --outdir "$evidence/wheels" "$source"
done
sha256sum "$evidence"/wheels/*.whl > "$evidence/wheel-SHA256.txt"
step reader-wheel-install uv pip install --python "$python" --no-deps "$evidence"/wheels/*.whl
step installed-package-check uv pip check --python "$python"
step runtime-lock-inventory "$python" -I -B "$source_root/scripts/check-runtime-locks.py"
step readme-links "$python" -I -B "$source_root/scripts/readme-lint.py"
uv pip freeze --python "$python" > "$evidence/installed-packages.txt"
step installed-source-check "$python" -I -B - "$source_root" "$aps_profile" "$profile" <<'PY'
from importlib import resources
import hashlib, json, pathlib, sys
from probity_pic_aps_refund.reader import _pic_source
root, aps, profile = map(pathlib.Path, sys.argv[1:])
checked = {}
for package, source in (("probity_observer", root / "src/probity_observer"),
                        ("probity_aps_refund", aps / "probity_aps_refund"),
                        ("probity_pic_aps_refund", profile / "probity_pic_aps_refund")):
    installed = resources.files(package)
    for path in sorted(source.rglob("*")):
        if not path.is_file() or path.suffix not in {".py", ".json"}:
            continue
        relative = path.relative_to(source)
        actual = installed.joinpath(*relative.parts).read_bytes()
        if actual != path.read_bytes():
            raise SystemExit("installed reader bytes differ: " + package + "/" + str(relative))
        checked[package + "/" + relative.as_posix()] = hashlib.sha256(actual).hexdigest()
print(json.dumps({"nativePICCommit": _pic_source(), "installedSourceFiles": checked}, sort_keys=True))
PY
step source-lint "$python" -I -B -m ruff check "$profile/probity_pic_aps_refund" "$profile/test_reader.py"
step source-complexity "$python" -I -B -m radon cc -j "$profile/probity_pic_aps_refund"
step complexity-contract "$python" -I -B - "$evidence/source-complexity.stdout" <<'PY'
import json, pathlib, sys
files = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
blocks = [block for items in files.values() for block in items]
if not blocks or any(block["complexity"] > 10 for block in blocks):
    raise SystemExit("new reader exceeds the documented complexity contract")
print("all new reader functions have complexity at most 10")
PY
export COVERAGE_FILE="$evidence/.coverage"
step reader-controls "$python" -I -B -m coverage run --include='*/probity_pic_aps_refund/reader.py' -m pytest -c /dev/null "$profile/test_reader.py" --import-mode=importlib -q -p no:cacheprovider --junitxml="$evidence/tests.xml"
step coverage-report "$python" -I -B -m coverage json -o "$evidence/coverage.json"
step coverage-floor "$python" -I -B - "$evidence/coverage.json" <<'PY'
import json, pathlib, sys
report = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
files = [value["summary"] for name, value in report["files"].items() if name.endswith("/probity_pic_aps_refund/reader.py")]
if len(files) != 1 or files[0]["percent_covered"] < 80:
    raise SystemExit("new reader statement coverage is incomplete or below 80")
print(json.dumps(files[0], sort_keys=True))
PY
for case in restart after-intent approval-reissue; do
    if "$python" -I -B -m probity_pic_aps_refund.reader --fixtures "$profile/fixtures" --case "$case" --node "$(command -v node)" --aps-verifier "$aps_profile/verify-aps.mjs" > "$evidence/$case.json" 2> "$evidence/$case.stderr"; then
        printf '0\n' > "$evidence/$case.exit"
        echo 'incomplete join unexpectedly exited zero' >&2
        exit 1
    else
        status=$?
        printf '%s\n' "$status" > "$evidence/$case.exit"
        test "$status" -eq 3
    fi
done
step cli-results "$python" -I -B - "$evidence" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
for case, effects in (("restart", 1), ("after-intent", 0), ("approval-reissue", 1)):
    report = json.loads((root / (case + ".json")).read_bytes())
    comparison = report["comparison"]
    expected = "Combined refund admission is not established; see comparison and missingInputs.\n"
    if comparison["combinedAdmissionEstablished"] is not False or (root / (case + ".stderr")).read_text() != expected:
        raise SystemExit("incomplete join outcome or stderr differs")
    if report["APS"]["retainedLocalCapture"]["localEffects"] != effects:
        raise SystemExit("retained effect count differs")
print("all three CLI reports retain the native scopes and refuse combined admission")
PY
