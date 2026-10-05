#!/usr/bin/env bash
set -euo pipefail
export SOURCE_DATE_EPOCH=946684800
umask 077
profile=$(cd "$(dirname "$0")" && pwd)
source_root=$(cd "$profile/../.." && pwd)
python3 -I -B - "$profile" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
selection = json.loads((root / "source-selection.json").read_bytes())
for name, expected in selection["sourceFiles"].items():
    path = (root / name).resolve()
    if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise SystemExit("selected profile source differs")
lock = json.loads((root / "package-lock.json").read_bytes())
if lock["packages"]["node_modules/agent-passport-system"]["integrity"] != selection["npm"]["integrity"]:
    raise SystemExit("selected npm integrity differs")
print("SELECTED_SOURCE_FILES", len(selection["sourceFiles"]))
PY
evidence=$1
mkdir "$evidence"
evidence=$(cd "$evidence" && pwd)
private_state=$(mktemp -d /tmp/probity-aps-refund.XXXXXXXX)
trap 'rm -rf -- "$private_state"' EXIT
node --version > "$evidence/node-version.txt"
npm --version > "$evidence/npm-version.txt"
(
  cd "$profile"
  npm ci --ignore-scripts
  npm ls --json > "$evidence/installed-npm.json"
)
cp "$profile"/package*.json "$profile"/requirements* "$profile/source-selection.json" "$evidence/"
for role in operator reader; do
  uv venv "$evidence/$role" --python 3.12
  uv pip install --python "$evidence/$role/bin/python" --require-hashes -r "$profile/requirements.lock"
done
"$evidence/operator/bin/python" -I -B -m build --wheel --no-isolation --outdir "$evidence/wheels" "$source_root"
"$evidence/operator/bin/python" -I -B -m build --wheel --no-isolation --outdir "$evidence/wheels" "$profile"
for role in operator reader; do
  uv pip install --python "$evidence/$role/bin/python" --no-deps "$evidence"/wheels/*.whl
  uv pip freeze --python "$evidence/$role/bin/python" > "$evidence/$role-install.txt"
  "$evidence/$role/bin/python" -I -B - "$source_root" "$profile" > "$evidence/$role-installed-source.json" <<'PY'
import hashlib, importlib.resources, json, pathlib, sys
source_root, profile = map(pathlib.Path, sys.argv[1:])
checked = {}
for package, source in (("probity_observer", source_root / "src/probity_observer"),
                        ("probity_aps_refund", profile / "probity_aps_refund")):
    installed = importlib.resources.files(package)
    for path in sorted(source.rglob("*.py")):
        relative = path.relative_to(source)
        actual = installed.joinpath(*relative.parts).read_bytes()
        expected = path.read_bytes()
        if actual != expected:
            raise SystemExit("installed source differs: " + package + "/" + relative.as_posix())
        checked[package + "/" + relative.as_posix()] = hashlib.sha256(actual).hexdigest()
print(json.dumps(checked, sort_keys=True, separators=(",", ":")))
PY
done
cat > "$evidence/core-coverage.toml" <<'CORE_TOML'
[tool.coverage.run]
branch = true
parallel = true
source_pkgs = ["probity_observer"]
patch = ["subprocess"]
data_file = "${APS_CORE_COVERAGE_FILE?}"
CORE_TOML
export APS_CORE_COVERAGE_FILE="$evidence/.core-coverage"
"$evidence/operator/bin/python" -I -B -m coverage run --rcfile="$evidence/core-coverage.toml" -m pytest -c /dev/null "$source_root/tests" -q -p no:cacheprovider --junitxml="$evidence/core-tests.xml"
"$evidence/operator/bin/python" -I -B -m coverage combine --rcfile="$evidence/core-coverage.toml"
"$evidence/operator/bin/python" -I -B -m coverage json --rcfile="$evidence/core-coverage.toml" -o "$evidence/core-coverage.json"
"$evidence/operator/bin/python" -I -B - "$evidence/core-coverage.json" <<'CORE_PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
report = json.loads(path.read_bytes())
files = {name: item["summary"] for name, item in report["files"].items() if name.endswith(("/ticket_service.py", "/authorization.py"))}
path.with_name("core-coverage-changed-file.json").write_text(json.dumps({"threshold": 80, "files": files}, sort_keys=True) + "\n")
if len(files) != 2 or any(item["percent_covered"] < 80 for item in files.values()):
    raise SystemExit("changed core file coverage incomplete or below 80")
CORE_PY
export APS_REFUND_COVERAGE_FILE="$evidence/.coverage"
"$evidence/operator/bin/python" -I -B -m coverage run --rcfile="$profile/pyproject.toml" -m pytest -c /dev/null "$profile/test_controls.py" "$profile/test_reader.py" --import-mode=importlib -q -p no:cacheprovider --basetemp="$private_state/profile-tests" --junitxml="$evidence/profile-tests.xml"
"$evidence/operator/bin/python" -I -B - "$private_state/profile-tests" "$evidence/public-hostile-controls" <<'HOSTILE_PY'
import hashlib, json, pathlib, shutil, sys
source, destination = map(pathlib.Path, sys.argv[1:])
expected = {"signed-event-sequence", "signed-intent-revision", "signed-effect-revision",
    "unsupported-effect", "missing-initialize", "signed-state-revision", "signed-state-count",
    "integer-revocation", "sql-row-real", "sql-sequence-real", "incomplete-readback-revision",
    "completed-readback-revision", "unsigned-copy-revision", "signed-public-revision", "signed-witness-scope",
    "historical-native-intent", "signed-retained-revocation", "signed-retained-phase", "signed-retained-digest", "signed-retained-time",
    "consistent-effect-identity", "terminal-content-and-row", "signed-time-seconds", "signed-time-short",
    "signed-time-long", "signed-time-offset", "policy-precision-missing", "policy-precision-seconds",
    "policy-precision-case", "policy-clock-seconds", "policy-clock-fine", "policy-clock-offset"}
members = ("host-policy.json", "receipt.json", "readback.json", "attempts.json", "service.sqlite",
    "consumer-stdout.bin", "consumer-stderr.txt", "consumer-check.json")
checks = {}
for check in sorted(source.rglob("consumer-check.json")):
    record = json.loads(check.read_bytes())
    kind = record["kind"]
    case = check.parent
    if kind not in expected or kind in checks or record["exit"] != 2:
        raise SystemExit("unexpected or duplicate hostile control")
    if (case / "consumer-stdout.bin").read_bytes() or record["refusal"].encode("ascii") not in (case / "consumer-stderr.txt").read_bytes():
        raise SystemExit("hostile consumer refusal differs")
    if record["independentCustody"] is not False or record["witnessScope"] != "PEER":
        raise SystemExit("hostile capture scope differs")
    target = destination / kind
    target.mkdir(parents=True)
    checks[kind] = {}
    for name in members:
        member = case / name
        if not member.is_file() or member.is_symlink():
            raise SystemExit("hostile capture member is not a regular file")
        shutil.copyfile(member, target / name)
        checks[kind][name] = hashlib.sha256(member.read_bytes()).hexdigest()
    if checks[kind]["host-policy.json"] != record["policySha256"] or checks[kind]["service.sqlite"] != record["SQLiteSha256"]:
        raise SystemExit("hostile control selected bytes differ")
if set(checks) != expected:
    raise SystemExit("hostile capture population incomplete")
(destination / "inventory.json").write_text(json.dumps({"caseCount": len(checks), "cases": checks,
    "independentCustody": False, "witnessScope": "PEER"}, sort_keys=True) + "\n")
HOSTILE_PY
"$evidence/operator/bin/python" -I -B - "$private_state/profile-tests" "$evidence/public-temporal-controls" <<'TEMPORAL_PY'
import hashlib, json, pathlib, shutil, sqlite3, sys
from contextlib import closing
source, destination = map(pathlib.Path, sys.argv[1:])
expected = {"transaction-" + stage + "-" + str(offset) for stage in ("intent", "effect") for offset in (-2, -1, 59, 60, 61)}
expected.update("current-local-grant-" + str(offset) for offset in (119, 120, 121))
expected.update("fractional-" + stage + "-" + str(offset) for stage in ("intent", "effect") for offset in (249, 250, 749, 750, 751))
expected.update({"fine-host-intent", "fine-host-effect", "fractional-host"})
members = ("host-policy.json", "receipt.json", "readback.json", "attempts.json", "service.sqlite",
    "consumer-stdout.bin", "consumer-stderr.txt", "temporal-check.json")
checks = {}
for check in sorted(source.rglob("temporal-check.json")):
    record = json.loads(check.read_bytes())
    kind, case = record["kind"], check.parent
    if kind not in expected or kind in checks or record["readerExit"] not in (0, 2):
        raise SystemExit("unexpected or duplicate temporal control")
    if record["independentCustody"] is not False or record["witnessScope"] != "PEER":
        raise SystemExit("temporal capture scope differs")
    policy = json.loads((case / "host-policy.json").read_bytes())
    if policy["timePrecision"] != "milliseconds":
        raise SystemExit("temporal precision differs")
    for name, pin in policy["files"].items():
        if hashlib.sha256((case / name).read_bytes()).hexdigest() != pin:
            raise SystemExit("temporal member selection differs")
    with closing(sqlite3.connect((case / "service.sqlite").resolve().as_uri() + "?mode=ro", uri=True)) as db:
        effects = db.execute("SELECT count(*) FROM tickets").fetchone()[0]
        events = [json.loads(row[0]) for row in db.execute("SELECT record FROM events")]
    admissions = sum(item["payload"]["event"]["kind"] == "intent" for item in events)
    if (record["logicalAdmissions"], record["localEffects"]) != (admissions, effects) or policy["expected"] != {"logicalAdmissions": admissions, "localEffects": effects}:
        raise SystemExit("temporal actual native population differs")
    stdout, stderr = (case / "consumer-stdout.bin").read_bytes(), (case / "consumer-stderr.txt").read_bytes()
    if record["readerExit"] == 2:
        if stdout or not stderr:
            raise SystemExit("temporal refusal output differs")
    elif stderr or json.loads(stdout)["localEffects"] != effects:
        raise SystemExit("temporal accepted output differs")
    target = destination / kind
    target.mkdir(parents=True)
    checks[kind] = {}
    for name in members:
        member = case / name
        if not member.is_file() or member.is_symlink():
            raise SystemExit("temporal member is not a regular file")
        shutil.copyfile(member, target / name)
        checks[kind][name] = hashlib.sha256(member.read_bytes()).hexdigest()
    if checks[kind]["host-policy.json"] != record["policySha256"] or checks[kind]["service.sqlite"] != record["SQLiteSha256"]:
        raise SystemExit("temporal selected bytes differ")
if set(checks) != expected:
    raise SystemExit("temporal capture population incomplete")
(destination / "inventory.json").write_text(json.dumps({"caseCount": len(checks), "cases": checks,
    "independentCustody": False, "witnessScope": "PEER"}, sort_keys=True) + "\n")
TEMPORAL_PY
"$evidence/operator/bin/python" -I -B -m coverage combine --rcfile="$profile/pyproject.toml"
"$evidence/operator/bin/python" -I -B -m coverage json --rcfile="$profile/pyproject.toml" -o "$evidence/profile-coverage.json"
"$evidence/operator/bin/python" -I -B - "$evidence/profile-coverage.json" <<'PY'
import importlib.resources, json, pathlib, sys
path = pathlib.Path(sys.argv[1])
report = json.loads(path.read_bytes())
expected = {item.name for item in importlib.resources.files("probity_aps_refund").iterdir()
            if item.name.endswith(".py")}
measured = {pathlib.Path(name).name: values["summary"]
            for name, values in report["files"].items()}
result = {"threshold": 80, "expectedFiles": sorted(expected), "files": measured}
path.with_name("profile-coverage-per-file.json").write_text(json.dumps(result, sort_keys=True) + "\n")
if set(measured) != expected or any(item["percent_covered"] < 80 for item in measured.values()):
    raise SystemExit("installed profile per-file coverage is below 80 or incomplete")
PY
"$evidence/operator/bin/python" -I -B -m probity_aps_refund.native "$evidence/native" --private-state "$private_state/native" --profile "$profile"
for case in restart cross-instance after-intent inside-effect-transaction lost-ack approval-reissue different-action-first different-action; do
  policy_sha=$(sha256sum "$evidence/native/$case/host-policy.json" | cut -d' ' -f1)
  args=("$evidence/native/$case" --policy-sha256 "$policy_sha" --node "$(command -v node)" --verifier "$profile/verify-aps.mjs")
  "$evidence/reader/bin/python" -I -B -m probity_aps_refund.reader "${args[@]}" > "$evidence/$case-reader.json"
  "$evidence/reader/bin/python" -I -B -m probity_aps_refund.reader "${args[@]}" > "$evidence/$case-reader-repeat.json"
  cmp "$evidence/$case-reader.json" "$evidence/$case-reader-repeat.json"
done
git -C "$source_root" rev-parse HEAD > "$evidence/source-sha.txt"
git -C "$source_root" rev-parse HEAD^{tree} > "$evidence/source-tree.txt"
sha256sum "$evidence"/wheels/*.whl > "$evidence/wheel-sha256.txt"
cat "$evidence/native/native-report.json"
