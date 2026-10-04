"""Trusted launcher retains source and child receipts before any synthesis."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

PROBE = r'''
import hashlib,importlib.metadata as md,json,sys
from pathlib import Path
roots={"probity_ag2_push":("probity-ag2-push-authority","probity_ag2_push"),
       "probity_observer":("agent-evidence-observer","probity_observer")}
if sys.argv[1]=="producer":roots.update({"ag2":("ag2","ag2"),"a2a":("a2a-sdk","a2a")})
files={};versions={}
for key,(dist,pkg) in roots.items():
 d=md.distribution(dist);versions[key]=d.version;root=Path(d.locate_file(pkg));items={}
 for p in sorted(root.rglob("*.py")):
  if p.is_symlink():raise ValueError("linked-installed-source")
  b=p.read_bytes();items[str(p.relative_to(root))]=hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
 files[key]=items
installed={}
for name in ("ag2","a2a-sdk"):
 try:md.distribution(name);installed[name]=True
 except md.PackageNotFoundError:installed[name]=False
print(json.dumps({"files":files,"versions":versions,"sdkInstalled":installed,
 "pythonVersion":list(sys.version_info[:3])},sort_keys=True))
'''


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def require(value, reason):
    if not value:
        raise ValueError(reason)


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def child(command, prefix, cwd):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("PYTHON", "PIP")) and not any(
               w in k.upper() for w in ("TOKEN", "SECRET", "CREDENTIAL", "API_KEY", "PASSWORD"))}
    try:
        p = subprocess.run(command, capture_output=True, env=env, cwd=cwd, timeout=120)
        out, err, status = p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired as e:
        out, err, status = e.stdout or b"", e.stderr or b"", None
    prefix.with_suffix(".stdout").write_bytes(out)
    prefix.with_suffix(".stderr").write_bytes(err)
    prefix.with_suffix(".status.json").write_bytes(encoded({"returncode": status, "timeout": status is None}))
    require(status == 0, "child-failed-or-timed-out")
    return out


def launch(args):
    profile = Path(__file__).resolve().parent
    output = args.output.resolve()
    require(not output.exists(), "output-already-exists")
    output.mkdir(parents=True)
    cwd = output / "empty-cwd"
    cwd.mkdir()
    source_raw = (profile / "native-source-selection.json").read_bytes()
    source = json.loads(source_raw)
    (output / "native-source-selection.json").write_bytes(source_raw)
    owned = {p.name: blob(p.read_bytes()) for p in sorted((profile / "probity_ag2_push").glob("*.py"))}
    for key, root in (("ag2", args.ag2), ("a2a", args.a2a)):
        selected = source[key]
        for name, expected in selected["pythonGitBlobs"].items():
            original = root / selected["prefix"] / name
            raw = original.read_bytes()
            require(not original.is_symlink() and blob(raw) == expected, "pinned-native-checkout")
            retained = output / "native-source" / key / selected["prefix"] / name
            retained.parent.mkdir(parents=True, exist_ok=True)
            retained.write_bytes(raw)
        extras = (["LICENSE", "pyproject.toml", "test/a2a/test_push_url_validator.py"] if key == "ag2"
                  else ["LICENSE", "pyproject.toml"])
        for name in extras:
            target = output / "native-source" / key / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / name, target)
    shutil.copytree(args.wheels, output / "wheels")
    expected = {"probity_ag2_push": owned,
                "probity_observer": source["probity_observer"]["pythonGitBlobs"]}
    versions = {"probity_ag2_push": "0.0.1", "probity_observer": "0.0.1"}
    for role, python in (("producer", args.producer), ("reader", args.reader)):
        p = json.loads(child([str(python), "-I", "-B", "-c", PROBE, role],
                             output / (role + "-installation"), cwd))
        require(p["pythonVersion"] == [3, 12, 14], "selected-python-version")
        want = {**expected, **({k: source[k]["pythonGitBlobs"] for k in ("ag2", "a2a")}
                              if role == "producer" else {})}
        ver = {**versions, **({k: source[k]["version"] for k in ("ag2", "a2a")}
                             if role == "producer" else {})}
        require(p["files"] == want and p["versions"] == ver, "installed-original-source-population")
        require(p["sdkInstalled"] == {"ag2": role == "producer", "a2a-sdk": role == "producer"},
                "reader-framework-isolation")
    packet = output / "packet"
    packet.mkdir()
    command = ("from probity_ag2_push.contract import plan,encode;import sys;"
               "sys.stdout.buffer.write(encode(plan(sys.argv[1])))")
    plan = child([str(args.reader), "-I", "-B", "-c", command, "ag2-push-" + uuid.uuid4().hex],
                 output / "plan-selection", cwd)
    (packet / "plan-before-run.json").write_bytes(plan)
    (output / "host-plan-before-run.json").write_bytes(plan)
    command = "from probity_ag2_push.producer import main;raise SystemExit(main())"
    child([str(args.producer), "-I", "-B", "-c", command, str(packet)], output / "native-production", cwd)
    command = ("from probity_ag2_push.reader import host_policy;from probity_ag2_push.contract import encode;"
               "from pathlib import Path;import sys;sys.stdout.buffer.write(encode(host_policy(Path(sys.argv[1]))))")
    policy = child([str(args.reader), "-I", "-B", "-c", command, str(packet)],
                   output / "host-policy-selection", cwd)
    (output / "host-policy.json").write_bytes(policy)
    policy_sha = hashlib.sha256(policy).hexdigest()
    repeats = []
    for i in (1, 2):
        command = "from probity_ag2_push.reader import main;raise SystemExit(main())"
        repeats.append(child([str(args.reader), "-I", "-B", "-c", command, str(packet), "--policy",
                              str(output / "host-policy.json"), "--policy-sha256", policy_sha,
                              "--output", str(output / f"decision-{i}.json")],
                             output / f"offline-reader-{i}", cwd))
    require(repeats[0] == repeats[1], "reader-literal-repeat")
    receipt = {"status": "finite-reference-admitted", "ag2Revision": source["ag2"]["revision"],
               "a2aSDKRevision": source["a2a"]["revision"], "hostPolicySHA256": policy_sha,
               "planSHA256": hashlib.sha256(plan).hexdigest(),
               "wheelSHA256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in sorted(args.wheels.glob("*.whl"))},
               "installedNativePythonFiles": {k: len(source[k]["pythonGitBlobs"]) for k in ("ag2", "a2a")},
               "installedSourceVerifiedBeforeImports": True, "readerFrameworkFree": True,
               "readerLiteralRepeat": True, "operator": "author-operated", "witnessScope": "PEER",
               "outsideOperator": False, "modelQuality": "not-evaluated",
               "older16Rows": "unchanged", "prospectiveEightTaskRun": "not-started"}
    (output / "publication-receipt.json").write_bytes(encoded(receipt))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("producer", "reader", "wheels", "ag2", "a2a", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    print(encoded(launch(args)).decode())


if __name__ == "__main__":
    main()
