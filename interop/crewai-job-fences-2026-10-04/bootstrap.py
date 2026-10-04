"""Select the installed native source before imports, then read the result offline twice."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

PROBE = r'''
import importlib.metadata as md, hashlib, json, sys
from pathlib import Path
roots={"probity_crewai_jobs":("probity-crewai-job-fences","probity_crewai_jobs"),
       "probity_observer":("agent-evidence-observer","probity_observer")}
if sys.argv[1]=="producer":
 roots.update({name:(dist,name) for name,dist in
  (("crewai","crewai"),("crewai_core","crewai-core"),("crewai_cli","crewai-cli"))})
files={};versions={};forbidden=[]
for name,(dist,package) in roots.items():
 d=md.distribution(dist);versions[name]=d.version;root=Path(d.locate_file(package))
 selected={}
 for p in [root,*sorted(root.rglob("*"))]:
  if p.is_symlink() or p.suffix in (".pyc",".pyo",".so",".pyd"):
   forbidden.append(str(p))
  if p.is_file() and p.suffix==".py":
   raw=p.read_bytes();selected[str(p.relative_to(root))]=hashlib.sha1(
    b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
 files[name]=selected
sdk_present=[]
for name in ("crewai","crewai-core","crewai-cli"):
 try:md.distribution(name);sdk_present.append(name)
 except md.PackageNotFoundError:pass
print(json.dumps(dict(files=files,versions=versions,forbidden=forbidden,
 sdkPresent=sdk_present,pythonVersion=list(sys.version_info[:3])),sort_keys=True))
'''


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def child(argv, prefix, cwd, timeout=120):
    environment = {k: v for k, v in os.environ.items()
                   if not k.startswith(("PYTHON", "PIP")) and not any(
                       word in k.upper() for word in
                       ("TOKEN", "SECRET", "CREDENTIAL", "API_KEY", "PASSWORD"))}
    environment.update({"CREWAI_DISABLE_TELEMETRY": "true", "CREWAI_DISABLE_TRACKING": "true",
                        "CREWAI_TRACING_ENABLED": "false", "OTEL_SDK_DISABLED": "true"})
    try:
        result = subprocess.run(argv, cwd=cwd, env=environment, capture_output=True,
                                check=False, timeout=timeout)
        status, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as failure:
        status, stdout, stderr = None, failure.stdout or b"", failure.stderr or b""
    prefix.with_suffix(".stdout").write_bytes(stdout)
    prefix.with_suffix(".stderr").write_bytes(stderr)
    prefix.with_suffix(".status.json").write_bytes(encoded({"returncode": status,
                                                           "timeout": status is None}))
    if status != 0:
        print("Failed retained child:", prefix.name, "status:", status, flush=True)
        for label, data in (("stdout", stdout), ("stderr", stderr)):
            print(label + " tail (maximum 8192 bytes):", flush=True)
            print(data[-8192:].decode("utf-8", errors="replace"), flush=True)
        native_output = prefix.parent / "native-production.stdout"
        if prefix.name != "native-production" and native_output.is_file():
            print("Earlier native producer stdout tail (maximum 8192 bytes):", flush=True)
            print(native_output.read_bytes()[-8192:].decode("utf-8", errors="replace"), flush=True)
        if prefix.name.startswith("offline-reader-"):
            for case in ("valid-runner", "refusal-before-body", "effect-before-refusal"):
                for name in ("manual-publication.json", "native-state-after-run.json"):
                    retained = prefix.parent / "packet" / "cases" / case / name
                    if not retained.is_file():
                        continue
                    raw = retained.read_bytes()
                    print("Retained native publication:", str(retained.relative_to(prefix.parent)),
                          "bytes:", len(raw), "sha256:", hashlib.sha256(raw).hexdigest(),
                          "maximum display bytes: 32768", flush=True)
                    print(raw[:32768].decode("utf-8", errors="replace"), flush=True)
    require(status == 0, "child-failed-or-timed-out")
    return stdout


def check_installation(probe, source, owned, role):
    expected = {"probity_crewai_jobs": owned,
                "probity_observer": {p.removeprefix("probity_observer/"): sha
                                    for p, sha in source["observerPythonGitBlobs"].items()}}
    versions = {"probity_crewai_jobs": "0.0.1", "probity_observer": "0.0.1"}
    if role == "producer":
        for name, item in source["components"].items():
            expected[name], versions[name] = item["pythonGitBlobs"], item["version"]
    require(probe["pythonVersion"] in ([3, 12, 14], [3, 13, 15]), "selected-python-version")
    require(probe["files"] == expected and probe["versions"] == versions and not probe["forbidden"],
            "installed-native-source-population")
    require(probe["sdkPresent"] == (["crewai", "crewai-core", "crewai-cli"] if role == "producer" else []),
            "sdk-free-reader")


def launch(producer, reader, wheels, sdk, output):
    profile = Path(__file__).resolve().parent
    selected_raw = (profile / "native-source-selection.json").read_bytes()
    source = json.loads(selected_raw)
    require(source["revision"] == "738c8e19e35c2888d8e0663bc5cc45c5acf6ac2d", "unselected-crewai-source")
    require(not output.exists(), "output-already-exists")
    output.mkdir(parents=True)
    cwd = output / "empty-cwd"
    cwd.mkdir()
    owned = {str(p.relative_to(profile / "probity_crewai_jobs")): blob(p.read_bytes())
             for p in sorted((profile / "probity_crewai_jobs").glob("*.py"))}
    (output / "native-source-selection.json").write_bytes(selected_raw)
    for component in source["components"].values():
        for name, expected in component["pythonGitBlobs"].items():
            relative = component["sourceRoot"] + "/" + name
            original = sdk / relative
            raw = original.read_bytes()
            require(not original.is_symlink() and blob(raw) == expected, "publisher-checkout-source")
            target = output / "native-source" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
    for name, expected in source["sourceMetadataGitBlobs"].items():
        original = sdk / name
        raw = original.read_bytes()
        require(not original.is_symlink() and blob(raw) == expected, "publisher-source-metadata")
        (output / "native-source" / name).write_bytes(raw)
    shutil.copytree(wheels, output / "wheels")
    wheel_digests = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(wheels.glob("*.whl"))}
    require(set(wheel_digests) == {"agent_evidence_observer-0.0.1-py3-none-any.whl",
        "probity_crewai_job_fences-0.0.1-py3-none-any.whl", "crewai-1.15.23-py3-none-any.whl",
        "crewai_core-1.15.23-py3-none-any.whl", "crewai_cli-1.15.23-py3-none-any.whl"}, "native-wheel-population")
    for role, python in (("producer", producer), ("reader", reader)):
        raw = child([str(python), "-I", "-B", "-c", PROBE, role], output / (role + "-installation"), cwd)
        check_installation(json.loads(raw), source, owned, role)
        child([str(python), "-I", "-B", "-c",
               "import importlib.metadata as m,json;print(json.dumps(sorted([(d.metadata['Name'],d.version) for d in m.distributions()])))"],
              output / (role + "-dependencies"), cwd)
    command = "from probity_crewai_jobs.contract import plan,encode;import uuid;print(encode(plan('crewai-jobs-'+uuid.uuid4().hex)).decode())"
    chosen = json.loads(child([str(reader), "-I", "-B", "-c", command], output / "plan-selection", cwd))
    packet = output / "packet"
    packet.mkdir()
    (packet / "plan-before-run.json").write_bytes(encoded(chosen))
    (output / "host-plan-before-run.json").write_bytes(encoded(chosen))
    child([str(producer), "-I", "-B", "-c",
           "from probity_crewai_jobs.producer import main;raise SystemExit(main())", str(packet)],
          output / "native-production", cwd)
    command = "import sys;from pathlib import Path;from probity_crewai_jobs.reader import host_policy;from probity_crewai_jobs.contract import encode;sys.stdout.buffer.write(encode(host_policy(Path(sys.argv[1]))))"
    policy = child([str(reader), "-I", "-B", "-c", command, str(packet)], output / "host-policy-selection", cwd)
    policy_path = output / "host-policy.json"
    policy_path.write_bytes(policy)
    policy_sha = hashlib.sha256(policy).hexdigest()
    decisions = []
    for index in (1, 2):
        decisions.append(child([str(reader), "-I", "-B", "-c",
            "from probity_crewai_jobs.reader import main;raise SystemExit(main())", str(packet),
            "--policy", str(policy_path), "--policy-sha256", policy_sha,
            "--output", str(output / f"decision-{index}.json")], output / f"offline-reader-{index}", cwd))
    require(decisions[0] == decisions[1], "offline-reader-byte-repeat")
    receipt = {"status": "finite-native-job-fences-and-effects-verified", "sourceRevision": source["revision"],
               "hostPolicySHA256": policy_sha, "wheelSHA256": wheel_digests,
               "nativePythonFiles": {name: len(item["pythonGitBlobs"]) for name, item in source["components"].items()},
               "nativeInstallationVerifiedBeforeImports": True, "readerFrameworkFree": True,
               "readerLiteralRepeat": True, "directCases": 17, "runnerCases": 3,
               "nativeToolBodyEffects": 2, "providerRequests": 0, "custody": "author-operated PEER",
               "outsideOperator": False, "older16Rows": "unchanged", "prospectiveEightTaskRun": "not-started"}
    (output / "publication-receipt.json").write_bytes(encoded(receipt))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("producer", "reader", "wheels", "sdk", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    print(encoded(launch(args.producer, args.reader, args.wheels, args.sdk, args.output)).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
