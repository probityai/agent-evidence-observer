"""Trusted launcher: select installed source, execute once, then read offline twice."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

PROBE = r'''
import importlib.metadata as md, hashlib, json, sys
from pathlib import Path
roots={"probity_adk_responses":("probity-adk-user-responses","probity_adk_responses"),
       "probity_observer":("agent-evidence-observer","probity_observer")}
if sys.argv[1]=="producer":roots["adk"]=("google-adk","google/adk")
files={};versions={};forbidden=[]
for name,(dist,package) in roots.items():
 d=md.distribution(dist);versions[name]=d.version;root=Path(d.locate_file(package))
 items={}
 for p in [root,*sorted(root.rglob("*"))]:
  if p.is_symlink() or p.suffix in (".pyc",".pyo",".so",".pyd"):
   forbidden.append(str(p))
  if p.is_file() and p.suffix==".py":
   raw=p.read_bytes();items[str(p.relative_to(root))]=hashlib.sha1(
    b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
 files[name]=items
sdk_present=True
try:md.distribution("google-adk")
except md.PackageNotFoundError:sdk_present=False
print(json.dumps(dict(files=files,versions=versions,forbidden=forbidden,
 sdkPresent=sdk_present,pythonVersion=list(sys.version_info[:3])),sort_keys=True))
'''


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def ensure(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def child(argv: list[str], prefix: Path, cwd: Path, timeout: int = 120) -> bytes:
    environment = {k: v for k, v in os.environ.items()
                   if not k.startswith(("PYTHON", "PIP")) and not any(
                       word in k.upper() for word in
                       ("TOKEN", "SECRET", "CREDENTIAL", "API_KEY", "PASSWORD"))}
    try:
        result = subprocess.run(argv, cwd=cwd, env=environment, capture_output=True,
                                check=False, timeout=timeout)
        output, error, status = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as failure:
        output, error, status = failure.stdout or b"", failure.stderr or b"", None
    prefix.with_suffix(".stdout").write_bytes(output)
    prefix.with_suffix(".stderr").write_bytes(error)
    prefix.with_suffix(".status.json").write_bytes(encoded({"returncode": status,
                                                           "timeout": status is None}))
    ensure(status == 0, "child-failed-or-timed-out")
    return output


def check_installation(probe: dict, source: dict, owned: dict, role: str) -> None:
    expected = {
        "probity_adk_responses": owned,
        "probity_observer": {p.removeprefix("probity_observer/"): sha
                             for p, sha in source["observerPythonGitBlobs"].items()},
    }
    versions = {"probity_adk_responses": "0.0.1", "probity_observer": "0.0.1"}
    if role == "producer":
        expected["adk"] = source["pythonGitBlobs"]
        versions["adk"] = "2.11.0"
    ensure(probe["pythonVersion"] == [3, 13, 15], "selected-python-version")
    ensure(probe["files"] == expected and probe["versions"] == versions,
           "installed-source-population")
    ensure(probe["forbidden"] == [], "unselected-importable-or-cache")
    ensure(probe["sdkPresent"] is (role == "producer"), "framework-free-reader")


def launch(producer: Path, reader: Path, wheels: Path, sdk: Path, output: Path) -> dict:
    profile = Path(__file__).resolve().parent
    source_raw = (profile / "native-source-selection.json").read_bytes()
    source = json.loads(source_raw)
    ensure(not output.exists(), "output-already-exists")
    output.mkdir(parents=True)
    cwd = output / "empty-cwd"
    cwd.mkdir()
    owned = {str(p.relative_to(profile / "probity_adk_responses")): git_blob(p.read_bytes())
             for p in sorted((profile / "probity_adk_responses").glob("*.py"))}
    (output / "native-source-selection.json").write_bytes(source_raw)
    retained_source = output / "native-source"
    for path, expected in source["pythonGitBlobs"].items():
        original = sdk / "src" / "google" / "adk" / path
        raw = original.read_bytes()
        ensure(not original.is_symlink() and git_blob(raw) == expected, "sdk-checkout-source")
        target = retained_source / "src" / "google" / "adk" / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    for path in ("LICENSE", "pyproject.toml", "AGENTS.md"):
        shutil.copyfile(sdk / path, retained_source / path)
    for path in ("tests/unittests/agents/test_agent_router.py", "tests/unittests/test_runners.py",
                 "tests/unittests/runners/test_run_tool_confirmation.py"):
        target = retained_source / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(sdk / path, target)
    shutil.copytree(wheels, output / "wheels")
    wheel_digests = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted(wheels.glob("*.whl"))}
    ensure(set(wheel_digests) == {"agent_evidence_observer-0.0.1-py3-none-any.whl",
                                "probity_adk_user_responses-0.0.1-py3-none-any.whl"},
           "wheel-population")
    for role, python in (("producer", producer), ("reader", reader)):
        raw = child([str(python), "-I", "-B", "-c", PROBE, role],
                    output / (role + "-installation"), cwd)
        probe = json.loads(raw)
        check_installation(probe, source, owned, role)
    plan = {"profile": "probity-adk-user-response-routing-v1",
            "runId": "adk-responses-" + uuid.uuid4().hex,
            "sourceRevision": source["revision"],
            "observerRevision": source["observerRevision"],
            "cases": ["approval-granted", "approval-denied", "long-running-completed"],
            "resumability": False, "issuer": "issuer", "root": "root",
            "model": "fixed-public-script", "providerRequests": 0,
            "modelQuality": "not-evaluated", "operator": "author-operated",
            "witnessScope": "PEER", "prospectiveEightTaskRun": "not-started",
            "budget": {"cases": 3, "turnsPerCase": 3, "modelCalls": 12,
                       "toolBodyCalls": 2, "elapsedSeconds": 120}}
    packet = output / "packet"
    packet.mkdir()
    (packet / "plan-before-run.json").write_bytes(encoded(plan))
    (output / "host-plan-before-run.json").write_bytes(encoded(plan))
    command = "from probity_adk_responses.producer import main; raise SystemExit(main())"
    child([str(producer), "-I", "-B", "-c", command, str(packet)],
          output / "native-production", cwd)
    policy_command = (
        "import sys;from pathlib import Path;from probity_adk_responses.reader import host_policy;"
        "from probity_adk_responses.contract import encode;"
        "sys.stdout.buffer.write(encode(host_policy(Path(sys.argv[1]))))")
    policy = child([str(reader), "-I", "-B", "-c", policy_command, str(packet)],
                   output / "host-policy-selection", cwd)
    policy_path = output / "host-policy.json"
    policy_path.write_bytes(policy)
    policy_sha = hashlib.sha256(policy).hexdigest()
    decisions = []
    for index in (1, 2):
        command = "from probity_adk_responses.reader import main; raise SystemExit(main())"
        decisions.append(child([str(reader), "-I", "-B", "-c", command, str(packet),
                                "--policy", str(policy_path), "--policy-sha256", policy_sha,
                                "--output", str(output / f"decision-{index}.json")],
                               output / f"offline-reader-{index}", cwd))
    ensure(decisions[0] == decisions[1], "repeat-reader-byte-difference")
    receipt = {"status": "finite-reference-admitted", "sourceRevision": source["revision"],
               "planSHA256": hashlib.sha256(encoded(plan)).hexdigest(),
               "hostPolicySHA256": policy_sha, "wheelSHA256": wheel_digests,
               "nativePythonFiles": len(source["pythonGitBlobs"]),
               "nativeInstallationVerifiedBeforeImports": True,
               "readerFrameworkFree": True, "readerLiteralRepeat": True,
               "custody": "author-operated PEER", "outsideOperator": False,
               "modelQuality": "not-evaluated", "prospectiveEightTaskRun": "not-started"}
    (output / "publication-receipt.json").write_bytes(encoded(receipt))
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("producer", "reader", "wheels", "sdk", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    print(encoded(launch(args.producer, args.reader, args.wheels, args.sdk, args.output)).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
