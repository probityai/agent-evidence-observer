"""Select current SDK and installed consumer bytes before the twelve-case run."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HOST = "e94c2e726a269e0f04e2e4b202f5c131c80c20de"
HOST_TREE = "dd31c6fc5d041782f9227c2a3191c0df2779d8fd"
CASES = (
    "permit",
    "deny",
    "changed-arguments",
    "unhandled-before",
    "unhandled-after",
    "handled-first",
    "handled-last",
    "exhausted-first",
    "exhausted-last",
    "returned-error-first",
    "returned-error-last",
    "incomplete-close",
)
BUDGET = {
    "plannedAttempts": 12,
    "maxModelCalls": 25,
    "maxToolCalls": 18,
    "maxElapsedSeconds": 120,
}
PROBE = r"""
import importlib.metadata as md, hashlib,json,sys
from pathlib import Path
modules={};caches=[];native={};unselected=[]
def inspect_entries(root: Path) -> None:
 entries=[root,*root.rglob("*")]
 unselected.extend(str(p) for p in entries if p.is_symlink()
  or p.suffix in (".pyo",".so",".pyd"))
packages=(("agent-evidence-observer","probity_observer"),
          ("probity-adk-reference","probity_adk"))
for distribution,package in packages:
 root=Path(md.distribution(distribution).locate_file(package))
 inspect_entries(root)
 for p in sorted(root.rglob("*.py")):
  name=package+"/"+str(p.relative_to(root))
  modules[name]=hashlib.sha256(p.read_bytes()).hexdigest()
 caches.extend(str(p) for p in root.rglob("*.pyc"))
try:
 sdk=md.distribution("google-adk");root=Path(sdk.locate_file("google/adk"))
 inspect_entries(root)
 for p in sorted(root.rglob("*.py")):
  raw=p.read_bytes()
  native[str(p.relative_to(root))]=hashlib.sha1(
   b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
 caches.extend(str(p) for p in root.rglob("*.pyc"));version=sdk.version
except md.PackageNotFoundError:version=None
try:md.distribution("mcp");mcp=True
except md.PackageNotFoundError:mcp=False
print(json.dumps(dict(modules=modules,native=native,caches=sorted(caches),
 unselectedImportables=sorted(unselected),sdkVersion=version,mcpInstalled=mcp,
 pythonVersion=list(sys.version_info[:3])),
 sort_keys=True))
"""
NATIVE = r"""
import json,sys,uuid
from pathlib import Path
from typing import Any
from probity_adk import producer
selection=json.loads(Path(sys.argv[2]).read_bytes())
packet=Path(sys.argv[1]);external=Path(sys.argv[3])
producer.uuid4=lambda:uuid.UUID(selection["runId"].removeprefix("adk-reference-"))
execute=producer.execute
def require(condition: bool, reason: str) -> None:
 if not condition:raise ValueError(reason)
def selected_execute(entry: dict[str, Any],store: Any) -> dict[str, Any]:
 plan=json.loads((packet/"plan-before-run.json").read_bytes())
 require([row["id"]for row in plan["cases"]]==selection["cases"],"plan_cases")
 require(plan["budget"]==selection["budget"],"plan_budget")
 require(plan["runId"]==selection["runId"],"plan_run_identity")
 require(plan["sdkVersion"]=="2.11.0","plan_version")
 require(plan["sourceRevision"]==selection["host"],"plan_source")
 require(plan["modelQuality"]=="not-evaluated","plan_quality")
 require(plan["capturePayloads"] is True,"plan_capture")
 if not external.exists():
  external.write_bytes((packet/"plan-before-run.json").read_bytes())
 return execute(entry,store)
producer.execute=selected_execute
print(producer.encode(producer.run(packet,selection["host"])).decode())
"""


def encode(value: Any) -> bytes:
    """Serialize selected JSON without a canonicalization standard claim."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def digest(raw: bytes) -> str:
    """Digest retained original bytes."""
    return hashlib.sha256(raw).hexdigest()


def ensure(condition: bool, reason: str) -> None:
    """Refuse a failed trusted host condition."""
    if not condition:
        raise ValueError(reason)


def environment() -> dict[str, str]:
    """Strip inherited credentials and Python or pip overrides."""
    return {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("PYTHON", "PIP"))
        and not any(
            w in k.upper()
            for w in ("API_KEY", "TOKEN", "SECRET", "CREDENTIAL", "PASSWORD")
        )
    }


def command(argv: list[str], prefix: Path, cwd: Path) -> bytes:
    """Retain child bytes and exact status before raising any failure."""
    try:
        child = subprocess.run(
            argv,
            cwd=cwd,
            env=environment(),
            capture_output=True,
            timeout=180,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        prefix.with_suffix(".stdout").write_bytes(error.stdout or b"")
        prefix.with_suffix(".stderr").write_bytes(error.stderr or b"")
        prefix.with_suffix(".status.json").write_bytes(
            encode({"timeout": True, "returncode": None})
        )
        raise ValueError("child_timeout") from error
    prefix.with_suffix(".stdout").write_bytes(child.stdout)
    prefix.with_suffix(".stderr").write_bytes(child.stderr)
    prefix.with_suffix(".status.json").write_bytes(
        encode({"timeout": False, "returncode": child.returncode})
    )
    ensure(child.returncode == 0, "child_failed")
    return child.stdout


def installation(
    probe: dict[str, Any], selected: dict[str, Any], native: dict[str, Any] | None
) -> None:
    """Verify source closure before importing selected SDK or reader modules."""
    ensure(probe["pythonVersion"] == [3, 13, 15], "selected_python_version")
    ensure(probe["modules"] == selected["modules"], "installed_module_population")
    ensure(probe["caches"] == [], "unselected_bytecode_cache")
    ensure(probe["unselectedImportables"] == [], "unselected_importable_alias")
    expected = {} if native is None else native["pythonGitBlobs"]
    ensure(probe["native"] == expected, "native_source_population")
    ensure(
        probe["sdkVersion"] == (None if native is None else "2.11.0"), "native_version"
    )
    ensure(probe["mcpInstalled"] is (native is not None), "reader_framework_boundary")


def wheel_check(wheels: Path, policy: dict[str, Any]) -> None:
    """Require separately selected original normally built wheel bytes."""
    for name, expected in policy["wheels"].items():
        ensure(
            digest((wheels / name).read_bytes()) == expected, "selected_wheel_digest"
        )


def selected_plan() -> dict[str, Any]:
    """Declare the fixed population and unique run identity before imports."""
    return {
        "profile": "probity-google-adk-ticket-v0",
        "host": HOST,
        "runId": "adk-reference-" + uuid.uuid4().hex,
        "cases": list(CASES),
        "budget": BUDGET.copy(),
        "modelQuality": "not-evaluated",
    }


def sdk_checkout(root: Path | None) -> dict[str, str] | None:
    """Bind hosted runs to the actual clean official current SDK checkout."""
    if root is None:
        return None

    def git(*args: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(root), *args], text=True
        ).strip()

    ensure(git("rev-parse", "HEAD") == HOST, "sdk_checkout_head")
    ensure(git("rev-parse", "HEAD^{tree}") == HOST_TREE, "sdk_checkout_tree")
    ensure(
        not git("status", "--porcelain", "--untracked-files=no"), "sdk_checkout_dirty"
    )
    origin = git("remote", "get-url", "origin").removesuffix(".git")
    ensure(origin == "https://github.com/google/adk-python", "sdk_checkout_origin")
    return {"head": HOST, "tree": HOST_TREE, "origin": origin}


def host_sources(root: Path, args: argparse.Namespace) -> dict[str, Any]:
    """Retain reviewed launcher and selection bytes before native effects."""
    names = (
        "bootstrap.py",
        "publish_reference.py",
        "installation-policy.json",
        "native-source-selection.json",
    )
    return {
        "sdkCheckout": sdk_checkout(args.sdk_checkout),
        "hostFiles": {name: digest((root / name).read_bytes()) for name in names},
        "wheels": json.loads((root / "installation-policy.json").read_bytes())[
            "wheels"
        ],
        "trustedScope": (
            "interpreter, hash-locked dependency installation, "
            "site initialization and host directory"
        ),
    }


def captured_sources(
    packet: Path, policy: dict[str, Any], native: dict[str, Any]
) -> None:
    """Bind every retained original source file to the pre-execution selection."""
    manifest = json.loads((packet / "source-manifest-before-run.json").read_bytes())
    observed = {
        str(p.relative_to(packet / "sources")): digest(p.read_bytes())
        for p in (packet / "sources").rglob("*")
        if p.is_file()
    }
    ensure(manifest == observed, "retained_source_manifest")
    modules = {}
    for key in observed:
        if key.startswith(("observer/", "adapter/")) and key.endswith(".py"):
            package = (
                "probity_observer" if key.startswith("observer/") else "probity_adk"
            )
            modules[package + "/" + key.split("/", 1)[1]] = observed[key]
    ensure(modules == policy["modules"], "retained_reader_source_population")
    sdk = {}
    for key in observed:
        if key.startswith("adk/") and key.endswith(".py"):
            raw = (packet / "sources" / key).read_bytes()
            sdk[key[4:]] = hashlib.sha1(
                b"blob " + str(len(raw)).encode() + b"\0" + raw
            ).hexdigest()
    ensure(sdk == native["pythonGitBlobs"], "retained_native_source_population")


def external_pins(packet: Path, selection: dict[str, Any]) -> dict[str, Any]:
    """Compute post-capture original-byte selections in trusted host custody."""
    plan = json.loads((packet / "plan-before-run.json").read_bytes())
    ensure(
        [row["id"] for row in plan["cases"]] == selection["cases"],
        "captured_population",
    )
    ensure(
        plan["runId"] == selection["runId"] and plan["budget"] == selection["budget"],
        "captured_run_selection",
    )
    artifacts = {
        p.name: digest(p.read_bytes()) for p in (packet / "artifacts").glob("*.json")
    }
    ensure(
        set(artifacts) == {case + ".json" for case in CASES},
        "captured_artifact_population",
    )
    ensure(
        json.loads((packet / "artifact-manifest.json").read_bytes()) == artifacts,
        "captured_artifact_manifest",
    )
    return {
        "profile": selection["profile"],
        "planSha256": digest((packet / "plan-before-run.json").read_bytes()),
        "sourceManifestSha256": digest(
            (packet / "source-manifest-before-run.json").read_bytes()
        ),
        "artifactManifestSha256": digest(
            (packet / "artifact-manifest.json").read_bytes()
        ),
        "consumerTime": datetime.now(timezone.utc).isoformat(),
    }


def probe(
    interpreter: Path,
    output: Path,
    policy: dict[str, Any],
    native: dict[str, Any] | None,
) -> dict[str, Any]:
    """Inspect installed metadata and raw bytes through standard library only."""
    raw = command([str(interpreter), "-I", "-B", "-c", PROBE], output, output.parent)
    result = json.loads(raw)
    installation(result, policy, native)
    return result


def execute(args: argparse.Namespace) -> None:
    """Run the selected current source and its isolated installed consumers."""
    root = Path(__file__).resolve().parent
    policy = json.loads((root / "installation-policy.json").read_bytes())
    native = json.loads((root / "native-source-selection.json").read_bytes())
    wheel_check(args.wheels, policy)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "host-source-before-run.json").write_bytes(
        encode(host_sources(root, args))
    )
    selection = selected_plan()
    (args.output / "pre-execution-selection.json").write_bytes(encode(selection))
    probe(args.producer, args.output / "producer-installation", policy, native)
    probe(args.reader, args.output / "reader-installation", policy, None)
    packet = args.output.resolve() / "packet"
    command(
        [
            str(args.producer),
            "-I",
            "-B",
            "-c",
            NATIVE,
            str(packet),
            str((args.output / "pre-execution-selection.json").resolve()),
            str((args.output / "host-plan-before-effects.json").resolve()),
        ],
        args.output / "native",
        args.output,
    )
    captured_sources(packet, policy, native)
    pins = external_pins(packet, selection)
    selected = args.output.resolve() / "host-policy.json"
    selected.write_bytes(encode(pins))
    command(
        [
            str(args.reader),
            "-I",
            "-B",
            str(root / "publish_reference.py"),
            str(packet),
            "--policy",
            str(selected),
            "--policy-sha256",
            digest(selected.read_bytes()),
            "--python",
            str(args.reader),
            "--reader",
            str(args.reader.parent / "probity-adk-read"),
            "--output",
            str(args.output.resolve() / "publication"),
        ],
        args.output / "consumer",
        args.output,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer", type=Path, required=True)
    parser.add_argument("--reader", type=Path, required=True)
    parser.add_argument("--wheels", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sdk-checkout", type=Path)
    execute(parser.parse_args())


if __name__ == "__main__":
    main()
