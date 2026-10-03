"""Trusted, credential-free consumer placement for the literal current profile.

Run from a selected clean owned checkout. Package, host and native source pins
are chosen here before calls. Post-run original-byte selection remains in this
same operator's custody; it is not producer acceptance or independent evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid
from typing import Any

HOST = "93f7182cf2ce9be22724b05e499cd1358d7ed41d"
READER = "62f5d0c6fbd785259db2d5c8076dd844b53a0593"
VERSION = "probity-inspect-execution-v2"
INSPECT_VERSION = "0.3.276"
PROBE = r"""
import hashlib, importlib.metadata as md, importlib.util, json
from pathlib import Path
dist=md.distribution("agent-evidence-observer")
root=Path(dist.locate_file("probity_observer"))
current=md.distribution("probity-inspect-current-reader")
adapter=Path(current.locate_file("probity_inspect_current/adapter.py"))
native_spec=importlib.util.find_spec("inspect_ai")
native_root=Path(native_spec.origin).parent if native_spec is not None else None
selected_roots=[root, adapter.parent]
if native_spec is not None:
 selected_roots.append(Path(native_spec.origin).parent)
print(json.dumps({
 "python":__import__("sys").version.split()[0],
 "observer_version":dist.version,"reader_version":current.version,
 "observer_modules":{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob("*.py"))},
 "adapter_sha256":hashlib.sha256(adapter.read_bytes()).hexdigest(),
 "current_modules":{str(p.relative_to(adapter.parent)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(adapter.parent.rglob("*.py"))},
 "legacy":{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((adapter.parent/"_legacy").glob("*.py"))},
 "framework_available":native_spec is not None,
 "native_metadata_version":md.version("inspect-ai") if native_spec is not None else None,
 "native_git_blobs":{str(p.relative_to(native_root)):hashlib.sha1(b"blob "+str(len(p.read_bytes())).encode()+b"\0"+p.read_bytes()).hexdigest() for p in sorted(native_root.rglob("*.py"))} if native_root is not None else {},
 "bytecode_cache_population":[str(p) for r in selected_roots for p in sorted(r.rglob("*.pyc"))],
 "adapter_file":str(adapter),"observer_root":str(root)
},sort_keys=True))
"""


def encode(value: Any) -> bytes:
    """Encode canonical selected JSON bytes."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def sha(raw: bytes) -> str:
    """Digest original byte buffers."""
    return hashlib.sha256(raw).hexdigest()


def ensure(condition: bool, label: str) -> None:
    """Refuse a violated consumer condition."""
    if not condition:
        raise ValueError(label)


def clean_environment() -> tuple[dict[str, str], list[str]]:
    """Remove inherited credentials and Python or pip configuration."""
    removed = []
    env = {}
    for key, value in os.environ.items():
        if key.startswith(("PYTHON", "PIP")) or any(
            word in key.upper()
            for word in ("API_KEY", "TOKEN", "SECRET", "CREDENTIAL", "PASSWORD")
        ):
            removed.append(key)
        else:
            env[key] = value
    env["NO_COLOR"] = "1"
    return env, sorted(removed)


def command(
    argv: list[str], *, env: dict[str, str], cwd: Path, prefix: Path, timeout: int = 180
) -> bytes:
    """Retain child bytes and refuse a timeout or unsuccessful exit."""
    prefix.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            argv, env=env, cwd=cwd, capture_output=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as error:
        prefix.with_suffix(".stdout").write_bytes(error.stdout or b"")
        prefix.with_suffix(".stderr").write_bytes(error.stderr or b"")
        prefix.with_suffix(".status.json").write_bytes(encode({"timeout": True}))
        raise ValueError("child_timeout") from error
    prefix.with_suffix(".stdout").write_bytes(result.stdout)
    prefix.with_suffix(".stderr").write_bytes(result.stderr)
    prefix.with_suffix(".status.json").write_bytes(
        encode({"returncode": result.returncode})
    )
    ensure(result.returncode == 0, "child_failed")
    return result.stdout


def checkout(root: Path, selected: str, origin: str) -> dict[str, str]:
    """Require the selected clean checkout and origin before native calls."""

    def git(*args: str) -> str:
        """Read checkout metadata through the trusted git binary."""
        return subprocess.check_output(
            ["git", "-C", str(root), *args], text=True
        ).strip()

    ensure(git("rev-parse", "HEAD") == selected, "checkout_head")
    ensure(not git("status", "--porcelain", "--untracked-files=no"), "checkout_dirty")
    actual_origin = git("remote", "get-url", "origin").removesuffix(".git")
    ensure(actual_origin == origin, "checkout_origin")
    return {
        "head": selected,
        "tree": git("rev-parse", "HEAD^{tree}"),
        "origin": actual_origin,
    }


def population() -> dict[str, Any]:
    """Declare precisely six bounded cases and their launch policy."""
    cases = []
    for name, tier, final, launch in (
        ("tool-pass", "tools", "4", True),
        ("tool-fail", "tools", "wrong", True),
        ("agent-pass", "agents", "4", True),
        ("agent-error", "agents", None, True),
        ("workload-pass", "workloads", "DONE", True),
        ("planned-unstarted", "workloads", "DONE", False),
    ):
        cases.append(
            {
                "id": name,
                "tier": tier,
                "input": "Complete the bounded local task.",
                "target": "DONE" if tier == "workloads" else "4",
                "final": final,
                "launch": launch,
            }
        )
    return {
        "profile": VERSION,
        "run_id": "native-execution-" + uuid.uuid4().hex,
        "cases": cases,
    }


def probe_check(
    probe: dict[str, Any],
    policy: dict[str, Any],
    native: bool,
    native_sources: dict[str, str] | None = None,
) -> None:
    """Validate selected ordinary installs before importing their modules."""
    ensure(probe["python"] == "3.12.14", "python_version")
    ensure(
        probe["observer_version"] == "0.0.1" and probe["reader_version"] == "0.0.1",
        "package_versions",
    )
    ensure(
        probe["observer_modules"] == policy["observer_modules"],
        "observer_module_population",
    )
    ensure(probe["adapter_sha256"] == policy["adapter_sha256"], "adapter_digest")
    ensure(
        probe["current_modules"] == policy["current_modules"],
        "current_module_population",
    )
    ensure(probe["legacy"] == policy["legacy"], "legacy_population")
    ensure(probe["framework_available"] is native, "framework_boundary")
    ensure(probe["bytecode_cache_population"] == [], "unselected_bytecode_cache")
    if native:
        ensure(
            probe["native_metadata_version"] == INSPECT_VERSION,
            "preimport_native_version",
        )
        ensure(
            probe["native_git_blobs"] == native_sources,
            "preimport_native_source_population",
        )


def capture_selection(
    output: Path, frozen: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read actual captured originals independently; do not adopt producer pins."""
    declared = (output / "declaration-before-run.json").read_bytes()
    ensure(json.loads(declared) == frozen["declaration"], "captured_population_changed")
    sources = {
        name: (output / "sources" / name).read_bytes()
        for name in frozen["prepared"]["sources"]
    }
    ensure(
        {name: raw.decode() for name, raw in sources.items()}
        == frozen["prepared"]["sources"],
        "captured_sources_changed",
    )
    bindings = {}
    originals = {}
    for case in frozen["declaration"]["cases"]:
        if not case["launch"]:
            continue
        aid = case["id"]
        path = output / "packet" / (aid + "-native.json")
        raw = path.read_bytes()
        ev = json.loads(raw)["eval"]
        bindings[aid] = {
            "sha256": sha(raw),
            "run_id": ev["run_id"],
            "eval_id": ev["eval_id"],
        }
        originals[path.name] = {"sha256": sha(raw), "size_bytes": len(raw)}
    actual_bindings = (output / "packet" / "native-bindings.json").read_bytes()
    ensure(json.loads(actual_bindings) == bindings, "captured_binding_join")
    pins = {
        "expected_declaration_sha256": sha(declared),
        "expected_sources_sha256": sha(
            encode({name: sha(raw) for name, raw in sources.items()})
        ),
        "expected_bindings_sha256": sha(actual_bindings),
        "expected_plan_sha256": sha((output / "packet" / "plan.json").read_bytes()),
        "expected_history_sha256": sha(
            (output / "packet" / "history.json").read_bytes()
        ),
    }
    return {"declaration": frozen["declaration"], "pins": pins}, originals


def repeated(first: bytes, second: bytes) -> dict[str, Any]:
    """Require equal installed-reader bytes and faithful fixed-run outcomes."""
    ensure(first == second, "repeated_decision_changed")
    report = json.loads(first)
    ensure(report.get("mapping") == VERSION, "consumer_profile")
    expected = {
        "planned": 6,
        "started": 5,
        "complete": 4,
        "scored": 4,
        "task_passed": 3,
        "task_failed": 1,
        "failed": 1,
        "missing": 1,
        "unknown_start": 0,
        "incomplete": 0,
    }
    ensure(
        all(report.get(key) == value for key, value in expected.items()),
        "consumer_outcomes",
    )
    return report


def _install_checks(
    args: argparse.Namespace,
    policy: dict[str, Any],
    env: dict[str, str],
    receipt: dict[str, Any],
    native_sources: dict[str, str],
) -> None:
    """Bind reviewed wheels and actual installed source before import."""
    for wheel, name in (
        (args.observer_wheel, "observer_wheel_sha256"),
        (args.adapter_wheel, "adapter_wheel_sha256"),
    ):
        ensure(sha(wheel.read_bytes()) == policy[name], "installed_wheel_digest")
    for label, python, native in (
        ("producer", args.producer_python, True),
        ("reader", args.reader_python, False),
    ):
        raw = command(
            [str(python), "-I", "-B", "-c", PROBE],
            env=env,
            cwd=args.retained,
            prefix=args.retained / (label + "-probe"),
        )
        probe = json.loads(raw)
        probe_check(probe, policy, native, native_sources)
        receipt[label + "Probe"] = probe


def _mutations(
    args: argparse.Namespace, packet: Path, consumer_file: Path, env: dict[str, str]
) -> dict[str, str]:
    """Refuse fresh captured-byte mutants using the unchanged external pins."""
    # Fresh authentic packet each time; externally selected pins remain fixed.
    mutations = {
        "native": Path("packet/tool-pass-native.json"),
        "bindings": Path("packet/native-bindings.json"),
        "plan": Path("packet/plan.json"),
        "history": Path("packet/history.json"),
        "source": Path("sources/configuration.json"),
        "declaration": Path("declaration-before-run.json"),
    }
    controls = {}
    for label, relative in mutations.items():
        mutant = args.retained / ("mutant-" + label)
        shutil.copytree(packet, mutant)
        target = mutant / relative
        target.write_bytes(target.read_bytes() + b" ")
        try:
            command(
                [
                    str(args.reader_python),
                    "-I",
                    "-B",
                    "-m",
                    "probity_inspect_current.adapter",
                    "verify",
                    str(mutant),
                    "--selection",
                    str(consumer_file),
                ],
                env=env,
                cwd=args.retained,
                prefix=args.retained / ("control-" + label),
            )
        except ValueError as error:
            ensure(str(error) == "child_failed", "control_infrastructure_failure")
            controls[label] = "refused"
        else:
            raise ValueError("mutant_was_accepted")
    return controls


def run(args: argparse.Namespace) -> dict[str, Any]:
    """Retain a faithful current-source packet and installed consumer decisions."""
    here = Path(__file__).resolve().parent
    policy = json.loads((here / "installation-policy.json").read_bytes())
    ensure(
        sha(Path(__file__).read_bytes()) == policy["bootstrap_sha256"],
        "bootstrap_digest",
    )
    native_policy_raw = (here / "native-source-selection.json").read_bytes()
    ensure(
        sha(native_policy_raw) == policy["native_selection_sha256"],
        "native_selection_digest",
    )
    native_policy = json.loads(native_policy_raw)
    args.retained.mkdir(parents=True, exist_ok=False)
    env, removed = clean_environment()
    receipt = {
        "providerCredentialsRemoved": removed,
        "producerAcceptance": False,
        "recurringOutsideAdoption": False,
        "independentEffectCustody": False,
        "scope": "same-operator-current-host-mock-six-cases",
    }
    try:
        receipt["candidate"] = checkout(
            args.candidate, args.candidate_sha, "https://github.com/probityai/agent-evidence-observer"
        )
        receipt["host"] = checkout(
            args.host, HOST, "https://github.com/UKGovernmentBEIS/inspect_ai"
        )
        receipt["readerSource"] = checkout(
            args.reader_source, READER, "https://github.com/probityai/agent-evidence-observer"
        )
        _install_checks(args, policy, env, receipt, native_policy["files"])
        declaration = population()
        selection = {"declaration": declaration}
        selected = args.retained / "selection-before-run.json"
        selected.write_bytes(encode(selection))
        prepare_raw = command(
            [
                str(args.producer_python),
                "-I",
                "-B",
                "-m",
                "probity_inspect_current.adapter",
                "prepare",
                str(args.retained / "packet"),
                "--selection",
                str(selected),
            ],
            env=env,
            cwd=args.retained,
            prefix=args.retained / "prepare",
        )
        prepared = json.loads(prepare_raw)
        ensure(
            prepared["native_git_blobs"] == native_policy["files"],
            "native_source_population",
        )
        ensure(
            prepared["installed_version"] == INSPECT_VERSION, "installed_native_version"
        )
        ensure(prepared["declaration"] == declaration, "prepared_population")
        selection["prepared"] = prepared
        selected.write_bytes(encode(selection))
        receipt["preexecutionSelectionSha256"] = sha(selected.read_bytes())
        packet = args.retained / "packet"
        command(
            [
                str(args.producer_python),
                "-I",
                "-B",
                "-m",
                "probity_inspect_current.adapter",
                "produce",
                str(packet),
                "--selection",
                str(selected),
            ],
            env=env,
            cwd=args.retained,
            prefix=args.retained / "producer",
        )
        consumer, originals = capture_selection(packet, selection)
        consumer_file = args.retained / "consumer-selected-pins.json"
        consumer_file.write_bytes(encode(consumer))
        read_command = [
            str(args.reader_python),
            "-I",
            "-B",
            "-m",
            "probity_inspect_current.adapter",
            "verify",
            str(packet),
            "--selection",
            str(consumer_file),
        ]
        first = command(
            read_command,
            env=env,
            cwd=args.retained,
            prefix=args.retained / "reader-first",
        )
        second = command(
            read_command,
            env=env,
            cwd=args.retained,
            prefix=args.retained / "reader-repeat",
        )
        report = repeated(first, second)
        receipt.update(
            {
                "status": "verified",
                "originals": originals,
                "report": report,
                "repeatDecisionSha256": sha(first),
                "selectedConsumerPinsSha256": sha(consumer_file.read_bytes()),
            }
        )
        receipt["controls"] = _mutations(args, packet, consumer_file, env)
        return receipt
    except Exception as error:
        receipt.update({"status": "failed", "error": str(error)})
        raise
    finally:
        (args.retained / "trusted-host-receipt.json").write_bytes(encode(receipt))


def main() -> None:
    """Read selected host paths and execute the trusted bootstrap."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "candidate",
        "host",
        "reader-source",
        "producer-python",
        "reader-python",
        "observer-wheel",
        "adapter-wheel",
        "retained",
    ):
        parser.add_argument(
            "--" + name, type=lambda value: Path(value).absolute(), required=True
        )
    parser.add_argument("--candidate-sha", required=True)
    print(json.dumps(run(parser.parse_args()), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
