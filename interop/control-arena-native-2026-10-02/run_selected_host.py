"""Run a selected native host after verifying an independently installed reader."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

HOST_COMMIT = "7c0ebaa21c9d59d146c0eafcf7d6938734e8e430"
HOST_TREE = "6c2e81ac9d251232ef278de01e4ed1ba198c0a49"
WHEEL_SHA256 = "096ab32f22716c11b95cb7c4be9daadf29ffea01513cf5aa9390b053654178a3"
MODULE_SHA256 = "106446beaf68fe9775c3bbe1d4fa8fe8fb32090a2235ec1e4041408322a6204c"
INSPECT_VERSION = "0.3.257"
PROVIDER_VARIABLES = {
    "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
}


def digest(path: Path) -> str:
    """Return the SHA256 of a caller-selected local file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clean_environment() -> dict[str, str]:
    """Remove inherited provider credentials without reporting their values."""
    return {
        key: value
        for key, value in os.environ.items()
        if key not in PROVIDER_VARIABLES
        and not key.endswith(("_API_KEY", "_API_TOKEN", "_ACCESS_TOKEN"))
    }


def git(root: Path, arguments: Sequence[str]) -> str:
    """Read source identity using Git without importing candidate code."""
    return subprocess.check_output(
        ["git", "-C", str(root), *arguments], text=True, env=clean_environment()
    ).strip()


def write_json(path: Path, value: object) -> None:
    """Create a receipt exclusively so a previous result cannot be overwritten."""
    with path.open("x") as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2) + "\n")


def command(
    arguments: Sequence[str], cwd: Path, output: Path, env: Mapping[str, str]
) -> None:
    """Execute one declared command and retain its full output and exit status.

    Parameters
    ----------
    arguments : sequence of str
        Argument vector selected by the consumer, without shell evaluation.
    cwd : Path
        Selected source working directory.
    output : Path
        Exclusive output file outside candidate source.
    env : mapping of str to str
        Provider-credential-free process environment.
    """
    with output.open("xb") as stream:
        result = subprocess.run(
            list(arguments),
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=stream,
            stderr=subprocess.STDOUT,
            timeout=300,
            check=False,
        )
    write_json(
        output.with_suffix(".command.json"),
        {
            "arguments": list(arguments),
            "cwd": str(cwd),
            "exitCode": result.returncode,
            "outputSha256": digest(output),
        },
    )
    if result.returncode:
        raise RuntimeError(f"Selected command failed; retained {output}")


def verify_sources(reader_root: Path, source: str, host: Path, origin: str) -> None:
    """Bind clean reader and host trees to source pins selected before execution."""
    if git(reader_root, ["rev-parse", "HEAD"]) != source:
        raise ValueError("Reader source differs from the outside commit selection")
    if git(reader_root, ["status", "--porcelain", "--untracked-files=no"]):
        raise ValueError("Reader source has tracked modifications")
    if git(host, ["rev-parse", "HEAD"]) != HOST_COMMIT:
        raise ValueError("Host source differs from the maintained exact pin")
    if git(host, ["rev-parse", "HEAD^{tree}"]) != HOST_TREE:
        raise ValueError("Host source tree differs from the maintained exact pin")
    if git(host, ["status", "--porcelain"]):
        raise ValueError("Host source must be clean")
    if git(host, ["remote", "get-url", "origin"]) != origin:
        raise ValueError("Host origin differs from the outside selection")


def verify_installed_reader(
    python: Path, wheel: Path, output: Path, env: Mapping[str, str]
) -> None:
    """Verify wheel and installed module bytes before importing native host code."""
    if digest(wheel) != WHEEL_SHA256:
        raise ValueError("Wheel differs from the reviewed byte selection")
    probe = (
        "import hashlib,importlib.util,json;from importlib.metadata import version;"
        "from pathlib import Path;"
        "spec=importlib.util.find_spec('probity_control_arena_reader');"
        "print(json.dumps({'version':version('probity-control-arena-reader'),"
        "'moduleSha256':hashlib.sha256(Path(spec.origin).read_bytes()).hexdigest(),"
        "'inspectPresent':importlib.util.find_spec('inspect_ai') is not None,"
        "'controlArenaPresent':importlib.util.find_spec('control_arena') is not None}))"
    )
    command([str(python), "-I", "-c", probe], output.parent, output, env)
    installed = json.loads(output.read_bytes())
    expected = {
        "version": "0.0.2",
        "moduleSha256": MODULE_SHA256,
        "inspectPresent": False,
        "controlArenaPresent": False,
    }
    if installed != expected:
        raise ValueError("Installed reader bytes or isolation differ from selection")


def capture_digests(native_dir: Path) -> dict[str, object]:
    """Hash the selected original and JSON independently of producer receipts."""
    files = list(native_dir.glob("*.eval"))
    if len(files) != 1 or files[0].is_symlink():
        raise ValueError("Expected one retained native file in the selected directory")
    native = files[0]
    exported = native_dir / "control-arena.json"
    if exported.is_symlink():
        raise ValueError("Selected JSON path must be a regular capture")
    selected: dict[str, object] = {
        "native_sha256": digest(native),
        "native_bytes": native.stat().st_size,
        "json_sha256": digest(exported),
        "json_bytes": exported.stat().st_size,
    }
    if json.loads((native_dir / "capture.json").read_bytes()) != selected:
        raise ValueError("Producer capture receipt differs from consumer byte hashes")
    return selected


def main() -> None:
    """Select sources, installed reader, population and time before a native run.

    Notes
    -----
    This trusted consumer script supplies a log-publication demonstration. Git
    revisions, timestamps and retained paths remain peer self-reports; this does
    not establish independent key/clock/store/retention or target-effect custody.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader-root", type=Path, required=True)
    parser.add_argument("--reader-source-commit", required=True)
    parser.add_argument("--reader-python", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--host-root", type=Path, required=True)
    parser.add_argument("--host-python", type=Path, required=True)
    parser.add_argument("--host-origin", required=True)
    parser.add_argument("--backend", choices=("asyncio", "trio"), required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    verify_sources(
        args.reader_root, args.reader_source_commit, args.host_root, args.host_origin
    )
    source_abbrev = git(args.host_root, ["rev-parse", "--short", "HEAD"])
    if not (7 <= len(source_abbrev) <= 40 and HOST_COMMIT.startswith(source_abbrev)):
        raise ValueError("Native source abbreviation must bind the verified full SHA")
    args.output_dir.mkdir(parents=True, exist_ok=False)
    env = clean_environment()
    env["INSPECT_ASYNC_BACKEND"] = args.backend
    env["TMPDIR"] = str(args.output_dir / "temporary")
    Path(env["TMPDIR"]).mkdir()
    verify_installed_reader(
        args.reader_python, args.wheel, args.output_dir / "installed-reader.json", env
    )
    start = datetime.now(UTC) - timedelta(seconds=2)
    end = start + timedelta(minutes=10)
    population = [
        {"id": identity, "epoch": epoch, "input": identity}
        for identity in ("alpha", "beta")
        for epoch in (1, 2)
    ]
    write_json(
        args.output_dir / "selection-before-execution.json",
        {
            "readerSourceCommit": args.reader_source_commit,
            "readerSourceTree": git(args.reader_root, ["rev-parse", "HEAD^{tree}"]),
            "readerWheelSha256": WHEEL_SHA256,
            "readerModuleSha256": MODULE_SHA256,
            "hostSourceCommit": HOST_COMMIT,
            "hostSourceTree": HOST_TREE,
            "hostNativeAbbreviation": source_abbrev,
            "hostSourceOrigin": args.host_origin,
            "expectedInspect": INSPECT_VERSION,
            "expectedSamples": population,
            "notBefore": start.isoformat(),
            "notAfter": end.isoformat(),
            "backend": args.backend,
            "providerCredentialsRemoved": True,
        },
    )
    native_dir = args.output_dir / "native"
    command(
        [
            str(args.host_python),
            "-m",
            "examples.evidence_publication.native",
            "--output-dir",
            str(native_dir),
        ],
        args.host_root,
        args.output_dir / "native-output.txt",
        env,
    )
    capture = capture_digests(native_dir)
    write_json(args.output_dir / "consumer-capture.json", capture)
    policy_path = args.output_dir / "policy.json"
    write_json(
        policy_path,
        {
            "profile": "control-arena-echo-submit-v0",
            "logSha256": capture["json_sha256"],
            "expectedSource": {
                "type": "git",
                "origin": args.host_origin,
                "commit": source_abbrev,
                "dirty": False,
            },
            "selectedSourceCommit": HOST_COMMIT,
            "expectedInspect": INSPECT_VERSION,
            "expectedSamples": population,
            "notBefore": start.isoformat(),
            "notAfter": end.isoformat(),
        },
    )
    command(
        [
            str(args.reader_python),
            "-I",
            "-m",
            "probity_control_arena_reader",
            "--log",
            str(native_dir / "control-arena.json"),
            "--policy",
            str(policy_path),
        ],
        args.output_dir,
        args.output_dir / "report.json",
        env,
    )


if __name__ == "__main__":
    main()
