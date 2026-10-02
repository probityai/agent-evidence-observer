"""Prepare an external, reviewable host selection before candidate execution.

Run this trusted setup with the normally installed Python environment. It checks
the original eight source snapshots, the installed wheels and selected native
tools, then creates distinct host keys outside candidate and retained-run bytes.
The operator must select the resulting manifest hash separately when invoking
:mod:`run_host`. No release, identity resolution, or independent custody follows.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import os
import site
import sys
from pathlib import Path
from typing import Any

from trust import (HOST_SCHEMA, OPA_SHA256, PROGRAMS, SOURCE_SHA256, check_source_file,
                   file_binding, installation_file_names, read_json, refuse, sha256,
                   validate_sources, write_json)

PROFILE = Path(__file__).resolve().parent
DIST_PACKAGES = {
    "agent-evidence-observer": "probity_observer",
    "agent-evidence-vectors": "agent_evidence_vectors",
    "probity-verify": "probity_verify",
}
SUBSTRATE_KEY = "496cbe15e391eccd3a0864f2709df0eeb4f5b6c1bad750c95cc80ee49bceae62"


def installed_snapshot() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Bind and close every file in the selected site-packages directories.

    Returns
    -------
    files, closures : tuple of lists
        Byte commitments and exact file-name closures for all selected
        site-packages roots, including every dependency, startup hook, dist-info
        and existing bytecode. The three component versions remain separately
        recorded rather than conflated with package-root closure.
    """
    bindings: dict[str, dict[str, Any]] = {}
    closures = []
    for directory in site.getsitepackages():
        root = Path(directory).resolve(strict=True)
        files = sorted(installation_file_names(root))
        for name in files:
            binding = file_binding(root / name)
            bindings[binding["path"]] = binding
        closures.append({"root": str(root), "files": files})
    return list(bindings.values()), closures


def source_snapshot(sources: Path, output: Path) -> Path:
    """Copy only authenticated original tracked bytes into an exclusive snapshot.

    Wheel build products remain in builder checkouts and cannot become runtime
    source selection. A fresh exact-file snapshot avoids relying on deletion or
    ignoring build directories in the runtime closure. All source hashes and
    declared revisions remain the original public selection.
    """
    if sha256((PROFILE / "SOURCE-SELECTION.json").read_bytes()) != SOURCE_SHA256:
        refuse("original component source selection differs")
    selection = read_json(PROFILE / "SOURCE-SELECTION.json")
    output.mkdir()
    for name, component in selection["components"].items():
        root = sources / name
        for relative, expected in component["files"].items():
            check_source_file(root, relative, expected)
            target = output / name / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as destination:
                destination.write((root / relative).read_bytes())
    return output


def check_python_mapping(source: Path, installed: Path, distribution: str) -> None:
    """Refuse an installed component module outside its frozen wheel mapping."""
    expected = {str(path.relative_to(source)) for path in source.rglob("*.py")}
    if distribution == "agent-evidence-vectors":
        expected.add("run_vectors.py")
    actual = {str(path.relative_to(installed)) for path in installed.rglob("*.py")}
    if actual != expected:
        refuse("installed component Python file mapping differs from pinned source")


def bind_python_sources(sources: Path) -> None:
    """Require the installed component code to equal the frozen source files.

    Parameters
    ----------
    sources : Path
        Original checked component checkouts. Both normal setuptools package
        mappings and Vectors' explicit wheel mapping are authenticated.
    """
    mappings = {
        "agent-evidence-observer": ("src", "probity_observer"),
        "probity-verify": ("src", "probity_verify"),
        "agent-evidence-vectors": ("packaging", "agent_evidence_vectors"),
    }
    for distribution, (directory, package) in mappings.items():
        dist = importlib.metadata.distribution(distribution)
        source = sources / distribution / directory / package
        installed_root = Path(dist.locate_file(package))
        check_python_mapping(source, installed_root, distribution)
        for path in source.rglob("*.py"):
            relative = path.relative_to(source)
            installed = Path(dist.locate_file(package)) / relative
            if path.read_bytes() != installed.read_bytes():
                refuse("installed component code differs from pinned source")
    rail = sources / "agent-evidence-vectors" / "packaging" / "run_vectors.py"
    dist = importlib.metadata.distribution("agent-evidence-vectors")
    if rail.read_bytes() != Path(dist.locate_file("agent_evidence_vectors/run_vectors.py")).read_bytes():
        refuse("installed Vectors rail differs from pinned source")


def create_keys(folder: Path) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """Create distinct test authority roles outside candidates and run archives.

    Parameters
    ----------
    folder : Path
        Fresh host-only key directory. Random seeds are retained there, never
        emitted into logs or public artifacts. They are disposable example
        authority, not production issuer identity.

    Returns
    -------
    seed_bindings, public_keys : tuple of dictionaries
        Selected private seed-file commitments and separate public-key pins.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    folder.mkdir(mode=0o700)
    bindings, public = {}, {}
    for role in ("envelope", "issuer", "service"):
        seed = os.urandom(32)
        path = folder / (role + ".seed")
        with path.open("xb") as output:
            output.write(seed.hex().encode() + b"\n")
        path.chmod(0o600)
        bindings[role] = file_binding(path)
        key = Ed25519PrivateKey.from_private_bytes(seed)
        public[role] = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        (folder / (role + ".public")).write_text(public[role] + "\n")
    return bindings, public


def coverage_policy(sources: Path) -> dict[str, Any]:
    """Select literal Atlas provenance nonclaims and a separately bound record.

    The source is the stable original provenance, rather than candidate text or
    a generated capture. The record retains the same selected literal limits.
    The witness's authority remains an explicit same-operator statement.
    """
    source = sources / "agent-evidence-atlas/experiments/authority-recovery-2026-10-02/provenance.json"
    record = PROFILE / "fixtures/coverage-record.txt"
    return {
        "schema_version": "probity-policy/v1",
        "witnesses": {"atlas-retained-provenance": {
            "artifact": "source", "sha256": sha256(source.read_bytes()),
            "captured_at": "2026-10-02T00:00:00Z", "source_format": "text_utf8/v1",
            "source_url": "https://github.com/probityai/agent-evidence-atlas/blob/58c89e18033a3c5fdd10d1a9b65497e25093dcc8/experiments/authority-recovery-2026-10-02/provenance.json",
            "authority": "Host-selected existing Probity-operated provenance bytes; source commit date window is an author selection, not independent capture custody",
        }},
        "assessments": {"atlas-provenance-nonclaims": {
            "claim_type": "source_text_coverage/v1", "source_witness": "atlas-retained-provenance",
            "record_artifact": "record", "record_sha256": sha256(record.read_bytes()),
            "record_version": "eight-component-selected-nonclaims-v1",
            "source_window": {"start": "2026-10-02T00:00:00Z", "end": "2026-10-02T23:59:59Z"},
            "required_spans": [
                {"id": "independent-custody", "text": '"independentEffectCustody": "not-established"'},
                {"id": "outside-recurring-use", "text": '"outsideRecurringUse": "not-established"'},
            ],
        }},
    }


def host_policy(sources: Path, public: dict[str, str]) -> dict[str, Any]:
    """Select signer pins, admission obligations, and effect identity externally."""
    return {
        "schema": "probity-eight-component-host-policy-v1", "publicKeys": public,
        "substratePublicKeys": [SUBSTRATE_KEY], "requiredVectorTier": "attested",
        "opa": {"consumer": {
            "expected_corpus_digest": "cc1bdef2ffca96d86a636e5a9fb27a4a111836773e0dd1368d8de94f413979be",
            "expected_substrate_digest": "018bbaf3710e526b0653abafbd3bd3c3356150d747db166021f1e107446c85bb",
            "expected_catch_policy_digest": "846c2ccf97b5a5f4da335fe733e7f4f786ffd224ce582fb5a9685d52184abdc3",
            "allowed_network_postures": {"sinkhole": True}, "demanded_classes": ["XA"],
            "accepted_results": ["pass"],
        }},
        "verify": coverage_policy(sources),
        "request": {"run_id": "eight-component-host", "attempt_id": "host-selected",
                    "request_id": "single-content-ticket", "tenant_id": "probity-example",
                    "principal_id": "host-operator", "tool_id": "ticket-update",
                    "target_path": "/work/tickets/eight-component"},
        "grantValiditySeconds": 60, "referenceTime": "2026-10-02T12:00:00Z", "effectOffsetSeconds": 10,
        "doesNotAssert": ["independent-effect-custody", "outside-recurring-adoption",
                          "production-issuer-identity", "general-containment",
                          "blind-evaluation", "distributed-exactly-once", "power-loss-recovery"],
    }


def prepare(sources: Path, tools: dict[str, Path], wheels: Path, output: Path) -> Path:
    """Create the host configuration and expose its separately selectable hash.

    Parameters
    ----------
    sources : Path
        Frozen original checkouts validated before setup imports.
    tools : dict[str, Path]
        Actual ordinarily installed Rust byte gate and official pinned OPA.
    wheels : Path
        Ordinary source-built Observer, Vectors, and Verify wheels retained
        separately from source revision and published version status.
    output : Path
        New external host configuration directory, outside candidate outputs.

    Returns
    -------
    Path
        Complete installation manifest. Its hash is printed by :func:`main`.
    """
    sources = sources.resolve(strict=True)
    output = output.resolve()
    output.mkdir(mode=0o700)
    sources = source_snapshot(sources, output / "selected-sources")
    selection = validate_sources(PROFILE, sources)
    bind_python_sources(sources)
    seeds, public = create_keys(output / "keys")
    public_files = {role: file_binding(output / "keys" / (role + ".public")) for role in public}
    policy_path = output / "policy.json"
    write_json(policy_path, host_policy(sources, public))
    selected_tools = {name: file_binding(path) for name, path in tools.items()}
    if selected_tools["opa"]["sha256"] != OPA_SHA256:
        refuse("OPA official release selection differs")
    python = file_binding(Path(sys.executable))
    python["invocationPath"] = sys.executable
    launcher = [file_binding(Path(sys.prefix) / "pyvenv.cfg")] if sys.prefix != sys.base_prefix else []
    installed, closures = installed_snapshot()
    versions = {name: importlib.metadata.version(name) for name in DIST_PACKAGES}
    programs = [file_binding(PROFILE / name) for name in PROGRAMS]
    policy = file_binding(policy_path)
    wheel_files = [file_binding(path) for path in sorted(wheels.glob("*.whl"))]
    manifest = {
        "schema": HOST_SCHEMA, "profile": str(PROFILE), "sources": str(sources),
        "sourceSelectionSha256": sha256((PROFILE / "SOURCE-SELECTION.json").read_bytes()),
        "componentHeads": {name: data["head"] for name, data in selection["components"].items()},
        "python": python, "tools": selected_tools, "programs": programs,
        "policy": policy, "seedFiles": seeds, "publicFiles": public_files, "wheels": wheel_files,
        "installedFiles": installed, "packageClosures": closures, "componentVersions": versions,
        "launcherConfiguration": launcher,
        "selectedFiles": [python, policy, *launcher, *programs, *selected_tools.values(), *seeds.values(),
                          *public_files.values(), *wheel_files],
    }
    path = output / "installation.json"
    write_json(path, manifest)
    return path


def main() -> None:
    """Prepare a fresh explicit host selection from command-line host paths."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sources", "byte-gate", "opa", "wheels", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    path = prepare(args.sources, {"byteGate": args.byte_gate, "opa": args.opa}, args.wheels, args.output)
    print(sha256(path.read_bytes()))


if __name__ == "__main__":
    main()
