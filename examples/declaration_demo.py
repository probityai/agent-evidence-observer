"""Retain declaration/runtime/action/effect crosswalk controls for one file write."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from probity_observer import Broker, LedgerWitness, SigningKey
from probity_observer.authorization import (
    ActionRequest,
    AuthorizedAction,
    AuthorizedBroker,
    GrantPolicy,
    issue_grant,
    verify_grant,
)
from probity_observer.declaration import (
    EffectObservation,
    ManifestProjection,
    RuntimeObservation,
    check_crosswalk,
    project_cose_manifest,
    project_manifest,
    sha256_bytes,
    tool_catalog_digest,
)

FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures/declaration"
NATIVE_REVISION = "fed9aeb091e4c77e0b40e12e959bee30b52e3c75"


def _json_bytes(value: Any) -> bytes:
    """Serialize retained fixture values; these are not native signing bytes."""
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def reference_manifest() -> tuple[dict[str, Any], dict[str, bytes]]:
    """Build a full local native-shaped fixture with actual artifact digests."""
    files = {
        "system_prompt": b"Replace only the authorized local report.\n",
        "policy_bundle": b"local exact-action fixture policy\n",
        "model": b"model-byte-fixture-not-a-trained-model\n",
    }
    tool = {
        "tool_id": "org.probity.files.replace",
        "tool_name": "replace",
        "endpoint_id": "spiffe://lab.example/broker",
        "version": "1.0.0",
        "schema_hash": sha256_bytes(b"exact target and replacement bytes"),
        "description_hash": sha256_bytes(b"replace one local file"),
    }
    catalog = {
        "tools": [tool],
        "catalog_hash": tool_catalog_digest([tool]),
        "allow_dynamic_registration": False,
        "rug_pull_policy": "deny-and-alert",
        "bound_at": "2026-10-01T00:00:00Z",
    }
    files["tool_manifest"] = _json_bytes(catalog)
    return {
        "@context": "https://manifest.agentrust-io.com/v0.2/context.json",
        "@type": "AgentManifest",
        "version": "0.2",
        "manifest_id": "019236ab-cdef-7000-8000-000000000001",
        "agent_id": "spiffe://lab.example/agent",
        "agent_instance_id": "fixture-instance-1",
        "issued_at": "2026-10-01T00:00:00Z",
        "expires_at": "2026-10-02T00:00:00Z",
        "issuer": "spiffe://lab.example/fixture-issuer",
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {
                "hash": sha256_bytes(files["system_prompt"]),
                "hash_algorithm": "SHA-256",
                "version": "1.0.0",
                "classification": "public",
                "bound_at": "2026-10-01T00:00:00Z",
            },
            "policy_bundle": {
                "hash": sha256_bytes(files["policy_bundle"]),
                "policy_language": "cedar",
                "version": "1.0.0",
                "enforcement_mode": "enforce",
                "bound_at": "2026-10-01T00:00:00Z",
            },
            "tool_manifest": catalog,
            "model_identity": {
                "provider": "local-fixture",
                "model_id": "byte-fixture",
                "version": "fixture-v1",
                "deployment_type": "local",
                "model_hash": sha256_bytes(files["model"]),
                "model_attestation_type": "hash-bound",
                "bound_at": "2026-10-01T00:00:00Z",
            },
        },
    }, files


def _runtime_from_files(
    directory: Path, payload: bytes, manifest: dict[str, Any]
) -> RuntimeObservation:
    """Read the retained local files; do not call them hardware measurements."""
    bindings = tuple(
        (name, sha256_bytes((directory / name).read_bytes()))
        for name in ("system_prompt", "policy_bundle")
    )
    catalog = json.loads((directory / "tool_manifest").read_bytes())
    bindings += (("tool_manifest", tool_catalog_digest(catalog["tools"])),)
    return RuntimeObservation(
        manifest["agent_id"],
        manifest["agent_instance_id"],
        sha256_bytes(payload),
        bindings,
        "fixture-v1",
        sha256_bytes((directory / "model").read_bytes()),
        "declaration-run-1",
        "same-operator-file-readback-fixture",
    )


def _execute_action(
    output: Path, manifest: dict[str, Any]
) -> tuple[AuthorizedAction, EffectObservation, dict[str, Any], AuthorizedAction]:
    """Apply one signed-grant broker write and separately read its target."""
    content = b"one declaration-linked effect\n"
    request = ActionRequest(
        "declaration-run-1",
        "attempt-1",
        "request-1",
        "tenant-a",
        manifest["agent_id"],
        "org.probity.files.replace",
        "/work/report.txt",
        hashlib.sha256(content).hexdigest(),
    )
    issuer, observer, witness_key = (SigningKey.generate() for _ in range(3))
    now = datetime.now(UTC).replace(microsecond=0)
    policy = GrantPolicy(issuer.public_hex)
    grant = issue_grant(
        request, issuer, issued_at=now, expires_at=now + timedelta(minutes=5)
    )
    action = verify_grant(grant, request, policy, now=now)
    alternate_request = replace(request, tool_id="org.other.files.replace")
    alternate_grant = issue_grant(
        alternate_request, issuer, issued_at=now, expires_at=now + timedelta(minutes=5)
    )
    alternate_action = verify_grant(alternate_grant, alternate_request, policy, now=now)
    workspace = output / "workspace"
    workspace.mkdir()
    witness = LedgerWitness(output / "ledger.jsonl", witness_key, observer.public_hex)
    authority = {
        "intervalId": request.run_id,
        "scope": "/work",
        "operation": "write-file",
    }
    broker = Broker(workspace, output / "history.jsonl", authority, observer, witness)
    authorized = AuthorizedBroker(broker, grant, policy, request)
    broker.begin()
    authorized.write(request, content)
    packet = authorized.seal()
    effect = EffectObservation(
        request.run_id,
        request.attempt_id,
        request.request_id,
        request.target_path,
        hashlib.sha256((workspace / "report.txt").read_bytes()).hexdigest(),
        "same-operator-broker-target-readback",
    )
    return (
        action,
        effect,
        {
            "grant": grant,
            "grantPolicy": asdict(policy),
            "request": asdict(request),
            "packet": packet,
            "referenceTime": now.isoformat(),
            "outsideCatalogGrant": alternate_grant,
            "outsideCatalogRequest": asdict(alternate_request),
        },
        alternate_action,
    )


def _case_results(
    projection: ManifestProjection,
    runtime: RuntimeObservation,
    action: AuthorizedAction,
    effect: EffectObservation,
    alternate_action: AuthorizedAction,
) -> dict[str, Any]:
    """Keep controls orthogonal so each result identifies its changed evidence."""
    baseline = {"runtime": runtime, "action": action, "effect": effect}
    changed = dict(runtime.artifact_hashes)
    changed["policy_bundle"] = "sha256:" + "0" * 64
    variations = {
        "matched-local-fixture": {},
        "runtime-digest-drift": {
            "runtime": replace(runtime, artifact_hashes=tuple(changed.items()))
        },
        "wrong-live-instance": {
            "runtime": replace(runtime, agent_instance_id="fixture-instance-2")
        },
        "declared-tool-not-approved-operation": {"action": alternate_action},
        "effect-bytes-differ": {"effect": replace(effect, content_sha256="0" * 64)},
        "effect-target-differs": {
            "effect": replace(effect, target_path="/work/other.txt")
        },
        "missing-effect": {"effect": None},
        "missing-runtime": {"runtime": None},
        "missing-grant": {"action": None},
    }
    return {
        name: check_crosswalk(projection, **(baseline | variation))
        for name, variation in variations.items()
    }


def _verify_sdk_source(root: Path) -> dict[str, Any]:
    """Check every retained upstream module against its exact Git blob pin."""
    pins = json.loads((FIXTURES / "native-source-pins.json").read_bytes())
    if pins["revision"] != NATIVE_REVISION:
        raise ValueError("native source revision differs")
    for entry in pins["files"]:
        data = (root / entry["path"]).read_bytes()
        header = f"blob {len(data)}\0".encode()
        if hashlib.sha1(header + data).hexdigest() != entry["git_blob_sha"]:
            raise ValueError("native SDK source blob differs: " + entry["path"])
    return {
        "repository": pins["repository"],
        "revision": pins["revision"],
        "moduleCount": len(pins["files"]),
        "gitBlobPinsVerified": True,
    }


def _native_result(envelope: bytes, context: dict[str, Any]) -> dict[str, Any]:
    """Call the native verifier with explicit fixture trust and runtime context."""
    from agent_manifest import RevocationStore, VerificationContext, verify_manifest

    return verify_manifest(
        envelope, VerificationContext(**context), RevocationStore()
    ).model_dump(mode="json")


def _retain_native_source(sdk_root: Path, output: Path) -> None:
    pins_bytes = (FIXTURES / "native-source-pins.json").read_bytes()
    pins = json.loads(pins_bytes)
    (output / "source-pins.json").write_bytes(pins_bytes)
    for entry in pins["files"]:
        destination = output / "source" / entry["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((sdk_root / entry["path"]).read_bytes())
    for name in ("LICENSE", "NOTICE"):
        (output / "source" / name).write_bytes((FIXTURES / name).read_bytes())


def _run_native(output: Path, sdk_root: Path) -> dict[str, Any]:
    """Rerun the exact upstream COSE vector and retain native negative controls."""
    source = _verify_sdk_source(sdk_root)
    sys.path.insert(0, str(sdk_root / "python/src"))
    import agent_manifest
    from agent_manifest import verify_cose_manifest

    expected_module = sdk_root / "python/src/agent_manifest/__init__.py"
    if Path(agent_manifest.__file__).resolve() != expected_module.resolve():
        raise RuntimeError(
            "loaded native SDK does not match the pinned source checkout"
        )

    vector_bytes = (FIXTURES / "AM-VEC-COSE-001.json").read_bytes()
    if (
        hashlib.sha1(f"blob {len(vector_bytes)}\0".encode() + vector_bytes).hexdigest()
        != "687d8f736c96b4286e4597ccaa5dfd7e138ec0ae"
    ):
        raise ValueError("native vector bytes differ from owner pin")
    vector = json.loads(vector_bytes)
    envelope = bytes.fromhex(vector["envelope_hex"])
    context = vector["context"]
    appraisal = verify_cose_manifest(envelope, context["trusted_keys"])
    projection = project_cose_manifest(
        envelope,
        expected_sha256=sha256_bytes(envelope),
        trusted_keys=context["trusted_keys"],
    )
    tampered = envelope[:-1] + bytes([envelope[-1] ^ 1])
    wrong_policy = copy.deepcopy(context)
    wrong_policy["policy_bundle_hash"] = "sha256:" + "0" * 64
    missing_keys = copy.deepcopy(context)
    missing_keys["trusted_keys"] = {}
    results = {
        "owner-vector": _native_result(envelope, context),
        "substituted-signature": _native_result(tampered, context),
        "runtime-policy-drift": _native_result(envelope, wrong_policy),
        "missing-trusted-keys": _native_result(envelope, missing_keys),
    }
    expected = {
        "owner-vector": "VALID",
        "substituted-signature": "MISMATCH",
        "runtime-policy-drift": "MISMATCH",
        "missing-trusted-keys": "UNVERIFIABLE",
    }
    _assert_native_results(results, expected)
    if results["substituted-signature"]["signature_verified"]:
        raise RuntimeError("substituted native signature was verified")
    native_output = output / "native"
    native_output.mkdir()
    _retain_native_source(sdk_root, native_output)
    (native_output / "owner-vector.json").write_bytes(vector_bytes)
    (native_output / "envelope.cose").write_bytes(envelope)
    (native_output / "substituted-signature.cose").write_bytes(tampered)
    (native_output / "contexts.json").write_bytes(
        _json_bytes(
            {
                "original": context,
                "wrong-policy": wrong_policy,
                "missing-keys": missing_keys,
            }
        )
    )
    return {
        "source": source,
        "fixtureTrust": "owner vector public test key; not production issuer authority",
        "signatureVerified": appraisal.verified,
        "payloadSha256": appraisal.manifest_hash,
        "projection": asdict(projection),
        "results": results,
        "actionCrosswalk": check_crosswalk(
            projection, runtime=None, action=None, effect=None
        ),
    }


def _assert_native_results(results: dict[str, Any], expected: dict[str, str]) -> None:
    """Reject a changed native result rather than rewriting it as a pass."""
    for name, status in expected.items():
        if results[name]["result"] != status:
            raise RuntimeError(
                f"native {name}: expected {status}, got {results[name]['result']}"
            )


def _assert_case_outcomes(cases: dict[str, Any]) -> None:
    """Every control must produce its expected outcome, not just the baseline."""
    expected = {
        "matched-local-fixture": "matched",
        "runtime-digest-drift": "refused",
        "wrong-live-instance": "refused",
        "declared-tool-not-approved-operation": "refused",
        "effect-bytes-differ": "refused",
        "effect-target-differs": "refused",
        "missing-effect": "incomplete",
        "missing-runtime": "incomplete",
        "missing-grant": "incomplete",
    }
    for name, outcome in expected.items():
        if cases[name]["outcome"] != outcome:
            raise RuntimeError("crosswalk control did not meet its outcome: " + name)


def run_demo(output: Path, *, native_sdk_root: Path | None = None) -> dict[str, Any]:
    """Run all reference controls into a new directory; retain actual inputs.

    Parameters
    ----------
    output : Path
        New or empty directory; existing results are never overwritten.
    native_sdk_root : Path or None
        Optional exact pinned upstream checkout. Every Python module is checked.

    Returns
    -------
    dict
        Local comparison results and, when requested, fresh native SDK results.
    """
    if output.exists() and any(output.iterdir()):
        raise ValueError("declaration output directory must be empty")
    output.mkdir(parents=True, exist_ok=True)
    directory = output / "artifacts"
    directory.mkdir()
    manifest, artifacts = reference_manifest()
    for name, data in artifacts.items():
        (directory / name).write_bytes(data)
    payload = _json_bytes(manifest)
    (output / "manifest-payload.json").write_bytes(payload)
    projection = project_manifest(payload, expected_sha256=sha256_bytes(payload))
    runtime = _runtime_from_files(directory, payload, manifest)
    action, effect, action_inputs, alternate_action = _execute_action(output, manifest)
    cases = _case_results(projection, runtime, action, effect, alternate_action)
    _assert_case_outcomes(cases)
    report = {
        "fixtureKind": (
            "same-operator reference case; no trained model or isolation claim"
        ),
        "payloadSha256": sha256_bytes(payload),
        "cases": cases,
        "native": {"status": "not-run"},
        "limits": [
            "comparisons are not native validity or consumer admission",
            "different local keys do not establish independent custody",
            "no hardware measurement or complete runtime history",
        ],
    }
    if native_sdk_root is not None:
        report["native"] = _run_native(output, native_sdk_root)
    retained = {
        "runtime.json": asdict(runtime),
        "effect.json": asdict(effect),
        "action-inputs.json": action_inputs,
        "results.json": report,
    }
    for name, value in retained.items():
        (output / name).write_bytes(_json_bytes(value))
    manifest = {
        path.relative_to(output).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in output.rglob("*")
        if path.is_file()
    }
    (output / "file-manifest.json").write_bytes(_json_bytes({"fileSha256": manifest}))
    return report


def main() -> int:
    """Run the retained reference cases and optional native COSE controls."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--native-sdk-root", type=Path)
    arguments = parser.parse_args()
    report = run_demo(arguments.output, native_sdk_root=arguments.native_sdk_root)
    print(
        json.dumps(
            {
                "output": str(arguments.output),
                "outcomes": {
                    name: result["outcome"] for name, result in report["cases"].items()
                },
                "nativeExecuted": arguments.native_sdk_root is not None,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
