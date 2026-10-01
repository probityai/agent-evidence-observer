"""Compare a pinned Manifest payload with supplied runtime and action evidence.

This is a proposed reference crosswalk, not Manifest or TRACE conformance.
Projection does not authenticate an issuer. Native COSE signature checking is
available separately; neither operation establishes hardware or custody.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any, Literal, NoReturn

from cryptography.exceptions import InvalidSignature

from .authorization import AuthorizedAction
from .crypto import VerificationError

LOGGER = logging.getLogger(__name__)
PROFILE = "probity-declaration-action-reference-v0"
MAX_PAYLOAD_BYTES = 65536
MAX_NODES = 2048
MAX_DEPTH = 12
MAX_TOOLS = 64
HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
ARTIFACT_PATHS = {
    "system_prompt": "hash",
    "policy_bundle": "hash",
    "tool_manifest": "catalog_hash",
    "supply_chain": "container_image_digest",
}
Status = Literal["matched", "mismatch", "missing", "unsupported"]


def _refuse(reason: str) -> NoReturn:
    """Reject a bounded reason without logging candidate bytes."""
    LOGGER.warning("declaration crosswalk refused: %s", reason)
    raise VerificationError(reason)


def sha256_bytes(data: bytes) -> str:
    """Return the Manifest-style SHA-256 identifier of exact bytes."""
    if not isinstance(data, bytes):
        _refuse("hash input must be bytes")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _hash(value: Any, field: str) -> str:
    """Require the SHA-256 subset supported by this reference profile."""
    if not isinstance(value, str) or HASH.fullmatch(value) is None:
        _refuse(f"{field} must be a lowercase sha256 identifier")
    return value


def _text(value: Any, field: str) -> str:
    """Require a bounded identifier without control characters."""
    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        _refuse(f"{field} must be a bounded nonempty identifier")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        _refuse(f"{field} contains a control character")
    return value


def _object(value: Any, field: str) -> dict[str, Any]:
    """Require an object where the pinned native shape uses one."""
    if not isinstance(value, dict):
        _refuse(f"{field} must be an object")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate keys rather than choosing a parser-dependent value."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _refuse("manifest contains duplicate JSON keys")
        result[key] = value
    return result


def _children(value: Any) -> list[Any]:
    if isinstance(value, dict):
        return list(value.values())
    if isinstance(value, list):
        return value
    return []


def _bounded_structure(value: Any) -> None:
    """Limit parsed nesting and node count independently of byte length."""
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            _refuse("manifest exceeds structural limits")
        pending.extend((child, depth + 1) for child in _children(item))


def _load_payload(payload: bytes) -> dict[str, Any]:
    """Parse finite UTF-8 JSON without duplicate keys or nonfinite numbers."""
    _bounded_bytes(payload, "manifest payload")
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: _refuse("nonfinite JSON number"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        _refuse(f"manifest JSON cannot be parsed: {type(error).__name__}")
    _bounded_structure(value)
    return _object(value, "manifest")


def _bounded_bytes(data: Any, name: str) -> None:
    """Reject oversized candidates before hashing or native parsing."""
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_PAYLOAD_BYTES:
        _refuse(f"{name} exceeds byte limit or is empty")


def _tool_leaf(tool: dict[str, Any]) -> tuple[str, bytes]:
    """Compute the section 3.2.3 SHA-256 leaf from native tool fields."""
    identifier = _text(tool.get("tool_id"), "tool_id")
    if not identifier.isascii() or "\x00" in identifier:
        _refuse("tool_id is outside the ASCII reference subset")
    schema = bytes.fromhex(_hash(tool.get("schema_hash"), "schema_hash")[7:])
    description = bytes.fromhex(
        _hash(tool.get("description_hash"), "description_hash")[7:]
    )
    leaf = hashlib.sha256(
        b"\x00" + identifier.encode() + b"\x00" + schema + description
    )
    return identifier, leaf.digest()


def _merkle_root(leaves: list[bytes]) -> bytes:
    """Compute the RFC 9162 root, without duplicating an odd final leaf."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return hashlib.sha256(
        b"\x01" + _merkle_root(leaves[:split]) + _merkle_root(leaves[split:])
    ).digest()


def tool_catalog_digest(tools: list[dict[str, Any]]) -> str:
    """Compute the bounded native catalog commitment, sorting by tool_id.

    Parameters
    ----------
    tools : list of dict
        At most 64 native entries with tool_id, schema_hash and description_hash.

    Returns
    -------
    str
        sha256-prefixed RFC 9162 root.
    """
    if not isinstance(tools, list) or len(tools) > MAX_TOOLS:
        _refuse("tool catalog exceeds its entry limit")
    entries = sorted(_tool_leaf(_object(tool, "tool")) for tool in tools)
    if len({identifier for identifier, _ in entries}) != len(entries):
        _refuse("tool catalog contains duplicate tool identifiers")
    return "sha256:" + _merkle_root([leaf for _, leaf in entries]).hex()


def _catalog(artifacts: dict[str, Any]) -> tuple[str, ...] | None:
    """Distinguish an absent catalog from a valid, empty catalog."""
    if "tool_manifest" not in artifacts:
        return None
    catalog = _object(artifacts["tool_manifest"], "tool_manifest")
    tools = catalog.get("tools")
    computed = tool_catalog_digest(tools)
    if computed != _hash(catalog.get("catalog_hash"), "catalog_hash"):
        _refuse("tool catalog hash differs from its declared entries")
    return tuple(sorted(tool["tool_id"] for tool in tools))


def _artifact_hashes(artifacts: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """Project only supported native fields, without validating a full schema."""
    result = []
    for name, field in ARTIFACT_PATHS.items():
        if name in artifacts:
            binding = _object(artifacts[name], name)
            result.append((name, _hash(binding.get(field), f"{name}.{field}")))
    return tuple(sorted(result))


@dataclass(frozen=True, slots=True)
class ManifestProjection:
    """Immutable projection of exact native payload bytes, not an appraisal."""

    payload_sha256: str
    version: str
    manifest_id: str
    agent_id: str
    agent_instance_id: str | None
    artifact_hashes: tuple[tuple[str, str], ...]
    tool_ids: tuple[str, ...] | None
    model_version: str | None
    model_attestation_type: str | None
    model_hash: str | None


def _model_hash(model: dict[str, Any], kind: str | None) -> str | None:
    model_hash = model.get("model_hash")
    if model_hash is not None:
        model_hash = _hash(model_hash, "model_hash")
    if kind == "provider-asserted" and model_hash is not None:
        _refuse("provider-asserted model cannot carry a weight hash")
    if kind == "hash-bound" and model_hash is None:
        _refuse("hash-bound model is missing its weight hash")
    return model_hash


def _model_fields(
    artifacts: dict[str, Any],
) -> tuple[str | None, str | None, str | None]:
    """Keep provider assertions distinct from hash-bound model declarations."""
    if "model_identity" not in artifacts:
        return None, None, None
    model = _object(artifacts["model_identity"], "model_identity")
    version = _text(model.get("version"), "model_identity.version")
    kind = model.get("model_attestation_type")
    if kind is not None and kind not in ("provider-asserted", "hash-bound"):
        _refuse("model attestation type is unsupported")
    return version, kind, _model_hash(model, kind)


def project_manifest(payload: bytes, *, expected_sha256: str) -> ManifestProjection:
    """Map a pinned JSON payload; signature, validity and revocation stay separate.

    Parameters
    ----------
    payload : bytes
        Exact native JSON payload, at most 64 KiB. A COSE envelope is not JSON.
    expected_sha256 : str
        Consumer-selected digest acquired separately from the candidate bytes.

    Returns
    -------
    ManifestProjection
        Bounded native field mapping. Missing native fields remain absent.

    Raises
    ------
    VerificationError
        On pin mismatch, malformed supported fields, or unsupported version.
    """
    _bounded_bytes(payload, "manifest payload")
    expected = _hash(expected_sha256, "expected_sha256")
    if sha256_bytes(payload) != expected:
        _refuse("manifest payload differs from the expected pin")
    manifest = _load_payload(payload)
    version = manifest.get("version")
    if version not in ("0.1", "0.2"):
        _refuse("manifest version is unsupported")
    artifacts = _object(manifest.get("artifacts"), "artifacts")
    instance = manifest.get("agent_instance_id")
    if instance is not None:
        instance = _text(instance, "agent_instance_id")
    return ManifestProjection(
        expected,
        version,
        _text(manifest.get("manifest_id"), "manifest_id"),
        _text(manifest.get("agent_id"), "agent_id"),
        instance,
        _artifact_hashes(artifacts),
        _catalog(artifacts),
        *_model_fields(artifacts),
    )


def project_cose_manifest(
    envelope: bytes, *, expected_sha256: str, trusted_keys: Mapping[str, str]
) -> ManifestProjection:
    """Verify a native COSE signature before projecting its exact payload.

    This optional path calls the installed upstream Agent Manifest SDK. It does
    not verify hardware, unprotected headers, issuer entitlement, deployment,
    revocation or freshness. The example records the SDK source revision.
    Invalid signatures become VerificationError; native structure, version and
    key errors propagate. A missing SDK is a dependency error, not a verdict.
    """
    _bounded_bytes(envelope, "COSE envelope")
    if sha256_bytes(envelope) != _hash(expected_sha256, "expected_sha256"):
        _refuse("COSE envelope differs from the expected pin")
    from agent_manifest import verify_cose_manifest

    try:
        result = verify_cose_manifest(envelope, dict(trusted_keys))
    except InvalidSignature:
        _refuse("native COSE signature is invalid")
    if not result.verified:
        _refuse("native COSE signature was not verified")
    return project_manifest(result.payload, expected_sha256=result.manifest_hash)


@dataclass(frozen=True, slots=True)
class RuntimeObservation:
    """Locally supplied runtime values; source and custody are explicit labels."""

    agent_id: str
    agent_instance_id: str | None
    manifest_sha256: str
    artifact_hashes: tuple[tuple[str, str], ...]
    model_version: str | None
    model_hash: str | None
    run_id: str
    source: str

    def __post_init__(self) -> None:
        """Reject ambiguous or malformed observed identities and digests."""
        _text(self.agent_id, "runtime.agent_id")
        _text(self.run_id, "runtime.run_id")
        _text(self.source, "runtime.source")
        _hash(self.manifest_sha256, "runtime.manifest_sha256")
        _validate_optional_text(self.agent_instance_id, "runtime.agent_instance_id")
        _validate_optional_text(self.model_version, "runtime.model_version")
        _validate_optional_hash(self.model_hash, "runtime.model_hash")
        _validate_runtime_hashes(self.artifact_hashes)


@dataclass(frozen=True, slots=True)
class EffectObservation:
    """One read-back effect, joined by run, attempt and request identifiers."""

    run_id: str
    attempt_id: str
    request_id: str
    target_path: str
    content_sha256: str
    source: str

    def __post_init__(self) -> None:
        """Require exact read-back identifiers and a bare SHA-256 byte digest."""
        for name in ("run_id", "attempt_id", "request_id", "target_path", "source"):
            _text(getattr(self, name), "effect." + name)
        if not isinstance(self.content_sha256, str):
            _refuse("effect.content_sha256 must be a bare lowercase digest")
        _hash("sha256:" + self.content_sha256, "effect.content_sha256")


def _validate_optional_text(value: Any, name: str) -> None:
    """Validate a supplied identifier without inventing absent evidence."""
    if value is not None:
        _text(value, name)


def _validate_optional_hash(value: Any, name: str) -> None:
    """Validate a supplied digest without inventing absent evidence."""
    if value is not None:
        _hash(value, name)


def _validate_runtime_hashes(bindings: tuple[tuple[str, str], ...]) -> None:
    """Require immutable, duplicate-free observed artifact names and digests."""
    if not isinstance(bindings, tuple) or len(bindings) > len(ARTIFACT_PATHS):
        _refuse("runtime artifact hashes must be a bounded tuple")
    seen = set()
    for binding in bindings:
        _validate_runtime_binding(binding, seen)


def _validate_runtime_binding(binding: Any, seen: set[str]) -> None:
    """Validate one observed artifact binding without choosing among duplicates."""
    if not isinstance(binding, tuple) or len(binding) != 2:
        _refuse("runtime artifact binding must be a pair")
    name, value = binding
    if not isinstance(name, str) or name not in ARTIFACT_PATHS or name in seen:
        _refuse("runtime artifact names are unsupported or duplicated")
    seen.add(name)
    _hash(value, "runtime." + name)


@dataclass(frozen=True, slots=True)
class CrosswalkCheck:
    """One comparison, not a consumer admission decision."""

    axis: str
    status: Status
    reason: str


def _equal(axis: str, expected: Any, observed: Any) -> CrosswalkCheck:
    """Never turn an absent expected or observed value into a match."""
    if expected is None or observed is None:
        return CrosswalkCheck(axis, "missing", "required comparison value is absent")
    if expected != observed:
        return CrosswalkCheck(axis, "mismatch", "expected and observed values differ")
    return CrosswalkCheck(axis, "matched", "exact values match")


def _runtime_checks(
    projection: ManifestProjection, runtime: RuntimeObservation
) -> list[CrosswalkCheck]:
    """Join the exact payload, subject, instance, artifact hashes and model."""
    checks = [
        _equal("manifest", projection.payload_sha256, runtime.manifest_sha256),
        _equal("subject", projection.agent_id, runtime.agent_id),
        _equal("instance", projection.agent_instance_id, runtime.agent_instance_id),
    ]
    observed = dict(runtime.artifact_hashes)
    declared = dict(projection.artifact_hashes)
    for name in ("system_prompt", "policy_bundle", "tool_manifest"):
        checks.append(_equal(name, declared.get(name), observed.get(name)))
    checks.append(
        _equal("model-version", projection.model_version, runtime.model_version)
    )
    checks.append(_model_check(projection, runtime))
    return checks


def _model_check(
    projection: ManifestProjection, runtime: RuntimeObservation
) -> CrosswalkCheck:
    """A provider assertion never becomes a hash-bound weight measurement."""
    if projection.model_attestation_type != "hash-bound":
        return CrosswalkCheck(
            "model-bytes", "unsupported", "no hash-bound model declaration"
        )
    return _equal("model-bytes", projection.model_hash, runtime.model_hash)


def _action_checks(
    projection: ManifestProjection, action: AuthorizedAction
) -> list[CrosswalkCheck]:
    """Compare supplied action fields; do not authenticate the Python object."""
    request = action.request
    checks = [_equal("action-subject", projection.agent_id, request.principal_id)]
    if projection.tool_ids is None:
        return checks + [
            CrosswalkCheck("action-tool", "missing", "tool catalog is absent")
        ]
    status: Status = "matched" if request.tool_id in projection.tool_ids else "mismatch"
    return checks + [
        CrosswalkCheck("action-tool", status, "exact tool membership checked")
    ]


def _effect_checks(
    action: AuthorizedAction, effect: EffectObservation
) -> list[CrosswalkCheck]:
    """Compare the actual read-back identity, destination and effect bytes."""
    expected = asdict(action.request)
    return [
        _equal("effect-" + name, expected[name], getattr(effect, name))
        for name in (
            "run_id",
            "attempt_id",
            "request_id",
            "target_path",
            "content_sha256",
        )
    ]


def _outcome(checks: list[CrosswalkCheck]) -> str:
    """A mismatch refuses; missing and unsupported comparisons stay incomplete."""
    states = {check.status for check in checks}
    if "mismatch" in states:
        return "refused"
    if states != {"matched"}:
        return "incomplete"
    return "matched"


def _runtime_or_missing(
    projection: ManifestProjection, runtime: RuntimeObservation | None
) -> list[CrosswalkCheck]:
    if runtime is None:
        return [CrosswalkCheck("runtime", "missing", "runtime observation is absent")]
    return _runtime_checks(projection, runtime)


def _run_id(runtime: RuntimeObservation | None) -> str | None:
    return runtime.run_id if runtime is not None else None


def _action_or_missing(
    projection: ManifestProjection,
    runtime: RuntimeObservation | None,
    action: AuthorizedAction | None,
) -> list[CrosswalkCheck]:
    if action is None:
        return [
            CrosswalkCheck(
                "authorization", "missing", "local verifier result is absent"
            )
        ]
    return _action_checks(projection, action) + [
        _equal("action-run", action.request.run_id, _run_id(runtime))
    ]


def _effect_or_missing(
    action: AuthorizedAction | None, effect: EffectObservation | None
) -> list[CrosswalkCheck]:
    if action is None or effect is None:
        return [
            CrosswalkCheck(
                "effect", "missing", "effect observation or action is absent"
            )
        ]
    return _effect_checks(action, effect)


def _source(observation: RuntimeObservation | EffectObservation | None) -> str | None:
    return observation.source if observation is not None else None


def check_crosswalk(
    projection: ManifestProjection,
    *,
    runtime: RuntimeObservation | None,
    action: AuthorizedAction | None,
    effect: EffectObservation | None,
) -> dict[str, Any]:
    """Compare declaration, supplied runtime, local verifier result and effect.

    Parameters
    ----------
    projection : ManifestProjection
        Pinned native field projection. This object is not a native appraisal.
    runtime : RuntimeObservation or None
        Explicitly labeled observed values. Labels do not establish custody.
    action : AuthorizedAction or None
        Caller-supplied local verifier result. This constructible Python object
        is not authenticated here; retained grants require separate verification.
    effect : EffectObservation or None
        Read-back values. Absence means missing evidence, not a successful write.

    Returns
    -------
    dict
        Per-axis results and a matched/refused/incomplete comparison outcome.
        A matched comparison is not permission, native validity or completeness.
    """
    checks = _runtime_or_missing(projection, runtime)
    checks += _action_or_missing(projection, runtime, action)
    checks += _effect_or_missing(action, effect)
    return {
        "profile": PROFILE,
        "outcome": _outcome(checks),
        "checks": [asdict(check) for check in checks],
        "runtimeSource": _source(runtime),
        "effectSource": _source(effect),
        "authorizationInput": (
            "caller-supplied local verifier result; signatures are not rerun"
        ),
        "scope": (
            "listed comparisons only; authenticity, permission, "
            "native validity and custody not established"
        ),
    }
