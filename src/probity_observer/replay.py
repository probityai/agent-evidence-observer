"""Replay declared native checks instead of trusting a signed success report.

This is a consumer-specific profile layered on artifact consumption records.
It preserves native input bytes and keeps signature binding, replay results,
and a durable consumer admission separate. All local custody remains PEER.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, NoReturn

from .attribution import ArtifactPin, verify_consumption
from .authorization import (
    ActionRequest,
    GrantPolicy,
    verify_authorized_packet,
    verify_grant,
)
from .crypto import VerificationError, canonical, digest, strict_loads
from .ledger import verify_ledger_head, verify_ledger_receipts

LOGGER = logging.getLogger(__name__)
PROFILE = "probity-declared-pilot-replay-v0"
MAX_INPUT_BYTES = 65_536
MAX_TOTAL_BYTES = 524_288
MAX_RECORD_BYTES = 65_536
MAX_DEPTH = 16
MAX_NODES = 4096
MAX_INPUTS = 48
MAX_MEMBERS = 12
MAX_LINES = 128
HEX = re.compile(r"[0-9a-f]{64}\Z")
GIT_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
BASE_ROLES = frozenset(
    {
        "authorization",
        "observation",
        "request",
        "grant-policy",
        "admission-policy",
        "key-pins",
        "reference-time",
        "history",
        "ledger",
        "workspace-manifest",
        "owner-manifest",
        "copy-manifest",
    }
)
CHECKER_MODULES = (
    "authorization.py",
    "crypto.py",
    "history.py",
    "ledger.py",
    "broker.py",
    "verify.py",
    "replay.py",
    "attribution.py",
)


class ReplayOutcome(StrEnum):
    """Closed outcomes; only PASS can satisfy this profile's consumer gate."""

    PASS = "pass"
    REFUSAL = "refusal"
    INVALID = "invalid"
    INCOMPLETE = "incomplete"
    ERROR = "error"
    NOT_RUN = "not-run"


def _refuse(reason: str) -> NoReturn:
    """Reject profile data without logging candidate contents or key material."""
    LOGGER.warning("pilot replay refused: %s", reason)
    raise VerificationError(reason)


def _hex(value: Any, name: str) -> None:
    """Require a lowercase SHA-256-sized digest or public key."""
    if not isinstance(value, str) or HEX.fullmatch(value) is None:
        _refuse(f"{name} must be lowercase 64-character hexadecimal")


def _name(value: Any) -> None:
    """Allow normalized relative names without filesystem aliases."""
    value = _member_text(value)
    if any(ord(item) < 33 or ord(item) == 127 for item in value):
        _refuse("member name must be a normalized relative ASCII path")
    if "\\" in value or any(part in {"", ".", ".."} for part in value.split("/")):
        _refuse("member name must be a normalized relative ASCII path")


def _member_text(value: Any) -> str:
    """Require bounded ASCII text before examining path components."""
    if not isinstance(value, str) or not value.isascii() or not 1 <= len(value) <= 128:
        _refuse("member name must be a normalized relative ASCII path")
    return value


def _members(names: tuple[str, ...], label: str) -> None:
    """Validate a finite immutable member set and disallow file/directory collisions."""
    if type(names) is not tuple or not 1 <= len(names) <= MAX_MEMBERS:
        _refuse(f"{label} must contain 1 to {MAX_MEMBERS} immutable member names")
    for name in names:
        _name(name)
    if len(set(names)) != len(names):
        _refuse(f"{label} contains repeated names")
    if any(other.startswith(name + "/") for name in names for other in names):
        _refuse(f"{label} contains colliding file and directory names")


def _git_pin(pin: ArtifactPin) -> None:
    """Apply immutable Git-object provenance only to this Git-specific profile."""
    if not isinstance(pin, ArtifactPin):
        _refuse("replay input pin must be an ArtifactPin")
    pin.fields()
    if GIT_REVISION.fullmatch(pin.revision) is None:
        _refuse("Git replay revision must be a full lowercase object id")
    if not pin.source.startswith("https://"):
        _refuse("Git replay source must be an HTTPS source reference")


@dataclass(frozen=True, slots=True)
class InputPin:
    """Bind one declared replay role to externally selected artifact provenance.

    Parameters
    ----------
    role : str
        Fixed context role or a named owner, copy, or workspace member.
    artifact : ArtifactPin
        Expected bytes and immutable Git source chosen by the consumer. The
        candidate receipt is not a source of policy or key pins.
    """

    role: str
    artifact: ArtifactPin

    def __post_init__(self) -> None:
        if not isinstance(self.role, str) or not self.role.isascii() or not self.role:
            _refuse("replay input role must be nonempty ASCII")
        _git_pin(self.artifact)


@dataclass(frozen=True, slots=True)
class ReplayPolicy:
    """Freeze the declared population, checker bytes, context, and consumer pins.

    Parameters
    ----------
    input_pins : tuple[InputPin, ...]
        Exact expected input set, including every declared fixture and workspace
        member. Its SHA-256 pins bind policy, time, keys, request, and history.
    checker_source : ArtifactPin
        Provenance and SHA-256 of :func:`checker_implementation_bytes`. This
        pins local Python sources, not a remotely attested execution runtime.
    fixture_names, workspace_names : tuple[str, ...]
        Closed file populations for the owner/copy comparison and workspace
        reconstruction. Undeclared populations are not evaluated.
    action_id, claim_digest, pinned_signer : str
        Consumer expectations used by :func:`~.attribution.verify_consumption`.
        None is learned from the candidate record.

    Notes
    -----
    This policy accepts only the local reference profile. A replay acceptance
    is not a durable admission, current-time permission, or outside custody.
    """

    input_pins: tuple[InputPin, ...]
    checker_source: ArtifactPin
    fixture_names: tuple[str, ...]
    workspace_names: tuple[str, ...]
    action_id: str
    claim_digest: str
    pinned_signer: str

    def __post_init__(self) -> None:
        _members(self.fixture_names, "fixture_names")
        _members(self.workspace_names, "workspace_names")
        _git_pin(self.checker_source)
        _declared_pins(self.input_pins, self.expected_roles)
        if not isinstance(self.action_id, str) or not 1 <= len(self.action_id) <= 128:
            _refuse("replay action id must be a bounded nonempty string")
        _hex(self.claim_digest, "claim digest")
        _hex(self.pinned_signer, "consumption signer")
        _bounded_value(self.fields())

    @property
    def expected_roles(self) -> frozenset[str]:
        """Return the exact declared roles, including named member bytes."""
        fixtures = {
            f"{kind}:{name}"
            for kind in ("owner", "copy")
            for name in self.fixture_names
        }
        workspace = {f"workspace:{name}" for name in self.workspace_names}
        return BASE_ROLES | fixtures | workspace

    @property
    def pins(self) -> dict[str, ArtifactPin]:
        """Return a fresh map rather than expose mutable policy state."""
        return {pin.role: pin.artifact for pin in self.input_pins}

    @property
    def policy_digest(self) -> str:
        """Bind every expected role, source, byte digest, and checker selection."""
        return digest(PROFILE, self.fields())

    def fields(self) -> dict[str, Any]:
        """Return the closed portable representation of consumer-selected policy."""
        return {
            "profile": PROFILE,
            "input_pins": [asdict(pin) for pin in self.input_pins],
            "checker_source": asdict(self.checker_source),
            "fixture_names": list(self.fixture_names),
            "workspace_names": list(self.workspace_names),
            "action_id": self.action_id,
            "claim_digest": self.claim_digest,
            "pinned_signer": self.pinned_signer,
        }

    @classmethod
    def from_fields(cls, value: dict[str, Any]) -> ReplayPolicy:
        """Load a retained policy after bounded parsing outside the candidate.

        Raises
        ------
        VerificationError
            If fields, nested pins, or immutable member populations are invalid.
        """
        _bounded_value(value)
        expected = {"profile", *cls.__dataclass_fields__}
        _object(value, expected, "replay policy has unexpected fields")
        if value["profile"] != PROFILE:
            _refuse("replay policy has an unsupported profile")
        try:
            pins = _input_pin_fields(value["input_pins"])
            return cls(
                pins,
                ArtifactPin(**value["checker_source"]),
                tuple(value["fixture_names"]),
                tuple(value["workspace_names"]),
                value["action_id"],
                value["claim_digest"],
                value["pinned_signer"],
            )
        except VerificationError:
            raise
        except (KeyError, TypeError, ValueError):
            _refuse("replay policy nested fields are malformed")


def _declared_pins(pins: tuple[InputPin, ...], expected_roles: frozenset[str]) -> None:
    """Require a bounded immutable pin set matching the complete declared roles."""
    if type(pins) is not tuple or len(pins) > MAX_INPUTS:
        _refuse("replay input pins must be an immutable bounded tuple")
    if not all(isinstance(pin, InputPin) for pin in pins):
        _refuse("replay input pins contain an invalid pin")
    roles = tuple(pin.role for pin in pins)
    if len(set(roles)) != len(roles) or set(roles) != expected_roles:
        _refuse("replay input roles differ from the declared profile")


def _input_pin_fields(raw: Any) -> tuple[InputPin, ...]:
    """Load nested input pins without silently dropping unrecognized fields."""
    if type(raw) is not list or len(raw) > MAX_INPUTS:
        _refuse("replay input pins must be a bounded list")
    for item in raw:
        _object(item, {"role", "artifact"}, "replay input pin has unexpected fields")
    return tuple(
        InputPin(item["role"], ArtifactPin(**item["artifact"])) for item in raw
    )


def load_replay_object(raw: bytes) -> dict[str, Any]:
    """Parse a bounded canonical replay object without dropping duplicate fields.

    Parameters
    ----------
    raw : bytes
        Exact retained JSON bytes, at most 64 KiB. Depth and node bounds also
        apply; deeply nested parser failures are explicit refusals.

    Returns
    -------
    dict[str, Any]
        An object in the native restricted canonical JSON profile.

    Raises
    ------
    VerificationError
        For duplicate members, noncanonical encoding, unsupported values or
        exceeded byte, depth or node bounds.
    """
    if type(raw) is not bytes or len(raw) > MAX_INPUT_BYTES:
        _refuse("retained replay JSON must be bounded immutable bytes")
    return _load(raw)


def checker_implementation_bytes() -> bytes:
    """Return a deterministic manifest of the local native checker source bytes.

    The consumer must acquire the expected digest and Git provenance separately.
    This fingerprints these source files, not their installation history, the
    interpreter, cryptography library, host, or already-loaded Python bytecode.
    """
    root = Path(__file__).parent
    members = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in CHECKER_MODULES
    }
    return canonical({"profile": PROFILE, "fileSha256": members})


def _bounded_value(value: Any) -> None:
    """Bound structure before recursive canonical serialization."""
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            _refuse("replay JSON exceeds depth or node bounds")
        children = _children(item)
        pending.extend((child, depth + 1) for child in children)


def _children(value: Any) -> list[Any]:
    """Enumerate JSON structure without accepting custom or cyclic containers."""
    if type(value) is dict:
        return [*value.keys(), *value.values()]
    if type(value) is list:
        return value
    if value is None or type(value) in {str, int, bool}:
        return []
    _refuse("replay value is outside the restricted JSON profile")


def _load(raw: bytes) -> dict[str, Any]:
    """Parse bounded canonical native JSON without changing its signed bytes."""
    try:
        value = strict_loads(raw)
    except RecursionError:
        _refuse("replay JSON exceeds depth or node bounds")
    _bounded_value(value)
    if not isinstance(value, dict):
        _refuse("replay context must contain JSON objects")
    return value


def _object(value: Any, fields: set[str], reason: str) -> None:
    """Reject missing and extra object members with one stable reason."""
    if type(value) is not dict or set(value) != fields:
        _refuse(reason)


def _input_bounds(
    inputs: Mapping[str, bytes], policy: ReplayPolicy
) -> dict[str, bytes]:
    """Snapshot exact byte objects before invoking any native checker."""
    snapshot = _snapshot(inputs)
    if set(snapshot) != policy.expected_roles:
        _refuse("replay inputs differ from the declared context")
    return snapshot


def _snapshot(inputs: Mapping[str, bytes]) -> dict[str, bytes]:
    """Enforce resource bounds even when declared inputs are missing."""
    if not isinstance(inputs, Mapping) or len(inputs) > MAX_INPUTS:
        _refuse("replay input count exceeds the profile bound")
    snapshot = dict(inputs)
    if not all(type(raw) is bytes for raw in snapshot.values()):
        _refuse("replay inputs must be immutable bytes")
    if any(len(raw) > MAX_INPUT_BYTES for raw in snapshot.values()):
        _refuse("replay input exceeds the byte bound")
    if sum(map(len, snapshot.values())) > MAX_TOTAL_BYTES:
        _refuse("replay inputs exceed the total byte bound")
    return snapshot


def _pins_match(inputs: Mapping[str, bytes], policy: ReplayPolicy) -> None:
    """Refuse changed native bytes or checker sources before replay."""
    for role, pin in policy.pins.items():
        if hashlib.sha256(inputs[role]).hexdigest() != pin.sha256:
            _refuse("replay input bytes differ from the consumer pin")
    actual = hashlib.sha256(checker_implementation_bytes()).hexdigest()
    if actual != policy.checker_source.sha256:
        _refuse("replay checker bytes differ from the consumer pin")


def _manifest(raw: bytes, expected: tuple[str, ...]) -> dict[str, str]:
    """Read a closed manifest whose declared member population is consumer-pinned."""
    value = _load(raw)
    _object(value, {"files"}, "replay manifest has unexpected fields")
    files = value["files"]
    _object(
        files, set(expected), "replay manifest differs from the declared population"
    )
    for member_digest in files.values():
        _hex(member_digest, "manifest member digest")
    return files


def _fixture_binding(inputs: Mapping[str, bytes], policy: ReplayPolicy) -> None:
    """Compare both manifest claims and every declared owner/copy fixture byte."""
    owner = _manifest(inputs["owner-manifest"], policy.fixture_names)
    copied = _manifest(inputs["copy-manifest"], policy.fixture_names)
    if owner != copied:
        _refuse("owner and copy fixture manifests differ")
    for name in policy.fixture_names:
        _fixture_member(inputs[f"owner:{name}"], inputs[f"copy:{name}"], owner[name])


def _fixture_member(owner_raw: bytes, copy_raw: bytes, expected_digest: str) -> None:
    """Check one owner manifest digest and the corresponding copied bytes."""
    if hashlib.sha256(owner_raw).hexdigest() != expected_digest:
        _refuse("owner fixture bytes differ from their manifest")
    if owner_raw != copy_raw:
        _refuse("copied fixture bytes differ from the pinned owner")


def _workspace_binding(
    inputs: Mapping[str, bytes], policy: ReplayPolicy
) -> dict[str, bytes]:
    """Bind all declared current workspace members before reconstructing a tree."""
    manifest = _manifest(inputs["workspace-manifest"], policy.workspace_names)
    workspace = {name: inputs[f"workspace:{name}"] for name in policy.workspace_names}
    if any(
        hashlib.sha256(raw).hexdigest() != manifest[name]
        for name, raw in workspace.items()
    ):
        _refuse("workspace bytes differ from the pinned manifest")
    return workspace


def _lines(raw: bytes) -> None:
    """Bound and parse every retained history/ledger line before native replay."""
    lines = raw.splitlines()
    if len(lines) > MAX_LINES or (raw and not raw.endswith(b"\n")):
        _refuse("replay log exceeds line bounds or has an incomplete line")
    for line in lines:
        _load(line)


@dataclass(frozen=True, slots=True)
class _Context:
    """Private parsed snapshots; raw signed artifacts remain in the input map."""

    request: ActionRequest
    grant_policy: GrantPolicy
    admission_policy: dict[str, Any]
    key_pins: dict[str, str]
    now: datetime
    grant: dict[str, Any]
    packet: dict[str, Any]
    workspace: dict[str, bytes]


def _time(raw: bytes) -> datetime:
    """Require explicit historical UTC seconds rather than implicit wall time."""
    value = _load(raw)
    _object(value, {"now"}, "replay time context has unexpected fields")
    try:
        reference = datetime.strptime(value["now"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except (TypeError, ValueError):
        _refuse("replay reference time must use canonical UTC seconds")
    if reference.isoformat(timespec="seconds").replace("+00:00", "Z") != value["now"]:
        _refuse("replay reference time must use canonical UTC seconds")
    return reference


def _context(inputs: Mapping[str, bytes], policy: ReplayPolicy) -> _Context:
    """Parse the entire declared native replay context with no external reads."""
    _fixture_binding(inputs, policy)
    workspace = _workspace_binding(inputs, policy)
    for role in ("history", "ledger"):
        _lines(inputs[role])
    request = _load(inputs["request"])
    grant_policy = _load(inputs["grant-policy"])
    _object(
        request,
        set(ActionRequest.__dataclass_fields__),
        "replay request has unexpected fields",
    )
    _object(
        grant_policy,
        set(GrantPolicy.__dataclass_fields__),
        "replay grant policy has unexpected fields",
    )
    keys = _load(inputs["key-pins"])
    _object(
        keys,
        {"issuer", "observer", "witness"},
        "replay key pins have unexpected fields",
    )
    for public_key in keys.values():
        _hex(public_key, "replay public key")
    admission = _load(inputs["admission-policy"])
    _object(
        admission,
        {
            "interval_id",
            "authority_digest",
            "observer_key",
            "witness_key",
            "retained_witness_head",
        },
        "replay admission policy has unexpected fields",
    )
    _context_keys(keys, grant_policy, admission)
    return _Context(
        ActionRequest(**request),
        GrantPolicy(**grant_policy),
        admission,
        keys,
        _time(inputs["reference-time"]),
        _load(inputs["authorization"]),
        _load(inputs["observation"]),
        workspace,
    )


def _context_keys(
    keys: dict[str, str], grant: dict[str, Any], admission: dict[str, Any]
) -> None:
    """Require consumer key contexts to agree, without deriving pins from records."""
    actual = (grant["issuer_key"], admission["observer_key"], admission["witness_key"])
    if actual != (keys["issuer"], keys["observer"], keys["witness"]):
        _refuse("replay key contexts disagree")
    if len(set(keys.values())) != 3:
        _refuse("replay issuer observer and witness keys must differ")


def _authorization(context: _Context, policy: ReplayPolicy) -> None:
    """Execute the native issuer, exact-request, signature, and time checks."""
    if context.request.request_id != policy.action_id:
        _refuse("replay request differs from the selected action")
    verify_grant(context.grant, context.request, context.grant_policy, now=context.now)


def _native_policy(
    claim: dict[str, Any], context: _Context, policy: ReplayPolicy
) -> None:
    """Bind verified native semantics to independently selected consumer policy."""
    admission = context.admission_policy
    if (claim["intervalId"], claim["authorityDigest"]) != (
        admission["interval_id"],
        admission["authority_digest"],
    ):
        _refuse("replay native claim differs from the consumer policy")
    if digest("probity-claim-v0", claim) != policy.claim_digest:
        _refuse("replay native claim differs from the selected claim")
    if claim["coverage"]["noDetectedGap"] is not True:
        _refuse("replay policy requires no detected broker coverage gap")


def _observation(
    context: _Context, policy: ReplayPolicy, inputs: Mapping[str, bytes]
) -> None:
    """Replay native history, target bytes, authorization binding, and retained head."""
    with TemporaryDirectory(prefix="probity-replay-") as directory:
        root = Path(directory)
        workspace = root / "workspace"
        workspace.mkdir()
        for name, raw in context.workspace.items():
            target = workspace / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        history, ledger = root / "history.jsonl", root / "ledger.jsonl"
        history.write_bytes(inputs["history"])
        ledger.write_bytes(inputs["ledger"])
        result = verify_authorized_packet(
            context.grant,
            context.request,
            context.grant_policy,
            context.packet,
            history,
            context.key_pins["observer"],
            context.key_pins["witness"],
            now=context.now,
            workspace=workspace,
        )
        _native_policy(result["claim"], context, policy)
        verify_ledger_head(
            ledger,
            context.admission_policy["retained_witness_head"],
            context.key_pins["witness"],
        )
        verify_ledger_receipts(
            ledger,
            context.packet["startCheckpoint"],
            context.packet["checkpoint"],
            context.key_pins["witness"],
        )


def _run(operation: Callable[[], None]) -> tuple[ReplayOutcome, str]:
    """Retain native refusal, invalid context, and checker failure separately."""
    try:
        operation()
    except VerificationError as exc:
        LOGGER.warning("pilot replay check refused: %s", exc)
        return ReplayOutcome.REFUSAL, str(exc)
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        LOGGER.warning("pilot replay check invalid: malformed native input")
        return ReplayOutcome.INVALID, "malformed native input"
    except Exception:
        LOGGER.error("pilot replay check error: local checker failed")
        return ReplayOutcome.ERROR, "local checker failed"
    return ReplayOutcome.PASS, "native checks passed"


def replay_checks(inputs: Mapping[str, bytes], policy: ReplayPolicy) -> dict[str, Any]:
    """Execute actual bounded checks on consumer-pinned declared inputs.

    Parameters
    ----------
    inputs : Mapping[str, bytes]
        Complete declared context, retained as exact immutable native bytes.
    policy : ReplayPolicy
        Consumer-acquired policy, artifact provenance, and checker pin.

    Returns
    -------
    dict[str, Any]
        Actual outcomes and reasons for each role. Incomplete input populations
        leave checks not-run; invalid data, native refusals, and local errors
        remain visible. This does not sign or admit a record.

    Raises
    ------
    VerificationError
        For excessive resource use, changed byte pins, or checker substitution.
    """
    snapshot = _snapshot(inputs)
    if set(snapshot) < policy.expected_roles:
        return _report(
            policy, {}, ReplayOutcome.INCOMPLETE, "declared replay context is missing"
        )
    snapshot = _input_bounds(snapshot, policy)
    _pins_match(snapshot, policy)
    parsed: list[_Context] = []
    outcome, reason = _run(lambda: parsed.append(_context(snapshot, policy)))
    if outcome is not ReplayOutcome.PASS:
        return _report(policy, {}, outcome, reason)
    context = parsed[0]
    outcomes = {
        role: (ReplayOutcome.PASS, "declared context checked")
        for role in policy.expected_roles
    }
    outcomes["authorization"] = _run(lambda: _authorization(context, policy))
    outcomes["observation"] = _run(lambda: _observation(context, policy, snapshot))
    return _report(
        policy, outcomes, ReplayOutcome.PASS, "declared replay context checked"
    )


def _report(
    policy: ReplayPolicy,
    outcomes: dict[str, tuple[ReplayOutcome, str]],
    context: ReplayOutcome,
    reason: str,
) -> dict[str, Any]:
    """Build bounded actual results without claiming a larger accounting population."""
    checks = [
        {
            "role": role,
            "outcome": outcomes.get(role, (ReplayOutcome.NOT_RUN, reason))[0].value,
            "reason": outcomes.get(role, (ReplayOutcome.NOT_RUN, reason))[1],
        }
        for role in sorted(policy.expected_roles)
    ]
    acceptable = context is ReplayOutcome.PASS and all(
        item["outcome"] == "pass" for item in checks
    )
    return {
        "profile": PROFILE,
        "policyDigest": policy.policy_digest,
        "contextOutcome": context.value,
        "contextReason": reason,
        "checks": checks,
        "decision": "replay-acceptable" if acceptable else "block",
        "coverage": "declared-inputs-only",
        "resultAuthority": "local-substantive-replay",
        "durableAdmission": "not-performed",
        "witnessScope": "PEER",
    }


def consumption_checks(
    inputs: Mapping[str, bytes], policy: ReplayPolicy, report: dict[str, Any]
) -> list[dict[str, Any]]:
    """Convert actual outcomes into strict results for generic consumption signing.

    The report remains a caller-supplied assertion at signing time. Only fresh
    :func:`replay_consumption` checks its substantive truth for the consumer.
    """
    snapshot = _input_bounds(inputs, policy)
    _pins_match(snapshot, policy)
    outcomes = {
        item["role"]: ReplayOutcome(item["outcome"]).value for item in report["checks"]
    }
    if set(outcomes) != policy.expected_roles:
        _refuse("replay report roles differ from the declared profile")
    return [
        {
            "role": role,
            "input": policy.pins[role].fields(),
            "result": {
                "profile": PROFILE,
                "policyDigest": policy.policy_digest,
                "outcome": outcomes[role],
            },
        }
        for role in sorted(policy.expected_roles)
    ]


def replay_consumption(
    record: dict[str, Any], inputs: Mapping[str, bytes], policy: ReplayPolicy
) -> dict[str, Any]:
    """Verify signed bindings, then freshly replay the declared native checkers.

    A valid signature over fabricated success can pass binding verification but
    cannot satisfy this gate when actual replay disagrees. Closed non-pass
    outcomes also block. Caller-selected policies and source pins remain the
    trust boundary; this function neither fetches sources nor independently
    proves ownership, the historical clock, or observation completeness.
    """
    _bounded_value(record)
    if len(canonical(record)) > MAX_RECORD_BYTES:
        _refuse("consumption record exceeds the replay byte bound")
    snapshot = _input_bounds(inputs, policy)
    _pins_match(snapshot, policy)
    binding = verify_consumption(
        record,
        snapshot,
        policy.pins,
        action_id=policy.action_id,
        claim_digest=policy.claim_digest,
        pinned_signer=policy.pinned_signer,
    )
    reported = _reported(record, policy)
    actual = replay_checks(snapshot, policy)
    mismatches = [
        item["role"]
        for item in actual["checks"]
        if item["outcome"] != reported[item["role"]]
    ]
    actual.update({"bindings": binding, "reportedOutcomeMismatches": mismatches})
    if mismatches:
        LOGGER.warning(
            "pilot replay blocked: reported outcomes differ from actual replay"
        )
        actual["decision"] = "block"
    return actual


def _reported(record: dict[str, Any], policy: ReplayPolicy) -> dict[str, str]:
    """Accept only the six outcomes and exact profile/policy binding."""
    reported = {}
    for check in record["payload"]["checks"]:
        result = check["result"]
        _object(
            result,
            {"profile", "policyDigest", "outcome"},
            "reported replay result has unexpected fields",
        )
        if (result["profile"], result["policyDigest"]) != (
            PROFILE,
            policy.policy_digest,
        ):
            _refuse(
                "reported replay result differs from the consumer profile or policy"
            )
        try:
            reported[check["role"]] = ReplayOutcome(result["outcome"]).value
        except (TypeError, ValueError):
            _refuse("reported replay outcome is outside the closed profile")
    return reported
