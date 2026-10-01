"""Check a declared evaluation population against retained attempts and bytes.

These checks establish record consistency and exact artifact binding. An author
can fabricate a consistent record; this module does not prove execution,
independent custody, or that every possible attempt was declared.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, NoReturn

from .crypto import VerificationError

LOGGER = logging.getLogger(__name__)
PROFILE = "probity-evaluation-history-reference-v0"
IDENTIFIER = re.compile(r"[!-~]{1,256}\Z")
HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
REQUIRED_ROLES = frozenset(
    {"task", "model", "solver", "checker", "scorer", "policy", "harness"}
)
STATUSES = frozenset({"completed", "error", "interrupted", "not_run"})
OUTCOMES = frozenset({"pass", "fail", "not_scored"})
MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_JSON_DEPTH = 128
MAX_JSON_NODES = 100_000


def _refuse(reason: str) -> NoReturn:
    """Emit one bounded refusal without model inputs, outputs, or credentials."""
    LOGGER.warning("evaluation history refused: %s", reason)
    raise VerificationError(reason)


def _identifier(value: Any, field: str) -> None:
    """Require finite nonempty printable ASCII identity fields."""
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        _refuse(f"{field} must be a nonempty printable ASCII identifier")


def _digest(value: Any) -> None:
    """Require an exact lowercase SHA-256 representation."""
    if not isinstance(value, str) or HEX_DIGEST.fullmatch(value) is None:
        _refuse("artifact digest must be lowercase SHA-256")


def _time(value: Any) -> datetime:
    """Parse aware UTC timestamps, preserving native subsecond precision."""
    if not isinstance(value, str):
        _refuse("evaluation timestamp must be timezone-aware UTC")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _refuse("evaluation timestamp must be timezone-aware UTC")
    if parsed.utcoffset() != timedelta(0):
        _refuse("evaluation timestamp must be timezone-aware UTC")
    return parsed


def encode_record(value: Any) -> bytes:
    """Encode reference JSON deterministically without claiming RFC 8785.

    Parameters
    ----------
    value : Any
        JSON data. NaN and infinity are refused; native output bytes are hashed
        separately and are never silently rewritten by this encoding.

    Returns
    -------
    bytes
        Compact ASCII JSON with escaped non-ASCII strings and sorted members.
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON members rather than selecting their last value."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _invalid_constant(value: str) -> NoReturn:
    """Refuse non-finite values outside the JSON data model."""
    raise ValueError("non-finite JSON value")


def decode_record(content: bytes) -> Any:
    """Read retained JSON without duplicate members or non-finite numbers.

    Parameters
    ----------
    content : bytes
        Original UTF-8 JSON bytes, not a filename or a fetchable URI.

    Returns
    -------
    Any
        Decoded JSON data. Its original bytes remain the hash authority.

    Raises
    ------
    VerificationError
        If the bytes are malformed or have ambiguous object members.
    """
    if not isinstance(content, bytes):
        _refuse("retained JSON must be bytes")
    if len(content) > MAX_RECORD_BYTES:
        _refuse("retained JSON exceeds the reference size limit")
    try:
        value = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_unique_members,
            parse_constant=_invalid_constant,
        )
    except (ValueError, UnicodeError, RecursionError):
        _refuse("retained JSON is malformed or ambiguous")
    _json_depth(value)
    return value


def _json_depth(value: Any) -> None:
    """Bound nested retained data after parsing, without recursive traversal."""
    pending = [(value, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        _json_node_limit(count, depth)
        children = _json_children(node)
        _json_node_limit(count + len(pending) + len(children), depth)
        pending.extend((child, depth + 1) for child in children)


def _json_children(node: Any) -> Any:
    """Enumerate only JSON container values before expanding the bounded queue."""
    if isinstance(node, dict):
        return node.values()
    if isinstance(node, list):
        return node
    return ()


def _json_node_limit(count: int, depth: int) -> None:
    """Keep decoded evidence within explicit depth and population limits."""
    if depth > MAX_JSON_DEPTH:
        _refuse("retained JSON exceeds the reference depth limit")
    if count > MAX_JSON_NODES:
        _refuse("retained JSON exceeds the reference node limit")


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    """Expected exact bytes under a consumer-selected artifact name.

    Parameters
    ----------
    name : str
        Finite identity within the supplied artifact mapping, not a path to
        resolve or a URI to fetch.
    sha256 : str
        SHA-256 of the original retained bytes.
    size_bytes : int
        Exact byte count. Boolean and negative values are refused.
    """

    name: str
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        _identifier(self.name, "artifact name")
        _digest(self.sha256)
        if type(self.size_bytes) is not int or self.size_bytes < 0:
            _refuse("artifact size must be a nonnegative integer")


@dataclass(frozen=True, slots=True)
class SourcePin:
    """Versioned identity and actual source bytes for one evaluation role.

    Parameters
    ----------
    role : str
        One of task, model, solver, checker, scorer, policy, or harness.
    identity, version : str
        Exact implementation or configuration identity and its selected
        version. Scorer implementation and decision policy are separate roles.
    artifact : ArtifactRef
        Reference to exact retained source/configuration bytes.
    """

    role: str
    identity: str
    version: str
    artifact: ArtifactRef

    def __post_init__(self) -> None:
        if not isinstance(self.role, str) or self.role not in REQUIRED_ROLES:
            _refuse("source role is unsupported")
        _identifier(self.identity, "source identity")
        _identifier(self.version, "source version")
        if not isinstance(self.artifact, ArtifactRef):
            _refuse("source artifact must be an ArtifactRef")


@dataclass(frozen=True, slots=True)
class AttemptSpec:
    """One declared sample and epoch, including the complete attempt identity.

    Parameters
    ----------
    attempt_id, sample_id : str
        Consumer-selected exact identities. Their spelling is never inferred
        from successful results or silently changed by an adapter.
    epoch : int
        Positive non-Boolean epoch number. Multiple retries within an epoch
        require another explicitly declared attempt; they are not hidden here.
    """

    attempt_id: str
    sample_id: str
    epoch: int

    def __post_init__(self) -> None:
        _identifier(self.attempt_id, "attempt_id")
        _identifier(self.sample_id, "sample_id")
        if type(self.epoch) is not int or self.epoch < 1:
            _refuse("epoch must be a positive integer")


@dataclass(frozen=True, slots=True)
class RunPlan:
    """Frozen declared evaluation scope and seven source roles.

    Parameters
    ----------
    run_id : str
        Program run identity selected before invoking the harness.
    created_at : str
        Aware UTC timestamp preceding retained attempt execution.
    attempts : tuple[AttemptSpec, ...]
        Ordered declared population. Every entry requires exactly one record,
        including errors and explicitly not-run entries.
    sources : tuple[SourcePin, ...]
        Exactly one task, model, solver, checker, scorer, policy, and harness
        pin. Their original bytes must be supplied to :func:`verify_history`.
    mode : str, default='offline-contract'
        Either offline-contract or model-evaluation. The former measures a
        harness/evidence contract and cannot be reported as LLM performance.

    Notes
    -----
    This declaration is selected by an operator. Its completeness cannot be
    established solely by comparing records against the same declaration.
    """

    run_id: str
    created_at: str
    attempts: tuple[AttemptSpec, ...]
    sources: tuple[SourcePin, ...]
    mode: str = "offline-contract"

    def __post_init__(self) -> None:
        _identifier(self.run_id, "run_id")
        _time(self.created_at)
        object.__setattr__(self, "attempts", _typed_tuple(self.attempts, AttemptSpec))
        object.__setattr__(self, "sources", _typed_tuple(self.sources, SourcePin))
        if not isinstance(self.mode, str) or self.mode not in {
            "offline-contract",
            "model-evaluation",
        }:
            _refuse("evaluation mode is unsupported")
        _population(self.attempts)
        roles = [source.role for source in self.sources]
        if len(roles) != len(REQUIRED_ROLES) or set(roles) != REQUIRED_ROLES:
            _refuse("run requires exactly one source pin for every role")


def _typed_tuple(values: Any, kind: type) -> tuple[Any, ...]:
    """Snapshot a finite typed collection before any identity checks."""
    if not isinstance(values, (tuple, list)):
        _refuse("record collection must be a tuple or list")
    result = tuple(values)
    if not all(isinstance(value, kind) for value in result):
        _refuse("record collection contains an unsupported type")
    return result


def _population(attempts: Sequence[AttemptSpec]) -> None:
    """Require a nonempty population with distinct attempts and sample epochs."""
    if not attempts:
        _refuse("declared attempt population must be nonempty")
    if len({attempt.attempt_id for attempt in attempts}) != len(attempts):
        _refuse("declared attempt identities are duplicated")
    if len({(attempt.sample_id, attempt.epoch) for attempt in attempts}) != len(
        attempts
    ):
        _refuse("declared sample epochs are duplicated")


@dataclass(frozen=True, slots=True)
class AttemptRecord:
    """Retained attempt status independent of its task score.

    Parameters
    ----------
    run_id, attempt_id : str
        Exact bindings to :class:`RunPlan` and :class:`AttemptSpec`.
    ordinal : int
        One-based record order within the declared population. It does not
        claim actual dispatch order when a native harness runs concurrently.
    status : str
        completed, error, interrupted, or not_run. A wrong answer is completed.
    outcome : str
        pass, fail, or not_scored under the separately pinned scorer policy.
    started_at, ended_at : str | None
        Original UTC execution timestamps; both are absent for not_run.
    error_code : str | None
        Bounded error/not-run reason. Detailed native errors remain in raw
        artifacts rather than logs emitted by this checker.
    output : ArtifactRef | None
        Retained output envelope, including partial native data when available.
        Completed attempts require one. Its run and attempt
        identities, status and outcome must agree with this record.
    actions : tuple[ArtifactRef, ...], default=()
        Bounded optional observed-action artifacts. Their presence is not proof
        of complete action capture or independently observed effects.
    """

    run_id: str
    attempt_id: str
    ordinal: int
    status: str
    outcome: str
    started_at: str | None
    ended_at: str | None
    error_code: str | None
    output: ArtifactRef | None
    actions: tuple[ArtifactRef, ...] = ()

    def __post_init__(self) -> None:
        _identifier(self.run_id, "run_id")
        _identifier(self.attempt_id, "attempt_id")
        if type(self.ordinal) is not int or self.ordinal < 1:
            _refuse("record ordinal must be a positive integer")
        _record_fields(self)


def _record_fields(record: AttemptRecord) -> None:
    """Freeze action references and reject unsupported retained record fields."""
    if not isinstance(record.status, str) or record.status not in STATUSES:
        _refuse("attempt status or outcome is unsupported")
    if not isinstance(record.outcome, str) or record.outcome not in OUTCOMES:
        _refuse("attempt status or outcome is unsupported")
    if record.error_code is not None:
        _identifier(record.error_code, "error_code")
    if record.output is not None and not isinstance(record.output, ArtifactRef):
        _refuse("attempt output must be an ArtifactRef")
    object.__setattr__(record, "actions", _typed_tuple(record.actions, ArtifactRef))


def artifact_ref(name: str, content: bytes) -> ArtifactRef:
    """Bind an artifact's original bytes without interpreting their contents.

    Parameters
    ----------
    name : str
        Finite identity in the retained artifact mapping, not a path to resolve.
    content : bytes
        Original retained bytes.

    Returns
    -------
    ArtifactRef
        Exact name, SHA-256, and byte count.

    Raises
    ------
    VerificationError
        If the identity or byte input is unsupported.
    """
    if not isinstance(content, bytes):
        _refuse("retained artifact content must be bytes")
    return ArtifactRef(name, hashlib.sha256(content).hexdigest(), len(content))


def plan_digest(plan: RunPlan) -> str:
    """Return the domain-separated exact reference-plan digest.

    Parameters
    ----------
    plan : RunPlan
        Frozen declaration containing all attempts and source-role pins.

    Returns
    -------
    str
        Lowercase SHA-256 of the profile domain and deterministic plan JSON.
    """
    return hashlib.sha256(
        PROFILE.encode("ascii") + b"\0" + encode_record(asdict(plan))
    ).hexdigest()


def _bytes(ref: ArtifactRef, artifacts: Mapping[str, bytes]) -> bytes:
    """Check presence, type, exact size, and digest before interpreting bytes."""
    content = artifacts.get(ref.name)
    if not isinstance(content, bytes):
        _refuse("retained artifact is missing or is not bytes")
    if len(content) != ref.size_bytes:
        _refuse("retained artifact size differs from its pin")
    if hashlib.sha256(content).hexdigest() != ref.sha256:
        _refuse("retained artifact digest differs from its pin")
    return content


def _sources(plan: RunPlan, sources: Mapping[str, bytes]) -> None:
    """Check the exact source population and each original source artifact."""
    names = {source.artifact.name for source in plan.sources}
    if set(sources) != names:
        _refuse("retained source population differs from the plan")
    for source in plan.sources:
        _bytes(source.artifact, sources)


def _record_identity(plan: RunPlan, records: Sequence[AttemptRecord]) -> None:
    """Reject omissions, duplicates, cross-run records, and changed record order."""
    if len(records) != len(plan.attempts):
        _refuse("retained attempt count differs from the declared population")
    actual = [(record.run_id, record.attempt_id, record.ordinal) for record in records]
    expected = [
        (plan.run_id, attempt.attempt_id, index)
        for index, attempt in enumerate(plan.attempts, 1)
    ]
    if actual != expected:
        _refuse("retained attempt identities or order differ from the plan")


def _not_run(record: AttemptRecord) -> None:
    """Require explicit absent execution rather than silently skipping a sample."""
    if record.started_at is not None or record.ended_at is not None:
        _refuse("not-run attempt must not claim execution timestamps")
    if record.output is not None or record.actions:
        _refuse("not-run attempt must not claim output or observed actions")
    if record.outcome != "not_scored" or record.error_code is None:
        _refuse("not-run attempt requires an explicit unscored reason")


def _executed(plan: RunPlan, record: AttemptRecord, ended_at: str) -> None:
    """Check explicit attempt timing and status without inferring execution truth."""
    start, end = _time(record.started_at), _time(record.ended_at)
    if not _time(plan.created_at) <= start <= end <= _time(ended_at):
        _refuse("attempt timestamps are outside the declared run interval")
    if record.status == "error":
        _error(record)
    elif record.error_code is not None or record.output is None:
        _refuse("completed attempt requires output and no execution error")


def _error(record: AttemptRecord) -> None:
    """Keep execution failure separate from successful grading."""
    if record.outcome != "not_scored" or record.error_code is None:
        _refuse("errored attempt must be explicitly unscored")


def _interrupted(plan: RunPlan, record: AttemptRecord, ended_at: str) -> None:
    """Retain a started sample without inventing a native completion time."""
    if record.ended_at is not None:
        _refuse("interrupted attempt must not claim a completion timestamp")
    if not _time(plan.created_at) <= _time(record.started_at) <= _time(ended_at):
        _refuse("attempt timestamps are outside the declared run interval")
    if record.outcome != "not_scored" or record.error_code is None:
        _refuse("interrupted attempt must be explicitly unscored")


def _output(record: AttemptRecord, artifacts: Mapping[str, bytes]) -> None:
    """Reject stale/cross-run output or a selectively changed outcome envelope."""
    if record.output is None:
        return
    content = _bytes(record.output, artifacts)
    envelope = decode_record(content)
    expected = {
        "run_id": record.run_id,
        "attempt_id": record.attempt_id,
        "status": record.status,
        "outcome": record.outcome,
    }
    if not isinstance(envelope, dict) or any(
        envelope.get(key) != value for key, value in expected.items()
    ):
        _refuse("attempt output is stale or differs from its retained record")


def _artifact_population(
    records: Sequence[AttemptRecord], artifacts: Mapping[str, bytes]
) -> None:
    """Require exact retained output/action population, without hidden extras."""
    refs = [ref for record in records for ref in _record_refs(record)]
    names = [ref.name for ref in refs]
    if len(names) != len(set(names)):
        _refuse("attempt artifact identities are duplicated")
    if set(artifacts) != set(names):
        _refuse("retained artifact population differs from the records")
    for ref in refs:
        _bytes(ref, artifacts)


def _record_refs(record: AttemptRecord) -> tuple[ArtifactRef, ...]:
    """Collect output and optional action references in record order."""
    return ((record.output,) if record.output else ()) + record.actions


def _summary(records: Sequence[AttemptRecord]) -> dict[str, int]:
    """Count every declared attempt, retaining task and harness failures."""
    statuses = Counter(record.status for record in records)
    outcomes = Counter(record.outcome for record in records)
    return {
        "attempts": len(records),
        **{status: statuses[status] for status in sorted(STATUSES)},
        **{outcome: outcomes[outcome] for outcome in sorted(OUTCOMES)},
    }


def verify_history(
    plan: RunPlan,
    records: Sequence[AttemptRecord],
    *,
    artifacts: Mapping[str, bytes],
    sources: Mapping[str, bytes],
    ended_at: str,
    claimed_summary: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """Check all declared attempts, sources, outputs, times, and summary counts.

    Parameters
    ----------
    plan : RunPlan
        Consumer-selected declared population and immutable source-role pins.
    records : Sequence[AttemptRecord]
        Exactly one ordered record for every declaration, including errors and
        not-run entries. The function does not silently drop failed attempts.
    artifacts, sources : Mapping[str, bytes]
        Original retained byte populations. Extra, missing, replaced, or
        duplicate artifact identities are refused.
    ended_at : str
        UTC end of the declared run, following creation and executed attempts.
    claimed_summary : Mapping[str, int] | None, optional
        If supplied, every count must exactly equal the retained population's
        recomputed counts. Selectively reporting only successes is refused.

    Returns
    -------
    dict[str, Any]
        Record-consistency result, complete declared counts, source identities,
        plan digest, and explicit observation/custody limits. A pass means
        consistent records, not an independently established successful run.

    Raises
    ------
    VerificationError
        On population, identity, timing, source, artifact, outcome, or summary
        mismatch. Logs retain bounded reasons without candidate contents.
    """
    records = _typed_tuple(records, AttemptRecord)
    artifacts, sources = dict(artifacts), dict(sources)
    _sources(plan, sources)
    _record_identity(plan, records)
    if _time(ended_at) < _time(plan.created_at):
        _refuse("run ends before its declared creation")
    _artifact_population(records, artifacts)
    for record in records:
        _check_record(plan, record, artifacts, ended_at)
    summary = _summary(records)
    _check_summary(claimed_summary, summary)
    return {
        "profile": PROFILE,
        "status": "records-consistent",
        "mode": plan.mode,
        "runId": plan.run_id,
        "planDigest": plan_digest(plan),
        "endedAt": ended_at,
        "summary": summary,
        "allDeclaredAttemptsRecorded": True,
        "resultAuthority": "retained-records-only",
        "executionTruth": "not-established",
        "globalNoOmission": "not-established",
        "independentCustody": "not-established",
        "sources": {
            source.role: {
                "identity": source.identity,
                "version": source.version,
                "sha256": source.artifact.sha256,
            }
            for source in plan.sources
        },
    }


def _check_summary(claimed: Mapping[str, int] | None, actual: dict[str, int]) -> None:
    """Compare all counts strictly; Boolean counts are not integers here."""
    if claimed is None:
        return
    values = dict(claimed)
    if values != actual or any(type(value) is not int for value in values.values()):
        _refuse("reported summary differs from retained attempts")


def _check_record(
    plan: RunPlan, record: AttemptRecord, artifacts: Mapping[str, bytes], ended_at: str
) -> None:
    """Apply status-specific checks before trusting a retained output envelope."""
    if record.status == "not_run":
        _not_run(record)
    elif record.status == "interrupted":
        _interrupted(plan, record, ended_at)
    else:
        _executed(plan, record, ended_at)
    _output(record, artifacts)
