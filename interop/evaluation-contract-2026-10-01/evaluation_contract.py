"""Validate pinned result populations without asserting execution or custody.

This optional, standalone contract leaves native evidence bytes unchanged. It is
not the Observer evaluation_history wire format and never rewrites that API.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
from collections import Counter
from typing import Any, NoReturn

LOGGER = logging.getLogger(__name__)
PROFILE = "probity-five-tier-result-reference-v0"
TIERS = frozenset({"reasoning", "tools", "agents", "workloads", "a2a"})
OUTCOMES = frozenset({"pass", "fail", "unknown", "not-exercised", "out-of-scope"})
STATUSES = frozenset(
    {"complete", "error", "timeout", "interrupted", "incomplete", "not-started"}
)
AXES = frozenset(
    {
        "task_outcome",
        "judge_reliability",
        "trust",
        "authority",
        "effect",
        "coverage",
        "consumer",
    }
)
IDENTITIES = frozenset(
    {
        "task_id",
        "logical_request_id",
        "attempt_id",
        "interval_id",
        "catalog_authority_id",
        "capability_id",
        "runtime_target_id",
        "effect_id",
        "consumer_decision_id",
    }
)
ROLES = frozenset(
    {
        "case_author",
        "implementation_author",
        "runner",
        "witness_operator",
        "key_holder",
        "retention_holder",
        "policy_owner",
        "consumer",
    }
)
RESOURCES = frozenset({"elapsed_ns", "input_tokens", "output_tokens", "peak_bytes"})
HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_BYTES = 8 * 1024 * 1024


class ContractError(ValueError):
    """A pinned population or retained result violates the reference contract."""


def refuse(reason: str) -> NoReturn:
    """Log only a bounded code, then raise the same machine-readable reason."""
    LOGGER.warning("evaluation contract refused: %s", reason)
    raise ContractError(reason)


def require(condition: bool, reason: str) -> None:
    """Enforce one invariant without logging native evidence or credentials."""
    if not condition:
        refuse(reason)


def encode(value: Any) -> bytes:
    """Encode deterministic reference JSON, not JCS or a native signing input.

    Parameters
    ----------
    value : Any
        Finite JSON value. Native artifacts are retained as their original bytes.

    Returns
    -------
    bytes
        Compact UTF-8 JSON with sorted keys; used by :func:`digest` for local pins.
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def digest(content: bytes) -> str:
    """Return SHA-256 over the supplied original octets."""
    return hashlib.sha256(content).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse duplicate object members before any interpretation or hashing."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_member")
        result[key] = value
    return result


def decode(content: bytes) -> Any:
    """Parse bounded UTF-8 JSON with duplicate and non-finite-value rejection.

    Parameters
    ----------
    content : bytes
        Retained JSON, at most eight MiB. Parsing does not replace raw-byte pins.

    Returns
    -------
    Any
        Parsed JSON value.

    Raises
    ------
    ContractError
        For oversized, malformed, duplicated, non-finite, or deeply nested data.
    """
    require(type(content) is bytes, "json_requires_bytes")
    require(len(content) <= MAX_BYTES, "json_size_limit")
    try:
        result = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _: refuse("nonfinite_json"),
        )
    except ContractError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        refuse("malformed_json")
    pending = [(result, 0)]
    nodes = 0
    while pending:
        node, depth = pending.pop()
        nodes += 1
        require(type(node) is not float or math.isfinite(node), "nonfinite_json")
        require(depth <= 64 and nodes <= 100_000, "json_structure_limit")
        children = (
            node.values() if type(node) is dict else node if type(node) is list else ()
        )
        pending.extend((child, depth + 1) for child in children)
    return result


def object_keys(value: Any, fields: set[str] | frozenset[str], reason: str) -> None:
    """Require an exact object shape; unknown semantic fields need a new profile."""
    require(type(value) is dict, reason)
    require(value.keys() == fields, reason)


def identifier(value: Any) -> None:
    """Require a printable bounded identifier without silently normalizing it."""
    require(type(value) is str, "invalid_identifier")
    require(
        0 < len(value) <= 256 and all(33 <= ord(c) <= 126 for c in value),
        "invalid_identifier",
    )


def pinned(content: bytes, expected: str) -> None:
    """Bind exact supplied bytes to a consumer-selected external digest."""
    require(
        type(expected) is str and HEX.fullmatch(expected) is not None, "invalid_digest"
    )
    require(type(content) is bytes and digest(content) == expected, "pin_mismatch")


def artifact(ref: Any, artifacts: dict[str, bytes]) -> None:
    """Check exact named bytes without following file paths or network URLs."""
    object_keys(
        ref,
        {"name", "sha256", "size_bytes", "media_type", "source_revision"},
        "artifact_shape",
    )
    identifier(ref["name"])
    identifier(ref["source_revision"])
    identifier(ref["media_type"])
    require(type(ref["size_bytes"]) is int and ref["size_bytes"] >= 0, "artifact_size")
    require(ref["name"] in artifacts, "artifact_missing")
    raw = artifacts[ref["name"]]
    pinned(raw, ref["sha256"])
    require(len(raw) == ref["size_bytes"], "artifact_size")


def _source(value: Any, artifacts: dict[str, bytes]) -> None:
    """Bind one task, harness, policy or configuration to retained source bytes."""
    object_keys(value, {"identity", "revision", "artifact"}, "source_shape")
    identifier(value["identity"])
    identifier(value["revision"])
    artifact(value["artifact"], artifacts)
    require(
        value["revision"] == value["artifact"]["source_revision"],
        "source_revision_mismatch",
    )


def _identity(value: Any) -> None:
    """Require semantic identities in separate fields, without deriving aliases."""
    object_keys(value, IDENTITIES, "identity_shape")
    for key in IDENTITIES - {"effect_id"}:
        identifier(value[key])
    if value["effect_id"] is not None:
        identifier(value["effect_id"])


def _attempt(spec: Any, earlier: dict[str, Any]) -> None:
    """Check retry lineage against an earlier declared attempt in the same run."""
    object_keys(spec, {"identity", "tier", "parent_attempt_id"}, "attempt_spec_shape")
    _identity(spec["identity"])
    require(type(spec["tier"]) is str and spec["tier"] in TIERS, "unsupported_tier")
    current = spec["identity"]
    aid = current["attempt_id"]
    require(aid not in earlier, "duplicate_attempt")
    parent = spec["parent_attempt_id"]
    siblings = [
        x
        for x in earlier.values()
        if x["identity"]["logical_request_id"] == current["logical_request_id"]
    ]
    if parent is None:
        require(not siblings, "hidden_retry")
        return
    identifier(parent)
    require(parent in earlier, "unknown_or_forward_parent")
    prior = earlier[parent]
    expected = {
        k: v
        for k, v in prior["identity"].items()
        if k not in {"attempt_id", "effect_id", "consumer_decision_id"}
    }
    actual = {
        k: v
        for k, v in current.items()
        if k not in {"attempt_id", "effect_id", "consumer_decision_id"}
    }
    require(actual == expected and prior["tier"] == spec["tier"], "retry_scope_changed")
    require(parent == siblings[-1]["identity"]["attempt_id"], "retry_not_latest")


def _plan(plan: Any, artifacts: dict[str, bytes]) -> dict[str, Any]:
    """Validate the finite declared population and pinned source configurations."""
    object_keys(
        plan,
        {"profile", "run_id", "mode", "roles", "sources", "attempts"},
        "plan_shape",
    )
    require(plan["profile"] == PROFILE, "unsupported_profile")
    identifier(plan["run_id"])
    require(
        type(plan["mode"]) is str
        and plan["mode"] in {"synthetic-contract", "retained-native"},
        "unsupported_mode",
    )
    object_keys(plan["roles"], ROLES, "roles_shape")
    for value in plan["roles"].values():
        require(value is None or type(value) is str, "role_identity")
        if value is not None:
            identifier(value)
    object_keys(
        plan["sources"],
        {"task", "harness", "model", "rubric", "policy", "configuration"},
        "sources_shape",
    )
    for source in plan["sources"].values():
        _source(source, artifacts)
    require(
        type(plan["attempts"]) is list and 0 < len(plan["attempts"]) <= 10000,
        "attempt_population",
    )
    earlier: dict[str, Any] = {}
    for spec in plan["attempts"]:
        _attempt(spec, earlier)
        earlier[spec["identity"]["attempt_id"]] = spec
    return earlier


def _claim(claim: Any, artifacts: dict[str, bytes]) -> None:
    """Keep outcome, reason, native meaning, policy and supporting bytes separate."""
    object_keys(
        claim,
        {"status", "reason_code", "native_reason", "profile", "evidence"},
        "claim_shape",
    )
    require(
        type(claim["status"]) is str and claim["status"] in OUTCOMES, "claim_status"
    )
    identifier(claim["reason_code"])
    identifier(claim["profile"])
    require(
        type(claim["native_reason"]) is str and len(claim["native_reason"]) <= 4096,
        "native_reason",
    )
    require(type(claim["evidence"]) is list, "claim_evidence")
    require(
        claim["status"] not in {"pass", "fail"} or bool(claim["evidence"]),
        "decisive_claim_without_evidence",
    )
    for ref in claim["evidence"]:
        artifact(ref, artifacts)


def _measurement(record: Any, artifacts: dict[str, bytes]) -> None:
    """Validate independent axes and refuse implicit zero-effect completeness."""
    object_keys(record["resources"], RESOURCES, "resource_shape")
    for value in record["resources"].values():
        require(value is None or (type(value) is int and value >= 0), "resource_value")
    object_keys(record["claims"], AXES, "claim_axes")
    for claim in record["claims"].values():
        _claim(claim, artifacts)
    coverage = record["capture"]
    object_keys(
        coverage,
        {"scope", "complete", "gaps", "observed_effect_count"},
        "capture_shape",
    )
    identifier(coverage["scope"])
    require(type(coverage["complete"]) is bool, "capture_complete_type")
    require(
        type(coverage["gaps"]) is list
        and all(type(x) is str for x in coverage["gaps"]),
        "capture_gaps",
    )
    require(
        not coverage["complete"] or not coverage["gaps"], "complete_capture_with_gaps"
    )
    count = coverage["observed_effect_count"]
    require(count is None or (type(count) is int and count >= 0), "effect_count")
    effect = record["claims"]["effect"]
    absence = (
        effect["status"] == "pass" and effect["reason_code"] == "no_effect_in_scope"
    )
    require(
        not absence or (coverage["complete"] and count == 0), "absence_without_coverage"
    )


def _native(record: Any, artifacts: dict[str, bytes]) -> None:
    """Bind report claims to retained normalized output, without native appraisal."""
    artifact(record["output"], artifacts)
    payload = decode(artifacts[record["output"]["name"]])
    expected = {k: v for k, v in record.items() if k != "output"}
    require(encode(payload) == encode(expected), "output_binding_mismatch")


def _record(
    record: Any, plan: Any, specs: dict[str, Any], artifacts: dict[str, bytes]
) -> str:
    """Validate one declared attempt including unsuccessful and absent attempts."""
    object_keys(
        record,
        {
            "run_id",
            "identity",
            "tier",
            "parent_attempt_id",
            "harness_status",
            "resources",
            "claims",
            "capture",
            "output",
        },
        "record_shape",
    )
    require(record["run_id"] == plan["run_id"], "cross_run_record")
    _identity(record["identity"])
    aid = record["identity"]["attempt_id"]
    require(aid in specs, "undeclared_attempt")
    expected = {k: record[k] for k in ("identity", "tier", "parent_attempt_id")}
    require(encode(expected) == encode(specs[aid]), "attempt_identity_changed")
    require(
        type(record["harness_status"]) is str and record["harness_status"] in STATUSES,
        "harness_status",
    )
    _measurement(record, artifacts)
    if record["harness_status"] != "complete":
        require(
            record["claims"]["task_outcome"]["status"] not in {"pass", "fail"},
            "unsuccessful_attempt_scored",
        )
    if record["harness_status"] == "not-started":
        require(
            all(v is None for v in record["resources"].values()), "unstarted_resources"
        )
        require(record["capture"]["observed_effect_count"] is None, "unstarted_effect")
    _native(record, artifacts)
    return aid


def validate(
    plan_bytes: bytes,
    history_bytes: bytes,
    artifacts: dict[str, bytes],
    *,
    expected_plan_sha256: str,
    expected_history_sha256: str,
) -> dict[str, Any]:
    """Check an exact finite attempt population and return separate denominators.

    Parameters
    ----------
    plan_bytes, history_bytes : bytes
        Frozen declaration and retained history. History includes every planned
        attempt, an ordered start ledger and a named scope. These are assertions
        by their operator until separately witnessed; this function authenticates
        neither their origin nor completeness outside the declared population.
    artifacts : dict[str, bytes]
        Consumer-supplied original octets, keyed by names rather than fetch paths.
    expected_plan_sha256, expected_history_sha256 : str
        Consumer-held digests selected outside the submitted packet. Taking these
        from the packet itself removes their protection against total replacement.

    Returns
    -------
    dict[str, Any]
        Counts for planned, started, complete, scored, failed, missing and each
        harness status, plus exact pins and an explicit non-attestation boundary.

    Raises
    ------
    ContractError
        On a mismatched pin, hidden/omitted/reused attempt, changed run or retry
        scope, inconsistent measurement, or altered retained output.

    Notes
    -----
    Passing validates accounting and bytes. It does not establish task correctness,
    prior commitment, independent observation, native signatures, or host adoption.
    Use a native adapter before this function for those separately scoped checks.
    """
    pinned(plan_bytes, expected_plan_sha256)
    pinned(history_bytes, expected_history_sha256)
    plan, history = decode(plan_bytes), decode(history_bytes)
    specs = _plan(plan, artifacts)
    object_keys(
        history,
        {
            "profile",
            "run_id",
            "plan_sha256",
            "start_ledger",
            "history_head_ref",
            "records",
        },
        "history_shape",
    )
    require(
        history["profile"] == PROFILE and history["run_id"] == plan["run_id"],
        "cross_run_history",
    )
    require(history["plan_sha256"] == expected_plan_sha256, "history_plan_mismatch")
    require(type(history["records"]) is list, "records_population")
    ids = [_record(record, plan, specs, artifacts) for record in history["records"]]
    require(len(ids) == len(set(ids)), "duplicate_record")
    require(set(ids) == set(specs), "omitted_attempt")
    starts = history["start_ledger"]
    require(
        type(starts) is list and all(type(x) is str for x in starts),
        "start_ledger_shape",
    )
    require(len(starts) == len(set(starts)), "reused_attempt_start")
    started = [
        r["identity"]["attempt_id"]
        for r in history["records"]
        if r["harness_status"] != "not-started"
    ]
    require(starts == started, "start_ledger_mismatch")
    seen: set[str] = set()
    for aid in starts:
        parent = specs[aid]["parent_attempt_id"]
        require(parent is None or parent in seen, "retry_started_before_parent")
        seen.add(aid)
    artifact(history["history_head_ref"], artifacts)
    ledger = decode(artifacts[history["history_head_ref"]["name"]])
    require(
        encode(ledger) == encode({"run_id": plan["run_id"], "starts": starts}),
        "history_head_mismatch",
    )
    counts = Counter(r["harness_status"] for r in history["records"])
    scored = sum(
        r["claims"]["task_outcome"]["status"] in {"pass", "fail"}
        for r in history["records"]
    )
    return {
        "profile": PROFILE,
        "run_id": plan["run_id"],
        "mode": plan["mode"],
        "planned": len(specs),
        "started": len(starts),
        "complete": counts["complete"],
        "scored": scored,
        "task_passed": sum(
            r["claims"]["task_outcome"]["status"] == "pass" for r in history["records"]
        ),
        "task_failed": sum(
            r["claims"]["task_outcome"]["status"] == "fail" for r in history["records"]
        ),
        "failed": sum(counts[s] for s in ("error", "timeout", "interrupted")),
        "missing": counts["not-started"],
        "incomplete": counts["incomplete"],
        "harness_counts": dict(counts),
        "plan_sha256": expected_plan_sha256,
        "history_sha256": expected_history_sha256,
        "boundary": "declared-population byte consistency; not execution, benchmark quality, signature verification or independent custody",
    }
