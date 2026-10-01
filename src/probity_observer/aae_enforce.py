"""Recompute AAE enforce-core 3.0 decisions without the producer's verifier.

This kernel evaluates unsigned mandate/transaction JSON only. It does not
authenticate an issuer, run the AAE nine-step JWS verifier, or observe an effect.
RFC 8785 serialization comes from the separately maintained rfc8785 package.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VERSION = "3.0"
TAGS = {
    "action": "aae:enforce-action:v1",
    "mandate": "aae:enforce-mandate:v1",
    "transaction": "aae:enforce-transaction:v1",
    "core": "aae:enforce-core:v1",
    "statement": "aae:enforce-ratify-statement:v1",
    "ratify_core": "aae:enforce-ratify-core:v1",
}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 64


class RatifyError(ValueError):
    """The proposed ratification does not identify a ratifiable prior record."""


def canonical_bytes(value: Any) -> bytes:
    """Serialize JSON under RFC 8785, then check the two-MiB byte limit.

    Nesting is checked first. The byte check happens after serialization; it is
    not a CPU or memory bound for an arbitrary Python object supplied by a caller.

    Parameters
    ----------
    value : Any
        JSON value; dictionary keys remain strings, integers remain within the
        serializer's safe range, and strings must be valid UTF-8.

    Returns
    -------
    bytes
        JCS bytes, without a digest domain tag.

    Raises
    ------
    ValueError
        If the value exceeds the local byte limit.
    rfc8785.CanonicalizationError
        If the value cannot be represented by the selected JCS implementation.
    """
    _depth(value)
    raw = rfc8785.dumps(value)
    if len(raw) > MAX_BYTES:
        raise ValueError("AAE JSON exceeds the local two-MiB limit")
    return raw


def _depth(value: Any, level: int = 0) -> None:
    """Refuse excessive nesting before the serializer descends."""
    if level > MAX_DEPTH:
        raise ValueError("AAE JSON exceeds the local nesting limit")
    if isinstance(value, dict):
        children = value.values()
    elif isinstance(value, list):
        children = value
    else:
        return
    for child in children:
        _depth(child, level + 1)


def native_digest(kind: str, value: Any) -> str | None:
    """Hash JCS bytes under the named AAE tag; return None on invalid input."""
    try:
        raw = canonical_bytes(value)
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        return None
    tagged = TAGS[kind].encode("ascii") + b"\0" + raw
    return "sha256:" + hashlib.sha256(tagged).hexdigest()


def _same(left: Any, right: Any) -> bool:
    """Compare UTF-8 strings without prefix, case or Unicode normalization."""
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
    except UnicodeError:
        return False


def _pred(
    name: str,
    passed: bool,
    field_name: Any = None,
    value: Any = None,
    bound: Any = None,
) -> dict[str, Any]:
    return {
        "predicate": name,
        "field": field_name,
        "value": value,
        "bound": bound,
        "result": "PASS" if passed else "FAIL",
    }


@dataclass
class _Decision:
    verdict: str = "DENY"
    reason: str = "no matching grant satisfied its constraints"
    index: int | None = None
    trace: list[dict[str, Any]] = field(default_factory=list)


def _type_fields(value: Any) -> bool:
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        return False
    if any(not isinstance(item, str) or not item for item in value):
        return False
    return len(set(value)) == len(value) and "verb" in value


def _grant(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    binding = value.get("action_binding")
    if not isinstance(binding, str) or DIGEST.fullmatch(binding) is None:
        return False
    constraints = value.get("constraints")
    return (
        value.get("disposition") in ("allow", "hold", "forbid")
        and _type_fields(value.get("type_fields"))
        and isinstance(constraints, list)
        and len(constraints) <= 64
    )


def _mandate_problem(mandate: Any) -> str | None:
    if not isinstance(mandate, dict):
        return "mandate missing or not an object"
    grants = mandate.get("grants")
    if not isinstance(grants, list) or not grants:
        return "mandate.grants missing or empty"
    if len(grants) > 256:
        return "mandate.grants exceeds cap"
    invalid = next((i for i, value in enumerate(grants) if not _grant(value)), None)
    if invalid is not None:
        return f"grant[{invalid}] malformed type_fields or grant fields"
    return None


def _shape_reason(action: Any, names: list[str]) -> str | None:
    if not isinstance(action, dict):
        return "action is not an object"
    missing, extra = sorted(set(names) - set(action)), sorted(set(action) - set(names))
    if missing and extra:
        return f"missing type_fields {missing}; outside type_fields {extra}"
    if missing:
        return f"missing type_fields {missing}"
    if extra:
        return f"outside type_fields {extra}"
    return None


def _field(transaction: dict[str, Any], path: Any) -> tuple[bool, Any]:
    if not isinstance(path, str) or not path:
        return False, None
    segments = path.split(".")
    if len(segments) > 8 or any(not part for part in segments):
        return False, None
    cursor: Any = transaction
    for part in segments:
        if not isinstance(cursor, dict) or part not in cursor:
            return False, None
        cursor = cursor[part]
    return True, cursor


def _integer(value: Any) -> bool:
    return (
        isinstance(value, int) and not isinstance(value, bool) and abs(value) <= 10**15
    )


def _exact(constraint: dict[str, Any], transaction: dict[str, Any]) -> dict[str, Any]:
    expected = constraint.get("value")
    found, actual = _field(transaction, constraint.get("field"))
    observed = actual if isinstance(expected, str) and found else None
    passed = found and _same(actual, expected)
    return _pred("exact", passed, constraint.get("field"), observed, expected)


def _enumeration(
    constraint: dict[str, Any], transaction: dict[str, Any]
) -> dict[str, Any]:
    members = constraint.get("values")
    name = constraint.get("field")
    if not isinstance(members, list) or not members:
        return _pred("enum", False, name, None, members)
    if len(members) > 512:
        return _pred("enum", False, name, None, len(members))
    found, actual = _field(transaction, name)
    if not found:
        return _pred("enum", False, name, None, members)
    matches = [_same(actual, member) for member in members]
    return _pred("enum", any(matches), name, actual, members)


def _range(constraint: dict[str, Any], transaction: dict[str, Any]) -> dict[str, Any]:
    lo, hi = constraint.get("lo"), constraint.get("hi")
    bound = {"lo": lo, "hi": hi}
    name = constraint.get("field")
    if not _integer(lo) or not _integer(hi):
        return _pred("range", False, name, None, bound)
    if lo > hi:
        return _pred("range", False, name, None, bound)
    found, actual = _field(transaction, name)
    passed = found and _integer(actual) and lo <= actual <= hi
    return _pred("range", passed, name, actual if found else None, bound)


def _constraint(value: Any, transaction: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        return _pred("unknown", False)
    kind = value.get("type")
    handlers = {"exact": _exact, "enum": _enumeration, "range": _range}
    if not isinstance(kind, str) or kind not in handlers:
        return _pred(str(kind), False, value.get("field"))
    return handlers[kind](value, transaction)


def _satisfied(
    decision: _Decision,
    matched: list[int],
    grants: list[dict[str, Any]],
    transaction: dict[str, Any],
) -> None:
    for index in matched:
        predicates = [
            _constraint(value, transaction) for value in grants[index]["constraints"]
        ]
        decision.trace.extend(predicates)
        if all(item["result"] == "PASS" for item in predicates):
            disposition = grants[index]["disposition"]
            decision.index = index
            decision.verdict = "PERMIT" if disposition == "allow" else "PENDING"
            decision.reason = f"all constraints hold; disposition={disposition}"
            decision.trace.append(_pred("disposition", True, value=disposition))
            return


def _bound_grants(
    decision: _Decision,
    typed: list[int],
    grants: list[dict[str, Any]],
    transaction: dict[str, Any],
    action_digest: str,
) -> None:
    matched = [i for i in typed if _same(grants[i]["action_binding"], action_digest)]
    if not matched:
        decision.reason = "unaddressed action"
        decision.trace.append(_pred("action_binding", False, "action", action_digest))
        return
    decision.trace.append(
        _pred("action_binding", True, "action", action_digest, action_digest)
    )
    forbidden = [i for i in matched if grants[i]["disposition"] == "forbid"]
    if forbidden:
        decision.index = forbidden[0]
        decision.reason = "disposition=forbid"
        decision.trace.append(_pred("disposition", False, value="forbid"))
        return
    _satisfied(decision, matched, grants, transaction)


def _typed_grants(
    decision: _Decision,
    mandate: dict[str, Any],
    transaction: dict[str, Any],
    action_digest: str,
) -> None:
    action = transaction.get("action")
    grants = mandate["grants"]
    typed = [
        i
        for i, grant in enumerate(grants)
        if _shape_reason(action, grant["type_fields"]) is None
    ]
    if not typed:
        decision.reason = (
            _shape_reason(action, grants[0]["type_fields"]) or "type mismatch"
        )
        value = sorted(action) if isinstance(action, dict) else None
        decision.trace.append(
            _pred("type_fields", False, "action", value, list(grants[0]["type_fields"]))
        )
        return
    decision.trace.append(
        _pred(
            "type_fields",
            True,
            "action",
            sorted(action),
            list(grants[typed[0]]["type_fields"]),
        )
    )
    _bound_grants(decision, typed, grants, transaction, action_digest)


def _evaluate(mandate: Any, transaction: Any, action_digest: str | None) -> _Decision:
    decision = _Decision()
    problem = _mandate_problem(mandate)
    if problem is not None:
        decision.reason = problem
        decision.trace.append(_pred("mandate_present", False))
    elif not isinstance(transaction, dict):
        decision.reason = "transaction missing or not an object"
        decision.trace.append(_pred("transaction_present", False))
    elif action_digest is None:
        decision.reason = "transaction.action missing or not canonicalizable"
        decision.trace.append(_pred("action_binding", False, "action"))
    else:
        decision.trace.append(_pred("mandate_present", True))
        _typed_grants(decision, mandate, transaction, action_digest)
    return decision


def enforce_check(
    mandate: Any, transaction: Any, prev_core_digest: str | None = None
) -> dict[str, Any]:
    """Recompute the unsigned enforce-core 3.0 decision and exact digest.

    Parameters
    ----------
    mandate, transaction : Any
        Retained JSON inputs, not a signed AAE. Unknown constraints fail closed.
    prev_core_digest : str or None
        Caller-supplied predecessor; no external history is queried.

    Returns
    -------
    dict[str, Any]
        Verdict, ordered predicate trace, core and tagged JCS core digest.
        A PERMIT is a kernel decision, not authenticated issuer authority or an
        observation that the action executed.
    """
    action_digest = (
        native_digest("action", transaction.get("action"))
        if isinstance(transaction, dict)
        else None
    )
    decision = _evaluate(mandate, transaction, action_digest)
    core = {
        "enforce_version": VERSION,
        "mandate_digest": native_digest("mandate", mandate),
        "transaction_digest": native_digest("transaction", transaction),
        "action_digest": action_digest,
        "verdict": decision.verdict,
        "grant_index": decision.index,
        "trace": decision.trace,
        "prev_core_digest": prev_core_digest
        if isinstance(prev_core_digest, str)
        else None,
    }
    return {
        "verdict": decision.verdict,
        "reason": decision.reason,
        "grant_index": decision.index,
        "trace": decision.trace,
        "core": core,
        "core_digest": native_digest("core", core),
    }


def ratify_statement(prior_digest: str, decision: str, authority: str) -> bytes:
    """Return the native domain-separated bytes an authority must sign."""
    statement = {
        "ratify_version": VERSION,
        "ratifies": prior_digest,
        "decision": decision,
        "authority": authority,
    }
    return TAGS["statement"].encode("ascii") + b"\0" + canonical_bytes(statement)


def _prior(
    prior_record: Any, decision: str, previous: str | None
) -> tuple[dict[str, Any], str]:
    if decision not in ("APPROVED", "DISAPPROVED"):
        raise RatifyError("decision must be APPROVED or DISAPPROVED")
    if not isinstance(prior_record, dict):
        raise RatifyError("prior_record missing or not an object")
    core, claimed = prior_record.get("core"), prior_record.get("core_digest")
    if not isinstance(core, dict) or not isinstance(claimed, str):
        raise RatifyError("prior_record.core or core_digest missing")
    _prior_core(core, claimed, previous)
    return core, claimed


def _prior_core(core: dict[str, Any], claimed: str, previous: str | None) -> None:
    if native_digest("core", core) != claimed:
        raise RatifyError("prior_record.core_digest does not match its own core")
    if "mandate_digest" not in core:
        raise RatifyError("prior_record has no mandate_digest")
    _core_profile(core)
    if core.get("verdict") not in ("DENY", "PENDING"):
        raise RatifyError("prior verdict is not ratifiable")
    if previous is not None and previous != claimed:
        raise RatifyError(
            "prev_core_digest must equal the core_digest of the record being ratified"
        )


def _core_profile(core: dict[str, Any]) -> None:
    fields = {
        "enforce_version",
        "mandate_digest",
        "transaction_digest",
        "action_digest",
        "verdict",
        "grant_index",
        "trace",
        "prev_core_digest",
    }
    if set(core) != fields:
        raise RatifyError("prior_record core fields differ from enforce-core 3.0")
    if core["enforce_version"] != VERSION:
        raise RatifyError("prior_record enforce version is not 3.0")
    _core_digests(core)
    index = core["grant_index"]
    if index is not None and (type(index) is not int or index < 0 or index > 255):
        raise RatifyError("prior_record core has a malformed grant index")
    if not _trace_profile(core["trace"]):
        raise RatifyError("prior_record core has a malformed predicate trace")


def _core_digests(core: dict[str, Any]) -> None:
    mandate_digest = core["mandate_digest"]
    if (
        not isinstance(mandate_digest, str)
        or DIGEST.fullmatch(mandate_digest) is None
        or any(
            value is not None
            and (not isinstance(value, str) or DIGEST.fullmatch(value) is None)
            for value in (core["transaction_digest"], core["action_digest"])
        )
    ):
        raise RatifyError("prior_record core has malformed input digests")
    previous = core["prev_core_digest"]
    if previous is not None and (
        not isinstance(previous, str) or DIGEST.fullmatch(previous) is None
    ):
        raise RatifyError("prior_record core has a malformed predecessor digest")


def _trace_profile(trace: Any) -> bool:
    return isinstance(trace, list) and all(_trace_entry_profile(item) for item in trace)


def _trace_entry_profile(item: Any) -> bool:
    if not isinstance(item, dict) or set(item) != {
        "predicate",
        "field",
        "value",
        "bound",
        "result",
    }:
        return False
    if not isinstance(item["predicate"], str) or item["result"] not in ("PASS", "FAIL"):
        return False
    return item["field"] is None or isinstance(item["field"], str)


def _authority(entry: Any, role: str) -> tuple[str, str, str] | None:
    if not isinstance(entry, dict):
        return None
    did, key = entry.get("did"), entry.get("public_key")
    if not isinstance(did, str) or not isinstance(key, str):
        return None
    if not did.startswith("did:") or any(char in did for char in "/?#"):
        return None
    return did, key, entry.get("role") if isinstance(entry.get("role"), str) else role


def _authorities(mandate: Any) -> list[tuple[str, str, str]]:
    if not isinstance(mandate, dict):
        return []
    principal = _authority(mandate.get("principal"), "principal")
    entries = mandate.get("ratification_authorities", [])
    if principal is None or not isinstance(entries, list) or len(entries) > 64:
        return []
    authorities = [_authority(entry, "named_authority") for entry in entries]
    if any(item is None for item in authorities):
        return []
    allowed = [principal, *authorities]
    if len({item[0] for item in allowed}) != len(allowed):
        return []
    return allowed


def _signature(key: Any, signature: Any, message: bytes) -> bool:
    if not isinstance(key, str) or not isinstance(signature, str):
        return False
    try:
        raw, signed = bytes.fromhex(key), bytes.fromhex(signature)
        if len(raw) != 32 or len(signed) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(raw).verify(signed, message)
    except (ValueError, InvalidSignature):
        return False
    return True


def _ratify_authority(
    core: dict[str, Any],
    claimed: str,
    decision: str,
    proof: dict[str, Any],
    trace: list[dict[str, Any]],
) -> tuple[str | None, str]:
    mandate = proof.get("mandate")
    supplied = native_digest("mandate", mandate) if mandate is not None else None
    bound = supplied == core["mandate_digest"]
    trace.append(
        _pred("mandate_binding", bound, "mandate", supplied, core["mandate_digest"])
    )
    if not bound:
        return None, "supplied mandate does not match the prior record"
    allowed = _authorities(mandate)
    match = next(
        (entry for entry in allowed if _same(entry[0], proof.get("authority"))), None
    )
    trace.append(
        _pred(
            "authority_in_mandate",
            match is not None,
            "authority",
            proof.get("authority"),
            [entry[0] for entry in allowed],
        )
    )
    if match is None:
        return None, "authority does not derive from the mandate"
    return _ratify_signature(claimed, decision, proof, match, trace)


def _ratify_signature(
    claimed: str,
    decision: str,
    proof: dict[str, Any],
    authority: tuple[str, str, str],
    trace: list[dict[str, Any]],
) -> tuple[str | None, str]:
    did, key, role = authority
    passed = _signature(
        key, proof.get("signature"), ratify_statement(claimed, decision, did)
    )
    trace.append(_pred("authority_signature", passed, "signature"))
    if not passed:
        return None, "authority signature does not verify"
    return did, f"ratified by {role} {did}"


def ratify(
    prior_record: Any,
    decision: str,
    authority_proof: Any,
    prev_core_digest: str | None = None,
) -> dict[str, Any]:
    """Recompute an appended ratification, preserving the prior verdict.

    Signature keys come from the digest-bound mandate, never the proof's own
    key. This establishes authority relative to that mandate, not authenticity
    of the mandate's issuer; a consumer must authenticate the mandate separately.

    Raises
    ------
    RatifyError
        For a bad prior core, non-ratifiable verdict, invalid decision or a chain
        link naming any record other than the one being ratified.
    """
    core, claimed = _prior(prior_record, decision, prev_core_digest)
    verdict = core["verdict"]
    trace = [_pred("prior_ratifiable", True, value=verdict)]
    authority, reason = None, "authority_proof missing or not an object"
    if isinstance(authority_proof, dict):
        authority, reason = _ratify_authority(
            core, claimed, decision, authority_proof, trace
        )
    else:
        trace.append(_pred("authority_proof", False))
    status = "RATIFIED" if authority is not None else "REJECTED"
    if authority is not None:
        reason += f": prior {verdict} -> {decision}"
    rcore = {
        "ratify_version": VERSION,
        "ratifies": claimed,
        "prior_verdict": verdict,
        "decision": decision,
        "status": status,
        "authority": authority,
        "mandate_digest": core["mandate_digest"],
        "trace": trace,
        "prev_core_digest": claimed,
    }
    return {
        "status": status,
        "decision": decision,
        "ratifies": claimed,
        "authority": authority,
        "reason": reason,
        "trace": trace,
        "core": rcore,
        "core_digest": native_digest("ratify_core", rcore),
        "priorEnforcement": "not-replayed",
    }
