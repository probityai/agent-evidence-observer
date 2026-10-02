"""Host-selected publication policy for the frozen 384-call boundary profile.

The native reader remains byte-identical to the original experiment. This module
checks the complete host selection and the reader's report before applying any
threshold. It grants report publication only; it grants no execution authority.
"""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from itertools import product
from pathlib import Path
from typing import Any

PROFILE = "probity-local-cpu-boundary-tasks-v1"
SCHEMA = "probity-model-publication-policy-v3"
IDENTITY_FIELDS = ("model", "decoder", "configuration", "family")
THRESHOLDS = {
    "minCorrect": "correct",
    "minFormatValid": "formatValid",
    "minSchemaValid": "schemaValid",
    "minFullyCorrectPairs": "fullyCorrectPairs",
}
LIMIT_KEYS = (
    "elapsedNs",
    "promptTokens",
    "completionTokens",
    "returnedCallProcessCpuNs",
    "processLifetimePeakRssKiB",
    "totalProcessCpuNs",
    "preparationPayloadBytes",
)
ROW_RESOURCE_SCOPE = (
    "returned calls only; CPU is whole-process delta, RSS is lifetime peak, "
    "not task allocation"
)
_LOGGER = logging.getLogger(__name__)
Record = dict[str, Any]
RowIdentity = tuple[str, ...]


def _require(condition: bool, message: str) -> None:
    """Log a precise refusal and raise the same message for durable receipts."""
    if not condition:
        _LOGGER.warning(message)
        raise ValueError(message)


def _object(value: Any, fields: set[str], message: str) -> Record:
    """Require an exact object grammar, including absence of unknown fields."""
    _require(type(value) is dict and set(value) == fields, message)
    return value


def _integer(value: Any) -> int:
    """Read a nonnegative integer, refusing booleans and numerical coercion."""
    _require(
        type(value) is int and value >= 0,
        "boundary counts require nonnegative integers",
    )
    return value


def _string(value: Any) -> str:
    """Read a nonempty literal identity without string coercion."""
    _require(
        type(value) is str and bool(value),
        "boundary identities require nonempty strings",
    )
    return value


def _digest(value: Any) -> str:
    """Require a literal lowercase SHA256 selected by the external host."""
    _require(
        type(value) is str
        and len(value) == 64
        and set(value) <= set("0123456789abcdef"),
        "boundary policy requires lowercase SHA256 selections",
    )
    return value


def identity(row: Record) -> RowIdentity:
    """Return the complete model/decoder/cap/family key used by :func:`decide`."""
    _require(type(row) is dict, "boundary quality row requires an object")
    return tuple(_string(row.get(name)) for name in IDENTITY_FIELDS)


def _selected_row(row: Any) -> None:
    """Validate independent semantic, schema, format and paired thresholds."""
    _object(
        row,
        {*IDENTITY_FIELDS, "planned", "plannedPairs", *THRESHOLDS},
        "boundary policy row fields differ",
    )
    identity(row)
    counts = {
        key: _integer(row[key]) for key in ("planned", "plannedPairs", *THRESHOLDS)
    }
    _require(
        counts["planned"] == 16 and counts["plannedPairs"] == 8,
        "boundary row denominator must retain sixteen cases and eight pairs",
    )
    _require(
        max(counts[key] for key in THRESHOLDS) <= 16,
        "boundary row threshold exceeds selected population",
    )
    _require(
        counts["minFullyCorrectPairs"] <= counts["plannedPairs"],
        "boundary pair threshold exceeds selected pair population",
    )


def _cases(policy: Record) -> dict[str, Record]:
    """Validate all authored identities; repeated literal inputs remain disclosed."""
    population = _object(
        policy["casePopulation"],
        {
            "authoredIdentities",
            "uniqueLiteralInputs",
            "casesPerFamily",
            "pairsPerFamily",
        },
        "boundary case population fields differ",
    )
    expected = dict(
        authoredIdentities=48,
        uniqueLiteralInputs=46,
        casesPerFamily=16,
        pairsPerFamily=8,
    )
    _require(
        {key: _integer(value) for key, value in population.items()} == expected,
        "boundary authored population differs from frozen selection",
    )
    cases = policy["cases"]
    _require(
        type(cases) is list and len(cases) == 48,
        "boundary policy requires all forty-eight case identities",
    )
    selected: dict[str, Record] = {}
    for case in cases:
        _object(
            case,
            {"id", "family", "pair", "pairRole", "inputSha256"},
            "boundary case selection fields differ",
        )
        for field in ("id", "family", "pair", "pairRole"):
            _string(case[field])
        _digest(case["inputSha256"])
        _require(
            case["id"] not in selected, "duplicate selected boundary case identity"
        )
        selected[case["id"]] = case
    _require(
        len({case["inputSha256"] for case in cases}) == 46,
        "boundary unique literal input population differs",
    )
    _case_pairs(cases)
    return selected


def _case_pairs(cases: list[Record]) -> None:
    """Require sixteen cases and eight two-role pairs in each frozen family."""
    families: dict[str, list[Record]] = defaultdict(list)
    for case in cases:
        families[case["family"]].append(case)
    _require(
        set(families) == {"typed-boundary", "policy-boundary", "grounded-boundary"},
        "boundary case families differ",
    )
    for members in families.values():
        pairs: dict[str, list[str]] = defaultdict(list)
        for case in members:
            pairs[case["pair"]].append(case["pairRole"])
        _require(
            len(members) == 16 and len(pairs) == 8,
            "boundary case family or pair denominator differs",
        )
        _require(
            all(sorted(roles) == ["a", "b"] for roles in pairs.values()),
            "boundary pairs require exactly one case of each role",
        )


def validate_policy(policy: Any) -> None:
    """Validate the external policy before any native reader code is launched.

    Parameters
    ----------
    policy : dict
        Strictly decoded host policy. Each of the 24 rows selects one model,
        decoder, output cap and family; all 48 cases and 46 literal input
        digests must be explicitly retained. Resource limits include whole-run
        CPU and selected preparation payload, separately from returned-call CPU.

    Raises
    ------
    ValueError
        If the grammar, profile version, denominator, identity, pair role,
        digest or integer selection differs. The refusal is also logged.

    See Also
    --------
    verify_host_selection : Bind the case selections to the selected protocol.
    decide : Verify the complete report and apply these thresholds.
    """
    _object(
        policy,
        {
            "schema",
            "profile",
            "planned",
            "rows",
            "limits",
            "pinsSha256",
            "readerSha256",
            "casePopulation",
            "cases",
        },
        "boundary policy fields differ",
    )
    _require(
        policy["schema"] == SCHEMA and policy["profile"] == PROFILE,
        "boundary policy schema or profile differs",
    )
    _require(
        _integer(policy["planned"]) == 384, "boundary policy must retain 384 attempts"
    )
    _digest(policy["pinsSha256"])
    _digest(policy["readerSha256"])
    _cases(policy)
    rows = policy["rows"]
    _require(
        type(rows) is list and len(rows) == 24,
        "boundary policy requires all twenty-four quality rows",
    )
    for row in rows:
        _selected_row(row)
    expected = set(
        product(
            ("smol135-q4", "smol360-q4"),
            ("unconstrained", "schema"),
            ("short24", "long96"),
            ("typed-boundary", "policy-boundary", "grounded-boundary"),
        )
    )
    _require(
        {identity(row) for row in rows} == expected,
        "boundary quality row identities differ or repeat",
    )
    limits = _object(
        policy["limits"], set(LIMIT_KEYS), "boundary policy resource fields differ"
    )
    for value in limits.values():
        _integer(value)


def verify_host_selection(
    packet: Path, pins: Record, policy: Record, decode: Any
) -> None:
    """Bind externally selected case identities to authenticated protocol bytes.

    Parameters
    ----------
    packet : pathlib.Path
        Producer packet. No code is imported or executed from this directory.
    pins : dict
        Independently frozen native pins already bound by ``pinsSha256``.
    policy : dict
        Policy accepted by :func:`validate_policy`, outside ``packet``.
    decode : callable
        Strict JSON decoder rejecting duplicates and nonfinite constants.

    Raises
    ------
    ValueError
        If protocol bytes, a case identity/input, or the complete case
        population differs from the host's selection.

    Notes
    -----
    The installed native reader additionally verifies its frozen protocol,
    original source/runtime/model provenance and every retained member.
    """
    _require(type(pins) is dict, "boundary native pins require an object")
    pin = _object(
        pins.get("protocol"), {"path", "sha256"}, "boundary protocol pin fields differ"
    )
    path = packet / _string(pin["path"])
    _require(
        path.resolve().is_relative_to(packet.resolve()) and not path.is_symlink(),
        "boundary selected protocol escapes producer packet",
    )
    raw = path.read_bytes()
    _require(
        hashlib.sha256(raw).hexdigest() == _digest(pin["sha256"]),
        "boundary selected protocol bytes changed",
    )
    protocol = decode(raw)
    _require(type(protocol) is dict, "boundary protocol requires an object")
    selected = _cases(policy)
    native = protocol.get("cases", [])
    _require(
        type(native) is list and len(native) == len(selected),
        "boundary protocol case population differs",
    )
    observed = [
        {
            "id": case["id"],
            "family": case["family"],
            "pair": case["pair"],
            "pairRole": case["role"],
            "inputSha256": hashlib.sha256(case["input"].encode()).hexdigest(),
        }
        for case in native
    ]
    _require(
        observed == policy["cases"],
        "boundary protocol cases differ from host selection",
    )


def _report_population(report: Record) -> None:
    """Refuse absent, unsupported or incomplete outcomes without denominator loss."""
    _object(
        report,
        {
            "profile",
            "publicationDecision",
            "evidence",
            "population",
            "quality",
            "nativeTokens",
            "preparation",
            "elapsed_ns",
            "process_cpu_ns",
            "attempts",
            "interpretation",
            "custody",
            "effects",
            "tokenScope",
        },
        "boundary report fields differ",
    )
    expected = dict(
        planned=384, started=384, scored=384, error=0, incomplete=0, unsupported=0
    )
    expected["unknown-start"] = 0
    population = _object(
        report["population"], set(expected), "boundary report population fields differ"
    )
    _require(
        {key: _integer(value) for key, value in population.items()} == expected,
        "boundary report population differs from host selection",
    )
    evidence = _object(
        report["evidence"],
        {"complete", "withinRunBudget"},
        "boundary evidence fields differ",
    )
    _require(
        all(value is True for value in evidence.values()),
        "boundary evidence validity is not established",
    )
    _require(
        report["profile"] == PROFILE
        and report["publicationDecision"] == "publish-scoped-report",
        "boundary reader profile or publication decision differs",
    )


def _measured_row(row: Record) -> None:
    """Validate every count, exact denominator and declared resource scope."""
    fields = {
        *IDENTITY_FIELDS,
        "planned",
        "scored",
        "correct",
        "formatValid",
        "schemaValid",
        "plannedPairs",
        "fullyCorrectPairs",
        "promptTokens",
        "completionTokens",
        "callElapsedNs",
        "processCpuNs",
        "processLifetimePeakRssKiB",
        "resourceScope",
    }
    _object(row, fields, "boundary report row fields differ")
    identity(row)
    for field in fields - set(IDENTITY_FIELDS) - {"resourceScope"}:
        _integer(row[field])
    _require(
        row["planned"] == row["scored"] == 16 and row["plannedPairs"] == 8,
        "boundary measured row or pair denominator differs",
    )
    _require(
        row["correct"] <= row["schemaValid"] <= row["formatValid"] <= 16,
        "boundary semantic, schema and format counts are inconsistent",
    )
    _require(
        row["fullyCorrectPairs"] <= 8
        and row["fullyCorrectPairs"] * 2 <= row["correct"],
        "boundary paired correctness exceeds semantic correctness",
    )
    _require(
        row["resourceScope"] == ROW_RESOURCE_SCOPE,
        "boundary row resource scope differs",
    )


def _attempt(attempt: Record, selected: Record, key: RowIdentity) -> None:
    """Validate an authored case's literal identity, outcome and typed scores."""
    _object(
        attempt,
        {
            *IDENTITY_FIELDS,
            "id",
            "pair",
            "pairRole",
            "outcome",
            "output",
            "correct",
            "formatValid",
            "schemaValid",
            "tokens",
            "resources",
        },
        "boundary attempt fields differ",
    )
    _require(
        identity(attempt) == key and attempt["outcome"] == "scored",
        "boundary attempt identity or outcome differs",
    )
    _require(
        attempt["pair"] == selected["pair"]
        and attempt["pairRole"] == selected["pairRole"],
        "boundary attempt pair identity or role differs",
    )
    flags = [attempt[field] for field in ("correct", "schemaValid", "formatValid")]
    _require(
        all(type(flag) is bool for flag in flags) and flags == sorted(flags),
        "boundary attempt semantic, schema or format flags differ",
    )
    _require(type(attempt["output"]) is str, "boundary attempt output requires text")
    tokens = _object(
        attempt["tokens"],
        {"prompt_tokens", "completion_tokens", "total_tokens"},
        "boundary attempt token fields differ",
    )
    _require(
        _integer(tokens["total_tokens"])
        == _integer(tokens["prompt_tokens"]) + _integer(tokens["completion_tokens"]),
        "boundary attempt token subtotal differs",
    )
    resources = _object(
        attempt["resources"],
        {"elapsed_ns", "process_cpu_ns", "process_maxrss_kib"},
        "boundary attempt resource fields differ",
    )
    for value in resources.values():
        _integer(value)


def _summarize(attempts: list[Record]) -> Record:
    """Recompute a single row, including both-role pair correctness, without pooling."""
    pairs: dict[str, list[bool]] = defaultdict(list)
    for attempt in attempts:
        pairs[attempt["pair"]].append(attempt["correct"])
    return {
        "correct": sum(attempt["correct"] for attempt in attempts),
        "schemaValid": sum(attempt["schemaValid"] for attempt in attempts),
        "formatValid": sum(attempt["formatValid"] for attempt in attempts),
        "fullyCorrectPairs": sum(all(flags) for flags in pairs.values()),
        "promptTokens": sum(attempt["tokens"]["prompt_tokens"] for attempt in attempts),
        "completionTokens": sum(
            attempt["tokens"]["completion_tokens"] for attempt in attempts
        ),
        "callElapsedNs": sum(
            attempt["resources"]["elapsed_ns"] for attempt in attempts
        ),
        "processCpuNs": sum(
            attempt["resources"]["process_cpu_ns"] for attempt in attempts
        ),
        "processLifetimePeakRssKiB": max(
            attempt["resources"]["process_maxrss_kib"] for attempt in attempts
        ),
    }


def _verify_attempts(
    report: Record, policy: Record, rows: dict[RowIdentity, Record]
) -> None:
    """Refuse missing/duplicate calls and recompute each row's independent counters."""
    cases = _cases(policy)
    expected = {
        "--".join((key[0], key[2], key[1], case["id"])): (key, case)
        for key in rows
        for case in cases.values()
        if case["family"] == key[3]
    }
    attempts = report["attempts"]
    _require(
        type(attempts) is list and len(attempts) == 384,
        "boundary report requires all 384 attempts",
    )
    grouped: dict[RowIdentity, list[Record]] = defaultdict(list)
    seen: set[str] = set()
    for attempt in attempts:
        _require(type(attempt) is dict, "boundary attempt requires an object")
        ident = _string(attempt.get("id"))
        _require(
            ident in expected and ident not in seen,
            "boundary attempt population differs or repeats",
        )
        key, case = expected[ident]
        _attempt(attempt, case, key)
        seen.add(ident)
        grouped[key].append(attempt)
    _require(seen == set(expected), "boundary attempt population is incomplete")
    for key, row in rows.items():
        subtotal = _summarize(grouped[key])
        _require(
            all(row[field] == value for field, value in subtotal.items()),
            "boundary quality or paired/resource subtotals differ from attempts",
        )


def report_rows(report: Record, policy: Record) -> dict[RowIdentity, Record]:
    """Verify all 24 rows and 384 attempts before :func:`decide` applies minima.

    Parameters
    ----------
    report : dict
        Exact report returned by the separately selected installed native reader.
    policy : dict
        Complete host policy validated by :func:`validate_policy`.

    Returns
    -------
    dict
        Rows indexed by complete model/decoder/cap/family identity. No semantic
        score is aggregated across rows, families, models or decoding methods.

    Raises
    ------
    ValueError
        If any population, attempt identity, role, paired/typed count or
        resource subtotal differs or is malformed.
    """
    _require(type(report) is dict, "boundary report requires an object")
    _report_population(report)
    measured = report["quality"]
    _require(
        type(measured) is list and len(measured) == 24,
        "boundary report requires all twenty-four quality rows",
    )
    for row in measured:
        _measured_row(row)
    rows = {identity(row): row for row in measured}
    _require(
        len(rows) == 24 and set(rows) == {identity(row) for row in policy["rows"]},
        "boundary report quality identities differ or repeat",
    )
    _verify_attempts(report, policy, rows)
    _resources(report, rows)
    return rows


def _resources(report: Record, rows: dict[RowIdentity, Record]) -> dict[str, int]:
    """Retain total CPU, returned-call CPU and shared lifetime RSS separately."""
    tokens = _object(
        report["nativeTokens"],
        {"prompt", "completion"},
        "boundary native token fields differ",
    )
    for field, row_field in (
        ("prompt", "promptTokens"),
        ("completion", "completionTokens"),
    ):
        _require(
            _integer(tokens[field]) == sum(row[row_field] for row in rows.values()),
            "boundary native token subtotal differs",
        )
    elapsed, total_cpu = (
        _integer(report["elapsed_ns"]),
        _integer(report["process_cpu_ns"]),
    )
    call_cpu = sum(row["processCpuNs"] for row in rows.values())
    _require(
        sum(row["callElapsedNs"] for row in rows.values()) <= elapsed,
        "boundary summed serial call time exceeds native elapsed envelope",
    )
    _require(
        call_cpu <= total_cpu, "boundary returned-call CPU exceeds whole-process CPU"
    )
    prep = report["preparation"]
    _require(
        type(prep) is dict and prep.get("complete") is True,
        "boundary preparation validity is not established",
    )
    categories = _object(
        prep["selectedPayloadBytesByCategory"],
        {"dependencies", "metadata", "model", "source"},
        "boundary preparation category fields differ",
    )
    payload = _integer(prep["selectedPayloadBytes"])
    _require(
        payload == sum(_integer(value) for value in categories.values()),
        "boundary preparation payload subtotal differs",
    )
    return dict(
        elapsedNs=elapsed,
        promptTokens=tokens["prompt"],
        completionTokens=tokens["completion"],
        returnedCallProcessCpuNs=call_cpu,
        totalProcessCpuNs=total_cpu,
        processLifetimePeakRssKiB=max(
            row["processLifetimePeakRssKiB"] for row in rows.values()
        ),
        preparationPayloadBytes=payload,
    )


def decide(report: Record, policy: Record) -> Record:
    """Apply every independently selected row and resource threshold.

    Parameters
    ----------
    report : dict
        Selected native report; :func:`report_rows` reconstructs its complete
        denominator, per-case/pair counts and resource subtotals first.
    policy : dict
        External policy frozen before consumer replay. Example policies were
        selected after inference; they are not model-success preregistrations.

    Returns
    -------
    dict
        A verified evidence decision and separate publication decision, every
        row/resource failure, preserved task population and scoped resources.
        One family's successes cannot cover another family's failure.

    Raises
    ------
    ValueError
        If the policy or report is malformed, inconsistent or incomplete.
    """
    validate_policy(policy)
    rows = report_rows(report, policy)
    failures: list[Record] = []
    for selected in policy["rows"]:
        key = identity(selected)
        for threshold, field in THRESHOLDS.items():
            if rows[key][field] < selected[threshold]:
                failures.append(
                    dict(
                        row=dict(zip(IDENTITY_FIELDS, key)),
                        field=field,
                        measured=rows[key][field],
                        minimum=selected[threshold],
                    )
                )
    resources = _resources(report, rows)
    for name, measured in resources.items():
        if measured > policy["limits"][name]:
            failures.append(
                dict(resource=name, measured=measured, maximum=policy["limits"][name])
            )
    return dict(
        evidenceDecision="verified",
        publicationDecision="publish"
        if not failures
        else "hold-selected-score-or-resource",
        policyFailures=failures,
        resources=resources,
        casePopulation=policy["casePopulation"],
        scope="host-selected report publication; no dispatch or recovery authority",
    )
