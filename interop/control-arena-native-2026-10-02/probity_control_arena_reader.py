"""Read a selected, bounded ControlArena native log without a framework import."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import NoReturn, TypeAlias, cast

Json: TypeAlias = None | bool | int | float | str | list["Json"] | dict[str, "Json"]
Object: TypeAlias = dict[str, Json]
LOGGER = logging.getLogger(__name__)
PROFILE = "control-arena-echo-submit-v0"
DOES_NOT_ASSERT = (
    "model quality",
    "external target effect",
    "independent key, clock, store or retention custody",
    "producer acceptance",
    "recurring outside adoption",
    "other ControlArena settings, protocols or scaffolds",
)
SUPPORTED_EVENTS = {
    "span_begin",
    "span_end",
    "sample_init",
    "model",
    "tool",
    "store",
    "state",
}


class ReaderRefusal(ValueError):
    """The selected log is not publishable under this bounded reader profile."""


def refuse(message: str) -> NoReturn:
    LOGGER.warning("ControlArena publication refused: %s", message)
    raise ReaderRefusal(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        refuse(message)


def obj(value: Json, context: str) -> Object:
    require(isinstance(value, dict), f"{context} must be an object")
    return cast(Object, value)


def arr(value: Json, context: str) -> list[Json]:
    require(isinstance(value, list), f"{context} must be an array")
    return cast(list[Json], value)


def string(value: Json, context: str) -> str:
    require(isinstance(value, str), f"{context} must be a string")
    return cast(str, value)


def integer(value: Json, context: str) -> int:
    require(type(value) is int, f"{context} must be an integer")
    return cast(int, value)


def timestamp(value: Json, context: str) -> datetime:
    text = string(value, context)
    try:
        result = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        refuse(f"{context} must be an ISO timestamp")
    require(result.tzinfo is not None, f"{context} must include a timezone")
    return result


def unique_object(pairs: list[tuple[str, Json]]) -> Object:
    result: Object = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON object key")
        result[key] = value
    return result


def forbid_constant(value: str) -> NoReturn:
    refuse(f"Non-finite JSON number: {value}")


def parse(raw: bytes) -> Object:
    try:
        value = json.loads(
            raw, object_pairs_hook=unique_object, parse_constant=forbid_constant
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        refuse(f"Invalid JSON: {error.__class__.__name__}")
    return obj(cast(Json, value), "Document")


@dataclass(frozen=True)
class Policy:
    """A caller-selected policy supplied separately from the candidate log.

    Attributes
    ----------
    log_sha256 : str
        Digest selected by the trusted capture stage, not from the candidate.
    expected_source : Object
        Exact native ``eval.revision`` record expected by the consumer. This
        comparison does not authenticate a candidate's claimed source itself.
    selected_source_commit : str
        Full source SHA selected outside the candidate; the reported native
        abbreviation must be an exact prefix of this full selection.
    expected_inspect : str
        Selected Inspect version; no compatibility claim for other versions.
    samples : tuple
        Complete population of ``(id, epoch, literal input)`` tuples.
    not_before, not_after : datetime
        Outside-selected observation window; candidate clock custody is unknown.

    Notes
    -----
    Source and wheel installation must be authorised before candidate execution.
    This policy does not download, import or install code from the candidate.
    """

    log_sha256: str
    expected_source: Object
    selected_source_commit: str
    expected_inspect: str
    samples: tuple[tuple[str, int, str], ...]
    not_before: datetime
    not_after: datetime

    @classmethod
    def from_bytes(cls, raw: bytes) -> Policy:
        """Validate an externally selected policy with an exact finite population.

        Parameters
        ----------
        raw : bytes
            Trusted policy JSON bytes.

        Returns
        -------
        Policy
            Immutable selection used by :func:`read_log`.

        Raises
        ------
        ReaderRefusal
            On malformed, duplicate or unsupported policy selections.
        """
        data = parse(raw)
        require(data.get("profile") == PROFILE, "Unsupported reader profile")
        digest = string(data.get("logSha256"), "logSha256")
        require(
            len(digest) == 64 and all(c in "0123456789abcdef" for c in digest),
            "Invalid selected log digest",
        )
        selected: list[tuple[str, int, str]] = []
        for item in arr(data.get("expectedSamples"), "expectedSamples"):
            row = obj(item, "Expected sample")
            selected.append(
                (
                    string(row.get("id"), "Sample id"),
                    integer(row.get("epoch"), "Sample epoch"),
                    string(row.get("input"), "Sample input"),
                )
            )
        require(bool(selected), "Selected population must not be empty")
        identities = [(row[0], row[1]) for row in selected]
        require(
            len(set(identities)) == len(identities),
            "Duplicate selected sample identity",
        )
        require(all(row[1] > 0 for row in selected), "Selected epochs must be positive")
        require(
            sorted(selected)
            == [
                (identity, epoch, identity)
                for identity in ("alpha", "beta")
                for epoch in (1, 2)
            ],
            "Unsupported selected population",
        )
        source = obj(data.get("expectedSource"), "expectedSource")
        commit = string(source.get("commit"), "Selected source commit")
        full_commit = string(data.get("selectedSourceCommit"), "selectedSourceCommit")
        require(
            len(full_commit) == 40
            and all(c in "0123456789abcdef" for c in full_commit),
            "Selected full source commit must be 40 lowercase hexadecimal characters",
        )
        require(
            source.get("type") == "git"
            and source.get("dirty") is False
            and 7 <= len(commit) <= 40
            and all(c in "0123456789abcdef" for c in commit)
            and isinstance(source.get("origin"), str),
            "Selected source must be a clean pinned Git revision",
        )
        require(
            full_commit.startswith(commit),
            "Selected source abbreviation must bind the full source commit",
        )
        inspect_version = string(data.get("expectedInspect"), "expectedInspect")
        require(inspect_version == "0.3.257", "Unsupported selected Inspect version")
        lower = timestamp(data.get("notBefore"), "notBefore")
        upper = timestamp(data.get("notAfter"), "notAfter")
        require(lower <= upper, "Selected time window is reversed")
        return cls(
            digest,
            source,
            full_commit,
            inspect_version,
            tuple(selected),
            lower,
            upper,
        )


def within(value: Json, policy: Policy, context: str) -> datetime:
    instant = timestamp(value, context)
    require(
        policy.not_before <= instant <= policy.not_after,
        f"{context} outside selected time window",
    )
    return instant


def no_failure(value: Object, context: str) -> None:
    for key in ("error", "limit", "error_retries", "control_solver_error"):
        require(value.get(key) in (None, [], ""), f"{context} contains {key}")


def validate_header(log: Object, policy: Policy) -> None:
    require(log.get("version") == 2, "Unsupported Inspect log version")
    require(
        log.get("status") == "success" and not log.get("invalidated"),
        "Evaluation incomplete or invalidated",
    )
    no_failure(log, "Evaluation")
    evaluation = obj(log.get("eval"), "eval")
    require(evaluation.get("task") == "evidence_publication_mock", "Unexpected task")
    require(evaluation.get("model") == "mockllm/model", "Unexpected model")
    require(
        evaluation.get("revision") == policy.expected_source, "Source revision mismatch"
    )
    packages = obj(evaluation.get("packages"), "packages")
    require(
        packages.get("inspect_ai") == policy.expected_inspect,
        "Inspect version mismatch",
    )
    metadata = obj(evaluation.get("metadata"), "eval metadata")
    require(log.get("metadata") == metadata, "Evaluation metadata mirror mismatch")
    require(
        obj(metadata.get("setting"), "setting").get("type") == "evidence_publication",
        "Unsupported setting",
    )
    protocol = obj(metadata.get("micro_protocol"), "micro_protocol")
    require(
        protocol.get("type") == "honest_policy"
        and protocol.get("model_role") == "untrusted"
        and protocol.get("cache") is False,
        "Unsupported micro-protocol",
    )
    require(metadata.get("mode") == "honest", "Unsupported evaluation mode")
    dataset = obj(evaluation.get("dataset"), "dataset")
    expected_ids = sorted({row[0] for row in policy.samples})
    require(
        sorted(
            string(x, "Dataset id")
            for x in arr(dataset.get("sample_ids"), "sample_ids")
        )
        == expected_ids,
        "Dataset population mismatch",
    )
    require(dataset.get("samples") == len(expected_ids), "Dataset denominator mismatch")
    plan = obj(log.get("plan"), "plan")
    steps = arr(plan.get("steps"), "plan steps")
    require(len(steps) == 1, "Unsupported ControlArena solver plan")
    step = obj(steps[0], "solver step")
    require(
        step.get("solver") == "control_arena/control_solver",
        "Unsupported ControlArena solver plan",
    )
    params = obj(step.get("params"), "solver params")
    require(
        params.get("max_steps") == 3
        and params.get("scaffold") is None
        and params.get("system_prompt") is None
        and params.get("tool_output_limit") is None,
        "Unsupported ControlArena scaffold parameters",
    )
    require(
        obj(params.get("micro_protocol"), "solver protocol").get("name")
        == "control_arena/honest_policy",
        "Unsupported solver micro-protocol",
    )
    stats = obj(log.get("stats"), "stats")
    start = within(stats.get("started_at"), policy, "Evaluation start")
    end = within(stats.get("completed_at"), policy, "Evaluation completion")
    require(start <= end, "Evaluation time is reversed")


def begin_span(event: Object, active: dict[str, Object], closed: set[str]) -> str:
    identity = string(event.get("id"), "Span id")
    require(
        identity == event.get("span_id")
        and identity not in active
        and identity not in closed,
        "Duplicate or mismatched span",
    )
    parent = event.get("parent_id")
    require(
        parent is None or string(parent, "Span parent") in active, "Unknown span parent"
    )
    signature = (
        string(event.get("type"), "Span type"),
        string(event.get("name"), "Span name"),
    )
    roots = {("init", "init"), ("solvers", "solvers"), ("scorers", "scorers")}
    if parent is None:
        require(signature in roots, "Unsupported root span")
    else:
        parent_kind = active[string(parent, "Span parent")].get("type")
        allowed = (
            parent_kind == "solvers"
            and signature == ("solver", "control_arena/control_solver")
        ) or (
            parent_kind == "solver"
            and signature in (("tool", "echo"), ("tool", "submit"))
        )
        require(allowed, "Unsupported nested span")
    active[identity] = event
    return identity


def end_span(event: Object, active: dict[str, Object]) -> str:
    identity = string(event.get("id"), "Span id")
    require(
        identity == event.get("span_id") and identity in active,
        "Unknown or duplicate span end",
    )
    require(
        not any(span.get("parent_id") == identity for span in active.values()),
        "Span closed with active children",
    )
    begin = active[identity]
    for key in ("parent_id", "type", "name"):
        require(
            event.get(key, begin.get(key)) == begin.get(key),
            "Span begin/end fields mismatch",
        )
    del active[identity]
    return identity


def validate_spans(
    events: list[Object],
) -> tuple[str, dict[str, tuple[Object, Object]]]:
    active: dict[str, Object] = {}
    closed: set[str] = set()
    solver_ids: list[str] = []
    begins: dict[str, Object] = {}
    spans: dict[str, tuple[Object, Object]] = {}
    for event in events:
        kind = event.get("event")
        span_id = string(event.get("span_id"), "Event span")
        if kind == "span_begin":
            identity = begin_span(event, active, closed)
            begins[identity] = event
            if event.get("type") == "solver":
                require(
                    event.get("name") == "control_arena/control_solver",
                    "Unsupported solver span",
                )
                solver_ids.append(identity)
        elif kind == "span_end":
            identity = end_span(event, active)
            closed.add(identity)
            spans[identity] = (begins[identity], event)
        else:
            require(span_id in active, "Event outside active span")
    require(not active, "Incomplete native spans")
    require(len(solver_ids) == 1, "Missing or duplicate ControlArena solver span")
    signatures = sorted(
        (string(begin.get("type"), "Span type"), string(begin.get("name"), "Span name"))
        for begin in begins.values()
    )
    require(
        signatures
        == sorted(
            [
                ("init", "init"),
                ("solvers", "solvers"),
                ("solver", "control_arena/control_solver"),
                ("tool", "echo"),
                ("tool", "submit"),
                ("scorers", "scorers"),
            ]
        ),
        "Incomplete or duplicate native span population",
    )
    return solver_ids[0], spans


def validate_event_time(
    event: Object, spans: dict[str, tuple[Object, Object]], policy: Policy
) -> tuple[datetime, datetime]:
    begin, end = spans[string(event.get("span_id"), "Event span")]
    lower = within(begin.get("timestamp"), policy, "Span start")
    upper = within(end.get("timestamp"), policy, "Span end")
    require(lower <= upper, "Native span time is reversed")
    start = within(event.get("timestamp"), policy, "Event timestamp")
    completed = within(
        event.get("completed", event.get("timestamp")), policy, "Event completion"
    )
    require(start <= completed, "Native event time is reversed")
    require(lower <= start <= completed <= upper, "Event outside owning native span")
    return start, completed


def validate_timing(
    sample: Object,
    events: list[Object],
    spans: dict[str, tuple[Object, Object]],
    policy: Policy,
    evaluation_start: datetime,
    evaluation_end: datetime,
) -> None:
    sample_start = within(sample.get("started_at"), policy, "Sample start")
    sample_end = within(sample.get("completed_at"), policy, "Sample completion")
    require(
        evaluation_start <= sample_start <= sample_end <= evaluation_end,
        "Sample outside evaluation interval",
    )
    for begin, end in spans.values():
        lower = within(begin.get("timestamp"), policy, "Span start")
        upper = within(end.get("timestamp"), policy, "Span end")
        require(
            evaluation_start <= lower <= upper <= evaluation_end,
            "Span outside evaluation interval",
        )
        # Inspect records sample initialisation before EvalSample.started_at.
        if begin.get("type") == "init":
            require(upper <= sample_start, "Initialisation overlaps sample execution")
        else:
            require(
                sample_start <= lower <= upper <= sample_end,
                "Span outside sample interval",
            )
        if (parent := begin.get("parent_id")) is not None:
            parent_begin, parent_end = spans[string(parent, "Span parent")]
            require(
                timestamp(parent_begin.get("timestamp"), "Parent start")
                <= lower
                <= upper
                <= timestamp(parent_end.get("timestamp"), "Parent end"),
                "Child span outside parent interval",
            )
    actions = [event for event in events if event.get("event") in ("model", "tool")]
    require(
        [event.get("event") for event in actions] == ["model", "tool", "model", "tool"],
        "Native action order mismatch",
    )
    previous = sample_start
    for event in events:
        start, completed = validate_event_time(event, spans, policy)
        if event.get("event") in ("model", "tool"):
            require(previous <= start, "Native action causal order mismatch")
            previous = completed


def one_call(
    message: Object, expected_function: str, expected_arguments: Object
) -> str:
    require(message.get("role") == "assistant", "Expected assistant message")
    calls = arr(message.get("tool_calls"), "tool_calls")
    require(len(calls) == 1, "Unsupported tool-call population")
    call = obj(calls[0], "tool call")
    require(
        call.get("function") == expected_function
        and call.get("arguments") == expected_arguments,
        "Tool call differs from selected literal",
    )
    return string(call.get("id"), "Tool call id")


def validate_transcript(sample: Object, expected_input: str) -> tuple[Object, Object]:
    messages = [
        obj(item, "Message") for item in arr(sample.get("messages"), "messages")
    ]
    require(len(messages) == 6, "Incomplete or unsupported message population")
    require(
        messages[0].get("role") == "system"
        and messages[1].get("role") == "user"
        and messages[1].get("content") == expected_input,
        "Input message mismatch",
    )
    call_ids = (
        one_call(messages[2], "echo", {"value": expected_input}),
        one_call(messages[4], "submit", {"answer": expected_input}),
    )
    require(call_ids[0] != call_ids[1], "Duplicate tool-call id")
    for index, message in enumerate((messages[3], messages[5])):
        no_failure(message, "Tool message")
        require(
            message.get("role") == "tool"
            and message.get("tool_call_id") == call_ids[index],
            "Unmatched tool result",
        )
        require(
            message.get("function") == ("echo", "submit")[index],
            "Tool result function mismatch",
        )
        require(
            message.get("content") == (expected_input, "")[index],
            "Tool result differs from selected literal",
        )
    store = obj(sample.get("store"), "store")
    require(
        parse(string(store.get("submit_args"), "submit_args").encode())
        == {"answer": expected_input},
        "Submission store mismatch",
    )
    require(store.get("StepCounter:count") == 2, "Unexpected native step count")
    output = obj(sample.get("output"), "sample output")
    choices = arr(output.get("choices"), "output choices")
    require(
        len(choices) == 1 and obj(choices[0], "choice").get("message") == messages[4],
        "Final output/message mismatch",
    )
    return messages[2], messages[4]


def validate_events(
    sample: Object,
    expected_input: str,
    policy: Policy,
    evaluation_start: datetime,
    evaluation_end: datetime,
) -> None:
    events = [obj(item, "Event") for item in arr(sample.get("events"), "events")]
    identifiers: set[str] = set()
    for event in events:
        require(
            string(event.get("event"), "Event kind") in SUPPORTED_EVENTS,
            "Unsupported native event",
        )
        identity = string(event.get("uuid"), "Event uuid")
        require(identity not in identifiers, "Duplicate native event uuid")
        identifiers.add(identity)
        no_failure(event, "Native event")
        within(event.get("timestamp"), policy, "Event timestamp")
    solver_id, spans = validate_spans(events)
    models = [event for event in events if event.get("event") == "model"]
    tools = [event for event in events if event.get("event") == "tool"]
    initialisations = [event for event in events if event.get("event") == "sample_init"]
    require(
        len(initialisations) == 1 and len(models) == 2 and len(tools) == 2,
        "Incomplete or duplicate native execution events",
    )
    validate_timing(sample, events, spans, policy, evaluation_start, evaluation_end)
    state = obj(initialisations[0].get("state"), "Initial state")
    initial_messages = arr(state.get("messages"), "Initial messages")
    require(
        len(initial_messages) == 1
        and obj(initial_messages[0], "Initial input").get("content") == expected_input,
        "Native sample initialisation mismatch",
    )
    assistant_messages = validate_transcript(sample, expected_input)
    for index, event in enumerate(models):
        require(
            event.get("span_id") == solver_id
            and event.get("model") == "mockllm/model"
            and event.get("role") == "untrusted",
            "Unexpected native model event",
        )
        output = obj(event.get("output"), "Model output")
        choices = arr(output.get("choices"), "Model choices")
        require(
            len(choices) == 1
            and obj(choices[0], "Model choice").get("message")
            == assistant_messages[index],
            "Native model/message mismatch",
        )
        within(event.get("completed"), policy, "Model completion")
    messages = [
        obj(item, "Message") for item in arr(sample.get("messages"), "messages")
    ]
    for index, event in enumerate(tools):
        call = obj(
            arr(assistant_messages[index].get("tool_calls"), "Tool calls")[0],
            "Tool call",
        )
        require(
            event.get("span_id") == solver_id
            and event.get("id") == call.get("id")
            and event.get("function") == call.get("function")
            and event.get("arguments") == call.get("arguments"),
            "Native tool/call mismatch",
        )
        result_message = messages[(3, 5)[index]]
        require(
            event.get("result") == result_message.get("content")
            and event.get("message_id") == result_message.get("id"),
            "Native tool/result mismatch",
        )
        require(event.get("events") == [], "Unsupported nested tool events")
        within(event.get("completed"), policy, "Tool completion")


def read_log(raw: bytes, policy: Policy) -> Object:
    """Decide publication for the selected echo/submit native population.

    Parameters
    ----------
    raw : bytes
        Full JSON exported with Inspect's native asynchronous log writer.
    policy : Policy
        Separately supplied consumer policy. Its digest comes from the trusted
        capture stage, never from a manifest supplied by the candidate.

    Returns
    -------
    Object
        A bounded ``PEER`` publication report with exact sample/epoch identities
        and eight model/eight tool observations for the four-sample example.

    Raises
    ------
    ReaderRefusal
        On a changed byte, unsupported plan/event grammar, failure, incomplete
        span, mismatched native joins, or missing/duplicate/unexpected identity.

    Notes
    -----
    This checks consistency of host logs. It cannot establish external target
    effects, authenticity of a hostile host, independent custody, model quality,
    upstream acceptance, or adoption. Plain Inspect use_tools/generate/react
    solver profiles are not aliases for this ControlArena profile.
    """
    require(
        hashlib.sha256(raw).hexdigest() == policy.log_sha256,
        "Selected log digest mismatch",
    )
    log = parse(raw)
    validate_header(log, policy)
    stats = obj(log.get("stats"), "stats")
    evaluation_start = timestamp(stats.get("started_at"), "Evaluation start")
    # Inspect records eval completion at second precision; include that full
    # final second rather than excluding legitimate subsecond sample events.
    evaluation_end = timestamp(
        stats.get("completed_at"), "Evaluation completion"
    ) + timedelta(seconds=1, microseconds=-1)
    selected = {(identity, epoch): value for identity, epoch, value in policy.samples}
    seen: set[tuple[str, int]] = set()
    for item in arr(log.get("samples"), "samples"):
        sample = obj(item, "Sample")
        key = (
            string(sample.get("id"), "Sample id"),
            integer(sample.get("epoch"), "Sample epoch"),
        )
        require(key in selected, "Unexpected sample identity")
        require(key not in seen, "Duplicate sample identity")
        seen.add(key)
        no_failure(sample, "Sample")
        no_failure(obj(sample.get("metadata"), "Sample metadata"), "Sample metadata")
        require(sample.get("input") == selected[key], "Selected sample input mismatch")
        started = within(sample.get("started_at"), policy, "Sample start")
        completed = within(sample.get("completed_at"), policy, "Sample completion")
        require(started <= completed, "Sample time is reversed")
        validate_events(sample, selected[key], policy, evaluation_start, evaluation_end)
    require(seen == set(selected), "Missing selected sample identity")
    return {
        "profile": PROFILE,
        "decision": "publish",
        "witnessScope": "PEER",
        "logSha256": policy.log_sha256,
        "samples": [{"id": key[0], "epoch": key[1]} for key in sorted(seen)],
        "modelObservations": len(seen) * 2,
        "toolObservations": len(seen) * 2,
        "doesNotAssert": list(DOES_NOT_ASSERT),
    }


def main() -> None:
    """Read only caller-selected files and emit a bounded decision on stdout."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = read_log(
            args.log.read_bytes(), Policy.from_bytes(args.policy.read_bytes())
        )
    except (ReaderRefusal, OSError) as error:
        print(
            json.dumps({"profile": PROFILE, "decision": "hold", "reason": str(error)})
        )
        raise SystemExit(1) from error
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
