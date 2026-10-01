"""Adapt a pinned Inspect AI JSON log to a declared evaluation history.

The adapter supports one task, one generate solver, the match scorer, and no
native retries or log rewrites. It checks retained records, not execution truth.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

from .crypto import VerificationError
from .evaluation_history import (
    ArtifactRef,
    AttemptRecord,
    AttemptSpec,
    RunPlan,
    artifact_ref,
    decode_record,
    encode_record,
    plan_digest,
    verify_history,
)

LOGGER = logging.getLogger(__name__)
INSPECT_VERSION = "0.3.273"
LOG_VERSION = 2
PROFILE = "probity-inspect-history-reference-v0"
POLICY_BYTES = encode_record(
    {
        "identity": "match-C-I",
        "version": "v0",
        "C": "pass",
        "I": "fail",
        "missing_score": "not_scored",
        "execution_error": "not_scored",
        "missing_native_entry": "not_scored",
    }
)


def _refuse(reason: str) -> NoReturn:
    """Log a bounded reason without native prompts, completions, or errors."""
    LOGGER.warning("Inspect history refused: %s", reason)
    raise VerificationError(reason)


def _object(value: Any, field: str) -> dict[str, Any]:
    """Require an object before reading the supported native log contract."""
    if not isinstance(value, dict):
        _refuse(f"native {field} must be an object")
    return value


@dataclass(frozen=True, slots=True)
class InspectBinding:
    """Consumer-selected native run and evaluation identities.

    Parameters
    ----------
    run_id, eval_id : str
        Exact identifiers from a retained launch receipt. Matching them prevents
        accidentally accepting another run's log; it does not authenticate the
        launch receipt or establish prior declaration by an independent party.
    log_sha256 : str
        Consumer-selected digest of the exact native log. Replacement bytes
        are refused even if they repeat the original native identity fields.
    """

    run_id: str
    eval_id: str
    log_sha256: str

    def __post_init__(self) -> None:
        for value in (self.run_id, self.eval_id):
            if not isinstance(value, str) or not value or not value.isascii():
                _refuse("native binding identities must be nonempty ASCII")
            if len(value) > 256 or any(
                ord(char) < 33 or ord(char) > 126 for char in value
            ):
                _refuse("native binding identities must be nonempty ASCII")
        ArtifactRef("inspect-log.json", self.log_sha256, 0)


@dataclass(frozen=True, slots=True)
class InspectHistory:
    """Ordered records and exact output envelopes derived from one native log.

    Parameters
    ----------
    records : tuple[AttemptRecord, ...]
        One record per declared sample and epoch. Missing native entries are
        explicitly unscored, not silently dropped or described as executed.
    artifacts : dict[str, bytes]
        Retained per-attempt envelopes containing native transcript data.
    native_log : ArtifactRef
        Digest and size of the original native log, retained separately.
    report : dict[str, Any]
        Native identities and coverage limits; not an execution attestation.
    """

    records: tuple[AttemptRecord, ...]
    artifacts: dict[str, bytes]
    native_log: ArtifactRef
    report: dict[str, Any]


def _pins(plan: RunPlan) -> dict[str, Any]:
    """Read the exact pinned profile, refusing misleading mock evaluation mode."""
    pins = {source.role: source for source in plan.sources}
    identities = {role: pins[role].identity for role in ("solver", "scorer", "harness")}
    if identities != {"solver": "generate", "scorer": "match", "harness": "inspect_ai"}:
        _refuse("source identities are outside the supported Inspect profile")
    if any(
        pins[role].version != INSPECT_VERSION
        for role in ("model", "solver", "scorer", "harness")
    ):
        _refuse("source versions are outside the pinned Inspect profile")
    if pins["model"].identity != "mockllm/model":
        _refuse("native model is outside the offline mock profile")
    if plan.mode != "offline-contract":
        _refuse("mock model execution must be labelled offline-contract")
    _decision_pins(pins)
    return pins


def _decision_pins(pins: dict[str, Any]) -> None:
    """Keep checker implementation and its score decision policy distinct."""
    expected = {"checker": "probity-inspect-history", "policy": "match-C-I"}
    if any(
        pins[role].identity != identity or pins[role].version != "v0"
        for role, identity in expected.items()
    ):
        _refuse("checker or grading policy identity differs from the profile")


def _header(
    log: dict[str, Any], plan: RunPlan, binding: InspectBinding, pins: dict[str, Any]
) -> dict[str, Any]:
    """Bind native schema, package version, task, model, and run identities."""
    if type(log.get("version")) is not int or log["version"] != LOG_VERSION:
        _refuse("native log schema version is unsupported")
    if not isinstance(log.get("status"), str) or log["status"] not in {
        "started",
        "success",
        "error",
        "cancelled",
    }:
        _refuse("native run status is unsupported")
    spec = _object(log.get("eval"), "evaluation spec")
    _native_identity(spec, plan, binding, pins)
    _native_profile(log, spec)
    _declared_scope(spec, plan)
    return spec


def _native_identity(
    spec: dict[str, Any], plan: RunPlan, binding: InspectBinding, pins: dict[str, Any]
) -> None:
    """Reject cross-run logs, changed implementations, and unpinned task versions."""
    expected = {
        "run_id": binding.run_id,
        "eval_id": binding.eval_id,
        "task": pins["task"].identity,
        "model": pins["model"].identity,
    }
    if any(spec.get(key) != value for key, value in expected.items()):
        _refuse("native run, task, or model identity differs from its binding")
    if str(spec.get("task_version")) != pins["task"].version:
        _refuse("native task version differs from its source pin")
    if (
        _object(spec.get("packages"), "package versions").get("inspect_ai")
        != INSPECT_VERSION
    ):
        _refuse("native Inspect version differs from the pinned profile")
    metadata = _object(spec.get("metadata"), "task metadata")
    if metadata.get("probity_run_id") != plan.run_id or metadata.get(
        "probity_plan_digest"
    ) != plan_digest(plan):
        _refuse("native task metadata differs from the declared run")


def _native_profile(log: dict[str, Any], spec: dict[str, Any]) -> None:
    """Refuse solver/scorer changes and unsupported log mutations."""
    native_plan = _object(log.get("plan"), "solver plan")
    if native_plan.get("finish") is not None:
        _refuse("native finish solver is outside the supported profile")
    steps = native_plan.get("steps")
    if (
        not isinstance(steps, list)
        or len(steps) != 1
        or _object(steps[0], "solver step").get("solver") != "generate"
    ):
        _refuse("native solver plan differs from the supported profile")
    scorers = spec.get("scorers")
    if (
        not isinstance(scorers, list)
        or len(scorers) != 1
        or _object(scorers[0], "scorer").get("name") != "match"
    ):
        _refuse("native scorer differs from the supported profile")
    _profile_options(log, spec, steps[0], scorers[0])


def _profile_options(
    log: dict[str, Any],
    spec: dict[str, Any],
    step: dict[str, Any],
    scorer: dict[str, Any],
) -> None:
    """Support the declared default scorer/solver and explicitly zero retries."""
    if (
        step.get("params") != {"tool_calls": "loop"}
        or step.get("params_passed", {}) != {}
        or scorer.get("options") != {}
    ):
        _refuse("native solver or scorer options are unsupported")
    config = _object(spec.get("config"), "configuration")
    if type(config.get("retry_on_error")) is not int or config["retry_on_error"] != 0:
        _refuse("native retries are outside the retained attempt profile")
    if any(log.get(key) for key in ("invalidated", "log_updates", "config_updates")):
        _refuse("native log rewrites or invalidation are unsupported")


def _declared_scope(spec: dict[str, Any], plan: RunPlan) -> None:
    """Require the exact sample-by-epoch population, not only successful samples."""
    dataset = _object(spec.get("dataset"), "dataset declaration")
    epochs = _object(spec.get("config"), "configuration").get("epochs")
    ids = dataset.get("sample_ids")
    if (
        not isinstance(ids, list)
        or not ids
        or any(not isinstance(value, str) for value in ids)
    ):
        _refuse("native sample identities are outside the supported profile")
    if type(epochs) is not int or epochs < 1 or type(dataset.get("samples")) is not int:
        _refuse("native dataset size or epoch count is unsupported")
    _scope_population(plan, ids, epochs, dataset["samples"])


def _scope_population(plan: RunPlan, ids: list[str], epochs: int, size: int) -> None:
    """Compare declared population with the complete native dataset grid."""
    if len(ids) != len(set(ids)) or size != len(ids):
        _refuse("native dataset declaration contains duplicate or missing samples")
    native = {(sample_id, epoch) for sample_id in ids for epoch in range(1, epochs + 1)}
    declared = {(attempt.sample_id, attempt.epoch) for attempt in plan.attempts}
    if native != declared:
        _refuse("native dataset declaration differs from the planned population")


def _sample_map(
    log: dict[str, Any], plan: RunPlan
) -> dict[tuple[str, int], dict[str, Any]]:
    """Index native samples without discarding duplicates or undeclared attempts."""
    values = _native_samples(log)
    declared = {(attempt.sample_id, attempt.epoch) for attempt in plan.attempts}
    result: dict[tuple[str, int], dict[str, Any]] = {}
    for value in values:
        sample = _object(value, "sample")
        key = _sample_key(sample)
        if key in result or key not in declared:
            _refuse("native sample population is duplicated or undeclared")
        _sample_profile(sample)
        result[key] = sample
    if log.get("status") == "success" and len(result) != len(declared):
        _refuse("successful native log omits declared samples")
    return result


def _native_samples(log: dict[str, Any]) -> list[Any]:
    """Keep absent interrupted logs distinct from malformed successful logs."""
    values = log.get("samples")
    if values is None and log.get("status") != "success":
        return []
    if not isinstance(values, list):
        _refuse("native samples must be a list")
    return values


def _sample_key(sample: dict[str, Any]) -> tuple[str, int]:
    """Preserve string IDs and positive non-Boolean epoch identities."""
    identity, epoch = sample.get("id"), sample.get("epoch")
    if not isinstance(identity, str) or type(epoch) is not int or epoch < 1:
        _refuse("native sample identity or epoch is unsupported")
    return identity, epoch


def _sample_profile(sample: dict[str, Any]) -> None:
    """Refuse merged retries, invalidation, and limits not represented here."""
    retries = sample.get("error_retries")
    if retries is not None and not isinstance(retries, list):
        _refuse("native error retries must be a list or null")
    if any(sample.get(key) for key in ("error_retries", "invalidation", "limit")):
        _refuse("native retries, sample invalidation, or limits are unsupported")
    if sample.get("completed_at") is not None and sample.get("started_at") is None:
        _refuse("native completion has no start timestamp")


def _state(sample: dict[str, Any]) -> tuple[str, str, str | None]:
    """Distinguish execution failures, partial execution, and grading failures."""
    if sample.get("completed_at") is None:
        return "interrupted", "not_scored", "native-completion-absent"
    if sample.get("error") is not None:
        return "error", "not_scored", "native-sample-error"
    scores = sample.get("scores")
    if scores is None or scores == {}:
        return "completed", "not_scored", None
    return "completed", _outcome(scores), None


def _outcome(scores: Any) -> str:
    """Apply the separately declared exact C/I match-score policy."""
    values = _object(scores, "scores")
    if set(values) != {"match"}:
        _refuse("native sample scorer population differs from the profile")
    value = _object(values["match"], "match score").get("value")
    if not isinstance(value, str) or value not in {"C", "I"}:
        _refuse("native match score is outside the declared grading policy")
    return "pass" if value == "C" else "fail"


def _record(
    plan: RunPlan,
    attempt: AttemptSpec,
    ordinal: int,
    sample: dict[str, Any] | None,
    binding: InspectBinding,
    native: ArtifactRef,
) -> tuple[AttemptRecord, bytes | None]:
    """Retain original sample data or an explicit absent-native-entry reason."""
    if sample is None:
        return AttemptRecord(
            plan.run_id,
            attempt.attempt_id,
            ordinal,
            "not_run",
            "not_scored",
            None,
            None,
            "absent-from-native-log",
            None,
        ), None
    if sample.get("started_at") is None:
        _refuse("retained native sample has no start timestamp")
    status, outcome, error = _state(sample)
    envelope = encode_record(
        {
            "run_id": plan.run_id,
            "attempt_id": attempt.attempt_id,
            "status": status,
            "outcome": outcome,
            "native_run_id": binding.run_id,
            "native_eval_id": binding.eval_id,
            "native_log_sha256": native.sha256,
            "native_sample": sample,
        }
    )
    ref = artifact_ref(f"attempt-{ordinal}.json", envelope)
    record = AttemptRecord(
        plan.run_id,
        attempt.attempt_id,
        ordinal,
        status,
        outcome,
        sample.get("started_at"),
        sample.get("completed_at"),
        error,
        ref,
    )
    return record, envelope


def adapt_inspect_log(
    content: bytes, plan: RunPlan, binding: InspectBinding
) -> InspectHistory:
    """Bind a retained native log to every declared sample and epoch.

    Parameters
    ----------
    content : bytes
        Original Inspect JSON log bytes, schema version 2 from Inspect 0.3.273.
    plan : RunPlan
        Selected attempt population and seven exact source-role pins. This
        adapter supports generate, match with default options, and zero retries.
    binding : InspectBinding
        Selected native run/evaluation IDs from the retained launch receipt.

    Returns
    -------
    InspectHistory
        Ordered records, exact envelopes, original log digest, and explicit
        coverage limits. Call verify_history with retained source bytes and the
        consumer's run end/capture time before admitting these records.

    Raises
    ------
    VerificationError
        On stale identity, changed scorer, duplicate samples, unsupported
        native schema, retries, options, log rewrites, or population changes.

    Notes
    -----
    An absent native sample is labelled not_run/absent-from-native-log. This
    means no native entry was retained, not proof that execution never occurred.
    Model and tool transcript events are retained; their external effects and
    completeness are not established. No model provider is invoked here.
    """
    native = artifact_ref("inspect-log.json", content)
    if native.sha256 != binding.log_sha256:
        _refuse("native log digest differs from the selected binding")
    log = _object(decode_record(content), "log")
    pins = _pins(plan)
    _header(log, plan, binding, pins)
    samples = _sample_map(log, plan)
    records: list[AttemptRecord] = []
    artifacts: dict[str, bytes] = {}
    for ordinal, attempt in enumerate(plan.attempts, 1):
        record, envelope = _record(
            plan,
            attempt,
            ordinal,
            samples.get((attempt.sample_id, attempt.epoch)),
            binding,
            native,
        )
        records.append(record)
        if envelope is not None:
            artifacts[record.output.name] = envelope
    report = {
        "profile": PROFILE,
        "nativeStatus": log["status"],
        "nativeRunId": binding.run_id,
        "nativeEvalId": binding.eval_id,
        "nativeLogSha256": native.sha256,
        "nativeLogVersion": LOG_VERSION,
        "inspectVersion": INSPECT_VERSION,
        "nativeEntries": len(samples),
        "declaredEntries": len(plan.attempts),
        "observedActionScope": "retained-native-transcript-only",
        "scoreAuthority": "selected-native-score-records-not-independent-rescoring",
        "retryCoverage": "sample-retries-refused;provider-retries-not-established",
        "executionTruth": "not-established",
        "globalNoOmission": "not-established",
        "independentCustody": "not-established",
    }
    return InspectHistory(tuple(records), artifacts, native, report)


def verify_inspect_history(
    content: bytes,
    plan: RunPlan,
    binding: InspectBinding,
    *,
    sources: Mapping[str, bytes],
    captured_at: str,
    claimed_summary: Mapping[str, int] | None = None,
    records: Sequence[AttemptRecord] | None = None,
    artifacts: Mapping[str, bytes] | None = None,
) -> dict[str, Any]:
    """Reconstruct and check retained evidence from the selected native log.

    Parameters
    ----------
    content, plan, binding
        Exact native bytes, declared population, and selected native IDs/digest.
    sources : Mapping[str, bytes]
        Exact retained bytes for all seven implementation/configuration roles.
    captured_at : str
        UTC capture/end time selected by the consumer or retained run wrapper.
        This remains an operator clock, not independently witnessed wall time.
    claimed_summary : Mapping[str, int] | None, optional
        Strict counts to compare with every reconstructed attempt.
    records, artifacts : optional
        If supplied, both must exactly equal the native-derived records and
        envelopes. Hash-consistent author-edited scores or transcripts are
        refused rather than accepted merely as self-consistent JSON.

    Returns
    -------
    dict[str, Any]
        Separate native-adaptation and record-consistency results. Neither
        establishes real model quality, global completeness, or external custody.

    Raises
    ------
    VerificationError
        If native binding, declared population, derived evidence, retained
        sources, timing, or claimed summary differs.
    """
    sources = dict(sources)
    history = adapt_inspect_log(content, plan, binding)
    _derived_evidence(history, records, artifacts)
    result = verify_history(
        plan,
        history.records,
        artifacts=history.artifacts,
        sources=sources,
        ended_at=captured_at,
        claimed_summary=claimed_summary,
    )
    _source_contract(content, plan, sources)
    return {
        "consistency": result,
        "native": history.report,
        "sourceBinding": {
            "task": "native-inputs-targets-config-checked",
            "policy": "v0-native-score-mapping-checked",
            "checker": "local-source-bundle-matched",
            "model": "declared-mock-prefix-completion-multiset-checked-not-order",
            "otherImplementations": "retained-bytes-and-native-identities-only",
        },
    }


def _source_contract(
    content: bytes, plan: RunPlan, sources: Mapping[str, bytes]
) -> None:
    """Apply source semantics after every retained source digest has been checked."""
    pins = {source.role: source for source in plan.sources}
    policy = decode_record(sources[pins["policy"].artifact.name])
    if policy != decode_record(POLICY_BYTES):
        _refuse("retained grading policy differs from the v0 decision contract")
    checker = decode_record(sources[pins["checker"].artifact.name])
    if checker != _local_checker_source():
        _refuse("retained checker source differs from the local verifier")
    task = _object(decode_record(sources[pins["task"].artifact.name]), "task source")
    log = _object(decode_record(content), "log")
    _task_source(task, log, plan)
    model = _object(decode_record(sources[pins["model"].artifact.name]), "model source")
    _model_source(model, log)


def _local_checker_source() -> dict[str, str]:
    """Bind the retained checker bundle to the local source files being checked."""
    root = Path(__file__).parent
    try:
        return {
            name: (root / name).read_text("utf-8")
            for name in ("evaluation_history.py", "inspect_history.py")
        }
    except (OSError, UnicodeError):
        _refuse("local checker source is unavailable")


def _task_source(task: dict[str, Any], log: dict[str, Any], plan: RunPlan) -> None:
    """Match declared task configuration to the selected native task and samples."""
    spec = log["eval"]
    _task_shape(task)
    expected = {
        "name": spec["task"],
        "version": spec["task_version"],
        "epochs": spec["config"]["epochs"],
        "retry_on_error": 0,
        "max_samples": 1,
    }
    if any(
        task.get(key) != value or type(task.get(key)) is not type(value)
        for key, value in expected.items()
    ):
        _refuse("retained task configuration differs from the native declaration")
    if (
        spec["config"].get("max_samples") != 1
        or type(spec["config"].get("max_samples")) is not int
    ):
        _refuse("native concurrency differs from the serial task profile")
    declared = _task_samples(task.get("samples"))
    if set(declared) != {attempt.sample_id for attempt in plan.attempts}:
        _refuse("retained task population differs from the declared plan")
    _sample_inputs(log, declared)


def _task_shape(task: dict[str, Any]) -> None:
    """Accept only configuration fields represented by this text-task profile."""
    if set(task) != {
        "name",
        "version",
        "epochs",
        "retry_on_error",
        "max_samples",
        "samples",
    }:
        _refuse("retained task configuration fields are unsupported")


def _task_samples(values: Any) -> dict[str, dict[str, Any]]:
    """Retain exact string sample identities with their input and target values."""
    if not isinstance(values, list) or not values:
        _refuse("retained task samples must be a nonempty list")
    result: dict[str, dict[str, Any]] = {}
    for value in values:
        sample = _object(value, "task source sample")
        _task_sample(sample, result)
        result[sample["id"]] = sample
    return result


def _task_sample(sample: dict[str, Any], previous: dict[str, Any]) -> None:
    """Reject incomplete or duplicate finite text-task declarations."""
    if set(sample) != {"id", "input", "target"}:
        _refuse("retained task sample fields differ from the text-task profile")
    if any(not isinstance(sample[key], str) for key in ("id", "input", "target")):
        _refuse("retained text-task fields must be strings")
    if sample["id"] in previous:
        _refuse("retained task sample identities are duplicated")


def _sample_inputs(log: dict[str, Any], declared: dict[str, dict[str, Any]]) -> None:
    """Bind native retained inputs and targets without rescoring model quality."""
    for sample in _native_samples(log):
        source = declared[sample["id"]]
        if any(sample.get(key) != source[key] for key in ("input", "target")):
            _refuse("native sample input or target differs from the retained task")


def _model_source(model: dict[str, Any], log: dict[str, Any]) -> None:
    """Compare the completion multiset with a declared finite mock-output prefix."""
    _model_shape(model)
    completions = _mock_outputs(log)
    if Counter(completions) != Counter(model["custom_outputs"][: len(completions)]):
        _refuse("native completed outputs differ from the declared mock stream")


def _mock_outputs(log: dict[str, Any]) -> list[str]:
    """Include retained model choices even if later scoring was interrupted."""
    values: list[str] = []
    for sample in _native_samples(log):
        output = _object(sample.get("output"), "model output")
        choices = output.get("choices")
        if not isinstance(choices, list):
            _refuse("native model choices must be a list")
        if choices:
            values.append(_completion(sample))
    return values


def _model_shape(model: dict[str, Any]) -> None:
    """Require mock source, finite text outputs, and zero usage."""
    if (
        set(model) != {"identity", "custom_outputs", "usage", "provider_source"}
        or model.get("identity") != "mockllm/model"
    ):
        _refuse("retained mock-model configuration fields are unsupported")
    outputs = model.get("custom_outputs")
    if not isinstance(outputs, list) or any(
        not isinstance(value, str) for value in outputs
    ):
        _refuse("retained mock outputs must be a finite string list")
    _model_provenance(model)


def _model_provenance(model: dict[str, Any]) -> None:
    """Check finite mock usage without claiming that source bytes prove execution."""
    expected = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    usage = model.get("usage")
    if usage != expected or any(
        type(value) is not int for value in _object(usage, "mock usage").values()
    ):
        _refuse("retained mock usage differs from the zero-usage profile")
    if (
        not isinstance(model.get("provider_source"), str)
        or not model["provider_source"]
    ):
        _refuse("retained mock provider source is missing")


def _completion(sample: dict[str, Any]) -> str:
    """Preserve the native completed text output used by the mock profile."""
    value = _object(sample.get("output"), "model output").get("completion")
    if not isinstance(value, str):
        _refuse("native completed mock output must be text")
    return value


def _derived_evidence(
    history: InspectHistory,
    records: Sequence[AttemptRecord] | None,
    artifacts: Mapping[str, bytes] | None,
) -> None:
    """Require both retained populations or reconstruct both from original bytes."""
    if records is None and artifacts is None:
        return
    if records is None or artifacts is None:
        _refuse("both native-derived records and artifacts must be supplied")
    if tuple(records) != history.records or dict(artifacts) != history.artifacts:
        _refuse("retained records or artifacts differ from the native log")
