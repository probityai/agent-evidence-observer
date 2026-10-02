"""Native execution and rehashed-fabrication controls for the additive profile."""

import copy
from pathlib import Path

import pytest

pytest.importorskip("probity_observer")
from evaluation_contract import ContractError, decode, digest, encode
from inspect_execution import adapt, run, verify, verify_saved


@pytest.fixture(scope="module")
def retained(tmp_path_factory):
    pytest.importorskip("inspect_ai")
    folder = tmp_path_factory.mktemp("execution") / "run"
    receipt = run(folder)
    declared = decode((folder / "declaration-before-run.json").read_bytes())
    native = {
        case["id"]: next((folder / case["id"] / "native").glob("*.json")).read_bytes()
        for case in declared["cases"]
        if case["launch"]
    }
    bindings = decode((folder / "packet/native-bindings.json").read_bytes())
    sources = {path.name: path.read_bytes() for path in (folder / "sources").iterdir()}
    readbacks = {"workload-pass": (folder / "workload-pass/ticket.txt").read_bytes()}
    return declared, native, bindings, sources, readbacks, receipt, folder


def packet(retained):
    values = copy.deepcopy(retained[:5])
    plan, history, artifacts = adapt(*values)
    return (*values, plan, history, artifacts)


def check(values):
    declared, native, bindings, sources, readbacks, plan, history, artifacts = values
    plan_raw, history_raw = encode(plan), encode(history)
    return verify(
        declared,
        native,
        bindings,
        sources,
        readbacks,
        plan_bytes=plan_raw,
        history_bytes=history_raw,
        artifacts=artifacts,
        expected_plan_sha256=digest(plan_raw),
        expected_history_sha256=digest(history_raw),
    )


def changed_native(retained, case, mutate):
    values = list(copy.deepcopy(retained[:5]))
    log = decode(values[1][case])
    mutate(log)
    values[1][case] = encode(log)
    values[2][case]["sha256"] = digest(values[1][case])
    return values


def test_actual_tool_agent_and_complete_local_workload(retained):
    result = check(packet(retained))
    assert (
        result["planned"],
        result["started"],
        result["complete"],
        result["task_passed"],
        result["task_failed"],
        result["failed"],
        result["missing"],
    ) == (6, 5, 4, 3, 1, 1, 1)
    assert retained[5]["localWorkloadReadback"] == {"workload-pass": "DONE"}
    assert retained[5]["providerCalls"] == "none-mock-provider"
    records = packet(retained)[6]["records"]
    assert [r["tier"] for r in records] == [
        "tools",
        "tools",
        "agents",
        "agents",
        "workloads",
        "workloads",
    ]
    assert all(
        r["resources"]["input_tokens"] is None
        and r["resources"]["output_tokens"] is None
        and r["resources"]["peak_bytes"] is None
        for r in records
    )
    assert all(type(r["resources"]["elapsed_ns"]) is int for r in records[:-1])
    assert records[4]["claims"]["effect"]["status"] == "unknown"
    assert all(r["claims"]["authority"]["status"] == "not-exercised" for r in records)


def test_actual_native_tool_metrics_retained_and_scoped(retained):
    artifacts = packet(retained)[7]
    metrics = decode(artifacts["execution-measurements.json"])
    assert [m["native_tool_event_count"] for m in metrics] == [1, 1, 1, 1, 2]
    assert all(
        type(m["tool_thread_cpu_ns"]) is int and m["tool_thread_cpu_ns"] >= 0
        for m in metrics
    )
    assert all(
        m["elapsed_mapping"] == "floor(native-total-time-seconds * 1e9)"
        for m in metrics
    )


@pytest.mark.parametrize("state", ["absent", "incomplete"])
def test_missing_native_evidence_does_not_prove_unstarted(retained, state):
    def mutate(log):
        log["status"] = "started"
        if state == "absent":
            log["samples"] = []
        else:
            log["samples"][0]["completed_at"] = None

    values = changed_native(retained, "agent-pass", mutate)
    plan, history, artifacts = adapt(*values)
    result = check((*values, plan, history, artifacts))
    if state == "absent":
        assert result["unknown_start"] == 1 and result["started"] == 4
        record = history["records"][2]
        assert record["resources"]["elapsed_ns"] is None
        assert "start_evidence_missing" in record["capture"]["gaps"]
    else:
        assert result["incomplete"] == 1 and result["scored"] == 3
    assert result["missing"] == 1


def test_unavailable_entire_log_stays_unknown(retained):
    values = list(copy.deepcopy(retained[:5]))
    del values[1]["agent-pass"]
    del values[2]["agent-pass"]
    _, history, _ = adapt(*values)
    assert history["records"][2]["harness_status"] == "start-unknown"


@pytest.mark.parametrize(
    "mutation,reason",
    [
        (
            lambda log: log["eval"]["config"].update(retry_on_error=1),
            "execution_config",
        ),
        (
            lambda log: log["eval"]["metadata"].update(
                probity_declaration_sha256="0" * 64
            ),
            "execution_declaration_binding",
        ),
        (
            lambda log: log["samples"].append(copy.deepcopy(log["samples"][0])),
            "execution_samples",
        ),
        (lambda log: log["samples"][0].update(error_retries=[{}]), "execution_retries"),
        (
            lambda log: log["samples"][0].update(completed_at=False),
            "execution_timestamp",
        ),
        (
            lambda log: log["samples"][0].update(started_at="garbage"),
            "execution_timestamp",
        ),
        (
            lambda log: log["samples"][0].update(
                completed_at="2000-01-01T00:00:00+00:00"
            ),
            "execution_timestamp_order",
        ),
        (
            lambda log: log["samples"][0].update(started_at="2026-01-01T00:00:00"),
            "execution_timestamp",
        ),
        (lambda log: log["samples"][0].update(total_time=True), "execution_elapsed"),
        (lambda log: log["samples"][0].update(total_time=-1), "execution_elapsed"),
        (
            lambda log: log["samples"][0].update(scores={"match": {"value": "X"}}),
            "execution_score",
        ),
        (
            lambda log: log["samples"][0]["messages"].pop(3),
            "execution_call_result_join",
        ),
    ],
)
def test_native_profile_mutations_refused_even_after_new_native_pin(
    retained, mutation, reason
):
    with pytest.raises(ContractError, match=reason):
        adapt(*changed_native(retained, "agent-pass", mutation))


def test_rehashed_changed_tool_result_is_recomputed(retained):
    def mutate(log):
        sample = log["samples"][0]
        event = next(e for e in sample["events"] if e.get("event") == "tool")
        result = decode(event["result"].encode())
        result["value"] = 5
        event["result"] = encode(result).decode()
        next(m for m in sample["messages"] if m.get("role") == "tool")["content"] = (
            event["result"]
        )

    with pytest.raises(ContractError, match="execution_tool_result_recomputed"):
        adapt(*changed_native(retained, "agent-pass", mutate))


def test_wrong_local_readback_refused(retained):
    values = list(copy.deepcopy(retained[:5]))
    values[4]["workload-pass"] = b"OPEN"
    with pytest.raises(ContractError, match="execution_readback_recomputed"):
        adapt(*values)


@pytest.mark.parametrize("changed", ["score", "resource", "axis", "tool-measurement"])
def test_rehashed_common_fabrication_fails_full_reconstruction(retained, changed):
    values = list(packet(retained))
    history, artifacts = values[6:]
    record = history["records"][1]
    if changed == "score":
        record["claims"]["task_outcome"]["status"] = "pass"
    elif changed == "resource":
        record["resources"]["input_tokens"] = 123
    elif changed == "axis":
        record["claims"]["authority"].update(
            status="pass", evidence=record["claims"]["task_outcome"]["evidence"]
        )
    else:
        artifact = decode(artifacts["execution-measurements.json"])
        artifact[0]["tool_thread_cpu_ns"] += 1
        artifacts["execution-measurements.json"] = encode(artifact)
    raw = encode({key: value for key, value in record.items() if key != "output"})
    artifacts[record["output"]["name"]] = raw
    record["output"].update(sha256=digest(raw), size_bytes=len(raw))
    with pytest.raises(
        ContractError, match="execution_(history|artifact)_mapping_mismatch"
    ):
        check(values)


def test_pin_is_consumer_selected(retained):
    values = list(packet(retained))
    values[1]["agent-pass"] += b" "
    with pytest.raises(ContractError, match="execution_native_pin"):
        check(values)


def test_existing_output_directory_refused(tmp_path):
    pytest.importorskip("inspect_ai")
    with pytest.raises(FileExistsError):
        run(tmp_path)


def test_offline_packet_reload(retained):
    folder = retained[6]
    selected = decode((folder / "packet/consumer-pins.json").read_bytes())
    assert verify_saved(folder, selected) == retained[5]["report"]


@pytest.mark.parametrize(
    "file",
    [
        "declaration-before-run.json",
        "sources/policy.txt",
        "packet/native-bindings.json",
        "packet/history.json",
    ],
)
def test_offline_pins_refuse_changed_selected_inputs(retained, tmp_path, file):
    import shutil

    folder = tmp_path / "copy"
    shutil.copytree(retained[6], folder)
    selected = decode((retained[6] / "packet/consumer-pins.json").read_bytes())
    path = folder / file
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ContractError):
        verify_saved(folder, selected)


def test_offline_reader_refuses_external_symlink(retained, tmp_path):
    import shutil

    folder = tmp_path / "copy"
    shutil.copytree(retained[6], folder)
    selected = decode((retained[6] / "packet/consumer-pins.json").read_bytes())
    source = tmp_path / "outside.txt"
    source.write_bytes((folder / "sources/policy.txt").read_bytes())
    target = folder / "sources/policy.txt"
    target.unlink()
    target.symlink_to(source)
    with pytest.raises(ContractError, match="execution_packet_path_escape"):
        verify_saved(folder, selected)


def test_offline_reader_refuses_extra_artifacts(retained, tmp_path):
    import shutil

    folder = tmp_path / "copy"
    shutil.copytree(retained[6], folder)
    selected = decode((retained[6] / "packet/consumer-pins.json").read_bytes())
    (folder / "packet/extra.json").write_bytes(b"{}")
    with pytest.raises(ContractError, match="execution_artifact_mapping_mismatch"):
        verify_saved(folder, selected)


def test_native_score_recomputed_for_declared_controlled_completion(retained):
    def mutate(log):
        log["samples"][0]["scores"]["match"]["value"] = "I"

    with pytest.raises(ContractError, match="execution_bounded_score_recomputed"):
        adapt(*changed_native(retained, "agent-pass", mutate))
