"""Exercise actual SDK HTTP execution and rehashed semantic mutations."""

import pytest
from a2a_contract import adapt, verify
from a2a_demo import run
from evaluation_contract import ContractError, decode, digest, encode


@pytest.fixture(scope="module")
def packet(tmp_path_factory):
    path = tmp_path_factory.mktemp("native") / "run"
    report = run(path)
    native_plan = decode((path / "native-plan.json").read_bytes())
    pins = decode((path / "selected-native-pins.json").read_bytes())
    common = path / "common"
    raw = {name: (common / name).read_bytes() for name in pins}
    sources = {
        name: (path / name).read_bytes()
        for name in (
            "sdk-source.json",
            "sdk-source-pins.json",
            "sdk-license.txt",
            "local-source.json",
            "rubric.json",
            "policy.json",
            "runtime.json",
        )
    }
    return native_plan, raw, sources, pins, report


def test_actual_sdk_two_party_exchange(packet):
    _, _, _, _, result = packet
    assert result["planned"] == 6
    assert result["started"] == 5
    assert result["complete"] == result["scored"] == 2
    assert result["task_passed"] == result["task_failed"] == 1
    assert result["failed"] == 2
    assert result["incomplete"] == result["unknown_start"] == 1
    assert result["missing"] == 0
    assert result["custody"] == "same-operator"


def test_raw_measured_elapsed_not_tokens_or_effects(packet):
    native, raw, sources, pins, _ = packet
    _, history, _ = adapt(native, raw, sources, pins)
    for record in history["records"]:
        assert record["resources"]["input_tokens"] is None
        assert record["resources"]["output_tokens"] is None
        assert record["resources"]["peak_bytes"] is None
        assert record["identity"]["effect_id"] is None
        assert record["identity"]["consumer_decision_id"] is None
        assert record["capture"]["complete"] is False
        if record["harness_status"] != "start-unknown":
            assert record["resources"]["elapsed_ns"] > 0


@pytest.mark.parametrize(
    "kind",
    [
        "request-content",
        "request-context",
        "request-method",
        "rpc-id",
        "returned-content",
        "task-id",
        "task-context",
        "task-state",
        "task-history",
        "target-url",
        "protocol",
        "response-missing",
        "fake-success",
        "extra-artifact",
        "bool-elapsed",
        "server-message",
        "hidden-start",
    ],
)
def test_canonical_valid_native_changes_refused_even_with_new_self_pins(packet, kind):
    native, original, sources, _, _ = packet
    raw = dict(original)

    def change(name, update):
        value = decode(raw[name])
        update(value)
        raw[name] = encode(value)

    if kind == "request-content":
        change(
            "a2a-pass-request.json",
            lambda v: v["params"]["message"]["parts"][0].update(text="2+4"),
        )
    elif kind == "request-context":
        change(
            "a2a-pass-request.json",
            lambda v: v["params"]["message"].update(contextId="other"),
        )
    elif kind == "request-method":
        change("a2a-pass-request.json", lambda v: v.update(method="GetTask"))
    elif kind == "rpc-id":
        change("a2a-pass-response.json", lambda v: v.update(id="other"))
    elif kind == "returned-content":
        change(
            "a2a-pass-response.json",
            lambda v: v["result"]["message"]["parts"][0].update(text="6"),
        )
    elif kind.startswith("task-"):
        field = kind.split("-")[1]

        def update(v):
            task = v["result"]["task"]
            if field == "id":
                task["id"] = "other"
            elif field == "context":
                task["contextId"] = "other"
            elif field == "state":
                task["status"]["state"] = "TASK_STATE_COMPLETED"
            else:
                task["history"][0]["parts"][0]["text"] = "2+3"

        change("a2a-task-failed-response.json", update)
    elif kind == "target-url":
        change(
            "a2a-pass-request-metadata.json",
            lambda v: v.update(url="http://127.0.0.1:1/rpc"),
        )
    elif kind == "protocol":
        change(
            "agent-card.json",
            lambda v: v["supportedInterfaces"][0].update(protocolVersion="0.3"),
        )
    elif kind == "response-missing":
        del raw["a2a-pass-response.json"]
    elif kind == "fake-success":
        change("launch-ledger.json", lambda v: v[-1].update(outcome="returned"))
    elif kind == "extra-artifact":
        raw["extra.json"] = b"{}"
    elif kind == "bool-elapsed":
        change("launch-ledger.json", lambda v: v[1].update(elapsed_ns=True))
    elif kind == "server-message":
        events = [decode(line) for line in raw["server-events.jsonl"].splitlines()]
        events[0]["message_id"] = "other"
        raw["server-events.jsonl"] = b"\n".join(encode(event) for event in events)
    elif kind == "hidden-start":
        change(
            "launch-ledger.json",
            lambda v: v.extend(
                [{"attempt_id": "a2a-missing", "event": "client-start"}]
            ),
        )
    with pytest.raises(ContractError):
        adapt(
            native, raw, sources, {name: digest(value) for name, value in raw.items()}
        )


def test_selected_native_pin_blocks_changed_bytes(packet):
    native, original, sources, pins, _ = packet
    raw = dict(original)
    raw["a2a-pass-response.json"] += b" "
    with pytest.raises(ContractError, match="native_pin_mismatch"):
        adapt(native, raw, sources, pins)


def test_rehashed_fabricated_common_result_refused(packet):
    native, raw, sources, pins, _ = packet
    plan, history, artifacts = adapt(native, raw, sources, pins)
    history["records"][1]["claims"]["task_outcome"]["status"] = "pass"
    name = history["records"][1]["output"]["name"]
    artifacts[name] = encode(
        {k: v for k, v in history["records"][1].items() if k != "output"}
    )
    history["records"][1]["output"]["sha256"] = digest(artifacts[name])
    history["records"][1]["output"]["size_bytes"] = len(artifacts[name])
    p, h = encode(plan), encode(history)
    with pytest.raises(ContractError, match="native_history_mapping_mismatch"):
        verify(
            native,
            raw,
            sources,
            pins,
            p,
            h,
            artifacts,
            expected_plan_sha256=digest(p),
            expected_history_sha256=digest(h),
        )


def test_whole_normalized_artifact_replacement_refused(packet):
    native, raw, sources, pins, _ = packet
    plan, history, artifacts = adapt(native, raw, sources, pins)
    artifacts["rubric.json"] = b"{}"
    p, h = encode(plan), encode(history)
    with pytest.raises(ContractError, match="native_artifact_mapping_mismatch"):
        verify(
            native,
            raw,
            sources,
            pins,
            p,
            h,
            artifacts,
            expected_plan_sha256=digest(p),
            expected_history_sha256=digest(h),
        )


def test_reader_actual_packet_and_external_common_pin(tmp_path):
    from a2a_verify import read_and_verify

    path = tmp_path / "reader-run"
    result = run(path)
    pins = decode((path / "selected-native-pins.json").read_bytes())
    assert (
        read_and_verify(path, pins, result["plan_sha256"], result["history_sha256"])[
            "planned"
        ]
        == 6
    )
    with pytest.raises(ContractError, match="pin_mismatch"):
        read_and_verify(path, pins, "0" * 64, result["history_sha256"])
    with pytest.raises(ContractError, match="artifact_name"):
        read_and_verify(
            path,
            {"../../secret.json": "0" * 64},
            result["plan_sha256"],
            result["history_sha256"],
        )


@pytest.mark.parametrize(
    "name",
    [
        "agent-card.json",
        "server-events.jsonl",
        "launch-ledger.json",
        "a2a-pass-request.json",
        "a2a-pass-request-metadata.json",
        "a2a-pass-response-status.json",
    ],
)
def test_missing_required_native_artifact_refused(packet, name):
    native, original, sources, _, _ = packet
    raw = dict(original)
    del raw[name]
    with pytest.raises(ContractError):
        adapt(native, raw, sources, {key: digest(value) for key, value in raw.items()})
