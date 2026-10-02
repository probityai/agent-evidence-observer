"""Independent task adjudication and selected CPU accounting boundaries."""

import json
from pathlib import Path

import pytest
from task_matrix import protocol, score, verify
from test_task_matrix import change, fixture, repin


def selected():
    return protocol(Path(__file__).parents[1].joinpath("protocol.json").read_bytes())


def test_typed_targets_preserve_supplied_record_types_and_value():
    for case in selected()["cases"]:
        if case["family"] == "typed-boundary":
            record = json.loads(case["input"].split("Record: ", 1)[1])
            expected = {"value": record["payload"]}
            assert score(json.dumps(case["target"]), expected)["correct"]
    assert len({case["pair"] for case in selected()["cases"]}) == 24


def test_policy_pairs_have_one_changed_field_and_correct_boundary_disposition():
    cases = [c for c in selected()["cases"] if c["family"] == "policy-boundary"]
    for offset in range(0, 16, 2):
        a, b = cases[offset : offset + 2]
        left = json.loads(a["input"].split("Record: ", 1)[1])
        right = json.loads(b["input"].split("Record: ", 1)[1])
        assert a["pair"] == b["pair"]
        assert set(left) == set(right)
        assert sum(left[key] != right[key] for key in left) == 1
        assert a["target"]["decision"] != b["target"]["decision"]
    for case in cases:
        record = json.loads(case["input"].split("Record: ", 1)[1])
        if "checks" in record:
            expected = "publish" if record["checks"] and record["consent"] else "hold"
        elif "signature" in record:
            expected = (
                "admit"
                if record["signature"] == "valid" and record["now"] < record["expiry"]
                else "reject"
            )
        elif "committed" in record:
            expected = (
                "retry"
                if not record["committed"] and record["retry_authorized"]
                else "inspect"
            )
        elif "nonce_spent" in record:
            expected = (
                "dispatch"
                if record["authorized"] and not record["nonce_spent"]
                else "hold"
            )
        else:
            expected = (
                "publish"
                if record["evidence_complete"]
                and record["evidence_profile"] in record["reader_supports"]
                else "hold"
            )
        assert case["target"] == {"decision": expected}


def test_grounded_known_flag_distinguishes_explicit_null_false_zero_and_absence():
    cases = [c for c in selected()["cases"] if c["family"] == "grounded-boundary"]
    for case in cases:
        records = json.loads(case["input"].split("Records: ", 1)[1])
        field = case["input"].split("Query field ", 1)[1].split(".", 1)[0]
        if "Only subject Nia" in case["input"]:
            records = [record for record in records if record.get("subject") == "Nia"]
        values = [record[field] for record in records if field in record]
        known = bool(values) and all(
            type(value) is type(values[0]) and value == values[0] for value in values
        )
        expected = {"known": known, "value": values[0] if known else None}
        assert score(json.dumps(case["target"]), expected)["correct"]
    pairs = {c["id"]: c for c in cases}
    assert pairs["grounded-null-a"]["target"] == {"known": True, "value": None}
    assert pairs["grounded-null-b"]["target"] == {"known": False, "value": None}
    assert pairs["grounded-false-a"]["target"]["known"] is True
    assert pairs["grounded-zero-a"]["target"]["known"] is True


@pytest.mark.parametrize("value", [True, -1, 3.0])
def test_reselected_terminal_cpu_requires_nonnegative_integer(tmp_path, value):
    fixture(tmp_path)
    change(
        tmp_path,
        "terminal.json",
        lambda terminal: terminal.update(process_cpu_ns=value),
    )
    with pytest.raises(ValueError, match="terminal"):
        verify(tmp_path, repin(tmp_path))


def test_reselected_call_cpu_must_fit_total_cpu(tmp_path):
    fixture(tmp_path)
    change(
        tmp_path, "terminal.json", lambda terminal: terminal.update(process_cpu_ns=1)
    )
    with pytest.raises(ValueError, match="summed call CPU"):
        verify(tmp_path, repin(tmp_path))


def test_late_cpu_retains_all_scores_but_holds_publication(tmp_path):
    fixture(tmp_path)
    change(
        tmp_path,
        "terminal.json",
        lambda terminal: terminal.update(process_cpu_ns=600_000_000_001),
    )
    report = verify(tmp_path, repin(tmp_path))
    assert report["population"]["scored"] == 384
    assert report["evidence"]["withinRunBudget"] is False
    assert report["publicationDecision"].startswith("hold")


def test_typed_boundary_parser_rejects_duplicate_nonfinite_and_type_coercion():
    assert not score('{"value":0,"value":0}', {"value": 0})["formatValid"]
    assert not score('{"value":NaN}', {"value": None})["formatValid"]
    assert not score('{"value":false}', {"value": 0})["correct"]
    assert not score('{"known":1,"value":null}', {"known": True, "value": None})[
        "correct"
    ]
    assert not score('{"value":"7"}', {"value": 7})["correct"]
    assert not score('{"value":["first","second"]}', {"value": ["second", "first"]})[
        "correct"
    ]


def test_one_wrong_foil_cannot_count_as_a_correct_pair(tmp_path):
    fixture(tmp_path)
    p = selected()
    ident = next(
        ident
        for ident in p["order"]["attemptIds"]
        if ident.endswith("--policy-publish-consent-b")
    )
    change(
        tmp_path,
        f"calls/{ident}-returned.json",
        lambda row: row["response"]["choices"][0].update(text='{"decision":"publish"}'),
    )
    report = verify(tmp_path, repin(tmp_path))
    model, configuration, decoder, _ = ident.split("--")
    group = next(
        row
        for row in report["quality"]
        if row["model"] == model
        and row["configuration"] == configuration
        and row["decoder"] == decoder
        and row["family"] == "policy-boundary"
    )
    assert group["correct"] == 15 and group["schemaValid"] == 16
    assert group["plannedPairs"] == 8 and group["fullyCorrectPairs"] == 7
