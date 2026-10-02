"""Native format controls preserve decoder populations and semantic refusals."""

from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("format_gate", ROOT / "model_gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def selected(tmp_path):
    packet = tmp_path / "packet"
    packet.mkdir()
    with zipfile.ZipFile(ROOT / "format-run.zip") as archive:
        archive.extractall(packet)
    pins = ROOT / "format-native-pins.json"
    return packet, pins, json.loads((packet / "report.json").read_bytes())


def invoke(selected, tmp_path, kind="evidence", policy=None):
    packet, pins, _ = selected
    policy_path = ROOT / ("format-" + kind + "-policy.json")
    if policy is not None:
        policy_path = tmp_path / "host-policy.json"
        policy_path.write_text(json.dumps(policy) + "\n")
    return gate.gate(
        packet,
        pins,
        policy_path,
        sha(policy_path.read_bytes()),
        tmp_path / "receipts",
        60,
    )


def test_native_192_rows_keep_all_decoders_and_scores(selected, tmp_path):
    result = invoke(selected, tmp_path)
    assert result["publicationDecision"] == "publish"
    report = json.loads((tmp_path / "receipts/reader.stdout").read_bytes())
    assert report == selected[2]
    assert report["population"] == dict(
        planned=192,
        started=192,
        scored=192,
        error=0,
        incomplete=0,
        unsupported=0,
        **{"unknown-start": 0},
    )
    assert len(report["quality"]) == 32
    rows = [r for r in report["quality"] if r["decoder"] == "schema"]
    assert sum(r["formatValid"] for r in rows) == 96
    assert sum(r["schemaValid"] for r in rows) == 96
    assert sum(r["correct"] for r in rows if r["model"] == "smol135-q4") == 10
    assert sum(r["correct"] for r in rows if r["model"] == "smol360-q4") == 26


def test_native_valid_schema_does_not_override_semantic_policy(selected, tmp_path):
    result = invoke(selected, tmp_path, "quality")
    assert result["evidenceDecision"] == "verified"
    assert result["publicationDecision"] == "hold-selected-score-or-resource"
    assert len(result["policyFailures"]) == 2
    for failure in result["policyFailures"]:
        assert failure["row"]["model"] == "smol360-q4"
        assert failure["row"]["decoder"] == "schema"
        assert failure["row"]["family"] == "policy-decision"
        assert (failure["field"], failure["measured"], failure["minimum"]) == (
            "correct",
            1,
            3,
        )


def test_native_schema_policy_is_enforced_separately(selected, tmp_path):
    policy = json.loads((ROOT / "format-evidence-policy.json").read_bytes())
    row = next(
        r
        for r in policy["rows"]
        if r["model"] == "smol135-q4"
        and r["decoder"] == "unconstrained"
        and r["family"] == "arithmetic"
        and r["configuration"] == "short24"
    )
    row["minSchemaValid"] = 1
    result = invoke(selected, tmp_path, policy=policy)
    assert result["evidenceDecision"] == "verified"
    assert any(x["field"] == "schemaValid" for x in result["policyFailures"])


@pytest.mark.parametrize("name", gate.LIMIT_KEYS)
def test_native_format_resource_policy_holds(selected, tmp_path, name):
    policy = json.loads((ROOT / "format-evidence-policy.json").read_bytes())
    policy["limits"][name] = 0
    result = invoke(selected, tmp_path, policy=policy)
    assert result["evidenceDecision"] == "verified"
    assert any(x.get("resource") == name for x in result["policyFailures"])


@pytest.mark.parametrize("field", ["decoder", "model", "minSchemaValid"])
def test_decoder_population_policy_cannot_omit_fields(selected, tmp_path, field):
    policy = json.loads((ROOT / "format-evidence-policy.json").read_bytes())
    for row in policy["rows"]:
        row.pop(field)
    result = invoke(selected, tmp_path, policy=policy)
    assert not result["launched"]


def test_unsupported_population_is_not_admitted(selected):
    report = copy.deepcopy(selected[2])
    report["population"]["unsupported"] = 1
    policy = json.loads((ROOT / "format-evidence-policy.json").read_bytes())
    with pytest.raises(ValueError, match="population"):
        gate.report_rows(report, policy)


@pytest.mark.parametrize("value", [True, 7, -1])
def test_impossible_schema_counter_is_refused(selected, value):
    report = copy.deepcopy(selected[2])
    report["quality"][0]["schemaValid"] = value
    policy = json.loads((ROOT / "format-evidence-policy.json").read_bytes())
    with pytest.raises(ValueError):
        gate.report_rows(report, policy)


def test_correct_cannot_exceed_schema_valid(selected):
    report = copy.deepcopy(selected[2])
    row = next(r for r in report["quality"] if r["correct"] > 0)
    row["schemaValid"] = 0
    policy = json.loads((ROOT / "format-evidence-policy.json").read_bytes())
    with pytest.raises(ValueError, match="schema-valid"):
        gate.report_rows(report, policy)


def test_native_grammar_substitution_refuses(selected, tmp_path):
    grammar = next((selected[0] / "sources/grammars").glob("*.gbnf"))
    grammar.write_bytes(b'root ::= "x"\n')
    result = invoke(selected, tmp_path)
    assert result["evidenceDecision"] == "not-verified"
    assert result["child"]["returncode"] == 1


def test_legacy_policy_schema_does_not_silently_enable_decoder(selected, tmp_path):
    policy = json.loads((ROOT / "format-evidence-policy.json").read_bytes())
    policy["schema"] = "probity-model-publication-policy-v1"
    result = invoke(selected, tmp_path, policy=policy)
    assert not result["launched"]
