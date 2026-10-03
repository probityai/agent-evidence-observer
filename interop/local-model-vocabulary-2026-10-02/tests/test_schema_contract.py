"""Vocabulary constraints must not become typed coercion or an answer oracle."""

import pytest
from schema_contract import schema_accepts, score, validate_schema

VOCABULARY = ["publish", "hold", "admit", "reject", "retry", "inspect", "dispatch"]
CONTRACT = {
    "type": "object",
    "properties": {"decision": {"type": "string", "enum": VOCABULARY}},
    "required": ["decision"],
    "additionalProperties": False,
}


@pytest.mark.parametrize("decision", VOCABULARY)
def test_all_host_actions_remain_available(decision):
    assert schema_accepts({"decision": decision}, CONTRACT)


@pytest.mark.parametrize(
    "decision", ["dispatch-anything", "Publish", "", True, None, 1]
)
def test_outside_vocabulary_and_wrong_types_refuse(decision):
    assert not schema_accepts({"decision": decision}, CONTRACT)


def test_valid_vocabulary_is_not_correct_authority():
    assert score('{"decision":"dispatch"}', {"decision": "hold"}, CONTRACT) == {
        "formatValid": True,
        "schemaValid": True,
        "correct": False,
    }


def test_broad_control_and_vocabulary_intervention_have_distinct_admissibility():
    broad = dict(CONTRACT, properties={"decision": {"type": "string"}})
    assert schema_accepts({"decision": "invented"}, broad)
    assert not schema_accepts({"decision": "invented"}, CONTRACT)


@pytest.mark.parametrize(
    "text",
    [
        '{"decision":"hold","decision":"dispatch"}',
        '{"decision":NaN}',
        '{"decision":Infinity}',
        '{"decision":1e999}',
        '{"decision":-1e999}',
        '{"decision":',
    ],
)
def test_duplicate_nonfinite_and_incomplete_outputs_refuse(text):
    assert score(text, {"decision": "hold"}, CONTRACT) == {
        "formatValid": False,
        "schemaValid": False,
        "correct": False,
    }


def test_deeply_nested_output_refuses_without_crashing_reader():
    text = '{"decision":' + "[" * 20000 + "0" + "]" * 20000 + "}"
    result = score(text, {"decision": "hold"}, CONTRACT)
    assert result["schemaValid"] is False
    assert result["correct"] is False


@pytest.mark.parametrize("value", [{}, {"decision": "hold", "extra": "hold"}])
def test_member_population_is_exact(value):
    assert not schema_accepts(value, CONTRACT)


def test_union_preserves_enum_and_bool_integer_distinction():
    contract = {"type": ["integer", "boolean", "null"], "enum": [1, False, None]}
    assert schema_accepts(1, contract)
    assert schema_accepts(False, contract)
    assert schema_accepts(None, contract)
    assert not schema_accepts(True, contract)
    assert not schema_accepts(0, contract)
    assert not schema_accepts(1.0, contract)


def test_array_items_apply_nested_enums():
    contract = {
        "type": "array",
        "items": {"type": "string", "enum": ["hold", "inspect"]},
    }
    assert schema_accepts(["hold", "inspect"], contract)
    assert not schema_accepts(["hold", "publish"], contract)


@pytest.mark.parametrize(
    "contract",
    [
        {"type": "string", "enum": []},
        {"type": "string", "enum": "hold"},
        {"type": "string", "enum": ["hold", "hold"]},
        {"type": "integer", "enum": [True]},
        {"type": "string", "enum": [None]},
        {"type": "string", "const": "hold"},
        {"type": "string", "pattern": "hold"},
        {"type": ["string", "string"]},
        {"type": ["object", "null"]},
        {"type": "number"},
        {"type": "array"},
        {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": True,
        },
        {
            "type": "object",
            "properties": {"decision": {"type": "string"}},
            "required": [],
            "additionalProperties": False,
        },
    ],
)
def test_unsupported_or_malformed_contract_refuses_before_scoring(contract):
    with pytest.raises(ValueError):
        validate_schema(contract)
    with pytest.raises(ValueError):
        score('{"decision":"hold"}', {"decision": "hold"}, contract)
