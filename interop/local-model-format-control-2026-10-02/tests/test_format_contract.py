"""Grammar is a syntax aid, never an answer oracle or repaired-score route."""

import importlib.util
import json
from pathlib import Path

import pytest
from task_matrix import (
    PROTOCOL_SHA256,
    digest,
    encode,
    population,
    protocol,
    request,
    score,
    verify,
    write,
)
from test_task_matrix import change, fixture, repin

ROOT = Path(__file__).parents[1]


def selected_protocol():
    return protocol(ROOT.joinpath("protocol.json").read_bytes())


def test_exact_selected_compiler_reproduces_frozen_syntax_grammars():
    p = selected_protocol()
    compiler = p["formatControl"]["compiler"]
    source = ROOT / compiler["sourcePath"]
    assert digest(source.read_bytes()) == compiler["sourceSHA256"]
    spec = importlib.util.spec_from_file_location("selected_grammar_compiler", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    patch = compiler["syntaxPatch"]
    for contract in p["formatControl"]["taskContracts"].values():
        schema = contract["schema"]
        generated = module.json_schema_to_gbnf(
            json.dumps(schema), prop_order=schema["required"]
        )
        generated = (generated.replace(patch["from"], patch["to"]) + "\n").encode()
        assert generated == ROOT.joinpath(contract["grammarPath"]).read_bytes()
        assert digest(generated) == contract["grammarSHA256"]
        assert digest(encode(schema)) == contract["schemaSHA256"]


def test_schema_contracts_contain_no_target_value_constraints():
    def walk(schema):
        assert set(schema) <= {
            "type",
            "properties",
            "required",
            "additionalProperties",
            "items",
        }
        for child in schema.get("properties", {}).values():
            walk(child)
        if "items" in schema:
            walk(schema["items"])

    p = selected_protocol()
    assert set(p["formatControl"]["taskContracts"]) == {
        case["id"] for case in p["cases"]
    }
    for case in p["cases"]:
        contract = p["formatControl"]["taskContracts"][case["id"]]
        walk(contract["schema"])
        grammar = ROOT.joinpath(contract["grammarPath"]).read_text()
        if case["family"] == "policy-decision":
            assert all(
                '"' + value + '"' not in grammar
                for value in ["publish", "hold", "admit", "reject"]
            )
    # Grounded absence and presence share one broad nullable scalar contract.
    grounded = [
        p["formatControl"]["taskContracts"][case["id"]]["schema"]
        for case in p["cases"]
        if case["family"] == "grounded-abstention"
    ]
    assert all(schema == grounded[0] for schema in grounded)


@pytest.mark.parametrize(
    "text,target,kind,syntax,contract,correct",
    [
        ('{"answer":11}', {"answer": 14}, "arithmetic-combined", True, True, False),
        (
            '{"decision":"publish"}',
            {"decision": "hold"},
            "policy-hold-consent",
            True,
            True,
            False,
        ),
        (
            '{"answer":"unknown"}',
            {"answer": None},
            "abstain-unknown-age",
            True,
            True,
            False,
        ),
        ('{"answer":true}', {"answer": 1}, "arithmetic-sum", True, False, False),
        ('{"answer":14.0}', {"answer": 14}, "arithmetic-combined", True, False, False),
        (
            '{"answer":14,"extra":0}',
            {"answer": 14},
            "arithmetic-combined",
            True,
            False,
            False,
        ),
        ('{"answer":14}', {"answer": 14}, "arithmetic-combined", True, True, True),
        ('{"answer":', {"answer": 14}, "arithmetic-combined", False, False, False),
    ],
)
def test_format_contract_and_semantic_correctness_remain_separate(
    text, target, kind, syntax, contract, correct
):
    schema = selected_protocol()["formatControl"]["taskContracts"][kind]["schema"]
    assert score(text, target, schema) == {
        "formatValid": syntax,
        "schemaValid": contract,
        "correct": correct,
    }


def test_decoder_does_not_change_prompt_or_native_non_grammar_settings():
    p = selected_protocol()
    rows = population(p)
    for offset in range(0, 192, 8):
        requests = [request(p, cfg, case) for _, cfg, case in rows[offset : offset + 8]]
        assert len({r["prompt"] for r in requests}) == 1
        for req in requests:
            assert {
                k: v
                for k, v in req.items()
                if k not in {"grammarSelection", "max_tokens", "prompt"}
            } == p["generation"]
    assert digest(ROOT.joinpath("protocol.json").read_bytes()) == PROTOCOL_SHA256


@pytest.mark.parametrize(
    "mutation",
    ["grammar", "compiler", "nativecompiler", "request", "decoder", "declaration"],
)
def test_reselected_grammar_source_selection_and_call_configuration_refuse(
    tmp_path, mutation
):
    fixture(tmp_path)
    p = selected_protocol()
    order = population(p)
    first = next(
        (ident, cfg, case) for ident, cfg, case in order if cfg["decoder"] == "schema"
    )
    if mutation == "grammar":
        (tmp_path / "sources/grammars" / (first[2]["id"] + ".gbnf")).write_text(
            'root ::= "correct-answer"\n'
        )
    elif mutation == "compiler":
        (tmp_path / "sources/selected-grammar-compiler.py").write_bytes(b"changed")
    elif mutation == "nativecompiler":
        (tmp_path / "sources/llama/llama_grammar.py").write_bytes(b"changed")
    elif mutation == "request":
        change(
            tmp_path,
            f"calls/{first[0]}-started.json",
            lambda v: v["request"]["grammarSelection"].update(grammarSHA256="0" * 64),
        )
    elif mutation == "decoder":
        change(
            tmp_path,
            f"calls/{first[0]}-started.json",
            lambda v: v["request"]["grammarSelection"].update(decoder="unconstrained"),
        )
    elif mutation == "declaration":
        change(
            tmp_path,
            "declaration.json",
            lambda v: v.update(formatControlSHA256="0" * 64),
        )
    with pytest.raises(ValueError):
        verify(tmp_path, repin(tmp_path))


def test_native_unsupported_constraint_keeps_denominator_without_fallback(tmp_path):
    fixture(tmp_path)
    row = next(
        (ident, cfg, case)
        for ident, cfg, case in population(selected_protocol())
        if cfg["decoder"] == "schema"
    )
    name = f"calls/{row[0]}"
    start = json.loads((tmp_path / (name + "-started.json")).read_bytes())
    returned = json.loads((tmp_path / (name + "-returned.json")).read_bytes())
    (tmp_path / (name + "-returned.json")).unlink()
    write(
        tmp_path / (name + "-error.json"),
        dict(
            **start,
            finishedAt=returned["finishedAt"],
            error={
                "type": "NotImplementedError",
                "message": "selected schema interface unsupported",
            },
        ),
    )
    change(tmp_path, "terminal.json", lambda v: v.update(status="error"))
    report = verify(tmp_path, repin(tmp_path))
    assert report["population"]["planned"] == 192
    assert report["population"]["unsupported"] == 1
    assert report["population"]["scored"] == 191
    assert report["publicationDecision"].startswith("hold")
    attempt = next(a for a in report["attempts"] if a["id"] == row[0])
    assert (
        attempt["correct"] is attempt["formatValid"] is attempt["schemaValid"] is None
    )
