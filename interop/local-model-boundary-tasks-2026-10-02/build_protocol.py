"""Produce a fixed authored boundary population without invoking a model."""

import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).parent


def encode(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def object_schema(fields):
    return {
        "type": "object",
        "properties": fields,
        "required": list(fields),
        "additionalProperties": False,
    }


def build():
    old = json.loads(
        ROOT.parent.joinpath(
            "local-model-format-control-2026-10-02/protocol.json"
        ).read_bytes()
    )
    cases = []
    contracts = {}
    paired = []

    def add(ident, family, text, target, schema, pair, role):
        cases.append(
            {
                "id": ident,
                "family": family,
                "input": text,
                "target": target,
                "pair": pair,
                "role": role,
            }
        )
        contracts[ident] = {"schema": schema}

    # Every type is requested in the prompt. No target value enters the schema.
    values = [
        ("integer-zero", 0, "integer"),
        ("integer-negative", -7, "integer"),
        ("boolean-false", False, "boolean"),
        ("boolean-true", True, "boolean"),
        ("null-value", None, "null"),
        ("string-null", "null", "string"),
        ("string-number", "007", "string"),
        ("integer-seven", 7, "integer"),
        ("empty-string", "", "string"),
        ("space-string", " ", "string"),
        ("escaped-quote", 'a"b', "string"),
        ("escaped-backslash", "a\\b", "string"),
        ("empty-list", [], "array"),
        ("ordered-list", ["second", "first"], "array"),
        ("unicode-string", "Málaga", "string"),
        ("newline-string", "top\nbottom", "string"),
    ]
    for index, (name, value, kind) in enumerate(values):
        field = {
            "type": ["string", "null"]
            if name in {"null-value", "string-null"}
            else kind
        }
        if kind == "array":
            field["items"] = {"type": "string"}
        schema = object_schema({"value": field})
        text = (
            f"Copy the payload into a JSON object with only key value. Preserve its JSON {kind} type, exact value and array order. Record: "
            + json.dumps({"payload": value}, ensure_ascii=False)
        )
        add(
            "typed-" + name,
            "typed-boundary",
            text,
            {"value": value},
            schema,
            "typed-pair-" + str(index // 2),
            "a" if index % 2 == 0 else "b",
        )

    policies = [
        (
            "publish-consent",
            "Publish iff checks and consent are both true; otherwise hold.",
            [{"checks": True, "consent": True}, {"checks": True, "consent": False}],
            ["publish", "hold"],
        ),
        (
            "publish-checks",
            "Publish iff checks and consent are both true; otherwise hold.",
            [{"checks": True, "consent": True}, {"checks": False, "consent": True}],
            ["publish", "hold"],
        ),
        (
            "admit-expiry",
            "Admit iff signature is valid and now is strictly less than expiry; otherwise reject.",
            [
                {"signature": "valid", "now": 10, "expiry": 11},
                {"signature": "valid", "now": 11, "expiry": 11},
            ],
            ["admit", "reject"],
        ),
        (
            "admit-signature",
            "Admit iff signature is valid and now is strictly less than expiry; otherwise reject.",
            [
                {"signature": "valid", "now": 10, "expiry": 11},
                {"signature": "invalid", "now": 10, "expiry": 11},
            ],
            ["admit", "reject"],
        ),
        (
            "recover-committed",
            "After an execution error, retry iff committed is false and retry_authorized is true; otherwise inspect. An error does not undo a committed effect.",
            [
                {"execution": "error", "committed": False, "retry_authorized": True},
                {"execution": "error", "committed": True, "retry_authorized": True},
            ],
            ["retry", "inspect"],
        ),
        (
            "recover-authorized",
            "After an execution error, retry iff committed is false and retry_authorized is true; otherwise inspect.",
            [
                {"execution": "error", "committed": False, "retry_authorized": True},
                {"execution": "error", "committed": False, "retry_authorized": False},
            ],
            ["retry", "inspect"],
        ),
        (
            "dispatch-spent",
            "Dispatch iff authorized is true and nonce_spent is false; otherwise hold.",
            [
                {"authorized": True, "nonce_spent": False},
                {"authorized": True, "nonce_spent": True},
            ],
            ["dispatch", "hold"],
        ),
        (
            "publish-reader",
            "Publish iff evidence_complete is true and the selected reader supports the evidence_profile; otherwise hold.",
            [
                {
                    "evidence_complete": True,
                    "evidence_profile": "v2",
                    "reader_supports": ["v1", "v2"],
                },
                {
                    "evidence_complete": True,
                    "evidence_profile": "v2",
                    "reader_supports": ["v1"],
                },
            ],
            ["publish", "hold"],
        ),
    ]
    for name, policy, records, targets in policies:
        pair = "policy-" + name
        paired.append(
            {
                "id": pair,
                "family": "policy-boundary",
                "changedField": next(
                    key for key in records[0] if records[0][key] != records[1][key]
                ),
            }
        )
        for index, (record, target) in enumerate(zip(records, targets)):
            role = "a" if index == 0 else "b"
            add(
                pair + "-" + role,
                "policy-boundary",
                policy
                + " Return only a JSON object with string key decision. Record: "
                + json.dumps(record),
                {"decision": target},
                object_schema({"decision": {"type": "string"}}),
                pair,
                role,
            )

    grounded = [
        ("zero", "age", [{"age": 0}], [{}], 0),
        ("false", "enabled", [{"enabled": False}], [{}], False),
        ("empty", "nickname", [{"nickname": ""}], [{}], ""),
        ("string-number", "code", [{"code": "007"}], [{}], "007"),
        ("null", "reviewer", [{"reviewer": None}], [{}], None),
        ("integer-conflict", "rooms", [{"rooms": 2}], [{"rooms": 2}, {"rooms": 3}], 2),
        (
            "string-conflict",
            "city",
            [{"city": "Lima"}],
            [{"city": "Lima"}, {"city": "Oslo"}],
            "Lima",
        ),
        (
            "matching-record",
            "age",
            [{"subject": "Nia", "age": 17}],
            [{"subject": "Omar", "age": 17}],
            17,
        ),
    ]
    shared = object_schema(
        {
            "known": {"type": "boolean"},
            "value": {"type": ["integer", "string", "boolean", "null"]},
        }
    )
    for name, key, good, bad, value in grounded:
        pair = "grounded-" + name
        paired.append(
            {
                "id": pair,
                "family": "grounded-boundary",
                "contrast": "unique supplied value versus absent or conflicting supplied evidence",
            }
        )
        rule = f"Use only the supplied records. Query field {key}. "
        if name == "matching-record":
            rule += "Only subject Nia matches the query. "
        rule += "Return only a JSON object with keys known and value. known is true iff at least one matching record explicitly contains the field and all such supplied values agree in both JSON type and value. If known is true, copy that value exactly, including false, zero, empty string or null. Otherwise known is false and value is null. Do not infer missing facts. Records: "
        for role, records, target in [
            ("a", good, {"known": True, "value": value}),
            ("b", bad, {"known": False, "value": None}),
        ]:
            add(
                pair + "-" + role,
                "grounded-boundary",
                rule + json.dumps(records),
                target,
                shared,
                pair,
                role,
            )

    spec = importlib.util.spec_from_file_location(
        "selected_compiler", ROOT / old["formatControl"]["compiler"]["sourcePath"]
    )
    compiler = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(compiler)
    patch = old["formatControl"]["compiler"]["syntaxPatch"]
    (ROOT / "grammars").mkdir(exist_ok=True)
    for ident, contract in contracts.items():
        schema = contract["schema"]
        raw = (
            compiler.json_schema_to_gbnf(
                json.dumps(schema), prop_order=schema["required"]
            ).replace(patch["from"], patch["to"])
            + "\n"
        ).encode()
        path = "grammars/" + ident + ".gbnf"
        (ROOT / path).write_bytes(raw)
        contract.update(
            schemaSHA256=hashlib.sha256(encode(schema)).hexdigest(),
            grammarPath=path,
            grammarSHA256=hashlib.sha256(raw).hexdigest(),
        )

    p = old
    p.update(
        schema="probity-local-cpu-boundary-tasks-protocol-v1",
        profile="probity-local-cpu-boundary-tasks-v1",
        cases=cases,
    )
    p["interpretation"] = (
        "New finite authored boundary population; typed values, policy decisions and grounded known/unknown distinctions. Model and decoder selections were informed by prior public authored studies; no blinded or representative benchmark, real protected effect or independent custody claim. Format/schema correctness remain separate from strict semantic correctness."
    )
    p["formatControl"]["taskContracts"] = contracts
    p["formatControl"]["compiler"]["rangeLimits"] = (
        "At most16 decimal integer digits, one optional ASCII space, fixed required-key order; no target constants/enums/patterns."
    )
    p["taskSelection"] = {
        "authored": True,
        "count": 48,
        "families": {
            "typed-boundary": 16,
            "policy-boundary": 16,
            "grounded-boundary": 16,
        },
        "selection": "Fixed before any new inference; informed by failures in earlier retained authored tasks. No task/drop/target/prompt/grammar changes after outputs.",
        "pairContrasts": paired,
        "historicalTasksUnchanged": True,
        "targetExposure": "Public targets and raw outputs emitted together; no blind custody.",
        "typedPairs": "Eight paired type/value boundaries; not all are single-field semantic foils.",
    }
    p["budgets"].update(
        maximum_model_calls=384,
        maximum_prompt_tokens=196608,
        maximum_completion_tokens=23040,
        maximum_process_cpu_seconds=600,
    )
    p["resources"]["cpu"] = (
        "Whole-process CPU delta for each call plus total process CPU during run, including initialization and worker threads; maximum600CPU seconds selected before run."
    )
    p["resources"]["limits"] += (
        "; CPU total checked at preflight and reader; no CPU hardkill and late returns retained/held."
    )
    p["resourceHistory"] = {
        "original48": {"run": 37044646302, "bytes": 278149773},
        "comparisonFailedPreparation": {
            "run": 37052641046,
            "bytes": 472190754,
            "started": 0,
        },
        "comparison96": {"run": 37053301748, "bytes": 472221945},
        "format192": {"run": 37056945285, "bytes": 472221945},
        "priorFourAttemptBytes": 1694784417,
        "scope": "512MiB per separate preparation. Current fresh preparation is additional and its actual bytes will be retained, including any failure; no response retry or aggregate reset.",
    }
    p["preparation"]["scope"] = (
        "Fresh selected transfer, no model/runtime payload cache exemption, within512MiB per declared preparation; previous attempts disclosed separately."
    )
    seed = "probity-boundary-tasks-2026-10-02"
    ranked = sorted(
        cases,
        key=lambda case: hashlib.sha256((seed + ":" + case["id"]).encode()).hexdigest(),
    )
    base = p["order"]["base"]
    attempts = []
    for index, case in enumerate(ranked):
        offset = index % 8
        for model, cap, decoder in base[offset:] + base[:offset]:
            attempts.append("--".join([model, cap, decoder, case["id"]]))
    p["order"] = {
        "seed": seed,
        "method": "SHA256(seed+colon+case.id) ranked48case blocks; rotate all8 model/cap/decoder pairs by sorted-case indexmod8; each pair each position6times; no warmup/repair/examples/retries/retuning",
        "base": base,
        "attemptIds": attempts,
    }
    assert len(cases) == 48 and len(attempts) == len(set(attempts)) == 384
    (ROOT / "protocol.json").write_bytes(encode(p))


if __name__ == "__main__":
    build()
