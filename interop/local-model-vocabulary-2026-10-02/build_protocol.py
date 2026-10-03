"""Freeze a global action-vocabulary intervention without running a model."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PARENT = ROOT.parent / "local-model-boundary-tasks-2026-10-02"
PARENT_SHA = "78ee69f5c5a8cc51095e960939ca42497d6f48f2bb6aad54deff098a5faf2ea2"
ACTIONS = ["publish", "hold", "admit", "reject", "retry", "inspect", "dispatch"]


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def build():
    original_raw = (PARENT / "protocol.json").read_bytes()
    if digest(original_raw) != PARENT_SHA:
        raise ValueError("immutable parent protocol changed")
    old = json.loads(original_raw)
    original = [c for c in old["cases"] if c["family"] == "policy-boundary"]
    assert len(original) == 16
    p = copy.deepcopy(old)
    cases, contracts = [], {}
    for case in original:
        for mode in ["control", "vocabulary"]:
            clone = copy.deepcopy(case)
            clone.update(id=case["id"] + "-" + mode, family="policy-" + mode,
                         pair=case["pair"] + "-" + mode, mode=mode,
                         originalIdentity={k: case[k] for k in ["id", "family", "pair", "role"]},
                         originalCase=copy.deepcopy(case))
            cases.append(clone)
            schema = copy.deepcopy(old["formatControl"]["taskContracts"][case["id"]]["schema"])
            if mode == "vocabulary":
                schema["properties"]["decision"]["enum"] = ACTIONS.copy()
            contracts[clone["id"]] = {"schema": schema}
    spec = importlib.util.spec_from_file_location("selected_compiler", ROOT / old["formatControl"]["compiler"]["sourcePath"])
    compiler = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(compiler)
    patch = old["formatControl"]["compiler"]["syntaxPatch"]
    (ROOT / "grammars").mkdir(exist_ok=True)
    for ident, contract in contracts.items():
        schema = contract["schema"]
        raw = (compiler.json_schema_to_gbnf(json.dumps(schema), prop_order=schema["required"]).replace(patch["from"], patch["to"]) + "\n").encode()
        path = "grammars/" + ident + ".gbnf"
        (ROOT / path).write_bytes(raw)
        contract.update(schemaSHA256=digest(encode(schema)), grammarPath=path, grammarSHA256=digest(raw))
    p.update(schema="probity-local-cpu-vocabulary-protocol-v1", profile="probity-local-cpu-vocabulary-v1", cases=cases,
             decoders=[{"id": "schema", "grammar": True}], interpretation="Finite authored global action-vocabulary intervention informed by the previous384 run. Broad-string schema control versus the same seven-action enum for every vocabulary case. Format, schema validity and semantic correctness remain separate. No representative benchmark, protected effect, producer acceptance or independent custody claim.")
    p["formatControl"]["taskContracts"] = contracts
    p["formatControl"]["compiler"]["rangeLimits"] = "Same closed object grammar in both modes; vocabulary mode selects all seven global action labels, independently of case input or target. No target-specific constants, patterns or enums."
    p["taskSelection"] = {"authored": True, "count": 32, "families": {"policy-control": 16, "policy-vocabulary": 16},
        "selection": "Exact sixteen original policy-boundary objects cloned twice with original identity and full object retained. Fixed before inference; no task/drop/target/prompt/grammar changes after output.",
        "historicalTasksUnchanged": True, "targetExposure": "Public authored targets; no blinded custody.",
        "originalPolicyCasesSHA256": digest(encode(original)), "pairContrasts": [dict(copy.deepcopy(pair), id=pair["id"] + "-" + mode, family="policy-" + mode, originalIdentity={"id": pair["id"], "family": pair["family"]}) for pair in old["taskSelection"]["pairContrasts"] if pair["family"] == "policy-boundary" for mode in ["control", "vocabulary"]]}
    p["sourceClosure"] = {"originalProtocolPath": str(PARENT.relative_to(ROOT.parent.parent) / "protocol.json"),
        "originalProtocolSHA256": PARENT_SHA, "schemaHelperPath": "schema_contract.py", "schemaHelperSHA256": digest((ROOT / "schema_contract.py").read_bytes()),
        "builderSHA256": digest(Path(__file__).read_bytes()), "runnerAuthority": "Retained runner bytes must equal the active installed reader bytes; protocol commitment and externally held packet pins are additionally required. Replays use this frozen reader, never execute retained candidate code.",
        "requiredNativeSources": ["sources/task_matrix.py", "sources/schema_contract.py", "sources/prepare_boundary.py", "sources/build_protocol.py"]}
    p["budgets"].update(maximum_model_calls=128, maximum_prompt_tokens=65536, maximum_completion_tokens=7680)
    p["resourceHistory"]["boundary384"] = {"run": 37060702246, "bytes": 472221945}
    p["resourceHistory"].pop("priorFourAttemptBytes", None)
    p["resourceHistory"]["priorFiveAttemptBytes"] = 2167006362
    p["resourceHistory"]["scope"] = "Previous five preparations disclosed separately. This independently frozen128 preparation adds actual transferred bytes, including failures; no response retry, aggregate reset or model-cache exemption."
    seed = "probity-global-vocabulary-2026-10-02"
    ranked = sorted(original, key=lambda c: digest((seed + ":" + c["id"]).encode()))
    base = [[m["id"], c["id"], "schema", mode] for m in p["models"] for c in p["configurations"] for mode in ["control", "vocabulary"]]
    attempts = []
    for index, case in enumerate(ranked):
        offset = index % 8
        attempts.extend("--".join([*cfg[:3], case["id"] + "-" + cfg[3]]) for cfg in base[offset:] + base[:offset])
    p["order"] = {"seed": seed, "method": "SHA256(seed+colon+originalcase.id) ranked16 original-case blocks; rotate all eight model/cap/mode cells by original-case indexmod8; each cell each position twice; no warmup, repair, examples, retries or retuning.", "base": base, "attemptIds": attempts}
    assert len(cases) == 32 and len(attempts) == len(set(attempts)) == 128
    (ROOT / "protocol.json").write_bytes(encode(p))


if __name__ == "__main__":
    build()
