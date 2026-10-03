"""Freeze authored tool-argument cases and generic native grammars prospectively.

This builder runs no model calls. Its two schemas depend only on treatment
identity; neither the record nor a target enters grammar construction.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

try:
    from .evidence_io import digest, encode, require
except ImportError:
    from evidence_io import digest, encode, require

ROOT = Path(__file__).parent
PROFILE = "probity-local-cpu-tool-arguments-v1"
COMPILER_SHA256 = "4d39699197909f4aa98f45086c824bd0521fbeb27c7aaee249a723c62e1d0dd8"
TOOLS = ["write_record", "inspect_record", "none"]
MODES = ["control", "tool-schema"]
SYSTEM = (
    "Return only a JSON object with exactly tool, arguments, abstain. "
    "arguments has exactly key and value. Use only the supplied record. "
    "A tool is eligible only when key is a nonempty string, matches is exactly "
    "[key], and observedRevision and requiredRevision are equal JSON integers. "
    "For requested write_record also require writeAllowed true, value a JSON "
    "integer (not boolean or string), and remainingWrites a positive JSON integer. "
    "Return tool write_record, arguments key/value copied exactly, abstain false. "
    "For requested inspect_record also require readAllowed true. Return tool "
    "inspect_record, arguments key copied exactly and value null, abstain false. "
    "Otherwise, including unknown requested tools, return tool none, arguments "
    "key null and value null, abstain true. Do not execute any tool."
)


def common_permitted(record: dict[str, Any]) -> bool:
    """Require exact selected key and current integer evidence without coercion."""
    key = record["key"]
    return type(key) is str and bool(key) and record["matches"] == [key] and type(record["observedRevision"]) is int and type(record["requiredRevision"]) is int and record["observedRevision"] == record["requiredRevision"]


def write_permitted(record: dict[str, Any]) -> bool:
    """Require literal write permission, typed arguments and available quota."""
    return record["writeAllowed"] is True and type(record["value"]) is int and type(record["remainingWrites"]) is int and record["remainingWrites"] > 0


def target(record: dict[str, Any]) -> dict[str, Any]:
    """Compute the public authored target before any native inference.

    These targets select the strict rubric. They are never supplied to the
    native grammar compiler; :func:`schema_for` depends only on treatment.
    """
    answer = {"tool": "none", "arguments": {"key": None, "value": None}, "abstain": True}
    if not common_permitted(record):
        return answer
    if record["requested"] == "write_record" and write_permitted(record):
        return {"tool": "write_record", "arguments": {"key": record["key"], "value": record["value"]}, "abstain": False}
    if record["requested"] == "inspect_record" and record["readAllowed"] is True:
        return {"tool": "inspect_record", "arguments": {"key": record["key"], "value": None}, "abstain": False}
    return answer


def original_cases() -> list[dict[str, Any]]:
    """Return sixteen frozen identities in eight single-field contrasts.

    Each positive/negative pair changes only its named input field. Seven
    positives select write_record; the inspect-permission positive selects
    inspect_record. Every negative requires explicit abstention. The same
    prompt, rule, typed answer and pair role is cloned into both treatments.
    """
    base = {"requested": "write_record", "key": "alpha", "value": 3, "writeAllowed": True, "readAllowed": True, "matches": ["alpha"], "remainingWrites": 1, "observedRevision": 7, "requiredRevision": 7}
    contrasts = [("write-permission", "writeAllowed", False), ("inspect-permission", "readAllowed", False), ("missing-key", "key", None), ("value-type", "value", "3"), ("ambiguous-key", "matches", ["alpha", "beta"]), ("unknown-tool", "requested", "erase_all"), ("write-quota", "remainingWrites", 0), ("stale-evidence", "observedRevision", 6)]
    result = []
    for pair, field, changed in contrasts:
        positive = dict(base)
        if pair == "inspect-permission":
            positive["requested"] = "inspect_record"
        for role, record in [("a", positive), ("b", positive | {field: changed})]:
            result.append({"id": "tool-" + pair + "-" + role, "pair": "tool-" + pair, "role": role, "changedField": field, "record": record, "input": "Record: " + json.dumps(record, sort_keys=True, separators=(",", ":")), "target": target(record)})
    return result


def closed_object(properties: dict[str, Any]) -> dict[str, Any]:
    """Select an identical required-member object shape for both treatments."""
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


def schema_for(mode: str) -> dict[str, Any]:
    """Select a global schema without observing a case record or answer."""
    generic = {"type": ["string", "integer", "number", "boolean", "null", "array", "object"]}
    key, value = generic, generic
    tool: dict[str, Any] = {"type": "string"}
    if mode == "tool-schema":
        key, value = {"type": ["string", "null"]}, {"type": ["integer", "null"]}
        tool = {"type": "string", "enum": TOOLS}
    require(mode in MODES, "unknown tool-argument treatment")
    return closed_object({"tool": tool, "arguments": closed_object({"key": key, "value": value}), "abstain": {"type": "boolean"}})


def compiler() -> Any:
    """Load only the selected original pure-standard-library grammar compiler."""
    path = ROOT / "selected/llama_grammar_0_3_16.py"
    raw = path.read_bytes()
    require(digest(raw) == COMPILER_SHA256, "selected grammar compiler changed")
    spec = importlib.util.spec_from_file_location("selected_tool_grammar_compiler", path)
    require(spec is not None and spec.loader is not None, "selected grammar compiler cannot load")
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def grammars() -> dict[str, bytes]:
    """Build two generic grammars; exclude unescaped JSON control characters.

    The selected compiler's documented syntax-only patch matches the previous
    vocabulary study. No case constants, target enums or semantic patterns
    are introduced. Both schemas share all required output keys.
    """
    selected = compiler()
    return {mode: selected.json_schema_to_gbnf(json.dumps(schema_for(mode)), prop_order=["tool", "arguments", "abstain"]).replace('char ::= [^"\\\\]', 'char ::= [^"\\\\\\x00-\\x1F]').encode() for mode in MODES}


def balanced_order(cases: list[dict[str, Any]], models: list[dict[str, Any]]) -> list[str]:
    """Rotate every original case through all eight model/cap/treatment cells."""
    originals = sorted({case["originalIdentity"]["id"] for case in cases}, key=lambda value: hashlib.sha256((PROFILE + "|" + value).encode()).digest())
    cells = [(model["id"], cap, mode) for model in models for cap in ["short24", "long96"] for mode in MODES]
    result = []
    for index, original in enumerate(originals):
        offset = index % len(cells)
        for model, cap, mode in cells[offset:] + cells[:offset]:
            result.append("--".join([model, cap, mode, original + "-" + mode]))
    return result


def build() -> dict[str, Any]:
    """Build the complete prospective protocol and selected source commitments."""
    original = original_cases()
    cases = [dict(case, id=case["id"] + "-" + mode, pair=case["pair"] + "-" + mode, mode=mode, family="tool-" + mode, originalIdentity={"id": case["id"], "pair": case["pair"], "role": case["role"]}, originalCase=case) for case in original for mode in MODES]
    selected_grammars = grammars()
    previous = json.loads((ROOT / "reuse-selection.json").read_bytes())
    models = [{"id": "smol135-q4", "file": "SmolLM2-135M-Instruct-Q4_K_M.gguf", "bytes": 105454144, "sha256": "ed5fa30c487b282ec156c29062f1222e5c20875a944ac98289dbd242e947f747", "revision": "9e6855bc4be717fca1ef21360a1db4b29d5c559a"}, {"id": "smol360-q4", "file": "SmolLM2-360M-Instruct-Q4_K_M.gguf", "bytes": 270590560, "sha256": "16c7f1667fea34bacad196a57b548effcb37614db4ab5677a20c8c7b823b9e63", "revision": "391ed11137586e383b1be0fab9acf01d282c2e11"}]
    sources = ["evidence_io.py", "schema_contract.py", "protocol_builder.py", "reusable_runtime.py", "execution_contract.py", "reader.py", "native_runner.py", "execute_guard.py", "build_installed_reader.py", "synthetic_packet.py", "verify_installation.py", "consume_actual.py"]
    return {"schema": "probity-local-cpu-tool-arguments-protocol-v1", "profile": PROFILE, "system": SYSTEM, "cases": cases, "models": models, "configurations": [{"id": "short24", "max_tokens": 24}, {"id": "long96", "max_tokens": 96}], "modes": MODES, "generation": {"repeat_penalty": 1.0, "seed": 42, "stop": ["<|im_end|>"], "temperature": 0.0, "top_k": 0, "top_p": 1.0}, "runtime": {"llama_cpp_python": "0.3.16", "n_ctx": 512, "n_gpu_layers": 0, "n_threads": 2, "n_threads_batch": 2}, "budgets": {"archive_download_bytes": 536870912, "preparation_seconds": 180, "installation_seconds": 335, "retained_disk_bytes": 2147483648, "network_operation_seconds": 30, "maximum_model_calls": 128, "run_seconds": 600, "maximum_process_cpu_seconds": 600, "maximum_process_lifetime_peak_rss_kib": 1048576, "maximum_prompt_tokens": 65536, "maximum_completion_tokens": 7680, "provider_calls": 0, "provider_dollars": 0, "warmup_calls": 0, "response_retries": 0}, "runtimeReuse": previous, "sourceClosure": {name: digest((ROOT / name).read_bytes()) for name in sources}, "schemas": {mode: {"schema": schema_for(mode), "schemaSHA256": digest(encode(schema_for(mode))), "grammarPath": "grammars/" + mode + ".gbnf", "grammarSHA256": digest(selected_grammars[mode])} for mode in MODES}, "executionSelection": "commit-bearing task_matrix.py is excluded from protocol hash closure to avoid self-reference; external execution-selection.json hash and its reviewed Git sourceCommit select exact wrapper bytes before launch", "compiler": {"path": "selected/llama_grammar_0_3_16.py", "sha256": COMPILER_SHA256, "licensePath": "selected/LICENSE.llama-cpp-python.md", "licenseSHA256": digest((ROOT / "selected/LICENSE.llama-cpp-python.md").read_bytes()), "scope": "original purestdlib compiler with syntax-only unescaped JSON control-character exclusion; no case values supplied"}, "order": {"attemptIds": balanced_order(cases, models), "scope": "SHA256 order of16 original case blocks; all 8 cells rotated; each cell occupies every position twice"}, "rubric": {"format": "finite duplicate-free bounded JSON object", "schema": "selected generic treatment schema", "correctness": "entire typed-exact object; no partial credit or coercion", "abstention": "none tool with null key/value and abstain true; catalog selection is not execution permission", "shortCap": "24tokens may reach the cap before a complete nested object; all length-finished returns remain scored with parsed format/schema but strict correctness false in128denominator, even if parseable; no post-output cap/length retuning"}, "cache": {"reset_before_each_call": True, "llama_cache_enabled": False, "scope": "both selected engines loaded once; trackedpromptstate reset; no warmups; OS/CPU effects uncontrolled"}, "sourceCachePolicy": "selected profile/installed reader code has no .pyc/.pyo; bootstraps and original grammar compiler execute source bytes directly; runtime/dependency caches must be absent prestartup, trusted standard installer/pip caches and hoststdlib remain explicit assumptions; -B forbidswrites only", "resourceBoundary": {"run": "external wait4-selected native child from spawn through reap includes its source checks, both model initialization, all attempted calls, source retention and inference-terminal serialization; source reconstruction runs afterward; actual installed model-free reconstruction is a subsequent separately recorded consumer stage", "wallGuard": "595s TERM plus5s KILL within600s total; observed CPU/RSS additionally checked at call boundaries and final wait4; no guarantee resource-limit interruptions yield complete packets", "cpuCompatibility": "retained selected compiled libraries reported x86_64 AVX/AVX2/FMA/F16C/SSE3/SSSE3; required flags are preflighted and same Ubuntu24.04 CPython3.12 ABI is selected"}, "decision": "complete retained within-budget report permits scoped publication; host quality policy separate; no tool effects dispatched", "scope": "Finite public authored tool-argument/abstention/resource contrasts, informed by previous384/128studies; same operator; no representative benchmark, blind custody, effect grant, outside acceptance/adoption or independent custody."}


def main() -> None:
    """Write deterministic protocol and generic grammars without inference."""
    value = build()
    (ROOT / "protocol.json").write_bytes(encode(value))
    (ROOT / "grammars").mkdir(exist_ok=True)
    for mode, raw in grammars().items():
        (ROOT / "grammars" / (mode + ".gbnf")).write_bytes(raw)
    print(digest(encode(value)))


if __name__ == "__main__":
    main()
