"""Reconstruct the finite selected tool-argument population without model code.

The installed reader assesses original bytes, requests, timelines, typed answers
and whole-process resource observations. It does not import retained runtime
code, execute a model or provide an independent inference/effect witness.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

try:
    from .evidence_io import digest, encode, packet_buffers, require, strict_json, timestamp
    from .execution_contract import population, request
    from .schema_contract import exact, score
    from .reusable_runtime import verify_reuse
except ImportError:
    from evidence_io import digest, encode, packet_buffers, require, strict_json, timestamp
    from execution_contract import population, request
    from schema_contract import exact, score
    from reusable_runtime import verify_reuse

PIN_NAMES = {"manifest", "protocol", "declaration", "terminal"}


def selected_pins(buffers: dict[str, bytes], pins: dict[str, Any]) -> dict[str, Any]:
    """Require four separately supplied original-object byte commitments."""
    require(set(pins) == PIN_NAMES, "reader requires separately selected manifest/protocol/declaration/terminal")
    result = {}
    for name, pin in pins.items():
        require(set(pin) == {"path", "sha256"}, "invalid artifact pin")
        raw = buffers[pin["path"]]
        require(digest(raw) == pin["sha256"], "selected artifact changed")
        result[name] = strict_json(raw)
    return result


def verify_sources(buffers: dict[str, bytes], protocol: dict[str, Any], manifest: dict[str, str]) -> None:
    """Bind every retained helper and runner to the frozen active installation."""
    sources = dict(protocol["sourceClosure"], **{"task_matrix.py": digest(Path(__file__).with_name("task_matrix.py").read_bytes())})
    for name, selected in sources.items():
        require(digest(Path(__file__).with_name(name).read_bytes()) == selected, "active source differs from selected protocol")
        require(manifest["sources/" + name] == selected, "retained source differs from active frozen reader")
    for mode, selection in protocol["schemas"].items():
        require(digest(buffers["sources/grammars/" + mode + ".gbnf"]) == selection["grammarSHA256"], "retained generic grammar differs")
        require(digest(encode(selection["schema"])) == selection["schemaSHA256"], "selected generic schema differs")
    require(digest(buffers["sources/" + protocol["compiler"]["path"]]) == protocol["compiler"]["sha256"], "retained grammar compiler differs")


def verify_manifest(buffers: dict[str, bytes], manifest: dict[str, str]) -> None:
    """Require the complete bounded original population and every byte hash."""
    allowed = {"manifest.json", "consumer-pins.json", "report.json"}
    require(set(buffers) - allowed == set(manifest), "retained original population changed")
    for name, selected in manifest.items():
        require(digest(buffers[name]) == selected, "original retained bytes changed")


def verify_declaration(declaration: dict[str, Any], terminal: dict[str, Any], protocol: dict[str, Any], protocol_commit: str, protocol_hash: str) -> None:
    """Require the prospective registration, entire runtime and128denominator."""
    expected = {"profile": protocol["profile"], "protocolCommit": protocol_commit, "protocolSHA256": protocol_hash, "planned": 128, "models": protocol["models"], "runtime": protocol["runtime"], "cache": protocol["cache"], "effectsExecuted": 0, "providerCalls": 0, "providerDollars": 0}
    require(all(exact(declaration.get(key), value) for key, value in expected.items()), "declaration differs from frozen source/protocol/runtime")
    require(declaration.get("mode") in {"actual-native", "synthetic-control"}, "declared execution mode differs")
    require(terminal.get("status") in {"complete", "error"}, "terminal status differs")
    require(timestamp(declaration["declaredAt"]) <= timestamp(terminal["finishedAt"]), "terminal timeline differs")
    require(all(type(terminal.get(key)) is int and terminal[key] >= 0 for key in ["elapsed_ns", "process_cpu_ns", "process_maxrss_kib"]), "terminal resources differ")


def verify_child_terminal(buffers: dict[str, bytes], declaration: dict[str, Any], terminal: dict[str, Any]) -> None:
    """Bind actual child observations to its separately observed process terminal."""
    if declaration["mode"] == "synthetic-control":
        return
    require(type(terminal.get("returnCode")) is int and type(terminal.get("wallGuardTerminated")) is bool, "external native terminal differs")
    if "inference-terminal.json" not in buffers:
        require(terminal["status"] == "error", "complete process lacks native child terminal")
        return
    child = strict_json(buffers["inference-terminal.json"])
    require(child.get("status") in {"complete", "error"}, "native child status differs")
    require(timestamp(declaration["declaredAt"]) <= timestamp(child["finishedAt"]) <= timestamp(terminal["finishedAt"]), "native child terminal timeline differs")
    require(all(type(child.get(key)) is int and 0 <= child[key] <= terminal[key] for key in ["elapsed_ns", "process_cpu_ns", "process_maxrss_kib"]), "native child resources exceed external process")
    require(terminal["status"] != "complete" or (child["status"] == "complete" and terminal["returnCode"] == 0 and not terminal["wallGuardTerminated"]), "complete external process differs from native child")


def initial_row(ident: str, cell: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    """Keep every planned identity, target abstention and pair role explicit."""
    return {"id": ident, "model": cell["model"], "configuration": cell["id"], "mode": case["mode"], "family": case["family"], "pair": case["pair"], "pairRole": case["role"], "originalIdentity": case["originalIdentity"], "targetAbstention": case["target"]["abstain"], "outcome": "unknown-start", "formatValid": False, "schemaValid": False, "correct": False, "truncated": False}


def verify_start(start: dict[str, Any], ident: str, cell: dict[str, Any], case: dict[str, Any], protocol: dict[str, Any]) -> None:
    """Bind a started call to the exact prompt, grammar and context preflight."""
    require(set(start) == {"id", "request", "startedAt", "promptTokensPreflight"}, "started attempt members differ")
    require(start["id"] == ident and exact(start["request"], request(protocol, cell, case)), "started request differs from frozen population")
    tokens = start["promptTokensPreflight"]
    require(type(tokens) is int and 0 < tokens <= protocol["runtime"]["n_ctx"] - cell["max_tokens"], "started context exceeds selected runtime")


def verify_return(returned: dict[str, Any], start: dict[str, Any], cell: dict[str, Any]) -> None:
    """Require complete raw native response, usage and resource observations."""
    require(all(exact(returned.get(key), value) for key, value in start.items()), "returned call differs from started request")
    usage = returned["response"]["usage"]
    require(all(type(usage.get(key)) is int and usage[key] >= 0 for key in ["prompt_tokens", "completion_tokens", "total_tokens"]), "native usage must contain nonnegative integers")
    require(usage["prompt_tokens"] == start["promptTokensPreflight"] and usage["completion_tokens"] <= cell["max_tokens"] and usage["total_tokens"] == usage["prompt_tokens"] + usage["completion_tokens"], "native usage differs from preflight or selected cap")
    resources = returned["resources"]
    require(all(type(resources.get(key)) is int and resources[key] >= 0 for key in ["elapsed_ns", "process_cpu_ns", "process_maxrss_kib"]), "native resources must contain nonnegative integers")
    choices = returned["response"]["choices"]
    require(type(choices) is list and len(choices) == 1 and type(choices[0].get("text")) is str and choices[0].get("finish_reason") in {"stop", "length"}, "native response choice differs")


def completed_row(row: dict[str, Any], returned: dict[str, Any], case: dict[str, Any], protocol: dict[str, Any]) -> dict[str, Any]:
    """Score one returned attempt without turning truncation into an absent call."""
    choice = returned["response"]["choices"][0]
    result = dict(row, outcome="scored", truncated=choice["finish_reason"] == "length", usage=returned["response"]["usage"], resources=returned["resources"], finishReason=choice["finish_reason"])
    result.update(score(choice["text"], case["target"], protocol["schemas"][case["mode"]]["schema"]))
    if result["truncated"]:
        result["correct"] = False
    return result


def attempt_row(buffers: dict[str, bytes], ident: str, cell: dict[str, Any], case: dict[str, Any], protocol: dict[str, Any]) -> tuple[dict[str, Any], set[str], str | None, str | None]:
    """Reconstruct a single explicit started/returned/error/incomplete relation."""
    row = initial_row(ident, cell, case)
    names = {kind: "calls/" + ident + "-" + kind + ".json" for kind in ["started", "returned", "error"]}
    present = {name for name in names.values() if name in buffers}
    require(not present or names["started"] in present, "returned or error call lacks started original")
    if not present:
        return row, present, None, None
    start = strict_json(buffers[names["started"]])
    verify_start(start, ident, cell, case, protocol)
    row["outcome"] = "incomplete"
    require(not (names["returned"] in present and names["error"] in present), "attempt has both response and error")
    if names["returned"] in present:
        returned = strict_json(buffers[names["returned"]])
        verify_return(returned, start, cell)
        return completed_row(row, returned, case, protocol), present, start["startedAt"], returned["finishedAt"]
    if names["error"] in present:
        return error_row(row, strict_json(buffers[names["error"]]), start), present, start["startedAt"], strict_json(buffers[names["error"]])["finishedAt"]
    return row, present, start["startedAt"], None


def error_row(row: dict[str, Any], error: dict[str, Any], start: dict[str, Any]) -> dict[str, Any]:
    """Preserve unsupported interfaces and native failures without fabricated use."""
    require(all(exact(error.get(key), value) for key, value in start.items()) and type(error.get("error")) is dict, "error differs from started original")
    outcome = "unsupported" if error["error"].get("type") == "NotImplementedError" else "error"
    return dict(row, outcome=outcome, error=error["error"], resourceScope="failed native calls have unknown response token use; retained terminal totals remain selected")


def rows_and_timeline(buffers: dict[str, bytes], protocol: dict[str, Any], declaration: dict[str, Any], terminal: dict[str, Any]) -> list[dict[str, Any]]:
    """Join all128identities and require their balanced serial observation order."""
    rows, expected_calls = [], set()
    previous = timestamp(declaration["declaredAt"])
    stopped = False
    finished = timestamp(terminal["finishedAt"])
    for ident, cell, case in population(protocol):
        row, present, started_at, finished_at = attempt_row(buffers, ident, cell, case, protocol)
        require(not stopped or not present, "attempt started after frozen stop boundary")
        stopped = stopped or row["outcome"] != "scored"
        expected_calls.update(present)
        previous = check_times(previous, finished, started_at, finished_at)
        rows.append(row)
    require({name for name in buffers if name.startswith("calls/")} == expected_calls, "native call population differs from frozen selection")
    require(sum(row.get("resources", {}).get("elapsed_ns", 0) for row in rows) <= terminal["elapsed_ns"], "returned elapsed exceeds total process run")
    require(sum(row.get("resources", {}).get("process_cpu_ns", 0) for row in rows) <= terminal["process_cpu_ns"], "returned CPU exceeds total process run")
    require(terminal["status"] != "complete" or all(row["outcome"] == "scored" for row in rows), "complete terminal lacks full returned population")
    return rows


def check_times(previous: Any, terminal: Any, start: str | None, finish: str | None) -> Any:
    """Require serial order while leaving genuinely unstarted attempts unstarted."""
    if start is None:
        return previous
    require(previous <= timestamp(start) <= terminal, "balanced attempt timeline differs")
    if finish is None:
        return timestamp(start)
    require(timestamp(start) <= timestamp(finish) <= terminal, "attempt completion timeline differs")
    return timestamp(finish)


def quality_row(rows: list[dict[str, Any]], model: str, cap: str, mode: str) -> dict[str, Any]:
    """Preserve row denominators, abstention cases, pairs and explicit truncation."""
    selected = [row for row in rows if (row["model"], row["configuration"], row["mode"]) == (model, cap, mode)]
    pairs = {row["pair"] for row in selected}
    return {"model": model, "configuration": cap, "mode": mode, "planned": 16, "plannedPairs": 8, "scored": sum(row["outcome"] == "scored" for row in selected), "formatValid": sum(row["formatValid"] for row in selected), "schemaValid": sum(row["schemaValid"] for row in selected), "correct": sum(row["correct"] for row in selected), "fullyCorrectPairs": sum(all(row["correct"] for row in selected if row["pair"] == pair) for pair in pairs), "truncatedReturns": sum(row["truncated"] for row in selected), "plannedAbstentions": sum(row["targetAbstention"] for row in selected), "correctAbstentions": sum(row["correct"] and row["targetAbstention"] for row in selected)}


def within_budget(rows: list[dict[str, Any]], terminal: dict[str, Any], protocol: dict[str, Any], tokens: dict[str, int]) -> bool:
    """Assess complete whole-process totals without excluding initialization."""
    budgets = protocol["budgets"]
    peak = max([terminal["process_maxrss_kib"]] + [row.get("resources", {}).get("process_maxrss_kib", 0) for row in rows])
    return terminal["elapsed_ns"] <= budgets["run_seconds"] * 1000000000 and terminal["process_cpu_ns"] <= budgets["maximum_process_cpu_seconds"] * 1000000000 and peak <= budgets["maximum_process_lifetime_peak_rss_kib"] and tokens["prompt"] <= budgets["maximum_prompt_tokens"] and tokens["completion"] <= budgets["maximum_completion_tokens"]


def report(rows: list[dict[str, Any]], terminal: dict[str, Any], protocol: dict[str, Any], reuse: dict[str, Any]) -> dict[str, Any]:
    """Publish complete scoped evidence independently of the host quality hold."""
    outcomes = Counter(row["outcome"] for row in rows)
    tokens = {kind: sum(row.get("usage", {}).get(kind + "_tokens", 0) for row in rows) for kind in ["prompt", "completion"]}
    complete = outcomes["scored"] == 128 and terminal["status"] == "complete"
    bounded = within_budget(rows, terminal, protocol, tokens)
    quality = [quality_row(rows, model["id"], cap["id"], mode) for model in protocol["models"] for cap in protocol["configurations"] for mode in protocol["modes"]]
    admitted = all(row["correct"] == 16 and row["fullyCorrectPairs"] == 8 for row in quality)
    return {"profile": protocol["profile"], "population": {"planned": 128, "started": 128 - outcomes["unknown-start"], **{name: outcomes[name] for name in ["scored", "error", "unsupported", "incomplete", "unknown-start"]}}, "evidence": {"complete": complete, "withinRunBudget": bounded}, "publicationDecision": "publish-scoped-report" if complete and bounded else "hold-incomplete-or-resource-evidence", "qualityDecision": "admit-scoped-quality" if complete and bounded and admitted else "hold-tool-decision-quality", "quality": quality, "nativeTokens": tokens, "resources": {key: terminal[key] for key in ["elapsed_ns", "process_cpu_ns", "process_maxrss_kib"]}, "preparationReuse": reuse, "attempts": rows, "effectsExecuted": 0, "providerCalls": 0, "providerDollars": 0, "scope": protocol["scope"], "resourceScope": "external selected child wall/wait4 CPU/peak RSS include initialization, source/runtime checks and retained inference-terminal serialization; post-child installed reconstruction separately recorded; returned token use known, failed call response use unknown; observed CPU/RSS checks and external wall guard"}


def verify(root: Path, pins: dict[str, Any], protocol: dict[str, Any], protocol_commit: str, protocol_hash: str) -> dict[str, Any]:
    """Reconstruct selected originals using this frozen installed reader only.

    No model framework or retained Python/binary runtime code is imported.
    Original buffers are read once under finite limits. Source-selected packet
    pins remain an external input; same-operator observations and replay do
    not establish independently controlled inference or effect custody.
    """
    buffers = packet_buffers(root)
    selected = selected_pins(buffers, pins)
    require(digest(buffers[pins["protocol"]["path"]]) == protocol_hash and exact(selected["protocol"], protocol), "packet protocol differs from frozen installation")
    verify_manifest(buffers, selected["manifest"])
    verify_sources(buffers, protocol, selected["manifest"])
    verify_declaration(selected["declaration"], selected["terminal"], protocol, protocol_commit, protocol_hash)
    verify_child_terminal(buffers, selected["declaration"], selected["terminal"])
    reuse = verify_reuse_buffers(buffers, protocol)
    rows = rows_and_timeline(buffers, protocol, selected["declaration"], selected["terminal"])
    return dict(report(rows, selected["terminal"], protocol, reuse), executionMode=selected["declaration"]["mode"])


def verify_reuse_buffers(buffers: dict[str, bytes], protocol: dict[str, Any]) -> dict[str, Any]:
    """Assess custody from the same bounded snapshot through a private copy.

    The helper's filesystem interface consumes only copied selected buffers.
    It never rereads the live candidate tree or imports its retained code.
    """
    with TemporaryDirectory(prefix="probity-tool-reader-") as directory:
        selected = Path(directory)
        for name, raw in buffers.items():
            if name.startswith(("sources/reuse/", "sources/llama/", "sources/llama-cpp-python/")):
                path = selected / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
        return verify_reuse(selected, protocol)
