"""Shared immutable population and request selection for runner and reader."""

from __future__ import annotations

from typing import Any

try:
    from .evidence_io import digest, encode, require
except ImportError:
    from evidence_io import digest, encode, require


def population(protocol: dict[str, Any]) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    """Join the frozen128 attempt IDs to their exact model/cap/case objects.

    The explicit order balances all eight treatment cells within each original
    case. Missing, duplicate, extra or malformed identities refuse before any
    native model API request. Cases and targets are not filtered by output.
    """
    cases = {case["id"]: case for case in protocol["cases"]}
    cells = {(model["id"], cap["id"], mode): dict(cap, model=model["id"], mode=mode) for model in protocol["models"] for cap in protocol["configurations"] for mode in protocol["modes"]}
    expected = {"--".join([model, cap, mode, case]) for model, cap, mode in cells for case, item in cases.items() if item["mode"] == mode}
    order = protocol["order"]["attemptIds"]
    require(len(order) == 128 and set(order) == expected and len(set(order)) == len(order), "attempt population differs from frozen128 selection")
    return [join_attempt(ident, cells, cases) for ident in order]


def join_attempt(ident: str, cells: dict[tuple[str, str, str], dict[str, Any]], cases: dict[str, dict[str, Any]]) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """Resolve one exact balanced identity without inventing an attempt."""
    model, cap, mode, case = ident.split("--")
    return ident, cells[model, cap, mode], cases[case]


def request(protocol: dict[str, Any], cell: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    """Select the identical prompt and frozen generic grammar treatment.

    Only the sampler schema differs across modes. No per-case target or target
    enum is inserted into a prompt or grammar. Native generation parameters
    remain part of each retained original request.
    """
    prompt = f"<|im_start|>system\n{protocol['system']}<|im_end|>\n<|im_start|>user\n{case['input']}<|im_end|>\n<|im_start|>assistant\n"
    schema = protocol["schemas"][case["mode"]]
    require(digest(encode(schema["schema"])) == schema["schemaSHA256"], "selected generic schema commitment differs")
    return dict(protocol["generation"], prompt=prompt, max_tokens=cell["max_tokens"], grammarSelection={"mode": case["mode"], "schemaSHA256": schema["schemaSHA256"], "grammarSHA256": schema["grammarSHA256"]})
