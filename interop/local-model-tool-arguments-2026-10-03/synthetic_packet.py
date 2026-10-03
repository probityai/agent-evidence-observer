"""Author disclosed offline reader controls; no runtime or inference executes.

Native custody bytes come from the independently selected previous retained
ZIP. New synthetic preparation/installation/usage/resource observations are
simulated fixtures, explicitly labeled synthetic-control in the declaration.
They validate reconstruction, denominators and refusals, never real results.
"""

from __future__ import annotations

import json
from pathlib import Path
import zipfile
from typing import Any

try:
    from .evidence_io import digest, now, require, write
    from .execution_contract import population, request
    from .native_runner import custody_destination, finish
except ImportError:
    from evidence_io import digest, now, require, write
    from execution_contract import population, request
    from native_runner import custody_destination, finish

ROOT = Path(__file__).parent
PRIOR_NATIVE_SHA256 = "eef05226335f9e2de6783ee797d891cbd1fe47058264e2d57eb41f1ec39131d8"


def custody(root: Path, selected_archive: Path, protocol: dict[str, Any]) -> None:
    """Copy only exact selected native/receipt originals from the prior ZIP."""
    require(digest(selected_archive.read_bytes()) == PRIOR_NATIVE_SHA256, "selected prior native archive changed")
    with zipfile.ZipFile(selected_archive) as archive:
        for row in protocol["runtimeReuse"]["selectedFiles"]:
            destination = custody_destination(row)
            if destination is None:
                continue
            archive_name = row["archivePath"].removeprefix("run/")
            raw = (ROOT / "retained/reuse-originals" / row["path"]).read_bytes() if row["category"] == "receipt" else archive.read(archive_name)
            require(len(raw) == row["bytes"] and digest(raw) == row["sha256"], "selected native fixture custody differs")
            write(root / destination, raw)


def simulated_reuse(root: Path, protocol: dict[str, Any]) -> None:
    """Retain explicitly synthetic bounded accounting and native identity maps."""
    selection = protocol["runtimeReuse"]
    identity = {key: selection["archive"][key] for key in ["bytes", "sha256"]}
    charge = {"status": "passed", "route": "local-verified", "archiveIdentity": identity, "responseBodyBytes": 0, "networkAttempts": 0, "providerCalls": 0, "providerDollars": 0, "elapsedSeconds": 1.0, "originalPreparation": selection["originalPreparation"], "syntheticFixture": True}
    projection = {"status": "passed", "files": [{key: row[key] for key in ["archivePath", "path", "category", "bytes", "sha256"]} for row in selection["selectedFiles"]]}
    installed = {str(Path(row["path"]).relative_to("runtime")): {"bytes": row["bytes"], "sha256": row["sha256"]} for row in selection["selectedFiles"] if row["category"] in {"runtime", "runtime-metadata"}}
    installed_bytes = sum(row["bytes"] for row in installed.values())
    installation = {"status": "passed", "nativeBuilds": 0, "networkResponseBytes": 0, "elapsedSeconds": 1.0, "retainedBytes": 477404572, "installedBytes": installed_bytes, "installedFiles": installed, "abi": selection["abi"], "importProbe": "0.3.16", "syntheticFixture": True}
    terminal = {"status": "passed", "elapsedSeconds": 1.0, "responseBodyBytes": 0, "selectedBytes": sum(row["bytes"] for row in selection["selectedFiles"]), "syntheticFixture": True}
    for name, value in [("archive-accounting", charge), ("reuse-projection", projection), ("installation", installation), ("preparation-terminal", terminal)]:
        write(root / "sources/reuse" / (name + ".json"), value)


def sources(root: Path, protocol: dict[str, Any]) -> None:
    """Retain this active frozen reader's originals for source-refusal controls."""
    for name in list(protocol["sourceClosure"]) + ["task_matrix.py", protocol["compiler"]["path"], protocol["compiler"]["licensePath"]]:
        write(root / "sources" / name, (ROOT / name).read_bytes())
    for mode in protocol["modes"]:
        write(root / "sources/grammars" / (mode + ".gbnf"), (ROOT / "grammars" / (mode + ".gbnf")).read_bytes())


def build(root: Path, selected_archive: Path, protocol: dict[str, Any], commit: str, protocol_hash: str, *, incorrect: bool = False, stop_after: int = 128) -> dict[str, Any]:
    """Retain a disclosed synthetic complete/incorrect/stopped finite packet."""
    require(not root.exists(), "synthetic packet output must be fresh")
    root.mkdir(parents=True)
    write(root / "protocol.json", (ROOT / "protocol.json").read_bytes())
    declaration = {"profile": protocol["profile"], "protocolCommit": commit, "protocolSHA256": protocol_hash, "planned": 128, "models": protocol["models"], "runtime": protocol["runtime"], "cache": protocol["cache"], "effectsExecuted": 0, "providerCalls": 0, "providerDollars": 0, "declaredAt": now(), "mode": "synthetic-control"}
    write(root / "declaration.json", declaration)
    sources(root, protocol)
    custody(root, selected_archive, protocol)
    simulated_reuse(root, protocol)
    for index, (ident, cell, case) in enumerate(population(protocol)):
        if index >= stop_after:
            break
        retain_call(root, ident, cell, case, protocol, incorrect)
    terminal = {"status": "complete" if stop_after == 128 else "error", "finishedAt": now(), "elapsed_ns": 1000000000, "process_cpu_ns": 1000000000, "process_maxrss_kib": 16384, "syntheticFixture": True}
    return finish(root, protocol, commit, protocol_hash, terminal)


def retain_call(root: Path, ident: str, cell: dict[str, Any], case: dict[str, Any], protocol: dict[str, Any], incorrect: bool) -> None:
    """Simulate one selected request and response with openly artificial use."""
    start = {"id": ident, "request": request(protocol, cell, case), "startedAt": now(), "promptTokensPreflight": 10}
    write(root / "calls" / (ident + "-started.json"), start)
    answer = {"tool": "none", "arguments": {"key": None, "value": None}, "abstain": True} if incorrect else case["target"]
    response = {"choices": [{"text": json.dumps(answer, separators=(",", ":")), "finish_reason": "stop"}], "usage": {"prompt_tokens": 10, "completion_tokens": 12, "total_tokens": 22}, "syntheticFixture": True}
    write(root / "calls" / (ident + "-returned.json"), dict(start, finishedAt=now(), response=response, resources={"elapsed_ns": 100, "process_cpu_ns": 100, "process_maxrss_kib": 16384}))
