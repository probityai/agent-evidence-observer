"""Execute the prospectively selected native population and retain originals.

This module dispatches model inference only. Tool-shaped answers never execute
real effects. All native source, dependencies, libraries, weights and inputs
are selected before a call. The external wall guard remains necessary.
"""

from __future__ import annotations

import os
from pathlib import Path
import resource
import subprocess
import sys
import sysconfig
import time
import zipfile
from typing import Any

try:
    from .evidence_io import digest, encode, now, read_regular, require, strict_json, write
    from .execution_contract import population, request
    from .reader import verify
    from .reusable_runtime import file_identity
except ImportError:
    from evidence_io import digest, encode, now, read_regular, require, strict_json, write
    from execution_contract import population, request
    from reader import verify
    from reusable_runtime import file_identity

ROOT = Path(__file__).parent


def selected_registration(repository: Path, commit: str, protocol: dict[str, Any], protocol_hash: str) -> None:
    """Require the protocol and exact source closure at a prior Git object."""
    require(len(commit) == 40 and all(character in "0123456789abcdef" for character in commit), "inference requires published prospective registration")
    relative = ROOT.relative_to(repository)
    selections = dict(protocol["sourceClosure"], **{"protocol.json": protocol_hash})
    selections[protocol["compiler"]["path"]] = protocol["compiler"]["sha256"]
    selections[protocol["compiler"]["licensePath"]] = protocol["compiler"]["licenseSHA256"]
    for mode, selection in protocol["schemas"].items():
        selections["grammars/" + mode + ".gbnf"] = selection["grammarSHA256"]
        require(digest(encode(selection["schema"])) == selection["schemaSHA256"], "selected generic schema changed before inference")
    for name, selected in selections.items():
        command = ["git", "show", commit + ":" + (relative / name).as_posix()]
        result = subprocess.run(command, check=True, capture_output=True, timeout=10)
        require(digest(result.stdout) == selected and digest((ROOT / name).read_bytes()) == selected, "prospective registration source differs")


def verify_installation(prepared: Path, protocol: dict[str, Any]) -> dict[str, Any]:
    """Bind the actual interpreter and all installed members before model import."""
    installation = strict_json(read_regular(prepared / "installation.json"))
    require(installation["status"] == "passed" and Path(installation["interpreter"]).resolve() == Path(sys.executable).resolve(), "native process differs from selected installation")
    site = Path(installation["sitePackages"])
    require(site.resolve() == Path(sysconfig.get_path("purelib")).resolve(), "native import site differs from selected installation")
    verify_runtime_site(prepared, protocol, installation, site)
    require(not any(os.environ.get(name) for name in ["LLAMA_CPP_LIB_PATH", "LD_PRELOAD", "LD_LIBRARY_PATH"]), "native library override differs from selected runtime")
    return installation


def verify_runtime_site(prepared: Path, protocol: dict[str, Any], installation: dict[str, Any], site: Path) -> None:
    """Check the entire site and selected importable bytes before child startup.

    The host-selected interpreter/venv configuration and ancestor filesystem
    are trusted. Unknown startup hooks are refused even with a resigned local
    installation receipt. Selected wheel startup code remains selected code.
    """
    actual = installed_population(site, protocol["budgets"]["retained_disk_bytes"])
    require(actual == installation["installedFiles"], "installed runtime population changed before inference")
    for row in protocol["runtimeReuse"]["selectedFiles"]:
        require(file_identity(prepared / "extraction" / row["path"]) == {"bytes": row["bytes"], "sha256": row["sha256"]}, "prepared reuse identity changed")
    for row in protocol["runtimeReuse"]["selectedFiles"]:
        if row["category"] in {"runtime", "runtime-metadata"}:
            require(file_identity(site / Path(row["path"]).relative_to("runtime")) == {"bytes": row["bytes"], "sha256": row["sha256"]}, "installed native differs from frozen selection")
    verify_cache_population(actual)
    selected = verify_installed_wheels(site, prepared, protocol)
    selected.update(str(Path(row["path"]).relative_to("runtime")) for row in protocol["runtimeReuse"]["selectedFiles"] if row["category"] in {"runtime", "runtime-metadata"})
    verify_importable_population(actual, selected)
    verify_startup_hooks(actual, prepared, protocol)


def verify_cache_population(actual: dict[str, dict[str, Any]]) -> None:
    """Refuse executable caches beyond explicitly trusted installer/pip code.

    Python -B only prevents writes. Existing timestamp/hash-valid compiled
    modules must therefore be absent before selected source imports begin.
    """
    require(not any(name.endswith((".pyc", ".pyo")) and not name.startswith("pip/") for name in actual), "selected runtime/dependency caches must be absent")


def verify_startup_hooks(actual: dict[str, dict[str, Any]], prepared: Path, protocol: dict[str, Any]) -> None:
    """Require every startup hook to be an exact selected dependency member."""
    selected = {}
    for wheel in protocol["runtimeReuse"]["wheels"]:
        with zipfile.ZipFile(prepared / "extraction" / wheel["path"]) as archive:
            for member in archive.infolist():
                selected[member.filename] = {"bytes": member.file_size, "sha256": digest(archive.read(member))} if startup_hook(member.filename) else None
    for name, identity in actual.items():
        require(not startup_hook(name) or identity == selected.get(name), "unselected installed startup hook refused")


def startup_hook(name: str) -> bool:
    """Select all site startup hooks, including alternate bytecode spellings."""
    return name.endswith(".pth") or Path(name).parts[0] in {"sitecustomize", "usercustomize"} or Path(name).name.startswith(("sitecustomize.", "usercustomize."))


def verify_importable_population(actual: dict[str, dict[str, Any]], selected: set[str]) -> None:
    """Refuse aliases and extension neighbors absent from selected originals."""
    metadata = {Path(name).parts[0] for name in selected if Path(name).parts[0].endswith(".dist-info")}
    require(all(allowed_installed_name(name, selected, metadata) for name in actual), "unselected installed importable member refused")


def allowed_installed_name(name: str, selected: set[str], metadata: set[str]) -> bool:
    """Allow selected members, trusted pip seed and inert installer metadata."""
    root = Path(name).parts[0]
    if name in selected or root == "pip" or (root.startswith("pip-") and root.endswith(".dist-info")):
        return True
    return root in metadata and Path(name).name in {"INSTALLER", "REQUESTED", "RECORD", "direct_url.json"} and len(Path(name).parts) == 2


def installed_population(site: Path, maximum_bytes: int) -> dict[str, dict[str, Any]]:
    """Fail closed on linked/special descendants before importable site use.

    Host ancestor directories are trusted against concurrent replacement.
    Every final file is read through the no-follow selected identity reader.
    Traversal is finite and no directory link or injected hook is skipped.
    """
    require(site.is_dir() and not site.is_symlink(), "installed site must be a selected directory")
    pending, count, total = [site], 0, 0
    result = {}
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            count += 1
            require(count <= 100000 and not path.is_symlink(), "installed population is linked or exceeds entry limit")
            if path.is_dir():
                pending.append(path)
                continue
            selected = file_identity(path)
            total += selected["bytes"]
            require(total <= maximum_bytes, "installed population exceeds disk budget")
            result[path.relative_to(site).as_posix()] = selected
    return result


def verify_installed_wheels(site: Path, prepared: Path, protocol: dict[str, Any]) -> set[str]:
    """Bind importable dependency members to the selected original locked wheels.

    Installer-created RECORD and relocated executable scripts are excluded.
    Every importable package/module/native library and original metadata member
    is compared to its already verified wheel member, before native import.
    """
    selected = set()
    for wheel in protocol["runtimeReuse"]["wheels"]:
        with zipfile.ZipFile(prepared / "extraction" / wheel["path"]) as archive:
            for member in archive.infolist():
                if member.is_dir() or ".data/" in member.filename:
                    continue
                selected.add(member.filename)
                if member.filename.endswith(".dist-info/RECORD"):
                    continue
                raw = archive.read(member)
                require(file_identity(site / member.filename) == {"bytes": len(raw), "sha256": digest(raw)}, "installed dependency differs from selected wheel")
    return selected


def retain_sources(root: Path, prepared: Path, protocol: dict[str, Any], installation: dict[str, Any]) -> None:
    """Copy selected source and native custody receipts without rewriting them."""
    names = sorted(set(protocol["sourceClosure"]) | {"task_matrix.py", protocol["compiler"]["path"], protocol["compiler"]["licensePath"]})
    for name in names:
        write(root / "sources" / name, (ROOT / name).read_bytes())
    for mode in protocol["modes"]:
        write(root / "sources/grammars" / (mode + ".gbnf"), (ROOT / "grammars" / (mode + ".gbnf")).read_bytes())
    for name in ["archive-accounting.json", "reuse-projection.json", "preparation-terminal.json", "installation.json"]:
        write(root / "sources/reuse" / name, (prepared / name).read_bytes())
    retain_custody(root, prepared, protocol)


def retain_custody(root: Path, prepared: Path, protocol: dict[str, Any]) -> None:
    """Preserve selected prior native and receipt bytes before any inference."""
    for row in protocol["runtimeReuse"]["selectedFiles"]:
        destination = custody_destination(row)
        if destination is not None:
            write(root / destination, (prepared / "extraction" / row["path"]).read_bytes())


def custody_destination(row: dict[str, Any]) -> Path | None:
    """Map selected receipt/runtime originals into the finite native packet."""
    if row["category"] == "receipt":
        return Path("sources/reuse") / row["path"]
    if row["category"] == "runtime":
        return Path("sources/llama") / Path(row["path"]).relative_to("runtime/llama_cpp")
    if row["category"] == "runtime-metadata":
        return Path("sources/llama-cpp-python") / Path(row["archivePath"]).name
    return None


def totals(start_wall: int, start_cpu: int) -> dict[str, int]:
    """Observe whole-process CPU, monotonic elapsed and Linux lifetime peak RSS."""
    return {"elapsed_ns": time.monotonic_ns() - start_wall, "process_cpu_ns": time.process_time_ns() - start_cpu, "process_maxrss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}


def resource_guard(value: dict[str, int], protocol: dict[str, Any], prompt: int, completion: int) -> None:
    """Stop at observed wall, CPU, RSS or token budgets without retrying."""
    budgets = protocol["budgets"]
    require(value["elapsed_ns"] < budgets["run_seconds"] * 1000000000, "native wall budget exhausted")
    require(value["process_cpu_ns"] < budgets["maximum_process_cpu_seconds"] * 1000000000, "native CPU budget exhausted")
    require(value["process_maxrss_kib"] <= budgets["maximum_process_lifetime_peak_rss_kib"], "native RSS budget exhausted")
    require(prompt <= budgets["maximum_prompt_tokens"] and completion <= budgets["maximum_completion_tokens"], "native token budget exhausted")


def engines(protocol: dict[str, Any], prepared: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load both selected models and two generic grammars without warmup calls."""
    from llama_cpp import Llama, LlamaGrammar
    runtime = {key: value for key, value in protocol["runtime"].items() if key != "llama_cpp_python"}
    models = {model["id"]: Llama(model_path=str(prepared / "extraction" / (model["id"] + ".gguf")), verbose=False, **runtime) for model in protocol["models"]}
    grammars = {mode: LlamaGrammar.from_string((ROOT / "grammars" / (mode + ".gbnf")).read_text(), verbose=False) for mode in protocol["modes"]}
    return models, grammars


def one_call(root: Path, ident: str, cell: dict[str, Any], case: dict[str, Any], protocol: dict[str, Any], model: Any, grammar: Any) -> dict[str, Any]:
    """Retain start before native execution, then exact response or terminal error."""
    selected = request(protocol, cell, case)
    model.reset()
    tokens = len(model.tokenize(selected["prompt"].encode(), add_bos=True, special=True))
    require(0 < tokens <= protocol["runtime"]["n_ctx"] - cell["max_tokens"], "native context preflight exceeds selected runtime")
    started = {"id": ident, "request": selected, "startedAt": now(), "promptTokensPreflight": tokens}
    write(root / "calls" / (ident + "-started.json"), started)
    start_wall, start_cpu = time.monotonic_ns(), time.process_time_ns()
    try:
        parameters = {key: value for key, value in selected.items() if key != "grammarSelection"}
        response = model.create_completion(**parameters, grammar=grammar)
        returned = dict(started, finishedAt=now(), response=response, resources=totals(start_wall, start_cpu))
        write(root / "calls" / (ident + "-returned.json"), returned)
        return response["usage"]
    except Exception as error:
        write(root / "calls" / (ident + "-error.json"), dict(started, finishedAt=now(), error={"type": type(error).__name__, "message": str(error)}, resources=totals(start_wall, start_cpu)))
        raise


def run_population(root: Path, prepared: Path, protocol: dict[str, Any], start_wall: int, start_cpu: int) -> None:
    """Execute precisely the finite serial order and stop on its first failure."""
    models, grammars = engines(protocol, prepared)
    prompt, completion = 0, 0
    for ident, cell, case in population(protocol):
        resource_guard(totals(start_wall, start_cpu), protocol, prompt, completion + cell["max_tokens"])
        usage = one_call(root, ident, cell, case, protocol, models[cell["model"]], grammars[cell["mode"]])
        prompt += usage["prompt_tokens"]
        completion += usage["completion_tokens"]
        resource_guard(totals(start_wall, start_cpu), protocol, prompt, completion)


def finish(root: Path, protocol: dict[str, Any], commit: str, protocol_hash: str, terminal: dict[str, Any]) -> dict[str, Any]:
    """Retain complete original manifest and producer-selected pin receipt."""
    write(root / "terminal.json", terminal)
    manifest = {path.relative_to(root).as_posix(): digest(path.read_bytes()) for path in sorted(root.rglob("*")) if path.is_file()}
    write(root / "manifest.json", manifest)
    pins = {name: {"path": name + ".json", "sha256": digest((root / (name + ".json")).read_bytes())} for name in ["manifest", "protocol", "declaration", "terminal"]}
    write(root / "consumer-pins.json", pins)
    result = verify(root, pins, protocol, commit, protocol_hash)
    write(root / "report.json", result)
    return result


def execute(root: Path, prepared: Path, protocol: dict[str, Any], commit: str, protocol_hash: str, repository: Path, process_start_wall: int) -> dict[str, Any]:
    """Execute only a reviewed prospective source registration, retaining failures.

    Selected installation/source checks precede inference. Runtime totals begin
    before model loading and include source copying and final error observation.
    Model responses never enter an effect executor. Native CPU/RSS checks are
    observed boundaries; an external595sTERM+5sKILL wall guard is mandatory.
    """
    sys.dont_write_bytecode = True
    selected_registration(repository.resolve(), commit, protocol, protocol_hash)
    installation = verify_installation(prepared, protocol)
    require(not root.exists(), "native packet output must be fresh")
    root.mkdir(parents=True)
    start_wall, start_cpu = process_start_wall, 0
    write(root / "protocol.json", (ROOT / "protocol.json").read_bytes())
    declaration = {"profile": protocol["profile"], "protocolCommit": commit, "protocolSHA256": protocol_hash, "planned": 128, "models": protocol["models"], "runtime": protocol["runtime"], "cache": protocol["cache"], "effectsExecuted": 0, "providerCalls": 0, "providerDollars": 0, "declaredAt": now(), "mode": "actual-native"}
    write(root / "declaration.json", declaration)
    retain_sources(root, prepared, protocol, installation)
    from reader import verify_reuse_buffers
    from evidence_io import packet_buffers
    verify_reuse_buffers(packet_buffers(root), protocol)
    terminal: dict[str, Any] = {"status": "complete"}
    try:
        run_population(root, prepared, protocol, start_wall, start_cpu)
    except Exception as error:
        terminal.update(status="error", error={"type": type(error).__name__, "message": str(error)})
    terminal.update(finishedAt=now(), **totals(start_wall, start_cpu))
    write(root / "inference-terminal.json", terminal)
    return terminal
