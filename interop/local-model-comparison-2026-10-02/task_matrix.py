"""Bounded actual CPU microtasks and framework-free selected-byte reader."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import resource
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

PROTOCOL_SHA256 = "fb11ab63a4e26acac255a176b0af89931bd8424aa246a1b291e9c35991c85a00"
PROTOCOL_COMMIT = "6d6b205cc1c544968573381b72fbbe33c9ec4b3e"  # resolved to the full hash before execution
PROTOCOL_PATH = "interop/local-model-comparison-2026-10-02/protocol.json"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    return json.loads(
        raw,
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")),
    )


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(value if isinstance(value, bytes) else encode(value))
        stream.flush()
        os.fsync(stream.fileno())


def selected(root, name):
    path = root / name
    if (
        not path.is_file()
        or path.is_symlink()
        or not path.resolve().is_relative_to(root.resolve())
    ):
        raise ValueError("selected artifact must be a regular retained local file")
    return path.read_bytes()


def now():
    return datetime.now(UTC).isoformat()


def timestamp(value):
    result = datetime.fromisoformat(value)
    if result.utcoffset() is None:
        raise ValueError("timestamp requires timezone")
    return result


def protocol(raw):
    if digest(raw) != PROTOCOL_SHA256:
        raise ValueError("protocol differs from preregistration")
    return strict_json(raw)


def configurations(p):
    return [
        dict(**cfg, model=model["id"])
        for model in p["models"]
        for cfg in p["configurations"]
    ]


def population(p):
    configs = {(cfg["model"], cfg["id"]): cfg for cfg in configurations(p)}
    cases = {case["id"]: case for case in p["cases"]}
    result = []
    for ident in p["order"]["attemptIds"]:
        model, cfg, case = ident.split("--")
        result.append((ident, configs[model, cfg], cases[case]))
    return result


def request(p, cfg, case):
    prompt = f"<|im_start|>system\n{p['system']}<|im_end|>\n<|im_start|>user\n{case['input']}<|im_end|>\n<|im_start|>assistant\n"
    return dict(prompt=prompt, max_tokens=cfg["max_tokens"], **p["generation"])


def exact(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(exact(left[k], right[k]) for k in right)
    if isinstance(left, list):
        return len(left) == len(right) and all(exact(a, b) for a, b in zip(left, right))
    return left == right


def score(text, target):
    try:
        parsed = strict_json(text)
    except (ValueError, TypeError):
        return {"formatValid": False, "correct": False}
    return {"formatValid": isinstance(parsed, dict), "correct": exact(parsed, target)}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def preparation(root, p):
    """Reconstruct retained preparation receipts; not an independent transfer witness."""

    def source(name):
        return strict_json(selected(root, "sources/provenance/" + name))

    lock_raw = selected(root, "sources/provenance/dependency-lock.json")
    require(
        digest(lock_raw) == p["preparation"]["dependencySelectionSHA256"],
        "preparation dependency selection differs",
    )
    lock = strict_json(lock_raw)
    dependencies = [
        {key: entry[key] for key in ["path", "url", "bytes", "sha256"]}
        | {"category": "dependencies"}
        for entry in lock["dependencies"]
    ]
    items = p["payloads"] + dependencies
    totals = {
        category: sum(item["bytes"] for item in items if item["category"] == category)
        for category in p["preparation"]["categoryLimitBytes"]
    }
    require(
        len({item["path"] for item in items}) == len(items),
        "duplicate preparation selection",
    )
    require(
        sum(totals.values()) <= p["preparation"]["totalLimitBytes"]
        and all(totals[c] <= p["preparation"]["categoryLimitBytes"][c] for c in totals),
        "preparation selected budget overflow",
    )
    downloads = source("downloads.json")
    require(
        exact(downloads.get("files"), items)
        and exact(downloads.get("totalRetainedDownloadBytes"), sum(totals.values())),
        "preparation downloads differ from selected payloads",
    )
    declaration = source("download-declaration.json")
    selected_fields = {
        "profile": p["profile"],
        "dependencySelectionSHA256": p["preparation"]["dependencySelectionSHA256"],
        "items": items,
        "expectedPayloadBytesByCategory": totals,
        "expectedTotalPayloadBytes": sum(totals.values()),
        "totalLimitBytes": p["preparation"]["totalLimitBytes"],
        "categoryLimitBytes": p["preparation"]["categoryLimitBytes"],
        "downloadMonitoredSeconds": p["budgets"]["preparation_seconds"],
        "networkOperationTimeoutSeconds": p["budgets"]["network_operation_seconds"],
        "providerCalls": 0,
        "providerDollars": 0,
    }
    require(exact(declaration, selected_fields), "preparation declaration differs")
    account = source("download-accounting.json")
    require(
        account.get("status") == "verified" and account.get("error") is None,
        "preparation did not complete",
    )
    for key, value in {
        "actualResponseBodyBytes": sum(totals.values()),
        "actualResponseBodyBytesByCategory": totals,
        "retainedPayloadBytes": sum(totals.values()),
        "totalLimitBytes": p["preparation"]["totalLimitBytes"],
        "categoryLimitBytes": p["preparation"]["categoryLimitBytes"],
    }.items():
        require(
            exact(account.get(key), value),
            "preparation accounting differs or exceeds budget",
        )
    expected_files = [
        {
            "selected": item,
            "status": "verified",
            "retainedBytes": item["bytes"],
            "retainedSHA256": item["sha256"],
        }
        for item in items
    ]
    require(
        exact(account.get("files"), expected_files),
        "preparation retained payload selection differs",
    )
    elapsed = account.get("elapsedSeconds")
    require(
        type(elapsed) in {int, float}
        and 0 <= elapsed <= p["budgets"]["preparation_seconds"],
        "preparation elapsed budget differs",
    )
    prov = strict_json(selected(root, "sources/model-provenance.json"))
    for name, sha in prov["sources"].items():
        require(
            digest(selected(root, "sources/provenance/" + name)) == sha,
            "model provenance source binding differs",
        )
    require(
        prov["selectedRuntime"]["version"] == p["runtime"]["llama_cpp_python"]
        and prov["selectedRuntime"]["sourceSHA256"] == p["payloads"][1]["sha256"],
        "model provenance runtime selection differs",
    )
    for item in p["payloads"]:
        if item["category"] == "metadata":
            require(
                digest(selected(root, "sources/provenance/" + item["path"]))
                == item["sha256"],
                "model provenance primary metadata selection differs",
            )
    return {
        "selectedPayloadBytes": sum(totals.values()),
        "selectedPayloadBytesByCategory": totals,
        "elapsedSeconds": elapsed,
        "complete": True,
        "scope": "retained transfer/source selection receipts reconstructed; weights/source wheels omitted from native packet and retained in full preparation archive; not an independent transfer or inference witness",
    }


def verify(root, pins):
    if set(pins) != {"manifest", "protocol", "declaration", "terminal"}:
        raise ValueError(
            "reader requires separately selected manifest/protocol/declaration/terminal"
        )
    values = {}
    for kind, pin in pins.items():
        if set(pin) != {"path", "sha256"}:
            raise ValueError("invalid artifact pin")
        raw = selected(root, pin["path"])
        if digest(raw) != pin["sha256"]:
            raise ValueError("selected artifact changed")
        values[kind] = strict_json(raw)
    p = protocol(selected(root, pins["protocol"]["path"]))
    manifest = values["manifest"]
    for name, expected in manifest.items():
        if digest(selected(root, name)) != expected:
            raise ValueError("original retained bytes changed")
    if any(path.is_symlink() for path in root.rglob("*")):
        raise ValueError("packet contains a symlink")
    actual = {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()}
    allowed_derived = {"manifest.json", "consumer-pins.json", "report.json"}
    if actual - allowed_derived != set(manifest):
        raise ValueError("retained original population changed")
    required = {
        "protocol.json",
        "declaration.json",
        "terminal.json",
        "sources/task_matrix.py",
        "sources/protocol-preregistration.json",
        "sources/model-provenance.json",
        "sources/llama-system-info.txt",
        "sources/llama-cpp-python/METADATA.txt",
        "sources/llama-cpp-python/LICENSE.md",
        "sources/provenance/original-card.txt",
        "sources/provenance/quant-card.txt",
        "sources/provenance/build-gcc.log",
        "sources/provenance/downloads.json",
        "sources/provenance/candidate-original-README.txt",
        "sources/provenance/candidate-quant-README.txt",
        "sources/provenance/download-accounting.json",
        "sources/provenance/dependency-lock.json",
    }
    d, terminal = values["declaration"], values["terminal"]
    if terminal.get("status") != "complete" and not any(
        n.startswith("calls/") for n in manifest
    ):
        required = {
            "protocol.json",
            "declaration.json",
            "terminal.json",
            "sources/task_matrix.py",
            "sources/protocol-preregistration.json",
        }
    if not required <= set(manifest):
        raise ValueError("required source/runtime/license/model provenance absent")
    prereg = strict_json(selected(root, "sources/protocol-preregistration.json"))
    if (
        d.get("protocolSha256") != PROTOCOL_SHA256
        or d.get("protocolCommit") != prereg.get("commit")
        or d["protocolCommit"] != PROTOCOL_COMMIT
        or prereg.get("sha256") != PROTOCOL_SHA256
        or any(
            not exact(d.get("runtime", {}).get(k), v) for k, v in p["runtime"].items()
        )
        or not exact(d.get("planned"), 96)
        or not exact(d.get("models"), p["models"])
        or not exact(d.get("cache"), p["cache"])
        or d.get("runnerSha256") != manifest["sources/task_matrix.py"]
    ):
        raise ValueError("declaration differs from selected source/protocol/runtime")
    if not timestamp(d["declaredAt"]) <= timestamp(terminal["finishedAt"]):
        raise ValueError("run timeline differs")
    if (
        terminal.get("status") not in {"complete", "error"}
        or type(terminal.get("elapsed_ns")) is not int
        or terminal["elapsed_ns"] < 0
    ):
        raise ValueError("invalid terminal state")
    prep = (
        preparation(root, p)
        if any(n.startswith("calls/") for n in manifest)
        else {
            "complete": False,
            "scope": "no native calls; preparation provenance not established",
        }
    )
    attempts, totals, expected_calls = [], {"prompt": 0, "completion": 0}, set()
    last_start = timestamp(d["declaredAt"])
    previous_finished = last_start
    measured_call_ns = 0
    previous_peak_rss = 0
    for ident, cfg, case in population(p):
        start_name, return_name, error_name = [
            f"calls/{ident}-{suffix}.json"
            for suffix in ["started", "returned", "error"]
        ]
        row = {
            "id": ident,
            "configuration": cfg["id"],
            "model": cfg["model"],
            "family": case["family"],
            "outcome": "unknown-start",
            "correct": None,
            "formatValid": None,
        }
        if start_name in manifest:
            expected_calls.add(start_name)
            start = strict_json(selected(root, start_name))
            if (
                set(start) != {"id", "request", "startedAt", "promptTokensPreflight"}
                or start["id"] != ident
                or not exact(start["request"], request(p, cfg, case))
                or type(start["promptTokensPreflight"]) is not int
                or not 0
                < start["promptTokensPreflight"]
                <= p["runtime"]["n_ctx"] - cfg["max_tokens"]
            ):
                raise ValueError(
                    "start outside declared population/prompt/configuration"
                )
            if (
                not max(last_start, previous_finished)
                <= timestamp(start["startedAt"])
                <= timestamp(terminal["finishedAt"])
            ):
                raise ValueError("attempt order/timeline differs")
            last_start = timestamp(start["startedAt"])
            row["outcome"] = "incomplete"
            if return_name in manifest and error_name in manifest:
                raise ValueError("attempt has both response and error")
            if error_name in manifest:
                expected_calls.add(error_name)
                error = strict_json(selected(root, error_name))
                if (
                    any(not exact(error.get(k), v) for k, v in start.items())
                    or not timestamp(start["startedAt"])
                    <= timestamp(error["finishedAt"])
                    <= timestamp(terminal["finishedAt"])
                    or not isinstance(error.get("error"), dict)
                ):
                    raise ValueError("error differs from retained start")
                previous_finished = timestamp(error["finishedAt"])
                row.update(outcome="error", error=error["error"])
            if return_name in manifest:
                expected_calls.add(return_name)
                returned = strict_json(selected(root, return_name))
                if any(
                    not exact(returned.get(k), v) for k, v in start.items()
                ) or not timestamp(start["startedAt"]) <= timestamp(
                    returned["finishedAt"]
                ) <= timestamp(terminal["finishedAt"]):
                    raise ValueError("response differs from retained start")
                response = returned["response"]
                usage = response["usage"]
                if (
                    any(
                        type(usage.get(k)) is not int or usage[k] < 0
                        for k in ["prompt_tokens", "completion_tokens", "total_tokens"]
                    )
                    or usage["total_tokens"]
                    != usage["prompt_tokens"] + usage["completion_tokens"]
                    or usage["prompt_tokens"] != start["promptTokensPreflight"]
                    or usage["completion_tokens"] > cfg["max_tokens"]
                ):
                    raise ValueError("native token accounting differs")
                resources = returned["measurement"]
                if set(resources) != {
                    "elapsed_ns",
                    "process_cpu_ns",
                    "process_maxrss_kib",
                } or any(type(v) is not int or v < 0 for v in resources.values()):
                    raise ValueError("invalid native resource accounting")
                if resources["process_maxrss_kib"] < previous_peak_rss:
                    raise ValueError("process lifetime peak RSS decreased")
                previous_peak_rss = resources["process_maxrss_kib"]
                text = response["choices"][0]["text"]
                if not isinstance(text, str):
                    raise ValueError("native output must be text")
                row.update(
                    outcome="scored",
                    output=text,
                    tokens=usage,
                    resources=resources,
                    **score(text, case["target"]),
                )
                previous_finished = timestamp(returned["finishedAt"])
                measured_call_ns += resources["elapsed_ns"]
                totals["prompt"] += usage["prompt_tokens"]
                totals["completion"] += usage["completion_tokens"]
        attempts.append(row)
    if {name for name in manifest if name.startswith("calls/")} != expected_calls:
        raise ValueError("extra/orphan attempt record")
    if measured_call_ns > terminal["elapsed_ns"]:
        raise ValueError("summed serial call time exceeds total run time")
    complete = terminal["status"] == "complete" and all(
        x["outcome"] == "scored" for x in attempts
    )
    budget_ok = (
        totals["prompt"] <= p["budgets"]["maximum_prompt_tokens"]
        and totals["completion"] <= p["budgets"]["maximum_completion_tokens"]
        and terminal["elapsed_ns"] <= p["budgets"]["run_seconds"] * 10**9
        and all(
            r.get("resources", {}).get("process_maxrss_kib", 0)
            <= p["budgets"]["maximum_process_lifetime_peak_rss_kib"]
            for r in attempts
        )
    )
    groups = []
    for cfg in configurations(p):
        for family in dict.fromkeys(c["family"] for c in p["cases"]):
            rows = [
                r
                for r in attempts
                if r["configuration"] == cfg["id"]
                and r["model"] == cfg["model"]
                and r["family"] == family
            ]
            groups.append(
                {
                    "configuration": cfg["id"],
                    "model": cfg["model"],
                    "family": family,
                    "planned": len(rows),
                    "scored": sum(r["outcome"] == "scored" for r in rows),
                    "formatValid": sum(r["formatValid"] is True for r in rows),
                    "correct": sum(r["correct"] is True for r in rows),
                    "promptTokens": sum(
                        r.get("tokens", {}).get("prompt_tokens", 0) for r in rows
                    ),
                    "completionTokens": sum(
                        r.get("tokens", {}).get("completion_tokens", 0) for r in rows
                    ),
                    "callElapsedNs": sum(
                        r.get("resources", {}).get("elapsed_ns", 0) for r in rows
                    ),
                    "processCpuNs": sum(
                        r.get("resources", {}).get("process_cpu_ns", 0) for r in rows
                    ),
                    "processLifetimePeakRssKiB": max(
                        (
                            r.get("resources", {}).get("process_maxrss_kib", 0)
                            for r in rows
                        ),
                        default=0,
                    ),
                    "resourceScope": "returned calls only; CPU is whole-process delta, RSS is lifetime peak, not task allocation",
                }
            )
    return {
        "profile": p["profile"],
        "publicationDecision": (
            "publish-scoped-report"
            if complete and budget_ok
            else "hold-incomplete-or-over-budget"
        ),
        "evidence": {"complete": complete, "withinRunBudget": budget_ok},
        "population": {
            key: sum(r["outcome"] == key for r in attempts)
            for key in ["scored", "error", "incomplete", "unknown-start"]
        }
        | {
            "planned": 96,
            "started": sum(r["outcome"] != "unknown-start" for r in attempts),
        },
        "quality": groups,
        "nativeTokens": totals,
        "preparation": prep,
        "elapsed_ns": terminal["elapsed_ns"],
        "attempts": attempts,
        "interpretation": p["interpretation"],
        "custody": "Probity-operated; independent custody not established",
        "effects": "not executed",
        "tokenScope": "all returned native responses; errors have unknown token use",
    }


def run(root, weights, provenance, commit):
    raw = Path(__file__).with_name("protocol.json").read_bytes()
    p = protocol(raw)
    full_commit = subprocess.check_output(
        ["git", "rev-parse", f"{commit}^{{commit}}"], text=True
    ).strip()
    frozen = subprocess.check_output(["git", "show", f"{full_commit}:{PROTOCOL_PATH}"])
    if frozen != raw:
        raise ValueError("selected preregistration commit differs from protocol bytes")
    root.mkdir(parents=True, exist_ok=False)
    write(root / "protocol.json", raw)
    write(root / "sources/task_matrix.py", Path(__file__).read_bytes())
    write(
        root / "sources/protocol-preregistration.json",
        {"commit": full_commit, "sha256": digest(frozen)},
    )
    declaration = {
        "declaredAt": now(),
        "protocolCommit": full_commit,
        "protocolSha256": PROTOCOL_SHA256,
        "runnerSha256": digest(Path(__file__).read_bytes()),
        "planned": 96,
        "models": p["models"],
        "cache": p["cache"],
        "runtime": dict(
            **p["runtime"], python=sys.version, platform=platform.platform()
        ),
    }
    write(root / "declaration.json", declaration)
    began = time.perf_counter_ns()
    terminal = {"status": "error"}
    try:
        import llama_cpp

        if importlib.metadata.version("llama-cpp-python") != "0.3.16":
            raise ValueError("runtime differs from selected0.3.16")
        for model in p["models"]:
            path = weights / (model["id"] + ".gguf")
            h = hashlib.sha256()
            if path.is_symlink() or path.stat().st_size != model["bytes"]:
                raise ValueError("weights differ from pinned selection")
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    h.update(chunk)
            if h.hexdigest() != model["sha256"]:
                raise ValueError("weights differ from pinned selection")
        prov = provenance.read_bytes()
        write(root / "sources/model-provenance.json", prov)
        for name, sha in strict_json(prov)["sources"].items():
            body = selected(provenance.parent, name)
            if digest(body) != sha:
                raise ValueError("primary model/build provenance changed")
            write(root / "sources/provenance" / name, body)
        pkg = Path(llama_cpp.__file__).parent
        for path in sorted(pkg.rglob("*")):
            if path.is_file() and path.suffix in {".py", ".so", ".dylib", ".dll"}:
                write(root / "sources/llama" / path.relative_to(pkg), path.read_bytes())
        dist = importlib.metadata.distribution("llama-cpp-python")
        write(
            root / "sources/llama-cpp-python/METADATA.txt",
            dist.read_text("METADATA").encode(),
        )
        for item in dist.files or []:
            if "LICENSE" in item.name.upper():
                write(
                    root / "sources/llama-cpp-python" / item.name,
                    Path(dist.locate_file(item)).read_bytes(),
                )
        write(
            root / "sources/llama-system-info.txt",
            llama_cpp.llama_print_system_info() + b"\n",
        )
        engines = {}
        for model in p["models"]:
            engines[model["id"]] = llama_cpp.Llama(
                model_path=str(weights / (model["id"] + ".gguf")),
                **{k: v for k, v in p["runtime"].items() if k != "llama_cpp_python"},
                seed=42,
                verbose=False,
            )
            engines[model["id"]].set_cache(None)
        prompt_budget = completion_budget = 0
        for ident, cfg, case in population(p):
            engine = engines[cfg["model"]]
            engine.reset()
            req = request(p, cfg, case)
            count = len(
                engine.tokenize(req["prompt"].encode(), add_bos=True, special=True)
            )
            if (
                time.perf_counter_ns() - began >= p["budgets"]["run_seconds"] * 10**9
                or count + cfg["max_tokens"] > p["runtime"]["n_ctx"]
                or prompt_budget + count > p["budgets"]["maximum_prompt_tokens"]
                or completion_budget + cfg["max_tokens"]
                > p["budgets"]["maximum_completion_tokens"]
            ):
                raise ValueError("preflight resource boundary exceeded")
            prompt_budget += count
            completion_budget += cfg["max_tokens"]
            call = {
                "id": ident,
                "request": req,
                "startedAt": now(),
                "promptTokensPreflight": count,
            }
            write(root / f"calls/{ident}-started.json", call)
            wall, cpu = time.perf_counter_ns(), time.process_time_ns()
            try:
                response = engine.create_completion(**req)
            except Exception as exc:
                write(
                    root / f"calls/{ident}-error.json",
                    dict(
                        **call,
                        finishedAt=now(),
                        error={"type": type(exc).__name__, "message": str(exc)},
                    ),
                )
                raise
            write(
                root / f"calls/{ident}-returned.json",
                dict(
                    **call,
                    finishedAt=now(),
                    response=response,
                    measurement={
                        "elapsed_ns": time.perf_counter_ns() - wall,
                        "process_cpu_ns": time.process_time_ns() - cpu,
                        "process_maxrss_kib": resource.getrusage(
                            resource.RUSAGE_SELF
                        ).ru_maxrss,
                    },
                ),
            )
        terminal["status"] = "complete"
    except Exception as exc:  # noqa: BLE001 - retain any native setup/inference failure
        terminal["error"] = {"type": type(exc).__name__, "message": str(exc)}
    terminal.update(finishedAt=now(), elapsed_ns=time.perf_counter_ns() - began)
    write(root / "terminal.json", terminal)
    manifest = {
        str(path.relative_to(root)): digest(path.read_bytes())
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }
    write(root / "manifest.json", manifest)
    pins = {
        kind: {"path": name, "sha256": digest((root / name).read_bytes())}
        for kind, name in {
            "manifest": "manifest.json",
            "protocol": "protocol.json",
            "declaration": "declaration.json",
            "terminal": "terminal.json",
        }.items()
    }
    write(root / "consumer-pins.json", pins)
    report = verify(root, pins)
    write(root / "report.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--weights", type=Path)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--protocol-commit", default=PROTOCOL_COMMIT)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--pins-file", type=Path)
    args = parser.parse_args()
    if args.verify:
        if args.pins_file is None:
            parser.error("reader requires independently selected --pins-file")
        result = verify(args.output, strict_json(args.pins_file.read_bytes()))
    else:
        if args.weights is None or args.provenance is None:
            parser.error("run requires --weights and --provenance")
        result = run(args.output, args.weights, args.provenance, args.protocol_commit)
    print(json.dumps(result, indent=2, allow_nan=False))
    if result["publicationDecision"] != "publish-scoped-report":
        sys.exit(1)
