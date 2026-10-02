"""Run a bounded CPU model through native Inspect; verify retained outputs offline."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import resource
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROFILE = "probity-inspect-local-model-v1"
MODEL_REPO = "unsloth/SmolLM2-135M-Instruct-GGUF"
MODEL_REVISION = "9e6855bc4be717fca1ef21360a1db4b29d5c559a"
MODEL_FILE = "SmolLM2-135M-Instruct-Q4_K_M.gguf"
MODEL_SHA256 = "ed5fa30c487b282ec156c29062f1222e5c20875a944ac98289dbd242e947f747"
MODEL_SIZE = 105454144
ORIGINAL_REVISION = "12fd25f77366fa6b3b4b768ec3050bf629380bac"
SYSTEM = (
    "Answer the multiple-choice question. Reply with exactly one letter: A, B, C, or D."
)
CONFIG = {
    "seed": 42,
    "temperature": 0.0,
    "max_tokens": 24,
    "n_ctx": 512,
    "n_threads": 2,
    "n_threads_batch": 2,
    "n_gpu_layers": 0,
    "top_p": 1.0,
    "top_k": 0,
    "repeat_penalty": 1.0,
}
# Small, author-written smoke tasks. Their scores are not benchmark estimates.
CASES = [
    ("add", "What is 2 + 2?\nA. 4\nB. 5\nC. 6\nD. 7", "A"),
    ("subtract", "What is 9 - 3?\nA. 3\nB. 6\nC. 8\nD. 9", "B"),
    ("multiply", "What is 3 times 3?\nA. 6\nB. 8\nC. 9\nD. 12", "C"),
    ("divide", "What is 12 divided by 4?\nA. 8\nB. 6\nC. 4\nD. 3", "D"),
    ("sequence", "What comes next: 2, 4, 6, 8?\nA. 10\nB. 11\nC. 12\nD. 16", "A"),
    ("order", "Which number is smallest?\nA. 9\nB. 2\nC. 6\nD. 7", "B"),
    (
        "logic",
        "All cats are mammals. Luna is a cat. What follows?\nA. Luna is a bird\nB. Luna is a fish\nC. Luna is a mammal\nD. Luna is a plant",
        "C",
    ),
    ("negation", "Which is NOT an even number?\nA. 2\nB. 4\nC. 6\nD. 7", "D"),
    ("time", "How many minutes are in one hour?\nA. 60\nB. 30\nC. 24\nD. 100", "A"),
    (
        "reading",
        "Maya has a red bag and a blue hat. What color is her hat?\nA. Red\nB. Blue\nC. Green\nD. Yellow",
        "B",
    ),
    (
        "comparison",
        "A box holds 5 apples. Two apples are removed. How many remain?\nA. 2\nB. 4\nC. 3\nD. 5",
        "C",
    ),
    (
        "relation",
        "Tom is taller than Ana. Ana is taller than Li. Who is shortest?\nA. Tom\nB. Ana\nC. All equal\nD. Li",
        "D",
    ),
]


def encode(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as f:
        f.write(value if isinstance(value, bytes) else encode(value))
        f.flush()
        os.fsync(f.fileno())


def score_letter(output, target):
    """Whitespace stripping only. Explanations, extra letters and prose fail."""
    return int(isinstance(output, str) and output.strip() == target)


def prompt_for(question):
    return f"<|im_start|>system\n{SYSTEM}<|im_end|>\n<|im_start|>user\n{question}<|im_end|>\n<|im_start|>assistant\n"


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
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON")),
    )


def selected_file(folder, relative):
    path = folder / relative
    if (
        path.is_symlink()
        or not path.is_file()
        or not path.resolve().is_relative_to(folder.resolve())
    ):
        raise ValueError("artifact must be a retained regular local file")
    return path.read_bytes()


def verify(folder, pins):
    """Read selected hashes, reconstruct native outputs and retain population gaps."""
    required = {"declaration", "native", "calls", "sources"}
    if set(pins) != required:
        raise ValueError("select declaration, native log, calls and source manifest")
    raws = {}
    for kind in required:
        item = pins[kind]
        if set(item) != {"path", "sha256"}:
            raise ValueError("invalid selected artifact pin")
        raws[kind] = selected_file(folder, item["path"])
        if digest(raws[kind]) != item["sha256"]:
            raise ValueError("selected artifact changed")
    declaration, native, calls, sources = (
        strict_json(raws[k]) for k in ("declaration", "native", "calls", "sources")
    )
    if (
        declaration.get("profile") != PROFILE
        or declaration.get("cases")
        != [dict(id=i, input=q, target=a) for i, q, a in CASES]
        or encode(declaration.get("config")) != encode(CONFIG)
    ):
        raise ValueError("unsupported declaration")
    if declaration.get("sourceManifestSha256") != digest(raws["sources"]):
        raise ValueError("source manifest differs from declaration")
    if (
        declaration.get("model", {}).get("sha256") != MODEL_SHA256
        or declaration.get("model", {}).get("revision") != MODEL_REVISION
    ):
        raise ValueError("unsupported model identity")
    mandatory_sources = {
        "local_model.py",
        "model-provenance.json",
        "llama-system-info.txt",
        "inspect-ai/METADATA.txt",
        "inspect-ai/LICENSE",
        "llama-cpp-python/METADATA.txt",
        "llama-cpp-python/LICENSE.md",
        "provenance/original-card.txt",
        "provenance/quant-card.txt",
        "provenance/tokenizer-config.json",
        "provenance/source-download.json",
        "provenance/build-gcc.log",
        "provenance/downloads.json",
    }
    if not mandatory_sources <= set(sources):
        raise ValueError("required primary/runtime/source/license assets absent")
    for name, expected in sources.items():
        if digest(selected_file(folder, "sources/" + name)) != expected:
            raise ValueError("retained source changed")
    for path in folder.rglob("*"):
        if path.is_symlink():
            raise ValueError("packet contains a symlink")
    actual_sources = {
        str(p.relative_to(folder / "sources"))
        for p in (folder / "sources").rglob("*")
        if p.is_file()
    }
    if actual_sources != set(sources):
        raise ValueError("retained source population changed")
    envelope = native.get("eval", {})
    metadata = {
        "probity_profile": PROFILE,
        "probity_declaration_sha256": digest(raws["declaration"]),
        "probity_source_manifest_sha256": digest(raws["sources"]),
        "model_revision": MODEL_REVISION,
        "weight_sha256": MODEL_SHA256,
    }
    expected_generation = {
        "max_connections": 1,
        "max_tokens": 24,
        "temperature": 0.0,
        "seed": 42,
    }
    if (
        type(native.get("version")) is not int
        or native["version"] != 2
        or envelope.get("metadata") != metadata
        or native.get("metadata") != metadata
    ):
        raise ValueError("native envelope lacks selected declaration binding")
    if any(
        not isinstance(envelope.get(k), str) or not envelope[k]
        for k in ["run_id", "eval_id", "task_id"]
    ):
        raise ValueError("native evaluation identity absent")
    if (
        envelope.get("task") != "probity_local_model_smoke_v1"
        or type(envelope.get("task_version")) is not int
        or envelope["task_version"] != 1
        or envelope.get("packages", {}).get("inspect_ai") != "0.3.273"
        or envelope.get("model") != "probity-local-cpu/smollm2-135m-instruct-q4km"
    ):
        raise ValueError("native task or runtime differs from declared profile")
    if (
        encode(envelope.get("model_generate_config")) != encode(expected_generation)
        or envelope.get("model_args") != {}
    ):
        raise ValueError("native model configuration differs")
    if encode(envelope.get("dataset")) != encode(
        {
            "samples": len(CASES),
            "sample_ids": [i for i, _, _ in CASES],
            "shuffled": False,
        }
    ):
        raise ValueError("native dataset population differs")
    eval_config = envelope.get("config", {})
    for key, expected in {
        "epochs": 1,
        "retry_on_error": 0,
        "max_samples": 1,
        "fail_on_error": False,
        "score_on_error": False,
        "log_samples": True,
    }.items():
        if (
            type(eval_config.get(key)) is not type(expected)
            or eval_config[key] != expected
        ):
            raise ValueError("native attempt policy differs")
    if native.get("plan", {}).get("steps") != [
        {"solver": "generate", "params": {"tool_calls": "loop"}, "params_passed": {}}
    ] or [v.get("name") for v in envelope.get("scorers", [])] != ["letter_score"]:
        raise ValueError("native solver or scorer differs")

    def timestamp(value):
        if not isinstance(value, str):
            raise ValueError("missing native timestamp")
        parsed = datetime.fromisoformat(value)
        if parsed.utcoffset() is None:
            raise ValueError("timestamp requires timezone")
        return parsed

    declared = timestamp(declaration.get("declaredAt"))
    began = timestamp(native.get("stats", {}).get("started_at"))
    finished = timestamp(native.get("stats", {}).get("completed_at"))
    if (
        not declared.replace(microsecond=0)
        <= timestamp(envelope.get("created"))
        <= finished
        or not declared.replace(microsecond=0) <= began <= finished
    ):
        raise ValueError("native timeline precedes declaration or runs backwards")
    if native.get("status") not in {"success", "error", "cancelled"}:
        raise ValueError("invalid native completion")
    samples = native.get("samples", [])
    expected_ids = {i: (q, a) for i, q, a in CASES}
    seen = set()
    by_call = {}
    for call in calls:
        key = call["id"]
        if key not in expected_ids or key in by_call:
            raise ValueError("extra or duplicate native call")
        by_call[key] = call
        call_started = timestamp(call.get("startedAt"))
        if not declared <= call_started <= finished + timedelta(seconds=1):
            raise ValueError("native call start outside declared run")
        if "response" in call and not call_started <= timestamp(
            call.get("finishedAt")
        ) <= finished + timedelta(seconds=1):
            raise ValueError("native call completion precedes start or exceeds run")
        question, _ = expected_ids[key]
        started = strict_json(selected_file(folder, "calls/" + key + "-started.json"))
        if any(
            started.get(k) != call.get(k) for k in ["id", "request", "startedAt"]
        ) or set(started) != {"id", "request", "startedAt"}:
            raise ValueError("native call start differs from retained marker")
        if "response" in call and encode(
            strict_json(selected_file(folder, "calls/" + key + "-returned.json"))
        ) != encode(call):
            raise ValueError("native call differs from original returned bytes")
        if encode(call.get("request")) != encode(
            dict(
                prompt=prompt_for(question),
                max_tokens=24,
                temperature=0.0,
                seed=42,
                top_p=1.0,
                top_k=0,
                repeat_penalty=1.0,
                stop=["<|im_end|>"],
            )
        ):
            raise ValueError("native request differs from frozen prompt/config")
    expected_call_files = set()
    for call in calls:
        expected_call_files.add(call["id"] + "-started.json")
        if "response" in call:
            expected_call_files.add(call["id"] + "-returned.json")
        if "error" in call:
            name = call["id"] + "-error.json"
            expected_call_files.add(name)
            if strict_json(selected_file(folder, "calls/" + name)) != call:
                raise ValueError("original call error changed")
    if {
        str(p.relative_to(folder / "calls"))
        for p in (folder / "calls").rglob("*")
        if p.is_file()
    } != expected_call_files:
        raise ValueError("original call population changed")
    native_files = [
        str(p.relative_to(folder))
        for p in (folder / "native").rglob("*")
        if p.is_file()
    ]
    if native_files != [pins["native"]["path"]]:
        raise ValueError("native log population changed")

    def resolve_attachments(value, attachments):
        if isinstance(value, str) and value.startswith("attachment://"):
            key = value.removeprefix("attachment://")
            if not isinstance(attachments.get(key), str):
                raise ValueError("native attachment absent")
            return attachments[key]
        if isinstance(value, list):
            return [resolve_attachments(x, attachments) for x in value]
        if isinstance(value, dict):
            return {k: resolve_attachments(v, attachments) for k, v in value.items()}
        return value

    outcomes = []
    total_input = total_output = 0
    for sample in samples:
        key = sample["id"]
        if key not in expected_ids or key in seen:
            raise ValueError("extra or duplicate native attempt")
        seen.add(key)
        question, target = expected_ids[key]
        if (
            sample.get("input") != question
            or sample.get("target") != target
            or type(sample.get("epoch")) is not int
            or sample.get("epoch") != 1
        ):
            raise ValueError("native attempt declaration mismatch")
        if sample.get("completed_at") is None:
            if (
                not began
                <= timestamp(sample.get("started_at"))
                <= finished + timedelta(seconds=1)
            ):
                raise ValueError("incomplete sample timeline differs")
            outcomes.append(dict(id=key, outcome="incomplete", quality=None))
            continue
        if sample.get("error_retries") != [] or not began <= timestamp(
            sample.get("started_at")
        ) <= timestamp(sample.get("completed_at")) <= finished + timedelta(seconds=1):
            raise ValueError("native sample retry or timeline differs")
        call = by_call.get(key)
        if call is not None:
            sample_started, sample_finished = (
                timestamp(sample.get("started_at")),
                timestamp(sample.get("completed_at")),
            )
            if (
                not sample_started
                <= timestamp(call.get("startedAt"))
                <= sample_finished
            ):
                raise ValueError("native call start outside native attempt")
            if (
                "response" in call
                and not timestamp(call.get("finishedAt")) <= sample_finished
            ):
                raise ValueError("native call completion outside native attempt")
        if sample.get("error"):
            outcomes.append(dict(id=key, outcome="error", quality=None))
            continue
        if call is None or "response" not in call:
            raise ValueError("completed native sample has no original call")
        response = call["response"]
        usage = response["usage"]
        if (
            any(
                type(usage.get(k)) is not int or usage[k] < 0
                for k in ["prompt_tokens", "completion_tokens", "total_tokens"]
            )
            or usage["total_tokens"]
            != usage["prompt_tokens"] + usage["completion_tokens"]
        ):
            raise ValueError("invalid native token counts")
        text = response["choices"][0]["text"]
        native_output = resolve_attachments(
            sample["output"], sample.get("attachments", {})
        )
        if native_output["choices"][0]["message"]["content"] != text:
            raise ValueError("native output differs from retained model response")
        native_usage = native_output["usage"]
        if any(
            type(native_usage.get(k)) is not int
            for k in ["input_tokens", "output_tokens", "total_tokens"]
        ):
            raise ValueError("mapped token counts require integers")
        if (
            native_usage["input_tokens"],
            native_usage["output_tokens"],
            native_usage["total_tokens"],
        ) != (
            usage["prompt_tokens"],
            usage["completion_tokens"],
            usage["total_tokens"],
        ):
            raise ValueError("mapped usage differs from native usage")
        events = [e for e in sample.get("events", []) if e.get("event") == "model"]
        if (
            len(events) != 1
            or encode(
                resolve_attachments(
                    events[0].get("call", {}).get("response"),
                    sample.get("attachments", {}),
                )
            )
            != encode(response)
            or encode(
                resolve_attachments(
                    events[0].get("output"), sample.get("attachments", {})
                )
            )
            != encode(native_output)
            or encode(events[0].get("config")) != encode(expected_generation)
        ):
            raise ValueError("native model event differs from retained call/output")
        event_request = dict(events[0]["call"]["request"])
        if isinstance(event_request.get("prompt"), str) and event_request[
            "prompt"
        ].startswith("attachment://"):
            event_request["prompt"] = sample.get("attachments", {}).get(
                event_request["prompt"].removeprefix("attachment://")
            )
        if encode(event_request) != encode(call["request"]):
            raise ValueError("native event prompt differs from original request")
        scores = sample["scores"]
        score = score_letter(text, target)
        if (
            set(scores) != {"letter_score"}
            or type(scores["letter_score"]["value"]) is not int
            or scores["letter_score"]["value"] != score
        ):
            raise ValueError("native score differs from recomputed rubric")
        measurement = call["measurement"]
        for field in ["elapsed_ns", "process_cpu_ns", "process_maxrss_kib"]:
            if type(measurement.get(field)) is not int or measurement[field] < 0:
                raise ValueError("invalid measured resource")
        total_input += usage["prompt_tokens"]
        total_output += usage["completion_tokens"]
        outcomes.append(
            dict(
                id=key,
                outcome="scored",
                quality=score,
                output=text,
                tokens=usage,
                resources=measurement,
            )
        )
    for key in expected_ids.keys() - seen:
        outcomes.append(
            dict(
                id=key,
                outcome="incomplete" if key in by_call else "unknown-start",
                quality=None,
            )
        )
    outcomes.sort(key=lambda x: list(expected_ids).index(x["id"]))
    scored = [x for x in outcomes if x["outcome"] == "scored"]
    complete = native["status"] == "success" and len(scored) == len(CASES)
    return {
        "profile": PROFILE,
        "evidence": "complete-retained-local-attempts"
        if complete
        else "incomplete-retained-local-attempts",
        "population": {
            "planned": len(CASES),
            "started": len(samples),
            "nativeAttemptsStarted": len(samples),
            "modelCallsStarted": len(calls),
            "scored": len(scored),
            "errors": sum(x["outcome"] == "error" for x in outcomes),
            "incomplete": sum(x["outcome"] == "incomplete" for x in outcomes),
            "unknownStart": sum(x["outcome"] == "unknown-start" for x in outcomes),
        },
        "quality": {
            "correct": sum(x["quality"] for x in scored),
            "scored": len(scored),
            "declared": len(CASES),
            "interpretation": "author-written smoke tasks; not a benchmark estimate",
        },
        "nativeTokens": {
            "input": total_input,
            "output": total_output,
            "scope": "scored-call-only; errors and incomplete calls are excluded from this subtotal",
        },
        "attempts": outcomes,
        "independentCustody": "not-established",
        "providerCost": "zero-local-CPU-no-provider-call",
        "modelIdentityAuthority": "selected-file-digest; original-to-quantized derivation not independently reproduced",
        "effects": "not-established",
    }


def run(folder, weights, provenance):
    import inspect_ai
    import llama_cpp
    from inspect_ai import Task, eval
    from inspect_ai.dataset import Sample
    from inspect_ai.model import (
        GenerateConfig,
        Model,
        ModelAPI,
        ModelCall,
        ModelOutput,
        ModelUsage,
        modelapi,
    )
    from inspect_ai.scorer import Score, accuracy, scorer
    from inspect_ai.solver import generate

    if (
        importlib.metadata.version("inspect-ai") != "0.3.273"
        or importlib.metadata.version("llama-cpp-python") != "0.3.16"
    ):
        raise ValueError("requires Inspect0.3.273 and llama-cpp-python0.3.16")
    if (
        weights.is_symlink()
        or weights.stat().st_size != MODEL_SIZE
        or digest(weights.read_bytes()) != MODEL_SHA256
    ):
        raise ValueError("weights differ from selected model")
    folder = folder.resolve()
    folder.mkdir(parents=True, exist_ok=False)
    sources = {"local_model.py": Path(__file__).read_bytes()}
    for name, module in [("inspect", inspect_ai), ("llama", llama_cpp)]:
        root = Path(module.__file__).parent
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.suffix in {".py", ".so", ".dylib", ".dll"}:
                sources[name + "/" + str(path.relative_to(root))] = path.read_bytes()
    sources["model-provenance.json"] = provenance.read_bytes()
    retained_provenance = strict_json(provenance.read_bytes())
    for name, expected in retained_provenance["sources"].items():
        raw = selected_file(provenance.parent, name)
        if digest(raw) != expected:
            raise ValueError("selected primary provenance changed")
        sources["provenance/" + name] = raw
    for package in ["inspect-ai", "llama-cpp-python"]:
        distribution = importlib.metadata.distribution(package)
        sources[package + "/METADATA.txt"] = distribution.read_text("METADATA").encode()
        for item in distribution.files or []:
            if "LICENSE" in item.name.upper():
                sources[package + "/" + item.name] = Path(
                    distribution.locate_file(item)
                ).read_bytes()
    sources["llama-system-info.txt"] = llama_cpp.llama_print_system_info() + b"\n"
    for name, raw in sources.items():
        write(folder / "sources" / name, raw)
    manifest = {name: digest(raw) for name, raw in sources.items()}
    write(folder / "source-manifest.json", manifest)
    declaration = {
        "profile": PROFILE,
        "declaredAt": now(),
        "cases": [dict(id=i, input=q, target=a) for i, q, a in CASES],
        "config": CONFIG,
        "rubric": "strip surrounding whitespace then exact single target letter; all prose fails",
        "model": {
            "repo": MODEL_REPO,
            "revision": MODEL_REVISION,
            "file": MODEL_FILE,
            "sha256": MODEL_SHA256,
            "bytes": MODEL_SIZE,
            "originalRepo": "HuggingFaceTB/SmolLM2-135M-Instruct",
            "originalRevision": ORIGINAL_REVISION,
            "license": "Apache-2.0-as-declared-in-retained-model-cards",
        },
        "runtime": {
            "inspect": "0.3.273",
            "llama_cpp_python": "0.3.16",
            "python": sys.version,
            "platform": platform.platform(),
        },
        "budget": {
            "providerCalls": 0,
            "providerDollars": 0,
            "downloadBytesLimit": 512 * 1024 * 1024,
            "runSecondsLimit": 600,
            "maximumModelCalls": len(CASES),
        },
        "population": "12 planned attempts, one epoch each, no retries, no omitted failed samples",
        "resourceScope": "adapter-call elapsed and whole-process CPU delta; Linux whole-process lifetime peak RSS, not per-sample memory allocation",
        "sourceManifestSha256": digest(encode(manifest)),
    }
    write(folder / "declaration.json", declaration)
    began = time.perf_counter()
    calls = []
    try:
        engine = llama_cpp.Llama(
            model_path=str(weights),
            n_ctx=512,
            n_threads=2,
            n_threads_batch=2,
            n_gpu_layers=0,
            seed=42,
            verbose=False,
        )

        @modelapi(name="probity-local-cpu")
        class LocalAPI(ModelAPI):
            async def generate(self, input, tools, tool_choice, config):
                if (
                    tools
                    or time.perf_counter() - began >= 600
                    or len(calls) >= len(CASES)
                ):
                    raise ValueError("declared model-call boundary exceeded")
                question = input[-1].text
                matching = [i for i, q, _ in CASES if q == question]
                if len(matching) != 1 or any(c["id"] == matching[0] for c in calls):
                    raise ValueError("request outside frozen task population")
                request = dict(
                    prompt=prompt_for(question),
                    max_tokens=24,
                    temperature=0.0,
                    seed=42,
                    top_p=1.0,
                    top_k=0,
                    repeat_penalty=1.0,
                    stop=["<|im_end|>"],
                )
                call = dict(id=matching[0], request=request, startedAt=now())
                calls.append(call)
                write(folder / "calls" / f"{matching[0]}-started.json", call)
                wall, cpu = time.perf_counter_ns(), time.process_time_ns()
                try:
                    response = engine.create_completion(**request)
                except Exception as exc:
                    call["error"] = dict(type=type(exc).__name__, message=str(exc))
                    write(folder / "calls" / f"{matching[0]}-error.json", call)
                    raise
                call.update(
                    response=response,
                    finishedAt=now(),
                    measurement=dict(
                        elapsed_ns=time.perf_counter_ns() - wall,
                        process_cpu_ns=time.process_time_ns() - cpu,
                        process_maxrss_kib=resource.getrusage(
                            resource.RUSAGE_SELF
                        ).ru_maxrss,
                    ),
                )
                write(folder / "calls" / f"{matching[0]}-returned.json", call)
                usage = response["usage"]
                output = ModelOutput.from_content(
                    model=self.model_name, content=response["choices"][0]["text"]
                )
                output.usage = ModelUsage(
                    input_tokens=usage["prompt_tokens"],
                    output_tokens=usage["completion_tokens"],
                    total_tokens=usage["total_tokens"],
                )
                return output, ModelCall(request=request, response=response)

        @scorer(metrics=[accuracy()])
        def letter_score():
            async def score(state, target):
                return Score(
                    value=score_letter(state.output.completion, target.text),
                    answer=state.output.completion,
                )

            return score

        config = GenerateConfig(
            temperature=0, max_tokens=24, seed=42, max_connections=1
        )
        model = Model(LocalAPI("smollm2-135m-instruct-q4km", config=config), config)
        task = Task(
            name="probity_local_model_smoke_v1",
            version=1,
            dataset=[Sample(id=i, input=q, target=a) for i, q, a in CASES],
            solver=generate(),
            scorer=letter_score(),
            epochs=1,
            metadata={
                "probity_profile": PROFILE,
                "probity_declaration_sha256": digest(encode(declaration)),
                "probity_source_manifest_sha256": digest(encode(manifest)),
                "model_revision": MODEL_REVISION,
                "weight_sha256": MODEL_SHA256,
            },
        )
        logs = eval(
            task,
            model=model,
            log_dir=str(folder / "native"),
            log_format="json",
            max_samples=1,
            retry_on_error=0,
            display="none",
            fail_on_error=False,
        )
        native = Path(logs[0].location)
        write(folder / "calls.json", calls)
        pins = {
            kind: dict(
                path=str(path.relative_to(folder)), sha256=digest(path.read_bytes())
            )
            for kind, path in {
                "declaration": folder / "declaration.json",
                "native": native,
                "calls": folder / "calls.json",
                "sources": folder / "source-manifest.json",
            }.items()
        }
        write(folder / "consumer-pins.json", pins)
        report = verify(folder, pins)
        report["runElapsedSeconds"] = time.perf_counter() - began
        write(folder / "report.json", report)
        return report
    except Exception as exc:
        if not (folder / "calls.json").exists():
            write(folder / "calls.json", calls)
        write(
            folder / "run-error.json",
            dict(
                type=type(exc).__name__,
                message=str(exc),
                elapsedSeconds=time.perf_counter() - began,
            ),
        )
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--weights", type=Path)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--pins-file", type=Path)
    args = parser.parse_args()
    if args.verify:
        if args.pins_file is None:
            parser.error("offline reader requires externally selected --pins-file")
        report = verify(args.output, strict_json(args.pins_file.read_bytes()))
    else:
        if args.weights is None or args.provenance is None:
            parser.error("run requires --weights and --provenance")
        report = run(args.output, args.weights, args.provenance)
    print(json.dumps(report, indent=2, allow_nan=False))
