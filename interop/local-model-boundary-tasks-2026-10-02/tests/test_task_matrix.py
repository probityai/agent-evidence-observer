"""Synthetic byte contracts; these fixtures do not claim model execution."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from task_matrix import (
    PROTOCOL_COMMIT,
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


def fixture(root, *, preflight_failure=False):
    raw = Path(__file__).parents[1].joinpath("protocol.json").read_bytes()
    p = protocol(raw)
    write(root / "protocol.json", raw)
    sources = [
        "task_matrix.py",
        "llama-system-info.txt",
        "model-provenance.json",
        "llama-cpp-python/METADATA.txt",
        "llama-cpp-python/LICENSE.md",
        "provenance/original-card.txt",
        "provenance/quant-card.txt",
        "provenance/build-gcc.log",
        "provenance/downloads.json",
        "provenance/candidate-original-README.txt",
        "provenance/candidate-quant-README.txt",
        "provenance/download-accounting.json",
        "provenance/dependency-lock.json",
    ]
    for name in sources:
        write(root / "sources" / name, b"synthetic source")
    preparation_fixture(root, p)
    format_fixture(root, p)
    write(
        root / "sources/protocol-preregistration.json",
        {"commit": PROTOCOL_COMMIT, "sha256": PROTOCOL_SHA256},
    )
    write(
        root / "declaration.json",
        {
            "declaredAt": "2026-10-02T00:00:00+00:00",
            "protocolCommit": PROTOCOL_COMMIT,
            "protocolSha256": PROTOCOL_SHA256,
            "runnerSha256": digest(b"synthetic source"),
            "planned": 384,
            "runtime": p["runtime"],
            "models": p["models"],
            "cache": p["cache"],
            "formatControlSHA256": digest(encode(p["formatControl"])),
        },
    )
    if not preflight_failure:
        for index, (ident, cfg, case) in enumerate(population(p)):
            start = {
                "id": ident,
                "request": request(p, cfg, case),
                "startedAt": (
                    datetime(2026, 10, 2, tzinfo=UTC)
                    + timedelta(seconds=1, milliseconds=index * 2)
                ).isoformat(),
                "promptTokensPreflight": 100,
            }
            write(root / f"calls/{ident}-started.json", start)
            response = {
                "usage": {
                    "prompt_tokens": 100,
                    "completion_tokens": 10,
                    "total_tokens": 110,
                },
                "choices": [{"text": json.dumps(case["target"])}],
            }
            write(
                root / f"calls/{ident}-returned.json",
                dict(
                    **start,
                    finishedAt=(
                        datetime(2026, 10, 2, tzinfo=UTC)
                        + timedelta(seconds=1, milliseconds=index * 2 + 1)
                    ).isoformat(),
                    response=response,
                    measurement={
                        "elapsed_ns": 500_000,
                        "process_cpu_ns": 300_000,
                        "process_maxrss_kib": 1000,
                    },
                ),
            )
    write(
        root / "terminal.json",
        {
            "status": "error" if preflight_failure else "complete",
            "finishedAt": "2026-10-02T00:00:03+00:00",
            "elapsed_ns": 3_000_000_000,
            "process_cpu_ns": 3_000_000_000,
        },
    )
    return repin(root)


def preparation_fixture(root, p):
    folder = Path(__file__).parents[1]
    lock_raw = folder.joinpath("dependency-lock-linux-cp312.json").read_bytes()
    lock = json.loads(lock_raw)
    items = p["payloads"] + [
        {key: entry[key] for key in ["path", "url", "bytes", "sha256"]}
        | {"category": "dependencies"}
        for entry in lock["dependencies"]
    ]
    totals = {
        category: sum(item["bytes"] for item in items if item["category"] == category)
        for category in p["preparation"]["categoryLimitBytes"]
    }
    values = {
        "dependency-lock.json": lock_raw,
        "downloads.json": encode(
            {"files": items, "totalRetainedDownloadBytes": sum(totals.values())}
        ),
        "download-declaration.json": encode(
            {
                "profile": p["profile"],
                "dependencySelectionSHA256": p["preparation"][
                    "dependencySelectionSHA256"
                ],
                "items": items,
                "expectedPayloadBytesByCategory": totals,
                "expectedTotalPayloadBytes": sum(totals.values()),
                "totalLimitBytes": p["preparation"]["totalLimitBytes"],
                "categoryLimitBytes": p["preparation"]["categoryLimitBytes"],
                "downloadMonitoredSeconds": p["budgets"]["preparation_seconds"],
                "networkOperationTimeoutSeconds": p["budgets"][
                    "network_operation_seconds"
                ],
                "providerCalls": 0,
                "providerDollars": 0,
            }
        ),
        "download-accounting.json": encode(
            {
                "status": "verified",
                "error": None,
                "actualResponseBodyBytes": sum(totals.values()),
                "actualResponseBodyBytesByCategory": totals,
                "retainedPayloadBytes": sum(totals.values()),
                "totalLimitBytes": p["preparation"]["totalLimitBytes"],
                "categoryLimitBytes": p["preparation"]["categoryLimitBytes"],
                "files": [
                    {
                        "selected": item,
                        "status": "verified",
                        "retainedBytes": item["bytes"],
                        "retainedSHA256": item["sha256"],
                    }
                    for item in items
                ],
                "elapsedSeconds": 1.0,
            }
        ),
    }
    for item in p["payloads"]:
        if item["category"] == "metadata":
            values[item["path"]] = folder.joinpath(
                "tests/metadata", item["path"]
            ).read_bytes()
    for name, raw in values.items():
        path = root / "sources/provenance" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    (root / "sources/model-provenance.json").write_bytes(
        encode(
            {
                "sources": {name: digest(raw) for name, raw in values.items()},
                "selectedRuntime": {
                    "version": "0.3.16",
                    "sourceSHA256": p["payloads"][1]["sha256"],
                },
            }
        )
    )


def format_fixture(root, p):
    folder = Path(__file__).parents[1]
    body = folder.joinpath(p["formatControl"]["compiler"]["sourcePath"]).read_bytes()
    write(root / "sources/selected-grammar-compiler.py", body)
    write(root / "sources/llama/llama_grammar.py", body)
    for ident, contract in p["formatControl"]["taskContracts"].items():
        write(
            root / "sources/grammars" / (ident + ".gbnf"),
            folder.joinpath(contract["grammarPath"]).read_bytes(),
        )


def repin(root):
    manifest = {
        str(p.relative_to(root)): digest(p.read_bytes())
        for p in root.rglob("*")
        if p.is_file()
        and p.name not in {"manifest.json", "consumer-pins.json", "report.json"}
    }
    (root / "manifest.json").write_bytes(encode(manifest))
    return {
        kind: {"path": name, "sha256": digest((root / name).read_bytes())}
        for kind, name in {
            "manifest": "manifest.json",
            "protocol": "protocol.json",
            "declaration": "declaration.json",
            "terminal": "terminal.json",
        }.items()
    }


def change(root, name, fn):
    path = root / name
    value = json.loads(path.read_bytes())
    fn(value)
    path.write_bytes(encode(value))


@pytest.mark.parametrize(
    "text,target,expected",
    [
        (' {"answer": 7} ', {"answer": 7}, True),
        ('{"answer":true}', {"answer": 1}, False),
        ('{"answer":7.0}', {"answer": 7}, False),
        ('{"answer":7,"extra":0}', {"answer": 7}, False),
        ('{"answer":7,"answer":7}', {"answer": 7}, False),
        ('```json\n{"answer":7}\n```', {"answer": 7}, False),
        ('{"answer":NaN}', {"answer": None}, False),
        ('{"a":[2,1]}', {"a": [1, 2]}, False),
        ('{"answer":null}', {"answer": None}, True),
    ],
)
def test_frozen_rubric(text, target, expected):
    assert score(text, target)["correct"] is expected


def test_complete_separate_groups(tmp_path):
    report = verify(tmp_path, fixture(tmp_path))
    assert report["publicationDecision"] == "publish-scoped-report"
    assert report["population"]["planned"] == 384
    assert len(report["quality"]) == 24
    assert all(x["correct"] == x["planned"] == 16 for x in report["quality"])
    assert report["nativeTokens"] == {"prompt": 38400, "completion": 3840}


def test_absent_population_retained(tmp_path):
    report = verify(tmp_path, fixture(tmp_path, preflight_failure=True))
    assert report["publicationDecision"].startswith("hold")
    assert report["population"]["unknown-start"] == 384


@pytest.mark.parametrize(
    "mutation",
    [
        "prompt",
        "id",
        "tokens",
        "extra",
        "order",
        "rubric",
        "commit",
        "resource",
        "timeline",
        "orphan",
        "runtime",
    ],
)
def test_repin_does_not_widen_protocol(tmp_path, mutation):
    fixture(tmp_path)
    start = "calls/smol135-q4--short24--unconstrained--typed-integer-zero-started.json"
    returned = (
        "calls/smol135-q4--short24--unconstrained--typed-integer-zero-returned.json"
    )
    if mutation == "prompt":
        change(tmp_path, start, lambda v: v["request"].update(prompt="changed"))
    if mutation == "id":
        change(tmp_path, start, lambda v: v.update(id="unknown"))
    if mutation == "tokens":
        change(
            tmp_path,
            returned,
            lambda v: v["response"]["usage"].update(total_tokens=999),
        )
    if mutation == "extra":
        write(tmp_path / "calls/extra-started.json", {"id": "extra"})
    if mutation == "order":
        change(
            tmp_path,
            "calls/smol135-q4--short24--unconstrained--typed-integer-negative-started.json",
            lambda v: v.update(startedAt="2026-10-02T00:00:00+00:00"),
        )
    if mutation == "rubric":
        change(
            tmp_path, "protocol.json", lambda v: v["rubric"].update(partialCredit=True)
        )
    if mutation == "commit":
        change(
            tmp_path, "declaration.json", lambda v: v.update(protocolCommit="0" * 40)
        )
    if mutation == "resource":
        change(tmp_path, returned, lambda v: v["measurement"].update(elapsed_ns=-1))
    if mutation == "timeline":
        change(
            tmp_path,
            returned,
            lambda v: v.update(finishedAt="2026-10-01T00:00:00+00:00"),
        )
    if mutation == "orphan":
        (tmp_path / start).unlink()
    if mutation == "runtime":
        change(
            tmp_path,
            "declaration.json",
            lambda v: v["runtime"].update(llama_cpp_python="9.0"),
        )
    with pytest.raises(ValueError):
        verify(tmp_path, repin(tmp_path))


def test_selected_hash_change(tmp_path):
    pins = fixture(tmp_path)
    (tmp_path / "sources/task_matrix.py").write_text("changed")
    with pytest.raises(ValueError, match="bytes changed"):
        verify(tmp_path, pins)


def test_missing_pins(tmp_path):
    with pytest.raises(ValueError, match="separately selected"):
        verify(tmp_path, {})


def test_unknown_extra_file(tmp_path):
    pins = fixture(tmp_path)
    (tmp_path / "undeclared").write_text("extra")
    with pytest.raises(ValueError, match="population"):
        verify(tmp_path, pins)


def test_symlink_refused(tmp_path):
    pins = fixture(tmp_path)
    (tmp_path / "link").symlink_to("protocol.json")
    with pytest.raises(ValueError, match="symlink"):
        verify(tmp_path, pins)


def test_late_completion_is_retained_but_held(tmp_path):
    fixture(tmp_path)
    change(tmp_path, "terminal.json", lambda v: v.update(elapsed_ns=601_000_000_000))
    report = verify(tmp_path, repin(tmp_path))
    assert report["population"]["scored"] == 384
    assert report["evidence"]["withinRunBudget"] is False
    assert report["publicationDecision"].startswith("hold")


def test_serial_calls_cannot_overlap(tmp_path):
    fixture(tmp_path)
    change(
        tmp_path,
        "calls/"
        + population(
            protocol(Path(__file__).parents[1].joinpath("protocol.json").read_bytes())
        )[0][0]
        + "-returned.json",
        lambda v: v.update(finishedAt="2026-10-02T00:00:01.010000+00:00"),
    )
    with pytest.raises(ValueError, match="order/timeline"):
        verify(tmp_path, repin(tmp_path))


def test_serial_measurements_fit_run_envelope(tmp_path):
    fixture(tmp_path)
    change(tmp_path, "terminal.json", lambda v: v.update(elapsed_ns=0))
    with pytest.raises(ValueError, match="summed serial"):
        verify(tmp_path, repin(tmp_path))


def test_native_error_retains_denominator_and_original_binding(tmp_path):
    fixture(tmp_path)
    name = (
        "calls/"
        + population(
            protocol(Path(__file__).parents[1].joinpath("protocol.json").read_bytes())
        )[0][0]
    )
    start = json.loads((tmp_path / (name + "-started.json")).read_bytes())
    (tmp_path / (name + "-returned.json")).unlink()
    write(
        tmp_path / (name + "-error.json"),
        dict(
            **start,
            finishedAt="2026-10-02T00:00:01.001000+00:00",
            error={"type": "RuntimeError", "message": "native test failure"},
        ),
    )
    change(tmp_path, "terminal.json", lambda v: v.update(status="error"))
    report = verify(tmp_path, repin(tmp_path))
    assert report["population"]["planned"] == 384
    assert report["population"]["error"] == 1
    assert report["population"]["scored"] == 383
    assert report["publicationDecision"].startswith("hold")
    change(
        tmp_path, name + "-error.json", lambda v: v["request"].update(prompt="changed")
    )
    with pytest.raises(ValueError, match="error differs"):
        verify(tmp_path, repin(tmp_path))


@pytest.mark.parametrize(
    "field,value", [("n_gpu_layers", False), ("n_threads", 2.0), ("n_ctx", 512.0)]
)
def test_runtime_numbers_require_declared_types(tmp_path, field, value):
    fixture(tmp_path)
    change(tmp_path, "declaration.json", lambda v: v["runtime"].update({field: value}))
    with pytest.raises(ValueError, match="declaration differs"):
        verify(tmp_path, repin(tmp_path))


def test_population_size_requires_integer_type(tmp_path):
    fixture(tmp_path)
    change(tmp_path, "declaration.json", lambda v: v.update(planned=384.0))
    with pytest.raises(ValueError, match="declaration differs"):
        verify(tmp_path, repin(tmp_path))


def test_frozen_order_balances_every_position():
    p = protocol(Path(__file__).parents[1].joinpath("protocol.json").read_bytes())
    rows = population(p)
    assert len(rows) == len({row[0] for row in rows}) == 384
    for offset in range(8):
        assert {
            (model, cap, decoder): sum(
                rows[i][1]["model"] == model
                and rows[i][1]["id"] == cap
                and rows[i][1]["decoder"] == decoder
                for i in range(offset, 384, 8)
            )
            for model, cap, decoder in p["order"]["base"]
        } == {tuple(pair): 6 for pair in p["order"]["base"]}
    for i in range(0, 384, 8):
        assert len({row[2]["id"] for row in rows[i : i + 8]}) == 1
        assert {
            (row[1]["model"], row[1]["id"], row[1]["decoder"])
            for row in rows[i : i + 8]
        } == {tuple(pair) for pair in p["order"]["base"]}


def test_historical_settings_unchanged_but_population_is_new():
    p = protocol(Path(__file__).parents[1].joinpath("protocol.json").read_bytes())
    original = json.loads(
        Path(__file__)
        .parents[2]
        .joinpath("local-model-tasks-2026-10-02/protocol.json")
        .read_bytes()
    )
    assert len(p["cases"]) == 48
    assert {c["id"] for c in p["cases"]}.isdisjoint(c["id"] for c in original["cases"])
    for name in [
        "system",
        "rubric",
        "generation",
        "configurations",
        "runtime",
    ]:
        assert p[name] == original[name]


@pytest.mark.parametrize("field", ["models", "cache"])
def test_reselected_model_and_cache_declarations_refuse(tmp_path, field):
    fixture(tmp_path)
    change(tmp_path, "declaration.json", lambda v: v.update({field: []}))
    with pytest.raises(ValueError, match="declaration differs"):
        verify(tmp_path, repin(tmp_path))


def test_rss_limit_holds_complete_quality_report(tmp_path):
    fixture(tmp_path)
    first = population(
        protocol(Path(__file__).parents[1].joinpath("protocol.json").read_bytes())
    )[-1][0]
    change(
        tmp_path,
        f"calls/{first}-returned.json",
        lambda v: v["measurement"].update(process_maxrss_kib=1048577),
    )
    report = verify(tmp_path, repin(tmp_path))
    assert report["population"]["scored"] == 384
    assert report["evidence"]["withinRunBudget"] is False
    assert report["publicationDecision"].startswith("hold")


@pytest.mark.parametrize(
    "mutation",
    [
        "total",
        "category",
        "time",
        "timebool",
        "retainedhash",
        "modelhash",
        "metadata",
        "lock",
        "declaration",
        "provenance",
        "runtime",
    ],
)
def test_preparation_accounting_and_source_selection_refuse_reselected_mutations(
    tmp_path, mutation
):
    fixture(tmp_path)
    account = "sources/provenance/download-accounting.json"
    if mutation == "total":
        change(tmp_path, account, lambda v: v.update(actualResponseBodyBytes=536870913))
    elif mutation == "category":
        change(
            tmp_path,
            account,
            lambda v: v["actualResponseBodyBytesByCategory"].update(model=402653185),
        )
    elif mutation == "time":
        change(tmp_path, account, lambda v: v.update(elapsedSeconds=181.0))
    elif mutation == "timebool":
        change(tmp_path, account, lambda v: v.update(elapsedSeconds=True))
    elif mutation == "retainedhash":
        change(
            tmp_path, account, lambda v: v["files"][0].update(retainedSHA256="0" * 64)
        )
    elif mutation == "modelhash":
        change(
            tmp_path,
            "sources/provenance/downloads.json",
            lambda v: v["files"][0].update(sha256="0" * 64),
        )
    elif mutation == "metadata":
        (tmp_path / "sources/provenance/candidate-original-README.txt").write_bytes(
            b"changed"
        )
    elif mutation == "lock":
        (tmp_path / "sources/provenance/dependency-lock.json").write_bytes(b"{}")
    elif mutation == "declaration":
        change(
            tmp_path,
            "sources/provenance/download-declaration.json",
            lambda v: v.update(totalLimitBytes=536870913),
        )
    elif mutation == "provenance":
        change(
            tmp_path,
            "sources/model-provenance.json",
            lambda v: v["sources"].update(**{"dependency-lock.json": "0" * 64}),
        )
    elif mutation == "runtime":
        change(
            tmp_path,
            "sources/model-provenance.json",
            lambda v: v["selectedRuntime"].update(sourceSHA256="0" * 64),
        )
    with pytest.raises(ValueError, match="preparation|provenance"):
        verify(tmp_path, repin(tmp_path))


def test_serial_lifetime_peak_rss_cannot_decrease(tmp_path):
    fixture(tmp_path)
    order = population(
        protocol(Path(__file__).parents[1].joinpath("protocol.json").read_bytes())
    )
    change(
        tmp_path,
        "calls/" + order[1][0] + "-returned.json",
        lambda v: v["measurement"].update(process_maxrss_kib=999),
    )
    with pytest.raises(ValueError, match="lifetime peak RSS decreased"):
        verify(tmp_path, repin(tmp_path))
