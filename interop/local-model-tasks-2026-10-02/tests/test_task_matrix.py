"""Synthetic byte contracts; these fixtures do not claim model execution."""

import json
from datetime import datetime, timedelta, timezone
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
    ]
    for name in sources:
        write(root / "sources" / name, b"synthetic source")
    write(
        root / "sources/protocol-preregistration.json",
        dict(commit=PROTOCOL_COMMIT, sha256=PROTOCOL_SHA256),
    )
    write(
        root / "declaration.json",
        dict(
            declaredAt="2026-10-02T00:00:00+00:00",
            protocolCommit=PROTOCOL_COMMIT,
            protocolSha256=PROTOCOL_SHA256,
            runnerSha256=digest(b"synthetic source"),
            planned=48,
            runtime=p["runtime"],
        ),
    )
    if not preflight_failure:
        for index, (ident, cfg, case) in enumerate(population(p)):
            start = dict(
                id=ident,
                request=request(p, cfg, case),
                startedAt=(
                    datetime(2026, 10, 2, tzinfo=timezone.utc)
                    + timedelta(seconds=1, milliseconds=index * 2)
                ).isoformat(),
                promptTokensPreflight=100,
            )
            write(root / f"calls/{ident}-started.json", start)
            response = dict(
                usage=dict(prompt_tokens=100, completion_tokens=10, total_tokens=110),
                choices=[dict(text=json.dumps(case["target"]))],
            )
            write(
                root / f"calls/{ident}-returned.json",
                dict(
                    **start,
                    finishedAt=(
                        datetime(2026, 10, 2, tzinfo=timezone.utc)
                        + timedelta(seconds=1, milliseconds=index * 2 + 1)
                    ).isoformat(),
                    response=response,
                    measurement=dict(
                        elapsed_ns=500_000,
                        process_cpu_ns=300_000,
                        process_maxrss_kib=1000,
                    ),
                ),
            )
    write(
        root / "terminal.json",
        dict(
            status="error" if preflight_failure else "complete",
            finishedAt="2026-10-02T00:00:03+00:00",
            elapsed_ns=3_000_000_000,
        ),
    )
    return repin(root)


def repin(root):
    manifest = {
        str(p.relative_to(root)): digest(p.read_bytes())
        for p in root.rglob("*")
        if p.is_file()
        and p.name not in {"manifest.json", "consumer-pins.json", "report.json"}
    }
    (root / "manifest.json").write_bytes(encode(manifest))
    return {
        kind: dict(path=name, sha256=digest((root / name).read_bytes()))
        for kind, name in dict(
            manifest="manifest.json",
            protocol="protocol.json",
            declaration="declaration.json",
            terminal="terminal.json",
        ).items()
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
    assert report["population"]["planned"] == 48
    assert len(report["quality"]) == 8
    assert all(x["correct"] == x["planned"] == 6 for x in report["quality"])
    assert report["nativeTokens"] == dict(prompt=4800, completion=480)


def test_absent_population_retained(tmp_path):
    report = verify(tmp_path, fixture(tmp_path, preflight_failure=True))
    assert report["publicationDecision"].startswith("hold")
    assert report["population"]["unknown-start"] == 48


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
    start = "calls/short24--extract-owner-started.json"
    returned = "calls/short24--extract-owner-returned.json"
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
        write(tmp_path / "calls/extra-started.json", dict(id="extra"))
    if mutation == "order":
        change(
            tmp_path,
            "calls/short24--extract-quantity-started.json",
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
    assert report["population"]["scored"] == 48
    assert report["evidence"]["withinRunBudget"] is False
    assert report["publicationDecision"].startswith("hold")


def test_serial_calls_cannot_overlap(tmp_path):
    fixture(tmp_path)
    change(
        tmp_path,
        "calls/short24--extract-owner-returned.json",
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
    name = "calls/short24--extract-owner"
    start = json.loads((tmp_path / (name + "-started.json")).read_bytes())
    (tmp_path / (name + "-returned.json")).unlink()
    write(
        tmp_path / (name + "-error.json"),
        dict(
            **start,
            finishedAt="2026-10-02T00:00:01.001000+00:00",
            error=dict(type="RuntimeError", message="native test failure"),
        ),
    )
    change(tmp_path, "terminal.json", lambda v: v.update(status="error"))
    report = verify(tmp_path, repin(tmp_path))
    assert report["population"]["planned"] == 48
    assert report["population"]["error"] == 1
    assert report["population"]["scored"] == 47
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
    change(tmp_path, "declaration.json", lambda v: v.update(planned=48.0))
    with pytest.raises(ValueError, match="declaration differs"):
        verify(tmp_path, repin(tmp_path))
