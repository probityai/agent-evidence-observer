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
    for name in ["task_matrix.py", "schema_contract.py", "prepare_boundary.py", "build_protocol.py"]:
        (root / "sources" / name).write_bytes(Path(__file__).parents[1].joinpath(name).read_bytes())
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
            "runnerSha256": digest(Path(__file__).parents[1].joinpath("task_matrix.py").read_bytes()),
            "schemaHelperSHA256": p["sourceClosure"]["schemaHelperSHA256"],
            "planned": 128,
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



def test_exact_original_objects_and_global_intervention():
    folder = Path(__file__).parents[1]
    original = json.loads(folder.parent.joinpath("local-model-boundary-tasks-2026-10-02/protocol.json").read_bytes())
    p = protocol(folder.joinpath("protocol.json").read_bytes())
    expected = [c for c in original["cases"] if c["family"] == "policy-boundary"]
    assert p["taskSelection"]["originalPolicyCasesSHA256"] == digest(encode(expected))
    assert len(p["cases"]) == 32
    for case, old_case in zip(p["cases"][::2], expected):
        vocabulary = p["cases"][p["cases"].index(case) + 1]
        assert case["originalCase"] == vocabulary["originalCase"] == old_case
        assert case["input"] == vocabulary["input"] == old_case["input"]
        assert case["target"] == vocabulary["target"] == old_case["target"]
        assert case["originalIdentity"] == {k: old_case[k] for k in ["id", "family", "pair", "role"]}
        broad = p["formatControl"]["taskContracts"][case["id"]]["schema"]
        enum = p["formatControl"]["taskContracts"][vocabulary["id"]]["schema"]
        assert "enum" not in broad["properties"]["decision"]
        assert enum["properties"]["decision"]["enum"] == ["publish", "hold", "admit", "reject", "retry", "inspect", "dispatch"]
        enum = json.loads(json.dumps(enum)); enum["properties"]["decision"].pop("enum")
        assert enum == broad


def test_all128_native_receipts_score_separately(tmp_path):
    report = verify(tmp_path, fixture(tmp_path))
    assert report["publicationDecision"] == "publish-scoped-report"
    assert report["population"] == {"planned":128,"started":128,"scored":128,"error":0,"unsupported":0,"incomplete":0,"unknown-start":0}
    assert len(report["quality"]) == 8
    assert all(g["planned"] == g["correct"] == 16 and g["plannedPairs"] == 8 for g in report["quality"])


def test_fixed_order_and_budget():
    p = protocol(Path(__file__).parents[1].joinpath("protocol.json").read_bytes())
    rows = population(p)
    assert len(rows) == len({r[0] for r in rows}) == 128
    positions = {}
    for index, (_, cfg, case) in enumerate(rows):
        key = (cfg["model"], cfg["id"])
        positions.setdefault(key, [0]*4)[index % 4] += 1
        assert cfg["decoder"] == "schema"
        assert request(p, cfg, case)["grammarSelection"]["grammarSHA256"]
    assert list(positions.values()) == [[8]*4]*4
    assert sum(cfg["max_tokens"] for _, cfg, _ in rows) == 7680
    assert p["resourceHistory"]["priorFiveAttemptBytes"] == 2167006362


@pytest.mark.parametrize("name", ["schema_contract.py", "task_matrix.py", "prepare_boundary.py", "build_protocol.py"])
def test_reselected_source_cannot_be_repaired_by_manifest(tmp_path, name):
    fixture(tmp_path, preflight_failure=True)
    (tmp_path / "sources" / name).write_bytes(b"changed source")
    pins = repin(tmp_path)
    if name == "task_matrix.py":
        change(tmp_path, "declaration.json", lambda d: d.update(runnerSha256=digest(b"changed source")))
        pins = repin(tmp_path)
    with pytest.raises(ValueError): verify(tmp_path, pins)


def test_setup_error_retains128_denominator_and_helper(tmp_path):
    report = verify(tmp_path, fixture(tmp_path, preflight_failure=True))
    assert report["population"]["unknown-start"] == report["population"]["planned"] == 128
    assert report["publicationDecision"] == "hold-incomplete-or-over-budget"
    (tmp_path / "sources/schema_contract.py").unlink()
    with pytest.raises(ValueError): verify(tmp_path, repin(tmp_path))


def test_global_enum_checks_membership_without_semantic_oracle():
    p = protocol(Path(__file__).parents[1].joinpath("protocol.json").read_bytes())
    by_mode = {c["mode"]: c for c in p["cases"][:2]}
    for mode, case in by_mode.items():
        schema = p["formatControl"]["taskContracts"][case["id"]]["schema"]
        r = score('{"decision":"unlisted"}', case["target"], schema)
        assert r == {"formatValid":True, "schemaValid":mode=="control", "correct":False}
        wrong = "hold" if case["target"]["decision"] != "hold" else "publish"
        assert score(json.dumps({"decision":wrong}), case["target"], schema) == {"formatValid":True,"schemaValid":True,"correct":False}


def test_error_and_missing_returns_never_leave_denominator(tmp_path):
    fixture(tmp_path)
    p = protocol(tmp_path.joinpath("protocol.json").read_bytes())
    ident = population(p)[0][0]
    (tmp_path / f"calls/{ident}-returned.json").unlink()
    report = verify(tmp_path, repin(tmp_path))
    assert report["population"]["planned"] == 128
    assert report["population"]["incomplete"] == 1
    assert report["publicationDecision"] == "hold-incomplete-or-over-budget"
