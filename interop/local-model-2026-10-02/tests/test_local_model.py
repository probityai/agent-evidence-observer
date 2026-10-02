import json

import pytest

from local_model import (
    CASES,
    CONFIG,
    MODEL_REVISION,
    MODEL_SHA256,
    PROFILE,
    digest,
    encode,
    prompt_for,
    score_letter,
    strict_json,
    verify,
    write,
)


def fixture(folder):
    names = [
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
    ]
    manifest = {n: digest(b"source") for n in names}
    for name in names[1:]:
        write(folder / "sources" / name, b"source")
    write(folder / "sources/local_model.py", b"source")
    write(folder / "source-manifest.json", manifest)
    declaration = dict(
        declaredAt="2026-10-02T00:00:00+00:00",
        profile=PROFILE,
        cases=[dict(id=i, input=q, target=t) for i, q, t in CASES],
        config=CONFIG,
        model=dict(sha256=MODEL_SHA256, revision=MODEL_REVISION),
        sourceManifestSha256=digest(encode(manifest)),
    )
    write(folder / "declaration.json", declaration)
    samples = []
    calls = []
    for i, q, t in CASES:
        req = dict(
            prompt=prompt_for(q),
            max_tokens=24,
            temperature=0.0,
            seed=42,
            top_p=1.0,
            top_k=0,
            repeat_penalty=1.0,
            stop=["<|im_end|>"],
        )
        started = dict(id=i, request=req, startedAt="2026-10-02T00:00:00+00:00")
        write(folder / "calls" / (i + "-started.json"), started)
        response = dict(
            usage=dict(prompt_tokens=10, completion_tokens=1, total_tokens=11),
            choices=[dict(text=t)],
        )
        call = dict(
            **started,
            response=response,
            finishedAt="2026-10-02T00:00:00+00:00",
            measurement=dict(elapsed_ns=1, process_cpu_ns=1, process_maxrss_kib=1),
        )
        calls.append(call)
        write(folder / "calls" / (i + "-returned.json"), call)
        samples.append(
            dict(
                id=i,
                input=q,
                target=t,
                epoch=1,
                output=dict(
                    choices=[dict(message=dict(content=t))],
                    usage=dict(input_tokens=10, output_tokens=1, total_tokens=11),
                ),
                scores=dict(letter_score=dict(value=1)),
                error_retries=[],
                started_at="2026-10-02T00:00:00+00:00",
                completed_at="2026-10-02T00:00:00+00:00",
            )
        )
    for sample, call in zip(samples, calls):
        sample["events"] = [
            dict(
                event="model",
                call=dict(request=call["request"], response=call["response"]),
                output=sample["output"],
                config=dict(max_connections=1, max_tokens=24, temperature=0.0, seed=42),
            )
        ]
    write(folder / "calls.json", calls)
    metadata = dict(
        probity_profile=PROFILE,
        probity_declaration_sha256=digest(encode(declaration)),
        probity_source_manifest_sha256=digest(encode(manifest)),
        model_revision=MODEL_REVISION,
        weight_sha256=MODEL_SHA256,
    )
    native = dict(
        version=2,
        status="success",
        samples=samples,
        metadata=metadata,
        eval=dict(
            metadata=metadata,
            run_id="r",
            eval_id="e",
            task_id="t",
            task="probity_local_model_smoke_v1",
            task_version=1,
            packages=dict(inspect_ai="0.3.273"),
            model="probity-local-cpu/smollm2-135m-instruct-q4km",
            model_generate_config=dict(
                max_connections=1, max_tokens=24, temperature=0.0, seed=42
            ),
            model_args={},
            dataset=dict(
                samples=12, sample_ids=[i for i, _, _ in CASES], shuffled=False
            ),
            config=dict(
                epochs=1,
                retry_on_error=0,
                max_samples=1,
                fail_on_error=False,
                score_on_error=False,
                log_samples=True,
            ),
            scorers=[dict(name="letter_score")],
            created="2026-10-02T00:00:00+00:00",
        ),
        plan=dict(
            steps=[
                dict(
                    solver="generate", params=dict(tool_calls="loop"), params_passed={}
                )
            ]
        ),
        stats=dict(
            started_at="2026-10-02T00:00:00+00:00",
            completed_at="2026-10-02T00:00:00+00:00",
        ),
    )
    write(folder / "native/native.json", native)
    return {
        kind: dict(path=name, sha256=digest((folder / name).read_bytes()))
        for kind, name in dict(
            declaration="declaration.json",
            native="native/native.json",
            calls="calls.json",
            sources="source-manifest.json",
        ).items()
    }


def mutate(folder, pins, kind, fn):
    path = folder / pins[kind]["path"]
    value = json.loads(path.read_bytes())
    fn(value)
    path.write_bytes(encode(value))
    pins[kind]["sha256"] = digest(path.read_bytes())


def test_recomputes_quality_and_token_scope(tmp_path):
    report = verify(tmp_path, fixture(tmp_path))
    assert report["quality"]["correct"] == 12
    assert report["nativeTokens"] == dict(
        input=120,
        output=12,
        scope="scored-call-only; errors and incomplete calls are excluded from this subtotal",
    )
    assert report["population"] == dict(
        planned=12,
        started=12,
        nativeAttemptsStarted=12,
        modelCallsStarted=12,
        scored=12,
        errors=0,
        incomplete=0,
        unknownStart=0,
    )


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("A", 1),
        (" A\n", 1),
        ("a", 0),
        ("A because...", 0),
        ("AB", 0),
        ("Answer: A", 0),
        ("", 0),
    ],
)
def test_frozen_rubric(raw, expected):
    assert score_letter(raw, "A") == expected


@pytest.mark.parametrize("bad", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'])
def test_strict_json(bad):
    with pytest.raises(ValueError):
        strict_json(bad)


def test_changed_selected_bytes_refused(tmp_path):
    pins = fixture(tmp_path)
    (tmp_path / "native/native.json").write_bytes(b"{}")
    with pytest.raises(ValueError, match="selected artifact changed"):
        verify(tmp_path, pins)


@pytest.mark.parametrize(
    "change",
    [
        lambda x: x["samples"].append(x["samples"][0]),
        lambda x: x["samples"][0]["scores"]["letter_score"].update(value=0),
        lambda x: x["samples"][0]["output"]["usage"].update(input_tokens=11),
        lambda x: x["samples"][0].update(input="other"),
        lambda x: x["samples"][0]["output"]["choices"][0]["message"].update(
            content="wrong"
        ),
    ],
)
def test_rehashed_native_semantic_changes_refused(tmp_path, change):
    pins = fixture(tmp_path)
    mutate(tmp_path, pins, "native", change)
    with pytest.raises(ValueError):
        verify(tmp_path, pins)


def test_rehashed_call_changed_prompt_refused(tmp_path):
    pins = fixture(tmp_path)
    mutate(tmp_path, pins, "calls", lambda x: x[0]["request"].update(prompt="other"))
    with pytest.raises(ValueError):
        verify(tmp_path, pins)


def test_retained_original_call_required(tmp_path):
    pins = fixture(tmp_path)
    (tmp_path / "calls/add-returned.json").unlink()
    with pytest.raises(ValueError):
        verify(tmp_path, pins)


def test_rehashed_source_manifest_cannot_replace_declaration_join(tmp_path):
    pins = fixture(tmp_path)
    mutate(tmp_path, pins, "sources", lambda x: x.update(other="0" * 64))
    with pytest.raises(ValueError, match="source manifest differs"):
        verify(tmp_path, pins)


def test_partial_population_preserves_missing_attempt(tmp_path):
    pins = fixture(tmp_path)
    mutate(
        tmp_path,
        pins,
        "native",
        lambda x: (x.update(status="error"), x["samples"].pop()),
    )
    report = verify(tmp_path, pins)
    assert report["quality"]["scored"] == 11
    assert report["population"]["incomplete"] == 1
    assert report["attempts"][-1]["outcome"] == "incomplete"


def test_native_error_not_scored_as_wrong_answer(tmp_path):
    pins = fixture(tmp_path)
    mutate(
        tmp_path,
        pins,
        "native",
        lambda x: x["samples"][0].update(error=dict(message="failed")),
    )
    report = verify(tmp_path, pins)
    assert report["population"]["errors"] == 1
    assert report["quality"]["scored"] == 11


def test_symlink_artifact_refused(tmp_path):
    pins = fixture(tmp_path)
    native = tmp_path / "native/native.json"
    native.rename(tmp_path / "original.json")
    native.symlink_to(tmp_path / "original.json")
    with pytest.raises(ValueError, match="regular local file"):
        verify(tmp_path, pins)


@pytest.mark.parametrize(
    "change",
    [
        lambda x: x.pop("eval"),
        lambda x: x["samples"][0].update(epoch=True),
        lambda x: x["samples"][0]["scores"]["letter_score"].update(value=True),
        lambda x: x["eval"]["config"].update(epochs=True),
    ],
)
def test_minimal_envelope_and_boolean_numbers_refused(tmp_path, change):
    pins = fixture(tmp_path)
    mutate(tmp_path, pins, "native", change)
    with pytest.raises(ValueError):
        verify(tmp_path, pins)


@pytest.mark.parametrize(
    "where", ["sources/extra.py", "calls/extra-started.json", "native/extra.json"]
)
def test_extra_retained_population_refused(tmp_path, where):
    pins = fixture(tmp_path)
    write(tmp_path / where, b"{}")
    with pytest.raises(ValueError):
        verify(tmp_path, pins)


def test_incomplete_sample_preserved(tmp_path):
    pins = fixture(tmp_path)
    mutate(
        tmp_path, pins, "native", lambda x: x["samples"][0].update(completed_at=None)
    )
    assert verify(tmp_path, pins)["population"]["incomplete"] == 1


@pytest.mark.parametrize("field", ["temperature", "top_p"])
def test_boolean_request_number_refused(tmp_path, field):
    pins = fixture(tmp_path)
    mutate(
        tmp_path,
        pins,
        "calls",
        lambda x: x[0]["request"].update(
            {field: False if field == "temperature" else True}
        ),
    )
    with pytest.raises(ValueError):
        verify(tmp_path, pins)


def test_call_timestamp_garbage_refused(tmp_path):
    pins = fixture(tmp_path)
    mutate(tmp_path, pins, "calls", lambda x: x[0].update(startedAt="garbage"))
    with pytest.raises(ValueError):
        verify(tmp_path, pins)
