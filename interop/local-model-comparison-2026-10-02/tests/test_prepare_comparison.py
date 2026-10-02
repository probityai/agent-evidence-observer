"""No inference/downloads: meaningful selected transfer refusal controls."""

import hashlib
import io
import json

import prepare_comparison as prep
import pytest


def test_both_models_and_minimal_dependencies_fit_selected_budget():
    lock = json.loads(prep.LOCK_PATH.read_bytes())
    items = prep.selected_items(lock)
    totals = prep.expected_totals(items)
    assert totals == {
        "model": 376044704,
        "source": 50688636,
        "metadata": 30738,
        "dependencies": 45426676,
    }
    assert sum(totals.values()) == 472190754 < prep.TOTAL_LIMIT
    assert len(lock["dependencies"]) == 9
    assert sum(prep.CATEGORY_LIMITS.values()) == prep.TOTAL_LIMIT


@pytest.mark.parametrize("category", list(prep.CATEGORY_LIMITS))
def test_selected_category_overflow_refuses(category):
    item = prep.Download(
        "file", "url", prep.CATEGORY_LIMITS[category] + 1, "0" * 64, category
    )
    with pytest.raises(ValueError, match="declaration exceeds limit"):
        prep.expected_totals([item])


def test_partial_overflow_is_charged_and_retained():
    item = prep.Download("file", "url", 4, hashlib.sha256(b"1234").hexdigest(), "model")
    accounting = prep.Accounting()
    out = io.BytesIO()
    with pytest.raises(ValueError, match="selected size"):
        prep.stream_payload(io.BytesIO(b"12345"), out, item, accounting)
    assert accounting.transferred == 5
    assert out.getvalue() == b""


def test_each_download_is_attempted_once_and_failure_not_retried(tmp_path, monkeypatch):
    calls = []

    def fail(url, timeout):
        calls.append((url, timeout))
        raise OSError("selected transfer unavailable")

    monkeypatch.setattr(prep.urllib.request, "urlopen", fail)
    item = prep.Download(
        "model", "https://selected.example/model", 4, "0" * 64, "model"
    )
    account = prep.Accounting()
    with pytest.raises(OSError):
        prep.download_one(tmp_path, item, account)
    assert calls == [(item.url, 30)]
    assert account.files[0]["status"] == "refused"


def test_changed_dependency_lock_refuses_before_network(tmp_path, monkeypatch):
    lock = tmp_path / "lock.json"
    lock.write_text("{}")
    monkeypatch.setattr(prep, "LOCK_PATH", lock)
    with pytest.raises(ValueError, match="dependency selection differs"):
        prep.prepare(tmp_path / "packet")
    assert not (tmp_path / "packet").exists()


@pytest.mark.parametrize("count", [True, 0, -1, 1.0])
def test_dependency_size_rejects_coercion(count):
    entry = json.loads(prep.LOCK_PATH.read_bytes())["dependencies"][0]
    entry["bytes"] = count
    with pytest.raises(ValueError, match="invalid dependency size"):
        prep.validate_dependency(entry)
