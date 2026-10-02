"""Test selected transfers without downloading weights or invoking inference."""

import hashlib
import io
import json
import re
from copy import deepcopy
from urllib.error import URLError

import pytest
from hypothesis import given, strategies as st

import prepare_local_model as prep


def lock_for(payload=b"wheel"):
    """Construct a fully selected small dependency population."""
    entry = dict(name="fixture-wheel", version="1.0",
                 path="downloads/fixture_wheel-1.0-py3-none-any.whl",
                 url="https://files.pythonhosted.org/packages/fixture/fixture_wheel-1.0-py3-none-any.whl",
                 bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest())
    return dict(schema="probity-local-model-download-selection-v1",
                target=dict(os="Ubuntu 24.04", architecture="x86_64", python="3.12", distribution="CPython"),
                dependencyBytes=len(payload), dependencies=[entry])


@pytest.fixture
def selection(tmp_path, monkeypatch):
    """Freeze five primary files and one dependency under the real schema."""
    payloads = [b"model", b"source", b"original", b"quantized", b"tokenizer"]
    names = ["model.gguf", "downloads/llama_cpp_python-0.3.16.tar.gz",
             "original-card.txt", "quant-card.txt", "tokenizer-config.json"]
    pins = [(name, f"https://selected.example/{name}", len(raw), hashlib.sha256(raw).hexdigest())
            for name, raw in zip(names, payloads, strict=True)]
    monkeypatch.setattr(prep, "PINS", pins)
    lock = lock_for()
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(lock))
    monkeypatch.setattr(prep, "LOCK_PATH", path)
    responses = dict(zip([pin[1] for pin in pins], payloads, strict=True))
    responses[lock["dependencies"][0]["url"]] = b"wheel"
    calls = []

    def open_selected(url, timeout):
        calls.append((url, timeout))
        return io.BytesIO(responses[url])

    monkeypatch.setattr(prep.urllib.request, "urlopen", open_selected)
    return responses, calls


class TestDependencySelection:
    class TestPassingCases:
        def test_committed_population(self):
            lock = json.loads(prep.LOCK_PATH.read_bytes())
            totals = prep.expected_totals(prep.selected_items(lock))
            assert len(lock["dependencies"]) == 88
            assert totals == dict(model=105454144, source=50688636, metadata=15103, dependencies=121991890)
            assert sum(totals.values()) == 278149773
            assert 256 * prep.MIB < sum(totals.values()) < prep.TOTAL_LIMIT
            lines = prep.requirements_text(lock).splitlines()
            assert len(lines) == 88
            assert all("--hash=sha256:" in line for line in lines)

        @given(st.binary(min_size=1, max_size=1024))
        def test_size_and_hash_selection(self, payload):
            item = prep.dependency_items(lock_for(payload))[0]
            assert item.bytes == len(payload)
            assert item.sha256 == hashlib.sha256(payload).hexdigest()

    class TestFailingCases:
        @pytest.mark.parametrize(("field", "value", "message"), [
            ("name", None, "invalid dependency identity"),
            ("version", "1.0\n--index-url=bad", "invalid dependency identity"),
            ("path", "downloads/../fixture.whl", "invalid dependency path"),
            ("path", "/tmp/fixture.whl", "invalid dependency path"),
            ("url", None, "invalid dependency URL"),
            ("url", "https://files.pythonhosted.org.evil/packages/fixture.whl", "invalid dependency URL"),
            ("url", "http://files.pythonhosted.org/packages/fixture.whl", "invalid dependency URL"),
            ("bytes", True, "invalid dependency size"),
            ("bytes", 0, "invalid dependency size"),
            ("bytes", -1, "invalid dependency size"),
            ("sha256", "A" * 64, "invalid dependency digest"),
            ("sha256", None, "invalid dependency digest"),
        ])
        def test_invalid_wheel(self, field, value, message, caplog):
            entry = lock_for()["dependencies"][0]
            entry[field] = value
            with pytest.raises(ValueError, match=re.escape(message)):
                prep.validate_dependency(entry)
            assert message in caplog.text

        @pytest.mark.parametrize(("field", "value", "message"), [
            ("schema", "new", "unsupported dependency selection"),
            ("target", {}, "unsupported dependency target"),
            ("dependencies", [], "dependency selection must be nonempty"),
            ("dependencies", None, "dependency selection must be nonempty"),
            ("dependencyBytes", 1, "dependency byte total mismatch"),
            ("dependencyBytes", True, "dependency byte total mismatch"),
        ])
        def test_invalid_population(self, field, value, message, caplog):
            lock = lock_for()
            lock[field] = value
            with pytest.raises(ValueError, match=message):
                prep.dependency_items(lock)
            assert message in caplog.text

        def test_duplicate_identity(self, caplog):
            lock = lock_for()
            duplicate = deepcopy(lock["dependencies"][0])
            duplicate["name"] = "fixture_wheel"
            lock["dependencies"].append(duplicate)
            lock["dependencyBytes"] *= 2
            with pytest.raises(ValueError, match="duplicate dependency identity"):
                prep.dependency_items(lock)
            assert "duplicate dependency identity" in caplog.text

        @pytest.mark.parametrize("category", list(prep.CATEGORY_LIMITS))
        def test_category_overflow(self, category, caplog):
            item = prep.Download("item", "url", prep.CATEGORY_LIMITS[category] + 1, "0" * 64, category)
            message = f"{category} declaration exceeds limit"
            with pytest.raises(ValueError, match=message):
                prep.expected_totals([item])
            assert message in caplog.text

        def test_total_overflow(self, monkeypatch, caplog):
            monkeypatch.setattr(prep, "TOTAL_LIMIT", 1)
            with pytest.raises(ValueError, match="total download declaration exceeds limit"):
                prep.expected_totals([prep.Download("item", "url", 2, "0" * 64, "model")])
            assert "total download declaration exceeds limit" in caplog.text

        def test_duplicate_path(self, caplog):
            item = prep.dependency_items(lock_for())[0]
            with pytest.raises(ValueError, match="duplicate download path"):
                prep.expected_totals([item, item])
            assert "duplicate download path" in caplog.text


class TestTransferAccounting:
    class TestPassingCases:
        @given(st.binary(min_size=1, max_size=4096))
        def test_response_is_not_counted_twice(self, payload):
            item = prep.dependency_items(lock_for(payload))[0]
            account, destination = prep.Accounting(), io.BytesIO()
            count = prep.stream_payload(io.BytesIO(payload), destination, item, account)
            assert count == account.transferred == len(payload)
            assert destination.getvalue() == payload
            assert account.categories["dependencies"] == len(payload)

        def test_exact_category_boundary(self):
            account = prep.Accounting()
            account.charge("model", prep.CATEGORY_LIMITS["model"])
            assert account.transferred == prep.CATEGORY_LIMITS["model"]

    class TestFailingCases:
        def test_oversize_is_charged_but_not_written(self, caplog):
            item = prep.dependency_items(lock_for())[0]
            account, destination = prep.Accounting(), io.BytesIO()
            with pytest.raises(ValueError, match="download exceeds selected size"):
                prep.stream_payload(io.BytesIO(b"wheel!"), destination, item, account)
            assert account.transferred == 6
            assert destination.getvalue() == b""
            assert "download exceeds selected size" in caplog.text

        @pytest.mark.parametrize(("category", "message"), [
            ("model", "model transfer exceeds limit"),
            ("dependencies", "dependencies transfer exceeds limit"),
        ])
        def test_category_transfer_limit(self, category, message, caplog):
            with pytest.raises(ValueError, match=message):
                prep.Accounting().charge(category, prep.CATEGORY_LIMITS[category] + 1)
            assert message in caplog.text

        def test_total_transfer_limit(self, monkeypatch, caplog):
            monkeypatch.setattr(prep, "TOTAL_LIMIT", 4)
            account = prep.Accounting()
            with pytest.raises(ValueError, match="total transfer exceeds limit"):
                account.charge("model", 5)
            assert account.transferred == 5
            assert "total transfer exceeds limit" in caplog.text

        def test_deadline_before_read(self, monkeypatch, caplog):
            account = prep.Accounting(started=0)
            monkeypatch.setattr(prep.time, "monotonic", lambda: prep.DOWNLOAD_SECONDS + 1)
            with pytest.raises(ValueError, match="download exceeds time budget"):
                prep.stream_payload(io.BytesIO(b"wheel"), io.BytesIO(), prep.dependency_items(lock_for())[0], account)
            assert account.transferred == 0
            assert "download exceeds time budget" in caplog.text


class TestPreparation:
    class TestPassingCases:
        def test_single_transfers_and_receipts(self, tmp_path, selection):
            responses, calls = selection
            root = tmp_path / "attempt"
            prep.prepare(root)
            account = json.loads((root / "download-accounting.json").read_bytes())
            declaration = json.loads((root / "download-declaration.json").read_bytes())
            assert account["status"] == "verified"
            assert account["actualResponseBodyBytes"] == sum(map(len, responses.values()))
            assert account["retainedPayloadBytes"] == account["actualResponseBodyBytes"]
            assert len(calls) == len({url for url, _ in calls}) == 6
            assert all(timeout == 30 for _, timeout in calls)
            assert declaration["expectedTotalPayloadBytes"] == account["actualResponseBodyBytes"]
            assert all(record["status"] == "verified" for record in account["files"])
            assert "--hash=sha256:" in (root / "requirements.txt").read_text()

        def test_provenance_binds_accounting(self, tmp_path, selection):
            root = tmp_path / "attempt"
            prep.prepare(root)
            (root / "build-gcc.log").write_text("selected bounded build")
            prep.finalize(root)
            provenance = json.loads((root / "provenance.json").read_bytes())
            assert provenance["sources"]["download-accounting.json"] == prep.sha(root / "download-accounting.json")
            assert provenance["sources"]["dependency-lock.json"] == prep.sha(root / "dependency-lock.json")

    class TestFailingCases:
        @pytest.mark.parametrize(("payload", "message"), [
            (b"", "selected download mismatch"),
            (b"wrong", "selected download mismatch"),
            (b"model!", "download exceeds selected size"),
        ])
        def test_refusal_retains_size_and_error(self, tmp_path, selection, payload, message, caplog):
            responses, calls = selection
            responses[prep.PINS[0][1]] = payload
            root = tmp_path / "attempt"
            with pytest.raises(ValueError, match=message):
                prep.prepare(root)
            account = json.loads((root / "download-accounting.json").read_bytes())
            assert account["status"] == "refused"
            assert account["error"] == f"ValueError: {message}"
            assert account["actualResponseBodyBytes"] == len(payload)
            assert account["files"][0]["status"] == "refused"
            assert len(calls) == 1
            assert not (root / "downloads.json").exists()
            assert not (root / "provenance.json").exists()
            assert message in caplog.text

        @pytest.mark.parametrize("name", ["model.gguf", "downloads/llama_cpp_python-0.3.16.tar.gz", "downloads/fixture_wheel-1.0-py3-none-any.whl"])
        def test_changed_payload_cannot_finalize(self, tmp_path, selection, name, caplog):
            root = tmp_path / "attempt"
            prep.prepare(root)
            (root / name).write_bytes(b"replacement")
            with pytest.raises(ValueError, match="selected retained payload mismatch"):
                prep.finalize(root)
            assert not (root / "provenance.json").exists()
            assert "selected retained payload mismatch" in caplog.text

        @pytest.mark.parametrize(("name", "message"), [
            ("dependency-lock.json", "retained dependency selection mismatch"),
            ("requirements.txt", "retained requirements mismatch"),
        ])
        def test_adjacent_selection_cannot_replace_committed_selection(self, tmp_path, selection, name, message, caplog):
            root = tmp_path / "attempt"
            prep.prepare(root)
            (root / name).write_text("changed selection")
            with pytest.raises(ValueError, match=message):
                prep.verify_retained(root)
            assert message in caplog.text

        def test_network_refusal_does_not_retry(self, tmp_path, selection, monkeypatch, caplog):
            calls = []

            def refuse(url, timeout):
                calls.append(url)
                raise URLError("selected network refusal")

            monkeypatch.setattr(prep.urllib.request, "urlopen", refuse)
            root = tmp_path / "attempt"
            with pytest.raises(URLError, match="selected network refusal"):
                prep.prepare(root)
            account = json.loads((root / "download-accounting.json").read_bytes())
            assert len(calls) == 1
            assert account["actualResponseBodyBytes"] == 0
            assert account["files"][0]["errorType"] == "URLError"
            assert account["status"] == "refused"
            assert "selected network refusal" in caplog.text

        def test_existing_attempt_is_preserved(self, tmp_path, selection):
            root = tmp_path / "attempt"
            prep.prepare(root)
            original = (root / "download-accounting.json").read_bytes()
            with pytest.raises(FileExistsError, match=re.escape(str(root))):
                prep.prepare(root)
            assert (root / "download-accounting.json").read_bytes() == original

        def test_refused_accounting_cannot_finalize(self, tmp_path, caplog):
            prep.write(tmp_path / "download-accounting.json", {"status": "refused"})
            with pytest.raises(ValueError, match="download accounting is not verified"):
                prep.finalize(tmp_path)
            assert not (tmp_path / "provenance.json").exists()
            assert "download accounting is not verified" in caplog.text
