"""Exercise byte custody, source pinning and unsafe-archive refusal controls."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import logging
import stat
import sys
import urllib.request
import zipfile
from pathlib import Path

import pytest
from hypothesis import given, strategies as st

MODULE_PATH = Path(__file__).resolve().parents[1] / "retain_archive.py"
SPEC = importlib.util.spec_from_file_location("selected_archive_retention", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
retention = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = retention
SPEC.loader.exec_module(retention)


@pytest.fixture
def metadata():
    """Provide native metadata with every original source pin satisfied."""
    artifact = {
        "id": retention.ARTIFACT_ID,
        "workflow_run": {"id": retention.RUN_ID, "head_sha": retention.SOURCE_HEAD},
        "size_in_bytes": retention.EXPECTED_BYTES,
        "digest": f"sha256:{retention.EXPECTED_SHA256}",
        "expired": False,
        "expires_at": "2077-01-01T00:00:00Z",
    }
    run = {"id": retention.RUN_ID, "head_sha": retention.SOURCE_HEAD,
           "repository": {"full_name": retention.REPOSITORY}}
    return artifact, run


class FragmentedStream(io.BytesIO):
    """Model legal short reads from a network response."""

    def read(self, size=-1):
        """Limit each read to seven bytes regardless of requested capacity."""
        return super().read(min(size, 7) if size >= 0 else 7)


class TestArchiveCustody:
    """Check exact transport and refusal conditions independently of a runner."""

    class TestPassingCases:
        """Valid byte streams, source identities and safe members are accepted."""

        @given(st.binary(max_size=2048))
        def test_fragmented_network_copy_is_exact(self, payload):
            output = io.BytesIO()
            digest = retention.copy_and_hash(FragmentedStream(payload), output, len(payload))
            assert output.getvalue() == payload
            assert digest == hashlib.sha256(payload).hexdigest()

        @pytest.mark.parametrize("payload,part_bytes", [
            (b"x", 8), (bytes(range(128)), 32), (b"a" * 64, 32),
            (b"different byte ranges" * 11, 32),
        ])
        def test_parts_reconstruct_original_and_authenticate_ranges(self, tmp_path, payload, part_bytes):
            original = tmp_path / "original.zip"
            original.write_bytes(payload)
            output = tmp_path / "parts"
            rows = retention.split_archive(original, output, part_bytes)
            recovered = b"".join((output / row["name"]).read_bytes() for row in rows)
            assert recovered == payload
            assert original.read_bytes() == payload
            assert len(rows) == (len(payload) + part_bytes - 1) // part_bytes
            for index, row in enumerate(rows):
                actual = (output / row["name"]).read_bytes()
                assert row == {"index": index, "name": f"part-{index:03d}.bin",
                               "offset": index * part_bytes, "bytes": len(actual),
                               "sha256": hashlib.sha256(actual).hexdigest()}

        def test_source_metadata_accepts_exact_pins(self, metadata):
            retention.validate_metadata(*metadata)

        @pytest.mark.parametrize("name", ["a.json", "a/b/c.whl", "folder/"])
        def test_safe_member_names(self, name):
            names = set()
            retention.validate_member(zipfile.ZipInfo(name), names)
            assert names == {name}

        def test_entire_member_readback_retains_exact_selected_json(self, tmp_path, monkeypatch):
            payload = b'{"original":true}\n'
            name = "tool-argument-preparation/run/report.json"
            original = tmp_path / "original.zip"
            with zipfile.ZipFile(original, "w") as archive:
                archive.writestr(name, payload)
            monkeypatch.setattr(retention, "EXPECTED_MEMBERS", 1)
            monkeypatch.setattr(retention, "EXPECTED_UNCOMPRESSED_BYTES", len(payload))
            monkeypatch.setattr(retention, "SELECTED_MEMBERS", {
                name: (len(payload), hashlib.sha256(payload).hexdigest())})
            output = tmp_path / "metadata"
            output.mkdir()
            receipt = retention.verify_zip(original, output)
            assert receipt["members"][0]["sha256"] == hashlib.sha256(payload).hexdigest()
            assert receipt["allMembersRead"] is True
            assert receipt["archiveCodeExecuted"] is False
            assert (output / "original-report.json").read_bytes() == payload
            assert json.loads((output / "members.json").read_bytes()) == receipt
            assert not (tmp_path / "tool-argument-preparation").exists()

        def test_blob_download_has_no_github_authorization(self, tmp_path, monkeypatch):
            payload = b"opaque original archive bytes"
            requests = []

            class Opener:
                def open(self, request, timeout):
                    requests.append(request)
                    return io.BytesIO(payload)

            monkeypatch.setattr(retention, "EXPECTED_BYTES", len(payload))
            monkeypatch.setattr(retention, "EXPECTED_SHA256", hashlib.sha256(payload).hexdigest())
            monkeypatch.setattr(retention, "download_location", lambda token: "https://example.invalid/archive")
            monkeypatch.setattr(retention.urllib.request, "build_opener", lambda *args: Opener())
            output = tmp_path / "original.zip"
            retention.download_original(output, "ephemeral-fixture-token")
            assert output.read_bytes() == payload
            assert requests[0].get_header("Authorization") is None
            assert "ephemeral-fixture-token" not in repr(requests[0].header_items())
            assert not output.with_suffix(".partial").exists()

        def test_authenticated_redirect_is_never_automatically_followed(self):
            request = urllib.request.Request("https://api.github.com/test", headers={"Authorization": "fixture"})
            assert retention.NoRedirect().redirect_request(
                request, None, 302, "Found", {}, "https://example.invalid/blob") is None

    class TestFailingCases:
        """Changed source metadata, lengths and archive member semantics fail."""

        @pytest.mark.parametrize("payload,expected,message", [
            (b"abcd", 3, "Stream exceeds its expected byte length."),
            (b"abc", 4, "Stream is shorter than its expected byte length."),
            (b"", -1, "Expected byte length must be nonnegative."),
        ])
        def test_wrong_stream_lengths(self, payload, expected, message, caplog):
            with caplog.at_level(logging.ERROR), pytest.raises(ValueError, match=f"^{message.replace('.', r'\.')}$"):
                retention.copy_and_hash(io.BytesIO(payload), io.BytesIO(), expected)
            assert caplog.messages == [message]

        @pytest.mark.parametrize("key,value,message", [
            ("id", 0, "Original artifact ID differs."),
            ("workflow_run", {"id": 0}, "Original artifact owning run differs."),
            ("workflow_run", {"id": retention.RUN_ID, "head_sha": "changed"}, "Original artifact source head differs."),
            ("size_in_bytes", 0, "Original artifact provider length differs."),
            ("digest", "sha256:changed", "Original artifact provider digest differs."),
            ("expired", True, "Original artifact has expired."),
            ("expires_at", "2000-01-01T00:00:00Z", "Original artifact retention has ended."),
        ])
        def test_changed_provider_metadata(self, metadata, key, value, message, caplog):
            artifact, run = metadata
            artifact[key] = value
            with caplog.at_level(logging.ERROR), pytest.raises(ValueError) as caught:
                retention.validate_metadata(artifact, run)
            assert str(caught.value) == message
            assert caplog.messages == [message]

        @pytest.mark.parametrize("name,message", [
            ("../escape", "ZIP member path is unsafe."),
            ("/absolute", "ZIP member path is unsafe."),
            ("a/../../escape", "ZIP member path is unsafe."),
            ("a\\b", "ZIP member path is ambiguous or too deep."),
            ("C:/drive", "ZIP member path is ambiguous or too deep."),
        ])
        def test_unsafe_member_paths(self, name, message, caplog):
            with caplog.at_level(logging.ERROR), pytest.raises(ValueError) as caught:
                retention.validate_member(zipfile.ZipInfo(name), set())
            assert str(caught.value) == message
            assert caplog.messages == [message]

        @pytest.mark.parametrize("mode", [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFSOCK])
        def test_special_member_types(self, mode, caplog):
            info = zipfile.ZipInfo("member")
            info.external_attr = mode << 16
            with caplog.at_level(logging.ERROR), pytest.raises(ValueError) as caught:
                retention.validate_member(info, set())
            assert str(caught.value) == "ZIP member filesystem type is unsupported."
            assert caplog.messages == [str(caught.value)]

        def test_duplicate_member_names(self, caplog):
            with caplog.at_level(logging.ERROR), pytest.raises(ValueError) as caught:
                retention.validate_member(zipfile.ZipInfo("member"), {"member"})
            assert str(caught.value) == "ZIP member names are duplicated."
            assert caplog.messages == [str(caught.value)]

        @pytest.mark.parametrize("part_bytes", [0, -1, retention.PART_BYTES + 1])
        def test_invalid_part_bounds(self, tmp_path, part_bytes, caplog):
            with caplog.at_level(logging.ERROR), pytest.raises(ValueError) as caught:
                retention.split_archive(tmp_path / "missing", tmp_path / "parts", part_bytes)
            assert str(caught.value) == "Part byte bound is invalid."
            assert caplog.messages == [str(caught.value)]

        def test_finite_part_count(self, tmp_path, caplog):
            original = tmp_path / "too-many.zip"
            original.write_bytes(b"x" * (retention.MAX_PARTS + 1))
            with caplog.at_level(logging.ERROR), pytest.raises(ValueError) as caught:
                retention.split_archive(original, tmp_path / "parts", 1)
            assert str(caught.value) == "Archive requires an unsupported part count."
            assert caplog.messages == [str(caught.value)]
            assert not (tmp_path / "parts").exists()

        def test_wrong_original_digest_retains_only_partial(self, tmp_path, monkeypatch, caplog):
            payload = b"changed archive bytes"

            class Opener:
                def open(self, request, timeout):
                    return io.BytesIO(payload)

            monkeypatch.setattr(retention, "EXPECTED_BYTES", len(payload))
            monkeypatch.setattr(retention, "EXPECTED_SHA256", "0" * 64)
            monkeypatch.setattr(retention, "download_location", lambda token: "https://example.invalid/archive")
            monkeypatch.setattr(retention.urllib.request, "build_opener", lambda *args: Opener())
            original = tmp_path / "original.zip"
            with caplog.at_level(logging.ERROR), pytest.raises(ValueError) as caught:
                retention.download_original(original, "ephemeral-fixture-token")
            assert str(caught.value) == "Original ZIP byte digest differs."
            assert caplog.messages == [str(caught.value)]
            assert not original.exists()
            assert original.with_suffix(".partial").read_bytes() == payload
