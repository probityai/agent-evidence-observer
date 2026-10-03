"""Meaningful bounded extraction, charge accounting and offline installation controls."""
from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import subprocess
from pathlib import Path
import stat
import sys
import urllib.request
import zipfile

import pytest
from hypothesis import given, strategies as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import reusable_runtime as runtime


def identity(data: bytes) -> dict:
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def selected(name: str, data: bytes, *, category="model", path=None) -> dict:
    return {"archivePath": name, "path": path or name, "category": category, **identity(data)}


def fixture_archive(tmp_path: Path, *, data=b"model", mode=None):
    archive = tmp_path / "original.zip"
    with zipfile.ZipFile(archive, "w") as z:
        info = zipfile.ZipInfo("model.gguf")
        if mode is not None:
            info.create_system = 3
            info.external_attr = mode << 16
        z.writestr(info, data)
        z.writestr("unselected/hostile.py", "raise RuntimeError('must never execute')")
    protocol = {"runtimeReuse": {"archive": {"apiUrl": "https://api.github.com/repos/owner/repo/actions/artifacts/1/zip",
        "repository": "owner/repo", "artifactId": 1, **runtime.file_identity(archive)},
        "selectedFiles": [selected("model.gguf", data)], "originalPreparation": {"responseBodyBytes": 472221945},
        "wheels": [], "abi": {}}, "budgets": {"preparation_seconds": 180,
        "installation_seconds": 335, "network_operation_seconds": 30, "archive_download_bytes": 536870912,
        "retained_disk_bytes": 2147483648}}
    return archive, protocol


def refuses(caplog, message, call):
    with caplog.at_level(logging.ERROR), pytest.raises(ValueError, match="^" + message + "$"):
        call()
    assert message in caplog.messages


class TestReusableRuntime:
    class TestPassingCases:
        def test_local_archive_zero_charge_and_exact_selected_only(self, tmp_path):
            archive, p = fixture_archive(tmp_path)
            output = tmp_path / "prepared"
            result = runtime.prepare_archive(p, output, local_archive=archive)
            charge = json.loads((output / "archive-accounting.json").read_text())
            assert result["status"] == "passed"
            assert charge["responseBodyBytes"] == 0
            assert charge["networkAttempts"] == 0
            assert charge["originalPreparation"]["responseBodyBytes"] == 472221945
            assert (output / "extraction/model.gguf").read_bytes() == b"model"
            assert not (output / "extraction/unselected").exists()
            assert json.loads((output / "reuse-projection.json").read_text())["files"] == p["runtimeReuse"]["selectedFiles"]

        @given(st.binary(max_size=3 * runtime.CHUNK_BYTES))
        def test_bounded_stream_identity(self, data):
            import tempfile
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "payload"
                accounting = {"responseBodyBytes": 0}
                runtime._copy_stream(io.BytesIO(data), path, len(data), runtime.time.monotonic(), 10, accounting)
                assert runtime.file_identity(path) == identity(data)
                assert accounting == {"responseBodyBytes": len(data), "sha256": identity(data)["sha256"]}

        def test_same_archive_entry_can_preserve_original_receipt(self, tmp_path):
            archive, p = fixture_archive(tmp_path)
            p["runtimeReuse"]["selectedFiles"].append(selected("model.gguf", b"model", category="receipt", path="original/model.gguf"))
            projection = runtime.extract_selected(p, archive, tmp_path / "extract")
            assert projection["selectedBytes"] == 10
            assert (tmp_path / "extract/original/model.gguf").read_bytes() == b"model"

        def test_download_once_exact_body_charge_and_no_payload_requests(self, tmp_path, monkeypatch):
            archive, p = fixture_archive(tmp_path)
            blob = archive.read_bytes()
            requests = []
            class Opener:
                def open(self, request, timeout):
                    requests.append((request, timeout))
                    return io.BytesIO(blob)
            monkeypatch.setenv("GH_TOKEN", "never-print-selected-secret")
            monkeypatch.setattr(runtime.urllib.request, "build_opener", lambda *args: Opener())
            charge = runtime.acquire_archive(p, tmp_path / "downloaded")
            assert len(requests) == 1
            assert requests[0][0].full_url == p["runtimeReuse"]["archive"]["apiUrl"]
            assert charge["networkAttempts"] == 1
            assert charge["responseBodyBytes"] == len(blob)
            assert charge["archiveIdentity"] == identity(blob)

        def test_redirect_strips_authentication(self):
            original = urllib.request.Request("https://api.github.com/selected", headers={"Authorization": "Bearer secret"})
            redirected = runtime._CredentialSafeRedirect().redirect_request(original, None, 302, "Found", {}, "https://objects.example/selected")
            assert not redirected.has_header("Authorization")

        def test_environment_removes_python_and_pip_hooks(self, monkeypatch):
            for key in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_TARGET", "GH_TOKEN", "LD_PRELOAD", "LD_LIBRARY_PATH"):
                monkeypatch.setenv(key, "hostile")
            sanitized = runtime.sanitized_environment()
            assert not any(value == "hostile" for value in sanitized.values())
            assert sanitized["PIP_CONFIG_FILE"] == runtime.os.devnull
            assert sanitized["PIP_NO_INDEX"] == "1"

        def test_install_uses_offline_hashed_wheels_and_exact_native_copy(self, tmp_path, monkeypatch):
            archive, p = fixture_archive(tmp_path)
            output = tmp_path / "prepared"
            runtime.prepare_archive(p, output, local_archive=archive)
            native = b"selected retained source"
            relative = "runtime/llama_cpp/__init__.py"
            row = selected("source/__init__.py", native, category="runtime", path=relative)
            p["runtimeReuse"]["selectedFiles"].append(row)
            path = output / "extraction" / relative
            path.parent.mkdir(parents=True)
            path.write_bytes(native)
            site = tmp_path / "environment/lib/python3.12/site-packages"
            commands = []
            def execute(command, start, seconds):
                commands.append(command)
                if "venv" in command:
                    site.mkdir(parents=True)
                if "sysconfig" in command[-1]:
                    return str(site) + "\n"
                if "import importlib.metadata" in command[-1]:
                    return "0.3.16\n"
                return ""
            monkeypatch.setattr(runtime, "_check_abi", lambda *args: None)
            monkeypatch.setattr(runtime, "_execute", execute)
            installed = runtime.install_runtime(p, output, tmp_path / "environment")
            command = next(command for command in commands if "pip" in command)
            assert all(flag in command for flag in ("-I", "-B", "--no-index", "--no-deps", "--require-hashes", "--no-cache-dir", "--no-compile"))
            assert installed["installedFiles"]["llama_cpp/__init__.py"] == identity(native)
            assert installed["nativeBuilds"] == installed["networkResponseBytes"] == 0
            assert installed["importProbe"] == "0.3.16"
            assert all("-I" in call and "-B" in call for call in commands)

    class TestFailingCases:
        @pytest.mark.parametrize("name", ["../escape", "/absolute", "a/../escape", "a//b", "a/./b", "a\\b", "C:escape", "", "a\x00b"])
        def test_unsafe_paths_refused(self, name, caplog):
            expected = "selected path contains a forbidden character" if name in {"a\\b", "C:escape", "a\x00b"} else "selected path is not a normalized relative path"
            refuses(caplog, expected, lambda: runtime._safe_relative(name))

        def test_wrong_archive_retains_failure_accounting(self, tmp_path, caplog):
            archive, p = fixture_archive(tmp_path)
            p["runtimeReuse"]["archive"]["sha256"] = "0" * 64
            output = tmp_path / "prepared"
            refuses(caplog, "selected file bytes or SHA256 mismatch", lambda: runtime.prepare_archive(p, output, local_archive=archive))
            assert json.loads((output / "archive-accounting.json").read_text())["status"] == "failed"
            assert json.loads((output / "preparation-terminal.json").read_text())["status"] == "failed"

        @pytest.mark.parametrize("mode", [stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o600, stat.S_IFDIR | 0o755])
        def test_nonregular_archive_entry_refused(self, tmp_path, caplog, mode):
            archive, p = fixture_archive(tmp_path, mode=mode)
            refuses(caplog, "selected archive entry is not an exact regular file", lambda: runtime.extract_selected(p, archive, tmp_path / "extract"))

        def test_selected_entry_digest_tamper_refused(self, tmp_path, caplog):
            archive, p = fixture_archive(tmp_path)
            p["runtimeReuse"]["selectedFiles"][0]["sha256"] = "0" * 64
            refuses(caplog, "selected file bytes or SHA256 mismatch", lambda: runtime.extract_selected(p, archive, tmp_path / "extract"))

        def test_duplicate_output_refused(self, tmp_path, caplog):
            archive, p = fixture_archive(tmp_path)
            p["runtimeReuse"]["selectedFiles"] *= 2
            refuses(caplog, "selected file paths must be unique", lambda: runtime.extract_selected(p, archive, tmp_path / "extract"))

        def test_disk_budget_refused_before_extraction(self, tmp_path, caplog):
            archive, p = fixture_archive(tmp_path)
            p["budgets"]["retained_disk_bytes"] = 1
            refuses(caplog, "retained disk byte budget exceeded", lambda: runtime.extract_selected(p, archive, tmp_path / "extract"))
            assert not (tmp_path / "extract").exists()

        def test_existing_output_refused(self, tmp_path, caplog):
            archive, p = fixture_archive(tmp_path)
            output = tmp_path / "extract"
            output.mkdir()
            refuses(caplog, "extraction output must be a fresh directory", lambda: runtime.extract_selected(p, archive, output))

        def test_partial_archive_charge_includes_overflow_bytes_and_no_retry(self, tmp_path, monkeypatch, caplog):
            archive, p = fixture_archive(tmp_path)
            p["budgets"]["archive_download_bytes"] = 1
            p["runtimeReuse"]["archive"]["bytes"] = 1
            attempts = []
            class Opener:
                def open(self, request, timeout):
                    attempts.append(request)
                    return io.BytesIO(archive.read_bytes())
            monkeypatch.setenv("GH_TOKEN", "secret")
            monkeypatch.setattr(runtime.urllib.request, "build_opener", lambda *args: Opener())
            output = tmp_path / "download"
            refuses(caplog, "archive response body byte budget exceeded", lambda: runtime.acquire_archive(p, output))
            charge = json.loads((output / "archive-accounting.json").read_text())
            assert len(attempts) == 1
            assert charge["responseBodyBytes"] == archive.stat().st_size
            assert charge["status"] == "failed"
            assert "secret" not in json.dumps(charge)

        def test_expired_preparation_records_failure(self, tmp_path, caplog):
            archive, p = fixture_archive(tmp_path)
            p["budgets"]["preparation_seconds"] = -1
            refuses(caplog, "preparation elapsed time budget exceeded", lambda: runtime.prepare_archive(p, tmp_path / "prepared", local_archive=archive))
            assert json.loads((tmp_path / "prepared/preparation-terminal.json").read_text())["status"] == "failed"

        def test_abi_mismatch_refused_with_installation_receipt(self, tmp_path, monkeypatch, caplog):
            archive, p = fixture_archive(tmp_path)
            p["runtimeReuse"]["abi"] = {"system": "Linux"}
            monkeypatch.setattr(runtime, "_execute", lambda *args: '{"system":"Other"}')
            output = tmp_path / "prepared"
            output.mkdir()
            refuses(caplog, "selected interpreter or host ABI mismatch", lambda: runtime.install_runtime(p, output, tmp_path / "env"))
            assert json.loads((output / "installation.json").read_text())["status"] == "failed"
            assert not (tmp_path / "env").exists()

        def test_symbolic_input_refused(self, tmp_path, caplog):
            target = tmp_path / "regular"
            target.write_bytes(b"selected")
            alias = tmp_path / "alias"
            alias.symlink_to(target)
            refuses(caplog, "selected input is not a regular file", lambda: runtime.file_identity(alias))


class TestRetainedReuseVerification:
    class TestPassingCases:
        def test_complete_projection_is_verified_without_effects(self, tmp_path):
            archive, p = fixture_archive(tmp_path)
            reuse = tmp_path / "packet/sources/reuse"
            runtime.prepare_archive(p, reuse, local_archive=archive)
            runtime._write_json(reuse / "installation.json", {"status": "passed", "nativeBuilds": 0,
                "networkResponseBytes": 0, "installedFiles": {}, "elapsedSeconds": 1,
                "installedBytes": 0, "retainedBytes": 100, "abi": p["runtimeReuse"]["abi"],
                "importProbe": "0.3.16"})
            assert runtime.verify_reuse(tmp_path / "packet", p) == {"status": "passed",
                "selectedFiles": 1, "nativeFiles": 0, "newArchiveResponseBodyBytes": 0,
                "inferencePerformed": False}

    class TestFailingCases:
        @pytest.mark.parametrize("field,value,message", [
            ("responseBodyBytes", 12, "retained archive response charge does not match its route"),
            ("networkAttempts", 1, "retained archive response charge does not match its route"),
            ("originalPreparation", {}, "retained original preparation history differs from selection"),
            ("providerCalls", 1, "retained archive charge contains unexpected provider use"),
            ("providerDollars", 1, "retained archive charge contains unexpected provider use"),
        ])
        def test_falsified_charges_are_refused(self, tmp_path, caplog, field, value, message):
            archive, p = fixture_archive(tmp_path)
            reuse = tmp_path / "packet/sources/reuse"
            runtime.prepare_archive(p, reuse, local_archive=archive)
            charge = json.loads((reuse / "archive-accounting.json").read_text())
            charge[field] = value
            runtime._write_json(reuse / "archive-accounting.json", charge)
            refuses(caplog, message, lambda: runtime.verify_reuse(tmp_path / "packet", p))

        def test_falsified_projection_refused(self, tmp_path, caplog):
            archive, p = fixture_archive(tmp_path)
            reuse = tmp_path / "packet/sources/reuse"
            runtime.prepare_archive(p, reuse, local_archive=archive)
            projection = json.loads((reuse / "reuse-projection.json").read_text())
            projection["files"][0]["sha256"] = "0" * 64
            runtime._write_json(reuse / "reuse-projection.json", projection)
            refuses(caplog, "retained runtime projection differs from selected identities",
                lambda: runtime.verify_reuse(tmp_path / "packet", p))



def complete_reuse_packet(tmp_path):
    archive, protocol = fixture_archive(tmp_path)
    reuse = tmp_path / "packet/sources/reuse"
    runtime.prepare_archive(protocol, reuse, local_archive=archive)
    runtime._write_json(reuse / "installation.json", {"status": "passed", "nativeBuilds": 0,
        "networkResponseBytes": 0, "installedFiles": {}, "elapsedSeconds": 1,
        "installedBytes": 0, "retainedBytes": 100, "abi": protocol["runtimeReuse"]["abi"],
        "importProbe": "0.3.16"})
    return protocol, reuse


class TestMeasuredReuseReceiptLimits:
    class TestPassingCases:
        @pytest.mark.parametrize("elapsed", [0, 180])
        def test_archive_and_preparation_duration_boundary(self, tmp_path, elapsed):
            p, reuse = complete_reuse_packet(tmp_path)
            for filename in ("archive-accounting.json", "preparation-terminal.json"):
                value = json.loads((reuse / filename).read_text())
                value["elapsedSeconds"] = elapsed
                runtime._write_json(reuse / filename, value)
            assert runtime.verify_reuse(tmp_path / "packet", p)["status"] == "passed"

        @pytest.mark.parametrize("elapsed", [0, 335])
        def test_installation_duration_boundary(self, tmp_path, elapsed):
            p, reuse = complete_reuse_packet(tmp_path)
            value = json.loads((reuse / "installation.json").read_text())
            value["elapsedSeconds"] = elapsed
            runtime._write_json(reuse / "installation.json", value)
            assert runtime.verify_reuse(tmp_path / "packet", p)["status"] == "passed"

        def test_exact_retained_disk_limit(self, tmp_path):
            p, reuse = complete_reuse_packet(tmp_path)
            value = json.loads((reuse / "installation.json").read_text())
            value["retainedBytes"] = p["budgets"]["retained_disk_bytes"]
            runtime._write_json(reuse / "installation.json", value)
            assert runtime.verify_reuse(tmp_path / "packet", p)["status"] == "passed"

    class TestFailingCases:
        @pytest.mark.parametrize("filename,message", [
            ("archive-accounting.json", "retained archive duration exceeds its budget or is invalid"),
            ("preparation-terminal.json", "retained preparation receipt exceeds its budget or failed"),
            ("installation.json", "retained installation duration exceeds its budget or is invalid"),
        ])
        @pytest.mark.parametrize("elapsed", [-1, None, True, "1", 336, 10**1000])
        def test_invalid_measured_duration(self, tmp_path, caplog, filename, message, elapsed):
            p, reuse = complete_reuse_packet(tmp_path)
            value = json.loads((reuse / filename).read_text())
            value["elapsedSeconds"] = elapsed
            runtime._write_json(reuse / filename, value)
            refuses(caplog, message, lambda: runtime.verify_reuse(tmp_path / "packet", p))

        @pytest.mark.parametrize("filename", ["archive-accounting.json", "preparation-terminal.json",
            "installation.json", "reuse-projection.json"])
        @pytest.mark.parametrize("raw,message", [
            ('{"status":"passed","status":"failed"}', "duplicate JSON member"),
            ('{"elapsedSeconds":NaN}', "nonfinite JSON"),
            ('{"elapsedSeconds":Infinity}', "nonfinite JSON"),
            ('{"elapsedSeconds":1e999}', "nonfinite JSON"),
        ])
        def test_duplicate_and_nonfinite_original_json(self, tmp_path, caplog, filename, raw, message):
            p, reuse = complete_reuse_packet(tmp_path)
            (reuse / filename).write_text(raw)
            refuses(caplog, message, lambda: runtime.verify_reuse(tmp_path / "packet", p))

        @pytest.mark.parametrize("field,value,message", [
            ("installedBytes", -1, "retained installed byte count exceeds retained bytes or is invalid"),
            ("installedBytes", 101, "retained installed byte count exceeds retained bytes or is invalid"),
            ("installedBytes", True, "retained installed byte count exceeds retained bytes or is invalid"),
            ("installedBytes", None, "retained installed byte count exceeds retained bytes or is invalid"),
            ("retainedBytes", -1, "retained installation disk byte count exceeds its budget or is invalid"),
            ("retainedBytes", 2147483649, "retained installation disk byte count exceeds its budget or is invalid"),
            ("retainedBytes", False, "retained installation disk byte count exceeds its budget or is invalid"),
            ("retainedBytes", 1.5, "retained installation disk byte count exceeds its budget or is invalid"),
            ("abi", {"system":"Other"}, "retained installation ABI or import probe differs from selection"),
            ("importProbe", "0.3.17", "retained installation ABI or import probe differs from selection"),
            ("nativeBuilds", 1, "retained installation receipt is not a passed offline reuse"),
            ("networkResponseBytes", 1, "retained installation receipt is not a passed offline reuse"),
            ("networkResponseBytes", False, "retained installation receipt is not a passed offline reuse"),
            ("installedFiles", [], "retained installation file identities must be an object"),
            ("installedFiles", {"file":{"bytes":1}}, "retained installation file byte count is invalid"),
            ("installedBytes", 1, "retained installed bytes differ from installation file identities"),
        ])
        def test_installation_receipt_mutations(self, tmp_path, caplog, field, value, message):
            p, reuse = complete_reuse_packet(tmp_path)
            installation = json.loads((reuse / "installation.json").read_text())
            installation[field] = value
            runtime._write_json(reuse / "installation.json", installation)
            refuses(caplog, message, lambda: runtime.verify_reuse(tmp_path / "packet", p))

        @pytest.mark.parametrize("field,value,message", [
            ("responseBodyBytes", -1, "retained archive response byte count exceeds its budget or is invalid"),
            ("responseBodyBytes", 536870913, "retained archive response byte count exceeds its budget or is invalid"),
            ("responseBodyBytes", False, "retained archive response byte count exceeds its budget or is invalid"),
            ("responseBodyBytes", 0.0, "retained archive response byte count exceeds its budget or is invalid"),
            ("networkAttempts", False, "retained archive network attempt count is invalid"),
            ("networkAttempts", 2, "retained archive network attempt count is invalid"),
        ])
        def test_archive_charge_typed_limits(self, tmp_path, caplog, field, value, message):
            p, reuse = complete_reuse_packet(tmp_path)
            charge = json.loads((reuse / "archive-accounting.json").read_text())
            charge[field] = value
            runtime._write_json(reuse / "archive-accounting.json", charge)
            refuses(caplog, message, lambda: runtime.verify_reuse(tmp_path / "packet", p))

        def test_preparation_charge_cannot_disagree_with_archive_charge(self, tmp_path, caplog):
            p, reuse = complete_reuse_packet(tmp_path)
            terminal = json.loads((reuse / "preparation-terminal.json").read_text())
            terminal["responseBodyBytes"] = 1
            runtime._write_json(reuse / "preparation-terminal.json", terminal)
            refuses(caplog, "retained preparation charge differs from archive accounting",
                lambda: runtime.verify_reuse(tmp_path / "packet", p))



class TestArchiveSocketTimeout:
    class TestPassingCases:
        @pytest.mark.parametrize("elapsed,network_limit,expected", [(0, 30, 30), (175, 30, 5), (170, 3, 3)])
        def test_socket_timeout_selects_network_or_remaining_preparation(self, tmp_path, monkeypatch, elapsed, network_limit, expected):
            archive, protocol = fixture_archive(tmp_path)
            protocol["budgets"]["network_operation_seconds"] = network_limit
            observed = []
            class Opener:
                def open(self, request, timeout):
                    observed.append(timeout)
                    return io.BytesIO(archive.read_bytes())
            monkeypatch.setenv("GH_TOKEN", "secret")
            monkeypatch.setattr(runtime.time, "monotonic", lambda: elapsed)
            monkeypatch.setattr(runtime.urllib.request, "build_opener", lambda *args: Opener())
            receipt = {"responseBodyBytes": 0}
            runtime._download(protocol, tmp_path / "received.zip", 0, receipt)
            assert observed == [expected]
            assert receipt["responseBodyBytes"] == archive.stat().st_size
            assert receipt["networkAttempts"] == 1

    class TestFailingCases:
        def test_elapsed_preparation_refuses_before_socket_open(self, tmp_path, monkeypatch, caplog):
            archive, protocol = fixture_archive(tmp_path)
            attempts = []
            monkeypatch.setenv("GH_TOKEN", "secret")
            monkeypatch.setattr(runtime.time, "monotonic", lambda: 181)
            monkeypatch.setattr(runtime.urllib.request, "build_opener", lambda *args: attempts.append(args))
            refuses(caplog, "preparation elapsed time budget exceeded",
                lambda: runtime._download(protocol, tmp_path / "received.zip", 0, {"responseBodyBytes": 0}))
            assert attempts == []
            assert not (tmp_path / "received.zip").exists()



class TestDescriptorBoundFileIdentity:
    class TestPassingCases:
        @pytest.mark.parametrize("raw", [b"", b"ordinary", b"x" * (runtime.CHUNK_BYTES + 19)])
        def test_regular_descriptor_exact_identity(self, tmp_path, raw):
            path = tmp_path / "regular"
            path.write_bytes(raw)
            assert runtime.file_identity(path) == identity(raw)

    class TestFailingCases:
        def test_fifo_is_refused_without_blocking(self, tmp_path, caplog):
            path = tmp_path / "selected.fifo"
            os.mkfifo(path)
            profile = str(Path(runtime.__file__).parent)
            script = "import sys;sys.path.insert(0,sys.argv[1]);from pathlib import Path;import reusable_runtime as r;r.file_identity(Path(sys.argv[2]))"
            process = subprocess.run([sys.executable, "-I", "-B", "-c", script, profile, str(path)],
                capture_output=True, text=True, timeout=2, check=False)
            assert process.returncode != 0
            assert "ValueError: selected input is not a regular file" in process.stderr
            refuses(caplog, "selected input is not a regular file", lambda: runtime.file_identity(path))

        @pytest.mark.parametrize("kind", ["link", "directory", "missing"])
        def test_final_member_replacement_refuses(self, tmp_path, caplog, kind):
            path = tmp_path / "selected"
            if kind == "link":
                original = tmp_path / "original"
                original.write_bytes(b"selected")
                path.symlink_to(original)
            if kind == "directory":
                path.mkdir()
            refuses(caplog, "selected input is not a regular file", lambda: runtime.file_identity(path))



class TestBytecodeFreeInterpreterCommands:
    class TestPassingCases:
        def test_abi_probe_uses_isolation_and_bytecode_suppression(self, tmp_path, monkeypatch):
            commands = []
            selected = {"system": "Linux"}
            def execute(command, start, seconds):
                commands.append(command)
                return json.dumps(selected)
            monkeypatch.setattr(runtime, "_execute", execute)
            runtime._check_abi(tmp_path / "selected-python", selected, 0, 335)
            assert len(commands) == 1
            assert commands[0][1:4] == ["-I", "-B", "-c"]

    class TestFailingCases:
        def test_bytecode_suppression_does_not_accept_wrong_abi(self, tmp_path, monkeypatch, caplog):
            monkeypatch.setattr(runtime, "_execute", lambda *args: '{"system":"Other"}')
            refuses(caplog, "selected interpreter or host ABI mismatch",
                lambda: runtime._check_abi(tmp_path / "selected-python", {"system":"Linux"}, 0, 335))
