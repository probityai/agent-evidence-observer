"""Bounded isolated installation and prelaunch refusal controls."""
from __future__ import annotations

import hashlib
import logging
import json
import os
import sys
from pathlib import Path

import pytest
from hypothesis import given, strategies as st

import joint_host_gate as host
import verify_upgrade as upgrade
from test_host_gate import selected_files


def selected(tmp_path: Path):
    """Select explicit nonreader fixture bytes outside an empty packet."""
    return selected_files(tmp_path, {"fixture": "installation-boundary-only"})


def refuses(tmp_path: Path, selection: tuple, caplog, expected: str):
    """Check the literal refusal and absence of any reader launch record."""
    packet, pins, policy, digest, reader = selection
    output = tmp_path / "refusal-receipts"
    with caplog.at_level(logging.WARNING):
        result = host.gate(packet, pins, policy, digest, reader, output)
    assert result["decision"] == "refuse"
    assert result["reason"] == expected
    assert result["readerReturncode"] is None
    assert not (output / "launch.json").exists()
    assert "Joint recovery refused: " + expected in caplog.messages


class TestInstalledSelection:
    """Installation bytes are necessary alongside explicit runtime isolation."""

    class TestPassingCases:
        def test_standard_library_alias_is_selected_once(self, tmp_path: Path):
            _, _, _, _, reader = selected(tmp_path)
            prefix = reader.parent.parent
            (prefix / "lib64").symlink_to("lib", target_is_directory=True)
            closure = host.reader_closure(reader)
            assert closure["files"]["lib64"] == {
                "type": "symlink", "link": "lib", "target": str(prefix / "lib")
            }

        @given(st.binary(max_size=4096))
        def test_regular_bytes_are_exactly_selected(self, raw: bytes):
            import tempfile
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "selected"
                path.write_bytes(raw)
                observed = host.selected_file(path)
            assert observed["size"] == len(raw)
            assert observed["sha256"] == hashlib.sha256(raw).hexdigest()

        def test_finite_bounds_admit_exact_limit(self, tmp_path: Path, monkeypatch):
            path = tmp_path / "member"
            path.write_bytes(b"abc")
            monkeypatch.setattr(host, "MAX_INSTALL_FILE", 3)
            monkeypatch.setattr(host, "MAX_INSTALL_BYTES", 3)
            assert host.installation_inventory(tmp_path)["member"]["size"] == 3

    class TestFailingCases:
        @pytest.mark.parametrize("config", [
            "", "include-system-site-packages = true\n",
            "include-system-site-packages = false\ninclude-system-site-packages = true\n",
            "include-system-site-packages = false\ninclude-system-site-packages = false\n",
            "include-system-site-packages = sometimes\n",
        ])
        def test_ambiguous_or_unisolated_config_refuses(self, tmp_path, caplog, config):
            selection = selected(tmp_path)
            (selection[-1].parent.parent / "pyvenv.cfg").write_text(config)
            refuses(tmp_path, selection, caplog, "reader-system-packages")

        @pytest.mark.parametrize("override", ["file", "broken-link"])
        def test_bin_config_override_refuses(self, tmp_path, caplog, override):
            selection = selected(tmp_path)
            path = selection[-1].parent / "pyvenv.cfg"
            if override == "file":
                path.write_text("include-system-site-packages = true\n")
            else:
                path.symlink_to("missing-config")
            refuses(tmp_path, selection, caplog, "reader-config-override")

        @pytest.mark.parametrize("kind", ["external", "internal"])
        def test_unsupported_directory_alias_refuses(self, tmp_path, caplog, kind):
            selection = selected(tmp_path)
            prefix = selection[-1].parent.parent
            target = tmp_path if kind == "external" else prefix / "lib"
            (prefix / "injected-directory").symlink_to(target, target_is_directory=True)
            refuses(tmp_path, selection, caplog, "reader-install-directory-link")

        def test_fifo_refuses_without_waiting_for_writer(self, tmp_path, caplog):
            selection = selected(tmp_path)
            os.mkfifo(selection[-1].parent.parent / "unselected-pipe")
            refuses(tmp_path, selection, caplog, "reader-install-regular-file")

        @pytest.mark.parametrize("member", ["launcher", "metadata"])
        def test_selected_fifo_refuses_before_early_parse(self, tmp_path, caplog, member):
            selection = selected(tmp_path)
            reader = selection[-1]
            path = reader if member == "launcher" else next(reader.parent.parent.glob("lib/python*/site-packages/*.dist-info/METADATA"))
            path.unlink()
            os.mkfifo(path)
            refuses(tmp_path, selection, caplog, "reader-install-regular-file")

        @pytest.mark.parametrize("limit, value, expected", [
            ("MAX_INSTALL_FILE", 1, "reader-install-file-bound"),
            ("MAX_INSTALL_BYTES", 1, "reader-install-byte-bound"),
            ("MAX_INSTALL_FILES", 1, "reader-closure-population-limit"),
            ("MAX_INSTALL_ENTRIES", 1, "reader-install-entry-bound"),
            ("MAX_INSTALL_DEPTH", 0, "reader-install-depth-bound"),
        ])
        def test_excessive_selection_refuses_before_launch(self, tmp_path, caplog, monkeypatch, limit, value, expected):
            selection = selected(tmp_path)
            monkeypatch.setattr(host, limit, value)
            refuses(tmp_path, selection, caplog, expected)

        def test_unreadable_tree_cannot_disappear(self, tmp_path, monkeypatch, caplog):
            real_scandir = os.scandir
            denied = tmp_path / "denied"
            denied.mkdir()
            def inaccessible(path):
                if Path(path) == denied:
                    raise PermissionError("explicit-unreadable-directory")
                return real_scandir(path)
            monkeypatch.setattr(os, "scandir", inaccessible)
            with pytest.raises(PermissionError, match="^explicit-unreadable-directory$"):
                host.installed_names(tmp_path)
            assert not caplog.messages


class TestIsolatedExecution:
    """An unselected working-directory import cannot run before the reader."""

    class TestPassingCases:
        def test_current_directory_injection_is_not_executed(self, tmp_path, monkeypatch):
            _, _, _, _, reader = selected(tmp_path)
            marker = tmp_path / "injected-marker"
            reader.write_text("#!" + str(reader.parent / "python") +
                              "\nimport json,sys\nprint(json.dumps(sys.path))\n")
            reader.chmod(0o755)
            cwd = tmp_path / "unselected-current-directory"
            cwd.mkdir()
            (cwd / "sitecustomize.py").write_text("from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('executed')\n")
            monkeypatch.chdir(cwd)
            output = tmp_path / "execution"
            output.mkdir()
            assert host.execute(tmp_path, reader, output) == 0
            assert not marker.exists()
            assert str(cwd).encode() not in (output / "reader.stdout").read_bytes()

    class TestFailingCases:
        def test_changed_reader_bytes_are_not_reselected(self, tmp_path, caplog):
            selection = selected(tmp_path)
            selection[-1].write_text("changed selected launcher")
            refuses(tmp_path, selection, caplog, "host-selection")


class TestUpgradeCommand:
    """Actual subprocess outputs survive both completion and timeout."""

    class TestPassingCases:
        def test_original_stdout_is_preserved(self, tmp_path):
            result = upgrade.command([sys.executable, "-c", "print('complete')"], tmp_path, "complete")
            assert result == b"complete\n"
            assert (tmp_path / "complete.stdout").read_bytes() == result
            assert json.loads((tmp_path / "complete.process.json").read_bytes())["timedOut"] is False

    class TestFailingCases:
        def test_timeout_preserves_partial_streams(self, tmp_path, monkeypatch, caplog):
            monkeypatch.setattr(upgrade, "MAX_COMMAND_SECONDS", 1)
            argv = [sys.executable, "-c", "import sys,time; print('partial',flush=True); print('diagnostic',file=sys.stderr,flush=True); time.sleep(2)"]
            with caplog.at_level(logging.WARNING), pytest.raises(ValueError, match="^upgrade-command-outcome: timeout$"):
                upgrade.command(argv, tmp_path, "timeout")
            assert (tmp_path / "timeout.stdout").read_bytes() == b"partial\n"
            assert (tmp_path / "timeout.stderr").read_bytes() == b"diagnostic\n"
            metadata = json.loads((tmp_path / "timeout.process.json").read_bytes())
            assert metadata["timedOut"] is True
            assert metadata["returncode"] == 124
            assert "Joint upgrade refused: upgrade-command-outcome: timeout" in caplog.messages
