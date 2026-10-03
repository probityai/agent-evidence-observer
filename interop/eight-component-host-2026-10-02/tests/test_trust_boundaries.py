"""Exercise bounded prelaunch trust refusal without a native tool installation.

These tests use actual directory links, files, sockets and FIFOs. Injected
enumeration errors stand for an inaccessible host subtree even when CI runs as
root. Native complete-chain tests remain mandatory in ``test_host_chain.py``.
"""

from __future__ import annotations

import os
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings, strategies as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_host  # noqa: E402
import trust  # noqa: E402


def assert_refusal(call: Any, reason: str, caplog: pytest.LogCaptureFixture) -> None:
    """Check the exact exception and bounded public log message together."""
    with pytest.raises(trust.HostRefusal, match="^" + re.escape(reason) + "$"):
        call()
    assert "eight-component host refused: " + reason in caplog.text


def retire_unsafe_fixture(path: Path) -> None:
    """Retain a regular description and remove special nodes before CI upload.

    Artifact upload follows symlinks and cannot archive cyclic links, sockets
    or FIFOs safely. Their actual modes/link targets remain in this receipt and
    their tested exact refusal remains in the retained JUnit report.
    """
    if not os.path.lexists(path):
        return
    info = path.lstat()
    description = {"name": path.name, "mode": info.st_mode,
                   "link": os.readlink(path) if path.is_symlink() else None}
    path.with_name(path.name + ".fixture.json").write_text(json.dumps(description))
    if stat.S_ISDIR(info.st_mode):
        path.rmdir()
    else:
        path.unlink()


class TestRegularFile:
    """Check real descriptor type, byte budget, path and invocation selection."""

    class TestPassingCases:
        @given(st.binary(max_size=4096))
        @settings(max_examples=40)
        def test_exact_bytes_and_empty_files(self, raw: bytes) -> None:
            from tempfile import TemporaryDirectory

            with TemporaryDirectory() as directory:
                path = Path(directory) / "selected"
                path.write_bytes(raw)
                assert trust.read_regular(path, "file refused", limit=len(raw)) == raw
                assert trust.check_file(trust.file_binding(path), "file refused") == path

        def test_intentional_interpreter_invocation_link(self, tmp_path: Path) -> None:
            target = tmp_path / "python-real"
            target.write_bytes(b"selected interpreter bytes")
            invocation = tmp_path / "python"
            invocation.symlink_to(target)
            binding = trust.file_binding(target)
            binding["invocationPath"] = str(invocation)
            assert trust.check_file(binding, "file refused") == target

    class TestFailingCases:
        @pytest.mark.parametrize("kind", ["fifo", "socket", "directory", "symlink", "missing"])
        def test_unsafe_selected_files_refuse_before_read(
            self, kind: str, tmp_path: Path, caplog: pytest.LogCaptureFixture,
        ) -> None:
            path = tmp_path / "selected"
            if kind == "fifo":
                os.mkfifo(path)
            elif kind == "socket":
                os.mknod(path, stat.S_IFSOCK | 0o600)
            elif kind == "directory":
                path.mkdir()
            elif kind == "symlink":
                target = tmp_path / "target"
                target.write_bytes(b"selected")
                path.symlink_to(target)
            try:
                assert_refusal(lambda: trust.read_regular(path, "file refused"), "file refused", caplog)
            finally:
                retire_unsafe_fixture(path)

        def test_byte_budget_checked_before_read(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
            path = tmp_path / "selected"
            path.write_bytes(b"five!")
            assert_refusal(lambda: trust.read_regular(path, "file refused", limit=4), "file refused", caplog)

        def test_relative_path_refused(self, caplog: pytest.LogCaptureFixture) -> None:
            assert_refusal(lambda: trust.read_regular(Path("trust.py"), "file refused"), "file refused", caplog)

        def test_same_size_different_bytes_refused(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
            path = tmp_path / "selected"
            path.write_bytes(b"original")
            binding = trust.file_binding(path)
            path.write_bytes(b"changed!")
            assert_refusal(lambda: trust.check_file(binding, "file refused"), "file refused", caplog)

        def test_invocation_target_substitution_refused(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
        ) -> None:
            path = tmp_path / "selected"
            path.write_bytes(b"same bytes")
            other = tmp_path / "other"
            other.write_bytes(path.read_bytes())
            binding = trust.file_binding(path)
            binding["invocationPath"] = str(other)
            assert_refusal(lambda: trust.check_file(binding, "file refused"), "file refused", caplog)

        def test_cyclic_path_link_refused(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
            path = tmp_path / "cycle"
            path.symlink_to(path)
            try:
                assert_refusal(lambda: trust.read_regular(path, "file refused"), "file refused", caplog)
            finally:
                retire_unsafe_fixture(path)


class TestTreeClosure:
    """Bound every tree entry, reject links/special files and retain read errors."""

    class TestPassingCases:
        def test_regular_closure_includes_nested_git(self, tmp_path: Path) -> None:
            (tmp_path / ".git").mkdir()
            (tmp_path / ".git/inert").write_bytes(b"metadata")
            (tmp_path / "package/.git").mkdir(parents=True)
            (tmp_path / "package/.git/extra.py").write_bytes(b"selected")
            (tmp_path / "module.py").write_bytes(b"selected")
            assert trust.source_file_names(tmp_path) == {"package/.git/extra.py", "module.py"}
            assert trust.installation_file_names(tmp_path) == {
                ".git/inert", "package/.git/extra.py", "module.py",
            }

        def test_empty_tree_and_exact_limits(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
            assert trust.installation_file_names(tmp_path) == set()
            (tmp_path / "one.py").write_bytes(b"one")
            monkeypatch.setattr(trust, "MAX_TREE_ENTRIES", 1)
            monkeypatch.setattr(trust, "MAX_TREE_DEPTH", 0)
            assert trust.installation_file_names(tmp_path) == {"one.py"}

    class TestFailingCases:
        @pytest.mark.parametrize("boundary", ["source", "installed"])
        @pytest.mark.parametrize("kind", ["fifo", "directory-link", "file-link", "broken-link"])
        def test_unselected_unsafe_entries_refused(
            self, boundary: str, kind: str, tmp_path: Path, caplog: pytest.LogCaptureFixture,
        ) -> None:
            root = tmp_path / "root"
            root.mkdir()
            path = root / "unselected"
            target = tmp_path / "target"
            if kind == "fifo":
                os.mkfifo(path)
                suffix = " contains a nonregular file"
            else:
                if kind == "directory-link":
                    target.mkdir()
                elif kind == "file-link":
                    target.write_bytes(b"unselected")
                path.symlink_to(target)
                suffix = " directory redirects"
            call = trust.source_file_names if boundary == "source" else trust.installation_file_names
            prefix = "pinned component source" if boundary == "source" else "installed package"
            try:
                assert_refusal(lambda: call(root), prefix + suffix, caplog)
            finally:
                retire_unsafe_fixture(path)

        def test_root_link_refused(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
            root = tmp_path / "real"
            root.mkdir()
            alias = tmp_path / "alias"
            alias.symlink_to(root)
            try:
                assert_refusal(lambda: trust.source_file_names(alias), "pinned component source root redirects", caplog)
            finally:
                retire_unsafe_fixture(alias)

        def test_missing_root_refused(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
            assert_refusal(lambda: trust.installation_file_names(tmp_path / "missing"),
                           "installed package enumeration failed", caplog)

        def test_root_git_link_is_not_ignored(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
            path = tmp_path / ".git"
            path.symlink_to(tmp_path / "missing")
            try:
                assert_refusal(lambda: trust.source_file_names(tmp_path), "pinned component source directory redirects", caplog)
            finally:
                retire_unsafe_fixture(path)

        @pytest.mark.parametrize("scope", ["root", "descendant"])
        def test_enumeration_errors_are_not_silent(
            self, scope: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
        ) -> None:
            child = tmp_path / "child"
            child.mkdir()
            original = os.scandir
            rejected = tmp_path if scope == "root" else child

            def fail_selected(path: Path) -> Any:
                if Path(path) == rejected:
                    raise PermissionError("inaccessible subtree")
                return original(path)

            monkeypatch.setattr(os, "scandir", fail_selected)
            assert_refusal(lambda: trust.installation_file_names(tmp_path), "installed package enumeration failed", caplog)

        def test_empty_directories_count_against_entry_budget(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
        ) -> None:
            (tmp_path / "one").mkdir()
            (tmp_path / "two").mkdir()
            monkeypatch.setattr(trust, "MAX_TREE_ENTRIES", 1)
            assert_refusal(lambda: trust.installation_file_names(tmp_path), "installed package entries exceed budget", caplog)

        def test_empty_directories_count_against_depth_budget(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
        ) -> None:
            (tmp_path / "one/two").mkdir(parents=True)
            monkeypatch.setattr(trust, "MAX_TREE_DEPTH", 1)
            assert_refusal(lambda: trust.installation_file_names(tmp_path), "installed package depth exceeds budget", caplog)

        @pytest.mark.parametrize("scope", ["file", "total"])
        def test_file_bytes_count_before_any_content_reads(
            self, scope: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
        ) -> None:
            (tmp_path / "one").write_bytes(b"four")
            (tmp_path / "two").write_bytes(b"four")
            budget = "MAX_FILE_BYTES" if scope == "file" else "MAX_TREE_BYTES"
            monkeypatch.setattr(trust, budget, 3 if scope == "file" else 7)
            reason = "installed package " + ("file exceeds byte budget" if scope == "file" else "total bytes exceed budget")
            assert_refusal(lambda: trust.installation_file_names(tmp_path), reason, caplog)

        def test_entry_stat_errors_refused(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
        ) -> None:
            class BrokenEntry:
                def stat(self, *, follow_symlinks: bool) -> Any:
                    raise PermissionError("inaccessible entry")

            class BrokenScan:
                def __enter__(self) -> Any:
                    return iter([BrokenEntry()])

                def __exit__(self, *args: Any) -> None:
                    pass

            monkeypatch.setattr(os, "scandir", lambda _: BrokenScan())
            assert_refusal(lambda: trust.installation_file_names(tmp_path), "installed package enumeration failed", caplog)


class TestHostPrelaunch:
    """Retain real launcher decisions proving filesystem refusals start no child."""

    class TestFailingCases:
        def test_fifo_manifest_refused_without_a_child(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
        ) -> None:
            manifest = tmp_path / "manifest.json"
            os.mkfifo(manifest)

            def unexpected_child(*args: Any, **kwargs: Any) -> None:
                pytest.fail("a child started before trust selection")

            monkeypatch.setattr(run_host, "run_child", unexpected_child)
            try:
                result = run_host.execute(manifest, "0" * 64, tmp_path / "candidate", tmp_path / "output")
            finally:
                retire_unsafe_fixture(manifest)
            assert result["status"] == "refused"
            assert result["reason"] == "external host manifest digest differs"
            assert result["childProcesses"] == result["httpDispatchRequests"] == 0
            assert "external host manifest digest differs" in caplog.text

        @pytest.mark.parametrize("raw,reason", [
            (b'{"value":1e999}', "selected JSON is nonfinite"),
            (b'{"nested":{"value":-1e999}}', "selected JSON is nonfinite"),
            (b'{"value":NaN}', "selected JSON is nonfinite"),
            (b'{"value":Infinity}', "selected JSON is nonfinite"),
            (b'{"nested":' + b'[' * 20_000 + b'0' + b']' * 20_000 + b'}', "selected JSON is malformed"),
        ])
        def test_nonfinite_and_recursive_json_retains_no_child_decision(
            self, raw: bytes, reason: str, tmp_path: Path, caplog: pytest.LogCaptureFixture,
        ) -> None:
            manifest = tmp_path / "manifest.json"
            manifest.write_bytes(raw)
            output = tmp_path / "output"
            result = run_host.execute(manifest, trust.sha256(raw), tmp_path / "candidate", output)
            assert result["status"] == "refused"
            assert result["reason"] == reason
            assert result["childProcesses"] == result["httpDispatchRequests"] == 0
            assert trust.read_json(output / "decision.json") == result
            assert "eight-component host refused: " + reason in caplog.text
