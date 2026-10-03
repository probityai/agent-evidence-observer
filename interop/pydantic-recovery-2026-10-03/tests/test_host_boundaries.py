"""Altered host installations cannot block or exceed the selection budgets."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from probity_observer.crypto import VerificationError

from probity_pydantic_recovery.common import MAX_FILE
from recovery_host import gate, reader_closure, select_policy


def installation(root: Path) -> Path:
    """Create a real isolated tree with the ordinary selected interpreter link."""
    (root / "bin").mkdir(parents=True)
    (root / "pyvenv.cfg").write_text("include-system-site-packages = false\n")
    (root / "bin/python").symlink_to(sys.executable)
    executable = root / "bin/probity-read-pydantic-recovery"
    executable.write_bytes(b"selected console entry point")
    return executable


def test_complete_installation_selection_includes_linked_interpreter(tmp_path: Path) -> None:
    executable = installation(tmp_path / "venv")
    selected = reader_closure(executable)
    assert set(selected["files"]) == {"pyvenv.cfg", "bin/python", "bin/probity-read-pydantic-recovery"}
    assert selected["files"]["bin/python"]["symlink"] == sys.executable
    assert selected["files"]["bin/python"]["sha256"] == selected["interpreterSha256"]
    assert selected["interpreterBytes"] > 0


@pytest.mark.parametrize("kind", ["fifo", "directory", "oversize"])
def test_untrusted_file_selection_refuses_without_blocking(tmp_path: Path, kind: str) -> None:
    import recovery_host

    path = tmp_path / "changed-installation"
    if kind == "fifo":
        os.mkfifo(path)
    elif kind == "directory":
        path.mkdir()
    else:
        with path.open("wb") as stream:
            stream.truncate(recovery_host.MAX_INSTALL_FILE + 1)
    code = "from pathlib import Path; from recovery_host import select_file; select_file(Path(__import__('sys').argv[1]))"
    result = subprocess.run([sys.executable, "-c", code, str(path)], capture_output=True, timeout=5, check=False)
    assert result.returncode != 0
    expected = b"host-install-file-bound" if kind == "oversize" else b"host-install-regular-file"
    assert expected in result.stderr


def test_directory_symlink_cannot_hide_unselected_package_files(tmp_path: Path) -> None:
    executable = installation(tmp_path / "venv")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "__init__.py").write_text("raise RuntimeError('unselected package')")
    (executable.parent.parent / "unselected-package").symlink_to(outside, target_is_directory=True)
    with pytest.raises(VerificationError, match="host-install-directory-link"):
        reader_closure(executable)


@pytest.mark.parametrize("budget,limit,reason", [("MAX_INSTALL_FILES", 2, "host-install-file-population"), ("MAX_INSTALL_ENTRIES", 2, "host-install-entry-bound"), ("MAX_INSTALL_BYTES", 1, "host-install-byte-bound"), ("MAX_INSTALL_DEPTH", 0, "host-install-depth-bound")])
def test_complete_traversal_enforces_every_population_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, budget: str, limit: int, reason: str) -> None:
    import recovery_host

    executable = installation(tmp_path / "venv")
    assert reader_closure(executable)["files"]
    monkeypatch.setattr(recovery_host, budget, limit)
    with pytest.raises(VerificationError, match=reason):
        reader_closure(executable)


@pytest.mark.parametrize("boundary", ["pins", "policy", "config"])
def test_host_selection_json_and_config_are_bounded_before_launch(tmp_path: Path, boundary: str) -> None:
    executable = installation(tmp_path / "venv")
    selected = tmp_path / "selected.json"
    if boundary == "config":
        selected = executable.parent.parent / "pyvenv.cfg"
    with selected.open("wb") as stream:
        stream.truncate(MAX_FILE + 1)
    with pytest.raises(VerificationError, match="file-bound"):
        bounded_call(boundary, selected, executable, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def bounded_call(boundary: str, selected: Path, executable: Path, output: Path) -> None:
    """Reach each real pre-launch boundary with the same hostile sparse input."""
    if boundary == "pins":
        select_policy(selected, executable)
    elif boundary == "policy":
        gate(output, selected, selected, "0" * 64, executable, output)
    else:
        reader_closure(executable)


def test_policy_fifo_refuses_before_any_reader_process(tmp_path: Path) -> None:
    executable = installation(tmp_path / "venv")
    policy = tmp_path / "policy.json"
    os.mkfifo(policy)
    with pytest.raises(VerificationError, match="nonregular-file"):
        gate(tmp_path, policy, policy, "0" * 64, executable, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_actual_cpython_environment_selects_the_required_internal_lib64_link(tmp_path: Path) -> None:
    root = tmp_path / "real-venv"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(root)], check=True, capture_output=True, timeout=15)
    assert (root / "lib64").readlink() == Path("lib")
    executable = root / "bin/probity-read-pydantic-recovery"
    executable.write_bytes(b"selected console entry point")
    marker = root / "lib/selected-file"
    marker.write_bytes(b"same canonical package file")
    selected = reader_closure(executable)
    assert selected["directoryLinks"] == {"lib64": {"symlink": "lib", "target": "lib"}}
    assert "lib/selected-file" in selected["files"]
    assert not any(name.startswith("lib64/") for name in selected["files"])


@pytest.mark.parametrize("target", ["outside", "missing", "lib64", "other"])
def test_lib64_link_cannot_escape_or_hide_an_unselected_directory(tmp_path: Path, target: str) -> None:
    executable = installation(tmp_path / "venv")
    root = executable.parent.parent
    (root / "lib").mkdir()
    (root / "other").mkdir()
    (tmp_path / "outside").mkdir()
    link = str(tmp_path / "outside") if target == "outside" else target
    (root / "lib64").symlink_to(link, target_is_directory=True)
    with pytest.raises(VerificationError):
        reader_closure(executable)


@pytest.mark.parametrize("config", [
    "include-system-site-packages = true\n# include-system-site-packages = false\n",
    "include-system-site-packages = false\ninclude-system-site-packages = true\n",
    "include-system-site-packages = false\ninclude-system-site-packages = false\n",
    "include-system-site-packages = false-extra\n",
    "# include-system-site-packages = false\n",
])
def test_config_substrings_and_ambiguous_duplicates_cannot_select_isolation(tmp_path: Path, config: str) -> None:
    executable = installation(tmp_path / "venv")
    (executable.parent.parent / "pyvenv.cfg").write_text(config)
    with pytest.raises(VerificationError, match="reader-system-packages"):
        reader_closure(executable)


def test_config_accepts_the_cpython_key_and_value_normalization(tmp_path: Path) -> None:
    executable = installation(tmp_path / "venv")
    (executable.parent.parent / "pyvenv.cfg").write_text("  Include-System-Site-Packages = FALSE  \n")
    assert reader_closure(executable)["files"]


def test_interpreter_config_in_bin_cannot_override_the_selected_parent_config(tmp_path: Path) -> None:
    executable = installation(tmp_path / "venv")
    (executable.parent / "pyvenv.cfg").write_text("include-system-site-packages = true\n")
    with pytest.raises(VerificationError, match="reader-config-override"):
        reader_closure(executable)


def test_invalid_config_encoding_is_a_clean_prelaunch_refusal(tmp_path: Path) -> None:
    executable = installation(tmp_path / "venv")
    (executable.parent.parent / "pyvenv.cfg").write_bytes(b"\xff")
    with pytest.raises(VerificationError, match="reader-config-encoding"):
        reader_closure(executable)
