"""Verify source/custody selection and failure retention before native imports."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

spec = importlib.util.spec_from_file_location(
    "trusted_adk_host", Path(__file__).with_name("bootstrap.py")
)
assert spec is not None and spec.loader is not None
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


def state() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    policy = {"modules": {"probity_adk/reader.py": "selected"}}
    native = {"pythonGitBlobs": {"version.py": "primary"}}
    probe = {
        "pythonVersion": [3, 13, 15],
        "modules": policy["modules"].copy(),
        "native": native["pythonGitBlobs"].copy(),
        "caches": [],
        "unselectedImportables": [],
        "sdkVersion": "2.11.0",
        "mcpInstalled": True,
    }
    return policy, native, probe


def test_exact_current_source_and_framework_free_reader() -> None:
    policy, native, probe = state()
    host.installation(probe, policy, native)
    probe.update(native={}, sdkVersion=None, mcpInstalled=False)
    host.installation(probe, policy, None)


@pytest.mark.parametrize(
    "field,value",
    [
        ("pythonVersion", [3, 13, 14]),
        ("modules", {}),
        ("native", {}),
        ("native", {"version.py": "other"}),
        ("caches", ["unselected.pyc"]),
        ("sdkVersion", "2.12.0"),
        ("unselectedImportables", ["unselected.so"]),
        ("unselectedImportables", ["unselected.pyd"]),
        ("unselectedImportables", ["unselected.pyo"]),
        ("unselectedImportables", ["linked-module.py"]),
        ("mcpInstalled", False),
        ("mcpInstalled", 1),
    ],
)
def test_changed_installation_refused(field: str, value: Any) -> None:
    policy, native, probe = state()
    probe[field] = value
    with pytest.raises(ValueError):
        host.installation(probe, policy, native)


def test_population_declared_before_imports() -> None:
    a, b = host.selected_plan(), host.selected_plan()
    assert len(a["cases"]) == 12 and len(set(a["cases"])) == 12
    assert a["runId"] != b["runId"]
    assert a["budget"] == {
        "plannedAttempts": 12,
        "maxModelCalls": 25,
        "maxToolCalls": 18,
        "maxElapsedSeconds": 120,
    }
    assert a["modelQuality"] == "not-evaluated"


def test_selected_wheel_before_imports(tmp_path: Path) -> None:
    wheel = tmp_path / "reader.whl"
    wheel.write_bytes(b"selected")
    policy = {"wheels": {wheel.name: host.digest(wheel.read_bytes())}}
    host.wheel_check(tmp_path, policy)
    wheel.write_bytes(b"changed")
    with pytest.raises(ValueError, match="selected_wheel_digest"):
        host.wheel_check(tmp_path, policy)


@pytest.mark.parametrize("code", [0, 1])
def test_child_status_and_original_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    monkeypatch.setattr(
        host.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            [], code, b"actual", b"error"
        ),
    )
    prefix = tmp_path / "child"
    if code:
        with pytest.raises(ValueError, match="child_failed"):
            host.command(["selected"], prefix, tmp_path)
    else:
        assert host.command(["selected"], prefix, tmp_path) == b"actual"
    assert json.loads(prefix.with_suffix(".status.json").read_bytes()) == {
        "timeout": False,
        "returncode": code,
    }
    assert prefix.with_suffix(".stdout").read_bytes() == b"actual"


def test_timeout_retention(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(*args: Any, **kwargs: Any) -> None:
        raise subprocess.TimeoutExpired([], 180, output=b"partial", stderr=b"actual")

    monkeypatch.setattr(host.subprocess, "run", timeout)
    prefix = tmp_path / "child"
    with pytest.raises(ValueError, match="child_timeout"):
        host.command([], prefix, tmp_path)
    assert json.loads(prefix.with_suffix(".status.json").read_bytes()) == {
        "timeout": True,
        "returncode": None,
    }
    assert prefix.with_suffix(".stdout").read_bytes() == b"partial"


def test_no_credential_or_python_override(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ["PYTHONPATH", "PIP_CONFIG_FILE", "PROVIDER_API_KEY", "AUTH_TOKEN"]:
        monkeypatch.setenv(key, "inherited")
    assert not any(
        key in host.environment()
        for key in ["PYTHONPATH", "PIP_CONFIG_FILE", "PROVIDER_API_KEY", "AUTH_TOKEN"]
    )


@pytest.mark.skipif(
    "ADK_CURRENT_READER_PYTHON" not in os.environ,
    reason="requires the separately installed selected reader",
)
@pytest.mark.parametrize("suffix", [".pyc", ".pyo", ".so", ".pyd", ".linked"])
def test_actual_installed_alias_before_module_import(
    tmp_path: Path, suffix: str
) -> None:
    """Reject real package aliases using the metadata-only child probe."""
    interpreter = Path(os.environ["ADK_CURRENT_READER_PYTHON"])
    root = Path(__file__).parent
    policy = json.loads((root / "installation-policy.json").read_bytes())
    argv = [
        str(interpreter),
        "-I",
        "-B",
        "-c",
        "import importlib.metadata as m; "
        'print(m.distribution("probity-adk-reference").locate_file("probity_adk"))',
    ]
    package = Path(subprocess.check_output(argv, text=True).strip())
    alias = package / ("selected-probe-alias" + suffix)
    assert not alias.exists() and not alias.is_symlink()
    if suffix == ".linked":
        alias.symlink_to(package / "reader.py")
    else:
        alias.write_bytes(b"unselected importable alias")
    try:
        with pytest.raises(ValueError, match="unselected_"):
            host.probe(interpreter, tmp_path / "alias-probe", policy, None)
        receipt = json.loads((tmp_path / "alias-probe.stdout").read_bytes())
        assert receipt["sdkVersion"] is None
        assert any(
            str(alias) in row
            for row in receipt["caches"] + receipt["unselectedImportables"]
        )
    finally:
        alias.unlink()
