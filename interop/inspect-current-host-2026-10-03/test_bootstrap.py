"""Controls for executable host selection and isolated installed reader policy."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import marshal
import struct
import shutil

import pytest

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("bootstrap", HERE / "bootstrap.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)
adapter_spec = importlib.util.spec_from_file_location(
    "adapter", HERE / "src/probity_inspect_current/adapter.py"
)
adapter = importlib.util.module_from_spec(adapter_spec)
adapter_spec.loader.exec_module(adapter)


def test_literal_new_namespace_preserves_original_bytes_and_version():
    engine = adapter.load_engine()
    assert engine.VERSION == "probity-inspect-execution-v2"
    assert engine.INSPECT_VERSION == "0.3.276"
    original = (
        HERE / "src/probity_inspect_current/_legacy/inspect_execution.py"
    ).read_bytes()
    assert adapter.sha(original) == adapter.LEGACY["inspect_execution.py"]
    assert b'VERSION = "probity-inspect-execution-v1"' in original
    assert b'INSPECT_VERSION = "0.3.273"' in original
    assert "inspect_ai" not in sys.modules


@pytest.mark.parametrize(
    "profile",
    ["probity-inspect-execution-v1", "newer", "", "probity-inspect-execution-v3"],
)
def test_cross_version_population_refused(profile):
    declared = bootstrap.population()
    declared["profile"] = profile
    with pytest.raises(ValueError, match="execution_profile"):
        adapter.load_engine()._declared(declared)


def test_fixed_declared_population():
    value = bootstrap.population()
    assert len(value["cases"]) == 6
    assert [x["id"] for x in value["cases"]] == [
        "tool-pass",
        "tool-fail",
        "agent-pass",
        "agent-error",
        "workload-pass",
        "planned-unstarted",
    ]
    assert sum(x["launch"] for x in value["cases"]) == 5
    assert value["cases"][3]["final"] is None


@pytest.mark.parametrize("alias", ["evaluation_contract", "inspect_contract"])
def test_preimported_helper_cannot_redirect_authenticated_source(monkeypatch, alias):
    monkeypatch.setitem(sys.modules, alias, object())
    with pytest.raises(ValueError, match="legacy_module_collision"):
        adapter.load_engine()


def test_native_source_selection_is_frozen_entire_current_population():
    value = json.loads((HERE / "native-source-selection.json").read_bytes())
    assert value["version"] == "0.3.276"
    assert value["commit"] == bootstrap.HOST
    assert len(value["files"]) == 834
    for name in ("model/_model.py", "_eval/eval.py", "log/_log.py"):
        assert name in value["files"]


def probe():
    policy = json.loads((HERE / "installation-policy.json").read_bytes())
    value = {
        "python": "3.12.14",
        "observer_version": "0.0.1",
        "reader_version": "0.0.1",
        "observer_modules": policy["observer_modules"],
        "adapter_sha256": policy["adapter_sha256"],
        "current_modules": policy["current_modules"],
        "legacy": policy["legacy"],
        "framework_available": False,
        "bytecode_cache_population": [],
    }
    return value, policy


def test_clean_install_selection():
    value, policy = probe()
    bootstrap.probe_check(value, policy, False)


def test_native_version_and_source_are_authenticated_before_import():
    value, policy = probe()
    value.update(
        framework_available=True,
        native_metadata_version="0.3.276",
        native_git_blobs={"selected.py": "a" * 40},
    )
    expected = {"selected.py": "a" * 40}
    bootstrap.probe_check(value, policy, True, expected)
    value["native_git_blobs"]["extra.py"] = "b" * 40
    with pytest.raises(ValueError, match="preimport_native_source_population"):
        bootstrap.probe_check(value, policy, True, expected)
    value["native_git_blobs"] = expected
    value["native_metadata_version"] = "0.3.273"
    with pytest.raises(ValueError, match="preimport_native_version"):
        bootstrap.probe_check(value, policy, True, expected)


@pytest.mark.parametrize(
    "key,wrong,label",
    [
        ("python", "3.12.13", "python_version"),
        ("observer_version", "0.0.2", "package_versions"),
        ("reader_version", "0.0.2", "package_versions"),
        ("observer_modules", {}, "observer_module_population"),
        ("adapter_sha256", "0" * 64, "adapter_digest"),
        ("current_modules", {}, "current_module_population"),
        ("legacy", {}, "legacy_population"),
        ("framework_available", True, "framework_boundary"),
        ("bytecode_cache_population", ["unselected.pyc"], "unselected_bytecode_cache"),
    ],
)
def test_changed_install_refused_before_reader_import(key, wrong, label):
    value, policy = probe()
    value = copy.deepcopy(value)
    value[key] = wrong
    with pytest.raises(ValueError, match=label):
        bootstrap.probe_check(value, policy, False)


def report():
    return {
        "mapping": bootstrap.VERSION,
        "planned": 6,
        "started": 5,
        "complete": 4,
        "scored": 4,
        "task_passed": 3,
        "task_failed": 1,
        "failed": 1,
        "missing": 1,
        "unknown_start": 0,
        "incomplete": 0,
    }


def test_actual_repeat_required():
    raw = bootstrap.encode(report())
    assert bootstrap.repeated(raw, raw) == report()
    with pytest.raises(ValueError, match="repeated_decision_changed"):
        bootstrap.repeated(raw, raw + b" ")


@pytest.mark.parametrize(
    "key",
    [
        "planned",
        "started",
        "complete",
        "scored",
        "task_passed",
        "task_failed",
        "failed",
        "missing",
        "unknown_start",
        "incomplete",
    ],
)
def test_errors_unstarted_or_population_never_relabelled(key):
    value = report()
    value[key] += 1
    raw = bootstrap.encode(value)
    with pytest.raises(ValueError, match="consumer_outcomes"):
        bootstrap.repeated(raw, raw)


def test_environment_strips_inherited_provider_python_and_pip(monkeypatch):
    for key in (
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GITHUB_TOKEN",
        "PYTHONPATH",
        "PIP_INDEX_URL",
    ):
        monkeypatch.setenv(key, "not-a-secret")
    env, removed = bootstrap.clean_environment()
    assert all(
        key not in env
        for key in (
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GITHUB_TOKEN",
            "PYTHONPATH",
            "PIP_INDEX_URL",
        )
    )
    assert "PYTHONPATH" in removed


def test_timeout_retains_failure_before_decision(tmp_path, monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            args[0], 1, output=b"partial", stderr=b"timeout"
        )

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(ValueError, match="child_timeout"):
        bootstrap.command(["python"], env={}, cwd=tmp_path, prefix=tmp_path / "child")
    assert (tmp_path / "child.stdout").read_bytes() == b"partial"
    assert json.loads((tmp_path / "child.status.json").read_bytes()) == {
        "timeout": True
    }


def test_failure_retains_stdout_and_stderr(tmp_path, monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(a[0], 7, b"partial", b"refusal"),
    )
    with pytest.raises(ValueError, match="child_failed"):
        bootstrap.command(["python"], env={}, cwd=tmp_path, prefix=tmp_path / "child")
    assert (tmp_path / "child.stderr").read_bytes() == b"refusal"


def test_installed_reader_remains_framework_free():
    raw = subprocess.check_output(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            "from probity_inspect_current.adapter import load_engine; import sys; x=load_engine(); assert x.INSPECT_VERSION=='0.3.276'; assert 'inspect_ai' not in sys.modules; print('framework-free')",
        ]
    )
    assert raw.strip() == b"framework-free"


def test_authenticated_buffer_ignores_timestamp_valid_unselected_cache(tmp_path):
    """A source-valid cache cannot replace the checked legacy buffer."""
    root = tmp_path / "package"
    shutil.copytree(HERE / "src/probity_inspect_current", root)
    target = root / "_legacy/evaluation_contract.py"
    cache = Path(importlib.util.cache_from_source(str(target)))
    cache.parent.mkdir(parents=True, exist_ok=True)
    header = importlib.util.MAGIC_NUMBER + struct.pack(
        "<III", 0, int(target.stat().st_mtime), target.stat().st_size
    )
    cache.write_bytes(
        header
        + marshal.dumps(
            compile("raise RuntimeError('unselected cache')", str(target), "exec")
        )
    )
    selected = importlib.util.spec_from_file_location(
        "copied_adapter", root / "adapter.py"
    )
    module = importlib.util.module_from_spec(selected)
    selected.loader.exec_module(module)
    assert module.load_engine().VERSION == bootstrap.VERSION


def test_external_declaration_mismatch_refused_before_native_decode(tmp_path):
    frozen = bootstrap.population()
    changed = copy.deepcopy(frozen)
    changed["cases"][0]["launch"] = False
    (tmp_path / "declaration-before-run.json").write_bytes(bootstrap.encode(changed))
    with pytest.raises(ValueError, match="external_population_changed"):
        adapter.verify(
            adapter.load_engine(), {"declaration": frozen, "pins": {}}, tmp_path
        )


@pytest.mark.parametrize(
    "tier,names",
    [
        ("tools", ["double"]),
        ("agents", ["double"]),
        ("workloads", ["read_ticket", "write_ticket"]),
    ],
)
def test_literal_extension_registry_names_project_without_runtime_changes(tier, names):
    specs = [
        {"type": "tool", "name": adapter.TOOL_NAMESPACE + name, "params": {}}
        for name in names
    ]
    steps = [{"params": {"tools": [specs] if tier == "tools" else specs}}]
    if tier == "tools":
        steps.append({"params": {}})
    log = {"plan": {"steps": steps}, "samples": [{"events": [{"function": names[0]}]}]}
    result = adapter.registry_projection(adapter.load_engine(), log, {"tier": tier})
    assert result["samples"] == [{"events": [{"function": names[0]}]}]
    assert "probity_inspect_current/" not in str(result["plan"])


@pytest.mark.parametrize(
    "name",
    [
        "double",
        "another_package/double",
        "probity_inspect_current/other",
        "probity_inspect_current/double/extra",
    ],
)
def test_unknown_unqualified_or_foreign_registry_name_refused(name):
    log = {
        "plan": {
            "steps": [
                {"params": {"tools": [[{"type": "tool", "name": name, "params": {}}]]}},
                {"params": {}},
            ]
        }
    }
    with pytest.raises(ValueError, match="current_registry_names"):
        adapter.registry_projection(adapter.load_engine(), log, {"tier": "tools"})


def test_original_native_digest_checked_before_registry_projection():
    with pytest.raises(ValueError, match="execution_native_pin"):
        adapter.load_engine()._sample(
            b"not-json",
            {"tier": "tools"},
            {},
            {"sha256": "0" * 64, "run_id": "r", "eval_id": "e"},
        )
