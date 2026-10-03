"""Synthetic wheel and report controls; no native model results are claimed."""

import base64
import csv
import hashlib
import importlib.util
import io
import shutil
import sys
import zipfile
from pathlib import Path

import pytest
from build_installed_reader import PACKAGE, select, verify_wheel

ROOT = Path(__file__).parents[1]


@pytest.fixture
def cli(tmp_path):
    package = tmp_path / "installed"
    package.mkdir()
    for name in ["__init__.py", "cli.py"]:
        shutil.copyfile(ROOT / "reader_package" / name, package / name)
    for name in [
        "task_matrix.py",
        "schema_contract.py",
        "protocol.json",
        "prepare_boundary.py",
    ]:
        shutil.copyfile(ROOT / name, package / name)
    module_name = "vocabulary_test_install"
    spec = importlib.util.spec_from_file_location(
        module_name, package / "__init__.py", submodule_search_locations=[str(package)]
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    loaded = importlib.import_module(module_name + ".cli")
    yield loaded
    for key in list(sys.modules):
        if key == module_name or key.startswith(module_name + "."):
            del sys.modules[key]


def quality_report(cli):
    protocol = cli.task_matrix.protocol((ROOT / "protocol.json").read_bytes())
    return {
        "publicationDecision": "publish-scoped-report",
        "quality": [
            {
                "model": cfg["model"],
                "configuration": cfg["id"],
                "family": family,
                "correct": 16,
                "fullyCorrectPairs": 8,
            }
            for cfg in cli.task_matrix.configurations(protocol)
            for family in {case["family"] for case in protocol["cases"]}
        ],
    }


def test_quality_hold_preserves_valid_evidence_and_original_scores(cli):
    report = quality_report(cli)
    report["quality"][0].update(correct=2, fullyCorrectPairs=0)
    result = cli.assess(report, 16, 8)
    assert result["evidenceDecision"] == "accept-scoped-evidence"
    assert result["qualityDecision"] == result["consumerDecision"] == "hold-quality"
    assert result["report"] is report
    assert result["qualityFailures"][0]["correct"] == 2


@pytest.mark.parametrize("population", ["empty", "missing", "duplicate", "extra"])
def test_incomplete_or_duplicate_quality_population_refuses(cli, population):
    report = quality_report(cli)
    if population == "empty":
        report["quality"] = []
    elif population == "missing":
        report["quality"].pop()
    elif population == "duplicate":
        report["quality"][-1] = dict(report["quality"][0])
    else:
        report["quality"].append(dict(report["quality"][0]))
    with pytest.raises(ValueError, match="population differs"):
        cli.assess(report, 16, 8)


@pytest.mark.parametrize("count", [float("nan"), float("inf"), True, -1, 17])
def test_quality_counts_must_be_finite_integers_in_declared_population(cli, count):
    report = quality_report(cli)
    report["quality"][0]["correct"] = count
    with pytest.raises(ValueError, match="finite declared integers"):
        cli.assess(report, 16, 8)


def test_host_can_select_weaker_threshold_without_rewriting_scores(cli):
    report = quality_report(cli)
    report["quality"][0].update(correct=2, fullyCorrectPairs=0)
    result = cli.assess(report, 2, 0)
    assert result["consumerDecision"] == "admit-scoped-quality"
    assert result["report"]["quality"][0]["fullyCorrectPairs"] == 0


def test_evidence_refusal_overrides_high_quality(cli):
    report = quality_report(cli)
    report["publicationDecision"] = "hold"
    assert cli.assess(report, 16, 8)["consumerDecision"] == "hold-evidence"


def wheel_fixture(path, *, extra=None, redirect=False, changed_source=False):
    selected = {PACKAGE + "/cli.py": b"# reviewed reader\n", "LICENSE": b"license\n"}
    metadata = PACKAGE + "-0.1.0.dist-info/"
    members = {
        PACKAGE + "/cli.py": b"# changed reader\n"
        if changed_source
        else selected[PACKAGE + "/cli.py"],
        metadata + "LICENSE": selected["LICENSE"],
        metadata
        + "METADATA": b"Metadata-Version: 2.1\nName: probity-policy-vocabulary-reader\nVersion: 0.1.0\n\n",
        metadata + "WHEEL": b"Wheel-Version: 1.0\nTag: py3-none-any\n",
        metadata + "top_level.txt": (PACKAGE + "\n").encode(),
        metadata + "entry_points.txt": (
            "[console_scripts]\nprobity-policy-vocabulary-reader = "
            + ("other:main" if redirect else PACKAGE + ".cli:main")
            + "\n"
        ).encode(),
    }
    if extra:
        members[extra] = b"import unwanted_code\n"
    rows = []
    for name, raw in members.items():
        sha = (
            base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        )
        rows.append([name, "sha256=" + sha, str(len(raw))])
    rows.append([metadata + "RECORD", "", ""])
    record = io.StringIO()
    csv.writer(record).writerows(rows)
    members[metadata + "RECORD"] = record.getvalue().encode()
    with zipfile.ZipFile(path, "w") as archive:
        for name, raw in members.items():
            archive.writestr(name, raw)
    return selected


def test_selected_wheel_members_and_commitments_accept(tmp_path):
    wheel = tmp_path / "reader.whl"
    verify_wheel(wheel, wheel_fixture(wheel))


@pytest.mark.parametrize(
    "extra", ["surprise.pth", "sitecustomize.py", PACKAGE + "/extra.py"]
)
def test_extra_code_refuses_even_when_wheel_record_is_resigned(tmp_path, extra):
    wheel = tmp_path / "reader.whl"
    selected = wheel_fixture(wheel, extra=extra)
    with pytest.raises(ValueError, match="population differs"):
        verify_wheel(wheel, selected)


def test_redirected_entry_point_refuses_even_with_resigned_record(tmp_path):
    wheel = tmp_path / "reader.whl"
    selected = wheel_fixture(wheel, redirect=True)
    with pytest.raises(ValueError, match="entry point differs"):
        verify_wheel(wheel, selected)


def test_changed_python_refuses_even_with_resigned_record(tmp_path):
    wheel = tmp_path / "reader.whl"
    selected = wheel_fixture(wheel, changed_source=True)
    with pytest.raises(ValueError, match="changes selected source"):
        verify_wheel(wheel, selected)


def test_source_contract_needs_independent_host_digest_before_git_or_build(tmp_path):
    with pytest.raises(ValueError, match="host selection"):
        select(tmp_path, b"{}", "0" * 64)
