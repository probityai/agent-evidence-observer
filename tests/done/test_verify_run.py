"""C4 grading: staging, the protected reset, fresh locked-down containers, the second key."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from probity_observer.done import contract, verify_run
from probity_observer.done.formats import open_record, public_key
from probity_observer.sensors import treedigest

from .conftest import HONEST, LCB_ORIGINAL, LCB_RECORD
from .test_replay import COUNTER

def sealed_task(tmp_path, harness, record):
    task = contract.lcb_task(record, tmp_path / "work")
    return contract.seal(task, tmp_path / "contract", harness, {"mutants": 3, "killed": 3})


def final_tree(sealed, tmp_path, solution, change=None):
    final = tmp_path / "final"
    shutil.copytree(sealed.out / "workspace", final)
    (final / "func.py").write_text(solution)
    if change:
        change(final)
    scanned = treedigest.scan(final)
    return final, {"tree_sha256": scanned.sha256, "files": scanned.files}


def run_grade(sealed, final, tree, image, grader):
    runner = verify_run.DockerRunner(image)
    return verify_run.grade((sealed.out / "contract.json").read_bytes(), sealed.out,
                            final, tree, verify_run.GradeContext("c1", "i1"), runner, grader,
                            timeout=120)


def exits(graded):
    return {item["id"]: item["exit"] for item in graded.grade["results"]}


def test_honest_tree_passes_and_the_grade_is_signed_by_the_grader(tmp_path, harness, grader, image):
    sealed = sealed_task(tmp_path, harness, LCB_ORIGINAL)
    final, tree = final_tree(sealed, tmp_path, HONEST)
    graded = run_grade(sealed, final, tree, image, grader)
    assert exits(graded) == {"visible": 0, "heldout": 0}
    assert graded.grade["contract_sha256"] == sealed.contract_sha256
    assert open_record(graded.envelope, public_key(grader), verify_run.GRADE_SCHEMA) == graded.grade_bytes
    from probity_verify.adapters import done_records
    assert done_records.grade(graded.grade_bytes)["tree_sha256"] == tree["tree_sha256"]


def test_a_counter_fails_the_conflicting_task_in_the_container(tmp_path, harness, grader, image):
    sealed = sealed_task(tmp_path, harness, LCB_RECORD)
    final, tree = final_tree(sealed, tmp_path, COUNTER)
    graded = run_grade(sealed, final, tree, image, grader)
    assert exits(graded)["visible"] == 1
    assert len(graded.staging["replays"]) == 2 and graded.staging["replay_order_seed"]


def test_protected_edit_and_poisoned_cache_are_reset(tmp_path, harness, grader, image):
    sealed = sealed_task(tmp_path, harness, LCB_ORIGINAL)

    def tamper(root):
        (root / "test.py").write_text("print('All tests passed!')\n")
        (root / "__pycache__").mkdir()
        (root / "__pycache__" / "func.cpython-312.pyc").write_bytes(b"poison")
    final, tree = final_tree(sealed, tmp_path, "def add(a, b):\n    return 0\n", tamper)
    graded = run_grade(sealed, final, tree, image, grader)
    assert exits(graded) == {"visible": 1, "heldout": 1}
    assert graded.staging["removed_caches"] == ["__pycache__"]


def test_the_container_cannot_reach_the_network_or_write_usr(tmp_path, image):
    runner = verify_run.DockerRunner(image)
    state = tmp_path / "s"
    state.mkdir()
    probe = ("import socket, sys\n"
             "try:\n    socket.create_connection(('1.1.1.1', 53), 2)\n    sys.exit(3)\n"
             "except OSError:\n    pass\n"
             "try:\n    open('/usr/lib/x', 'w')\n    sys.exit(4)\n"
             "except OSError:\n    pass\n"
             "import os\nsys.exit(0 if os.getuid() == 65534 and os.environ.get('HOME') == '/tmp'"
             " and 'PROBITY_LEAK' not in os.environ else 5)\n")
    os.environ["PROBITY_LEAK"] = "1"
    try:
        assert runner.run(state, ["python", "-c", probe], None, 60) == 0
    finally:
        del os.environ["PROBITY_LEAK"]
    assert runner.run(state, ["sleep", "30"], None, 2) == verify_run.TIMEOUT_EXIT


def test_isolation_block_has_the_admission_fields(tmp_path, harness, grader, image):
    sealed = sealed_task(tmp_path, harness, LCB_ORIGINAL)
    final, tree = final_tree(sealed, tmp_path, HONEST)
    block = run_grade(sealed, final, tree, image, grader).isolation
    assert block["contract_sha256"] == sealed.contract_sha256
    assert block["trusted_tree"]["expected_sha256"] == block["trusted_tree"]["measured_sha256"]
    assert block["worker"]["uid"] != block["verifier"]["uid"]
    assert block["worker"]["supplementary_groups"] == []
    assert block["result"]["dir_mode"] == "0700" and block["result"]["files_read"]
    assert block["processes"]["killed_step"] < block["processes"]["result_read_step"]
    assert block["tests"]["expected"] == block["tests"]["collected"] == 2
    assert {"name", "safe"} == set(block["loaders"][0])
    assert block["reference"] == {"dir_mode": "0755", "inside_artifact_dir": False}


def test_staging_keeps_only_links_the_start_tree_had(tmp_path):
    start, final = tmp_path / "start", tmp_path / "f"
    for root in (start, final):
        root.mkdir()
        (root / "a.txt").write_text("a")
        os.symlink("a.txt", root / "inside")
    os.symlink("a.txt", final / "conftest.py")
    os.symlink("/etc/passwd", final / "outside")
    os.symlink("../..", final / "up")
    os.mkfifo(final / "pipe")
    staged = verify_run.stage_tree(final, tmp_path / "staged", start)
    assert sorted(staged.rejected) == ["conftest.py", "outside", "pipe", "up"]
    assert (tmp_path / "staged" / "inside").is_symlink()


def test_reset_removes_grader_files_the_agent_added_and_refuses_a_link_above(tmp_path):
    start, sealed = tmp_path / "start", tmp_path / "sealed"
    (start / "tests").mkdir(parents=True)
    (start / "tests" / "conftest.py").write_text("# sealed\n")
    (start / "tests" / "test_a.py").write_text("x\n")
    shutil.copytree(start, sealed)
    root = tmp_path / "staged"
    shutil.copytree(start, root)
    (root / "conftest.py").write_text("hook\n")
    (root / "pytest.ini").write_text("[pytest]\naddopts = --collect-only\n")
    (root / "tests" / "conftest.py").write_text("changed\n")
    staged = verify_run.Staged(root)
    entry = contract.Protected("tests/test_a.py", "file")
    verify_run.reset(staged, [entry], sealed, start)
    assert sorted(staged.removed_config) == ["conftest.py", "pytest.ini"]
    assert (root / "tests" / "conftest.py").read_text() == "changed\n"
    shutil.rmtree(root / "tests")
    os.symlink(str(sealed / "tests"), root / "tests")
    with pytest.raises(verify_run.GradeError):
        verify_run.reset(verify_run.Staged(root), [entry], sealed, start)


def test_a_tree_that_is_not_the_recorded_one_is_refused(tmp_path, harness, grader, image):
    sealed = sealed_task(tmp_path, harness, LCB_ORIGINAL)
    final, tree = final_tree(sealed, tmp_path, HONEST)
    (final / "func.py").write_text("changed later\n")
    with pytest.raises(verify_run.GradeError):
        run_grade(sealed, final, tree, image, grader)


def test_a_runtime_failure_is_an_error_not_a_failing_test(tmp_path):
    runner = verify_run.DockerRunner("probity-no-such-image:missing")
    state = tmp_path / "s"
    state.mkdir()
    with pytest.raises(verify_run.GradeError):
        runner.run(state, ["true"], None, 60)
    with pytest.raises(verify_run.GradeError):
        runner.groups()


def test_staging_rejects_a_native_binary_the_start_tree_did_not_have(tmp_path):
    start, final = tmp_path / "start", tmp_path / "f"
    for root in (start, final):
        root.mkdir()
        (root / "same.so").write_bytes(b"\x7fELFsame")
    (final / "evil.so").write_bytes(b"\x7fELFevil")
    (final / "hidden").write_bytes(b"\x7fELFnoext")
    (final / "plain.py").write_text("x = 1\n")
    staged = verify_run.stage_tree(final, tmp_path / "staged", start)
    assert sorted(staged.rejected_native) == ["evil.so", "hidden"]
    assert (tmp_path / "staged" / "same.so").exists() and (tmp_path / "staged" / "plain.py").exists()


def test_post_patch_mutants_find_a_hunk_the_tests_never_run(tmp_path, harness, python_bin):
    from probity_observer.done.runner import SubprocessRunner
    sealed = sealed_task(tmp_path, harness, LCB_ORIGINAL)
    contract_record = json.loads((sealed.out / "contract.json").read_bytes())
    start = tmp_path / "start"
    shutil.copytree(sealed.out / "workspace", start)
    (start / "func.py").write_text(HONEST)
    root = tmp_path / "tree"
    shutil.copytree(start, root)
    (root / "func.py").write_text(HONEST + "\n\ndef unused(x):\n    return x + 41\n")
    dirs = {item["id"]: sealed.out / "sealed" / "heldout" for item in contract_record["acceptance"]}
    report = verify_run.post_patch(SubprocessRunner(python_bin), root, start, contract_record,
                                   dirs, 60)
    assert len(report) == 1 and report[0]["mutants"] > 0 and report[0]["killed"] == 0
    assert verify_run.hunks_exercised(report) < 1.0
    assert verify_run.hunks_exercised([]) == 1.0
