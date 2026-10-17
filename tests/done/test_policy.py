"""The policy table, its digest, the exact latch and the tarball reset."""

from probity_observer.done import drift, policy
from probity_observer.launch import snapshot

SUPPORTED = {"decision": "supported", "reason": "done_checks_supported"}
CONTRA = {"decision": "contradicted", "reason": "protected_path_mutated"}
UNKNOWN = {"decision": "not_established", "reason": "observation_coverage_unestablished"}


def exec_event(step, argv, exit_code=1, origin=None):
    event = {"id": f"e{step}", "type": "exec", "step": step, "argv": argv, "exit": exit_code}
    if origin:
        event["origin"] = origin
    return event


def test_table_digest_is_stable_and_names_its_thresholds():
    first, second = policy.table(), policy.table()
    assert policy.table_sha256(first) == policy.table_sha256(second)
    assert policy.table_sha256(first) != policy.table_sha256(policy.table(attempts=5))
    assert first["latch"] == {"tree_repeats": 3, "command_repeats": 3}
    assert {rule["action"] for rule in first["rules"]} == set(policy.ACTIONS)


def test_each_rule_of_the_table():
    table = policy.table(attempts=3)
    latch = drift.Latch()
    assert policy.decide(table, SUPPORTED, 1, latch, None, False).record() == {
        "action": "stop", "reason": "done_checks_supported"}
    assert policy.decide(table, UNKNOWN, 1, latch, "loop_detected", False).action == "escalate"
    latch.contradicted = 1
    assert policy.decide(table, CONTRA, 1, latch, None, False).record() == {
        "action": "replan", "reason": "protected_path_mutated"}
    latch.contradicted = 2
    assert policy.decide(table, CONTRA, 2, latch, None, False).action == "escalate"
    assert policy.decide(table, UNKNOWN, 1, drift.Latch(), None, True).reason == "agent_escalated"
    assert policy.decide(table, UNKNOWN, 3, drift.Latch(), None, False).reason == "budget_exhausted"
    assert policy.decide(table, UNKNOWN, 1, drift.Latch(), None, False).action == "continue"


def test_the_contradicted_latch_never_decays():
    latch = drift.Latch()
    latch.observe("t1", [], "contradicted")
    latch.observe("t2", [], "supported")
    latch.observe("t3", [], "contradicted")
    assert latch.contradicted == 2


def test_tree_latch_fires_on_k_identical_trees_and_stays_fired():
    latch = drift.Latch(tree_repeats=3)
    assert latch.observe("same", [], "not_established") is None
    assert latch.observe("same", [], "not_established") is None
    assert latch.observe("same", [], "not_established") == "loop_detected"
    assert latch.observe("other", [], "not_established") == "loop_detected"
    assert latch.state()["fired"] == "tree" and latch.state()["evidence"]["attempts"] == 3


def test_command_latch_counts_the_agents_own_repeats_without_an_edit_between():
    pytest_argv = ["python", "-m", "pytest"]
    events = [exec_event(1, pytest_argv), exec_event(2, pytest_argv),
              {"id": "e3", "type": "write", "step": 3, "path": "x", "origin": "e2"},
              exec_event(4, pytest_argv)]
    assert drift.repeated_command(events, 3) == pytest_argv
    broken = events[:2] + [{"id": "e3", "type": "write", "step": 3, "path": "src/a.py"}] + events[3:]
    assert drift.repeated_command(broken, 3) is None
    child = [exec_event(1, pytest_argv), exec_event(2, ["python"], 0, origin="e1"),
             exec_event(3, ["python"], 0, origin="e1"), exec_event(4, ["python"], 0, origin="e1")]
    assert drift.repeated_command(child, 3) is None
    latch = drift.Latch(command_repeats=3)
    assert latch.observe("t", events, "not_established") == "loop_detected"
    assert latch.state()["evidence"]["argv"] == pytest_argv


def test_replan_resets_the_workspace_from_the_sealed_tarball(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "a.py").write_text("start\n")
    digest = snapshot.seal(workspace, tmp_path / "start.tar")
    (workspace / "a.py").write_text("changed\n")
    (workspace / "new.py").write_text("x\n")
    policy.apply(policy.Decision("continue", "r"), workspace, tmp_path / "start.tar", digest)
    assert (workspace / "new.py").exists()
    policy.apply(policy.Decision("replan", "r"), workspace, tmp_path / "start.tar", digest)
    assert (workspace / "a.py").read_text() == "start\n" and not (workspace / "new.py").exists()
    assert "protected_path_mutated" in policy.replan_input(
        policy.Decision("replan", "protected_path_mutated"), 1)


def test_consecutive_unestablished_verdicts_escalate():
    table = policy.table(attempts=5)
    latch = drift.Latch()
    latch.observe("a", [], "not_established")
    assert policy.decide(table, UNKNOWN, 1, latch, None, False).action == "continue"
    latch.observe("b", [], "not_established")
    assert policy.decide(table, UNKNOWN, 2, latch, None, False).record() == {
        "action": "escalate", "reason": "record_unestablished_repeatedly"}
    latch.observe("c", [], "contradicted")
    assert latch.unestablished_run == 0
