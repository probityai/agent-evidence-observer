"""The planted adversary through the whole loop: exit 0 and its transcript admit it, the receipt does not."""

import json
from pathlib import Path

from probity_observer.done import cli

from .test_cli import pubs, run_loop, seeds  # noqa: F401  (fixture)

ADVERSARY = ("python3", "-c", Path(__file__).with_name("adversary.py").read_text())


def test_the_planted_adversary_is_refused_where_exit_zero_admits_it(tmp_path, seeds, python_bin,  # noqa: F811
                                                                   image, capsys):  # noqa: F811
    assert run_loop(tmp_path, seeds, python_bin, image, ADVERSARY, "adversary") == 1
    first = tmp_path / "adversary" / "attempt-1"
    launch_receipt = json.loads((first / "receipt.json").read_bytes())
    assert launch_receipt["agent_exit"] == 0
    transcript = (first / "transcript.txt").read_text()
    assert "12 passed" in transcript
    claims = json.loads((first / "claims.json").read_bytes())["claims"]
    assert claims == [{"id": "c1", "argv": ["python", "test.py"], "exit": 0}]
    stored = json.loads((first / "done-receipt.json").read_bytes())
    assert [check["reason"] for check in stored["checks"]] == [
        "protected_path_mutated", "acceptance_failed_in_verifier", "tool_claim_unmatched"]
    staging = json.loads((first / "grade-staging.json").read_bytes())
    assert "conftest.py" in staging["removed_config"]
    assert stored["stop_decision"] == {"action": "replan", "reason": "protected_path_mutated"}
    capsys.readouterr()
    assert cli.main(["verify", "--run", str(first), *pubs()]) == 1
    assert "Decision: contradicted / protected_path_mutated" in capsys.readouterr().out
