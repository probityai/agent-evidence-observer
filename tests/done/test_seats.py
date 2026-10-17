"""The Claude Code worker seat: route A's launch and image, route B's host watch and hook."""

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from probity_observer.done import contract, receipt, seats
from probity_observer.done.formats import DoneError, public_key
from probity_observer.launch import backend_docker

from .conftest import LCB_ORIGINAL

CLAUDE_IMAGE = "probity-done-claude-seat:local"


@pytest.fixture
def sealed(tmp_path, harness):
    task = contract.lcb_task(LCB_ORIGINAL, tmp_path / "work")
    return contract.seal(task, tmp_path / "contract", harness, {"mutants": 3, "killed": 3})


def test_route_a_runs_claude_with_the_contract_in_its_prompt(sealed, tmp_path):
    spec = seats.route_a(sealed.record, "implement add", tmp_path, "img", "claude-sonnet-4-6",
                         "c", "i", secret_env=())
    assert spec.agent_argv[:2] == ("claude", "-p") and "--output-format" in spec.agent_argv
    prompt = spec.agent_argv[2]
    assert "python test.py" in prompt and "test.py" in prompt and "heldout" not in prompt
    assert "[flag_for_human_intervention]" in prompt
    assert spec.network is True


def test_route_a_never_puts_a_credential_into_a_record(sealed, tmp_path):
    with pytest.raises(DoneError, match="secret_env"):
        seats.route_a(sealed.record, "t", tmp_path, "img", "m", "c", "i", secret_env=(),
                      env={"CLAUDE_CODE_OAUTH_TOKEN": "x"})
    with pytest.raises(DoneError, match="by name"):
        seats.route_a(sealed.record, "t", tmp_path, "img", "m", "c", "i",
                      secret_env=("CLAUDE_CODE_OAUTH_TOKEN",))


def test_route_a_image_carries_the_pinned_cli_and_the_tracer():
    context = Path(__file__).with_name("claude-image")
    subprocess.run(["docker", "build", "-q", "-t", CLAUDE_IMAGE, str(context)], check=True,
                   capture_output=True)
    identity = backend_docker.preflight(CLAUDE_IMAGE)
    assert identity.strace_version.startswith("strace -- version")
    version = subprocess.run(["docker", "run", "--rm", "--entrypoint", "claude", CLAUDE_IMAGE,
                              "--version"], capture_output=True, text=True, check=True).stdout
    assert version.startswith(seats.CLI_VERSION)


def test_the_hook_records_each_bash_call(tmp_path):
    hook = tmp_path / "hook.py"
    hook.write_text(seats.HOOK)
    log = tmp_path / "claims.jsonl"
    for event in ({"tool_name": "Bash", "tool_input": {"command": "python test.py"},
                   "tool_response": {"exit_code": 0}},
                  {"tool_name": "Read", "tool_input": {"file_path": "x"}},
                  {"tool_name": "Bash", "tool_input": {"command": "pytest | tail"},
                   "tool_response": {}}):
        subprocess.run([sys.executable, str(hook)], input=json.dumps(event), text=True, check=True,
                       env={"PROBITY_DONE_CLAIMS": str(log)})
    assert seats.claims_from_hook_log(log.read_text()) == [
        {"id": "c1", "argv": ["python", "test.py"], "exit": 0},
        {"id": "c2", "argv": ["sh", "-c", "pytest | tail"]}]
    block = seats.hook_settings(hook)["hooks"]["PostToolUse"][0]
    assert block["matcher"] == "Bash" and str(hook) in block["hooks"][0]["command"]


def watched_run(tmp_path, sealed, keys, edit):
    harness, host, grader = keys
    workspace = tmp_path / "ws"
    shutil.copytree(sealed.out / "workspace", workspace)
    watch = seats.HostWatch(workspace, tmp_path / "run")
    watch.begin()
    time.sleep(0.3)
    edit(workspace)
    time.sleep(0.5)
    log = tmp_path / "claims.jsonl"
    log.write_text(json.dumps({"command": "python test.py", "exit": 0}) + "\n")
    records = watch.end("lcb_add", "lcb_add-1", log)
    run = watch.run
    for role in ("observation", "capability", "tree"):
        receipt.write_record(run, role, records[role], host)
    receipt.write_record(run, "claims", records["claims"], harness)
    receipt.write_record(run, "contract", sealed.record, harness)
    tree = records["tree"]
    grade = {"schema_version": "probity-acceptance-grade/v1", "claim_id": "lcb_add",
             "invocation_id": "lcb_add-1", "producer": "harness-verifier", "vantage": "independent",
             "witness_scope": "PEER", "contract_sha256": sealed.contract_sha256,
             "tree_sha256": tree["tree_sha256"],
             "results": [{"id": item["id"], "argv": item["argv"], "exit": 0}
                         for item in sealed.record["acceptance"]]}
    receipt.write_record(run, "grade", grade, grader)
    pins = receipt.Pins(public_key(harness), public_key(host), public_key(grader))
    return receipt.assemble(run, pins), workspace


def test_route_b_sees_a_protected_edit_from_the_host(tmp_path, sealed, harness, host, grader):
    predicate, _ = watched_run(tmp_path, sealed, (harness, host, grader),
                               lambda root: (root / "test.py").write_text("print('ok')\n"))
    assert predicate["checks"][0]["reason"] == "protected_path_mutated"
    assert predicate["checks"][2]["decision"] == "not_established"


def test_route_b_honest_edit_keeps_protected_paths_supported(tmp_path, sealed, harness, host, grader):
    predicate, _ = watched_run(tmp_path, sealed, (harness, host, grader),
                               lambda root: (root / "func.py").write_text("def add(a, b):\n    return a + b\n"))
    assert predicate["checks"][0]["decision"] == "supported"
    assert predicate["verdict"]["decision"] == "not_established"


def test_route_b_needs_a_started_watch(tmp_path):
    with pytest.raises(DoneError):
        seats.HostWatch(tmp_path, tmp_path / "run").end("c", "i", tmp_path / "none")
