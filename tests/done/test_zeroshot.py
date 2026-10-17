"""The zero-shot template: shipped text, parsed answers, refusals, and a sealed contract."""

import json
import shutil

import pytest

from probity_observer.done import contract, zeroshot
from probity_observer.done.formats import DoneError
from probity_observer.done.runner import SubprocessRunner


class Fixed:
    name = "fixed-test-model"

    def __init__(self, answer):
        self.answer = answer
        self.prompts = []

    def complete(self, prompt):
        self.prompts.append(prompt)
        return self.answer


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "tests").mkdir(parents=True)
    (root / "app.py").write_text("def double(x):\n    return x\n")
    (root / "tests" / "test_app.py").write_text(
        "import os, sys\nsys.path.insert(0, os.getcwd())\nfrom app import double\n\n\n"
        "def test_double():\n    assert double(2) == 4\n    assert double(0) == 0\n")
    return root


ANSWER = json.dumps({"acceptance": [{"id": "unit", "argv": ["python", "-m", "pytest", "-q",
                                                             "-p", "no:cacheprovider",
                                                             "tests/test_app.py"],
                                     "expect_on_start": "fail"}],
                     "protected_paths": [{"path": "tests", "kind": "directory"}],
                     "rationale": "the test file checks doubling"})


def test_template_text_is_shipped_and_filled(repo):
    text = zeroshot.template()
    assert "{task}" in text and "expect_on_start" in text
    prompt = zeroshot.render(repo, "make double double")
    assert "make double double" in prompt and "tests/test_app.py" in prompt
    assert "def test_double" in prompt


def test_a_proposal_seals_after_stability(tmp_path, repo, harness, python_bin):
    model = Fixed("Here it is:\n" + ANSWER)
    proposal = zeroshot.propose(repo, "repo-double", "make double double", model)
    assert len(model.prompts) == 1 and proposal.record["model"] == "fixed-test-model"
    sealed = contract.compile_task(proposal.task, tmp_path / "out", harness,
                                   SubprocessRunner(python_bin), timeout=60)
    compiled = json.loads((sealed.out / "sealed" / "compile.json").read_bytes())
    assert compiled["model_calls"] == 1 and compiled["notes"]["proposal"]["template_sha256"]
    assert sealed.record["protected_paths"][0]["exclude"] == list(contract.EXCLUDE)


@pytest.mark.parametrize("answer", [
    json.dumps({"acceptance": [{"id": "a", "argv": ["sh", "-c", "test -f DONE"],
                                "expect_on_start": "fail"}],
                "protected_paths": [], "rationale": ""}),
    "no json here",
    "{not json}",
    json.dumps({"acceptance": []}),
    json.dumps({"acceptance": [], "protected_paths": [], "rationale": ""}),
    json.dumps({"acceptance": [{"id": "a", "argv": [], "expect_on_start": "fail"}],
                "protected_paths": [], "rationale": ""}),
    json.dumps({"acceptance": [{"id": "a", "argv": ["x"]}], "protected_paths": [], "rationale": ""}),
    json.dumps({"acceptance": [{"id": "a", "argv": ["x"], "expect_on_start": "fail"}],
                "protected_paths": [{"path": "missing.py", "kind": "file"}], "rationale": ""}),
    json.dumps({"acceptance": [{"id": "a", "argv": ["x"], "expect_on_start": "fail"}],
                "protected_paths": [{"path": "../etc", "kind": "directory"}], "rationale": ""}),
    json.dumps({"acceptance": [{"id": "a", "argv": ["x"], "expect_on_start": "fail"}],
                "protected_paths": "tests", "rationale": ""}),
    json.dumps({"acceptance": [{"id": "a", "argv": ["x"], "expect_on_start": "fail"}],
                "protected_paths": [{"path": "tests"}], "rationale": ""}),
])
def test_malformed_answers_are_refused(repo, answer):
    with pytest.raises(DoneError):
        zeroshot.propose(repo, "t", "task", Fixed(answer))


def test_chat_model_posts_one_request(monkeypatch):
    seen = {}

    class Reply:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()

    def urlopen(request, timeout):
        seen["url"], seen["body"] = request.full_url, json.loads(request.data)
        return Reply()

    monkeypatch.setattr(zeroshot.urllib.request, "urlopen", urlopen)
    assert zeroshot.ChatModel("http://h:8000/", "gpt-oss-120b").complete("p") == "ok"
    assert seen["url"] == "http://h:8000/v1/chat/completions"
    assert seen["body"]["model"] == "gpt-oss-120b" and seen["body"]["temperature"] == 0


def test_a_reference_gives_the_proposal_mutants(tmp_path, repo, harness, python_bin):
    reference = tmp_path / "reference"
    shutil.copytree(repo, reference)
    (reference / "app.py").write_text("def double(x):\n    return x * 2\n")
    proposal = zeroshot.propose(repo, "repo-double", "make double double", Fixed(ANSWER), reference)
    assert proposal.task.mutation_targets == {"app.py": None}
    sealed = contract.compile_task(proposal.task, tmp_path / "out", harness,
                                   SubprocessRunner(python_bin), timeout=60)
    assert sealed.record["adequacy"]["killed"] >= 1
