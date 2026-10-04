"""Semantic controls reselect file hashes; altered evidence still must be refused."""

import os
from pathlib import Path
import shutil
import tempfile
import unittest

from probity_crewai_jobs.contract import decode, encode, sha
from probity_crewai_jobs.reader import host_policy, read


class Controls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "packet"
        shutil.copytree(Path(os.environ["CREWAI_JOB_PACKET"]), self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def change(self, relative, operation):
        path = self.root / relative
        value = decode(path.read_bytes())
        operation(value)
        path.write_bytes(encode(value))

    @staticmethod
    def wrap_change(wrapper, operation):
        operation(wrapper["value"])
        wrapper["jsonHex"] = encode(wrapper["value"]).hex()

    def refuse(self):
        raw = encode(host_policy(self.root))
        with self.assertRaises(ValueError):
            read(self.root, raw, sha(raw))

    def test_duplicate_native_member(self):
        path = self.root / "direct/valid-stage/native-call.json"
        path.write_bytes(b'{"case":"a","case":"b"}')
        self.refuse()

    def test_nonfinite_native_number(self):
        path = self.root / "direct/valid-stage/native-call.json"
        path.write_bytes(b'{"case":NaN}')
        self.refuse()

    def test_changed_native_return(self):
        self.change("direct/foreign-owner/native-call.json", lambda v: v.update(accepted=True))
        self.refuse()

    def test_nonnull_native_error_enrichment(self):
        self.change("direct/valid-stage/native-call.json",
                    lambda v: self.wrap_change(v["submitted"], lambda u: u.update(error="unselected")))
        self.refuse()

    def test_missing_native_nullable_default(self):
        self.change("direct/valid-stage/native-call.json",
                    lambda v: self.wrap_change(v["submitted"], lambda u: u.pop("error")))
        self.refuse()

    def test_owner_fault_removed(self):
        self.change("direct/foreign-owner/inputs-before-call.json",
                    lambda v: v["candidate"].update(session_id="session:foreign-owner"))
        self.change("direct/foreign-owner/native-call.json",
                    lambda v: self.wrap_change(v["submitted"], lambda u: u.update(session_id="session:foreign-owner")))
        self.refuse()

    def test_revision_fault_removed(self):
        self.change("direct/stale-revision/inputs-before-call.json", lambda v: v["candidate"].update(revision=1))
        self.change("direct/stale-revision/native-call.json",
                    lambda v: self.wrap_change(v["submitted"], lambda u: u.update(revision=1)))
        self.refuse()

    def test_gap_relabelled_contiguous(self):
        self.change("direct/sequence-gap/inputs-before-call.json", lambda v: v["candidate"].update(seq=2))
        self.change("direct/sequence-gap/native-call.json",
                    lambda v: self.wrap_change(v["submitted"], lambda u: u.update(seq=2)))
        self.refuse()

    def test_terminal_before_state_relabelled(self):
        def mutate(v):
            self.wrap_change(v["before"], lambda s: s["jobs"]["job:postterminal"].update(status="running"))
        self.change("direct/postterminal/native-call.json", mutate)
        self.refuse()

    def test_boolean_candidate_relabelled(self):
        self.change("direct/strict-boolean-sequence/inputs-before-call.json",
                    lambda v: v["candidate"].update(seq=1))
        self.refuse()

    def test_callback_sequence_hole(self):
        self.change("cases/valid-runner/callbacks.json", lambda v: v[1].update(sequence=900))
        self.refuse()

    def test_native_receipt_removed(self):
        def mutate(v):
            v.remove(next(r for r in v if r["kind"] == "native-commit-receipt"))
        self.change("cases/valid-runner/callbacks.json", mutate)
        self.refuse()

    def test_refusal_return_changed(self):
        def mutate(v):
            next(r for r in v if r["kind"] == "native-commit-receipt" and r["accepted"] is False)["accepted"] = True
        self.change("cases/refusal-before-body/callbacks.json", mutate)
        self.refuse()

    def test_native_body_request_relabelled(self):
        self.change("cases/effect-before-refusal/body-effects.json", lambda v: v[0].update(requestId="foreign"))
        self.refuse()

    def test_body_operator_relabelled(self):
        self.change("cases/valid-runner/body-effects.json", lambda v: v[0].update(operator="outside"))
        self.refuse()

    def test_current_file_corrupted(self):
        (self.root / "cases/effect-before-refusal/workspace/result.txt").write_bytes(b"changed")
        self.refuse()

    def test_automatic_publication_relabelled(self):
        self.change("cases/valid-runner/manual-publication.json", lambda v: v.update(sdkAutoPublication=True))
        self.refuse()

    def test_prepublication_message_inserted(self):
        self.change("cases/valid-runner/manual-publication.json",
                    lambda v: self.wrap_change(v["before"], lambda s: s["messages"].append(
                        {"role": "assistant", "content": "premature"})))
        self.refuse()

    def test_native_answer_corrupted(self):
        self.change("cases/effect-before-refusal/manual-publication.json",
                    lambda v: self.wrap_change(v["before"], lambda s: s["jobs"]["job:effect-before-refusal"].update(answer="Public answer")))
        self.refuse()

    def test_before_run_population_widened(self):
        self.change("plan-before-run.json", lambda v: v["runnerCases"].append("new-case"))
        self.refuse()

    def test_native_worker_does_not_settle(self):
        self.change("cases/valid-runner/runner-after-close.json", lambda v: v.update(tasksSettled=False))
        self.refuse()

    def test_missing_earlier_commitment(self):
        self.change("cases/valid-runner/begin-before-run.json", lambda v: v.update(checkpoint={}))
        self.refuse()


if __name__ == "__main__":
    unittest.main()
