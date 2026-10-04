"""Trusted source controls and semantic refusals over the actual native packet."""

from __future__ import annotations

import copy
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from probity_adk_responses.contract import decode, encode, sha
from probity_adk_responses.reader import host_policy, read

spec = importlib.util.spec_from_file_location("selected_bootstrap", Path(__file__).with_name("bootstrap.py"))
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class InstallationControls(unittest.TestCase):
    def setUp(self):
        self.source = {"pythonGitBlobs": {"runners.py": "native-blob"},
                       "observerPythonGitBlobs": {"probity_observer/verify.py": "observer-blob"}}
        self.owned = {"reader.py": "owned-blob"}
        self.probe = {"files": {"probity_adk_responses": self.owned,
                                 "probity_observer": {"verify.py": "observer-blob"}},
                      "versions": {"probity_adk_responses": "0.0.1",
                                   "probity_observer": "0.0.1"},
                      "pythonVersion": [3, 13, 15], "forbidden": [], "sdkPresent": False}

    def test_selected_framework_free_installation(self):
        bootstrap.check_installation(self.probe, self.source, self.owned, "reader")

    def test_source_cache_framework_version_controls(self):
        for field, value in (("forbidden", ["cached.pyc"]), ("sdkPresent", True),
                             ("pythonVersion", [3, 12, 0]), ("files", {}),
                             ("versions", {})):
            with self.subTest(field=field), self.assertRaises(ValueError):
                probe = copy.deepcopy(self.probe)
                probe[field] = value
                bootstrap.check_installation(probe, self.source, self.owned, "reader")

    def test_native_population_is_exact(self):
        probe = copy.deepcopy(self.probe)
        probe["files"]["adk"] = self.source["pythonGitBlobs"].copy()
        probe["versions"]["adk"] = "2.11.0"
        probe["sdkPresent"] = True
        bootstrap.check_installation(probe, self.source, self.owned, "producer")
        probe["files"]["adk"]["unselected.py"] = "extra"
        with self.assertRaisesRegex(ValueError, "installed-source-population"):
            bootstrap.check_installation(probe, self.source, self.owned, "producer")

    def test_child_failure_is_retained_before_raising(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaisesRegex(ValueError, "child-failed"):
                bootstrap.child([sys.executable, "-c", "import sys; print('primary');sys.exit(7)"],
                                root / "attempt", root)
            self.assertEqual((root / "attempt.stdout").read_bytes(), b"primary\n")
            self.assertEqual(decode((root / "attempt.status.json").read_bytes())["returncode"], 7)


class NativeSemanticControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.retained = Path(os.environ["ADK_RESPONSES_PACKET"])
        if not (cls.retained / "native-result.json").is_file():
            raise ValueError("actual-native-packet-required")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "packet"
        shutil.copytree(self.retained, self.root)
        self.addCleanup(self.temp.cleanup)

    def decision(self):
        selected = encode(host_policy(self.root))
        return read(self.root, selected, sha(selected))

    def edit(self, case, name, mutate):
        path = self.root / "cases" / case / name
        value = decode(path.read_bytes())
        mutate(value)
        path.write_bytes(encode(value))

    def test_genuine_actual_native_packet_and_literal_repeat(self):
        decision = encode(self.decision())
        self.assertEqual(decision, encode(self.decision()))
        self.assertEqual([r["observedWrites"] for r in decode(decision)["rows"]], [1, 0, 1])

    def test_wrong_confirmation_call_id_even_with_reselected_original_bytes(self):
        def mutate(value):
            content = value["value"]
            part = content["parts"][0]
            response = part.get("function_response", part.get("functionResponse"))
            response["id"] = "foreign-call"
            value["jsonHex"] = encode(content).hex()
        self.edit("approval-granted", "supplied-user-response.json", mutate)
        with self.assertRaisesRegex(ValueError, "supplied-response-call-binding"):
            self.decision()

    def test_response_sent_to_root_is_refused(self):
        def mutate(value):
            for event in value[1]:
                event["value"]["author"] = "root"
                event["jsonHex"] = encode(event["value"]).hex()
        self.edit("long-running-completed", "turns.json", mutate)
        with self.assertRaisesRegex(ValueError, "response-issuer"):
            self.decision()

    def test_plain_text_trapped_at_issuer_is_refused(self):
        def mutate(value):
            value[2][0]["value"]["author"] = "issuer"
            value[2][0]["jsonHex"] = encode(value[2][0]["value"]).hex()
        self.edit("approval-granted", "turns.json", mutate)
        with self.assertRaisesRegex(ValueError, "plain-text-root"):
            self.decision()

    def test_omitted_callback_is_refused_after_reselection(self):
        def mutate(value):
            value["records"] = [r for r in value["records"]
                                if r["callback"] != "before-agent"]
            for index, record in enumerate(value["records"]):
                record["sequence"] = index
        self.edit("approval-granted", "callbacks.json", mutate)
        with self.assertRaisesRegex(ValueError, "callback-routed-agents"):
            self.decision()

    def test_open_or_failed_capture_is_refused(self):
        for key, bad in (("closed", False), ("failures", 1), ("capturePayloads", False)):
            with self.subTest(key=key):
                path = self.root / "cases" / "approval-denied" / "callbacks.json"
                original = path.read_bytes()
                value = decode(original)
                value[key] = bad
                path.write_bytes(encode(value))
                with self.assertRaisesRegex(ValueError, "capture-closed-complete"):
                    self.decision()
                path.write_bytes(original)

    def test_foreign_model_agent_label_is_refused(self):
        def mutate(value):
            record = value["issuer"][1]
            record["value"]["config"]["labels"]["adk_agent_name"] = "root"
            record["jsonHex"] = encode(record["value"]).hex()
        self.edit("long-running-completed", "model-requests.json", mutate)
        with self.assertRaisesRegex(ValueError, "callback-model-request-population"):
            self.decision()

    def test_post_callback_request_change_is_refused(self):
        def mutate(value):
            record = value["issuer"][1]
            record["value"]["contents"][0]["parts"][0]["text"] = "changed input"
            record["jsonHex"] = encode(record["value"]).hex()
        self.edit("approval-granted", "model-requests.json", mutate)
        with self.assertRaisesRegex(ValueError, "callback-model-request-population"):
            self.decision()

    def test_early_callback_label_is_refused(self):
        def mutate(value):
            record = next(r["native"] for r in value["records"]
                          if r["callback"] == "before-model")
            record["value"]["config"]["labels"] = {"adk_agent_name": "root"}
            record["jsonHex"] = encode(record["value"]).hex()
        self.edit("approval-granted", "callbacks.json", mutate)
        with self.assertRaisesRegex(ValueError, "callback-pre-label-state"):
            self.decision()

    def test_native_original_ast_mismatch_is_refused(self):
        self.edit("approval-granted", "session.json", lambda value:
                  value["value"].update({"id": "invented"}))
        with self.assertRaisesRegex(ValueError, "native-original-byte-mismatch"):
            self.decision()

    def test_denial_does_not_become_an_executed_tool_body(self):
        self.edit("approval-denied", "tool-bodies.json", lambda value:
                  value.append({"tool": "approved_write"}))
        with self.assertRaisesRegex(ValueError, "denied-no-body-or-effect"):
            self.decision()

    def test_host_completion_does_not_become_native_tool_effect(self):
        self.edit("long-running-completed", "operator-effects.json", lambda value:
                  value[0].update({"effectOperator": "tool-body"}))
        with self.assertRaisesRegex(ValueError, "host-completion-distinct"):
            self.decision()

    def test_changed_target_bytes_are_refused(self):
        (self.root / "cases" / "approval-granted" / "workspace" / "result.txt").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.decision()

    def test_fabricated_quality_or_publication_is_refused(self):
        path = self.root / "native-result.json"
        value = decode(path.read_bytes())
        value["modelQuality"] = "evaluated"
        path.write_bytes(encode(value))
        with self.assertRaisesRegex(ValueError, "native-result-reconstruction"):
            self.decision()

    def test_stale_passing_decision_removed_on_refusal(self):
        root = self.root.parent
        policy = encode(host_policy(self.root))
        (root / "policy.json").write_bytes(policy)
        output = root / "decision.json"
        output.write_bytes(b"old passing decision")
        command = "from probity_adk_responses.reader import main; raise SystemExit(main())"
        child = subprocess.run([sys.executable, "-I", "-B", "-c", command, str(self.root),
                                "--policy", str(root / "policy.json"), "--policy-sha256", "0" * 64,
                                "--output", str(output)], capture_output=True, check=False)
        self.assertNotEqual(child.returncode, 0)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
