"""Refuse reselected semantic mutations, not only stale content hashes."""

import copy
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from probity_adk_nested.contract import decode, encode, sha
from probity_adk_nested.reader import host_policy, read


class SemanticControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "packet"
        shutil.copytree(Path(os.environ["ADK_NESTED_PACKET"]), self.root)

    def get(self, name):
        return decode((self.root / name).read_bytes())

    def put(self, name, value):
        (self.root / name).write_bytes(encode(value))

    def mutate(self, name, change):
        value = self.get(name)
        change(value)
        self.put(name, value)

    def decision(self):
        policy = encode(host_policy(self.root))
        return read(self.root, policy, sha(policy))

    def refusal(self):
        with self.assertRaises(ValueError):
            self.decision()

    def test_positive_population_and_hold(self):
        result = self.decision()
        self.assertEqual([r["nativeToolEffects"] for r in result["rows"]], [6] * 4)
        self.assertEqual(result["rows"][-1]["publicationDecision"], "hold-nested-plugin-coverage")

    def test_callback_sequence(self):
        self.mutate("cases/token/plugin-after-parent-close.json", lambda d: d["records"][-1].update(sequence=0))
        self.refusal()

    def test_callback_failure(self):
        self.mutate("cases/token/plugin-before-parent-close.json", lambda d: d.update(failures=1))
        self.refusal()

    def test_premature_shared_plugin_close(self):
        self.mutate("cases/token/plugin-after-parent-close.json", lambda d: d["records"][-1]["native"].update(phase="run-active"))
        self.refusal()

    def test_parent_closes_plugin_twice(self):
        self.mutate("cases/token/plugin-after-parent-close.json", lambda d: d.update(closeCalls=2))
        self.refusal()

    def test_parent_config_mutation(self):
        self.put("cases/token/parent-config-after.json", {"json": None})
        self.refusal()

    def test_nested_window_trigger(self):
        for n in ("plugin-before-parent-close.json", "plugin-after-parent-close.json"):
            def change(d):
                r = [r for r in d["records"] if r["callback"] == "config-before-run"][1]
                c = decode(bytes.fromhex(r["native"]["configJSONHex"]))
                c.update(compaction_interval=10000, overlap_size=0)
                r["native"]["configJSONHex"] = encode(c).hex()
            self.mutate("cases/token/" + n, change)
        self.refusal()

    def test_missing_nested_token_config(self):
        for n in ("plugin-before-parent-close.json", "plugin-after-parent-close.json"):
            self.mutate("cases/token/" + n, lambda d: [r for r in d["records"] if r["callback"] == "config-before-run"][2]["native"].update(configJSONHex=None))
        self.refusal()

    def test_repeated_nested_session_identity(self):
        for n in ("plugin-before-parent-close.json", "plugin-after-parent-close.json"):
            def change(d):
                configs = [r for r in d["records"] if r["callback"] == "config-before-run"]
                configs[4]["native"]["sessionId"] = configs[2]["native"]["sessionId"]
            self.mutate("cases/token/" + n, change)
        self.refusal()

    def test_repeated_leaf_history_leak(self):
        models = self.get("cases/token/model-requests.json")
        value = models["leaf"][4]["value"]
        value["contents"].append({"role": "model", "parts": [{"text": "NESTED SUMMARY"}]})
        models["leaf"][4]["jsonHex"] = encode(value).hex()
        self.put("cases/token/model-requests.json", models)
        for n in ("plugin-before-parent-close.json", "plugin-after-parent-close.json"):
            def change(d):
                r = [r for r in d["records"] if r["callback"] == "before-model" and r["native"]["value"]["config"]["labels"] is None][9]
                v = copy.deepcopy(value)
                v["config"]["labels"] = None
                r["native"] = {"value": v, "jsonHex": encode(v).hex()}
            self.mutate("cases/token/" + n, change)
        self.refusal()

    def test_native_model_callback_join(self):
        self.mutate("cases/token/model-requests.json", lambda d: d["leaf"].pop())
        self.refusal()

    def test_direct_summarizer_callback_laundering(self):
        def change(d):
            v = d["summarizer"][0]["value"]
            v["config"]["labels"] = {"adk_agent_name": "leaf"}
            d["summarizer"][0]["jsonHex"] = encode(v).hex()
        self.mutate("cases/token/model-requests.json", change)
        self.refusal()

    def test_native_duplicate_json_admission(self):
        self.mutate("cases/token/model-requests.json", lambda d: d["leaf"][0].update(jsonHex=b'{"contents":[],"contents":[]}'.hex()))
        self.refusal()

    def test_foreign_effect_call(self):
        self.mutate("cases/token/tool-effects.json", lambda d: d[0].update(functionCallId="foreign-call"))
        self.refusal()

    def test_effect_operator_laundering(self):
        self.mutate("cases/token/tool-effects.json", lambda d: d[0].update(operator="outside-operator"))
        self.refusal()

    def test_unmediated_extra_workspace_effect(self):
        (self.root / "cases/token/workspace/unobserved.txt").write_bytes(b"extra")
        self.refusal()

    def test_observer_signature(self):
        self.mutate("cases/token/observer-packet.json", lambda d: d.update(claimSignature="00" * 64))
        self.refusal()

    def test_no_plugin_coverage_laundering(self):
        self.mutate("native-result.json", lambda d: d["rows"][-1].update(nestedPluginCoverage=True))
        self.refusal()

    def test_candidate_claims_publication(self):
        self.mutate("native-result.json", lambda d: d.update(publicationDecision="admit-everything"))
        self.refusal()

    def test_unselected_host_policy(self):
        raw = encode(host_policy(self.root))
        with self.assertRaisesRegex(ValueError, "selected-host-policy"):
            read(self.root, raw, "00" * 32)


if __name__ == "__main__":
    unittest.main()
