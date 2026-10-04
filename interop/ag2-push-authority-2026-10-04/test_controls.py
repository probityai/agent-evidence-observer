"""Refuse semantic changes after their hashes have been reselected by the host."""

import copy
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from probity_ag2_push.contract import decode, encode, json_original, sha
from probity_ag2_push.reader import host_policy, read


class Controls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "packet"
        shutil.copytree(os.environ["AG2_PUSH_PACKET"], self.root)

    def mutate(self, relative, function):
        path = self.root / relative
        value = decode(path.read_bytes())
        function(value)
        path.write_bytes(encode(value))

    def refused(self):
        raw = encode(host_policy(self.root))
        with self.assertRaises((ValueError, KeyError, TypeError)):
            read(self.root, raw, sha(raw))

    def test_native_reference(self):
        raw = encode(host_policy(self.root))
        result = read(self.root, raw, sha(raw))
        self.assertEqual(result["status"], "verified")
        self.assertEqual(sum(r["observedWrites"] for r in result["rows"]), 3)

    def test_callback_sequence(self):
        self.mutate("cases/jsonrpc/accepted/native-callbacks.json",
                    lambda v: v["records"][0].update(sequence=99))
        self.refused()

    def test_capture_failure(self):
        self.mutate("cases/rest/accepted/native-callbacks.json", lambda v: v.update(failures=1))
        self.refused()

    def test_foreign_registration_task(self):
        def change(v):
            r = next(r for r in v["records"] if r["phase"] == "before" and
                     r["method"] == "create_task_push_notification_config")
            n = json_original(r["native"]["protobufJSONHex"])
            n["task_id"] = "foreign-task"
            r["native"]["protobufJSONHex"] = encode(n).hex()
        self.mutate("cases/grpc/accepted/native-callbacks.json", change)
        self.refused()

    def test_changed_registration_url(self):
        self.mutate("cases/rest/accepted/push-operations.json",
                    lambda v: v[0]["submitted"].update(url="https://foreign.example/"))
        self.refused()

    def test_dropped_stored_config(self):
        (self.root / "cases/jsonrpc/accepted/stored-configs.json").write_bytes(b"[]")
        self.refused()

    def test_dispatch_policy_laundering(self):
        self.mutate("cases/grpc/dispatch-denied/url-policy.json",
                    lambda v: v["dispatch"][0].update(accepted=True))
        self.refused()

    def test_target_task_changed(self):
        def change(v):
            raw = json_original(v[0]["bodyJSONHex"])
            raw["task"]["id"] = "foreign-task"
            b = encode(raw)
            v[0].update(bodyJSONHex=b.hex(), bodySHA256=sha(b))
        self.mutate("cases/rest/accepted/target-callbacks.json", change)
        self.refused()

    def test_target_token_changed(self):
        self.mutate("cases/jsonrpc/accepted/target-callbacks.json",
                    lambda v: v[0]["headers"].update(authorization="Bearer foreign"))
        self.refused()

    def test_target_denial_laundering(self):
        self.mutate("cases/grpc/target-denied/target-callbacks.json",
                    lambda v: v[0].update(targetAccepted=True, responseStatus=200))
        self.refused()

    def test_duplicate_raw_json(self):
        def change(v):
            b = b'{"task":{},"task":{}}'
            v[0].update(bodyJSONHex=b.hex(), bodySHA256=sha(b))
        self.mutate("cases/rest/accepted/target-callbacks.json", change)
        self.refused()

    def test_signed_history_change(self):
        path = self.root / "cases/jsonrpc/accepted/history.jsonl"
        path.write_bytes(path.read_bytes().replace(b"/work/result.txt", b"/work/forged.txt"))
        self.refused()

    def test_changed_broker_authority(self):
        self.mutate("cases/rest/accepted/authority-before-run.json", lambda v: v.update(scope="/elsewhere"))
        self.refused()

    def test_unmediated_effect(self):
        (self.root / "cases/grpc/registration-denied/workspace/injected.txt").write_bytes(b"injected")
        self.refused()

    def test_candidate_publication_decision(self):
        self.mutate("native-result.json", lambda v: v.update(publicationDecision="admit"))
        self.refused()

    def test_unselected_host_policy(self):
        raw = encode(host_policy(self.root))
        with self.assertRaises(ValueError):
            read(self.root, raw, "0" * 64)


if __name__ == "__main__":
    unittest.main()
