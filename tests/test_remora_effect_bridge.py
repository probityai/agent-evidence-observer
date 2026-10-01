"""Check the retained local effect probe and its source pin."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "examples" / "remora_effect_bridge.py"
SPEC = importlib.util.spec_from_file_location("remora_effect_bridge", SOURCE)
assert SPEC is not None and SPEC.loader is not None
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)


def _source(path):
    cases = [
        ("AR-00", "EFFECT_VERIFIED", 1, [{"op": "approve"}, {"op": "dispatch"}]),
        ("AR-01", "CALL_BINDING_MISMATCH", 0, [{"op": "approve"}, {"op": "dispatch", "arguments": {"to": "acct-99"}}]),
        ("AR-02", "IDENTITY_MISMATCH", 0, [{"op": "approve"}, {"op": "dispatch", "actor": "svc-reporting"}]),
        ("AR-03", "CALL_BINDING_MISMATCH", 0, [{"op": "approve"}, {"op": "register_alternate_tool"}, {"op": "dispatch", "tool": "wire_transfer"}]),
        ("AR-04", "CONTEXT_CHANGED", 0, [{"op": "approve"}, {"op": "change_policy_bundle"}, {"op": "dispatch"}]),
        ("AR-05", "EFFECT_MISMATCH", 1, [{"op": "approve"}, {"op": "dispatch"}, {"op": "verify_effect"}]),
    ]
    path.write_text(json.dumps({
        "suite": "autoreview-to-effect-v1",
        "vectors": [
            {"id": name, "expect": expected, "executions": count, "steps": steps}
            for name, expected, count, steps in cases
        ],
    }))


def test_retained_effects_can_be_checked_again(tmp_path, monkeypatch):
    source = tmp_path / "vectors.json"
    _source(source)
    monkeypatch.setattr(bridge, "VECTOR_SHA256", hashlib.sha256(source.read_bytes()).hexdigest())
    output = tmp_path / "run"
    report = bridge.run(output, source)
    assert [item["nativeWriteEvents"] for item in report["results"]] == [1, 0, 0, 0, 0, 1]
    assert report["results"][3]["relationship"] == "unsupported-exact-vector"
    assert bridge.verify_run(output, source)["status"] == "retained-cases-checked"
    (output / "AR-00" / "workspace" / "acct-2.txt").write_bytes(b"changed")
    with pytest.raises(ValueError, match="retained bridge files differ"):
        bridge.verify_run(output, source)


def test_changed_source_fails_before_a_case_runs(tmp_path):
    source = tmp_path / "vectors.json"
    _source(source)
    with pytest.raises(ValueError, match="REMORA vector bytes differ"):
        bridge.run(tmp_path / "run", source)
    assert not (tmp_path / "run").exists()
