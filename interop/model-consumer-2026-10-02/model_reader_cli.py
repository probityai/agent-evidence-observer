"""Normally installed offline reader; native execution is never invoked."""

from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import importlib.util
import types


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--pins-file", required=True, type=Path)
    parser.add_argument("--reader-sha256", required=True)
    args = parser.parse_args()
    try:
        candidates = []
        for name in ("model_task_reader", "model_comparison_reader"):
            spec = importlib.util.find_spec(name)
            if spec is not None and spec.origin:
                raw = Path(spec.origin).read_bytes()
                if hashlib.sha256(raw).hexdigest() == args.reader_sha256:
                    candidates.append((spec, raw))
        if len(candidates) != 1:
            raise ValueError("installed reader source differs from host selection")
        spec, source = candidates[0]
        model_task_reader = types.ModuleType("selected_offline_reader")
        model_task_reader.__file__ = spec.origin
        exec(compile(source, spec.origin, "exec"), model_task_reader.__dict__)
        pins = model_task_reader.strict_json(args.pins_file.read_bytes())
        report = model_task_reader.verify(args.packet, pins)
        print(json.dumps(report, indent=2, allow_nan=False))
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps({"readerDecision": "refused", "reason": str(error)}))
        raise SystemExit(1) from error
    if report["publicationDecision"] != "publish-scoped-report":
        raise SystemExit(1)
