"""Verify selected evidence and apply the host's separate quality thresholds."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import task_matrix


def threshold(raw: str) -> int:
    value = int(raw)
    if not 0 <= value <= 16:
        raise argparse.ArgumentTypeError("threshold must be between zero and sixteen")
    return value


def assess(report: dict, minimum_correct: int, minimum_pairs: int) -> dict:
    """Preserve the verified report; host thresholds do not change its scores."""
    if (
        type(minimum_correct) is not int
        or not 0 <= minimum_correct <= 16
        or type(minimum_pairs) is not int
        or not 0 <= minimum_pairs <= 8
    ):
        raise ValueError("host thresholds exceed the declared row population")
    p = task_matrix.protocol(
        Path(task_matrix.__file__).with_name("protocol.json").read_bytes()
    )
    expected = {
        (cfg["model"], cfg["id"], family)
        for cfg in task_matrix.configurations(p)
        for family in {case["family"] for case in p["cases"]}
    }
    rows = report["quality"]
    identities = [(row["model"], row["configuration"], row["family"]) for row in rows]
    if len(identities) != len(expected) or set(identities) != expected:
        raise ValueError("quality row population differs from frozen profile")
    for row in rows:
        if (
            type(row["correct"]) is not int
            or not 0 <= row["correct"] <= 16
            or type(row["fullyCorrectPairs"]) is not int
            or not 0 <= row["fullyCorrectPairs"] <= 8
        ):
            raise ValueError("quality counts must be finite declared integers")
    evidence_ok = report["publicationDecision"] == "publish-scoped-report"
    failures = [
        {
            "model": row["model"],
            "configuration": row["configuration"],
            "family": row["family"],
            "correct": row["correct"],
            "fullyCorrectPairs": row["fullyCorrectPairs"],
        }
        for row in rows
        if row["correct"] < minimum_correct or row["fullyCorrectPairs"] < minimum_pairs
    ]
    return {
        "schema": "probity-policy-vocabulary-consumer-v1",
        "evidenceDecision": "accept-scoped-evidence"
        if evidence_ok
        else "hold-evidence",
        "qualityDecision": "pass" if not failures else "hold-quality",
        "consumerDecision": (
            "admit-scoped-quality"
            if evidence_ok and not failures
            else "hold-quality"
            if evidence_ok
            else "hold-evidence"
        ),
        "hostThresholds": {
            "minimumCorrectPerRow": minimum_correct,
            "minimumFullyCorrectPairsPerRow": minimum_pairs,
        },
        "qualityFailures": failures,
        "report": report,
        "limits": "Operator-produced finite authored policy tasks; no effects, producer acceptance, recurring outside adoption or independent custody established.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--pins-file", type=Path, required=True)
    parser.add_argument("--minimum-correct-per-row", type=threshold, default=16)
    parser.add_argument("--minimum-pairs-per-row", type=threshold, default=8)
    parser.add_argument(
        "--evidence-only",
        action="store_true",
        help="Exit on evidence validity while still reporting the host quality decision",
    )
    args = parser.parse_args()
    if args.minimum_pairs_per_row > 8:
        parser.error("each row contains only eight declared pairs")
    try:
        pins = task_matrix.strict_json(args.pins_file.read_bytes())
        report = task_matrix.verify(args.packet, pins)
        result = assess(
            report, args.minimum_correct_per_row, args.minimum_pairs_per_row
        )
        rendered = json.dumps(result, indent=2, allow_nan=False)
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        print(
            json.dumps(
                {
                    "schema": "probity-policy-vocabulary-consumer-v1",
                    "consumerDecision": "hold-evidence",
                    "error": {"type": type(exc).__name__, "message": str(exc)},
                },
                sort_keys=True,
            )
        )
        return 1
    print(rendered)
    accepted = (
        result["evidenceDecision"] == "accept-scoped-evidence"
        if args.evidence_only
        else result["consumerDecision"] == "admit-scoped-quality"
    )
    return 0 if accepted else 1


if __name__ == "__main__":
    sys.exit(main())
