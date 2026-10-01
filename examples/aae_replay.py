"""Replay the pinned enforce-core fixtures using the independent Probity kernel."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from probity_observer.aae_enforce import RatifyError, enforce_check, ratify

SOURCE = "MoltyCel/aae-conformance-vectors"
REVISION = "531f880155ea1ce993a7ca74137b12c255d5b2ee"
OWNER_MANIFEST_SHA256 = (
    "3dccb41bf3c84020719d17ea59a232cf001290fd4783882fbe60e856c13a2c82"
)
DEFAULT_FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures/aae-enforce"


def _trace_matches(
    expected: list[dict[str, Any]], actual: list[dict[str, Any]]
) -> bool:
    remaining = iter(actual)
    for wanted in expected:
        match = next(
            (entry for entry in remaining if entry["predicate"] == wanted["predicate"]),
            None,
        )
        if match is None or any(
            match.get(key) != value for key, value in wanted.items()
        ):
            return False
    return True


def _result(vector: dict[str, Any]) -> dict[str, Any]:
    inputs = vector["input"]
    if vector["kernel"] == "enforce_check":
        return enforce_check(
            inputs["mandate"], inputs["transaction"], inputs.get("prev_core_digest")
        )
    return ratify(
        inputs["prior_record"],
        inputs["decision"],
        inputs["authority_proof"],
        inputs.get("prev_core_digest"),
    )


def replay_vector(vector: dict[str, Any]) -> dict[str, Any]:
    """Compare actual verdict/digest/trace with this vector's declared targets."""
    expected = vector["expected"]
    try:
        actual = _result(vector)
    except RatifyError as exc:
        passed = expected.get("error") == "RatifyError"
        passed = passed and expected.get("reason_contains", "") in str(exc)
        return {"id": vector["id"], "passed": passed, "error": str(exc)}
    comparisons = {
        name: actual.get(name) == value
        for name, value in expected.items()
        if name not in ("trace", "reason_contains")
    }
    comparisons["trace"] = _trace_matches(expected.get("trace", []), actual["trace"])
    comparisons["reason"] = expected.get("reason_contains", "") in actual["reason"]
    return {
        "id": vector["id"],
        "passed": all(comparisons.values()),
        "comparisons": comparisons,
        "actual": actual,
    }


def _owner_files(directory: Path) -> list[tuple[Path, dict[str, Any]]]:
    raw_manifest = (directory / "source-manifest.json").read_bytes()
    if hashlib.sha256(raw_manifest).hexdigest() != OWNER_MANIFEST_SHA256:
        raise ValueError(
            "AAE fixture manifest differs from the verified owner manifest"
        )
    manifest = json.loads(raw_manifest)
    if manifest["repository"] != SOURCE or manifest["commit"] != REVISION:
        raise ValueError("AAE fixture source pin differs")
    rows = [row for row in manifest["files"] if row["ownerPath"].endswith(".json")]
    if len(rows) != 26:
        raise ValueError("AAE replay needs exactly 26 pinned enforce fixtures")
    return [
        item
        for row in manifest["files"]
        if (item := _owner_file(directory, row))[0].suffix == ".json"
    ]


def _owner_file(directory: Path, row: dict[str, Any]) -> tuple[Path, Any]:
    path = directory / row["path"]
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != row["sha256"]:
        raise ValueError("AAE fixture bytes differ from the source manifest")
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if blob != row["gitBlobSha"]:
        raise ValueError("AAE fixture bytes differ from the pinned owner blob")
    return path, json.loads(raw) if path.suffix == ".json" else None


def run_replay(directory: Path = DEFAULT_FIXTURES) -> dict[str, Any]:
    """Check all 26 retained owner vectors; do not run the JWS/composition sets."""
    rows = []
    for path, vector in _owner_files(directory):
        row = replay_vector(vector)
        row["fixtureSha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(row)
    return {
        "source": SOURCE,
        "revision": REVISION,
        "kernelVersion": "3.0",
        "passed": sum(row["passed"] for row in rows),
        "total": len(rows),
        "rows": rows,
        "nativeJwsVectorsRun": 0,
        "compositionVectorsRun": 0,
        "issuerAuthentication": "not-established",
        "execution": "not-tested-by-enforce-vectors",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    arguments = parser.parse_args()
    report = run_replay(arguments.fixtures)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] == 26 else 1


if __name__ == "__main__":
    raise SystemExit(main())
