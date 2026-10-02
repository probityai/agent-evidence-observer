"""Retain selected installed-reader evidence and a separate host score decision."""

from __future__ import annotations
import argparse
import hashlib
import json
import math
import subprocess
import sys
from pathlib import Path

FORMAT_PROFILE = "probity-local-cpu-format-control-v1"
DIGEST_KEYS = ("pinsSha256", "readerSha256")
LIMIT_KEYS = (
    "elapsedNs",
    "promptTokens",
    "completionTokens",
    "returnedCallProcessCpuNs",
    "processLifetimePeakRssKiB",
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def unique(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate JSON member")
            value[key] = item
        return value

    return json.loads(
        raw,
        object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")),
    )


def save(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def integer(value):
    if type(value) is not int or value < 0:
        raise ValueError("policy counts and limits require nonnegative integers")
    return value


def row_id(row):
    if type(row) is not dict:
        raise ValueError("quality row must be an object")
    names = ("configuration", "family")
    if "model" in row:
        names = ("model", *names)
    if "decoder" in row:
        if "model" not in row:
            raise ValueError("decoder selection requires a model identity")
        names = ("decoder", *names)
    if any(type(row.get(name)) is not str or not row[name] for name in names):
        raise ValueError("row selection requires nonempty string identities")
    return tuple((name, row[name]) for name in names)


def validate_row(row, format_profile=False):
    names = {"configuration", "family", "planned", "minCorrect", "minFormatValid"}
    if "model" in row:
        names.add("model")
    if format_profile:
        names.update({"model", "decoder", "minSchemaValid"})
    if set(row) != names:
        raise ValueError("policy row fields differ")
    row_id(row)
    count_names = ("planned", "minCorrect", "minFormatValid")
    if format_profile:
        count_names += ("minSchemaValid",)
    counts = [integer(row[name]) for name in count_names]
    if counts[0] == 0 or max(counts[1:]) > counts[0]:
        raise ValueError("policy row threshold exceeds selected population")


def validate_policy(policy):
    keys = {"schema", "profile", "planned", "rows", "limits", *DIGEST_KEYS}
    if type(policy) is not dict or set(policy) != keys:
        raise ValueError("policy fields differ")
    format_profile = policy.get("profile") == FORMAT_PROFILE
    expected_schema = (
        "probity-model-publication-policy-v2"
        if format_profile
        else "probity-model-publication-policy-v1"
    )
    if policy["schema"] != expected_schema:
        raise ValueError("policy schema differs")
    if type(policy["profile"]) is not str or not policy["profile"]:
        raise ValueError("policy profile requires a nonempty string")
    if integer(policy["planned"]) == 0:
        raise ValueError("empty policy population")
    for name in DIGEST_KEYS:
        value = policy[name]
        if (
            type(value) is not str
            or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)
        ):
            raise ValueError("policy requires lowercase SHA256 selections")
    if type(policy["rows"]) is not list or not policy["rows"]:
        raise ValueError("policy requires every quality row")
    for row in policy["rows"]:
        validate_row(row, format_profile)
    identities = [row_id(row) for row in policy["rows"]]
    if len(set(identities)) != len(identities):
        raise ValueError("duplicate selected quality row")
    if sum(row["planned"] for row in policy["rows"]) != policy["planned"]:
        raise ValueError("selected quality rows do not cover population")
    if type(policy["limits"]) is not dict or set(policy["limits"]) != set(LIMIT_KEYS):
        raise ValueError("policy resource fields differ")
    for value in policy["limits"].values():
        integer(value)


def report_rows(report, policy):
    population = report["population"]
    expected = {
        "planned": policy["planned"],
        "started": policy["planned"],
        "scored": policy["planned"],
        "error": 0,
        "incomplete": 0,
        "unknown-start": 0,
    }
    format_profile = policy["profile"] == FORMAT_PROFILE
    if format_profile:
        expected["unsupported"] = 0
    if population != expected or any(type(x) is not int for x in population.values()):
        raise ValueError("report population differs from host selection")
    if report["profile"] != policy["profile"]:
        raise ValueError("reader profile differs from host selection")
    if report["publicationDecision"] != "publish-scoped-report":
        raise ValueError("native reader holds incomplete or over-budget evidence")
    if report["evidence"] != {"complete": True, "withinRunBudget": True} or any(
        type(x) is not bool for x in report["evidence"].values()
    ):
        raise ValueError("native evidence validity is not established")
    rows = report["quality"]
    if type(rows) is not list or not rows:
        raise ValueError("quality report requires a nonempty row array")
    identities = [row_id(row) for row in rows]
    if len(set(identities)) != len(identities) or set(identities) != {
        row_id(row) for row in policy["rows"]
    }:
        raise ValueError("quality row population differs from host selection")
    for row in rows:
        for name in (
            "planned",
            "scored",
            "correct",
            "formatValid",
            "promptTokens",
            "completionTokens",
            "callElapsedNs",
            "processCpuNs",
            "processLifetimePeakRssKiB",
        ):
            integer(row[name])
        if (
            row["scored"] != row["planned"]
            or not row["correct"] <= row["formatValid"] <= row["planned"]
        ):
            raise ValueError("quality row counts are inconsistent")
        if format_profile and not (
            row["correct"] <= integer(row["schemaValid"]) <= row["formatValid"]
        ):
            raise ValueError("schema-valid quality counts are inconsistent")
    if sum(row["planned"] for row in rows) != policy["planned"]:
        raise ValueError("quality row counts differ from population")
    tokens = report["nativeTokens"]
    if type(tokens) is not dict or set(tokens) != {"prompt", "completion"}:
        raise ValueError("native token subtotal fields differ")
    for key, row_key in (
        ("prompt", "promptTokens"),
        ("completion", "completionTokens"),
    ):
        if integer(tokens[key]) != sum(row[row_key] for row in rows):
            raise ValueError("quality row token subtotals differ from native total")
    if sum(row["callElapsedNs"] for row in rows) > integer(report["elapsed_ns"]):
        raise ValueError("summed serial call time exceeds native elapsed envelope")
    return {row_id(row): row for row in rows}


def decide(report, policy):
    rows = report_rows(report, policy)
    failures = []
    for selected in policy["rows"]:
        measured = rows[row_id(selected)]
        if measured["planned"] != selected["planned"]:
            raise ValueError("selected row denominator differs")
        thresholds = [("minCorrect", "correct"), ("minFormatValid", "formatValid")]
        if policy["profile"] == FORMAT_PROFILE:
            thresholds.append(("minSchemaValid", "schemaValid"))
        for threshold, field in thresholds:
            if measured[field] < selected[threshold]:
                failures.append(
                    {
                        "row": dict(row_id(selected)),
                        "field": field,
                        "measured": measured[field],
                        "minimum": selected[threshold],
                    }
                )
    resources = {
        "elapsedNs": integer(report["elapsed_ns"]),
        "promptTokens": integer(report["nativeTokens"]["prompt"]),
        "completionTokens": integer(report["nativeTokens"]["completion"]),
        "returnedCallProcessCpuNs": sum(row["processCpuNs"] for row in rows.values()),
        "processLifetimePeakRssKiB": max(
            row["processLifetimePeakRssKiB"] for row in rows.values()
        ),
    }
    for name, measured in resources.items():
        if measured > policy["limits"][name]:
            failures.append(
                {
                    "resource": name,
                    "measured": measured,
                    "maximum": policy["limits"][name],
                }
            )
    return {
        "evidenceDecision": "verified",
        "publicationDecision": "publish"
        if not failures
        else "hold-selected-score-or-resource",
        "policyFailures": failures,
        "resources": resources,
        "scope": "host-selected report publication; no dispatch or recovery authority",
    }


def launch(command, output, timeout):
    streams = [output / "reader.stdout", output / "reader.stderr"]
    with streams[0].open("xb") as stdout, streams[1].open("xb") as stderr:
        try:
            child = subprocess.run(
                command, stdout=stdout, stderr=stderr, timeout=timeout, check=False
            )
            result = {"returncode": child.returncode, "timedOut": False}
        except subprocess.TimeoutExpired:
            result = {"returncode": None, "timedOut": True}
    result["streams"] = {
        path.name: {"bytes": path.stat().st_size, "sha256": digest(path.read_bytes())}
        for path in streams
    }
    save(output / "child.json", result)
    return result


def gate(packet, pins_file, policy_file, policy_sha256, output, timeout):
    if output.resolve().is_relative_to(packet.resolve()):
        raise ValueError("receipt directory must be outside producer packet")
    output.mkdir(parents=True, exist_ok=False)
    receipt = {
        "evidenceDecision": "not-verified",
        "publicationDecision": "hold",
        "policySha256": policy_sha256,
        "launched": False,
    }
    try:
        if (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or timeout <= 0
            or timeout > 600
        ):
            raise ValueError("reader timeout must be positive and at most600seconds")
        if any(
            path.resolve().is_relative_to(packet.resolve())
            for path in (pins_file, policy_file, output)
        ):
            raise ValueError(
                "host policy, pins and receipts must be outside producer packet"
            )
        raw = policy_file.read_bytes()
        (output / "policy.json").write_bytes(raw)
        if digest(raw) != policy_sha256:
            raise ValueError("policy differs from reviewed raw bytes")
        policy = strict_json(raw)
        validate_policy(policy)
        pins = pins_file.read_bytes()
        if digest(pins) != policy["pinsSha256"]:
            raise ValueError("pins differ from reviewed policy")
        strict_json(pins)
        frozen = output / "selected-pins.json"
        frozen.write_bytes(pins)
        command = [
            "probity-model-task-read",
            str(packet.resolve()),
            "--pins-file",
            str(frozen.resolve()),
            "--reader-sha256",
            policy["readerSha256"],
        ]
        save(
            output / "launch.json",
            {
                "command": command,
                "timeoutSeconds": timeout,
                "policySha256": digest(raw),
                "pinsSha256": digest(pins),
            },
        )
        receipt["launched"] = True
        child = launch(command, output, timeout)
        receipt["child"] = child
        if child["timedOut"] or child["returncode"] != 0:
            raise ValueError("installed reader timed out or refused selected evidence")
        if child["streams"]["reader.stdout"]["bytes"] > 10 * 1024 * 1024:
            raise ValueError("reader report exceeds selected10MiB envelope")
        report = strict_json((output / "reader.stdout").read_bytes())
        receipt.update(decide(report, policy))
        save(output / "verified-report.json", report)
    except (OSError, ValueError, TypeError, KeyError) as error:
        receipt["reason"] = str(error)
    save(output / "gate.json", receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--pins-file", type=Path, required=True)
    parser.add_argument("--policy-file", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=60)
    args = parser.parse_args()
    try:
        receipt = gate(
            args.packet,
            args.pins_file,
            args.policy_file,
            args.policy_sha256,
            args.output,
            args.timeout_seconds,
        )
    except (OSError, ValueError) as error:
        print(json.dumps({"publicationDecision": "hold", "reason": str(error)}))
        raise SystemExit(1) from error
    print(json.dumps(receipt, indent=2))
    sys.exit(0 if receipt["publicationDecision"] == "publish" else 1)
