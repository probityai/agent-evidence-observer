"""Recompute a retained packet using separately selected native and common pins."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from a2a_contract import adapt, verify
from evaluation_contract import decode, require


def read_and_verify(
    output: Path,
    native_pins: dict[str, str],
    plan_pin: str,
    history_pin: str,
    *,
    sources_pin: str | None = None,
) -> dict:
    require(
        type(native_pins) is dict
        and all(
            type(name) is str
            and re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+", name)
            for name in native_pins
        ),
        "artifact_name",
    )
    common = output / "common"
    raw = {name: (common / name).read_bytes() for name in native_pins}
    sources = {
        name: (common / name).read_bytes()
        for name in (
            "sdk-source.json",
            "sdk-source-pins.json",
            "sdk-license.txt",
            "local-source.json",
            "rubric.json",
            "policy.json",
            "runtime.json",
        )
    }
    native = decode(raw["native-plan.json"])
    _, _, reconstructed = adapt(
        native, raw, sources, native_pins, expected_sources_sha256=sources_pin
    )
    require(
        {file.name for file in common.iterdir()}
        == set(reconstructed) | {"plan.json", "history.json"},
        "retained_packet_population",
    )
    artifacts = {name: (common / name).read_bytes() for name in reconstructed}
    return verify(
        native,
        raw,
        sources,
        native_pins,
        (common / "plan.json").read_bytes(),
        (common / "history.json").read_bytes(),
        artifacts,
        expected_plan_sha256=plan_pin,
        expected_history_sha256=history_pin,
        expected_sources_sha256=sources_pin,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--native-pins", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--history-sha256", required=True)
    parser.add_argument(
        "--sources-sha256",
        help="Explicit consumer-selected retained-source map digest; avoids installing producer SDK/runtime",
    )
    args = parser.parse_args()
    print(
        json.dumps(
            read_and_verify(
                args.output,
                decode(args.native_pins.read_bytes()),
                args.plan_sha256,
                args.history_sha256,
                sources_pin=args.sources_sha256,
            ),
            indent=2,
        )
    )
