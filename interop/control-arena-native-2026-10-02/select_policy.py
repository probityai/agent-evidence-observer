"""Build a consumer selection without deriving its population from candidate logs."""

import argparse
import json
from pathlib import Path

from probity_control_arena_reader import PROFILE, Policy


def main() -> None:
    """Select capture digest, host source, Inspect version and time window.

    Notes
    -----
    Run this in the trusted host capture stage. The exact four identities and
    literal inputs are compiled in this reader profile. No candidate log is
    opened or consulted. Source installation and wheel verification occur in a
    separate bootstrap before execution. The source revision is still a host
    self-report, not independent execution custody.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-sha256", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-abbrev", required=True)
    parser.add_argument("--source-origin", required=True)
    parser.add_argument("--inspect-version", required=True)
    parser.add_argument("--not-before", required=True)
    parser.add_argument("--not-after", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if len(args.source_commit) != 40 or any(
        c not in "0123456789abcdef" for c in args.source_commit
    ):
        parser.error("--source-commit must be an exact lowercase 40-character Git SHA")
    if not (
        7 <= len(args.source_abbrev) <= 40
        and args.source_commit.startswith(args.source_abbrev)
    ):
        parser.error(
            "--source-abbrev must be an outside-selected 7-40 character prefix"
        )
    policy = {
        "profile": PROFILE,
        "logSha256": args.log_sha256,
        "expectedSource": {
            "type": "git",
            "origin": args.source_origin,
            "commit": args.source_abbrev,
            "dirty": False,
        },
        "selectedSourceCommit": args.source_commit,
        "expectedInspect": args.inspect_version,
        "notBefore": args.not_before,
        "notAfter": args.not_after,
        "expectedSamples": [
            {"id": identity, "epoch": epoch, "input": identity}
            for identity in ("alpha", "beta")
            for epoch in (1, 2)
        ],
    }
    raw = (json.dumps(policy, sort_keys=True, indent=2) + "\n").encode()
    Policy.from_bytes(raw)
    with args.output.open("xb") as stream:
        stream.write(raw)


if __name__ == "__main__":
    main()
