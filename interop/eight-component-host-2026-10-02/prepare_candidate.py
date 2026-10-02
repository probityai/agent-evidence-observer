"""Copy one existing signed Vectors fixture and selected literal coverage record.

The candidate contains evidence bytes only. It has no installation manifest,
private key, source selection, authority selection or OPA/Verify policy. This
published deterministic fixture is not a blind population or production issuer.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from trust import sha256, write_json

PROFILE = Path(__file__).resolve().parent


def prepare_candidate(sources: Path, output: Path) -> None:
    """Preserve the frozen original AEE bytes and bind a separate text record.

    Parameters
    ----------
    sources : Path
        Host materialized original component checkouts. Runtime trust selection
        remains with :mod:`prepare_host` and :func:`trust.validate_host`.
    output : Path
        New candidate directory with raw AEE, native Verify case and record.
    """
    output.mkdir()
    statement = sources / "agent-evidence-vectors/vectors/statements/vcc938c6038536dcb.json"
    source = sources / "agent-evidence-atlas/experiments/authority-recovery-2026-10-02/provenance.json"
    record = PROFILE / "fixtures/coverage-record.txt"
    (output / "raw-aee.json").write_bytes(statement.read_bytes())
    (output / "record.txt").write_bytes(record.read_bytes())
    write_json(output / "coverage-case.json", {
        "schema_version": "probity-case/v1", "case_id": "atlas-provenance-nonclaims",
        "artifacts": {
            "source": {"path": "source.txt", "sha256": sha256(source.read_bytes()), "length": source.stat().st_size},
            "record": {"path": "record.txt", "sha256": sha256(record.read_bytes()), "length": record.stat().st_size},
        },
    })


def main() -> None:
    """Prepare the exact deterministic candidate without selecting host trust."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prepare_candidate(args.sources, args.output)


if __name__ == "__main__":
    main()
