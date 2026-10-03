"""Run two unmodified Alakris source functions on controlled inputs.

The original file must match the publisher's exact SHA-256. No platform import,
database, live provider, deployed comparison or original test suite is run.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

SOURCE_COMMIT = "68054425873b9b373ce07359f8e994b817bee210"
SOURCE_SHA256 = "3a928ff97f2eb13d2138809d1aebbacd645a07210663d74e2d77bae7fa1002df"


def inspect_fingerprint(path: Path) -> dict[str, Any]:
    """Execute the publisher's fingerprint function without full-app dependencies.

    Parameters
    ----------
    path : pathlib.Path
        Captured ``publication_jobs.py`` from the published review package.
        A mismatched source is refused before its AST is compiled.

    Returns
    -------
    dict[str, Any]
        Source identity and observed digest relations for controlled title,
        body, media-reference, packaging and destination changes. Equality for
        unchanged media references cannot bind media bytes that are absent from
        this function's arguments. The record is source-function execution,
        not an end-to-end exploit or a production result.

    Raises
    ------
    ValueError
        If bytes or expected function definitions do not match the source pin.
    """
    source = path.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        logging.getLogger(__name__).warning("Alakris source differs from pinned SHA-256")
        raise ValueError("Alakris source differs from pinned SHA-256")
    tree = ast.parse(source)
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in {"_dict", "compute_fingerprint"}]
    if len(nodes) != 2:
        raise ValueError("Alakris fingerprint functions are missing")
    namespace: dict[str, Any] = {"hashlib": hashlib, "json": json,
                               "__builtins__": {"isinstance": isinstance, "str": str, "dict": dict}}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    fingerprint = namespace["compute_fingerprint"]
    item = {"title": "reviewed", "detail": {"body": "approved body"}, "media_id": "asset-1"}
    target = {"platform": "telegram", "lang": "en", "packaging": {"text": "reviewed packaging"}, "external_account_id": "destination-1"}
    initial = fingerprint(item, target)
    variants = {
        "covered-title": ({**item, "title": "changed"}, target),
        "covered-body-direct-write": ({**item, "detail": {"body": "changed"}}, target),
        "changed-media-reference": ({**item, "media_id": "asset-2"}, target),
        "same-reference-new-media-bytes": (item, target),
        "changed-platform-packaging": (item, {**target, "packaging": {"text": "changed"}}),
        "changed-external-destination": (item, {**target, "external_account_id": "destination-2"}),
    }
    rows = [{"caseId": name, "fingerprintChanged": fingerprint(candidate, addressing) != initial}
            for name, (candidate, addressing) in variants.items()]
    return {"evidenceClass": "source-function-execution-with-controlled-inputs",
            "sourceCommit": SOURCE_COMMIT, "sourceSha256": SOURCE_SHA256,
            "originalTestsRerun": False, "deployedSystemRerun": False, "results": rows}


def main() -> None:
    """Write the source-function discriminator record selected by the caller."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(inspect_fingerprint(args.source), indent=2) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
