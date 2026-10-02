"""Execute selected installed readers after the external host byte boundary.

Every path comes from the host launcher, which authenticates sources, installed
files, executables, policies and keys before starting this isolated interpreter.
Candidate AEE is read only from Rust's returned verified payload. This script
never infers a signer key, admission threshold, source witness or policy from it.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import logging
import zipfile
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger("probity.eight_component.native")


def read(path: Path) -> Any:
    """Read a host-retained JSON input after launcher selection and byte admission."""
    return json.loads(path.read_bytes())


def digest(raw: bytes) -> str:
    """Commit exact retained bytes without serializing their parsed value."""
    return hashlib.sha256(raw).hexdigest()


def vectors(config: dict[str, Any]) -> dict[str, Any]:
    """Run the real installed Vectors verifier with separately selected keys.

    Parameters
    ----------
    config : dict[str, Any]
        Host-authenticated payload path, policy, and original component roots.

    Returns
    -------
    dict[str, Any]
        Separate validity, recomputed result, with-key and no-key tiers. A
        structurally valid but unattested row refuses the host admission gate.
    """
    from agent_evidence_vectors.run_vectors import ReferenceVerifier

    raw = Path(config["payload"]).read_bytes()
    pubs = [bytes.fromhex(value) for value in config["policy"]["substratePublicKeys"]]
    outcome = ReferenceVerifier(pubs).verify(json.loads(raw), raw)
    tiers = outcome.tiers_with_key
    selected_tier = config["policy"]["requiredVectorTier"]
    tier_ok = bool(tiers) and all(value == selected_tier for value in tiers)
    return {"gate": "vectors", "admitted": outcome.verdict == "valid" and tier_ok,
            "validity": outcome.verdict, "codes": outcome.codes, "result": outcome.result,
            "tiersWithSelectedKeys": tiers, "tiersWithoutKeys": outcome.tiers_without_key,
            "payloadSha256": digest(raw), "cryptoSelection": "externally-pinned-published-test-key"}


def vocabulary(config: dict[str, Any]) -> dict[str, Any]:
    """Apply the actual closed vocabulary to AEE rows and bounded witness scope."""
    import yaml

    root = Path(config["sources"]) / "agent-evidence-vocabulary"
    terms = yaml.safe_load((root / "vocabulary.yaml").read_bytes())
    statement = read(Path(config["payload"]))
    predicate = statement["predicate"]
    dimensions = terms["evidence_dimensions"]
    checks = {
        "basis": all(row["basis"] in dimensions["observation_vantage"]["values"]
                     for row in predicate["attackResults"]),
        "method": all(row["method"] in dimensions["observation_directness"]["values"]
                      for row in predicate["attackResults"]),
        "result": predicate["result"] in terms["outcome_lattice"]["result"]["values"],
        "witnessScope": "PEER" in dimensions["witness_scope"]["values"],
    }
    return {"gate": "vocabulary", "admitted": all(checks.values()), "checks": checks,
            "version": terms["meta"]["version"], "termPromotion": "not-established",
            "referenceConsumption": "closed-term-check", "witnessScope": "PEER"}


def check_zip_members(retained: zipfile.ZipFile, selected: dict[str, Any]) -> None:
    """Require an exact unique original-member closure and every byte binding."""
    names = retained.namelist()
    if len(names) != len(set(names)) or set(names) != set(selected):
        raise ValueError("Atlas original archive member closure differs")
    for name in names:
        member = retained.read(name)
        if digest(member) != selected[name]["sha256"] or len(member) != selected[name]["bytes"]:
            raise ValueError("Atlas original archive member bytes differ")


def check_zip(provenance: dict[str, Any], archive: Path, report: Path) -> int:
    """Authenticate every original member and exact retained report bytes.

    The original 110-member ZIP is consumed in memory without extracting paths
    or executing archived files. Missing, added, duplicate, or changed members
    remain a refusal rather than a partial reference-data success.
    """
    raw = archive.read_bytes()
    if digest(raw) != provenance["originalArtifactSha256"] or len(raw) != provenance["originalArtifactBytes"]:
        raise ValueError("Atlas original archive bytes differ")
    selected = {entry["member"]: entry for entry in provenance["members"]}
    with zipfile.ZipFile(archive) as retained:
        check_zip_members(retained, selected)
        if retained.read(provenance["reportMember"]) != report.read_bytes():
            raise ValueError("Atlas retained report differs from original member")
    return len(selected)


def atlas(config: dict[str, Any]) -> dict[str, Any]:
    """Run the actual pinned Atlas register validator and original ZIP checks.

    This authenticates already retained author-operated measurements. It does
    not turn the kit's reference consumption into package adoption, new Atlas
    acceptance, outside recurring use, or independent effect custody.
    """
    root = Path(config["sources"]) / "agent-evidence-atlas"
    spec = importlib.util.spec_from_file_location("pinned_atlas_checker", root / "tools/check_lab.py")
    if spec is None or spec.loader is None:
        raise ValueError("Atlas selected validator is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    register = read(root / "data/lab-register.json")
    module.validate_register(register, root)
    record = next(item for item in register["records"] if item["id"] == "authority-recovery-2026-10-02")
    folder = root / "experiments/authority-recovery-2026-10-02"
    provenance = read(folder / "provenance.json")
    members = check_zip(provenance, folder / "original-artifact.zip", folder / "report.json")
    return {"gate": "atlas", "admitted": True, "registerRecords": len(register["records"]),
            "selectedRecord": record["id"], "sourceRevision": provenance["sourceCommit"],
            "originalMembers": members, "originalArchiveSha256": provenance["originalArtifactSha256"],
            "reportSha256": provenance["reportSha256"], "roles": provenance["roles"],
            "referenceConsumption": "existing-register-original-provenance-report"}


def verify_coverage(config: dict[str, Any]) -> dict[str, Any]:
    """Call installed Verify with independently pinned witness and record bytes.

    Returns
    -------
    dict[str, Any]
        The complete native ``source_text_coverage/v1`` result. ``supported``
        alone admits. Contradicted, not established, and malformed exceptions
        are retained distinctly by the launcher.
    """
    from probity_verify.core import adjudicate

    root = Path(config["run"])
    decision = adjudicate(read(root / "coverage-case.json"), config["policy"]["verify"], root)
    return {"gate": "verify", "admitted": decision["decision"] == "supported", "decision": decision}


def issue(config: dict[str, Any]) -> dict[str, Any]:
    """Issue a separate native Observer grant only after all gates have passed.

    Candidate evidence signs observations, not the effect grant. The host
    issuer binds the returned verified payload digest to its own exact action
    identity, duration and public key policy.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from probity_observer.authorization import ActionRequest, GrantPolicy, issue_grant
    from probity_observer.crypto import SigningKey

    policy = config["policy"]
    seed = bytes.fromhex(Path(config["seedFiles"]["issuer"]["path"]).read_text().strip())
    key = SigningKey(Ed25519PrivateKey.from_private_bytes(seed))
    request = ActionRequest(**policy["request"], content_sha256=digest(Path(config["payload"]).read_bytes()))
    grant_policy = GrantPolicy(policy["publicKeys"]["issuer"], policy["grantValiditySeconds"])
    now = datetime.fromisoformat(policy["referenceTime"].replace("Z", "+00:00"))
    grant = issue_grant(request, key, issued_at=now,
                        expires_at=now + timedelta(seconds=policy["grantValiditySeconds"]))
    return {"gate": "host-issued-grant", "admitted": True, "request": asdict(request),
            "grantPolicy": asdict(grant_policy), "grant": grant,
            "doesNotAssert": policy["doesNotAssert"], "signerAuthorityEffectRoles": "distinct-host-selected-keys"}


def verify_effect(config: dict[str, Any]) -> dict[str, Any]:
    """Authenticate a retained native receipt against separate HTTP readback."""
    from probity_observer.authorization import ActionRequest, GrantPolicy
    from probity_observer.ticket_service import verify_ticket_result

    selected = read(Path(config["run"]) / "host-grant.json")
    now = datetime.fromisoformat(config["currentTime"].replace("Z", "+00:00"))
    result = verify_ticket_result(config["receipt"], config["readback"],
                                  ActionRequest(**selected["request"]), GrantPolicy(**selected["grantPolicy"]),
                                  config["policy"]["publicKeys"]["service"], selected["grant"], now=now)
    return {"gate": "native-effect-readback", "admitted": True, "result": result,
            "doesNotAssert": config["policy"]["doesNotAssert"]}


OPERATIONS = {"vectors": vectors, "vocabulary": vocabulary, "atlas": atlas,
              "verify": verify_coverage, "issue": issue, "verify-effect": verify_effect}


def main() -> None:
    """Run one explicit native gate, preserving success and malformed refusals."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=OPERATIONS)
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    try:
        result = OPERATIONS[args.operation](read(args.config))
        print(json.dumps(result, sort_keys=True))
        raise SystemExit(0 if result["admitted"] else 2)
    except (ValueError, KeyError, TypeError, OSError) as error:
        LOGGER.warning("native gate malformed refusal: %s", error)
        outcome = "refused" if args.operation == "verify-effect" else "malformed"
        print(json.dumps({"gate": args.operation, "admitted": False,
                          "outcome": outcome, "reason": str(error)}, sort_keys=True))
        raise SystemExit(3) from error


if __name__ == "__main__":
    main()
