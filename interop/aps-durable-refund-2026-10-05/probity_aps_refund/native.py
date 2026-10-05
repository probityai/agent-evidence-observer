"""Retain actual local SDK, process, SQLite and public readback controls."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from typing import Any

from probity_observer.crypto import canonical

from .fixture import provision, select_action
from .worker import load_store


def _counts(path: Path) -> dict[str, int]:
    """Retain measured native intent and effect populations, separately."""
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        effects = db.execute("SELECT count(*) FROM tickets").fetchone()[0]
        events = [json.loads(row[0])["payload"]["event"] for row in db.execute("SELECT record FROM events")]
    return {"logicalAdmissions": sum(event["kind"] == "intent" for event in events), "localEffects": effects}


def _attempt(runtime_path: Path, fault: str | None = None) -> dict[str, Any]:
    """Retain real process exit and output bytes, including every failed attempt."""
    argv = [sys.executable, "-I", "-B", "-m", "probity_aps_refund.worker", str(runtime_path)]
    if fault:
        argv.append(fault)
    run = subprocess.run(argv, capture_output=True, timeout=20, check=False)
    return {"fault": fault, "exit": run.returncode, "stdoutHex": run.stdout.hex(), "stderrHex": run.stderr.hex()}


def _save(output: Path, name: str, runtime: dict[str, Any], attempts: list[dict[str, Any]],
          expected_effects: int, *, alternate: dict[str, Any] | None = None) -> dict[str, Any]:
    """Retain public bytes once, with actual intent/effect populations and no signing keys."""
    measured = _counts(Path(runtime["storePath"]))
    if measured != {"logicalAdmissions": 1, "localEffects": expected_effects}:
        raise ValueError("native local effect population differs")
    case_dir = output / name
    case_dir.mkdir(mode=0o700)
    readback = load_store(runtime).readback()
    for filename, record in (("readback.json", readback), ("receipt.json", readback["receipt"]), ("attempts.json", attempts)):
        (case_dir / filename).write_bytes(canonical(record))
    shutil.copyfile(runtime["storePath"], case_dir / "service.sqlite")
    public_policy = {key: runtime[key] for key in ("request", "grantPolicy", "tenantId", "evidence",
                                                  "verifierSha256", "sdkSha256", "now", "timePrecision", "servicePublicKey")}
    public_policy.update(grant=runtime["candidate"]["grant"], expected=measured, alternateApproval=alternate)
    public_policy["files"] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(case_dir.iterdir())}
    (case_dir / "host-policy.json").write_bytes(canonical(public_policy))
    return {"case": name, **measured, "logicalOperationId": runtime["request"]["request_id"],
            "approvalReceiptId": json.loads(runtime["evidence"]["approvalRaw"])["receipt_id"],
            "attemptExits": [attempt["exit"] for attempt in attempts],
            "hostPolicySha256": hashlib.sha256((case_dir / "host-policy.json").read_bytes()).hexdigest()}


def run(output: Path, private_state: Path, profile: Path) -> dict[str, Any]:
    """Publish eight bounded controls; never copy private runtime configurations."""
    output.mkdir(mode=0o700)
    private_state.mkdir(mode=0o700)
    records = []
    for name in ("restart", "cross-instance", "after-intent", "inside-effect-transaction", "lost-ack"):
        runtime = provision(private_state / name, profile)
        store = load_store(runtime)
        store.initialize()
        runtime_path = Path(runtime["storePath"]).parent / "runtime.json"
        if name == "cross-instance":
            with ThreadPoolExecutor(max_workers=2) as pool:
                attempts = list(pool.map(lambda _: _attempt(runtime_path), range(2)))
            attempts.append(_attempt(runtime_path))
        else:
            fault = {"restart": None, "lost-ack": "after-effect"}.get(name, name)
            attempts = [_attempt(runtime_path, fault), _attempt(runtime_path)]
        expected_effects = 0 if name in {"after-intent", "inside-effect-transaction"} else 1
        if not expected_effects:
            store.recover()
            attempts.append(_attempt(runtime_path))
        if expected_effects and attempts[-1]["exit"] != 0:
            raise ValueError("completed native retry failed")
        if not expected_effects and any(attempt["exit"] == 0 for attempt in attempts):
            raise ValueError("interrupted operation was reported as completed")
        records.append(_save(output, name, runtime, attempts, expected_effects))

    original = provision(private_state / "operation-identity", profile, alternatives=True)
    store = load_store(original)
    store.initialize()
    runtime_path = Path(original["storePath"]).parent / "runtime.json"
    first_attempt = _attempt(runtime_path)
    if first_attempt["exit"] != 0:
        raise ValueError("first operation did not complete")
    records.append(_save(output, "different-action-first", original, [first_attempt], 1))
    before = Path(original["storePath"]).read_bytes()
    reissued = select_action(original, original["alternatives"]["reissued"])
    if reissued["storePath"] != original["storePath"]:
        raise ValueError("reissued approval selected a new logical operation")
    runtime_path.write_bytes(canonical(reissued))
    rejected = _attempt(runtime_path)
    if rejected["exit"] != 1 or rejected["stdoutHex"] or b"ticket configuration differs on restart" not in bytes.fromhex(rejected["stderrHex"]):
        raise ValueError("reissued approval did not refuse the changed frozen configuration")
    if Path(original["storePath"]).read_bytes() != before:
        raise ValueError("reissued approval changed retained native state")
    runtime_path.write_bytes(canonical(original))
    retry = _attempt(runtime_path)
    if retry["exit"] != 0 or retry["stdoutHex"] != first_attempt["stdoutHex"]:
        raise ValueError("original completed operation did not retain its retry")
    records.append(_save(output, "approval-reissue", original, [first_attempt, rejected, retry], 1,
                         alternate=reissued["evidence"]))

    different = select_action(original, original["alternatives"]["differentAction"])
    if different["request"]["request_id"] == original["request"]["request_id"]:
        raise ValueError("different signed action lost its logical identity")
    load_store(different).initialize()
    runtime_path.write_bytes(canonical(different))
    different_attempt = _attempt(runtime_path)
    if different_attempt["exit"] != 0:
        raise ValueError("different approved action did not complete")
    records.append(_save(output, "different-action", different, [different_attempt], 1))
    result = {"profile": "probity-aps-refund-record-v0", "records": records,
              "nodeVersion": subprocess.check_output([original["node"], "--version"], text=True).strip(),
              "nativeSdkVersion": "7.2.1", "independentCustody": False, "witnessScope": "PEER",
              "casePopulation": "five separate fault fixtures and three captures from one operation-identity fixture; counts are per capture and must not be pooled",
              "sharedOperationCaptures": ["different-action-first", "approval-reissue"],
              "doesNotAssert": ["merchant legitimacy", "delegation authority", "PIC integration", "refund provider execution",
                                 "outside adoption", "independent operation", "power-loss durability", "distributed failover"]}
    (output / "native-report.json").write_bytes(canonical(result))
    return result


def main() -> int:
    """Run author-controlled local effects with a separate private state directory."""
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--private-state", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    args = parser.parse_args()
    print(canonical(run(args.output, args.private_state, args.profile.resolve())).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
