"""Actual installed SDK, SQLite and process controls for the local consumer profile."""
from __future__ import annotations

import copy
import json
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from probity_observer.authorization import ActionRequest, GrantPolicy
from probity_observer.crypto import VerificationError, canonical
from probity_observer.ticket_service import http_json, running_server
from probity_aps_refund.fixture import NOW, provision, select_action
from probity_aps_refund.service import parse_native_clock, verify_aps, verify_refund_result
from probity_aps_refund.worker import load_store

PROFILE = Path(__file__).resolve().parent


@pytest.fixture
def case(tmp_path: Path) -> dict[str, Any]:
    """Select host policy separately from every candidate transport attempt."""
    runtime = provision(tmp_path / "host", PROFILE)
    load_store(runtime).initialize()
    return runtime


def counts(runtime: dict[str, Any]) -> tuple[int, int]:
    """Measure actual native rows and durable intents rather than success booleans."""
    with closing(sqlite3.connect(runtime["storePath"])) as db:
        effects = db.execute("SELECT count(*) FROM tickets").fetchone()[0]
        events = [json.loads(row[0]) for row in db.execute("SELECT record FROM events")]
    return sum(event["payload"]["event"]["kind"] == "intent" for event in events), effects


def worker(runtime: dict[str, Any], fault: str | None = None) -> subprocess.CompletedProcess[bytes]:
    """Run a fresh installed process, preserving the real termination status."""
    argv = [sys.executable, "-I", "-B", "-m", "probity_aps_refund.worker", str(Path(runtime["storePath"]).parent / "runtime.json")]
    if fault:
        argv.append(fault)
    return subprocess.run(argv, capture_output=True, timeout=20, check=False)


def verify(runtime: dict[str, Any], receipt: dict[str, Any], readback: dict[str, Any]) -> dict[str, Any]:
    """Use retained public host pins and actual native SDK replay at the consumer."""
    return verify_refund_result(runtime["evidence"], receipt, readback, ActionRequest(**runtime["request"]),
        GrantPolicy(**runtime["grantPolicy"]), runtime["servicePublicKey"], runtime["candidate"]["grant"],
        tenant_id=runtime["tenantId"], node=Path(runtime["node"]), verifier=Path(runtime["verifier"]),
        verifier_sha256=runtime["verifierSha256"], sdk_sha256=runtime["sdkSha256"], now=parse_native_clock(runtime["now"]))


def test_exact_http_effect_and_public_readback(case: dict[str, Any]) -> None:
    """Native HTTP routes preserve exact payload and consumer binding."""
    store = load_store(case)
    with running_server(store) as server:
        code, receipt = http_json(server.url + "/dispatch", case["candidate"])
        read_code, readback = http_json(server.url + "/tickets/" + store.request.tenant_id + "/" + store.ticket_id)
    assert code == read_code == 200
    assert verify(case, receipt, readback)["approvalActionBinding"] == "verified"
    assert bytes.fromhex(readback["contentHex"]) == canonical(case["evidence"]["policy"]["expectedPayload"])
    assert counts(case) == (1, 1)


def test_restart_retry_is_same_logical_operation(case: dict[str, Any]) -> None:
    """Two fresh processes return one effect identity and create one durable intent."""
    first, second = worker(case), worker(case)
    assert first.returncode == second.returncode == 0, (first.stderr, second.stderr)
    assert first.stdout == second.stdout
    assert counts(case) == (1, 1)


def test_host_envelope_order_does_not_change_native_commitment(case: dict[str, Any]) -> None:
    """Keep raw native strings exact while ordinary host configuration key order is irrelevant."""
    original = load_store(case)
    changed = copy.deepcopy(case)
    changed["evidence"] = dict(reversed(list(changed["evidence"].items())))
    changed["evidence"]["policy"] = dict(reversed(list(changed["evidence"]["policy"].items())))
    assert load_store(changed).configuration_digest == original.configuration_digest
    original.dispatch(case["candidate"])
    assert load_store(changed).dispatch(case["candidate"]) == original.readback()["receipt"]
    assert counts(case) == (1, 1)


def test_same_action_two_valid_approvals_cannot_create_two_effects(tmp_path: Path) -> None:
    """Reissuance changes authorization evidence, never the signed action's logical identity."""
    first = provision(tmp_path / "host", PROFILE, alternatives=True)
    store = load_store(first)
    store.initialize()
    receipt = store.dispatch(first["candidate"])
    before = Path(first["storePath"]).read_bytes()
    second = select_action(first, first["alternatives"]["reissued"])
    report = verify_aps(second["evidence"], node=Path(second["node"]), verifier=Path(second["verifier"]),
                        verifier_sha256=second["verifierSha256"], sdk_sha256=second["sdkSha256"], now=NOW)
    first_approval = json.loads(first["evidence"]["approvalRaw"])
    assert report["receiptId"] != first_approval["receipt_id"]
    assert report["actionRef"] == first_approval["action_ref"]
    assert second["request"]["request_id"] == first["request"]["request_id"]
    assert second["storePath"] == first["storePath"]
    with pytest.raises(VerificationError, match="configuration differs"):
        load_store(second).dispatch(second["candidate"])
    assert Path(first["storePath"]).read_bytes() == before
    assert counts(first) == (1, 1)
    assert load_store(first).dispatch(first["candidate"]) == receipt


def test_different_signed_action_is_a_distinct_operation(tmp_path: Path) -> None:
    """A genuinely approved different nonce can create its own one local effect."""
    first = provision(tmp_path / "host", PROFILE, alternatives=True)
    original = load_store(first)
    original.initialize()
    original.dispatch(first["candidate"])
    second = select_action(first, first["alternatives"]["differentAction"])
    assert second["request"]["request_id"] != first["request"]["request_id"]
    assert json.loads(second["evidence"]["approvalRaw"])["action_ref"] != json.loads(first["evidence"]["approvalRaw"])["action_ref"]
    assert second["evidence"]["policy"]["publicKey"] == first["evidence"]["policy"]["publicKey"]
    other = load_store(second)
    other.initialize()
    receipt = other.dispatch(second["candidate"])
    verify(second, receipt, other.readback())
    assert counts(first) == counts(second) == (1, 1)


def test_cross_instance_concurrent_attempts_have_one_intent(case: dict[str, Any]) -> None:
    """Separate processes share SQLite state even when their attempts overlap."""
    with ThreadPoolExecutor(max_workers=2) as pool:
        runs = list(pool.map(lambda _: worker(case), range(2)))
    assert any(run.returncode == 0 for run in runs)
    assert counts(case) == (1, 1)
    assert worker(case).returncode == 0


@pytest.mark.parametrize("fault,expected", [("after-intent", (1, 0)), ("inside-effect-transaction", (1, 0)), ("after-effect", (1, 1))])
def test_real_process_crash_and_honest_recovery(case: dict[str, Any], fault: str, expected: tuple[int, int]) -> None:
    """Hard exits never automatically repeat an unknown operation."""
    crashed = worker(case, fault)
    assert crashed.returncode == 23 and not crashed.stdout
    assert counts(case) == expected
    retry = worker(case)
    if fault == "after-effect":
        assert retry.returncode == 0
        recovered = json.loads(retry.stdout)
        verify(case, recovered["receipt"], recovered["readback"])
    else:
        assert retry.returncode != 0 and not retry.stdout
        load_store(case).recover()
        assert worker(case).returncode != 0
    assert counts(case) == expected


@pytest.mark.parametrize("kind", ["payload-duplicate", "payload-escaped-duplicate", "receipt-duplicate", "action-duplicate",
                                  "amount", "currency", "payment", "key", "key-id", "worker", "boundary", "missing"])
def test_hostile_native_join_refuses_before_intent(case: dict[str, Any], kind: str) -> None:
    """Real SDK refusal or raw-schema refusal cannot become a durable admission."""
    changed = copy.deepcopy(case)
    evidence = changed["evidence"]
    if kind.startswith("payload-"):
        key = 'amount_minor' if kind == "payload-duplicate" else r'amount_\u006dinor'
        evidence["payloadRaw"] = '{"' + key + '":3900,' + evidence["payloadRaw"][1:]
    elif kind in {"receipt-duplicate", "action-duplicate"}:
        name, field = ("approvalRaw", "receipt_id") if kind == "receipt-duplicate" else ("actionRaw", "nonce")
        evidence[name] = '{"' + field + '":"wrong",' + evidence[name][1:]
    elif kind in {"amount", "currency", "payment"}:
        payload = json.loads(evidence["payloadRaw"])
        payload[{"amount": "amount_minor", "currency": "currency", "payment": "payment_id"}[kind]] = {"amount": 3900, "currency": "USD", "payment": "pay_B"}[kind]
        evidence["payloadRaw"] = json.dumps(payload)
    elif kind == "missing":
        evidence["approvalRaw"] = '{}'
    else:
        field = {"key": "publicKey", "key-id": "keyId", "worker": "workerIdentity", "boundary": "boundaryIdentity"}[kind]
        evidence["policy"][field] = "00" * 32 if kind == "key" else "did:example:wrong"
    before = Path(case["storePath"]).read_bytes()
    with pytest.raises(VerificationError):
        load_store(changed).dispatch(changed["candidate"])
    assert Path(case["storePath"]).read_bytes() == before
    assert counts(case) == (0, 0)


@pytest.mark.parametrize("spelling", ["4000.0", "4e3"])
def test_valid_numeric_spellings_preserve_exact_effect(case: dict[str, Any], spelling: str) -> None:
    """Equivalent JSON numbers remain valid under the unchanged SDK's JCS."""
    case["evidence"]["payloadRaw"] = case["evidence"]["payloadRaw"].replace('4000', spelling)
    store = load_store(case)
    receipt = store.dispatch(case["candidate"])
    verify(case, receipt, store.readback())
    assert counts(case) == (1, 1)


@pytest.mark.parametrize("kind", ["tenant", "principal", "request", "target", "content", "path"])
def test_local_effect_join_cannot_be_rebound(case: dict[str, Any], kind: str) -> None:
    """Typed host identity and exact effect fields cannot diverge from native approval."""
    changed = copy.deepcopy(case)
    if kind == "path":
        changed["storePath"] = str(Path(case["storePath"]).with_name("wrong.sqlite"))
    else:
        field = {"tenant": "tenant_id", "principal": "principal_id", "request": "request_id", "target": "target_path", "content": "content_sha256"}[kind]
        changed["request"][field] = "0" * 64 if kind == "content" else "wrong"
    with pytest.raises(VerificationError):
        load_store(changed)
    assert counts(case) == (0, 0)


@pytest.mark.parametrize("offset", [-2, 60, 61])
def test_local_dispatch_clock_window(case: dict[str, Any], offset: int) -> None:
    """This local profile requires issuance <= now < expiry, including exact equality refusal."""
    case["now"] = (NOW + timedelta(seconds=offset)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    with pytest.raises(VerificationError):
        load_store(case)
    assert counts(case) == (0, 0)


def test_expiry_between_intent_and_effect_is_rechecked(case: dict[str, Any]) -> None:
    """Fresh native validity applies inside the real two-phase local dispatch."""
    store = load_store(case)
    def advance(point: str) -> None:
        if point == "after-intent":
            store.clock = lambda: NOW + timedelta(seconds=60)
    store.crash_hook = advance
    with pytest.raises(VerificationError):
        store.dispatch(case["candidate"])
    assert counts(case) == (1, 0)


def test_expired_cached_retry_preserves_completed_effect(case: dict[str, Any]) -> None:
    """An old completion is retained when fresh approval validity refuses retry."""
    store = load_store(case)
    store.dispatch(case["candidate"])
    before = Path(case["storePath"]).read_bytes()
    store.clock = lambda: NOW + timedelta(seconds=60)
    with pytest.raises(VerificationError):
        store.dispatch(case["candidate"])
    assert Path(case["storePath"]).read_bytes() == before
    assert counts(case) == (1, 1)


def test_verifier_source_pin_is_not_a_report_boolean(case: dict[str, Any]) -> None:
    """A real source selection mismatch refuses before invoking alternate code."""
    case["verifierSha256"] = "00" * 32
    with pytest.raises(VerificationError):
        load_store(case)
    assert counts(case) == (0, 0)


def test_installed_sdk_bytes_are_checked(case: dict[str, Any]) -> None:
    """An actual installed module change refuses before any effect and is restored afterward."""
    sdk_file = PROFILE / "node_modules/agent-passport-system/dist/src/index.js"
    original = sdk_file.read_bytes()
    try:
        sdk_file.write_bytes(original + b"\n// hostile installed-byte control\n")
        with pytest.raises(VerificationError, match="installed APS SDK differs"):
            load_store(case)
    finally:
        sdk_file.write_bytes(original)
    assert counts(case) == (0, 0)


def test_missing_restart_state_is_not_reinitialized(case: dict[str, Any]) -> None:
    """Lost durable state refuses rather than recreating an unused approval ledger."""
    Path(case["storePath"]).unlink()
    run = worker(case)
    assert run.returncode != 0 and not run.stdout
    assert not Path(case["storePath"]).exists()


def test_private_runtime_file_is_required(case: dict[str, Any]) -> None:
    """An exposed host signing-key configuration cannot be used by the process worker."""
    (Path(case["storePath"]).parent / "runtime.json").chmod(0o644)
    run = worker(case)
    assert run.returncode != 0 and not run.stdout
    assert counts(case) == (0, 0)


@pytest.mark.parametrize("raw", [
    '{"payment_id":"pay_A","amount_minor":true,"currency":"EUR"}',
    '{"payment_id":"pay_A","amount_minor":4000.5,"currency":"EUR"}',
    '{"payment_id":"pay_A","amount_minor":9007199254740992,"currency":"EUR"}',
    '{"payment_id":"pay_A","amount_minor":1e999,"currency":"EUR"}',
    '{"payment_id":"pay_A","amount_minor":NaN,"currency":"EUR"}',
    '{"payment_id":"pay_A","amount_minor":4000,"currency":"EUR","extra":1}',
    '{"payment_id":"../pay_A","amount_minor":4000,"currency":"EUR"}',
    '{}', '{', ' ' * 65537,
])
def test_hostile_payload_never_creates_an_intent(case: dict[str, Any], raw: str) -> None:
    """Ambiguous amounts, changed schemas and unavailable bounded parsing remain refusals."""
    case["evidence"]["payloadRaw"] = raw
    with pytest.raises(VerificationError):
        load_store(case)
    assert counts(case) == (0, 0)


def test_unavailable_native_verifier_refuses(case: dict[str, Any]) -> None:
    """A verifier process launch failure cannot become a successful approval report."""
    case["node"] = str(Path(case["storePath"]).parent / "missing-node")
    with pytest.raises(VerificationError, match="unavailable"):
        load_store(case)
    assert counts(case) == (0, 0)


def test_local_revocation_blocks_otherwise_valid_native_approval(case: dict[str, Any]) -> None:
    """Native signature validity does not override the selected local authority policy."""
    store = load_store(case)
    store.revoke()
    with pytest.raises(VerificationError, match="revoked"):
        store.dispatch(case["candidate"])
    assert counts(case) == (0, 0)


def test_public_consumer_requires_native_host_pins(case: dict[str, Any]) -> None:
    """A valid local service signature cannot conceal a wrong APS issuer key."""
    store = load_store(case)
    receipt = store.dispatch(case["candidate"])
    changed = copy.deepcopy(case)
    changed["evidence"]["policy"]["publicKey"] = "00" * 32
    with pytest.raises(VerificationError):
        verify(changed, receipt, store.readback())


def test_signed_narrow_is_refused(tmp_path: Path) -> None:
    """Unenforced constraints never become an unconstrained permit."""
    runtime = provision(tmp_path / "host", PROFILE, verdict="narrow", constraints=["second-operator-required"])
    with pytest.raises(VerificationError):
        load_store(runtime)
    assert not Path(runtime["storePath"]).exists()


def test_signed_permit_with_unenforced_constraints_is_refused(tmp_path: Path) -> None:
    """A permit label cannot silently discard signed obligations."""
    runtime = provision(tmp_path / "host", PROFILE, constraints=["second-operator-required"])
    with pytest.raises(VerificationError):
        load_store(runtime)
    assert not Path(runtime["storePath"]).exists()


def retain_temporal_control(runtime: dict[str, Any], store: Any, output: Path, record: dict[str, Any], expected_reader_exit: int) -> None:
    """Preserve actual public native state and installed CLI results without fixture keys."""
    import hashlib
    import shutil
    output.mkdir()
    readback = store.readback()
    for filename, item in (("receipt.json", readback["receipt"]), ("readback.json", readback), ("attempts.json", [record])):
        (output / filename).write_bytes(canonical(item))
    shutil.copyfile(runtime["storePath"], output / "service.sqlite")
    public = {key: runtime[key] for key in ("request", "grantPolicy", "tenantId", "evidence", "verifierSha256", "sdkSha256", "now", "timePrecision", "servicePublicKey")}
    admissions, effects = counts(runtime)
    public.update(grant=runtime["candidate"]["grant"], expected={"logicalAdmissions": admissions, "localEffects": effects}, alternateApproval=None)
    public["files"] = {name: hashlib.sha256((output / name).read_bytes()).hexdigest() for name in ("receipt.json", "readback.json", "attempts.json", "service.sqlite")}
    (output / "host-policy.json").write_bytes(canonical(public))
    pin = hashlib.sha256((output / "host-policy.json").read_bytes()).hexdigest()
    before = (output / "service.sqlite").read_bytes()
    result = subprocess.run([sys.executable, "-I", "-B", "-m", "probity_aps_refund.reader", str(output), "--policy-sha256", pin,
        "--node", runtime["node"], "--verifier", runtime["verifier"]], capture_output=True, check=False, timeout=30)
    (output / "consumer-stdout.bin").write_bytes(result.stdout)
    (output / "consumer-stderr.txt").write_bytes(result.stderr)
    (output / "temporal-check.json").write_bytes(canonical({**record, "readerExit": result.returncode,
        "policySha256": pin, "SQLiteSha256": hashlib.sha256(before).hexdigest(), "logicalAdmissions": admissions,
        "localEffects": effects, "witnessScope": "PEER", "independentCustody": False}))
    assert result.returncode == expected_reader_exit, result.stderr
    assert (output / "service.sqlite").read_bytes() == before
    if result.returncode:
        assert not result.stdout
    else:
        assert json.loads(result.stdout)["localEffects"] == effects


@pytest.mark.parametrize("stage,offset,accepted", [("intent", -2, False), ("intent", -1, True), ("intent", 59, True),
    ("intent", 60, False), ("intent", 61, False), ("effect", -2, False), ("effect", -1, True),
    ("effect", 59, True), ("effect", 60, False), ("effect", 61, False)])
def test_exact_transaction_native_clock_boundary(case: dict[str, Any], tmp_path: Path, stage: str, offset: int, accepted: bool) -> None:
    """The same sampled transaction time governs genuine SDK approval and local authority."""
    store = load_store(case)
    observations = [NOW + timedelta(seconds=offset)] * 2 if stage == "intent" else [NOW - timedelta(seconds=1), NOW + timedelta(seconds=offset)]
    reads = []
    def clock():
        value = observations[len(reads)]
        reads.append(value)
        return value
    store.clock = clock
    if accepted:
        receipt = store.dispatch(case["candidate"])
        assert receipt["payload"]["intentTime"] == observations[0].isoformat(timespec="milliseconds").replace("+00:00", "Z")
        assert receipt["payload"]["effectTime"] == observations[1].isoformat(timespec="milliseconds").replace("+00:00", "Z")
        assert counts(case) == (1, 1) and len(reads) == 2
        case["now"] = observations[1].isoformat(timespec="milliseconds").replace("+00:00", "Z")
        refusal = None
    else:
        with pytest.raises(VerificationError, match="native APS approval verification refused") as failed:
            store.dispatch(case["candidate"])
        refusal = str(failed.value)
        assert counts(case) == ((0, 0) if stage == "intent" else (1, 0))
        assert len(reads) == (1 if stage == "intent" else 2)
        if stage == "effect":
            store.recover()
    retain_temporal_control(case, store, tmp_path / (stage + "-" + str(offset)), {"kind": "transaction-" + stage + "-" + str(offset),
        "accepted": accepted, "refusal": refusal, "observations": [value.isoformat() for value in reads]},
        0 if accepted or stage == "effect" else 2)


@pytest.mark.parametrize("offset,accepted", [(119, True), (120, False), (121, False)])
def test_incomplete_capture_requires_current_local_authority(tmp_path: Path, offset: int, accepted: bool) -> None:
    """A longer-lived genuine APS approval does not extend an expired local grant."""
    runtime = provision(tmp_path / "host", PROFILE)
    options = {"issuedAt": (NOW - timedelta(seconds=1)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "validUntil": (NOW + timedelta(seconds=180)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "verdict": "permit", "constraints": [], "alternatives": False,
        "reissuedValidUntil": (NOW + timedelta(seconds=200)).isoformat(timespec="milliseconds").replace("+00:00", "Z")}
    issued = subprocess.run([runtime["node"], str(PROFILE / "fixture.mjs")], input=canonical(options),
        capture_output=True, check=True, timeout=10)
    runtime = select_action(runtime, json.loads(issued.stdout))
    store = load_store(runtime)
    store.initialize()
    def interrupted(point: str) -> None:
        if point == "after-intent":
            raise RuntimeError("controlled incomplete authority capture")
    store.crash_hook = interrupted
    with pytest.raises(RuntimeError, match="controlled incomplete authority capture"):
        store.dispatch(runtime["candidate"])
    store.recover()
    runtime["now"] = (NOW + timedelta(seconds=offset)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    retain_temporal_control(runtime, store, tmp_path / ("current-local-grant-" + str(offset)),
        {"kind": "current-local-grant-" + str(offset), "accepted": accepted,
         "nativeValidUntil": options["validUntil"], "localGrantValidUntil": (NOW + timedelta(seconds=120)).isoformat()},
        0 if accepted else 2)


@pytest.mark.parametrize("kind", ["empty-observations", "changed-frozen-report"])
def test_native_observations_require_actual_sdk_and_frozen_report(case: dict[str, Any], kind: str) -> None:
    """Historical checks cannot silently accept no observations or another SDK decision."""
    from probity_aps_refund.service import verify_aps_observations
    arguments = {"node": Path(case["node"]), "verifier": Path(case["verifier"]),
        "verifier_sha256": case["verifierSha256"], "sdk_sha256": case["sdkSha256"]}
    report = verify_aps(case["evidence"], now=NOW, **arguments)
    observations = () if kind == "empty-observations" else (NOW,)
    if kind == "changed-frozen-report":
        report["receiptId"] = "f" * 64
    with pytest.raises(VerificationError, match="observations are missing|observation differs from frozen decision"):
        verify_aps_observations(case["evidence"], observations, report, **arguments)
    assert counts(case) == (0, 0)


@pytest.mark.parametrize("stage", ["intent", "effect"])
@pytest.mark.parametrize("milliseconds,accepted", [(249, False), (250, True), (749, True), (750, False), (751, False)])
def test_fractional_native_transaction_boundaries(tmp_path: Path, stage: str, milliseconds: int, accepted: bool) -> None:
    """Actual SDK issuance and exclusive expiry use the exact retained .sssZ transaction time."""
    issued_at, expires_at = NOW + timedelta(milliseconds=250), NOW + timedelta(milliseconds=750)
    runtime = provision(tmp_path / "host", PROFILE, now=issued_at, native_issued_at=issued_at, native_valid_until=expires_at)
    store = load_store(runtime)
    store.initialize()
    reference = NOW + timedelta(milliseconds=milliseconds)
    observations = [reference, reference] if stage == "intent" else [issued_at, reference]
    read = iter(observations)
    store.clock = lambda: next(read)
    refusal = None
    if accepted:
        receipt = store.dispatch(runtime["candidate"])
        assert counts(runtime) == (1, 1)
        assert receipt["payload"]["intentTime"] == observations[0].isoformat(timespec="milliseconds").replace("+00:00", "Z")
        assert receipt["payload"]["effectTime"] == observations[1].isoformat(timespec="milliseconds").replace("+00:00", "Z")
        runtime["now"] = observations[1].isoformat(timespec="milliseconds").replace("+00:00", "Z")
    else:
        with pytest.raises(VerificationError, match="native APS approval verification refused") as failed:
            store.dispatch(runtime["candidate"])
        refusal = str(failed.value)
        assert counts(runtime) == ((0, 0) if stage == "intent" else (1, 0))
        if stage == "effect":
            store.recover()
    retain_temporal_control(runtime, store, tmp_path / (stage + "-" + str(milliseconds)),
        {"kind": "fractional-" + stage + "-" + str(milliseconds), "accepted": accepted, "refusal": refusal,
         "nativeIssuedAt": issued_at.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
         "nativeValidUntil": expires_at.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
         "observations": [value.isoformat(timespec="milliseconds").replace("+00:00", "Z") for value in observations]},
        0 if accepted or stage == "effect" else 2)


@pytest.mark.parametrize("stage", ["intent", "effect"])
def test_native_refuses_finer_host_clock_without_rounding(case: dict[str, Any], tmp_path: Path, stage: str) -> None:
    """An injected submillisecond clock cannot silently change native authorization time."""
    store = load_store(case)
    fine = NOW + timedelta(microseconds=500001)
    observations = [fine, fine] if stage == "intent" else [NOW, fine]
    read = iter(observations)
    store.clock = lambda: next(read)
    with pytest.raises(VerificationError, match="UTC millisecond precision"):
        store.dispatch(case["candidate"])
    assert counts(case) == ((0, 0) if stage == "intent" else (1, 0))
    if stage == "effect":
        store.recover()
    retain_temporal_control(case, store, tmp_path / ("fine-" + stage),
        {"kind": "fine-host-" + stage, "accepted": False, "refusal": "UTC millisecond precision",
         "observations": [value.isoformat(timespec="microseconds").replace("+00:00", "Z") for value in observations]},
        2 if stage == "intent" else 0)


def test_declared_fractional_host_observation_is_preserved(case: dict[str, Any], tmp_path: Path) -> None:
    """The original fractional-host refusal becomes a checkable declared millisecond effect."""
    case["now"] = "2026-10-05T20:00:00.500Z"
    store = load_store(case)
    receipt = store.dispatch(case["candidate"])
    assert receipt["payload"]["intentTime"] == receipt["payload"]["effectTime"] == case["now"]
    assert verify(case, receipt, store.readback())["nativeRevision"] == 1
    retain_temporal_control(case, store, tmp_path / "fractional-host",
        {"kind": "fractional-host", "accepted": True, "observations": [case["now"], case["now"]]}, 0)


def test_native_default_clock_samples_declared_millisecond_resolution() -> None:
    """The live native clock selects millisecond resolution without modifying injected times."""
    import time
    from datetime import datetime, timezone
    from probity_aps_refund.service import millisecond_clock
    before = time.time_ns() // 1_000_000
    observation = millisecond_clock()
    after = time.time_ns() // 1_000_000
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    assert before <= (observation - epoch) // timedelta(milliseconds=1) <= after
    assert observation.microsecond % 1000 == 0 and observation.utcoffset() == timedelta(0)


@pytest.mark.parametrize("precision", [None, "seconds", "Milliseconds", True])
def test_native_runtime_precision_requires_explicit_selection(case: dict[str, Any], precision: Any) -> None:
    """The native host selects one contract, without inferring or migrating timestamp forms."""
    case["timePrecision"] = precision
    with pytest.raises(ValueError, match="time precision must be milliseconds"):
        load_store(case)
    assert counts(case) == (0, 0)
