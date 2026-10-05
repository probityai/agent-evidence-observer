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
from probity_aps_refund.service import verify_aps, verify_refund_result
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
        verifier_sha256=runtime["verifierSha256"], sdk_sha256=runtime["sdkSha256"], now=NOW)


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
    case["now"] = (NOW + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z")
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
