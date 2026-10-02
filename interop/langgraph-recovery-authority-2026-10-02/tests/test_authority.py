"""Fresh native cases and semantic refusals after artifact reselection."""
import copy
import shutil
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from authority_common import CASES, decode, encode, sha
from authority_reader import verify_saved
from authority_run import run
from authority_worker import gate
from lg_common import PacketError


@pytest.fixture(scope="module")
def packet(tmp_path_factory):
    root = tmp_path_factory.mktemp("authority") / "run"
    report = run(root, "pytest-exact-source")
    return root, decode((root / "consumer-pins.json").read_bytes()), report


@pytest.fixture
def copied(packet, tmp_path):
    root = tmp_path / "run"
    shutil.copytree(packet[0], root)
    return root, copy.deepcopy(packet[1])


def reselect(root, pins, name, mutate):
    path = root / "attempts" / (name + ".json")
    item = decode(path.read_bytes())
    mutate(item)
    path.write_bytes(encode(item))
    path = root / "artifact-manifest.json"
    manifest = decode(path.read_bytes())
    manifest[name + ".json"] = sha((root / "attempts" / (name + ".json")).read_bytes())
    path.write_bytes(encode(manifest))
    pins["artifactManifestSha256"] = sha(path.read_bytes())


MUTATIONS = [
    ("valid-before", lambda v: v["firstProcess"].update(exitCode=False), "first-hard-exit"),
    ("valid-before", lambda v: v["secondProcess"].update(exitCode=True), "second-worker-exit"),
    ("valid-before", lambda v: v["second"].update(pid=v["first"]["pid"]), "distinct-processes"),
    ("valid-before", lambda v: v["firstProcess"].update(elapsedNs=True), "resource-elapsed"),
    ("valid-before", lambda v: v["firstProcess"].update(elapsedNs=30000000001), "resource-elapsed"),
    ("valid-before", lambda v: v["firstProcess"].update(stderrHex="00"), "worker-unexpected-output"),
    ("valid-before", lambda v: v["first"]["authority"].update(priorClock=100), "first-authority"),
    ("revoked-before", lambda v: v["second"]["authority"]["current"].update(revoked=False), "recovery-authority"),
    ("expired-before", lambda v: v["second"]["authority"]["current"].update(clock=199), "recovery-authority"),
    ("rollback-after", lambda v: v["second"]["authority"].update(priorClock=0), "recovery-authority"),
    ("valid-before", lambda v: v["second"]["authority"]["current"].update(actionSha256="0" * 64), "recovery-authority"),
    ("revoked-after", lambda v: v["second"].update(status="completed"), "recovery-disposition"),
    ("revoked-after", lambda v: v["second"].update(result={}), "refused-no-result"),
    ("revoked-after", lambda v: v["second"]["http"].append(v["first"]["http"][0]), "dispatch-population"),
    ("valid-before", lambda v: v["second"]["http"].clear(), "dispatch-population"),
    ("valid-before", lambda v: v["second"]["loaded"]["config"]["configurable"].update(checkpoint_id="other"), "reopened-checkpoint"),
    ("valid-before", lambda v: v["first"]["history"].pop(), "native-history-population"),
    ("valid-after", lambda v: v["first"]["snapshot"]["interrupts"][0]["value"].update(httpSha256="0" * 64), "reopened-checkpoint"),
    ("valid-before", lambda v: v["second"]["http"][0].update(endpoint="http://outside.example"), "http-loopback"),
    ("valid-before", lambda v: v["second"]["http"][0].update(postResponseHex="7b7d"), "http-literal-bytes"),
    ("expired-after", lambda v: v.update(finalReadbackHex="7b7d"), "readback-literal-bytes"),
    ("valid-before", lambda v: v["second"]["result"]["result"].update(revision=0), "completed-result"),
    ("valid-before", lambda v: v["second"]["history"].pop(), "completed-history-population"),
]


@pytest.mark.parametrize("name", CASES)
def test_real_authority_transition(packet, name):
    root, pins, report = packet
    assert verify_saved(root, pins) == report
    item = next(r for r in report["records"] if r["attemptId"] == name)
    assert item["freshRecoveryDispatches"] == (1 if name.startswith("valid") else 0)
    assert item["retainedNativeRevision"] == (1 if name.endswith("after") or name.startswith("valid") else 0)
    assert report["independentCustody"] == report["exactlyOnce"] == "not-established"


@pytest.mark.parametrize("name,mutate,reason", MUTATIONS)
def test_reselected_semantic_refusal(copied, name, mutate, reason):
    root, pins = copied
    reselect(root, pins, name, mutate)
    with pytest.raises(PacketError, match="^" + reason + "$"):
        verify_saved(root, pins)


@pytest.mark.parametrize("pin", ("planSha256", "artifactManifestSha256", "policySha256"))
def test_host_selection_required(copied, pin):
    root, pins = copied
    pins[pin] = "0" * 64
    with pytest.raises(PacketError, match="^consumer-" + pin + "$"):
        verify_saved(root, pins)


def test_reader_framework_sqlite_network_forbidden(packet, monkeypatch):
    import builtins
    import urllib.request
    original = builtins.__import__
    def guarded(name, *args, **kwargs):
        assert not name.startswith("langgraph")
        return original(name, *args, **kwargs)
    def forbidden(*args, **kwargs):
        raise AssertionError("reader active IO")
    monkeypatch.setattr(builtins, "__import__", guarded)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    assert verify_saved(packet[0], packet[1]) == packet[2]


def selected(packet):
    case = decode((packet[0] / "cases" / "valid-before.json").read_bytes())
    current = decode((packet[0] / "workers" / "valid-before" / "first-authority.json").read_bytes())
    return case, current


def test_deleted_clock_row_refuses_recovery(packet, tmp_path):
    case, current = selected(packet)
    with sqlite3.connect(tmp_path / "anchor.sqlite") as conn:
        assert gate(conn, case, current, "first")["status"] == "authorized"
        conn.execute("DELETE FROM recovery_clock")
        conn.commit()
        assert gate(conn, case, current, "second")["status"] == "refused-missing-clock-anchor"
        assert conn.execute("SELECT COUNT(*) FROM recovery_clock").fetchone()[0] == 0


def test_concurrent_clock_update_serializes(packet, tmp_path):
    case, current = selected(packet)
    path = tmp_path / "concurrent.sqlite"
    with sqlite3.connect(path) as conn:
        gate(conn, case, current, "first")
    def update(clock):
        with sqlite3.connect(path) as conn:
            return gate(conn, case, {**current, "clock": clock}, "second")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(update, [150, 140]))
    assert any(r["status"] == "authorized" for r in results)
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT clock FROM recovery_clock").fetchone()[0] == 150
        assert gate(conn, case, {**current, "clock": 149}, "second")["status"] == "refused-clock-rollback"


@pytest.mark.parametrize("field,value,reason", [("clock", True, "authority-types"), ("expires", False, "authority-types"), ("revoked", 0, "authority-types"), ("actionSha256", "wrong", "authority-action")])
def test_malformed_host_authority_refuses_before_clock_update(packet, tmp_path, field, value, reason):
    case, current = selected(packet)
    current[field] = value
    with sqlite3.connect(tmp_path / "malformed.sqlite") as conn:
        with pytest.raises(PacketError, match="^" + reason + "$"):
            gate(conn, case, current, "first")
        assert conn.execute("SELECT name FROM sqlite_master WHERE name='recovery_clock'").fetchone() is None


def test_retained_original_native_fixture_replays(tmp_path):
    import zipfile
    from pathlib import Path
    profile = Path(__file__).resolve().parents[1]
    provenance = decode((profile / "provenance.json").read_bytes())
    archive = profile / "native-fixture.zip"
    assert sha(archive.read_bytes()) == provenance["archiveSha256"]
    with zipfile.ZipFile(archive) as retained:
        assert len(retained.namelist()) == provenance["memberCount"]
        assert all((tmp_path / name).resolve().is_relative_to(tmp_path.resolve()) for name in retained.namelist())
        retained.extractall(tmp_path)
    report = verify_saved(tmp_path, provenance["consumerPins"])
    assert report == decode((profile / "recorded-report.json").read_bytes())


@pytest.mark.parametrize("denied,status,stale", [({"clock": 150, "revoked": True}, "refused-revoked", 100), ({"clock": 200}, "refused-expired", 199)])
def test_denied_observation_prevents_stale_permit(packet, tmp_path, denied, status, stale):
    case, current = selected(packet)
    with sqlite3.connect(tmp_path / "denied-clock.sqlite") as conn:
        gate(conn, case, current, "first")
        assert gate(conn, case, {**current, **denied}, "second")["status"] == status
        assert gate(conn, case, {**current, "clock": stale}, "second")["status"] == "refused-clock-rollback"
        assert conn.execute("SELECT clock FROM recovery_clock").fetchone()[0] == denied["clock"]


def test_host_explicit_later_permit_after_revocation(packet, tmp_path):
    case, current = selected(packet)
    with sqlite3.connect(tmp_path / "later-permit.sqlite") as conn:
        gate(conn, case, current, "first")
        assert gate(conn, case, {**current, "clock": 150, "revoked": True}, "second")["status"] == "refused-revoked"
        assert gate(conn, case, {**current, "clock": 151}, "second")["status"] == "authorized"
