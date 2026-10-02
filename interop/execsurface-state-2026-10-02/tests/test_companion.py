import copy
import os
from pathlib import Path
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import companion as c


@pytest.fixture(scope="module")
def native(tmp_path_factory):
    binary = os.environ.get("EXECSURFACE_BINARY")
    assert binary, "select the hash-verified published native binary explicitly"
    packet = tmp_path_factory.mktemp("native") / "packet"
    pins = c.execute(packet, Path(binary), "test-exploratory")
    return packet, pins


def rewrite(packet, pins, name, value):
    c.write_json(packet / name, value)
    manifest = c.strict_json((packet / "manifest.json").read_bytes())
    manifest[name] = c.sha((packet / name).read_bytes())
    c.write_json(packet / "manifest.json", manifest)
    pins["manifestSha256"] = c.sha((packet / "manifest.json").read_bytes())


@pytest.fixture
def selected(native, tmp_path):
    import shutil
    original, pins = native
    packet = tmp_path / "selected"
    shutil.copytree(original, packet)
    return packet, copy.deepcopy(pins)


def test_actual_native_packet(native):
    packet, pins = native
    report = c.read_packet(packet, pins)
    assert report["evidenceValid"] and report["predicateVerdict"] == "valid"
    assert report["nativeOutcome"]["exit_code"] == 0 and report["carriedWrites"] == 1
    assert report["collectionHealth"] == "unknown-no-typed-envelope"
    assert not report["scopeComplete"] and report["tier"] == "voluntary"
    assert report["producerDriftVerdict"] == "pass"
    assert report["producerComparisonOutsideInterval"]


@pytest.mark.parametrize("member", ["manifestSha256", "planSha256", "sourcePinsSha256", "observerPublicKey"])
def test_host_selected_inputs_are_load_bearing(selected, member):
    packet, pins = selected
    pins[member] = "0" * len(pins[member])
    with pytest.raises(ValueError):
        c.read_packet(packet, pins)


@pytest.mark.parametrize("name", ["before.bin", "after.bin", "authority.json", "plan.json",
                                  "commitment.json", "observation.json", "observation.stderr",
                                  "invocation.json", "statement.json", "envelope.json"])
def test_original_bytes_are_required(selected, name):
    packet, pins = selected
    (packet / name).write_bytes(b"changed")
    with pytest.raises(ValueError, match="packet-bytes-mismatch"):
        c.read_packet(packet, pins)


def mutate_write_trace(packet, observation, fault):
    path = c.strict_json((packet / "plan.json").read_bytes())["path"]
    row = next(e for e in observation["events"] if e.get("operation") == "write" and e.get("path") == path)
    if fault == "drop-write":
        observation["events"].remove(row)
    elif fault == "repeat-write":
        repeat = copy.deepcopy(row)
        repeat["sequence"] = max(e["sequence"] for e in observation["events"]) + 1
        observation["events"].append(repeat)
    else:
        row["path"] = "/different-path"


@pytest.mark.parametrize("fault,code", [
    ("incomplete", "native-capture-incomplete"), ("warning", "native-capture-incomplete"),
    ("failed-command", "native-workload-failed"), ("drop-write", "declared-write-not-single"),
    ("repeat-write", "declared-write-not-single"), ("other-path", "declared-write-not-single"),
])
def test_reselected_native_semantic_faults(selected, fault, code):
    packet, pins = selected
    observation = c.strict_json((packet / "observation.json").read_bytes())
    if fault == "incomplete":
        observation["complete"] = False
    elif fault == "warning":
        observation["warnings"] = [{"code": "event_limit", "tid": 1, "message": "fixture"}]
    elif fault == "failed-command":
        observation["outcome"]["exit_code"] = 127
    else:
        mutate_write_trace(packet, observation, fault)
    rewrite(packet, pins, "observation.json", observation)
    with pytest.raises(ValueError, match=code):
        c.read_packet(packet, pins)


@pytest.mark.parametrize("fault,code", [("after-root", "snapshot-root-join"),
    ("complete", "health-mapping-gap"), ("missing-gap", "health-mapping-gap"),
    ("import-below", "import-authority-promotion"), ("missing-commitment", "priorCommitment")])
def test_reselected_mapping_refusals(selected, fault, code):
    packet, pins = selected
    statement = c.strict_json((packet / "statement.json").read_bytes())
    pred = statement["predicate"]
    if fault == "after-root":
        pred["interval"]["afterRoot"] = "0" * 64
    elif fault == "complete":
        pred["observation"]["coverage"]["scopeComplete"] = True
    elif fault == "missing-gap":
        pred["observation"]["coverage"]["gaps"] = []
    elif fault == "import-below":
        pred["observation"]["vantage"] = "below-observed"
    else:
        del pred["observation"]["priorCommitment"]
    rewrite(packet, pins, "statement.json", statement)
    with pytest.raises((ValueError, KeyError), match=code):
        c.read_packet(packet, pins)


@pytest.mark.parametrize("fault,code", [("subject", "subject-not-the-after-root"),
    ("drop-write", "mutation-observed-without-writes"), ("gap", "coverage-incomplete-without-gaps"),
    ("import-below", "origin-cannot-carry-below-observed-vantage"),
    ("commitment-signature", "commitment-signature-invalid"), ("hardware", "import-origin-requires-software-only-platform")])
def test_real_predicate_reader_rejects_resigned_faults(native, fault, code):
    packet, pins = native
    reader, _ = c.selected_reader(pins)
    key = Ed25519PrivateKey.generate()
    statement = c.strict_json((packet / "statement.json").read_bytes())
    pred = statement["predicate"]
    commitment = pred["observation"]["priorCommitment"]
    body = {"authorityDigest": pred["authorityDigest"], "beforeRoot": pred["interval"]["beforeRoot"],
            "intervalId": pred["intervalId"], "witnessNonce": commitment["witnessNonce"]}
    commitment["sig"] = key.sign(c.encode(body)).hex()
    commitment["keyid"] = key.public_key().public_bytes_raw().hex()
    positive = c.signed_statement(statement, key, reader)
    assert reader.verify(c.encode(positive), key.public_key().public_bytes_raw().hex()) == ("valid", [])
    mutations = {
        "subject": lambda: statement["subject"][0]["digest"].update(sha256="0" * 64),
        "drop-write": lambda: pred.update(writes=[]),
        "gap": lambda: pred["observation"]["coverage"].update(gaps=[]),
        "import-below": lambda: pred["observation"].update(vantage="below-observed"),
        "commitment-signature": lambda: commitment.update(sig="0" * 128),
        "hardware": lambda: pred["observation"]["runtime"].update(platform="tee"),
    }
    mutations[fault]()
    raw = c.encode(c.signed_statement(statement, key, reader))
    verdict, codes = reader.verify(raw, key.public_key().public_bytes_raw().hex())
    assert verdict != "valid" and codes == [code]


def test_symlink_refused_even_matching_bytes(selected, tmp_path):
    packet, pins = selected
    data = (packet / "before.bin").read_bytes()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(data)
    (packet / "before.bin").unlink()
    (packet / "before.bin").symlink_to(outside)
    with pytest.raises(ValueError, match="packet-file-boundary"):
        c.read_packet(packet, pins)


@pytest.mark.parametrize("data", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'])
def test_strict_json(data):
    with pytest.raises(ValueError):
        c.strict_json(data)


def test_state_root_is_path_and_bytes_not_event_digest():
    assert c.state_root("/a", b"one") != c.state_root("/b", b"one")
    assert c.state_root("/a", b"one") != c.state_root("/a", b"two")
    assert c.state_root("/a", b"one") != c.sha(b"one")


@pytest.mark.parametrize("required,reason", [("voluntary", "selected-limited-evidence-established"),
                                           ("authoritative", "selected-tier-not-established")])
def test_external_tier_gate(native, required, reason):
    packet, pins = native
    report = c.read_packet(packet, pins)
    decision = c.publication_gate(report, {"profile": report["profile"], "requiredTier": required,
                                          "requiredTypedHealth": False})
    assert decision["reason"] == reason and decision["publish"] == (required == "voluntary")
    assert decision["evidenceValid"]


def test_typed_health_policy_refuses_valid_evidence(native):
    packet, pins = native
    report = c.read_packet(packet, pins)
    assert c.publication_gate(report, {"profile": report["profile"], "requiredTier": "voluntary",
                                       "requiredTypedHealth": True})["reason"] == "typed-health-not-established"


@pytest.mark.parametrize("mutate", [lambda p: p.update(requiredTier="independent"),
                                    lambda p: p.update(requiredTypedHealth=0),
                                    lambda p: p.update(profile="unknown"),
                                    lambda p: p.update(extra=True)])
def test_invalid_policy_refused(native, mutate):
    packet, pins = native
    report = c.read_packet(packet, pins)
    policy = {"profile": report["profile"], "requiredTier": "voluntary", "requiredTypedHealth": False}
    mutate(policy)
    with pytest.raises(ValueError):
        c.publication_gate(report, policy)


@pytest.mark.parametrize("field", ["schema_version", "complete", "exit_code", "sequence"])
def test_bool_integer_coercion_refused(selected, field):
    packet, pins = selected
    observation = c.strict_json((packet / "observation.json").read_bytes())
    if field == "schema_version":
        observation[field] = True
    elif field == "complete":
        observation[field] = 1
    elif field == "exit_code":
        observation["outcome"][field] = False
    else:
        observation["events"][0][field] = True
    rewrite(packet, pins, "observation.json", observation)
    with pytest.raises(ValueError):
        c.read_packet(packet, pins)


@pytest.mark.parametrize("fault,code", [("other-interpreter", "root-executable-join"),
                                      ("other-tid", "write-process-join"),
                                      ("drop-workload-read", "workload-read-join")])
def test_process_and_workload_binding(selected, fault, code):
    packet, pins = selected
    observation = c.strict_json((packet / "observation.json").read_bytes())
    plan = c.strict_json((packet / "plan.json").read_bytes())
    if fault == "other-interpreter":
        next(e for e in observation["events"] if e["event_type"] == "process_exec")["path"] = "/other-python"
    elif fault == "other-tid":
        next(e for e in observation["events"] if e.get("operation") == "write" and
             e.get("path") == plan["path"])["tid"] += 1
    else:
        observation["events"] = [e for e in observation["events"] if not
            (e.get("operation") == "read" and e.get("path") == plan["command"][4])]
    rewrite(packet, pins, "observation.json", observation)
    with pytest.raises(ValueError, match=code):
        c.read_packet(packet, pins)


@pytest.mark.parametrize("tier,health,code", [("voluntary", False, 0), ("authoritative", False, 1),
                                           ("voluntary", True, 1)])
def test_cli_policy_exit_and_retained_evidence(selected, tmp_path, tier, health, code):
    import subprocess
    packet, pins = selected
    pin_path = tmp_path / "selected-pins.json"
    policy_path = tmp_path / "selected-policy.json"
    c.write_json(pin_path, pins)
    c.write_json(policy_path, {"profile": "probity-execsurface-state-v0", "requiredTier": tier,
                               "requiredTypedHealth": health})
    result = subprocess.run([sys.executable, str(c.HERE / "companion.py"), "read", str(packet),
        "--pins-file", str(pin_path), "--policy-file", str(policy_path), "--policy-sha256",
        c.sha(policy_path.read_bytes())], capture_output=True, timeout=10)
    assert result.returncode == code
    report = c.strict_json(result.stdout)
    assert report["evidenceValid"] and report["publication"]["publish"] == (code == 0)


@pytest.mark.parametrize("name", ["producer-baseline.json", "producer-policy.json", "producer-comparison.json",
                                  "calibration.json", "learn.stdout", "learn.stderr", "check.stdout", "check.stderr"])
def test_producer_comparison_original_bytes_required(selected, name):
    packet, pins = selected
    (packet / name).write_bytes(b"changed")
    with pytest.raises(ValueError, match="packet-bytes-mismatch"):
        c.read_packet(packet, pins)


def test_calibration_cannot_be_promoted_into_claimed_interval(selected):
    packet, pins = selected
    calibration = c.strict_json((packet / "calibration.json").read_bytes())
    calibration["outsideClaimedInterval"] = False
    rewrite(packet, pins, "calibration.json", calibration)
    with pytest.raises(ValueError, match="calibration-interval-join"):
        c.read_packet(packet, pins)


@pytest.mark.parametrize("field", ["name", "platform", "architecture", "capabilities", "limitations"])
def test_backend_semantics_cannot_be_relabelled(selected, field):
    packet, pins = selected
    observation = c.strict_json((packet / "observation.json").read_bytes())
    observation["backend"][field] = [] if field in {"capabilities", "limitations"} else "unsupported"
    rewrite(packet, pins, "observation.json", observation)
    with pytest.raises(ValueError, match="selected-backend-mismatch"):
        c.read_packet(packet, pins)
