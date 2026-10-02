"""Semantically reselected corruptions must refuse even with refreshed byte pins."""

import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from boundary_common import PROFILE, decode, sha
from boundary_reader import read
from host_gate import admit, gate

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def packet(tmp_path):
    target = tmp_path / "packet"
    target.mkdir()
    with zipfile.ZipFile(ROOT / "results/native-fixture.zip") as archive:
        archive.extractall(target)
    return target


def select(packet):
    """Reselect mutated producer bytes to test semantics beyond hash mismatch."""
    pins = packet.parent / "pins.json"
    pins.write_text(
        json.dumps(
            {
                "profile": PROFILE,
                "files": {
                    str(path.relative_to(packet)): sha(path.read_bytes())
                    for path in sorted(packet.rglob("*"))
                    if path.is_file()
                },
            }
        )
    )
    return pins


def modify(packet, path, mutate):
    """Rewrite one complete JSON receipt and reselect it."""
    target = packet / path
    value = decode(target.read_bytes())
    mutate(value)
    target.write_text(json.dumps(value))
    return select(packet)


def test_complete_native_packet(packet):
    assert read(packet, select(packet)) == decode(
        (ROOT / "results/recorded-report.json").read_bytes()
    )


MUTANTS = [
    ("cases/accepted-retry-00.json", lambda c: c["final"]["task"]["history"].pop()),
    (
        "cases/rejected-absent-00.json",
        lambda c: c["followupNativeCaller"][0].update({"class": "ValueError"}),
    ),
    (
        "cases/rejected-absent-00.json",
        lambda c: c["followupNativeCaller"][0].update({"module": "fixture.fake"}),
    ),
    (
        "cases/rejected-absent-00.json",
        lambda c: c["followup"]["parsed"]["error"].update({"code": -32000}),
    ),
    (
        "cases/rejected-absent-00.json",
        lambda c: c["nativeStoreTrace"][0].update({"nativeError": None}),
    ),
    (
        "cases/accepted-retry-00.json",
        lambda c: c["nativeStoreTrace"][0].update({"competingCommit": None}),
    ),
    (
        "cases/accepted-retry-00.json",
        lambda c: c["nativeStoreTrace"][1].update({"resultVersion": "TaskVersion(3)"}),
    ),
    (
        "cases/rejected-absent-00.json",
        lambda c: c["nativeStoreTrace"][2].update({"nativeError": None}),
    ),
    (
        "cases/rejected-absent-00.json",
        lambda c: c["sqlRow"]["history"].append(
            {"messageId": "followup-rejected-absent-00", "role": "ROLE_USER"}
        ),
    ),
    (
        "cases/accepted-retry-00.json",
        lambda c: c["sqlVersionRow"].update({"version": 4}),
    ),
    (
        "cases/accepted-retry-00.json",
        lambda c: c["sqlRow"].update({"owner": "different-owner"}),
    ),
    (
        "cases/accepted-retry-00.json",
        lambda c: c["before"].update({"version": "TaskVersion(3)"}),
    ),
    ("cases/rejected-absent-00.json", lambda c: c.update({"conflictBudget": True})),
    ("cases/accepted-retry-00.json", lambda c: c["initialNativeCaller"].clear()),
    (
        "cases/accepted-retry-00.json",
        lambda c: c["followupNativeCaller"].append(c["followupNativeCaller"][0]),
    ),
    ("manifest.json", lambda m: m["records"].pop()),
    ("manifest.json", lambda m: m["records"].__setitem__(1, m["records"][0])),
    ("manifest.json", lambda m: m.update({"plannedAttempts": True})),
    ("manifest.json", lambda m: m.update({"sourceHead": "0" * 40})),
    ("manifest.json", lambda m: m.update({"mysqlVersion": "sqlite-substitute"})),
    ("manifest.json", lambda m: m.update({"witnessScope": "INDEPENDENT"})),
    ("manifest.json", lambda m: m["doesNotAssert"].remove("normative-tck-adoption")),
    ("manifest.json", lambda m: m.update({"elapsedSeconds": 121})),
    ("manifest.json", lambda m: m["container"].update({"memoryBytes": 0})),
    ("manifest.json", lambda m: m["dependencies"].update({"PyMySQL": "1.2.3"})),
]


@pytest.mark.parametrize("path,mutation", MUTANTS)
def test_reselected_semantic_mutants(packet, path, mutation):
    pins = modify(packet, path, mutation)
    with pytest.raises((ValueError, KeyError)):
        read(packet, pins)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'])
def test_strict_json(raw):
    with pytest.raises(ValueError):
        decode(raw)


def test_unselected_byte_change(packet):
    pins = select(packet)
    (packet / "manifest.json").write_bytes(b"{}")
    with pytest.raises(ValueError):
        read(packet, pins)


def test_publication_population_and_scope(packet):
    value = read(packet, select(packet))
    report = {}
    admit(json.dumps(value).encode(), report)
    assert report["decision"] == "publish"
    value["records"].pop()
    with pytest.raises(ValueError):
        admit(json.dumps(value).encode(), {})


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r.update({"witnessScope": "INDEPENDENT"}),
        lambda r: r.update({"plannedAttempts": True}),
        lambda r: r["records"][0].update({"decision": "adopted"}),
        lambda r: r["records"][1].update({"taskId": r["records"][0]["taskId"]}),
    ],
)
def test_fake_success_child_refused(packet, change):
    value = read(packet, select(packet))
    change(value)
    with pytest.raises(ValueError):
        admit(json.dumps(value).encode(), {})


def test_host_policy_inside_packet_refused(packet):
    pins = select(packet)
    policy = packet / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "profile": PROFILE,
                "pinsSha256": sha(pins.read_bytes()),
                "plannedAttempts": 20,
            }
        )
    )
    report = gate(
        packet,
        pins,
        policy,
        sha(policy.read_bytes()),
        Path("/nonexistent"),
        packet.parent / "out",
    )
    assert report["decision"] == "refuse"
    assert report["reason"] == "selection-must-be-outside-packet"


def test_host_policy_reviewed_digest_refused(packet):
    pins = select(packet)
    policy = packet.parent / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "profile": PROFILE,
                "pinsSha256": sha(pins.read_bytes()),
                "plannedAttempts": 20,
            }
        )
    )
    report = gate(
        packet, pins, policy, "0" * 64, Path("/nonexistent"), packet.parent / "out"
    )
    assert report["decision"] == "refuse"
    assert report["reason"] == "host-policy-digest-differs"


def task_bytes(task):
    """Reserialize coherent mutants so protobuf/JSON consistency alone cannot catch them."""
    from google.protobuf.json_format import ParseDict
    from a2a_history_pb2 import Task

    return ParseDict(task, Task()).SerializeToString().hex()


def test_coherent_success_without_persisted_followup_refused(packet):
    def mutate(case):
        import copy

        before = copy.deepcopy(case["before"]["task"])
        case["final"]["task"] = before
        case["final"]["taskProtoHex"] = task_bytes(before)
        case["sqlRow"]["history"] = before["history"]
        case["sqlRow"]["status"] = before["status"]
        case["followupNativeCaller"][0]["task"] = before
        case["followupNativeCaller"][0]["taskProtoHex"] = task_bytes(before)
        case["followup"]["parsed"]["result"]["task"] = before
        case["followup"]["responseHex"] = (
            json.dumps(case["followup"]["parsed"]).encode().hex()
        )

    pins = modify(packet, "cases/accepted-retry-00.json", mutate)
    with pytest.raises(ValueError, match="accepted-history"):
        read(packet, pins)


def test_coherent_refusal_with_present_followup_refused(packet):
    def mutate(case):
        task = case["final"]["task"]
        task["history"].append(
            {
                "messageId": "followup-" + case["id"],
                "taskId": task["id"],
                "contextId": task["contextId"],
                "role": "ROLE_USER",
                "parts": [{"text": "public fixture turn"}],
            }
        )
        case["final"]["taskProtoHex"] = task_bytes(task)
        case["sqlRow"]["history"] = task["history"]

    pins = modify(packet, "cases/rejected-absent-00.json", mutate)
    with pytest.raises(ValueError, match="rejected-task-preserves-initial"):
        read(packet, pins)


def test_reselected_source_contract_refused(packet):
    name = "src/a2a/server/agent_execution/active_task.py"
    source = packet / "sources/sdk" / name
    source.write_bytes(source.read_bytes() + b"\n# changed source\n")
    pins = modify(
        packet,
        "manifest.json",
        lambda value: value["sdkSources"].update({name: sha(source.read_bytes())}),
    )
    with pytest.raises(ValueError, match="reviewed-native-source-selection"):
        read(packet, pins)


class ClosingHandler:
    def __init__(self, number, calls):
        self.number, self.calls = number, calls

    async def aclose(self):
        self.calls.append("handler-" + str(self.number))
        if self.number == 0:
            raise RuntimeError("forced-native-cleanup-failure")


class ClosingEngine:
    def __init__(self, number, calls):
        self.number, self.calls = number, calls

    async def dispose(self):
        self.calls.append("engine-" + str(self.number))


@pytest.mark.asyncio
async def test_failed_handler_close_still_disposes_all_connections():
    from boundary_native import cleanup

    calls = []

    with pytest.raises(RuntimeError, match="forced-native-cleanup-failure"):
        await cleanup(
            [ClosingHandler(i, calls) for i in range(2)],
            [ClosingEngine(i, calls) for i in range(4)],
        )
    assert sorted(calls) == [
        "engine-0",
        "engine-1",
        "engine-2",
        "engine-3",
        "handler-0",
        "handler-1",
    ]
