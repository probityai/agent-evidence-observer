"""Actual process recovery and semantic controls with reselected hashes."""
from __future__ import annotations

import copy
import shutil
from pathlib import Path
from typing import Any, Callable

import pytest

from durable_reader import CASES, REFUSALS, verify_saved
from durable_run import run
from lg_common import PacketError, decode, encode, read, sha


@pytest.fixture(scope="module")
def durable_packet(tmp_path_factory: pytest.TempPathFactory) -> tuple:
    root = tmp_path_factory.mktemp("durable") / "run"
    report = run(root, "pytest-exact-source")
    return root, decode(read(root, "consumer-pins.json")), report


@pytest.fixture
def copied(durable_packet: tuple, tmp_path: Path) -> tuple:
    root = tmp_path / "run"
    shutil.copytree(durable_packet[0], root)
    return root, copy.deepcopy(durable_packet[1])


def reselect(root: Path, pins: dict, name: str, mutate: Callable) -> None:
    path = root / "attempts" / (name + ".json")
    value = decode(path.read_bytes())
    mutate(value)
    path.write_bytes(encode(value))
    path = root / "artifact-manifest.json"
    manifest = decode(path.read_bytes())
    manifest[name + ".json"] = sha((root / "attempts" / (name + ".json")).read_bytes())
    path.write_bytes(encode(manifest))
    pins["artifactManifestSha256"] = sha(path.read_bytes())


MUTATIONS = [
    ("restart-before", lambda a: a["firstProcess"].update(exitCode=0), "first-hard-exit"),
    ("crash-after-effect", lambda a: a["firstProcess"].update(exitCode=73), "first-hard-exit"),
    ("restart-before", lambda a: a["secondProcess"].update(exitCode=73), "second-worker-exit"),
    ("restart-before", lambda a: a["second"].update(pid=a["firstLoaded"]["pid"]), "distinct-processes"),
    ("restart-before", lambda a: a["firstProcess"].update(elapsedNs=True), "resource-elapsed"),
    ("restart-before", lambda a: a["second"]["http"].clear(), "http-population"),
    ("restart-after", lambda a: a["firstHttp"].clear(), "http-population"),
    ("restart-before", lambda a: a["second"]["http"][0]["candidate"].update(contentHex="00"), "http-argument-binding"),
    ("restart-before", lambda a: a["second"]["http"][0].update(postRequestHex="7b7d"), "http-literal-bytes"),
    ("restart-before", lambda a: a["second"]["http"][0].update(endpoint="https://example.org"), "http-loopback"),
    ("restart-before", lambda a: a.update(finalReadbackHex="7b7d"), "http-final-bytes"),
    ("restart-before", lambda a: a["first"]["snapshot"]["interrupts"][0]["value"].update(point="after-effect"), "native-interrupt-http-join"),
    ("restart-before", lambda a: a["first"]["history"].pop(), "native-pre-exit-history"),
    ("restart-before", lambda a: a["second"]["loaded"]["config"]["configurable"].update(thread_id="wrong"), "native-thread"),
    ("restart-before", lambda a: a["second"]["loaded"]["config"]["configurable"].update(checkpoint_id="other"), "durable-restart-snapshot"),
    ("restart-before", lambda a: a["second"]["history"].pop(), "native-history-population"),
    ("restart-before", lambda a: a["second"]["history"][0]["parent_config"]["configurable"].update(checkpoint_id="other"), "native-history-parent"),
    ("restart-before", lambda a: a["second"]["history"][0]["values"]["result"].update(revision=0), "native-http-join"),
    ("restart-before", lambda a: a["second"]["history"][1]["tasks"][0]["result"]["result"].update(postStatus=409), "native-task-result"),
    ("crash-after-effect", lambda a: a.update(first={}), "hard-crash-no-return"),
    ("missing-checkpoint", lambda a: a["second"].update(status="completed"), "recovery-refusal"),
    ("wrong-thread", lambda a: a["second"]["loaded"].update(next=["dispatch"]), "missing-checkpoint-no-task"),
    ("restart-pending", lambda a: a["second"]["http"][0].update(postStatus=200), "pending-response-status"),
]


class TestDurableRestart:
    class TestPassingCases:
        @pytest.mark.parametrize("name", CASES)
        def test_real_distinct_workers(self, durable_packet: tuple, name: str) -> None:
            root, pins, report = durable_packet
            assert verify_saved(root, pins) == report
            record = next(r for r in report["records"] if r["attemptId"] == name)
            assert record["nativeRevision"] == (0 if name in REFUSALS or name == "restart-pending" else 1)
            assert record["workerExitCodes"] == ([74, 0] if name == "crash-after-effect" else [73, 0])
            assert report["exactlyOnce"] == report["independentCustody"] == "not-established"

        def test_framework_network_sqlite_forbidden_to_reader(self, durable_packet: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
            import builtins
            import sqlite3
            import urllib.request
            original = builtins.__import__
            def guarded(name: str, *args: Any, **kwargs: Any) -> Any:
                assert not name.startswith("langgraph")
                return original(name, *args, **kwargs)
            def forbidden(*args: Any, **kwargs: Any) -> None:
                raise AssertionError("offline reader attempted active IO")
            monkeypatch.setattr(builtins, "__import__", guarded)
            monkeypatch.setattr(sqlite3, "connect", forbidden)
            monkeypatch.setattr(urllib.request, "urlopen", forbidden)
            root, pins, report = durable_packet
            assert verify_saved(root, pins) == report

    class TestFailingCases:
        @pytest.mark.parametrize("name,mutate,reason", MUTATIONS)
        def test_reselected_semantic_mutation(self, copied: tuple, name: str, mutate: Callable, reason: str, caplog: pytest.LogCaptureFixture) -> None:
            root, pins = copied
            reselect(root, pins, name, mutate)
            with pytest.raises(PacketError, match="^" + reason + "$"):
                verify_saved(root, pins)
            assert caplog.messages == ["LangGraph packet refused: " + reason]

        @pytest.mark.parametrize("pin,reason", [("planSha256", "consumer-plan-pin"), ("artifactManifestSha256", "consumer-artifact-pin")])
        def test_consumer_pins_required(self, copied: tuple, pin: str, reason: str) -> None:
            root, pins = copied
            pins[pin] = "0" * 64
            with pytest.raises(PacketError, match="^" + reason + "$"):
                verify_saved(root, pins)

        @pytest.mark.parametrize("name", CASES)
        def test_missing_attempt_refuses(self, copied: tuple, name: str) -> None:
            root, pins = copied
            (root / "attempts" / (name + ".json")).unlink()
            with pytest.raises(PacketError, match="^artifact-file-population$"):
                verify_saved(root, pins)
