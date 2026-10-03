"""Real finite process population and refusals after full byte reselection."""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
from probity_observer.crypto import VerificationError, canonical

from probity_pydantic_recovery.common import CASES, load, sha
from probity_pydantic_recovery.reader import verify_saved
from recovery_run import run


@pytest.fixture(scope="session")
def native(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Execute all nine native cases once, including actual OS worker death."""
    root = tmp_path_factory.mktemp("native") / "packet"
    run(root, "test-native-source")
    return root


def reselect(root: Path) -> dict:
    """Select altered bytes so controls must reach their semantic relation."""
    manifest = load(root / "artifact-manifest.json")
    for name in manifest:
        manifest[name] = sha((root / name).read_bytes())
    (root / "artifact-manifest.json").write_bytes(canonical(manifest))
    pins = load(root / "consumer-pins.json")
    pins["artifactManifestSha256"] = sha(canonical(manifest))
    return pins


def test_native_population(native: Path) -> None:
    report = verify_saved(native, load(native / "consumer-pins.json"))
    assert report["freshWorkers"] == report["freshTargets"] == 18
    assert report["providerCalls"] == 0
    assert [record["id"] for record in report["records"]] == list(CASES)
    assert [record["releasedResult"] for record in report["records"]] == [True] + [False] * 8
    assert all(record["priorEffect"]["nativeRevision"] == 1 for record in report["records"])
    assert all(record["recoveryPosts"] == 0 for record in report["records"])


@pytest.mark.parametrize("mutation", ["tool-id", "result", "first-arguments", "completion", "current-authority", "signed-readback", "process-id", "exit-code", "released-denial", "child-env", "counter"])
def test_reselected_semantic_refusal(native: Path, tmp_path: Path, mutation: str) -> None:
    root = tmp_path / "packet"
    shutil.copytree(native, root)
    path, field, value = {
        "process-id": ("permit/processes.json", None, None),
        "exit-code": ("permit/processes.json", None, None),
        "child-env": ("permit/processes.json", None, None),
        "current-authority": ("permit/current-host-selection.json", "grant", {}),
        "signed-readback": ("permit/recovery.json", None, None),
        "released-denial": ("revoked/recovery.json", "releasedResult", True),
        "counter": ("permit/final-parent-readback.json", "revision", 2),
        "completion": ("permit/recovery.json", "status", "refused"),
        "tool-id": ("permit/resumed-history.json", None, None),
        "result": ("permit/resumed-history.json", None, None),
        "first-arguments": ("permit/history.json", None, None),
    }[mutation]
    target = root / path
    data = json.loads(target.read_bytes())
    if field is not None:
        data[field] = value
    else:
        alter(data, mutation)
    target.write_bytes(json.dumps(data, separators=(",", ":")).encode() if "history" in path else canonical(data))
    with pytest.raises((VerificationError, KeyError, TypeError)):
        verify_saved(root, reselect(root))


def alter(data: dict | list, mutation: str) -> None:
    """Change one substantive native/effect/process relationship."""
    if mutation in {"tool-id", "result"}:
        data[2]["parts"][0]["tool_call_id" if mutation == "tool-id" else "content"] = "swapped-result"
    elif mutation == "first-arguments":
        data[1]["parts"][0]["args"] = {"content": "CHANGED"}
    else:
        alter_record(data, mutation)


def alter_record(data: dict, mutation: str) -> None:
    """Change one signed-state or real-process record."""
    if mutation == "signed-readback":
        data["live"]["receipt"]["signature"] = "0" * 128
    elif mutation == "process-id":
        data["workers"][1]["pid"] = data["workers"][0]["pid"]
    elif mutation == "exit-code":
        data["workers"][0]["returncode"] = 0
    elif mutation == "child-env":
        data["workers"][0]["environment"]["OPENAI_API_KEY"] = "injected"


@pytest.mark.parametrize("which", ["postResponseHex", "getResponseHex"])
@pytest.mark.parametrize("suffix", [' ,"duplicate":0,"duplicate":1}', ',"nonfinite":NaN}'])
def test_ambiguous_http_bytes(native: Path, tmp_path: Path, which: str, suffix: str) -> None:
    root = tmp_path / "packet"
    shutil.copytree(native, root)
    target = root / "permit/prior-http.json"
    data = load(target)
    raw = bytes.fromhex(data[which])
    data[which] = (raw[:-1] + suffix.encode()).hex()
    target.write_bytes(canonical(data))
    with pytest.raises(VerificationError):
        verify_saved(root, reselect(root))


def test_linked_artifact_refuses(native: Path, tmp_path: Path) -> None:
    root = tmp_path / "packet"
    shutil.copytree(native, root)
    path = root / "permit/committed.sqlite"
    moved = tmp_path / "outside.sqlite"
    path.rename(moved)
    path.symlink_to(moved)
    with pytest.raises(VerificationError, match="packet-symlink"):
        verify_saved(root, load(root / "consumer-pins.json"))


@pytest.mark.parametrize("mutation", ["missing", "signature", "ticket", "effect", "content", "receipt-body", "revoked-effect"])
def test_final_state_is_required_and_authenticated(native: Path, tmp_path: Path, mutation: str) -> None:
    root = tmp_path / "packet"
    shutil.copytree(native, root)
    name = ("revoked" if mutation == "revoked-effect" else "permit") + "/final-parent-readback.json"
    target = root / name
    data = load(target)
    if mutation == "missing":
        target.unlink()
        manifest = load(root / "artifact-manifest.json")
        manifest.pop(name)
        (root / "artifact-manifest.json").write_bytes(canonical(manifest))
    else:
        mutate_final(data, mutation)
        target.write_bytes(canonical(data))
    with pytest.raises(VerificationError):
        verify_saved(root, reselect(root))


def mutate_final(data: dict, mutation: str) -> None:
    """Change signed final effect bytes or their exact body join."""
    changes = {"ticket": ("ticketId", "another-ticket"), "effect": ("effectId", "0" * 64), "content": ("contentHex", b"CHANGED".hex())}
    if mutation in changes:
        key, value = changes[mutation]
        data[key] = value
    elif mutation == "signature":
        data["receipt"]["signature"] = "0" * 128
    else:
        data["receipt"]["payload"]["effectId"] = "0" * 64


@pytest.mark.parametrize("raw", [b"[NaN]", b"[1e999]", b'[{"a":1,"a":2}]', b"[" * 40 + b"0" + b"]" * 40, b"[" * 2000 + b"0" + b"]" * 2000, b"[invalid]"])
def test_native_json_boundary(raw: bytes) -> None:
    from probity_pydantic_recovery.common import messages
    with pytest.raises(VerificationError):
        messages(raw)


def test_preparation_failure_removes_private_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A source-capture failure cannot leave selected private keys behind."""
    import recovery_run

    def fail_capture(root: Path) -> dict[str, str]:
        raise RuntimeError("controlled-source-capture-failure")

    monkeypatch.setattr(recovery_run, "capture_sources", fail_capture)
    root = tmp_path / "failed-packet"
    with pytest.raises(RuntimeError, match="controlled-source-capture-failure"):
        run(root, "test-source")
    assert not (tmp_path / "failed-packet-private").exists()
    assert not recovery_run.ACTIVE


def test_replaced_candidate_cannot_change_consumed_bytes(native: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Replacing a checked path cannot change the authenticated private copy."""
    from probity_pydantic_recovery import reader

    root = tmp_path / "packet"
    shutil.copytree(native, root)
    selected = load(root / "consumer-pins.json")
    target = root / "permit/recovery.json"
    original_read = reader.read

    def replace_after_read(path: Path) -> bytes:
        raw = original_read(path)
        if path == target:
            changed = load(target)
            changed["status"] = "refused"
            target.write_bytes(canonical(changed))
        return raw

    monkeypatch.setattr(reader, "read", replace_after_read)
    report = verify_saved(root, selected)
    assert report["records"][0]["recovery"] == "completed"
    assert load(target)["status"] == "refused"


@pytest.mark.parametrize("kind", ["directory", "symlink", "fifo"])
def test_regular_file_open_refuses_other_types(tmp_path: Path, kind: str) -> None:
    """No-follow and nonblocking open refuse links and special files."""
    from probity_pydantic_recovery.common import read

    path = tmp_path / "candidate"
    if kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        target = tmp_path / "outside"
        target.write_bytes(b"selected bytes")
        path.symlink_to(target)
    else:
        os.mkfifo(path)
    with pytest.raises(VerificationError):
        read(path)


@pytest.mark.parametrize("index", [2, 3])
def test_reselected_native_message_kind_refuses(native: Path, tmp_path: Path, index: int) -> None:
    """Native tool returns and final output need their real message kinds."""
    root = tmp_path / "packet"
    shutil.copytree(native, root)
    path = root / "permit/resumed-history.json"
    history = json.loads(path.read_bytes())
    history[index]["kind"] = "wrong-native-message-kind"
    path.write_bytes(json.dumps(history, separators=(",", ":")).encode())
    with pytest.raises(VerificationError, match="native-continuation-message-kinds"):
        verify_saved(root, reselect(root))


@pytest.mark.parametrize("case,field,value", [("permit", "returncode", False), ("permit", "nativeModelRequests", True), ("permit", "providerCalls", False), ("revoked", "nativeModelRequests", False), ("permit", "recoveryPosts", False), ("revoked", "recoveryPosts", False)])
def test_reselected_boolean_count_refuses(native: Path, tmp_path: Path, case: str, field: str, value: bool) -> None:
    """Boolean JSON values cannot impersonate native counts or process exits."""
    root = tmp_path / "packet"
    shutil.copytree(native, root)
    path = root / case / ("processes.json" if field == "returncode" else "recovery.json")
    data = load(path)
    selected = data["workers"][1] if field == "returncode" else data
    selected[field] = value
    path.write_bytes(canonical(data))
    with pytest.raises(VerificationError):
        verify_saved(root, reselect(root))


@pytest.mark.parametrize("mutation", ["target-startup", "recovery-worker", "target-event"])
def test_reselected_boolean_process_identity_refuses(native: Path, tmp_path: Path, mutation: str) -> None:
    """Integer one cannot make a boolean join pass as a real process identity."""
    root = tmp_path / "packet"
    shutil.copytree(native, root)
    path = root / "permit/processes.json"
    data = load(path)
    if mutation == "recovery-worker":
        data["workers"][1]["pid"] = 1
        target = root / "permit/recovery.json"
        recovery = load(target)
        recovery["pid"] = True
        target.write_bytes(canonical(recovery))
    else:
        data["targets"][0]["pid"] = 1
        data["targets"][0]["startup"]["pid"] = True if mutation == "target-startup" else 1
        target = root / "permit/first-target-http-events.json"
        events = load(target)
        for event in events:
            event["pid"] = True if mutation == "target-event" else 1
        target.write_bytes(canonical(events))
    path.write_bytes(canonical(data))
    with pytest.raises(VerificationError):
        verify_saved(root, reselect(root))
