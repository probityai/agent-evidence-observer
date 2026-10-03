"""Read native A2A task closure and durable effects without either SDK."""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from probity_observer.authorization import (
    ActionRequest, GrantPolicy, verify_authorized_packet, verify_grant,
)
from probity_observer.verify import verify_packet

from .contract import (
    A2A_VERSION, ARTIFACTS, BARE_FAILURE, CASES, CONTENT, FAILURE, PROFILE,
    REVISIONS, SDK_VERSION, decode, encode, exact, identity, load, population,
    require, sha, state_label,
)
from .source import expected_sources


def checked_file(root: Path, name: str, digest: str) -> Path:
    """Authenticate a selected regular artifact without following symlinks."""
    parts = name.split("/")
    require(all(part not in {"", ".", ".."} for part in parts), "artifact path differs")
    path = root / name
    parents = [parent for parent in path.parents if parent.is_relative_to(root)]
    require(not root.is_symlink() and not path.is_symlink() and path.is_file()
            and all(not parent.is_symlink() for parent in parents),
            "artifact must be a regular file")
    exact(sha(path.read_bytes()), digest, "artifact digest differs from host selection")
    return path


def core_check(function: Callable[[], Any], reason: str) -> Any:
    """Expose one logged profile reason when signed-core checking refuses."""
    try:
        return function()
    except (ValueError, KeyError, TypeError):
        require(False, reason)


def verify_sources(root: Path, policy: dict[str, Any]) -> None:
    """Check complete retained native/profile/core bytes against trust anchors."""
    manifest = load(checked_file(root, "source-before-run.json", policy["sourceManifestSha256"]))
    exact(manifest, expected_sources(policy["variant"]), "selected source population or bytes differ")
    source = root / "source"
    physical = list(source.rglob("*"))
    require(not source.is_symlink() and all(not path.is_symlink() for path in physical),
            "retained source is not regular")
    exact(sorted(path.relative_to(source).as_posix() for path in physical if path.is_file()),
          sorted(manifest), "retained source population differs")
    for name, digest in manifest.items():
        checked_file(root / "source", name, digest)


def text_of(event: dict[str, Any]) -> str:
    """Extract the same native content text without importing ADK."""
    content = event["content"] or {}
    return " ".join(part["text"] for part in content.get("parts", []) if part.get("text"))


def status_text(status: dict[str, Any]) -> str | None:
    """Read a status message while preserving its absence for bare failures."""
    message = status.get("message")
    if not message:
        return None
    return " ".join(part["text"] for part in message.get("parts", []) if part.get("text"))


def expected_events(case: str, streaming: bool, variant: str) -> list[tuple[str, str, Any, Any]]:
    """Return literal caller states/content/error fields for the selected pin.

    The non-streamed bare failure retains the earlier ``working`` text through
    the task history. The proposed patch falls back to that content as the
    error message. A streamed bare failure instead uses its generic reason.
    These are source-pinned observations, not invented task failure reasons.
    """
    spec = CASES[case]
    text = spec.text
    if case == "failed-after-bare":
        text = "" if streaming else "working"
    marked = variant == "proposed-fix" and spec.state == "FAILED"
    error = None
    if marked:
        error = BARE_FAILURE if case == "failed-after-bare" and streaming else text
    terminal = (spec.state, text, "A2A_TASK_FAILED" if marked else None, error)
    if not streaming:
        return [terminal]
    rows = [("SUBMITTED", "", None, None), ("WORKING", "working", None, None)]
    if case == "status-after-content":
        rows.append(("WORKING", "done", None, None))
    rows.append(terminal)
    return rows


def verify_caller(native: dict[str, Any], case: str, streaming: bool,
                  variant: str, task: dict[str, Any]) -> None:
    """Bind native events, converted metadata and stored session observations."""
    rows = native["events"]
    expected = expected_events(case, streaming, variant)
    exact(native["callerComplete"], CASES[case].complete, "caller closure differs")
    exact(len(rows), len(expected), "native event population differs")
    identifiers = [row["event"]["id"] for row in rows]
    require(len(set(identifiers)) == len(identifiers), "native event identity repeated")
    for row, selected in zip(rows, expected, strict=True):
        event = row["event"]
        exact(sorted(row), ["event", "isFinalResponse", "state", "text"], "native event shape differs")
        metadata = event["custom_metadata"] or {}
        response = metadata.get("a2a:response") or {}
        status = (response.get("status") or {}).get("state")
        exact([state_label(row["state"]), row["text"], event["error_code"], event["error_message"]],
              list(selected), "native state, content or error differs")
        exact(row["state"], status, "native response state and event differ")
        exact(row["text"], text_of(event), "native content and extracted text differ")
        exact(row["isFinalResponse"], True, "native final-response flag differs")
        exact(event["author"], "remote", "native author differs")
        exact([metadata.get("a2a:task_id"), metadata.get("a2a:context_id"),
               response.get("id"), response.get("contextId")],
              [task["taskId"], task["contextId"], task["taskId"], task["contextId"]],
              "native task binding differs")
        request = metadata.get("a2a:request") or {}
        exact(request.get("role"), "ROLE_USER", "native request role differs")
        exact(request.get("parts"), [{"text": case, "metadata": {"is_user_input": True}}],
              "native converted request differs")
    session = native["sessionEvents"]
    exact([row["author"] for row in session], ["user"] + ["remote"] * len(rows),
          "native session population differs")
    exact(text_of(session[0]), case, "native session request differs")
    exact(session[1:], [row["event"] for row in rows], "native session and caller events differ")
    require(len({row["invocation_id"] for row in session}) == 1, "native invocation binding differs")


def wire_responses(wire: list[dict[str, Any]], streaming: bool, case: str) -> list[dict[str, Any]]:
    """Parse complete native transport bodies, including streamed terminal flags."""
    for row in wire:
        exact(sorted(row), ["body", "direction", "moreBody", "path"], "wire row shape differs")
        require(row["direction"] in {"request", "response"} and type(row["body"]) is str
                and type(row["moreBody"]) is bool, "wire row type differs")
        require(row["path"] in {"/", "/.well-known/agent-card.json"}, "native wire route differs")
    requests = [row for row in wire if row["direction"] == "request"]
    exact([row["path"] for row in requests], ["/", "/"], "native wire request route differs")
    exact([row["moreBody"] for row in requests], [True, False], "native wire request closure differs")
    request = decode("".join(row["body"] for row in requests))
    exact(request["method"], "message/stream" if streaming else "message/send", "native transport method differs")
    exact(request["params"]["message"]["parts"][0]["text"], case, "native wire request differs")
    bodies = [row for row in wire if row["direction"] == "response" and row["path"] == "/"]
    require(bool(bodies) and bodies[-1]["moreBody"] is False, "native wire response did not close")
    exact([row["moreBody"] for row in bodies], [True] * (len(bodies) - 1) + [False],
          "native wire response closure order differs")
    raw = "".join(row["body"] for row in bodies)
    payloads = [decode(line.removeprefix("data: ")) for line in raw.splitlines() if line.startswith("data: ")] if streaming else [decode(raw)]
    require(bool(payloads), "native wire response is empty")
    for payload in payloads:
        exact(payload.get("id"), request["id"], "native wire RPC identity differs")
        exact(payload.get("jsonrpc"), "2.0", "native wire protocol differs")
        require("result" in payload and "error" not in payload, "native wire transport failed")
    return [payload["result"] for payload in payloads]


def verify_wire(wire: list[dict[str, Any]], case: str, streaming: bool,
                task: dict[str, Any]) -> str:
    """Require the actual remote closure independently of caller content/errors."""
    responses = wire_responses(wire, streaming, case)
    terminal = "COMPLETED" if case == "permit" else "FAILED"
    states = [state_label(row["status"]["state"]) for row in responses]
    selected = ["SUBMITTED", "WORKING"] if streaming else []
    if streaming and case in {"status-after-content", "dropped-closure"}:
        selected.append("WORKING")
    exact(states, selected + [terminal], "native wire task states differ")
    exact([row.get("kind") for row in responses],
          ["task"] + ["status-update"] * (len(responses) - 1), "native wire response kinds differ")
    terminal_text = None if case == "failed-after-bare" else "done" if case == "permit" else FAILURE
    texts = [None, "working"] if streaming else []
    if streaming and case in {"status-after-content", "dropped-closure"}:
        texts.append("done")
    exact([status_text(row["status"]) for row in responses], texts + [terminal_text],
          "native wire status message differs")
    for row in responses:
        exact([row.get("taskId", row.get("id")), row["contextId"]],
              [task["taskId"], task["contextId"]], "native wire task binding differs")
    if streaming:
        exact([row.get("final", False) for row in responses],
              [False] * (len(responses) - 1) + [True], "native wire terminal flag differs")
    return terminal


def verify_trace(native: dict[str, Any], case: str, request: ActionRequest) -> dict[str, Any]:
    """Bind the selected signed request to the server's ordered effect boundary."""
    trace = native["serverTrace"]
    kinds = ["request"] + ["effect"] * CASES[case].effects + ["terminal"]
    exact([row["kind"] for row in trace], kinds, "native server boundary order differs")
    task = trace[0]
    require(all(type(task[key]) is str and bool(task[key]) for key in ("taskId", "contextId")),
            "native task identity absent")
    if CASES[case].effects:
        exact(trace[1], {"kind": "effect", "committed": True, "request": asdict(request)},
              "native effect request differs")
    state = "COMPLETED" if case == "permit" else "FAILED"
    text = None if case == "failed-after-bare" else "done" if case == "permit" else FAILURE
    exact(trace[-1], {"kind": "terminal", "state": state, "text": text,
                     "taskId": task["taskId"], "contextId": task["contextId"]},
          "native server terminal differs")
    return task


def verify_case(root: Path, case: str, streaming: bool,
                variant: str, pins: dict[str, Any]) -> dict[str, Any]:
    """Preserve signed target effects even when native closure reports failure."""
    exact(sorted(pins["artifacts"]), sorted(ARTIFACTS), "artifact population differs")
    paths = {name: checked_file(root, name, digest) for name, digest in pins["artifacts"].items()}
    native, packet, grant, wire = (load(paths[name]) for name in
                                   ("native.json", "packet.json", "grant.json", "wire.json"))
    exact([native["profile"], native["case"], native["streaming"], native["variant"],
           native["sdkVersion"], native["a2aVersion"]],
          [PROFILE, case, streaming, variant, SDK_VERSION, A2A_VERSION], "native identity differs")
    case_id = identity(case, streaming)
    request = ActionRequest(case_id, "attempt-1", "request-1", "tenant-1", "principal-1",
                            "write_result", "/work/result.txt", sha(CONTENT.encode()))
    exact(pins["request"], asdict(request), "host action differs from finite profile")
    when = datetime.strptime(pins["referenceTime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    grant_policy = GrantPolicy(pins["issuerKey"])
    core_check(lambda: verify_grant(grant, request, grant_policy, now=when), "grant verification refused")
    claim = core_check(lambda: verify_packet(packet, paths["history.jsonl"], pins["observerKey"],
                       pins["witnessKey"], workspace=root / "work"), "signed effect verification refused")
    exact(len(claim["writes"]), CASES[case].effects, "signed effect population differs")
    exact(claim["intervalId"], case_id, "signed interval differs")
    exact(claim["witnessScope"], "PEER", "witness scope differs")
    if CASES[case].effects:
        core_check(lambda: verify_authorized_packet(grant, request, grant_policy, packet,
                   paths["history.jsonl"], pins["observerKey"], pins["witnessKey"], now=when,
                   workspace=root / "work"), "authorized effect verification refused")
    task = verify_trace(native, case, request)
    remote_state = verify_wire(wire, case, streaming, task)
    verify_caller(native, case, streaming, variant, task)
    last = native["events"][-1]
    return {"case": case_id, "streaming": streaming, "committedEffects": CASES[case].effects,
            "remoteTaskState": remote_state, "callerTaskState": state_label(last["state"]),
            "callerComplete": native["callerComplete"], "nativeFinalResponse": last["isFinalResponse"],
            "nativeErrorCode": last["event"]["error_code"],
            "nativeErrorMessage": last["event"]["error_message"],
            "publicationDecision": "RELEASE" if case == "permit" else "WITHHOLD",
            "witnessScope": claim["witnessScope"]}


def verify_saved(root: Path, policy: dict[str, Any]) -> dict[str, Any]:
    """Read a complete population against an independently selected host policy."""
    exact(sorted(policy), ["cases", "profile", "schema", "sdk", "sourceManifestSha256", "variant"],
          "host policy shape differs")
    exact(policy["schema"], "probity.adk-a2a-failure-host-policy.v1", "host schema differs")
    exact(policy["profile"], PROFILE, "host profile differs")
    variant = policy["variant"]
    require(variant in REVISIONS, "unknown SDK variant")
    exact(policy["sdk"], {"version": SDK_VERSION, "commit": REVISIONS[variant],
          "a2aVersion": A2A_VERSION}, "host SDK differs")
    exact(sorted(policy["cases"]), sorted(identity(*pair) for pair in population()), "planned population differs")
    verify_sources(root, policy)
    records = [verify_case(root / identity(case, streaming), case, streaming, variant,
               policy["cases"][identity(case, streaming)]) for case, streaming in population()]
    return {"profile": PROFILE, "variant": variant, "sdk": policy["sdk"], "records": records,
            "remoteTasks": len(records), "committedEffects": sum(row["committedEffects"] for row in records),
            "modelInferenceCalls": 0, "independentCustody": False}


def publish_saved(root: Path, policy: dict[str, Any], destination: Path) -> dict[str, Any]:
    """Publish only verified COMPLETED permit cases; preserve failed effects in reports."""
    require(not destination.resolve().is_relative_to(root.resolve()), "publication destination must be outside packet")
    require(not destination.exists(), "publication destination already exists")
    report = verify_saved(root, policy)
    result = {"profile": PROFILE, "variant": policy["variant"],
              "records": [row for row in report["records"] if row["publicationDecision"] == "RELEASE"],
              "selectionSha256": sha(encode(policy))}
    destination.mkdir()
    (destination / "published.json").write_bytes(encode(result))
    return result


def main() -> None:
    """Require an external host policy and its digest at the installed reader CLI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--host-policy", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--publish", type=Path)
    args = parser.parse_args()
    require(not args.host_policy.resolve().is_relative_to(args.packet.resolve()), "host policy must be outside packet")
    exact(sha(args.host_policy.read_bytes()), args.policy_sha256, "host policy pin differs")
    policy = load(args.host_policy)
    result = publish_saved(args.packet, policy, args.publish) if args.publish else verify_saved(args.packet, policy)
    print(encode(result).decode())


if __name__ == "__main__":
    main()
