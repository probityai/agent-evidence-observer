"""Run job-local UID controls while an existing pool job retains its heavy slot."""

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

ROLES = ("issuer", "gateway", "witness", "consumer", "workload")


def encode(value: object) -> bytes:
    """Keep coordinator records deterministic without importing candidate code."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(raw: bytes) -> str:
    """Hash the exact frozen bytes."""
    return hashlib.sha256(raw).hexdigest()


def write_new(path: Path, value: object, owner: tuple[int, int] | None = None) -> None:
    """Create a durable record without replacing a prior phase's evidence."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encode(value))
        stream.flush()
        os.fsync(stream.fileno())
    if owner is not None:
        os.chown(path, *owner)


def process_start(pid: int) -> str | None:
    """Distinguish one actual process from later PID reuse."""
    path = Path(f"/proc/{pid}/stat")
    try:
        return path.read_text().rsplit(")", 1)[1].split()[19]
    except FileNotFoundError:
        return None


def allocation(holder: str, source: Path, marker: str) -> dict[str, object]:
    """Read the holder label and kernel lock rather than treating a label as a lock."""
    selected_pid, selected_path = holder.split(":", 1)
    pid, path = int(selected_pid), Path(selected_path)
    if selected_path != "/tmp/workstation-heavy-gate.lock":
        raise RuntimeError("coordinator requires the normal pool heavy lock")
    job = re.fullmatch(r"box-run-(.+)-([0-9]+)-([0-9]+)", marker)
    if job is None or int(job[2]) != pid:
        raise RuntimeError("job marker does not name the selected holder")
    label = path.read_text()
    if label != f"pid {pid} worktree {source} via box_run {job[1]}":
        raise RuntimeError("heavy holder label does not select this checkout")
    start = process_start(pid)
    if start is None:
        raise RuntimeError("selected holder is no longer live")
    metadata = path.stat()
    descriptors = []
    for descriptor_path in sorted(Path(f"/proc/{pid}/fd").iterdir()):
        if descriptor_path.resolve() == path:
            selected = descriptor_path.stat()
            if (selected.st_dev, selected.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise RuntimeError("holder descriptor inode differs from the selected lock")
            fdinfo = Path(f"/proc/{pid}/fdinfo/{descriptor_path.name}").read_text()
            if "FLOCK" in fdinfo and "WRITE" in fdinfo:
                descriptors.append({"descriptor": descriptor_path.name, "target": str(path), "fdinfo": fdinfo,
                                    "device": selected.st_dev, "inode": selected.st_ino})
    if not descriptors:
        raise RuntimeError("holder has no recorded exclusive kernel lock")
    with path.open("rb") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            fcntl.flock(stream, fcntl.LOCK_UN)
            raise RuntimeError("normal heavy slot is not held")
    holder_owner = Path(f"/proc/{pid}").stat()
    return {"holder": holder, "label": label, "labelSha256": digest(label.encode()),
            "holderStart": start, "holderOwner": {"uid": holder_owner.st_uid, "gid": holder_owner.st_gid}, "lockedDescriptors": descriptors}


def require_owned_ancestor(pid: int) -> None:
    """Require the coordinator request to come from the live gate job's own tree."""
    current = os.getpid()
    while current != pid:
        stat = Path(f"/proc/{current}/stat").read_text().rsplit(")", 1)[1].split()
        current = int(stat[1])
        if current <= 1:
            raise RuntimeError("selected pool holder is not the request's ancestor")
    owner = Path(f"/proc/{pid}").stat()
    if (owner.st_uid, owner.st_gid) != (os.getuid(), os.getgid()):
        raise RuntimeError("selected holder belongs to another gate owner")


def source_output(source: Path, argv: list[str]) -> bytes:
    """Run metadata readbacks as the checkout's actual owner without a Git exception."""
    owner = source.stat()
    credentials = {}
    if os.geteuid() != owner.st_uid:
        if os.geteuid() != 0:
            raise RuntimeError("source metadata owner differs from this job")
        credentials = {"user": owner.st_uid, "group": owner.st_gid, "extra_groups": []}
    return subprocess.check_output(argv, **credentials)


def source_pins(source: Path) -> dict[str, str]:
    """Pin every tracked file in the frozen pool snapshot."""
    paths = source_output(source, ["git", "-C", str(source), "ls-tree", "-r", "--name-only", "-z", "HEAD"])
    return {path.decode(): digest((source / path.decode()).read_bytes()) for path in paths.split(b"\0") if path}


def prepare(source: Path, evidence: Path, runtime: Path) -> None:
    """Expose exact privileged argv only after the normal installed-source gates."""
    profile = source / "interop/protected-action-operator-2026-10-06"
    marker = os.environ["BOX_RUN_JOB"]
    holder = os.environ["WORKSTATION_HEAVY_GATE_HOLDER"]
    require_owned_ancestor(int(holder.split(":", 1)[0]))
    owner = source.stat()
    if owner.st_uid != os.getuid():
        raise RuntimeError("checkout owner differs from the selected gate job")
    python = {role: str(runtime / role / "bin/python") for role in ROLES}
    protected = [python["witness"], "-I", "-B", "-m", "probity_protected_operator.native", str(runtime / "native")]
    for role in ROLES:
        protected.extend(["--" + role + "-python", python[role]])
    legacy = [python["witness"], "-I", "-B", "-m", "probity_witness_operator.native", "run",
              str(runtime / "existing-native"), "--private-state", str(runtime / "existing-private"),
              "--producer-python", python["workload"], "--reader-python", python["consumer"]]
    request = {"format": "probity-held-pool-administrator-v0", "sourceRoot": str(source),
               "sourceHead": source_output(source, ["git", "-C", str(source), "rev-parse", "HEAD"]).decode().strip(),
               "sourceTree": source_output(source, ["git", "-C", str(source), "rev-parse", "HEAD^{tree}"]).decode().strip(),
               "sourceOwner": {"uid": owner.st_uid, "gid": owner.st_gid},
               "sourceFiles": source_pins(source), "evidence": str(evidence), "runtime": str(runtime),
               "gateOwner": {"uid": os.getuid(), "gid": os.getgid()}, "jobMarker": marker, "allocation": allocation(holder, source, marker),
               "installedSourceBefore": {role: digest((evidence / (role + "-source-before.json")).read_bytes()) for role in ROLES},
               "python": python, "commands": {"protected": protected, "existing": legacy},
               "driver": str(profile / "coordinate_root.py")}
    path = evidence / "root-request.json"
    write_new(path, request)
    print(json.dumps({"rootRequest": str(path), "requestSha256": digest(path.read_bytes()),
                      "sourceHead": request["sourceHead"], "jobMarker": marker}, sort_keys=True), flush=True)


def validate(request: dict[str, object]) -> None:
    """Refuse stale allocation, source or installed bytes before any root role run."""
    source, evidence = Path(request["sourceRoot"]), Path(request["evidence"])
    owner = source.stat()
    if {"uid": owner.st_uid, "gid": owner.st_gid} != request["sourceOwner"]:
        raise RuntimeError("checkout metadata owner changed")
    actual = allocation(request["allocation"]["holder"], source, request["jobMarker"])
    if actual != request["allocation"]:
        raise RuntimeError("held pool allocation changed")
    if request["gateOwner"] != actual["holderOwner"]:
        raise RuntimeError("capture owner differs from the selected gate job")
    if source_pins(source) != request["sourceFiles"]:
        raise RuntimeError("frozen source bytes changed")
    head = source_output(source, ["git", "-C", str(source), "rev-parse", "HEAD"]).decode().strip()
    if head != request["sourceHead"]:
        raise RuntimeError("frozen source head changed")
    for role in ROLES:
        before = (evidence / (role + "-source-before.json")).read_bytes()
        if digest(before) != request["installedSourceBefore"][role]:
            raise RuntimeError("installed source map changed: " + role)
        actual_source = source_output(source, [request["python"][role], "-I", "-B", str(source / "interop/protected-action-operator-2026-10-06/qualify_install.py"), str(source)])
        if actual_source != before:
            raise RuntimeError("selected installed source changed: " + role)


def record_command(name: str, argv: list[str], evidence: Path, environment: dict[str, str]) -> int:
    """Retain complete root child streams and its actual final status."""
    stdout_path, stderr_path = evidence / (name + ".stdout.original"), evidence / (name + ".stderr.original")
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        child = subprocess.Popen(argv, env=environment, stdout=stdout, stderr=stderr)
        returncode = child.wait()
    write_new(evidence / (name + "-result.json"), {"argv": argv, "pid": child.pid, "returncode": returncode,
              "stdoutSha256": digest(stdout_path.read_bytes()), "stderrSha256": digest(stderr_path.read_bytes())})
    return returncode


def return_capture(path: Path, owner: tuple[int, int]) -> None:
    """Return only fresh public capture files to the gate job's owner."""
    if not path.exists():
        return
    for selected in (path, *path.rglob("*")):
        if selected.is_symlink():
            raise RuntimeError("public capture contains a symlink")
        selected.chmod(0o755 if selected.is_dir() else 0o644)
        os.chown(selected, *owner)


def run_root(path: Path, selected_sha: str) -> None:
    """Execute the reviewed request; no users, daemons or shared settings change."""
    if os.getuid() != 0 or digest(path.read_bytes()) != selected_sha:
        raise RuntimeError("root or exact reviewed request SHA-256 is missing")
    request = json.loads(path.read_bytes())
    if os.environ.get("BOX_RUN_JOB") != request["jobMarker"] or os.environ.get("WORKSTATION_HEAVY_GATE_HOLDER") != request["allocation"]["holder"]:
        raise RuntimeError("administrator driver must start with the selected pool markers")
    evidence, runtime = Path(request["evidence"]), Path(request["runtime"])
    gate_owner = request["gateOwner"]["uid"], request["gateOwner"]["gid"]
    started = {"pid": os.getpid(), "start": process_start(os.getpid()), "requestSha256": selected_sha}
    write_new(evidence / "root-started.json", started, gate_owner)
    environment = {name: os.environ[name] for name in ("PATH", "LANG", "LC_ALL") if name in os.environ}
    environment.update({"BOX_RUN_JOB": request["jobMarker"], "WORKSTATION_HEAVY_GATE_HOLDER": request["allocation"]["holder"],
                        "PYTHONDONTWRITEBYTECODE": "1"})
    os.environ.update(environment)
    os.umask(0o022)
    status, error = 1, None
    try:
        validate(request)
        status = record_command("root-protected", request["commands"]["protected"], evidence, environment)
        if status == 0:
            status = record_command("root-existing", request["commands"]["existing"], evidence, environment)
    except BaseException as caught:
        error = repr(caught)
        raise
    finally:
        try:
            if (runtime / "existing-private").exists():
                shutil.rmtree(runtime / "existing-private")
            for selected in (runtime / "native", runtime / "existing-native"):
                return_capture(selected, gate_owner)
            for selected in evidence.glob("root-*"):
                return_capture(selected, gate_owner)
        except Exception as caught:
            status, error = 1, repr(caught)
        allocation_after = None
        try:
            allocation_after = allocation(request["allocation"]["holder"], Path(request["sourceRoot"]), request["jobMarker"])
        except Exception as caught:
            status, error = 1, repr(caught)
        final = {**started, "returncode": status, "error": error,
                 "allocationAfter": allocation_after,
                 "captures": {selected.name: digest(selected.read_bytes()) for selected in evidence.glob("root-*.original")}}
        write_new(evidence / "root-exit.json", final, gate_owner)
    if status:
        raise SystemExit(status)


def wait_root(path: Path) -> None:
    """Keep the normal job alive until the privileged driver has really ended."""
    request = json.loads(path.read_bytes())
    evidence = Path(request["evidence"])
    deadline = time.monotonic() + 1800
    while not (evidence / "root-exit.json").exists():
        if not (evidence / "root-started.json").exists() and time.monotonic() >= deadline:
            raise RuntimeError("no administrator phase started within the job's wait")
        allocation(request["allocation"]["holder"], Path(request["sourceRoot"]), request["jobMarker"])
        time.sleep(0.2)
    final = json.loads((evidence / "root-exit.json").read_bytes())
    if final["requestSha256"] != digest(path.read_bytes()):
        raise RuntimeError("administrator status selects another request")
    while process_start(final["pid"]) == final["start"]:
        time.sleep(0.05)
    for name, expected in final["captures"].items():
        if digest((evidence / name).read_bytes()) != expected:
            raise RuntimeError("administrator capture bytes changed")
    if final["returncode"]:
        raise SystemExit(final["returncode"])


def main() -> None:
    """Select one explicit coordinator operation."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preparing = commands.add_parser("prepare")
    for name in ("source", "evidence", "runtime"):
        preparing.add_argument(name, type=Path)
    for name in ("run", "wait"):
        selected = commands.add_parser(name)
        selected.add_argument("request", type=Path)
        if name == "run":
            selected.add_argument("--request-sha256", required=True)
    arguments = parser.parse_args()
    if arguments.command == "prepare":
        prepare(arguments.source, arguments.evidence, arguments.runtime)
    elif arguments.command == "run":
        run_root(arguments.request, arguments.request_sha256)
    else:
        wait_root(arguments.request)


if __name__ == "__main__":
    main()
