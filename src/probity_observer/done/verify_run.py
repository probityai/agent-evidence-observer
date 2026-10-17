"""C4: the harness, never the agent, grades the agent's final tree in fresh containers.

One grading run, in order:

1. Check that the final tree on disk is the one the tree record names (its digest).
2. Stage a copy without following links: regular files are copied with ``O_NOFOLLOW``, a
   link that would leave the tree and every special file are rejected and listed.
3. Reset every protected path from the sealed copy, together with its excluded names, and
   remove every ``__pycache__`` and ``.pytest_cache`` in the tree, so neither a poisoned
   ``.pyc`` nor a cache file survives. Measure the protected digests again.
4. Run each acceptance command (visible and held-out) in its own fresh container from the
   staged copy. The container has no network, no capabilities, ``no-new-privileges``, a
   read-only root file system (so ``/usr`` and ``site-packages`` are read-only), a private
   ``/tmp``, process and memory limits, an unprivileged uid with no supplementary groups, and
   ``env -i`` with a fixed environment. These are the lockdown layers of Ratchet's guard
   child (rlimits, network namespace, no new privileges) applied by the container runtime.
5. Write the ``probity-acceptance-grade/v1`` record and sign it with the grader's own key,
   which is not the harness key that sealed the contract.
6. Write the verifier's account of its own isolation, the ``verifier_isolation`` block the
   ``agent-evidence-admission`` rule set reads. Every fact is measured or follows from the
   argv above; where the grading run is weaker than an obligation asks (agent code is imported
   into the process that asserts, the result is an exit status the worker sets) the block says
   so, and the rule set refuses it.
"""

from __future__ import annotations

import difflib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from ..sensors import treedigest
from . import mutants
from .contract import ACCEPTANCE_CONFIG, Protected, copy_protected, protected_digest
from .formats import DoneError, encode, public_key, sha256, sign_record
from .runner import (SCRUBBED_ENV, TIMEOUT_EXIT, changed_paths, chmod_tree, is_replay,
                     run_replay, stage)

GRADE_SCHEMA = "probity-acceptance-grade/v1"
WORKER_UID = 65534
CACHE_NAMES = ("__pycache__", ".pytest_cache")
GRADER_FILES = frozenset({"conftest.py", *ACCEPTANCE_CONFIG})


class GradeError(DoneError):
    """The tree cannot be graded (wrong digest, runtime failure)."""


@dataclass
class DockerRunner:
    """One fresh, locked-down container per acceptance run."""

    image: str
    worker_uid: int = WORKER_UID
    memory: str = "2g"
    pids: int = 256
    tmpfs_size: str = "512m"
    docker: str = "docker"
    name: str = "docker"
    order_seed: str = "docker"
    replays: list[dict[str, Any]] = field(default_factory=list)

    def flags(self) -> list[str]:
        """Every isolation flag, in the order they are passed; part of the isolation report."""
        return ["--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--read-only", "--tmpfs", f"/tmp:rw,nosuid,nodev,size={self.tmpfs_size}",
                "--pids-limit", str(self.pids), "--memory", self.memory,
                "--ulimit", "core=0", "--user", f"{self.worker_uid}:{self.worker_uid}"]

    def command(self, name: str, scratch: Path, argv: Sequence[str], heldout: bool) -> list[str]:
        command = [self.docker, "run", "--rm", "--name", name, *self.flags(),
                   "--volume", f"{scratch / 'workspace'}:/workspace"]
        if heldout:
            command += ["--volume", f"{scratch / 'heldout'}:/heldout:ro"]
        command += ["--workdir", "/workspace", "--entrypoint", "/usr/bin/env", self.image, "-i",
                    *(f"{key}={value}" for key, value in sorted(SCRUBBED_ENV.items())), *argv]
        return command

    def child_argv(self, directory: Path, source: str) -> tuple[list[str], None]:
        """A fresh container holding only the candidate's module, read-only."""
        return ([self.docker, "run", "-i", "--rm", *self.flags(),
                 "--volume", f"{directory}:/workspace:ro", "--workdir", "/workspace",
                 "--entrypoint", "/usr/bin/env", self.image, "-i",
                 *(f"{key}={value}" for key, value in sorted(SCRUBBED_ENV.items())),
                 "python", "-I", "-P", "-c", source], None)

    def run(self, state: Path, argv: Sequence[str], heldout: Path | None,
            timeout: float, writes: list[str] | None = None,
            output: list[str] | None = None) -> int:
        with tempfile.TemporaryDirectory(prefix="probity-grade-") as scratch:
            root = Path(scratch)
            stage(Path(state), heldout, root)
            if is_replay(argv):
                return run_replay(root, argv, self.child_argv, timeout, self.order_seed,
                                  self.replays)
            chmod_tree(root / "workspace")
            if heldout is not None:
                chmod_tree(root / "heldout", 0o755, 0o644)
            os.chmod(root, 0o755)
            name = f"probity-grade-{uuid.uuid4().hex[:12]}"
            process = subprocess.Popen(self.command(name, root, argv, heldout is not None),
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
            try:
                printed, error = process.communicate(timeout=timeout)
                if output is not None:
                    output.append(printed.decode("utf-8", "replace"))
            except subprocess.TimeoutExpired:
                subprocess.run([self.docker, "kill", name], capture_output=True, check=False)
                process.communicate()
                code = TIMEOUT_EXIT
            else:
                if process.returncode == 125:
                    raise GradeError("container runtime failed: "
                                     + error.decode(errors="replace").strip())
                code = process.returncode
            if writes is not None:
                writes.extend(changed_paths(Path(state), root / "workspace"))
            return code

    def groups(self) -> list[int]:
        """The worker's supplementary groups, measured in a container with the same flags."""
        probe = subprocess.run([self.docker, "run", "--rm", *self.flags(), "--entrypoint",
                                "/usr/bin/env", self.image, "-i", "id", "-G"],
                               capture_output=True, text=True, check=False)
        if probe.returncode != 0:
            raise GradeError(f"cannot measure the worker's groups: {probe.stderr.strip()}")
        return sorted(int(item) for item in probe.stdout.split() if int(item) != self.worker_uid)


@dataclass
class Staged:
    root: Path
    rejected: list[str] = field(default_factory=list)
    removed_caches: list[str] = field(default_factory=list)
    removed_config: list[str] = field(default_factory=list)
    rejected_native: list[str] = field(default_factory=list)


def _copy_file(source: Path, target: Path) -> None:
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as reader, open(target, "xb") as writer:
            shutil.copyfileobj(reader, writer)
    finally:
        os.close(descriptor)
    os.chmod(target, stat.S_IMODE(os.lstat(source).st_mode))


def _inside(root: Path, link: Path) -> bool:
    target = os.readlink(link)
    if os.path.isabs(target):
        return False
    resolved = os.path.normpath(os.path.join(link.parent, target))
    return resolved == str(root) or resolved.startswith(str(root) + os.sep)


NATIVE_SUFFIXES = (".so", ".pyd", ".dll", ".dylib")


def native(path: Path) -> bool:
    """A compiled binary the Python-level layers cannot see into."""
    if path.name.endswith(NATIVE_SUFFIXES) or ".so." in path.name:
        return True
    with open(path, "rb") as handle:
        return handle.read(4) == b"\x7fELF"


def _same_file(path: Path, sealed: Path) -> bool:
    return (sealed.is_file() and not sealed.is_symlink()
            and treedigest.file_sha256(sealed) == treedigest.file_sha256(path))


def stage_tree(final: Path, destination: Path, start: Path) -> Staged:
    """Copy ``final`` into a new ``destination`` without following any link.

    A symbolic link is kept only when the sealed start tree ``start`` has the same link at
    the same path; any other link, and every special file, is rejected and listed. So is a
    native binary (an ELF file or a ``.so``, ``.pyd``, ``.dll``, ``.dylib``) that the start
    tree did not have byte for byte: compiled code is beyond every Python-level layer. A tree
    record hashes regular files only, so a link the agent made (``conftest.py -> /tmp/x``)
    would otherwise reach the grader unseen.
    """
    destination.mkdir()
    staged = Staged(destination)
    for directory, dirnames, filenames in os.walk(final, followlinks=False):
        base = Path(directory)
        relative = base.relative_to(final)
        for name in sorted(dirnames + filenames):
            source, target = base / name, destination / relative / name
            mode = os.lstat(source).st_mode
            if stat.S_ISLNK(mode):
                sealed = start / relative / name
                if (_inside(final, source) and sealed.is_symlink()
                        and os.readlink(sealed) == os.readlink(source)):
                    os.symlink(os.readlink(source), target)
                else:
                    staged.rejected.append((relative / name).as_posix())
                if name in dirnames:
                    dirnames.remove(name)
            elif stat.S_ISDIR(mode):
                target.mkdir()
            elif stat.S_ISREG(mode):
                if native(source) and not _same_file(source, start / relative / name):
                    staged.rejected.append((relative / name).as_posix())
                    staged.rejected_native.append((relative / name).as_posix())
                else:
                    _copy_file(source, target)
            else:
                staged.rejected.append((relative / name).as_posix())
    return staged


def _remove(target: Path) -> None:
    if target.is_symlink() or target.is_file():
        target.unlink()
    elif target.is_dir():
        shutil.rmtree(target)


def reset(staged: Staged, protected: list[Protected], sealed: Path, start: Path) -> None:
    """Restore every protected path from ``sealed`` and remove what grading must not load.

    Removed: every cache directory, and every ``conftest.py`` or acceptance-configuration
    file that the start tree did not have at that path. A protected path below a symbolic
    link is refused, because the restore would write through the link.
    """
    for entry in protected:
        parts = Path(entry.path).parts
        for index in range(1, len(parts)):
            if (staged.root / Path(*parts[:index])).is_symlink():
                raise GradeError(f"a protected path lies below a symbolic link: {entry.path}")
        _remove(staged.root / entry.path)
        copy_protected(sealed, entry, staged.root)
    for directory, dirnames, filenames in os.walk(staged.root):
        base = Path(directory)
        for name in list(dirnames):
            if name in CACHE_NAMES:
                staged.removed_caches.append((base / name).relative_to(staged.root).as_posix())
                shutil.rmtree(base / name)
                dirnames.remove(name)
        for name in filenames:
            relative = (base / name).relative_to(staged.root)
            if name in GRADER_FILES and not (start / relative).is_file():
                staged.removed_config.append(relative.as_posix())
                (base / name).unlink()


def _protected(contract: dict[str, Any]) -> list[Protected]:
    return [Protected(item["path"], item["kind"], tuple(item.get("exclude", ())))
            for item in contract["protected_paths"]]


def _trusted(contract: dict[str, Any], staged: Staged) -> tuple[str, str]:
    expected = [item["sha256"] for item in contract["protected_paths"]]
    measured = [protected_digest(staged.root, entry) for entry in _protected(contract)]
    return sha256(encode(expected)), sha256(encode(measured))


def _visible_part(heldout: Path, destination: Path) -> Path:
    """The part of the sealed directory a visible command may read."""
    destination.mkdir()
    if (heldout / "config").is_dir():
        shutil.copytree(heldout / "config", destination / "config")
    for name in ("visible_test.py",):
        if (heldout / name).is_file():
            shutil.copy2(heldout / name, destination / name)
    return destination


MIN_HUNKS_EXERCISED = 1.0
PER_HUNK_MUTANTS = 3


def patch_hunks(start: Path, staged: Path, protected: list[Protected]) -> list[tuple[str, tuple[int, int]]]:
    """Python source lines the agent added or changed, one range per hunk, outside protected paths."""
    hunks = []
    for path in sorted(staged.rglob("*.py")):
        name = path.relative_to(staged).as_posix()
        if path.is_symlink() or any(name == entry.path or name.startswith(entry.path + "/")
                                    for entry in protected):
            continue
        before = (start / name).read_text("utf-8", "replace").splitlines() if (start / name).is_file() else []
        after = path.read_text("utf-8", "replace").splitlines()
        for tag, _, _, first, last in difflib.SequenceMatcher(None, before, after).get_opcodes():
            if tag in ("replace", "insert") and last > first:
                hunks.append((name, (first + 1, last)))
    return hunks


def _killed(runner, state: Path, commands: list[dict[str, Any]], sealed: dict[str, Path | None],
            timeout: float) -> bool:
    for item in commands:
        if runner.run(state, item["argv"], sealed[item["id"]], timeout) != 0:
            return True
    return False


def post_patch(runner, root: Path, start: Path, contract: dict[str, Any],
               sealed: dict[str, Path | None], timeout: float) -> list[dict[str, Any]]:
    """Mutate each hunk of the agent's patch and require the acceptance commands to notice.

    A hunk whose mutants all survive was not exercised by the tests that passed: the pass
    says nothing about that change. Logging calls and docstrings are never mutation sites.
    """
    report = []
    for name, lines in patch_hunks(start, root, _protected(contract)):
        try:
            found = mutants.operator_mutants(name, (root / name).read_text(), [lines])
        except SyntaxError:
            found = []
        chosen = mutants.stratified([found], PER_HUNK_MUTANTS, f"{name}:{lines}")
        kills = []
        for mutant in chosen:
            with tempfile.TemporaryDirectory(prefix="probity-hunk-") as scratch:
                state = Path(scratch) / "tree"
                shutil.copytree(root, state, symlinks=True)
                (state / name).write_text(mutant.source)
                kills.append(_killed(runner, state, contract["acceptance"], sealed, timeout))
        report.append({"path": name, "lines": list(lines), "mutants": len(chosen),
                       "killed": sum(kills), "kill_vector": kills})
    return report


def hunks_exercised(report: list[dict[str, Any]]) -> float:
    counted = [item for item in report if item["mutants"]]
    return 1.0 if not counted else sum(1 for item in counted if item["killed"]) / len(counted)


@dataclass(frozen=True)
class Graded:
    grade: dict[str, Any]
    grade_bytes: bytes
    envelope: bytes
    isolation: dict[str, Any]
    staging: dict[str, Any]


@dataclass(frozen=True)
class GradeContext:
    claim_id: str
    invocation_id: str
    producer: str = "harness-verifier"
    witness_scope: str = "PEER"


def _isolation(contract_sha256: str, trusted: tuple[str, str], runner: DockerRunner,
               commands: list[dict[str, Any]], steps: tuple[int, int], result_dir: Path,
               heldout_mode: str | None) -> dict[str, Any]:
    """The verifier's account of itself, in the fields ``docs/VERIFIER-ISOLATION.md`` names."""
    python_isolated = all(item["argv"][0] != "python" or bool({"-I", "-P"} & set(item["argv"]))
                          for item in commands)
    # A replay holds every assertion in the verifier's own process and receives only plain
    # data from the candidate; any other command's result is an exit status the worker sets.
    replayed = all(is_replay(item["argv"]) for item in commands)
    report: dict[str, Any] = {
        "contract_sha256": contract_sha256,
        "trusted_tree": {"expected_sha256": trusted[0], "measured_sha256": trusted[1],
                         "excluded_names_reset": True},
        "worker": {"uid": runner.worker_uid, "supplementary_groups": runner.groups(),
                   "env_scrubbed": True, "scratch_copy": True},
        "verifier": {"uid": os.getuid(), "assertions_in_parent": replayed,
                     "python_isolated": python_isolated},
        "result": {"dir_mode": format(stat.S_IMODE(os.stat(result_dir).st_mode), "04o"),
                   "precleared": True, "written_by": "verifier",
                   "files_read": ["replay-result" if replayed else "container-exit-status"]},
        "tests": {"expected": len(commands), "collected": len(commands), "skipped": 0,
                  "exit_status_alone_accepted": not replayed},
        "processes": {"worker_killed": True, "remaining": 0, "killed_step": steps[0],
                      "result_read_step": steps[1]},
        "staging": {"nofollow": True, "destination_removed_first": True,
                    "special_files_rejected": True},
        "evidence_from_worker": [] if replayed else ["exit_status"],
        "loaders": [{"name": "replay-result" if replayed else "container-exit-status",
                     "safe": True}],
        "lockdown": {"runtime": runner.name, "image": runner.image, "flags": runner.flags()},
    }
    if heldout_mode is not None:
        report["reference"] = {"dir_mode": heldout_mode, "inside_artifact_dir": False}
    return report


def grade(contract_bytes: bytes, bundle: Path, final: Path, tree_record: dict[str, Any],
          context: GradeContext, runner: DockerRunner, key, timeout: float = 900.0) -> Graded:
    """Grade the agent's final tree ``final`` against the contract bundle ``bundle``.

    ``bundle`` is the directory :func:`.contract.seal` wrote: its ``workspace`` is the
    sealed start tree and ``sealed`` holds the protected copies and held-out files.
    """
    sealed, start = bundle / "sealed", bundle / "workspace"
    contract = json.loads(contract_bytes)
    scanned = treedigest.scan(final)
    if scanned.sha256 != tree_record["tree_sha256"] or scanned.files != tree_record["files"]:
        raise GradeError("the final tree on disk is not the tree the record names")
    heldout = sealed / "heldout"
    has_heldout = heldout.is_dir()
    with tempfile.TemporaryDirectory(prefix="probity-verifier-") as work:
        result_dir = Path(work)
        os.chmod(result_dir, 0o700)
        staged = stage_tree(final, result_dir / "tree", start)
        reset(staged, _protected(contract), sealed / "protected", start)
        trusted = _trusted(contract, staged)
        if trusted[0] != trusted[1]:
            raise GradeError("protected paths do not match the contract after the reset")
        runner.order_seed = sha256((public_key(key) + sha256(contract_bytes)).encode())
        runner.replays = []
        visible = _visible_part(heldout, result_dir / "visible-sealed") if has_heldout else None
        results = []
        # Held-out tests reach only held-out commands. Visible commands get the sealed
        # configuration and the sealed visible test, never a held-out file.
        dirs = {item["id"]: heldout if item["id"].startswith("heldout") else visible
                for item in contract["acceptance"]}
        for item in contract["acceptance"]:
            exit_code = runner.run(staged.root, item["argv"], dirs[item["id"]], timeout)
            results.append({"id": item["id"], "argv": item["argv"], "exit": exit_code})
        replays = list(runner.replays)
        hunks = (post_patch(runner, staged.root, start, contract, dirs, timeout)
                 if all(item["exit"] == 0 for item in results) else [])
        # Each run's container has exited (and with it every worker process) before its
        # exit status is read: kill is step 1, the read step 2, for every command.
        isolation = _isolation(sha256(contract_bytes), trusted, runner, contract["acceptance"],
                               (1, 2), result_dir,
                               format(0o755, "04o") if has_heldout else None)
        staging = {"rejected": staged.rejected, "removed_caches": staged.removed_caches,
                   "removed_config": staged.removed_config,
                   "rejected_native": staged.rejected_native, "replays": replays,
                   "post_patch": hunks, "hunks_exercised": hunks_exercised(hunks),
                   "replay_order_seed": runner.order_seed}
    record = {"schema_version": GRADE_SCHEMA, "claim_id": context.claim_id,
              "invocation_id": context.invocation_id, "producer": context.producer,
              "vantage": "independent", "witness_scope": context.witness_scope,
              "contract_sha256": sha256(contract_bytes), "tree_sha256": tree_record["tree_sha256"],
              "results": results}
    data, envelope = sign_record(record, key)
    return Graded(record, data, envelope, isolation, staging)
