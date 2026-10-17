"""Run one acceptance command on one state of a task.

Each run gets a fresh copy of the state at ``<scratch>/workspace`` and, when the task has
held-out files, a copy of them at ``<scratch>/heldout``. Commands run with the workspace as
their working directory, so a held-out file is reached as ``../heldout/<name>``: the same
argv works for :class:`SubprocessRunner` here and for the docker runner in
:mod:`.verify_run`, which mounts the two directories at ``/workspace`` and ``/heldout``.

:class:`SubprocessRunner` isolates nothing beyond a scrubbed environment and a fresh copy.
The contract compiler may use it to measure stability and mutant kills on trusted states
(reference, pre-patch, mutants); grading an agent's tree always uses the docker runner.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence

from ..sensors import treedigest
from . import replay as replay_harness

TIMEOUT_EXIT = 124
SCRUBBED_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp",
    "LANG": "C.UTF-8",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
    "PYTHONHASHSEED": "0",
}


@dataclass(frozen=True)
class Command:
    """One acceptance command: an id, its exact argv, and whether it is held out."""

    id: str
    argv: tuple[str, ...]
    heldout: bool = False
    prepatch: str = "fail"
    ids_from: int | None = None

    def record(self) -> dict:
        return {"id": self.id, "argv": list(self.argv)}


class Runner(Protocol):
    """Run ``argv`` on a copy of ``state`` (and ``heldout``) and return its exit status.

    When ``writes`` is a list, the runner appends every workspace path the run created,
    changed or removed (regular files, compared by digest).
    """

    name: str

    def run(self, state: Path, argv: Sequence[str], heldout: Path | None,
            timeout: float, writes: list[str] | None = None,
            output: list[str] | None = None) -> int: ...


def changed_paths(before: Path, after: Path) -> list[str]:
    """Regular-file paths that differ between two trees, sorted."""
    old, new = treedigest.scan(before).files, treedigest.scan(after).files
    return sorted(name for name in set(old) | set(new) if old.get(name) != new.get(name))


def stage(state: Path, heldout: Path | None, scratch: Path) -> Path:
    """Copy ``state`` (and ``heldout``) under an empty ``scratch``; return the workspace."""
    workspace = scratch / "workspace"
    shutil.copytree(state, workspace, symlinks=True)
    if heldout is not None:
        shutil.copytree(heldout, scratch / "heldout", symlinks=True)
    return workspace


def is_replay(argv: Sequence[str]) -> bool:
    return bool(argv) and argv[0] == replay_harness.COMMAND


def run_replay(scratch: Path, argv: Sequence[str], child_argv, timeout: float,
               order_seed: str, results: list[dict] | None) -> int:
    """Run a parent-compare replay command staged under ``scratch``.

    ``argv`` is ``(COMMAND, <sealed test path from the workspace>, <module>, <entry>)``. Only
    the module's file is copied into the child's directory; ``child_argv(directory, source)``
    returns the child's command line and working directory.
    """
    if len(argv) != 4:
        return 2
    _, test, module, entry = argv
    workspace = scratch / "workspace"
    candidate = scratch / "candidate"
    candidate.mkdir()
    source = workspace / f"{module}.py"
    if source.is_file() and not source.is_symlink():
        shutil.copy2(source, candidate / f"{module}.py")
        os.chmod(candidate / f"{module}.py", 0o644)
    os.chmod(candidate, 0o755)
    os.chmod(scratch, 0o755)
    command, cwd = child_argv(candidate, replay_harness.child_source(module, entry))
    request = {"test": str((workspace / test).resolve()), "child_argv": command,
               "child_cwd": cwd, "call_timeout": min(timeout, 60.0), "order_seed": order_seed,
               "out": str(scratch / "replay.json")}
    (scratch / "request.json").write_text(json.dumps(request))
    try:
        done = subprocess.run([sys.executable, "-I", "-m", "probity_observer.done.replay",
                               str(scratch / "request.json")], stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return TIMEOUT_EXIT
    if results is not None and (scratch / "replay.json").is_file():
        results.append({"argv": list(argv),
                        **json.loads((scratch / "replay.json").read_text())})
    return done.returncode


class SubprocessRunner:
    """A local run with a scrubbed environment; no isolation from the host."""

    name = "subprocess"

    def __init__(self, python: str | None = None, order_seed: str = "subprocess") -> None:
        self.env = dict(SCRUBBED_ENV)
        self.python = python or sys.executable
        self.order_seed = order_seed
        self.replays: list[dict] = []
        if python is not None:
            self.env["PATH"] = f"{Path(python).parent}:{self.env['PATH']}"

    def child_argv(self, directory: Path, source: str) -> tuple[list[str], str]:
        return [self.python, "-I", "-P", "-c", source], str(directory)

    def run(self, state: Path, argv: Sequence[str], heldout: Path | None,
            timeout: float, writes: list[str] | None = None,
            output: list[str] | None = None) -> int:
        with tempfile.TemporaryDirectory(prefix="probity-done-") as scratch:
            workspace = stage(Path(state), heldout, Path(scratch))
            if is_replay(argv):
                return run_replay(Path(scratch), argv, self.child_argv, timeout,
                                  self.order_seed, self.replays)
            try:
                done = subprocess.run(list(argv), cwd=workspace, env=self.env,
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, timeout=timeout,
                                      check=False, start_new_session=True)
                code = done.returncode
                if output is not None:
                    output.append(done.stdout.decode("utf-8", "replace"))
            except subprocess.TimeoutExpired:
                code = TIMEOUT_EXIT
            except OSError:
                code = 127
            if writes is not None:
                writes.extend(changed_paths(Path(state), workspace))
            return code


def chmod_tree(root: Path, mode_dirs: int = 0o777, mode_files: int = 0o666) -> None:
    """Open a scratch copy to an unprivileged worker uid (the copy is thrown away)."""
    for directory, dirnames, filenames in os.walk(root):
        os.chmod(directory, mode_dirs)
        for name in filenames:
            path = Path(directory) / name
            if not path.is_symlink():
                os.chmod(path, mode_files | (os.stat(path).st_mode & 0o111))
