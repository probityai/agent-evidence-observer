"""Host-selected byte boundaries checked before any candidate child starts.

This module uses only the Python standard library. Selection occurs in the
host-owned :mod:`prepare_host` step; :func:`validate_host` refuses a substituted
manifest, policy, key, installed file, executable, or pinned source before
:mod:`run_host` launches a byte gate, reader, OPA, or protected HTTP target.
The trusted host filesystem must remain outside candidate write authority.
Hashes detect changes; they do not sandbox an attacker sharing that filesystem.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
from pathlib import Path
from typing import Any, NoReturn

LOGGER = logging.getLogger("probity.eight_component.trust")
SOURCE_SHA256 = "1107cb0621b8b9227d5e7e8615c24bd1a2cee0ecb4cb1e7a15a1e3dd839540d6"
HOST_SCHEMA = "probity-eight-component-host-selection-v1"
OPA_SHA256 = "65d700b14b99b354982b61031b40bdc8e316ea93dadd61818f066d1d9a69dcce"
PROGRAMS = ("trust.py", "native_gate.py", "target_worker.py", "run_host.py")
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TREE_ENTRIES = 100_000
MAX_TREE_DEPTH = 64
MAX_TREE_BYTES = 1024 * 1024 * 1024


class HostRefusal(RuntimeError):
    """A selected boundary failed; no later gate or dispatch is authorized."""


def refuse(reason: str) -> NoReturn:
    """Log and raise an exact bounded reason without candidate or key contents.

    Parameters
    ----------
    reason : str
        Host-authored failure category, never raw candidate-controlled output.

    Raises
    ------
    HostRefusal
        Always, carrying the same reason emitted to the logger.
    """
    LOGGER.warning("eight-component host refused: %s", reason)
    raise HostRefusal(reason)


def sha256(raw: bytes) -> str:
    """Return the lowercase SHA-256 of exact bytes, without JSON rewriting."""
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate host-selection members before the JSON value is lossy."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            refuse("selected JSON has duplicate members")
        result[key] = value
    return result


def read_json(path: Path) -> dict[str, Any]:
    """Read a finite UTF-8 JSON object with duplicate and nonfinite refusal.

    Parameters
    ----------
    path : Path
        A host-selected manifest or a retained child report. This parser does
        not choose a key, policy, executable, or trust root from its contents.

    Returns
    -------
    dict[str, Any]
        Parsed object. Raw candidate AEE is admitted by Rust before parsing.

    Raises
    ------
    HostRefusal
        If bytes are oversized, malformed, nonfinite, or not an object.
    """
    raw = read_regular(path, "selected JSON is not a readable regular file", limit=16 * 1024 * 1024)
    try:
        result = json.loads(raw, object_pairs_hook=unique_object,
                            parse_constant=lambda _: refuse("selected JSON is nonfinite"))
    except (ValueError, UnicodeError):
        refuse("selected JSON is malformed")
    if not isinstance(result, dict):
        refuse("selected JSON is not an object")
    return result


def write_json(path: Path, value: Any) -> None:
    """Create a new retained JSON artifact; never overwrite an existing record."""
    with path.open("xb") as output:
        output.write((json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def file_binding(path: Path) -> dict[str, Any]:
    """Snapshot a host-selected file's resolved path, byte length, and digest."""
    selected = path.resolve(strict=True)
    raw = read_regular(selected, "selected file is not a readable regular file")
    return {"path": str(selected), "sha256": sha256(raw), "bytes": len(raw)}


def read_regular(path: Path, reason: str, *, limit: int = MAX_FILE_BYTES) -> bytes:
    """Read a bounded real file without blocking on a FIFO or following a link.

    Parameters
    ----------
    path : Path
        Canonical absolute host selection. Intentional interpreter invocation
        links are resolved separately by :func:`check_file`, never here.
    reason : str
        Fixed logged refusal category for this boundary.
    limit : int, default=MAX_FILE_BYTES
        Maximum accepted file size and read size. A stat check precedes reading
        and the read remains bounded if the selected file grows afterwards.

    Returns
    -------
    bytes
        Exact bytes read from a verified regular-file descriptor.

    Raises
    ------
    HostRefusal
        For relative or redirected paths, special files, failed opens/stat/read,
        oversize inputs, or files changing size while read. The trusted host must
        still protect selected paths throughout execution; this is no sandbox.
    """
    try:
        if not path.is_absolute() or path.resolve(strict=True) != path:
            refuse(reason)
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                refuse(reason)
            raw = source.read(info.st_size + 1)
    except (OSError, RuntimeError, ValueError):
        refuse(reason)
    if len(raw) > limit or len(raw) != info.st_size:
        refuse(reason)
    return raw


def check_file(binding: dict[str, Any], reason: str) -> Path:
    """Require the selected real file's exact bytes and reject path redirection.

    Parameters
    ----------
    binding : dict[str, Any]
        External ``path``, ``sha256`` and ``bytes`` selection. Relative paths,
        symlink redirection and changed byte length are refused.
    reason : str
        Fixed refusal reason identifying the boundary rather than file data.

    Returns
    -------
    Path
        The authenticated absolute file path.
    """
    try:
        path = Path(binding["path"])
        valid = path.is_absolute() and path.resolve(strict=True) == path
        invocation = Path(binding.get("invocationPath", path))
        valid = valid and invocation.resolve(strict=True) == path
        raw = read_regular(path, reason)
    except (KeyError, TypeError, ValueError, OSError):
        refuse(reason)
    if not valid or len(raw) != binding["bytes"] or sha256(raw) != binding["sha256"]:
        refuse(reason)
    return path


def check_source_file(root: Path, name: str, expected: str) -> None:
    """Compare one frozen tracked-file commitment without executing Git."""
    path = root / name
    try:
        valid = sha256(read_regular(path, "pinned component source bytes differ")) == expected
    except OSError:
        valid = False
    if not valid:
        refuse("pinned component source bytes differ")


def validate_sources(profile: Path, sources: Path) -> dict[str, Any]:
    """Authenticate every tracked file at the original eight source selections.

    Parameters
    ----------
    profile : Path
        Trusted kit source directory containing the original public selection.
    sources : Path
        Host-owned source materializations with one directory per component.

    Returns
    -------
    dict[str, Any]
        The original selection, authenticated against :data:`SOURCE_SHA256`.

    Notes
    -----
    All eight original heads and tracked-file hashes remain unchanged. Wheel
    build scratch and Git metadata are not treated as executable selection.
    The installation manifest separately authenticates installed file closure.
    """
    raw = read_regular(profile / "SOURCE-SELECTION.json", "original component source selection differs")
    if sha256(raw) != SOURCE_SHA256:
        refuse("original component source selection differs")
    selection = read_json(profile / "SOURCE-SELECTION.json")
    for name, component in selection["components"].items():
        root = sources.resolve(strict=True) / name
        if source_file_names(root) != set(component["files"]):
            refuse("pinned component source file closure differs")
        for file_name, digest in component["files"].items():
            check_source_file(root, file_name, digest)
    return selection


def source_file_names(root: Path) -> set[str]:
    """Close every materialized source file outside Git's inert metadata.

    Added importable modules, startup hooks, bytecode, data files and symlink
    directories are refused. Setup creates a fresh exact tracked-file snapshot;
    runtime children use ``-B`` and never create source bytecode caches.
    """
    return regular_file_names(root, "pinned component source", ignore_git=True)


def classify_entry(entry: os.DirEntry[str], boundary: str) -> tuple[bool, int]:
    """Return directory status and regular-file bytes of a checked entry.

    Symbolic links and special files are rejected before descent or content
    reads. Every enumeration/stat error is translated by
    :func:`regular_file_names` into a logged refusal rather than omitted.
    """
    info = entry.stat(follow_symlinks=False)
    mode = info.st_mode
    if stat.S_ISLNK(mode):
        refuse(boundary + " directory redirects")
    if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
        refuse(boundary + " contains a nonregular file")
    directory = stat.S_ISDIR(mode)
    if not directory and info.st_size > MAX_FILE_BYTES:
        refuse(boundary + " file exceeds byte budget")
    return directory, 0 if directory else info.st_size


def check_tree_root(root: Path, boundary: str) -> None:
    """Require a canonical directory, refusing missing or redirected roots."""
    try:
        valid = root.is_absolute() and root.resolve(strict=True) == root
        valid = valid and stat.S_ISDIR(root.lstat().st_mode)
    except (OSError, RuntimeError, ValueError):
        refuse(boundary + " enumeration failed")
    if not valid:
        refuse(boundary + " root redirects")


def regular_file_names(root: Path, boundary: str, *, ignore_git: bool = False) -> set[str]:
    """Enumerate a finite exact regular-file closure and fail on unreadable trees.

    Parameters
    ----------
    root : Path
        Canonical absolute directory protected by the host.
    boundary : str
        Fixed host-authored prefix used in refusal messages.
    ignore_git : bool, default=False
        Ignore only a real root-level ``.git`` directory. Nested directories
        named ``.git`` remain selected closure entries and cannot hide extras.

    Returns
    -------
    set[str]
        Relative regular-file names. Empty directories count against the entry
        and depth limits, preventing unbounded trees without selected files.

    Notes
    -----
    Unlike ``os.walk``'s default behavior, inaccessible descendants or iteration
    errors never silently disappear. Symlinks, sockets, devices and FIFOs are
    refused. At most :data:`MAX_TREE_ENTRIES` entries and
    :data:`MAX_TREE_DEPTH` levels are traversed without recursive Python calls.
    Regular files are bounded individually by :data:`MAX_FILE_BYTES` and in
    aggregate by :data:`MAX_TREE_BYTES` before content authentication begins.
    """
    check_tree_root(root, boundary)
    result: set[str] = set()
    pending = [(root, 0)]
    count = 0
    byte_count = 0
    while pending:
        folder, depth = pending.pop()
        check_tree_budget(count, depth, byte_count, boundary)
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    count += 1
                    directory, size = classify_entry(entry, boundary)
                    byte_count += size
                    check_tree_budget(count, depth, byte_count, boundary)
                    append_tree_entry(entry, directory, root, depth, pending, result, ignore_git)
        except OSError:
            refuse(boundary + " enumeration failed")
    return result


def check_tree_budget(count: int, depth: int, byte_count: int, boundary: str) -> None:
    """Refuse excessive tree work before retaining more names or descending."""
    if depth > MAX_TREE_DEPTH:
        refuse(boundary + " depth exceeds budget")
    if count > MAX_TREE_ENTRIES:
        refuse(boundary + " entries exceed budget")
    if byte_count > MAX_TREE_BYTES:
        refuse(boundary + " total bytes exceed budget")


def append_tree_entry(entry: os.DirEntry[str], directory: bool, root: Path, depth: int,
                      pending: list[tuple[Path, int]], result: set[str], ignore_git: bool) -> None:
    """Record one checked file or queue one checked directory for enumeration."""
    path = Path(entry.path)
    if directory:
        if not (ignore_git and path == root / ".git"):
            pending.append((path, depth + 1))
    else:
        result.add(str(path.relative_to(root)))


def installation_file_names(root: Path) -> set[str]:
    """Close installed files and reject directories redirecting outside them.

    An added directory symlink can expose new importable modules even when a
    recursive file-only listing omits it. Selection refuses these redirects
    before any Python child can process startup hooks or import dependencies.
    """
    return regular_file_names(root, "installed package")


def check_installation_closure(manifest: dict[str, Any]) -> None:
    """Authenticate installed code and refuse added importable package files.

    The host snapshot includes every site-packages file, including dependencies,
    dist-info, startup hooks and existing bytecode. Runtime children use ``-B``.
    Added startup/import code is refused even if all old hashes still match.
    """
    for closure in manifest["packageClosures"]:
        root = Path(closure["root"])
        actual = installation_file_names(root)
        if actual != set(closure["files"]):
            refuse("installed package file closure differs")
    for binding in manifest["installedFiles"]:
        check_file(binding, "installed package bytes differ")


def check_policy_roles(manifest: dict[str, Any]) -> None:
    """Enforce the separately pinned OPA asset and distinct authority key roles."""
    if manifest["tools"]["opa"]["sha256"] != OPA_SHA256:
        refuse("OPA official release selection differs")
    policy = read_json(Path(manifest["policy"]["path"]))
    public_keys = policy["publicKeys"]
    if len(set(public_keys.values())) != len(public_keys):
        refuse("host signer authority and effect keys must differ")


def validate_host(manifest_path: Path, manifest_sha256: str) -> dict[str, Any]:
    """Validate host selections before any component or target child starts.

    Parameters
    ----------
    manifest_path : Path
        Host-owned installation/policy/key/source selection. Its expected hash
        must be supplied separately by the relying party, never by a candidate.
    manifest_sha256 : str
        Explicit external SHA-256 selection for the complete manifest bytes.

    Returns
    -------
    dict[str, Any]
        Authenticated immutable-on-disk host configuration for this run.

    Raises
    ------
    HostRefusal
        If any trust boundary differs. :mod:`run_host` records zero dispatches
        and never launches a candidate child in this case.

    Notes
    -----
    The external host must protect these paths throughout execution. Same-host
    byte checks are neither independent custody nor a substitute for isolation.
    """
    if sha256(read_regular(manifest_path, "external host manifest digest differs")) != manifest_sha256:
        refuse("external host manifest digest differs")
    manifest = read_json(manifest_path)
    if manifest["schema"] != HOST_SCHEMA:
        refuse("host manifest schema differs")
    selection = validate_sources(Path(manifest["profile"]), Path(manifest["sources"]))
    heads = {name: item["head"] for name, item in selection["components"].items()}
    if manifest["componentHeads"] != heads or manifest["sourceSelectionSha256"] != SOURCE_SHA256:
        refuse("declared component selection differs from original source pins")
    for binding in manifest["selectedFiles"]:
        check_file(binding, "host-selected executable policy or key bytes differ")
    check_installation_closure(manifest)
    check_policy_roles(manifest)
    return manifest
