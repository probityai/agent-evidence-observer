"""Reuse a preregistered retained CPU runtime without new model or package transfer.

The archive charge is separate from the immutable original preparation receipts.
All input entries are selected by the prospective protocol before extraction.
This module prepares and installs bytes only; it never performs inference.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import stat
import subprocess
import sys
import time
from typing import Any, BinaryIO
import urllib.request
import zipfile

try:
    from .evidence_io import read_regular, strict_json
except ImportError:
    from evidence_io import read_regular, strict_json

LOGGER = logging.getLogger(__name__)
CHUNK_BYTES = 1024 * 1024


def _refuse(message: str) -> None:
    LOGGER.error(message)
    raise ValueError(message)


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _safe_relative(name: str) -> Path:
    pure = PurePosixPath(name)
    if not name or pure.is_absolute() or any(part in {"", ".", ".."} for part in name.split("/")):
        _refuse("selected path is not a normalized relative path")
    if "\\" in name or ":" in name or "\x00" in name:
        _refuse("selected path contains a forbidden character")
    return Path(*pure.parts)


def file_identity(path: Path) -> dict[str, Any]:
    """Measure a regular file using bounded reads.

    Parameters
    ----------
    path : pathlib.Path
        File whose exact bytes are selected by the protocol. The active host
        controls its ancestor directories. The final member is opened once
        with ``O_NOFOLLOW | O_NONBLOCK`` and checked by descriptor, so final
        link replacement and special files cannot substitute a blocking read.

    Returns
    -------
    dict
        The ``bytes`` count and hexadecimal ``sha256`` digest.

    Raises
    ------
    ValueError
        If the path is a symbolic link or is not a regular file.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _refuse("selected input is not a regular file")
    digest = hashlib.sha256()
    count = 0
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            _refuse("selected input is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(CHUNK_BYTES), b""):
                count += len(chunk)
                digest.update(chunk)
    finally:
        os.close(descriptor)
    return {"bytes": count, "sha256": digest.hexdigest()}


def _verify_file(path: Path, selected: dict[str, Any]) -> dict[str, Any]:
    measured = file_identity(path)
    if measured != {"bytes": selected["bytes"], "sha256": selected["sha256"]}:
        _refuse("selected file bytes or SHA256 mismatch")
    return measured


def _selected(protocol: dict[str, Any]) -> list[dict[str, Any]]:
    rows = protocol["runtimeReuse"]["selectedFiles"]
    paths = [_safe_relative(row["path"]).as_posix() for row in rows]
    for row in rows:
        _safe_relative(row["archivePath"])
    if len(paths) != len(set(paths)):
        _refuse("selected file paths must be unique")
    if any(type(row["bytes"]) is not int or row["bytes"] < 0 for row in rows):
        _refuse("selected file byte counts must be nonnegative integers")
    return rows


def _deadline(start: float, seconds: float) -> None:
    if time.monotonic() - start > seconds:
        _refuse("preparation elapsed time budget exceeded")


def _copy_stream(stream: BinaryIO, target: Path, limit: int, start: float, seconds: float,
                 accounting: dict[str, Any]) -> None:
    digest = hashlib.sha256()
    _deadline(start, seconds)
    with target.open("xb") as destination:
        for chunk in iter(lambda: stream.read(CHUNK_BYTES), b""):
            accounting["responseBodyBytes"] += len(chunk)
            if accounting["responseBodyBytes"] > limit:
                _refuse("archive response body byte budget exceeded")
            _deadline(start, seconds)
            destination.write(chunk)
            digest.update(chunk)
    accounting["sha256"] = digest.hexdigest()


class _CredentialSafeRedirect(urllib.request.HTTPRedirectHandler):
    """Follow the archive redirect without forwarding the GitHub credential."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> Any:
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            redirected.remove_header("Authorization")
        return redirected


def acquire_archive(protocol: dict[str, Any], output: Path, *,
                    local_archive: Path | None = None) -> dict[str, Any]:
    """Verify a local retained archive or transfer exactly one selected archive.

    Parameters
    ----------
    protocol : dict
        Prospective protocol containing ``runtimeReuse.archive`` and ``budgets``.
    output : pathlib.Path
        Fresh directory for the transferred archive and accounting receipt.
    local_archive : pathlib.Path, optional
        Existing archive to verify without copying or charging network bytes.

    Returns
    -------
    dict
        Charge receipt including archive location, exact identity, elapsed time,
        route, original preparation history, and explicit zero provider charges.

    Notes
    -----
    The network route reads GH_TOKEN only for the GitHub API request. Redirected
    storage requests do not receive that header. There are no transfer retries.
    Even failed partial transfers retain their measured accounting receipt.
    """
    output.mkdir(parents=True, exist_ok=True)
    selected = protocol["runtimeReuse"]["archive"]
    start = time.monotonic()
    receipt: dict[str, Any] = {"schema": "probity-runtime-archive-charge-v1", "status": "started",
        "route": "local-verified" if local_archive else "github-artifact-once",
        "responseBodyBytes": 0, "networkAttempts": 0, "providerCalls": 0,
        "providerDollars": 0, "originalPreparation": protocol["runtimeReuse"].get("originalPreparation", {})}
    path = local_archive or output / "selected-runtime.zip"
    try:
        if selected["bytes"] > protocol["budgets"]["archive_download_bytes"]:
            _refuse("selected archive exceeds archive download byte budget")
        if local_archive is None:
            _download(protocol, path, start, receipt)
        receipt["archiveIdentity"] = _verify_file(path, selected)
        _deadline(start, protocol["budgets"]["preparation_seconds"])
        receipt.update(status="passed", archivePath=str(path.resolve()))
        LOGGER.info("selected archive verified; charged response bytes=%s", receipt["responseBodyBytes"])
        return receipt
    except Exception as exc:
        receipt.update(status="failed", error=str(exc))
        raise
    finally:
        receipt["elapsedSeconds"] = time.monotonic() - start
        _write_json(output / "archive-accounting.json", receipt)


def _download(protocol: dict[str, Any], path: Path, start: float, receipt: dict[str, Any]) -> None:
    selected = protocol["runtimeReuse"]["archive"]
    expected_url = f"https://api.github.com/repos/{selected['repository']}/actions/artifacts/{selected['artifactId']}/zip"
    if selected["apiUrl"] != expected_url:
        _refuse("archive API URL does not match the selected artifact")
    token = os.environ.get("GH_TOKEN")
    if not token:
        _refuse("GH_TOKEN is required for selected archive transfer")
    request = urllib.request.Request(expected_url, headers={"Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    receipt["networkAttempts"] = 1
    seconds = protocol["budgets"]["preparation_seconds"]
    _deadline(start, seconds)
    remaining = seconds - (time.monotonic() - start)
    socket_timeout = min(protocol["budgets"]["network_operation_seconds"], remaining)
    with urllib.request.build_opener(_CredentialSafeRedirect()).open(request, timeout=socket_timeout) as response:
        _copy_stream(response, path, protocol["budgets"]["archive_download_bytes"], start, seconds, receipt)


def _extract_one(archive: zipfile.ZipFile, row: dict[str, Any], destination: Path,
                 start: float, seconds: float) -> dict[str, Any]:
    info = archive.getinfo(row["archivePath"])
    mode = info.external_attr >> 16
    kind = stat.S_IFMT(mode)
    if info.is_dir() or kind not in {0, stat.S_IFREG} or info.file_size != row["bytes"]:
        _refuse("selected archive entry is not an exact regular file")
    target = destination / _safe_relative(row["path"])
    target.parent.mkdir(parents=True, exist_ok=True)
    accounting: dict[str, Any] = {"responseBodyBytes": 0}
    with archive.open(info) as stream:
        _copy_stream(stream, target, row["bytes"], start, seconds, accounting)
    identity = _verify_file(target, row)
    return {"archivePath": row["archivePath"], "path": row["path"],
            "category": row["category"], **identity}


def extract_selected(protocol: dict[str, Any], archive_path: Path, output: Path, *,
                     start: float | None = None) -> dict[str, Any]:
    """Extract only preregistered regular entries and return their exact projection.

    Parameters
    ----------
    protocol : dict
        Full prospective protocol. Its fixed selection is the extraction authority.
    archive_path : pathlib.Path
        Archive verified by :func:`acquire_archive`; reverified before extraction.
    output : pathlib.Path
        Fresh extraction directory. Existing outputs are refused.
    start : float, optional
        Shared monotonic preparation start for the combined archive/extraction cap.

    Returns
    -------
    dict
        Exact selected identities and retained byte total, including original
        receipts. No original receipt is rewritten or used as a new network charge.
    """
    selected = _selected(protocol)
    _verify_file(archive_path, protocol["runtimeReuse"]["archive"])
    if output.exists():
        _refuse("extraction output must be a fresh directory")
    total = sum(row["bytes"] for row in selected)
    limit = protocol["budgets"]["retained_disk_bytes"]
    if total + archive_path.stat().st_size > limit:
        _refuse("retained disk byte budget exceeded")
    output.mkdir(parents=True)
    started = time.monotonic() if start is None else start
    with zipfile.ZipFile(archive_path) as archive:
        names = [info.filename for info in archive.infolist()]
        if len(names) != len(set(names)):
            _refuse("archive entry names must be unique")
        projection = [_extract_one(archive, row, output, started,
            protocol["budgets"]["preparation_seconds"]) for row in selected]
    return {"schema": "probity-runtime-reuse-projection-v1", "status": "passed",
            "files": projection, "selectedBytes": total, "streamBoundBytes": CHUNK_BYTES,
            "originalPreparation": protocol["runtimeReuse"].get("originalPreparation", {})}


def prepare_archive(protocol: dict[str, Any], output: Path, *,
                    local_archive: Path | None = None) -> dict[str, Any]:
    """Prepare selected runtime bytes and always retain a terminal receipt.

    The archive verification/download and selected extraction share the 180-second
    budget. Installation is separately charged by :func:`install_runtime`.
    """
    start = time.monotonic()
    terminal: dict[str, Any] = {"schema": "probity-runtime-preparation-terminal-v1", "status": "started"}
    try:
        charge = acquire_archive(protocol, output, local_archive=local_archive)
        projection = extract_selected(protocol, Path(charge["archivePath"]), output / "extraction", start=start)
        _write_json(output / "reuse-projection.json", projection)
        terminal.update(status="passed", selectedBytes=projection["selectedBytes"],
                        responseBodyBytes=charge["responseBodyBytes"])
        return terminal
    except Exception as exc:
        terminal.update(status="failed", error=str(exc))
        raise
    finally:
        terminal["elapsedSeconds"] = time.monotonic() - start
        _write_json(output / "preparation-terminal.json", terminal)


def sanitized_environment() -> dict[str, str]:
    """Return a small subprocess environment without Python/pip injection hooks."""
    result = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "TMPDIR") if key in os.environ}
    result.update(PIP_CONFIG_FILE=os.devnull, PIP_NO_INDEX="1", PIP_DISABLE_PIP_VERSION_CHECK="1",
                  PYTHONDONTWRITEBYTECODE="1")
    return result


def _execute(command: list[str], start: float, seconds: float) -> str:
    remaining = seconds - (time.monotonic() - start)
    if remaining <= 0:
        _refuse("installation elapsed time budget exceeded")
    result = subprocess.run(command, env=sanitized_environment(), capture_output=True,
                            text=True, timeout=remaining, check=False)
    if result.returncode:
        _refuse("isolated installation command failed: " + result.stderr[-3000:])
    return result.stdout


def _check_abi(python: Path, selected: dict[str, str], start: float, seconds: float) -> None:
    script = "import json,platform,sys; o=platform.freedesktop_os_release(); print(json.dumps(dict(system=platform.system(),machine=platform.machine(),implementation=platform.python_implementation(),python=f'{sys.version_info.major}.{sys.version_info.minor}',osReleaseId=o.get('ID'),osReleaseVersion=o.get('VERSION_ID'))))"
    measured = json.loads(_execute([str(python), "-I", "-B", "-c", script], start, seconds))
    if measured != selected:
        _refuse("selected interpreter or host ABI mismatch")


def _runtime_copy(rows: list[dict[str, Any]], extraction: Path, site: Path) -> None:
    for row in rows:
        if row["category"] not in {"runtime", "runtime-metadata"}:
            continue
        source = extraction / row["path"]
        _verify_file(source, row)
        relative = _safe_relative(row["path"]).relative_to("runtime")
        target = site / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        _verify_file(target, row)


def _installation_map(site: Path) -> dict[str, dict[str, Any]]:
    return {path.relative_to(site).as_posix(): file_identity(path)
            for path in sorted(site.rglob("*")) if path.is_file()}


def install_runtime(protocol: dict[str, Any], prepared: Path, environment: Path,
                    receipt_output: Path | None = None) -> dict[str, Any]:
    """Install locked local wheels and reconstruct the selected native package.

    Parameters
    ----------
    protocol : dict
        Prospective protocol including ABI, wheel locks and installation budget.
        ``runtimeReuse.pythonExecutable`` optionally selects the base interpreter.
    prepared : pathlib.Path
        Successful :func:`prepare_archive` output directory.
    environment : pathlib.Path
        Fresh virtual environment path. Existing paths are refused.
    receipt_output : pathlib.Path, optional
        Installation receipt path; defaults to ``prepared/installation.json``.

    Returns
    -------
    dict
        Exact installed file identities, timings and commands. The native package
        is copied from verified retained source/library bytes, never rebuilt.

    Notes
    -----
    Every interpreter uses ``-I -B`` so import probes cannot create new caches.
    pip uses ``--no-index --no-deps --require-hashes`` and an isolated interpreter.
    Failure receipts remain available and no source receipt is deleted.
    """
    start = time.monotonic()
    receipt: dict[str, Any] = {"schema": "probity-runtime-installation-v1", "status": "started",
                              "networkResponseBytes": 0, "nativeBuilds": 0}
    destination = receipt_output or prepared / "installation.json"
    try:
        _install(protocol, prepared, environment, start, receipt)
        receipt["status"] = "passed"
        LOGGER.info("isolated retained runtime installation passed")
        return receipt
    except Exception as exc:
        receipt.update(status="failed", error=str(exc))
        raise
    finally:
        receipt["elapsedSeconds"] = time.monotonic() - start
        _write_json(destination, receipt)


def _install(protocol: dict[str, Any], prepared: Path, environment: Path,
             start: float, receipt: dict[str, Any]) -> None:
    if environment.exists():
        _refuse("installation environment must be a fresh directory")
    selected = protocol["runtimeReuse"]
    seconds = protocol["budgets"]["installation_seconds"]
    python = Path(selected.get("pythonExecutable", sys.executable)).resolve()
    _check_abi(python, selected["abi"], start, seconds)
    rows = _selected(protocol)
    extraction = prepared / "extraction"
    for row in rows:
        _verify_file(extraction / row["path"], row)
    _execute([str(python), "-I", "-B", "-m", "venv", str(environment.resolve())], start, seconds)
    interpreter = environment.resolve() / "bin/python"
    requirements = prepared / "locked-runtime-requirements.txt"
    requirements.write_text("".join(f"{wheel['name']}=={wheel['version']} --hash=sha256:{wheel['sha256']}\n"
                                    for wheel in selected["wheels"]), encoding="utf-8")
    command = [str(interpreter), "-I", "-B", "-m", "pip", "install", "--no-index", "--no-deps",
        "--require-hashes", "--no-cache-dir", "--no-compile", "--find-links",
        str((extraction / "downloads").resolve()), "-r", str(requirements.resolve())]
    receipt["pipStdout"] = _execute(command, start, seconds)
    site = Path(_execute([str(interpreter), "-I", "-B", "-c",
        "import sysconfig; print(sysconfig.get_path('purelib'))"], start, seconds).strip())
    _runtime_copy(rows, extraction, site)
    receipt["importProbe"] = _execute([str(interpreter), "-I", "-B", "-c",
        "import importlib.metadata,llama_cpp; print(importlib.metadata.version('llama_cpp_python'))"], start, seconds).strip()
    receipt["installedFiles"] = _installation_map(site)
    receipt["installedBytes"] = sum(row["bytes"] for row in receipt["installedFiles"].values())
    receipt["interpreter"] = str(interpreter)
    receipt["sitePackages"] = str(site)
    receipt["abi"] = selected["abi"]
    receipt["command"] = command
    retained_paths = {path.resolve(): path.stat().st_size for root in (prepared, environment)
                      for path in root.rglob("*") if path.is_file()}
    archive_receipt = _read_receipt(prepared / "archive-accounting.json")
    archive_path = Path(archive_receipt["archivePath"]).resolve()
    retained_paths[archive_path] = archive_path.stat().st_size
    retained = sum(retained_paths.values())
    if retained > protocol["budgets"]["retained_disk_bytes"]:
        _refuse("retained disk byte budget exceeded")
    receipt["retainedBytes"] = retained
    if time.monotonic() - start > seconds:
        _refuse("installation elapsed time budget exceeded")


def verify_reuse(packet_root: Path, protocol: dict[str, Any]) -> dict[str, Any]:
    """Verify retained reuse projections without installing or executing code.

    Parameters
    ----------
    packet_root : pathlib.Path
        Native packet whose ``sources/reuse`` directory contains preparation and
        installation receipts and whose ``sources/llama`` holds native originals.
    protocol : dict
        Prospectively selected runtime identities.

    Returns
    -------
    dict
        Checked selected/runtime counts and new archive charge. This receipt is
        evidence of byte custody only, never inference quality or adoption.
    """
    reuse = packet_root / "sources/reuse"
    projection = _read_receipt(reuse / "reuse-projection.json")
    expected = [{key: row[key] for key in ("archivePath", "path", "category", "bytes", "sha256")}
                for row in _selected(protocol)]
    if projection.get("files") != expected or projection.get("status") != "passed":
        _refuse("retained runtime projection differs from selected identities")
    charge = _read_receipt(reuse / "archive-accounting.json")
    _validate_charge(protocol, charge)
    install = _read_receipt(reuse / "installation.json")
    _validate_installation(protocol, install)
    _verify_terminal(protocol, reuse, charge)
    checked = _verify_native_projection(packet_root, protocol, install)
    return {"status": "passed", "selectedFiles": len(expected), "nativeFiles": checked,
            "newArchiveResponseBodyBytes": charge["responseBodyBytes"], "inferencePerformed": False}


def _read_receipt(path: Path) -> dict[str, Any]:
    """Read one bounded regular receipt using frozen strict JSON semantics."""
    value = strict_json(read_regular(path))
    if not isinstance(value, dict):
        _refuse("retained runtime receipt must be a JSON object")
    return value


def _finite_within(value: Any, maximum: int | float) -> bool:
    return type(value) in {int, float} and 0 <= value <= maximum and math.isfinite(value)


def _integer_within(value: Any, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _verify_terminal(protocol: dict[str, Any], reuse: Path, charge: dict[str, Any]) -> None:
    terminal = _read_receipt(reuse / "preparation-terminal.json")
    if terminal.get("status") != "passed" or not _finite_within(terminal.get("elapsedSeconds"), protocol["budgets"]["preparation_seconds"]):
        _refuse("retained preparation receipt exceeds its budget or failed")
    if terminal.get("responseBodyBytes") != charge["responseBodyBytes"] or type(terminal.get("responseBodyBytes")) is not int:
        _refuse("retained preparation charge differs from archive accounting")
    if terminal.get("selectedBytes") != sum(row["bytes"] for row in _selected(protocol)):
        _refuse("retained preparation selected byte count differs from selection")


def _validate_installation(protocol: dict[str, Any], install: dict[str, Any]) -> None:
    offline = _integer_within(install.get("nativeBuilds"), 0) and _integer_within(install.get("networkResponseBytes"), 0)
    if install.get("status") != "passed" or not offline:
        _refuse("retained installation receipt is not a passed offline reuse")
    if not _finite_within(install.get("elapsedSeconds"), protocol["budgets"]["installation_seconds"]):
        _refuse("retained installation duration exceeds its budget or is invalid")
    _validate_installation_bytes(protocol, install)
    if install.get("abi") != protocol["runtimeReuse"]["abi"] or install.get("importProbe") != "0.3.16":
        _refuse("retained installation ABI or import probe differs from selection")


def _validate_installation_bytes(protocol: dict[str, Any], install: dict[str, Any]) -> None:
    retained = install.get("retainedBytes")
    if not _integer_within(retained, protocol["budgets"]["retained_disk_bytes"]):
        _refuse("retained installation disk byte count exceeds its budget or is invalid")
    if not _integer_within(install.get("installedBytes"), retained):
        _refuse("retained installed byte count exceeds retained bytes or is invalid")
    files = install.get("installedFiles")
    if not isinstance(files, dict):
        _refuse("retained installation file identities must be an object")
    _validate_installed_file_total(files, install["installedBytes"])


def _validate_installed_file_total(files: dict[str, Any], expected: int) -> None:
    measured = 0
    for row in files.values():
        if not isinstance(row, dict) or not _integer_within(row.get("bytes"), expected):
            _refuse("retained installation file byte count is invalid")
        measured += row["bytes"]
    if measured != expected:
        _refuse("retained installed bytes differ from installation file identities")


def _verify_native_projection(packet_root: Path, protocol: dict[str, Any], install: dict[str, Any]) -> int:
    count = 0
    for row in _selected(protocol):
        if row["category"] in {"runtime", "runtime-metadata"}:
            _verify_copied_runtime(packet_root, row, install)
            count += 1
        elif row["category"] == "receipt":
            _verify_original_receipt(packet_root, row)
    return count


def _verify_original_receipt(packet_root: Path, row: dict[str, Any]) -> None:
    original = packet_root / "sources/reuse" / row["path"]
    _verify_file(original, row)
    if original.suffix == ".json":
        _read_receipt(original)


def _verify_copied_runtime(packet_root: Path, row: dict[str, Any], install: dict[str, Any]) -> None:
    relative = _safe_relative(row["path"]).relative_to("runtime")
    if row["category"] == "runtime":
        packet_relative = Path("sources/llama") / relative.relative_to("llama_cpp")
    else:
        packet_relative = Path("sources/llama-cpp-python") / _safe_relative(row["archivePath"]).name
    _verify_file(packet_root / packet_relative, row)
    if install["installedFiles"].get(relative.as_posix()) != {"bytes": row["bytes"], "sha256": row["sha256"]}:
        _refuse("retained installation native identities differ from selection")


def _validate_charge(protocol: dict[str, Any], charge: dict[str, Any]) -> None:
    selected = protocol["runtimeReuse"]["archive"]
    _validate_charge_bounds(protocol, charge)
    if charge.get("status") != "passed" or charge.get("archiveIdentity") != {"bytes": selected["bytes"], "sha256": selected["sha256"]}:
        _refuse("retained archive charge identity mismatch")
    expected = {"local-verified": (0, 0), "github-artifact-once": (selected["bytes"], 1)}
    actual = (charge.get("responseBodyBytes"), charge.get("networkAttempts"))
    if expected.get(charge.get("route")) != actual:
        _refuse("retained archive response charge does not match its route")
    if charge.get("originalPreparation") != protocol["runtimeReuse"].get("originalPreparation", {}):
        _refuse("retained original preparation history differs from selection")
    if not _integer_within(charge.get("providerCalls"), 0) or not _finite_within(charge.get("providerDollars"), 0):
        _refuse("retained archive charge contains unexpected provider use")


def _validate_charge_bounds(protocol: dict[str, Any], charge: dict[str, Any]) -> None:
    if not _finite_within(charge.get("elapsedSeconds"), protocol["budgets"]["preparation_seconds"]):
        _refuse("retained archive duration exceeds its budget or is invalid")
    if not _integer_within(charge.get("responseBodyBytes"), protocol["budgets"]["archive_download_bytes"]):
        _refuse("retained archive response byte count exceeds its budget or is invalid")
    if not _integer_within(charge.get("networkAttempts"), 1):
        _refuse("retained archive network attempt count is invalid")


prepare_runtime = prepare_archive


def main() -> None:
    """Run the explicit preparation CLI, with installation optional."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--environment", type=Path)
    args = parser.parse_args()
    protocol = _read_receipt(args.protocol)
    prepare_archive(protocol, args.workdir, local_archive=args.archive)
    if args.environment:
        install_runtime(protocol, args.workdir, args.environment)


if __name__ == "__main__":
    main()
