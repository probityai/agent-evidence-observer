"""Transfer a source-pinned Actions ZIP without running any of its contents.

The original archive remains immutable. :func:`prepare` verifies its provider
metadata, downloads the exact bytes, reads and hashes every ZIP member, then
uses :func:`split_archive` to create independently transportable byte ranges.
The original archive can be recovered by concatenating those ranges in order.
All network authentication is confined to the GitHub API request; the signed
blob request receives no GitHub authorization header.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import stat
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

LOGGER = logging.getLogger(__name__)
REPOSITORY = "probityai/agent-evidence-observer"
RUN_ID = 37116827382
ARTIFACT_ID = 11272310915
SOURCE_HEAD = "51e0c12551339cce5898d3bfae2ba9ef3d9607f5"
EXPECTED_BYTES = 1051848146
EXPECTED_SHA256 = "9ae6d49f3445510ea3b094f6070271898bdc25f02cab405e54ac6825b5137076"
EXPECTED_MEMBERS = 14283
EXPECTED_UNCOMPRESSED_BYTES = 1271176874
PART_BYTES = 28 * 1024 * 1024
MAX_PARTS = 40
READ_BYTES = 1024 * 1024
ORIGINAL_NAME = f"tool-argument-cpu-preparation-{SOURCE_HEAD}.zip"
SELECTED_MEMBERS = {
    "tool-argument-preparation/run/report.json": (
        81221,
        "92b0a21e5fe5efc682e7b6c287a850e28847f33b4515b1a02155ad706bb673ba",
    ),
    "tool-argument-preparation/run/protocol.json": (
        76540,
        "f62ded1a32862839da80a80f8e871ef6cda4acc8c30363367cccf6bec9e92c97",
    ),
    "tool-argument-preparation/run/manifest.json": (
        46022,
        "f3d4a12d57e7ce1a20b0143e8adcf509582f1b9ab035374df1853282a6ce232d",
    ),
}


def require(condition: bool, message: str) -> None:
    """Reject an unmet custody condition with a stable logged error.

    Parameters
    ----------
    condition : bool
        Whether the custody requirement is satisfied.
    message : str
        Public, secret-free diagnostic emitted to the logger and exception.

    Raises
    ------
    ValueError
        If ``condition`` is false. No signed download URL or token is included.
    """
    if not condition:
        LOGGER.error(message)
        raise ValueError(message)


def write_json(path: Path, value: Any) -> None:
    """Create a UTF-8 JSON receipt without overwriting an earlier receipt.

    Parameters
    ----------
    path : pathlib.Path
        New receipt location, with an existing parent directory.
    value : Any
        JSON-serializable custody data; credentials must never be supplied.
    """
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, ensure_ascii=True)
        output.write("\n")


def copy_and_hash(source: BinaryIO, target: BinaryIO, expected_bytes: int) -> str:
    """Copy a bounded stream and return its complete SHA-256 digest.

    Parameters
    ----------
    source : BinaryIO
        Stream positioned at the first byte. Short reads are supported.
    target : BinaryIO
        Destination for exact source bytes, with no decoding or normalization.
    expected_bytes : int
        Exact required length. Oversized streams stop before excess bytes are
        written; undersized streams fail at EOF.

    Returns
    -------
    str
        Lowercase hexadecimal SHA-256 digest of every accepted byte.

    Raises
    ------
    ValueError
        If the expected length is negative or the stream length differs.
    """
    require(expected_bytes >= 0, "Expected byte length must be nonnegative.")
    digest = hashlib.sha256()
    total = 0
    while chunk := source.read(READ_BYTES):
        total += len(chunk)
        require(total <= expected_bytes, "Stream exceeds its expected byte length.")
        target.write(chunk)
        digest.update(chunk)
    require(total == expected_bytes, "Stream is shorter than its expected byte length.")
    return digest.hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep authenticated API redirects observable without forwarding headers."""

    def redirect_request(self, request: Any, response: Any, code: int,
                         message: str, headers: Any, new_url: str) -> None:
        """Refuse redirect following so callers can start a fresh request.

        Parameters
        ----------
        request, response, code, message, headers, new_url
            Standard :class:`urllib.request.HTTPRedirectHandler` arguments.
            Their values are neither logged nor retained.

        Returns
        -------
        None
            Causes ``urllib`` to expose the redirect as an HTTP error. The
            caller can inspect its Location privately and omit authorization.
        """
        return None


def api_request(path: str, token: str) -> urllib.request.Request:
    """Build a request whose authentication is confined to ``api.github.com``.

    Parameters
    ----------
    path : str
        Relative repository API path beginning with ``/``.
    token : str
        Ephemeral Actions token; never stored in a custody receipt.

    Returns
    -------
    urllib.request.Request
        Authenticated HTTPS request with explicit API version.
    """
    require(path.startswith("/") and "://" not in path,
            "API path must be relative to the selected repository.")
    return urllib.request.Request(
        f"https://api.github.com/repos/{REPOSITORY}{path}",
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": "probity-source-pinned-archive-retention"},
    )


def get_json(path: str, token: str) -> dict[str, Any]:
    """Fetch bounded API metadata with no automatic authenticated redirect.

    Parameters
    ----------
    path : str
        Selected repository API subresource; see :func:`api_request`.
    token : str
        Ephemeral token used only for the initial API host.

    Returns
    -------
    dict[str, Any]
        Decoded API object, limited to four MiB.

    Raises
    ------
    ValueError
        If the response exceeds the metadata bound or is not an object.
    """
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(api_request(path, token), timeout=60) as response:
        raw = response.read(4 * READ_BYTES + 1)
    require(len(raw) <= 4 * READ_BYTES, "API metadata exceeds the permitted size.")
    value = json.loads(raw)
    require(isinstance(value, dict), "API metadata must be a JSON object.")
    return value


def validate_metadata(artifact: dict[str, Any], run: dict[str, Any]) -> None:
    """Require the original artifact's exact provider identity and byte pins.

    Parameters
    ----------
    artifact : dict[str, Any]
        Native metadata for the selected artifact ID.
    run : dict[str, Any]
        Native metadata for its owning workflow run.

    Raises
    ------
    ValueError
        If ownership, source, size, digest or live retention differs.
    """
    owner = artifact.get("workflow_run", {})
    require(artifact.get("id") == ARTIFACT_ID, "Original artifact ID differs.")
    require(owner.get("id") == RUN_ID and run.get("id") == RUN_ID,
            "Original artifact owning run differs.")
    require(owner.get("head_sha") == SOURCE_HEAD and run.get("head_sha") == SOURCE_HEAD,
            "Original artifact source head differs.")
    require(run.get("repository", {}).get("full_name") == REPOSITORY,
            "Original artifact repository differs.")
    require(artifact.get("size_in_bytes") == EXPECTED_BYTES,
            "Original artifact provider length differs.")
    require(artifact.get("digest") == f"sha256:{EXPECTED_SHA256}",
            "Original artifact provider digest differs.")
    require(artifact.get("expired") is False, "Original artifact has expired.")
    expiry = datetime.fromisoformat(artifact["expires_at"].replace("Z", "+00:00"))
    require(expiry > datetime.now(timezone.utc), "Original artifact retention has ended.")


def download_location(token: str) -> str:
    """Resolve a provider-issued signed URL without exposing authentication.

    Parameters
    ----------
    token : str
        Ephemeral Actions token confined to the GitHub API request.

    Returns
    -------
    str
        HTTPS signed URL held only in memory until the download completes.

    Raises
    ------
    ValueError
        If the provider fails to supply a valid HTTPS redirect.
    """
    opener = urllib.request.build_opener(NoRedirect())
    try:
        opener.open(api_request(f"/actions/artifacts/{ARTIFACT_ID}/zip", token), timeout=60)
    except urllib.error.HTTPError as error:
        require(error.code in (301, 302, 303, 307, 308), "Artifact API did not redirect.")
        location = error.headers.get("Location", "")
        parsed = urllib.parse.urlparse(location)
        require(parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username,
                "Artifact download location is invalid.")
        return location
    raise ValueError("Artifact API did not supply a download redirect.")


def download_original(output: Path, token: str) -> None:
    """Retrieve and verify the exact original ZIP before publishing its path.

    Parameters
    ----------
    output : pathlib.Path
        New original ZIP path. A partial path is retained on failure.
    token : str
        Ephemeral API credential, omitted from the blob request.

    Raises
    ------
    ValueError
        If source bytes differ from the recorded archive length or digest.
    """
    request = urllib.request.Request(download_location(token), headers={
        "User-Agent": "probity-source-pinned-archive-retention"})
    opener = urllib.request.build_opener(NoRedirect())
    partial = output.with_suffix(".partial")
    require(not output.exists(), "Original ZIP output already exists.")
    with opener.open(request, timeout=120) as source, partial.open("xb") as target:
        digest = copy_and_hash(source, target, EXPECTED_BYTES)
    require(digest == EXPECTED_SHA256, "Original ZIP byte digest differs.")
    partial.rename(output)


def validate_member(info: zipfile.ZipInfo, names: set[str]) -> None:
    """Reject ambiguous or unsafe ZIP member names and filesystem types.

    Parameters
    ----------
    info : zipfile.ZipInfo
        Central-directory entry to inspect without extraction.
    names : set[str]
        Previously admitted raw names; the admitted name is added on success.

    Raises
    ------
    ValueError
        For duplicate names, traversal, absolute paths, backslashes, excessive
        depth, encryption or entries representing links or special files.
    """
    path = PurePosixPath(info.filename)
    require(info.filename not in names, "ZIP member names are duplicated.")
    require(bool(path.parts) and not path.is_absolute() and ".." not in path.parts,
            "ZIP member path is unsafe.")
    require("\\" not in info.filename and ":" not in info.filename and len(path.parts) <= 64,
            "ZIP member path is ambiguous or too deep.")
    require(stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG, stat.S_IFDIR),
            "ZIP member filesystem type is unsupported.")
    require(not info.flag_bits & 1, "Encrypted ZIP members are unsupported.")
    names.add(info.filename)


def hash_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    """Read every uncompressed member byte and verify its declared length.

    Parameters
    ----------
    archive : zipfile.ZipFile
        Original open ZIP; no files are extracted or executed.
    info : zipfile.ZipInfo
        Admitted central-directory entry.

    Returns
    -------
    str
        SHA-256 digest of the complete uncompressed member. ``zipfile`` also
        checks the CRC when the stream reaches EOF.
    """
    digest = hashlib.sha256()
    total = 0
    with archive.open(info) as source:
        while chunk := source.read(READ_BYTES):
            total += len(chunk)
            require(total <= info.file_size, "ZIP member exceeds its declared length.")
            digest.update(chunk)
    require(total == info.file_size, "ZIP member is shorter than its declared length.")
    return digest.hexdigest()


def verify_zip(original: Path, metadata_directory: Path) -> dict[str, Any]:
    """Verify the known member population and retain complete member digests.

    Parameters
    ----------
    original : pathlib.Path
        Exact original archive previously verified by :func:`download_original`
        or the calling workspace's whole-archive verification.
    metadata_directory : pathlib.Path
        Existing directory for the new per-member receipt and three selected
        original JSON files. Archive-provided paths are never extracted.

    Returns
    -------
    dict[str, Any]
        Complete member-readback receipt, including original byte pins.
    """
    rows: list[dict[str, Any]] = []
    with zipfile.ZipFile(original) as archive:
        infos = archive.infolist()
        require(len(infos) == EXPECTED_MEMBERS, "Original ZIP member count differs.")
        require(sum(info.file_size for info in infos) == EXPECTED_UNCOMPRESSED_BYTES,
                "Original ZIP uncompressed total differs.")
        names: set[str] = set()
        for info in infos:
            validate_member(info, names)
            rows.append({"name": info.filename, "bytes": info.file_size,
                         "sha256": hash_member(archive, info), "crc32": info.CRC})
        selected = retain_selected(archive, rows, metadata_directory)
    receipt = {"schema": "probity.exact-archive-member-readback.v1",
               "artifactId": ARTIFACT_ID, "runId": RUN_ID, "sourceHead": SOURCE_HEAD,
               "archiveBytes": EXPECTED_BYTES, "archiveSHA256": EXPECTED_SHA256,
               "memberCount": len(rows), "uncompressedBytes": EXPECTED_UNCOMPRESSED_BYTES,
               "allMembersRead": True, "archiveCodeExecuted": False,
               "selectedOriginals": selected, "members": rows}
    write_json(metadata_directory / "members.json", receipt)
    return receipt


def retain_selected(archive: zipfile.ZipFile, rows: list[dict[str, Any]],
                    output: Path) -> list[dict[str, Any]]:
    """Retain source-bound original report, protocol and manifest bytes.

    Parameters
    ----------
    archive : zipfile.ZipFile
        Already member-verified original ZIP.
    rows : list[dict[str, Any]]
        Results from :func:`hash_member`, keyed by exact member name.
    output : pathlib.Path
        Existing metadata directory. Only fixed selected basenames are used.

    Returns
    -------
    list[dict[str, Any]]
        Selected source paths, output basenames, lengths and digests.
    """
    by_name = {row["name"]: row for row in rows}
    retained = []
    for name, (length, digest) in SELECTED_MEMBERS.items():
        row = by_name.get(name, {})
        require(row.get("bytes") == length and row.get("sha256") == digest,
                "Selected original JSON bytes differ.")
        target = output / f"original-{PurePosixPath(name).name}"
        with target.open("xb") as handle:
            handle.write(archive.read(name))
        retained.append({**row, "retainedBasename": target.name})
    return retained


def split_archive(original: Path, output: Path, part_bytes: int = PART_BYTES) -> list[dict[str, Any]]:
    """Split an immutable file into contiguous individually hashed byte ranges.

    Parameters
    ----------
    original : pathlib.Path
        Verified ZIP whose bytes are preserved verbatim.
    output : pathlib.Path
        New directory for byte ranges; existing outputs are refused.
    part_bytes : int, default=29360128
        Maximum raw bytes per part. The production setting leaves four MiB
        below the 32 MiB connector materialization limit for ZIP overhead.

    Returns
    -------
    list[dict[str, Any]]
        Ordered part index, basename, offset, length and SHA-256 entries.

    Raises
    ------
    ValueError
        If part sizing is invalid or requires more than forty parts.
    """
    require(0 < part_bytes <= PART_BYTES, "Part byte bound is invalid.")
    length = original.stat().st_size
    count = (length + part_bytes - 1) // part_bytes
    require(0 < count <= MAX_PARTS, "Archive requires an unsupported part count.")
    output.mkdir()
    rows = []
    with original.open("rb") as source:
        for index in range(count):
            raw = source.read(part_bytes)
            name = f"part-{index:03d}.bin"
            with (output / name).open("xb") as target:
                target.write(raw)
            rows.append({"index": index, "name": name, "offset": index * part_bytes,
                         "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        require(source.read(1) == b"", "Archive changed while splitting.")
    require(sum(row["bytes"] for row in rows) == length, "Split byte total differs.")
    return rows


def prepare(output: Path) -> None:
    """Retrieve the original, verify it, and publish bounded transfer parts.

    Parameters
    ----------
    output : pathlib.Path
        New custody directory. Originals remain beside ``parts`` and metadata.

    Notes
    -----
    ``GH_TOKEN`` must contain the runner's read-only Actions token. This
    function does not install any archive dependency, execute archive code,
    invoke a model, alter the source artifact or change repository permissions.
    """
    token = os.environ.get("GH_TOKEN", "")
    require(bool(token), "GH_TOKEN is required for original artifact access.")
    output.mkdir()
    metadata = output / "metadata"
    metadata.mkdir()
    artifact = get_json(f"/actions/artifacts/{ARTIFACT_ID}", token)
    run = get_json(f"/actions/runs/{RUN_ID}", token)
    validate_metadata(artifact, run)
    write_json(metadata / "original-artifact-metadata.json", artifact)
    write_json(metadata / "original-run-metadata.json", run)
    original = output / ORIGINAL_NAME
    download_original(original, token)
    members = verify_zip(original, metadata)
    parts = split_archive(original, output / "parts")
    manifest = {"schema": "probity.exact-archive-chunk-transfer.v1",
                "createdAt": datetime.now(timezone.utc).isoformat(),
                "repository": REPOSITORY, "artifactId": ARTIFACT_ID, "runId": RUN_ID,
                "sourceHead": SOURCE_HEAD, "archiveName": ORIGINAL_NAME,
                "archiveBytes": EXPECTED_BYTES, "archiveSHA256": EXPECTED_SHA256,
                "partByteBound": PART_BYTES, "parts": parts,
                "memberCount": members["memberCount"],
                "uncompressedBytes": members["uncompressedBytes"],
                "allMembersRead": True, "archiveCodeExecuted": False,
                "inferenceCalls": 0, "providerCalls": 0}
    write_json(metadata / "transfer-manifest.json", manifest)
    LOGGER.info("Original ZIP verified; %d byte parts and %d members retained.",
                len(parts), members["memberCount"])


def main() -> None:
    """Run the finite custody transfer with secret-free failure diagnostics."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        prepare(arguments.output)
    except (OSError, urllib.error.URLError, ValueError, zipfile.BadZipFile) as error:
        LOGGER.error("Archive retention failed (%s); credentials and URLs omitted.",
                     type(error).__name__)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
