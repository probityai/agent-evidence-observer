"""Prepare selected CPU inputs with separate transfer and retention accounting."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import logging
import platform
import re
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, BinaryIO

LOGGER = logging.getLogger(__name__)
MIB = 1024 * 1024
TOTAL_LIMIT = 512 * MIB
CATEGORY_LIMITS = {"model": 128 * MIB, "source": 64 * MIB, "metadata": MIB, "dependencies": 256 * MIB}
DOWNLOAD_SECONDS = 180
LOCK_PATH = Path(__file__).with_name("dependency-lock-linux-cp312.json")

PINS = [
    (
        "model.gguf",
        "https://huggingface.co/unsloth/SmolLM2-135M-Instruct-GGUF/resolve/9e6855bc4be717fca1ef21360a1db4b29d5c559a/SmolLM2-135M-Instruct-Q4_K_M.gguf",
        105454144,
        "ed5fa30c487b282ec156c29062f1222e5c20875a944ac98289dbd242e947f747",
    ),
    (
        "downloads/llama_cpp_python-0.3.16.tar.gz",
        "https://files.pythonhosted.org/packages/e4/b4/c8cd17629ced0b9644a71d399a91145aedef109c0333443bef015e45b704/llama_cpp_python-0.3.16.tar.gz",
        50688636,
        "34ed0f9bd9431af045bb63d9324ae620ad0536653740e9bb163a2e1fcb973be6",
    ),
    (
        "original-card.txt",
        "https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct/resolve/12fd25f77366fa6b3b4b768ec3050bf629380bac/README.md",
        6772,
        "4f97533ad95b1b2fea15fbc075c01b94578ebdd7c8138888fa43fa3abd530dc4",
    ),
    (
        "quant-card.txt",
        "https://huggingface.co/unsloth/SmolLM2-135M-Instruct-GGUF/resolve/9e6855bc4be717fca1ef21360a1db4b29d5c559a/README.md",
        4567,
        "b464dc4a9ff26fea06ec45165546bbeb0c32b1a7847babcef048d5b84486ed84",
    ),
    (
        "tokenizer-config.json",
        "https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct/resolve/12fd25f77366fa6b3b4b768ec3050bf629380bac/tokenizer_config.json",
        3764,
        "4ec77d44f62efeb38d7e044a1db318f6a939438425312dfa333b8382dbad98df",
    ),
]


def sha(path: Path) -> str:
    """Hash original bytes without loading the complete payload into memory.

    Parameters
    ----------
    path : pathlib.Path
        Existing payload or receipt whose bytes must be committed.

    Returns
    -------
    str
        Lowercase SHA-256 hexadecimal digest.
    """
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(MIB), b""):
            result.update(chunk)
    return result.hexdigest()


def write(path: Path, value: Any) -> None:
    """Create a JSON receipt exclusively, preserving earlier attempt bytes."""
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


@dataclass(frozen=True)
class Download:
    """A selected payload and its original-byte/category commitments."""

    path: str
    url: str
    bytes: int
    sha256: str
    category: str

    def record(self) -> dict[str, Any]:
        """Return the selected fields retained in declarations and receipts."""
        return dict(path=self.path, url=self.url, bytes=self.bytes, sha256=self.sha256, category=self.category)


def validate_dependency(entry: dict[str, Any]) -> Download:
    """Validate one frozen wheel before allowing any network transfer.

    Raises
    ------
    ValueError
        If the identity, single wheel filename, publisher URL, byte length or
        SHA-256 digest is invalid. Population checks live in
        :func:`dependency_items`; envelopes live in :func:`expected_totals`.
    """
    require(isinstance(entry, dict), "invalid dependency entry")
    name, version = entry.get("name", ""), entry.get("version", "")
    require(matches(name, r"[A-Za-z0-9_.-]+") and matches(version, r"[A-Za-z0-9_.+-]+"), "invalid dependency identity")
    path = entry.get("path", "")
    require(matches(path, r"downloads/[A-Za-z0-9_.+-]+\.whl"), "invalid dependency path")
    url = entry.get("url", "")
    require(isinstance(url, str) and url.startswith("https://files.pythonhosted.org/packages/") and url.rsplit("/", 1)[-1] == Path(path).name, "invalid dependency URL")
    size, digest = entry.get("bytes"), entry.get("sha256", "")
    require(type(size) is int and size > 0, "invalid dependency size")
    require(matches(digest, r"[0-9a-f]{64}"), "invalid dependency digest")
    return Download(path, url, size, digest, "dependencies")


def require(condition: bool, message: str) -> None:
    """Refuse a violated selection invariant with its stable diagnostic."""
    if not condition:
        LOGGER.error("%s", message)
        raise ValueError(message)


def matches(value: Any, pattern: str) -> bool:
    """Match a complete string field, safely rejecting other JSON types."""
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def dependency_items(lock: dict[str, Any]) -> list[Download]:
    """Validate the frozen Linux CPython 3.12 wheel population before transfer.

    Parameters
    ----------
    lock : dict
        Committed pip/PyPI selection with exact versions, filenames, URLs,
        sizes and hashes for all direct and transitive dependencies.

    Returns
    -------
    list of Download
        Wheels in the selected order.

    Raises
    ------
    ValueError
        On unsupported schema/target, empty population, duplicate package
        identity, malformed entry or a mismatched dependency byte total.
    """
    require(isinstance(lock, dict), "invalid dependency selection")
    require(lock.get("schema") == "probity-local-model-download-selection-v1", "unsupported dependency selection")
    target = {"os": "Ubuntu 24.04", "architecture": "x86_64", "python": "3.12", "distribution": "CPython"}
    require(lock.get("target") == target, "unsupported dependency target")
    entries = lock.get("dependencies")
    require(isinstance(entries, list) and bool(entries), "dependency selection must be nonempty")
    items = [validate_dependency(entry) for entry in entries]
    identities = [re.sub(r"[-_.]+", "-", entry["name"]).lower() for entry in entries]
    require(len(set(identities)) == len(identities), "duplicate dependency identity")
    require(type(lock.get("dependencyBytes")) is int and sum(item.bytes for item in items) == lock["dependencyBytes"], "dependency byte total mismatch")
    return items


def selected_items(lock: dict[str, Any]) -> list[Download]:
    """Join immutable model/source/card pins to the separately frozen wheels."""
    categories = ("model", "source", "metadata", "metadata", "metadata")
    primary = [Download(*pin, category) for pin, category in zip(PINS, categories, strict=True)]
    return primary + dependency_items(lock)


def expected_totals(items: list[Download]) -> dict[str, int]:
    """Reject duplicate destinations and category/aggregate declaration overflow."""
    require(len({item.path for item in items}) == len(items), "duplicate download path")
    require(all(item.category in CATEGORY_LIMITS for item in items), "unknown download category")
    totals = {category: sum(item.bytes for item in items if item.category == category) for category in CATEGORY_LIMITS}
    for category, count in totals.items():
        require(count <= CATEGORY_LIMITS[category], f"{category} declaration exceeds limit")
    require(sum(totals.values()) <= TOTAL_LIMIT, "total download declaration exceeds limit")
    return totals


@dataclass
class Accounting:
    """Actual response-body bytes, separate from retained payload sizes.

    Bytes read before refusal remain charged. Each selected URL is attempted
    once, with no pip download subprocess or retry. HTTP/TLS overhead, metadata
    resolution, runner provisioning and artifact upload are outside this scope.
    """

    started: float = field(default_factory=time.monotonic)
    transferred: int = 0
    categories: dict[str, int] = field(default_factory=lambda: dict.fromkeys(CATEGORY_LIMITS, 0))
    files: list[dict[str, Any]] = field(default_factory=list)

    def charge(self, category: str, count: int) -> None:
        """Charge bytes read before checking category and aggregate limits."""
        self.transferred += count
        self.categories[category] += count
        require(self.transferred <= TOTAL_LIMIT, "total transfer exceeds limit")
        require(self.categories[category] <= CATEGORY_LIMITS[category], f"{category} transfer exceeds limit")

    def check_time(self) -> None:
        """Refuse further reads after the selected preparation wall time."""
        require(time.monotonic() - self.started <= DOWNLOAD_SECONDS, "download exceeds time budget")


def stream_payload(response: BinaryIO, destination: BinaryIO, item: Download, accounting: Accounting) -> int:
    """Copy one payload once, detecting size overflow with one additional byte.

    Returns
    -------
    int
        Actual response-body byte count at end of stream.

    Raises
    ------
    ValueError
        On time/transfer envelope or selected-size overflow. The extra byte
        is charged but not written; prior partial bytes remain retained.
    """
    count = 0
    while True:
        accounting.check_time()
        chunk = response.read(min(MIB, item.bytes - count + 1))
        if not chunk:
            return count
        accounting.charge(item.category, len(chunk))
        count += len(chunk)
        require(count <= item.bytes, "download exceeds selected size")
        destination.write(chunk)


def download_one(root: Path, item: Download, accounting: Accounting) -> None:
    """Retain a payload and its actual size/digest/status, including refusals."""
    path = root / item.path
    record = dict(selected=item.record(), status="started")
    accounting.files.append(record)
    try:
        with urllib.request.urlopen(item.url, timeout=30) as response, path.open("xb") as stream:
            count = stream_payload(response, stream, item, accounting)
        require(count == item.bytes and sha(path) == item.sha256, "selected download mismatch")
        record["status"] = "verified"
    except Exception as error:
        record.update(status="refused", error=str(error), errorType=type(error).__name__)
        LOGGER.error("Download refused for %s: %s", item.path, error)
        raise
    finally:
        if path.exists():
            record.update(retainedBytes=path.stat().st_size, retainedSHA256=sha(path))


def requirements_text(lock: dict[str, Any]) -> str:
    """Render every selected wheel for offline pip hash/identity verification."""
    dependency_items(lock)
    return "".join(f'{entry["name"]}=={entry["version"]} --hash=sha256:{entry["sha256"]}\n' for entry in lock["dependencies"])


def retain_accounting(root: Path, accounting: Accounting, status: str, error: str | None) -> None:
    """Write terminal size/refusal evidence even after failed preparation."""
    write(root / "download-accounting.json", {
        "schema": "probity-local-model-download-accounting-v1",
        "status": status, "error": error,
        "actualResponseBodyBytes": accounting.transferred,
        "actualResponseBodyBytesByCategory": accounting.categories,
        "retainedPayloadBytes": sum(record.get("retainedBytes", 0) for record in accounting.files),
        "elapsedSeconds": time.monotonic() - accounting.started,
        "totalLimitBytes": TOTAL_LIMIT, "categoryLimitBytes": CATEGORY_LIMITS,
        "files": accounting.files,
        "scope": "one response-body transfer per selected payload; no retry; excludes HTTP/TLS, metadata resolution, runner provisioning and artifact upload",
    })


def prepare(root: Path) -> None:
    """Freeze selections and transfer each payload once before installation.

    Dependencies are selected in the committed lock before this invocation.
    Model, source, metadata and dependency bytes have separate category limits
    inside a declared 512 MiB envelope. The workflow cannot install or infer
    unless every selected payload passes. See :func:`finalize` for provenance.
    """
    lock = json.loads(LOCK_PATH.read_bytes())
    items = selected_items(lock)
    totals = expected_totals(items)
    root.mkdir(parents=True, exist_ok=False)
    (root / "downloads").mkdir()
    (root / "dependency-lock.json").write_bytes(LOCK_PATH.read_bytes())
    (root / "requirements.txt").write_text(requirements_text(lock), encoding="utf-8")
    write(root / "download-declaration.json", {
        "profile": "probity-inspect-local-model-v1",
        "dependencySelectionSHA256": sha(LOCK_PATH), "items": [item.record() for item in items],
        "expectedPayloadBytesByCategory": totals, "expectedTotalPayloadBytes": sum(totals.values()),
        "totalLimitBytes": TOTAL_LIMIT, "categoryLimitBytes": CATEGORY_LIMITS,
        "downloadMonitoredSeconds": DOWNLOAD_SECONDS, "networkOperationTimeoutSeconds": 30, "providerCalls": 0, "providerDollars": 0,
    })
    accounting = Accounting()
    status, error = "refused", None
    try:
        for item in items:
            download_one(root, item, accounting)
        write(root / "downloads.json", {
            "files": [item.record() for item in items], "totalRetainedDownloadBytes": accounting.transferred,
            "limitBytes": TOTAL_LIMIT, "dependencySelectionSHA256": sha(LOCK_PATH),
            "scope": "original payload bytes; selected before transfer; excludes logs/installation copies",
        })
        write(root / "source-download.json", dict(url=PINS[1][1], bytes=PINS[1][2], sha256=PINS[1][3], file=PINS[1][0]))
        status = "verified"
    except Exception as failure:
        error = f"{type(failure).__name__}: {failure}"
        raise
    finally:
        retain_accounting(root, accounting, status, error)


def verify_retained(root: Path) -> None:
    """Recheck selected bytes before installation and after the bounded build.

    The committed lock remains the selection authority. A rewritten adjacent
    lock, requirements file or successful accounting label cannot select new
    payload bytes. Missing, resized or altered payloads refuse.
    """
    accounting = json.loads((root / "download-accounting.json").read_bytes())
    require(accounting.get("status") == "verified", "download accounting is not verified")
    lock = json.loads(LOCK_PATH.read_bytes())
    require(sha(root / "dependency-lock.json") == sha(LOCK_PATH), "retained dependency selection mismatch")
    require((root / "requirements.txt").read_text() == requirements_text(lock), "retained requirements mismatch")
    for item in selected_items(lock):
        verify_payload(root / item.path, item)


def verify_payload(path: Path, item: Download) -> None:
    """Refuse a missing or changed original payload with a stable diagnostic."""
    require(path.is_file(), "selected payload missing")
    require(path.stat().st_size == item.bytes and sha(path) == item.sha256, "selected retained payload mismatch")


def finalize(root: Path) -> None:
    """Bind verified transfer evidence and the bounded build into provenance."""
    verify_retained(root)
    names = ["original-card.txt", "quant-card.txt", "tokenizer-config.json", "downloads.json",
             "source-download.json", "build-gcc.log", "download-declaration.json",
             "dependency-lock.json", "requirements.txt", "download-accounting.json"]
    write(root / "provenance.json", {
        "sources": {name: sha(root / name) for name in names},
        "selectedRuntime": {
            "version": "0.3.16", "sourceSHA256": PINS[1][3],
            "buildFlags": ["CC=/usr/bin/gcc", "CXX=/usr/bin/g++", "CMAKE_BUILD_PARALLEL_LEVEL=2",
                           "GGML_NATIVE=OFF", "GGML_OPENMP=OFF", "GGML_CUDA=OFF", "GGML_BLAS=OFF"],
            "buildHardSeconds": 330,
        },
        "operator": "Probity-controlled-GitHub-Actions; same operator",
        "priorLocalRun": "local run006 and Ubuntu preparation refusal 36971133711 remain separately retained",
    })


def main() -> None:
    """Select preparation or finalization without changing the inference profile."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--finalize", action="store_true")
    mode.add_argument("--verify-downloads", action="store_true")
    args = parser.parse_args()
    if args.finalize:
        finalize(args.output.resolve())
    elif args.verify_downloads:
        verify_retained(args.output.resolve())
    else:
        if sys.version_info[:2] != (3, 12) or sys.platform != "linux" or platform.machine() != "x86_64":
            raise ValueError("preparation requires Linux x86_64 CPython 3.12")
        prepare(args.output.resolve())


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
