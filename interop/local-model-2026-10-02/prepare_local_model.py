"""Prepare one bounded public CPU run without inference/provider APIs."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

LIMIT = 256 * 1024 * 1024
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
PACKAGES = [
    "inspect-ai==0.3.273",
    "scikit-build-core==0.11.6",
    "cmake==4.0.3",
    "ninja==1.11.1.3",
    "numpy==2.2.6",
    "diskcache==5.6.3",
    "jinja2==3.1.6",
    "markupsafe==3.0.3",
    "typing-extensions==4.15.0",
]


def sha(path):
    result = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            result.update(chunk)
    return result.hexdigest()


def write(path, value):
    with path.open("x") as f:
        json.dump(value, f, indent=2)
        f.write("\n")


def prepare(root):
    root.mkdir(parents=True, exist_ok=False)
    (root / "downloads").mkdir()
    (root / "temporary").mkdir()
    write(
        root / "download-declaration.json",
        {
            "profile": "probity-inspect-local-model-v1",
            "limitBytes": LIMIT,
            "items": PINS,
            "packages": PACKAGES,
            "providerCalls": 0,
            "providerDollars": 0,
        },
    )
    consumed = 0
    receipt = []
    for name, url, size, expected in PINS:
        if consumed + size > LIMIT:
            raise ValueError("download declaration exceeds limit")
        path = root / name
        count = 0
        with urllib.request.urlopen(url, timeout=30) as response, path.open("xb") as f:
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > size:
                    raise ValueError("download exceeds selected size")
                f.write(chunk)
        consumed += count
        if count != size or sha(path) != expected:
            raise ValueError("selected primary download mismatch")
        receipt.append(dict(path=name, url=url, bytes=count, sha256=expected))
    environment = dict(os.environ, TMPDIR=str(root / "temporary"), PIP_NO_CACHE_DIR="1")
    command = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--retries",
        "0",
        "--timeout",
        "30",
        "--only-binary=:all:",
        "--dest",
        str(root / "downloads"),
        *PACKAGES,
    ]
    started = time.monotonic()
    with (root / "package-download.log").open("wb") as log:
        child = subprocess.Popen(
            command,
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            while child.poll() is None:
                # Includes pip temporary files; this is deliberately conservative.
                current = sum(p.stat().st_size for p in root.rglob("*") if p.is_file())
                if current > LIMIT or time.monotonic() - started > 180:
                    raise ValueError("package download exceeds size/time budget")
                time.sleep(0.1)
            if child.returncode:
                raise ValueError("package download failed")
        except BaseException:
            import signal

            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            raise
    for path in sorted((root / "downloads").glob("*.whl")):
        consumed += path.stat().st_size
        receipt.append(
            dict(
                path=str(path.relative_to(root)),
                bytes=path.stat().st_size,
                sha256=sha(path),
            )
        )
    if consumed > LIMIT:
        raise ValueError("retained download bytes exceed limit")
    write(
        root / "downloads.json",
        dict(
            files=receipt,
            totalRetainedDownloadBytes=consumed,
            limitBytes=LIMIT,
            scope="selected source/model/card bytes and all resolved dependency wheels; temporary files monitored conservatively",
        ),
    )
    write(
        root / "source-download.json",
        dict(url=PINS[1][1], bytes=PINS[1][2], sha256=PINS[1][3], file=PINS[1][0]),
    )


def finalize(root):
    names = [
        "original-card.txt",
        "quant-card.txt",
        "tokenizer-config.json",
        "downloads.json",
        "source-download.json",
        "build-gcc.log",
        "download-declaration.json",
    ]
    write(
        root / "provenance.json",
        dict(
            sources={n: sha(root / n) for n in names},
            selectedRuntime=dict(
                version="0.3.16",
                sourceSHA256=PINS[1][3],
                buildFlags=[
                    "CC=/usr/bin/gcc",
                    "CXX=/usr/bin/g++",
                    "CMAKE_BUILD_PARALLEL_LEVEL=2",
                    "GGML_NATIVE=OFF",
                    "GGML_OPENMP=OFF",
                    "GGML_CUDA=OFF",
                    "GGML_BLAS=OFF",
                ],
                buildHardSeconds=330,
            ),
            operator="Probity-controlled-GitHub-Actions; same operator",
            priorLocalRun="local run006 remains a separately retained operator record",
        ),
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--finalize", action="store_true")
    args = parser.parse_args()
    if args.finalize:
        finalize(args.output.resolve())
    else:
        prepare(args.output.resolve())
