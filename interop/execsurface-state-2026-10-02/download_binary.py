"""Retrieve the selected published Linux binary; verify before execution."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.request

HERE = Path(__file__).resolve().parent
MEMBER = "execsurface-v0.1.0-alpha.5-x86_64-unknown-linux-gnu/execsurface"


def download(output: Path):
    pins = json.loads((HERE / "source-pins.json").read_bytes())
    with urllib.request.urlopen(pins["releaseUrl"], timeout=30) as response:
        data = response.read(2 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != pins["releaseArchiveSha256"]:
        raise ValueError("release archive digest mismatch")
    archive = output.with_suffix(".tar.gz")
    archive.write_bytes(data)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        member = tar.getmember(MEMBER)
        if not member.isfile() or member.size > 5 * 1024 * 1024:
            raise ValueError("selected member is not a bounded regular file")
        binary = tar.extractfile(member).read()
    if hashlib.sha256(binary).hexdigest() != pins["binarySha256"]:
        raise ValueError("release binary digest mismatch")
    output.write_bytes(binary)
    output.chmod(0o755)
    print(json.dumps({"archiveSha256": pins["releaseArchiveSha256"],
                      "binarySha256": pins["binarySha256"], "bytes": len(binary)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    download(parser.parse_args().output)
