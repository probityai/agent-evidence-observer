"""Execute 20 declared native two-replica MySQL caller/history exercises."""

from __future__ import annotations

import argparse
import asyncio
import importlib.metadata
import json
import os
import subprocess
import time
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

import a2a
from a2a.server.models import Base
from boundary_common import (
    CASES,
    IMAGE,
    NONCLAIMS,
    PROFILE,
    SDK_FILES,
    SOURCE_HEAD,
    SOURCE_DIGESTS,
    same,
    sha,
)
from boundary_native import run_case


def write(path, value):
    """Retain ordinary formatted JSON."""
    path.write_text(json.dumps(value, indent=2) + "\n")


def sources(output, source):
    """Require the selected native source checkout before any task execution."""
    current = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if current != SOURCE_HEAD:
        raise ValueError("sdk-source-head-differs")
    result = {}
    for name in SDK_FILES:
        raw = (source / name).read_bytes()
        target = output / "sources" / "sdk" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        result[name] = sha(raw)
    same(result, SOURCE_DIGESTS, "reviewed-sdk-source-differs")
    installed_sources(result)
    for path in sorted(Path(__file__).parent.glob("*.py")):
        target = output / "sources" / "profile" / path.name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
    return result


def installed_sources(result):
    """Bind each loaded native runtime file to the reviewed source bytes."""
    installed = Path(next(iter(a2a.__path__))).parent
    for name in SDK_FILES:
        if name.startswith("src/"):
            same(
                sha((installed / name.removeprefix("src/")).read_bytes()),
                result[name],
                "installed-sdk-source-differs",
            )


def container_receipt(name):
    """Retain only public container identity, limits and loopback exposure, no environment."""
    value = json.loads(subprocess.check_output(["docker", "inspect", name]))[0]
    receipt = {
        "id": value["Id"],
        "image": value["Config"]["Image"],
        "imageId": value["Image"],
        "running": value["State"]["Running"],
        "memoryBytes": value["HostConfig"]["Memory"],
        "nanoCPUs": value["HostConfig"]["NanoCpus"],
        "pidsLimit": value["HostConfig"]["PidsLimit"],
        "bindings": value["HostConfig"]["PortBindings"]["3306/tcp"],
    }
    same(receipt["image"], IMAGE, "container-image-differs")
    same(receipt["running"], True, "mysql-container-stopped")
    same(receipt["memoryBytes"], 536870912, "mysql-memory-cap")
    same(receipt["nanoCPUs"], 1000000000, "mysql-cpu-cap")
    same(receipt["pidsLimit"], 128, "mysql-pids-cap")
    same(
        [v["HostIp"] for v in receipt["bindings"]], ["127.0.0.1"], "mysql-loopback-only"
    )
    return receipt


async def execute(output, dsn, source, container):
    """Bound the full declared population; retain abnormal execution visibly."""
    output.mkdir(parents=True, exist_ok=False)
    contract = sources(output, source)
    engine = create_async_engine(dsn)
    started = time.monotonic()
    manifest = {
        "profile": PROFILE,
        "witnessScope": "PEER",
        "doesNotAssert": NONCLAIMS,
        "status": "running",
        "sourceHead": SOURCE_HEAD,
        "sdkSources": contract,
        "mysqlImage": IMAGE,
        "plannedAttempts": 20,
        "asgiSubstrate": "httpx-ASGITransport-in-process",
        "resources": {
            "wholeRunSeconds": 120,
            "requestSeconds": 15,
            "mysqlMemoryMiB": 512,
            "mysqlCPUs": 1,
            "replicasPerCase": 2,
            "separateSQLConnectionsPerCase": 4,
        },
        "container": container_receipt(container),
        "records": [],
    }
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            manifest["mysqlVersion"] = (
                await conn.execute(text("SELECT VERSION()"))
            ).scalar_one()
        manifest["dependencies"] = {
            key: importlib.metadata.version(key)
            for key in [
                "a2a-sdk",
                "SQLAlchemy",
                "PyMySQL",
                "aiomysql",
                "protobuf",
                "httpx",
                "starlette",
            ]
        }
        for name, budget in CASES:
            result = await run_case(dsn, name, budget)
            path = "cases/" + name + ".json"
            (output / "cases").mkdir(exist_ok=True)
            write(output / path, result)
            manifest["records"].append({"id": name, "path": path})
        manifest["status"] = "captured"
    except BaseException as error:
        manifest["status"] = "failed"
        manifest["failure"] = {"class": type(error).__name__, "message": str(error)}
        raise
    finally:
        await engine.dispose()
        manifest["elapsedSeconds"] = time.monotonic() - started
        write(output / "manifest.json", manifest)
        pins = {
            str(path.relative_to(output)): sha(path.read_bytes())
            for path in sorted(output.rglob("*"))
            if path.is_file()
        }
        write(
            output.parent / (output.name + "-pins.json"),
            {"profile": PROFILE, "files": pins},
        )


def main():
    """Run with the local public fixture DSN supplied only through the environment."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sdk-source", type=Path, required=True)
    parser.add_argument("--mysql-container", required=True)
    args = parser.parse_args()
    asyncio.run(
        asyncio.wait_for(
            execute(
                args.output,
                os.environ["PROBITY_FIXTURE_MYSQL_DSN"],
                args.sdk_source,
                args.mysql_container,
            ),
            timeout=120,
        )
    )


if __name__ == "__main__":
    main()
