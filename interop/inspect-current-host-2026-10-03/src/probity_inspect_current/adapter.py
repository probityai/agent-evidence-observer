"""Retain unchanged native grammar behind an explicit Inspect 0.3.276 profile.

Trusted host bootstrap selects the adapter, legacy bytes, installed package and
full native source population before execution. This module supplies no claim
of independent custody, adoption, authority or model quality.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.metadata
import importlib.util
import importlib
import json
from pathlib import Path
import sys
from types import ModuleType
from typing import Any

VERSION = "probity-inspect-execution-v2"
INSPECT_VERSION = "0.3.276"
LEGACY = {
    "evaluation_contract.py": "2477f069f52e14545b8525c1b40cbe8deceb381cc036d6204d2069feaa54c221",
    "inspect_contract.py": "9a075a3e08fd48d20ddfc36f16a88277fd5a8075bf51288108697ed250022fb9",
    "inspect_execution.py": "a9919ba209f7507144cb657678b460ef54790021bc6df5c115b1ee7750dc5c50",
}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _authenticated_sources() -> tuple[Path, dict[str, bytes]]:
    """Retain each selected legacy source buffer after checking its digest."""
    root = Path(__file__).parent / "_legacy"
    authenticated = {}
    for name, expected in LEGACY.items():
        raw = (root / name).read_bytes()
        if sha(raw) != expected:
            raise ValueError("legacy_source_digest")
        authenticated[name] = raw
    return root, authenticated


def _load(root: Path, name: str, raw: bytes, aliases: tuple[str, ...]) -> ModuleType:
    """Execute one authenticated buffer without consulting bytecode caches."""
    stem = Path(name).stem
    spec = importlib.util.spec_from_file_location(
        "probity_inspect_current._authenticated_" + stem, root / name
    )
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    if stem in aliases:
        sys.modules[stem] = module
    exec(compile(raw, str(root / name), "exec"), module.__dict__)
    assert isinstance(module.__file__, str)
    if Path(module.__file__).resolve() != (root / name).resolve():
        raise ValueError("legacy_module_resolution")
    return module


def _modules(root: Path, authenticated: dict[str, bytes]) -> dict[str, ModuleType]:
    """Load authenticated source in an isolated namespace with exact aliases."""
    aliases = ("evaluation_contract", "inspect_contract")
    if any(name in sys.modules for name in aliases):
        raise ValueError("legacy_module_collision")
    modules = {}
    try:
        for name in LEGACY:
            stem = Path(name).stem
            modules[stem] = _load(root, name, authenticated[name], aliases)
    finally:
        for name in aliases:
            sys.modules.pop(name, None)
    return modules


def load_engine() -> ModuleType:
    """Authenticate sources and create the literal v2 engine namespace.

    Returns
    -------
    ModuleType
        An independent module whose native grammar is unchanged.
    """
    root, authenticated = _authenticated_sources()
    engine = _modules(root, authenticated)["inspect_execution"]
    if (
        engine.VERSION != "probity-inspect-execution-v1"
        or engine.INSPECT_VERSION != "0.3.273"
    ):
        raise ValueError("legacy_version_boundary")
    engine.__dict__["VERSION"] = VERSION
    engine.__dict__["INSPECT_VERSION"] = INSPECT_VERSION
    original_sources = engine.sources

    def sources(framework: Any, declared: dict[str, Any]) -> dict[str, bytes]:
        """Retain the adapter and literal compatibility mapping with source."""
        selected = original_sources(framework, declared)
        config = engine.decode(selected["configuration.json"])
        config["current_profile_adapter.py"] = Path(__file__).read_text("utf-8")
        config["current_profile_mapping"] = {
            "profile": VERSION,
            "inspect_version": INSPECT_VERSION,
            "legacy_engine_sha256": LEGACY,
            "grammar": "unchanged-bounded-mock-only",
        }
        selected["configuration.json"] = engine.encode(config)
        return selected

    engine.__dict__["sources"] = sources
    return engine


def prepare(engine: ModuleType, declaration: dict[str, Any]) -> dict[str, Any]:
    """Verify installed host and freeze full installed source before model calls."""
    inspect_ai = importlib.import_module("inspect_ai")

    if importlib.metadata.version("inspect-ai") != INSPECT_VERSION:
        raise ValueError("installed_inspect_version")
    assert isinstance(inspect_ai.__file__, str)
    root = Path(inspect_ai.__file__).parent
    engine._declared(declaration)
    sources = engine.sources(inspect_ai, declaration)
    if inspect_ai.__version__ != INSPECT_VERSION:
        raise ValueError("runtime_inspect_version")
    return {
        "declaration": declaration,
        "sources": {name: raw.decode("utf-8") for name, raw in sources.items()},
        "native_runtime": {
            str(p.relative_to(root)): sha(p.read_bytes())
            for p in sorted(root.rglob("*.py"))
        },
        "native_git_blobs": {
            str(p.relative_to(root)): hashlib.sha1(
                b"blob " + str(len(p.read_bytes())).encode() + b"\0" + p.read_bytes()
            ).hexdigest()
            for p in sorted(root.rglob("*.py"))
        },
        "installed_version": importlib.metadata.version("inspect-ai"),
    }


def produce(
    engine: ModuleType, selection: dict[str, Any], output: Path
) -> dict[str, Any]:
    """Run the exact externally selected declaration after source checks."""
    frozen = prepare(engine, selection["declaration"])
    if frozen != selection["prepared"]:
        raise ValueError("preexecution_selection_changed")
    engine.__dict__["declaration"] = lambda: copy.deepcopy(selection["declaration"])
    original_sources = engine.sources

    def selected_sources(framework: Any, declared: dict[str, Any]) -> dict[str, bytes]:
        """Check the frozen selection before returning execution sources."""
        actual = original_sources(framework, declared)
        if {name: raw.decode("utf-8") for name, raw in actual.items()} != frozen[
            "sources"
        ]:
            raise ValueError("preexecution_sources_changed")
        return actual

    engine.__dict__["sources"] = selected_sources
    return engine.run(output)


def verify(
    engine: ModuleType, selection: dict[str, Any], output: Path
) -> dict[str, Any]:
    """Read a packet under external pins without importing the framework."""
    if "inspect_ai" in sys.modules:
        raise ValueError("framework_in_reader")
    declared = engine.decode((output / "declaration-before-run.json").read_bytes())
    if declared != selection["declaration"]:
        raise ValueError("external_population_changed")
    return engine.verify_saved(output, selection["pins"])


def main() -> None:
    """Dispatch the separately installed profile command."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "produce", "verify"))
    parser.add_argument("output", type=Path)
    parser.add_argument("--selection", type=Path, required=True)
    args = parser.parse_args()
    selection = json.loads(args.selection.read_bytes())
    engine = load_engine()
    if args.mode == "prepare":
        result = prepare(engine, selection["declaration"])
    elif args.mode == "produce":
        result = produce(engine, selection, args.output)
    else:
        result = verify(engine, selection, args.output)
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
