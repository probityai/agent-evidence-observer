"""Assess finite JSON, selected generic schemas and typed exact task answers."""

from __future__ import annotations

from typing import Any

try:
    from .evidence_io import strict_json
except ImportError:
    from evidence_io import strict_json

JSON_TYPES = {"string": str, "integer": int, "boolean": bool, "null": type(None), "array": list, "object": dict}


def exact(left: Any, right: Any) -> bool:
    """Compare complete JSON answers without numeric, boolean or string coercion.

    Both values must already satisfy the depth/population limit enforced by
    ``evidence_io.strict_json``. Object order and whitespace are immaterial;
    array order, exact keys, nulls and value types remain part of the target.
    """
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(exact(left[key], right[key]) for key in right)
    if isinstance(left, list):
        return len(left) == len(right) and all(exact(a, b) for a, b in zip(left, right))
    return left == right


def accepts_type(value: Any, kind: str) -> bool:
    """Apply a selected JSON type, keeping bool separate from numeric values."""
    if kind == "number":
        return type(value) in {int, float}
    return type(value) is JSON_TYPES[kind]


def object_accepts(value: Any, schema: dict[str, Any]) -> bool:
    """Assess the fixed generic object members, without any case target data."""
    properties = schema.get("properties")
    if properties is None:
        return True
    return set(value) == set(schema["required"]) and all(schema_accepts(value[key], child) for key, child in properties.items())


def schema_accepts(value: Any, schema: dict[str, Any]) -> bool:
    """Assess only the prospectively selected finite JSON-schema subset.

    The frozen control permits arbitrary finite JSON argument values. The
    treatment permits a nullable string key and nullable integer value plus
    the same global three-tool catalog in every case. Both retain the same
    output shape; neither grammar encodes the selected case's answer.
    """
    kinds = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
    if not any(accepts_type(value, kind) for kind in kinds):
        return False
    if "enum" in schema and not any(exact(value, choice) for choice in schema["enum"]):
        return False
    return not isinstance(value, dict) or object_accepts(value, schema)


def score(text: str, target: dict[str, Any], schema: dict[str, Any]) -> dict[str, bool]:
    """Keep format/schema success separate from strict semantic correctness.

    A truncated output, duplicate member, nonfinite value or excess depth
    remains in the full attempted denominator with all three scores false.
    Grammar validity never supplies permission to execute a real tool.
    """
    try:
        value = strict_json(text)
    except (ValueError, TypeError, RecursionError):
        return {"formatValid": False, "schemaValid": False, "correct": False}
    return {"formatValid": isinstance(value, dict), "schemaValid": schema_accepts(value, schema), "correct": exact(value, target)}
