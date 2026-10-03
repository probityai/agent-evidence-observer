"""Check the selected JSON schema subset without coercing typed values."""

from __future__ import annotations

import json
from typing import Any

SCALAR_TYPES = {"integer": int, "string": str, "boolean": bool, "null": type(None)}


def exact(left: Any, right: Any) -> bool:
    """Compare JSON values with explicit type, member and array-order checks."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(exact(left[k], right[k]) for k in right)
    if isinstance(left, list):
        return len(left) == len(right) and all(exact(a, b) for a, b in zip(left, right))
    return left == right


def validate_schema(schema: dict[str, Any]) -> None:
    """Refuse malformed or unsupported contracts before output assessment."""
    if type(schema) is not dict:
        raise ValueError("schema must be an object")
    kind = schema.get("type")
    kinds = kind if type(kind) is list else [kind]
    if not kinds or any(type(k) is not str for k in kinds):
        raise ValueError("schema type selection is invalid")
    if len(set(kinds)) != len(kinds):
        raise ValueError("schema type selection contains duplicates")
    if type(kind) is list and any(k not in SCALAR_TYPES for k in kinds):
        raise ValueError("only scalar type unions are supported")
    if any(k not in {*SCALAR_TYPES, "object", "array"} for k in kinds):
        raise ValueError("schema type is unsupported")
    allowed = {"type", "enum"}
    if kind == "object":
        allowed |= {"properties", "required", "additionalProperties"}
        props, required = schema.get("properties"), schema.get("required")
        if (
            type(props) is not dict
            or type(required) is not list
            or any(type(name) is not str for name in required)
            or len(set(required)) != len(required)
            or set(required) != set(props)
            or schema.get("additionalProperties") is not False
        ):
            raise ValueError("object schema must select every required member exactly")
        for name, child in props.items():
            if type(name) is not str:
                raise ValueError("schema property name must be a string")
            validate_schema(child)
    elif kind == "array":
        allowed.add("items")
        validate_schema(schema.get("items"))
    if set(schema) - allowed:
        raise ValueError("schema contains unsupported constraints")
    if "enum" in schema:
        choices = schema["enum"]
        if type(choices) is not list or not choices:
            raise ValueError("enum must contain at least one selected value")
        broad = {k: v for k, v in schema.items() if k != "enum"}
        for index, choice in enumerate(choices):
            if not _accepts(choice, broad):
                raise ValueError("enum value does not satisfy its selected type")
            if any(exact(choice, previous) for previous in choices[:index]):
                raise ValueError("enum contains duplicate typed values")


def _accepts(value: Any, schema: dict[str, Any]) -> bool:
    if "enum" in schema and not any(exact(value, v) for v in schema["enum"]):
        return False
    kind = schema["type"]
    if type(kind) is list:
        return any(type(value) is SCALAR_TYPES[k] for k in kind)
    if kind == "object":
        return (
            type(value) is dict
            and set(value) == set(schema["required"])
            and all(_accepts(value[k], v) for k, v in schema["properties"].items())
        )
    if kind == "array":
        return type(value) is list and all(_accepts(v, schema["items"]) for v in value)
    return type(value) is SCALAR_TYPES[kind]


def schema_accepts(value: Any, schema: dict[str, Any]) -> bool:
    """Apply every selected type and enum constraint, including nested contracts."""
    validate_schema(schema)
    return _accepts(value, schema)


def score(text: str, target: Any, schema: dict[str, Any]) -> dict[str, bool]:
    """Keep JSON format, schema admissibility and exact task correctness separate."""
    validate_schema(schema)

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    def nonfinite(_):
        raise ValueError("nonfinite JSON")

    try:
        parsed = json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite)
    except (ValueError, TypeError):
        return {"formatValid": False, "schemaValid": False, "correct": False}
    return {
        "formatValid": type(parsed) is dict,
        "schemaValid": _accepts(parsed, schema),
        "correct": exact(parsed, target),
    }
