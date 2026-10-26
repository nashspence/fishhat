"""Structural JSON uniqueness without sorting or pairwise object comparisons.

The caller admits strict JSON values first. Typed keys preserve boolean/number
separation, object member order independence and array element order. Hash-table
lookups compare complete keys, so collisions never substitute for equality.
"""

from __future__ import annotations

from collections.abc import Hashable, Iterator
from typing import Any

from jsonschema.exceptions import ValidationError


def structural_key(value: Any) -> Hashable:
    if isinstance(value, dict):
        return ("object", frozenset((key, structural_key(item)) for key, item in value.items()))
    if isinstance(value, list):
        return ("array", tuple(structural_key(item) for item in value))
    return (type(value).__name__, value)


def unique_items(
    validator: Any, enabled: bool, value: Any, schema: Any
) -> Iterator[ValidationError]:
    if not enabled or not validator.is_type(value, "array"):
        return
    seen: set[Hashable] = set()
    for item in value:
        key = structural_key(item)
        if key in seen:
            yield ValidationError("array items are not unique")
            return
        seen.add(key)
