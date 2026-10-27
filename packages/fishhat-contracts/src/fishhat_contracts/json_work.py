"""Structural JSON uniqueness without sorting or pairwise object comparisons.

The caller admits strict JSON values first. Typed keys preserve boolean/number
separation, object member order independence and array element order. Hash-table
lookups compare complete keys, so collisions never substitute for equality.
"""

from __future__ import annotations

from collections.abc import Callable, Hashable, Iterable, Iterator
from typing import Any

from jsonschema.exceptions import ValidationError


def lexical(values: Iterable[Any], key: Callable[[Any], str] = str) -> list[Any]:
    """Stable UTF-8 radix ordering in total key bytes.

    Each partition has at most 256 byte values. Sorting that fixed alphabet
    adds no collection-size factor; prefixes are visited once per key byte.
    UTF-8 byte order agrees with Unicode scalar order for admitted JSON text.
    """
    pending = [([(key(value).encode("utf-8"), value) for value in values], 0)]
    result: list[Any] = []
    while pending:
        group, offset = pending.pop()
        if len(group) < 2:
            result.extend(value for _, value in group)
            continue
        children: dict[int, list[tuple[bytes, Any]]] = {}
        for encoded, value in group:
            if offset == len(encoded):
                result.append(value)
            else:
                children.setdefault(encoded[offset], []).append((encoded, value))
        pending.extend((children[byte], offset + 1) for byte in sorted(children, reverse=True))
    return result


def ordered_json(value: Any) -> Any:
    """Preserve exact JSON values while ordering every object's members linearly."""
    if isinstance(value, dict):
        return {key: ordered_json(value[key]) for key in lexical(value)}
    if isinstance(value, list):
        return [ordered_json(item) for item in value]
    return value


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
