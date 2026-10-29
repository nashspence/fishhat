"""Structural JSON uniqueness without sorting or pairwise object comparisons.

The caller admits strict JSON values first. Typed keys preserve boolean/number
separation, object member order independence and array element order. Hash-table
lookups compare complete keys, so collisions never substitute for equality.
"""

from __future__ import annotations

from collections.abc import Callable, Hashable, Iterable, Iterator
from fractions import Fraction
from io import BytesIO
from typing import Any

import rfc8785
from jsonschema.exceptions import ValidationError


def lexical(values: Iterable[Any], key: Callable[[Any], str] = str) -> list[Any]:
    """Stable UTF-8 radix ordering in total key bytes.

    Each partition has at most 256 byte values. Sorting that fixed alphabet
    adds no collection-size factor; prefixes are visited once per key byte.
    UTF-8 byte order agrees with Unicode scalar order for admitted JSON text.
    """
    return _radix(values, key, "utf-8")


def _radix(values: Iterable[Any], key: Callable[[Any], str], encoding: str) -> list[Any]:
    pending = [([(key(value).encode(encoding), value) for value in values], 0)]
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


def jcs_bytes(value: Any) -> bytes:
    """RFC 8785 with linear key ordering and the pinned library's scalar encoder.

    UTF-16BE byte order is unsigned UTF-16 code-unit order, including pairs for
    supplementary characters. Sorting each fixed byte alphabet is constant work;
    unlike a general comparison sort, common prefixes add only their byte extent.
    The caller validates the complete JSON value before entering this encoder.
    """
    sink = BytesIO()
    _jcs_write(value, sink)
    return sink.getvalue()


def _jcs_write(value: Any, sink: BytesIO) -> None:
    if isinstance(value, dict):
        sink.write(b"{")
        for index, key in enumerate(_radix(value, str, "utf-16be")):
            if index:
                sink.write(b",")
            rfc8785.dump(key, sink)
            sink.write(b":")
            _jcs_write(value[key], sink)
        sink.write(b"}")
    elif isinstance(value, list):
        sink.write(b"[")
        for index, item in enumerate(value):
            if index:
                sink.write(b",")
            _jcs_write(item, sink)
        sink.write(b"]")
    else:
        rfc8785.dump(value, sink)


def structural_key(value: Any) -> Hashable:
    if isinstance(value, dict):
        return ("object", frozenset((key, structural_key(item)) for key, item in value.items()))
    if isinstance(value, list):
        return ("array", tuple(structural_key(item) for item in value))
    if type(value) in (int, float):
        # JSON Schema compares numbers mathematically, including 1 == 1.0 and
        # negative zero == zero. Booleans remain a distinct JSON type.
        return ("number", value)
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


def multiple_of(validator: Any, divisor: Any, value: Any, schema: Any) -> Iterator[ValidationError]:
    """Compare exact JCS decimal values, avoiding binary division roundoff.

    Both numbers have already entered the finite binary64/safe-integer profile.
    Their canonical decimal lengths and integer arithmetic are bounded by that
    numeric domain, independently of collection extent. Schema admission requires
    a positive divisor. No source value is included in rejection text.
    """
    if not validator.is_type(value, "number"):
        return
    numerator = Fraction(rfc8785.dumps(value).decode("ascii"))
    denominator = Fraction(rfc8785.dumps(divisor).decode("ascii"))
    if denominator <= 0 or (numerator / denominator).denominator != 1:
        yield ValidationError("number is not a multiple of the declared divisor")
