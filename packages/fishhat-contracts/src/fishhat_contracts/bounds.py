"""Small operation-owned work/extent declarations; no timing or memory thresholds."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import ParamSpec, TypeVar

P = ParamSpec("P")
T = TypeVar("T")


@dataclass(frozen=True)
class Bounds:
    id: str
    work: str
    extent: str
    limits: tuple[tuple[str, int], ...]
    capacity: tuple[str, ...]
    proofs: tuple[str, ...]
    linear_proofs: tuple[str, ...] = ()
    growth: str = "linear"
    qualification: str = "reference-model"


def bounds(declaration: Bounds) -> Callable[[Callable[P, T]], Callable[P, T]]:
    def bind(operation: Callable[P, T]) -> Callable[P, T]:
        if hasattr(operation, "__growth_bounds__"):
            raise ValueError("operation already owns a bounds declaration")
        operation.__growth_bounds__ = declaration  # type: ignore[attr-defined]
        return operation

    return bind
