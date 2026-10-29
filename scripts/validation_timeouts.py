"""Validation-only watchdog arithmetic; runtime deadlines retain their own authority."""

from __future__ import annotations

import argparse
import contextlib
import contextvars
import functools
import json
import math
import os
import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Any, ParamSpec, TypeVar

VARIABLE = "FISHHAT_VALIDATION_TIMEOUT_SCALE"
FORMAT = "fishhat-validation-watchdogs/v1"
P = ParamSpec("P")
T = TypeVar("T")


def positive(value: Any) -> float:
    if isinstance(value, bool):
        raise ValueError("watchdog values must be finite and positive")
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("watchdog values must be finite and positive") from None
    if not math.isfinite(number) or number <= 0:
        raise ValueError("watchdog values must be finite and positive")
    return number


@dataclass
class Policy:
    scale: float
    budgets: dict[str, float] = field(default_factory=dict)
    unit_budgets: dict[str, dict[str, float | int]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.scale = positive(self.scale)

    @classmethod
    def resolve(cls, environment: Mapping[str, str] | None = None) -> Policy:
        source = os.environ if environment is None else environment
        try:
            return cls(positive(source.get(VARIABLE, "1")))
        except ValueError:
            raise ValueError(VARIABLE + " must be finite, positive and representable") from None

    def seconds(self, nominal: float, *, maximum: float = threading.TIMEOUT_MAX) -> float:
        nominal = positive(nominal)
        effective = positive(nominal * self.scale)
        if effective > positive(maximum):
            raise ValueError("effective watchdog exceeds backend capacity")
        self.budgets[format(nominal, ".17g")] = effective
        return effective

    def units(self, nominal: float, *, unit_seconds: float, maximum: int) -> int:
        if type(maximum) is not int or maximum <= 0:
            raise ValueError("invalid integer backend capacity")
        unit_seconds = positive(unit_seconds)
        effective = self.seconds(
            nominal, maximum=min(threading.TIMEOUT_MAX, maximum * unit_seconds)
        )
        ratio = Fraction(str(effective)) / Fraction(str(unit_seconds))
        result = (ratio.numerator + ratio.denominator - 1) // ratio.denominator
        if result > maximum or result * unit_seconds > threading.TIMEOUT_MAX:
            raise ValueError("rounded watchdog exceeds backend capacity")
        key = f"{nominal:.17g}/{unit_seconds:.17g}/{maximum}"
        self.unit_budgets[key] = {
            "nominal_seconds": float(nominal),
            "unit_seconds": unit_seconds,
            "maximum_units": maximum,
            "effective_units": result,
        }
        return result

    def report(self) -> dict[str, Any]:
        return {
            "format": FORMAT,
            "scale": self.scale,
            "budgets_seconds": dict(self.budgets),
            "unit_budgets": {key: dict(value) for key, value in self.unit_budgets.items()},
        }


ACTIVE: contextvars.ContextVar[Policy | None] = contextvars.ContextVar("watchdogs", default=None)


def current() -> Policy:
    return ACTIVE.get() or Policy.resolve()


def watchdog(nominal: float) -> float:
    return current().seconds(nominal)


def uv_http_watchdog() -> int:
    return current().units(30, unit_seconds=1, maximum=2**31 - 1)


def audit_http_watchdog() -> int:
    return current().units(15, unit_seconds=1, maximum=2**31 - 1)


def repository_policy(present: str, value: str) -> Policy:
    if present not in {"true", "false"}:
        raise ValueError("invalid repository variable presence")
    return Policy.resolve({VARIABLE: value} if present == "true" else {})


def execution_conditions() -> dict[str, Any]:
    nominal = os.environ.get("FISHHAT_VALIDATION_NOMINAL_MINUTES")
    effective = os.environ.get("FISHHAT_VALIDATION_JOB_MINUTES")
    outer = None
    if nominal is not None or effective is not None:
        actual = positive(effective)
        if not actual.is_integer() or actual > 360:
            raise ValueError("invalid Actions watchdog ceiling")
        outer = {
            "nominal_minutes": positive(nominal),
            "effective_minutes": int(actual),
            "platform_ceiling_minutes": 360,
        }
    return {
        "watchdog_scale": current().scale,
        "job_watchdog": outer,
        "uv_http_timeout_seconds": positive(os.environ.get("UV_HTTP_TIMEOUT", "30")),
    }


def observe_child(value: Any) -> None:
    if not valid_report(value) or value["scale"] != current().scale:
        raise ValueError("child watchdog conditions changed")
    current().budgets.update(value["budgets_seconds"])
    current().unit_budgets.update(value["unit_budgets"])


@contextlib.contextmanager
def using(policy: Policy) -> Iterator[Policy]:
    token = ACTIVE.set(policy)
    try:
        yield policy
    finally:
        ACTIVE.reset(token)


def invocation(function: Callable[P, T]) -> Callable[P, T]:
    @functools.wraps(function)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> T:
        with using(Policy.resolve()) as policy:
            try:
                return function(*args, **kwargs)
            except BaseException as exc:
                if not isinstance(exc, SystemExit) or exc.code not in {None, 0}:
                    print(
                        "Validation watchdog policy: "
                        + json.dumps(policy.report(), sort_keys=True),
                        file=sys.stderr,
                    )
                raise

    return wrapped


@dataclass(frozen=True)
class Deadline:
    end: float

    @classmethod
    def after(cls, nominal: float) -> Deadline:
        now = time.monotonic()
        end = now + watchdog(nominal)
        if not math.isfinite(end) or end <= now:
            raise ValueError("watchdog deadline is not representable")
        return cls(end)

    def remaining(self) -> float:
        return max(0.0, self.end - time.monotonic())


def valid_report(value: Any) -> bool:
    try:
        if (
            set(value) != {"format", "scale", "budgets_seconds", "unit_budgets"}
            or value["format"] != FORMAT
            or type(value["scale"]) not in {int, float}
        ):
            return False
        policy = Policy(value["scale"])
        for nominal, effective in value["budgets_seconds"].items():
            if type(effective) not in {int, float} or policy.seconds(float(nominal)) != effective:
                return False
        for record in value["unit_budgets"].values():
            if (
                set(record)
                != {"nominal_seconds", "unit_seconds", "maximum_units", "effective_units"}
                or type(record["effective_units"]) is not int
            ):
                return False
            if (
                policy.units(
                    record["nominal_seconds"],
                    unit_seconds=record["unit_seconds"],
                    maximum=record["maximum_units"],
                )
                != record["effective_units"]
            ):
                return False
        return bool(
            policy.budgets == value["budgets_seconds"]
            and policy.unit_budgets == value["unit_budgets"]
        )
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return False


@invocation
def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=["seconds", "units", "deadline", "pending", "uv-http", "audit-http", "bootstrap"],
    )
    parser.add_argument("value", type=float, nargs="?")
    parser.add_argument("--github-env", type=Path)
    args = parser.parse_args()
    if args.command == "bootstrap":
        if args.github_env is None:
            parser.error("--github-env is required")
        policy = repository_policy(
            os.environ["FISHHAT_VALIDATION_SCALE_DEFINED"],
            os.environ["FISHHAT_VALIDATION_SCALE_VALUE"],
        )
        with using(policy):
            timeout = uv_http_watchdog()
        with args.github_env.open("a") as output:
            output.write("UV_HTTP_TIMEOUT=" + str(timeout) + "\n")
        print(json.dumps(policy.report(), sort_keys=True))
        return
    if args.command == "pending":
        raise SystemExit(0 if time.monotonic() < positive(args.value) else 1)
    result: float
    if args.command in {"uv-http", "audit-http"}:
        result = uv_http_watchdog() if args.command == "uv-http" else audit_http_watchdog()
    elif args.command == "units":
        result = current().units(positive(args.value), unit_seconds=1, maximum=2**31 - 1)
    elif args.command == "seconds":
        result = watchdog(positive(args.value))
    else:
        result = Deadline.after(positive(args.value)).end
    print(format(result, ".17g"))
    print(json.dumps(current().report(), sort_keys=True), file=sys.stderr)


if __name__ == "__main__":
    main()
