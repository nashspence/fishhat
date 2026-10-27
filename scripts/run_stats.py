"""Observational process metrics. Collection is required; values are never a gate."""

from __future__ import annotations

import math
import re
import sys
import time
from pathlib import Path
from typing import Any

import psutil

FORMAT = "fishhat-run-stats/v1"


class RunStats:
    def __init__(self) -> None:
        self.process = psutil.Process()
        self.started = time.perf_counter()
        self.cpu = self.process.cpu_times()
        self.rss_start = self.process.memory_info().rss
        self.rss_sampled_peak = self.rss_start
        self.io_start = self.io()

    def sample(self) -> int:
        rss = self.process.memory_info().rss
        self.rss_sampled_peak = max(self.rss_sampled_peak, rss)
        return rss

    def io(self) -> dict[str, int] | None:
        try:
            counters = self.process.io_counters()
        except (AttributeError, psutil.Error, NotImplementedError):
            return None
        return {key: int(getattr(counters, key)) for key in ("read_bytes", "write_bytes")}

    def finish(self) -> dict[str, Any]:
        rss_end = self.sample()
        cpu = self.process.cpu_times()
        memory = self.process.memory_info()
        if sys.platform == "win32":
            peak = int(memory.peak_wset)
            method = "windows-peak-working-set"
        else:
            import resource

            peak = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
            if sys.platform != "darwin":
                peak *= 1024
            method = "getrusage-self-maxrss"
        io_end = self.io()
        io_delta = (
            {key: io_end[key] - self.io_start[key] for key in io_end}
            if io_end is not None and self.io_start is not None
            else None
        )
        return {
            "format": FORMAT,
            "non_contractual": True,
            "scope": "process-excludes-children",
            "elapsed_seconds": time.perf_counter() - self.started,
            "cpu_user_seconds": cpu.user - self.cpu.user,
            "cpu_system_seconds": cpu.system - self.cpu.system,
            "rss_start_bytes": self.rss_start,
            "rss_end_bytes": rss_end,
            "rss_sampled_peak_bytes": self.rss_sampled_peak,
            "rss_high_water_bytes": peak,
            "rss_high_water_scope": "process-lifetime",
            "rss_high_water_method": method,
            "io_bytes": io_delta,
            "io_available": io_delta is not None,
        }


def parallel_stats(processes: dict[str, Any]) -> dict[str, Any]:
    """Sum disjoint pytest processes; RSS peaks are an upper bound, not simultaneous."""
    if (
        "controller" not in processes
        or len(processes) < 2
        or any(not re.fullmatch(r"controller|gw[0-9]+", name) for name in processes)
        or any(
            not valid_stats(stats) or stats["scope"] != "process-excludes-children"
            for stats in processes.values()
        )
    ):
        raise ValueError("invalid parallel process statistics")
    # CPU totals must survive worker completion order and sorted JSON even on
    # Python versions whose built-in sum uses naive floating-point addition.
    result = dict(processes["controller"])
    for field in (
        "cpu_user_seconds",
        "cpu_system_seconds",
        "rss_start_bytes",
        "rss_end_bytes",
        "rss_sampled_peak_bytes",
        "rss_high_water_bytes",
    ):
        values = [stats[field] for stats in processes.values()]
        result[field] = math.fsum(values) if field.startswith("cpu_") else sum(values)
    available = all(stats["io_available"] for stats in processes.values())
    result.update(
        scope="pytest-controller-and-workers-excludes-other-children",
        rss_sampled_peak_scope="sum-of-per-process-samples-upper-bound",
        rss_high_water_scope="sum-of-process-lifetimes-upper-bound",
        rss_high_water_method="sum-of-process-high-water-marks",
        io_available=available,
        io_bytes={
            key: sum(stats["io_bytes"][key] for stats in processes.values())
            for key in ("read_bytes", "write_bytes")
        }
        if available
        else None,
        processes=processes,
    )
    return result


def valid_stats(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    if value.get("scope") == "pytest-controller-and-workers-excludes-other-children":
        try:
            processes = value["processes"]
            if not isinstance(processes, dict) or any(
                not isinstance(stats, dict) or stats.get("scope") != "process-excludes-children"
                for stats in processes.values()
            ):
                return False
            return value == parallel_stats(processes)
        except (KeyError, TypeError, ValueError):
            return False
    numeric = (
        "elapsed_seconds",
        "cpu_user_seconds",
        "cpu_system_seconds",
        "rss_start_bytes",
        "rss_end_bytes",
        "rss_sampled_peak_bytes",
        "rss_high_water_bytes",
    )
    return bool(
        value.get("format") == FORMAT
        and value.get("non_contractual") is True
        and value.get("scope") == "process-excludes-children"
        and value.get("rss_high_water_scope") == "process-lifetime"
        and value.get("rss_high_water_method")
        in {
            "windows-peak-working-set",
            "getrusage-self-maxrss",
        }
        and all(
            type(value.get(key)) in {int, float} and math.isfinite(value[key]) and value[key] >= 0
            for key in numeric
        )
        and isinstance(value.get("io_available"), bool)
        and (
            value.get("io_bytes", "missing") is None
            if not value["io_available"]
            else (
                isinstance(value["io_bytes"], dict)
                and set(value["io_bytes"]) == {"read_bytes", "write_bytes"}
                and all(type(n) is int and n >= 0 for n in value["io_bytes"].values())
            )
        )
    )


def comparison(
    root: Path, paths: list[str], stats: dict[str, Any], *, success: bool, filtered: bool
) -> dict[str, Any]:
    import tomllib

    policy = tomllib.loads((root / "policy/performance.toml").read_text())
    if policy["format"] != "fishhat-performance-targets/v1" or policy["report_only"] is not True:
        raise ValueError("invalid report-only performance targets")
    if stats["scope"] != "process-excludes-children":
        return {"report_only": True, "status": "not-compared", "reason": "measurement-scope"}
    selected = [(name, spec) for name, spec in policy["targets"].items() if spec["paths"] == paths]
    if not selected or filtered:
        return {"report_only": True, "status": "not-compared", "reason": "custom-selection"}
    name, spec = selected[0]
    observed = {
        "elapsed_seconds": stats["elapsed_seconds"],
        "cpu_seconds": stats["cpu_user_seconds"] + stats["cpu_system_seconds"],
        "rss_high_water_bytes": stats["rss_high_water_bytes"],
    }
    metrics = {}
    for key, actual in observed.items():
        target = spec[key]
        if type(target) not in {int, float} or not math.isfinite(target) or target <= 0:
            raise ValueError("invalid informational performance target")
        metrics[key] = {
            "observed": actual,
            "target": target,
            "status": "not-compared" if not success else "met" if actual < target else "missed",
        }
    return {
        "report_only": True,
        "workload": name,
        "status": "compared" if success else "not-compared",
        "metrics": metrics,
    }


def valid_phases(value: Any) -> bool:
    if not isinstance(value, dict) or not value:
        return False
    for phases in value.values():
        if (
            not isinstance(phases, dict)
            or not phases
            or set(phases) - {"setup", "call", "teardown"}
        ):
            return False
        for phase in phases.values():
            if not isinstance(phase, dict) or phase.get("outcome") not in {
                "passed",
                "failed",
                "skipped",
            }:
                return False
            seconds, rss = phase.get("seconds"), phase.get("rss_sample_bytes")
            if (
                not isinstance(seconds, (int, float))
                or isinstance(seconds, bool)
                or not math.isfinite(seconds)
                or seconds < 0
                or type(rss) is not int
                or rss < 0
                or phase.get("rss_scope") != "process-snapshot-not-test-allocation"
            ):
                return False
    return True
