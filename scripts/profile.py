"""Optional cProfile scaffolding; synthetic or maintained test workloads only."""

from __future__ import annotations

import argparse
import cProfile
import json
import platform
import pstats
import sys
from pathlib import Path
from typing import Any

from scripts.project_policy import ROOT
from scripts.run_stats import RunStats
from scripts.validation import source_identity
from scripts.validation_timeouts import current, invocation

WORKLOADS = {
    "unit": ["tests"],
    "database-qualification": ["tests/test_migrations.py"],
    "engineering-tests": ["tests/test_engineering.py"],
}


def synthetic(size: int, repeats: int) -> int:
    import io

    from fishhat_client.wire import frame, read_frame

    message = {"synthetic": "x" * size}
    for _ in range(repeats):
        assert read_frame(io.BytesIO(frame(message))) == message
    return 0


@invocation
def run(workload: str, size: int, repeats: int) -> int:
    if (
        workload not in {*WORKLOADS, "canonical"}
        or not 1 <= size <= 65536
        or not 1 <= repeats <= 1000
    ):
        raise ValueError("unknown or unbounded profiling workload")
    stats = RunStats()
    source = source_identity()
    profiler = cProfile.Profile()
    if workload == "canonical":
        status = profiler.runcall(synthetic, size, repeats)
    else:
        import pytest

        status = int(
            profiler.runcall(
                pytest.main, ["-q", *WORKLOADS[workload], "--durations=30", "--durations-min=0.25"]
            )
        )
    rows = []
    raw_stats: Any = pstats.Stats(profiler)
    for (filename, line, function), (
        primitive,
        calls,
        own,
        cumulative,
        _,
    ) in raw_stats.stats.items():
        path = Path(filename)
        safe = path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else path.name
        rows.append(
            {
                "file": safe,
                "line": line,
                "function": function,
                "primitive_calls": primitive,
                "calls": calls,
                "own_seconds": own,
                "cumulative_seconds": cumulative,
            }
        )
    directory = ROOT / "artifacts/profiles"
    if not directory.resolve().is_relative_to(ROOT):
        raise ValueError("profile output must stay inside checkout")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (workload + ".json")
    value = {
        "format": "fishhat-profile/v1",
        "non_contractual": True,
        "qualification_eligible": False,
        "production_qualified": False,
        "workload": workload,
        "watchdogs": current().report(),
        "instrumentation": "cProfile-overhead-included",
        "size": size if workload == "canonical" else None,
        "repeats": repeats if workload == "canonical" else None,
        "source_before": source,
        "source_after": source_identity(),
        "profile": {
            "python": platform.python_version(),
            "platform": sys.platform,
            "machine": platform.machine(),
        },
        "exit_status": status,
        "stats": stats.finish(),
        "functions": sorted(rows, key=lambda row: float(row["cumulative_seconds"]), reverse=True)[
            :30
        ],
    }
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")
    temporary.chmod(0o600)
    temporary.replace(path)
    print(
        json.dumps(
            {
                "profile": path.relative_to(ROOT).as_posix(),
                "exit_status": status,
                "non_contractual": True,
            }
        )
    )
    return status


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workload", choices=["canonical", *WORKLOADS], default="canonical")
    parser.add_argument("--size", type=int, default=1024)
    parser.add_argument("--repeats", type=int, default=100)
    args = parser.parse_args()
    raise SystemExit(run(args.workload, args.size, args.repeats))


if __name__ == "__main__":
    main()
