from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from filelock import FileLock
from fishhat_contracts import canonical

from scripts.check_evidence import entrypoints, execution_origin, valid_evidence
from scripts.project_policy import ROOT
from scripts.run_stats import valid_phases, valid_stats

FORMAT = "fishhat-validation/v1"
OVERRIDES = (
    "PYTEST_ADDOPTS",
    "PYTEST_PLUGINS",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
    "PYTHONPATH",
    "PYTHONOPTIMIZE",
    "MYPYPATH",
    "MYPY_CONFIG_FILE_DIR",
    "RUFF_OUTPUT_FORMAT",
    "RUFF_NO_CACHE",
    "COVERAGE_PROCESS_START",
)
# These are complete repository checks. Other/custom invocations are iteration records.
CANONICAL = {
    "unit": ["python", "-m", "pytest", "-q", "tests"],
    "ruff": ["python", "-m", "ruff", "check", "."],
    "format-check": ["python", "-m", "ruff", "format", "--check", "."],
    "mypy": ["python", "-m", "mypy"],
    "compile": [
        "python",
        "-m",
        "compileall",
        "-q",
        "packages",
        "fishhat",
        "some-implementations",
        "scripts",
        "tests",
    ],
    "contracts": ["python", "-m", "scripts.check_contracts"],
    "policy": ["python", "-m", "scripts.project_policy", "--history"],
    "license": ["python", "-m", "reuse", "lint"],
    "governance": ["python", "-m", "scripts.check_repository", "--scope", "full"],
    "dist": ["python", "-m", "scripts.distributions", "build"],
    "dist-smoke": ["python", "-m", "scripts.distributions", "smoke-fresh"],
    "operation-qualification": ["python", "-m", "scripts.operation_qualification", "check"],
}
TEST_TARGETS = {"unit", "database-qualification"}
CANONICAL["database-qualification"] = ["python", "-m", "pytest", "-q", "tests/test_migrations.py"]
CANONICAL["engineering"] = ["python", "-m", "scripts.engineering", "check"]
TARGETS = set(CANONICAL) | {
    "ruff-fix",
    "format",
    "bundle",
    "audit",
    "profile",
    "database-qualification",
}
SAFE_NODE = re.compile(r"tests/[A-Za-z0-9_./-]+\.py(?:::[A-Za-z0-9_]+)+(?:\[[A-Za-z0-9_.-]+\])?")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def source_identity(root: Path = ROOT) -> dict[str, Any]:
    def git(*args: str) -> bytes:
        return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.DEVNULL)

    sha = git("rev-parse", "HEAD").decode().strip()
    status = git("status", "--porcelain", "--untracked-files=all")
    fingerprint = hashlib.sha256(status)
    fingerprint.update(git("diff", "HEAD", "--binary"))
    fingerprint.update(git("diff", "--cached", "--binary"))
    for name in sorted(git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0")):
        if name:
            path = root / os.fsdecode(name)
            fingerprint.update(name)
            fingerprint.update(
                path.read_bytes() if not path.is_symlink() else os.fsencode(os.readlink(path))
            )
    return {"commit": sha, "clean": not status, "fingerprint": fingerprint.hexdigest()}


def test_command(command: list[str]) -> list[str]:
    """Only reporting and execution distribution flags preserve complete selection."""
    normalized: list[str] = []
    parts = iter(command)
    for part in parts:
        if part in {"-n", "--numprocesses"}:
            value = next(parts, "")
            if not re.fullmatch(r"[0-9]+", value):
                normalized.extend((part, value))
        elif not re.fullmatch(
            r"--junitxml=artifacts/[A-Za-z0-9_./-]+\.xml|--durations=[0-9]+|"
            r"--durations-min=[0-9.]+|-n[0-9]+|--numprocesses=[0-9]+|"
            r"--dist=(?:load|worksteal)|--max-worker-restart=0",
            part,
        ):
            normalized.append(part)
    return normalized


def selection(target: str, command: list[str]) -> dict[str, Any]:
    normalized = list(command)
    if target in TEST_TARGETS:
        normalized = test_command(command)
    overrides = [key for key in OVERRIDES if os.environ.get(key)]
    # Record source test references only; arbitrary arguments and environment values stay out.
    tests = [
        part
        for part in command
        if SAFE_NODE.fullmatch(part) or re.fullmatch(r"tests(?:/[A-Za-z0-9_./-]+)?", part)
    ]
    return {
        "canonical": normalized == CANONICAL.get(target) and not overrides,
        "tests": tests if target in TEST_TARGETS else [],
        "invocation_sha256": digest(command),
        "work_sha256": digest(normalized),
        "environment_overrides": overrides,
    }


def read_test_results(path: Path, root: Path = ROOT) -> dict[str, Any] | None:
    if not path.is_file() or path.is_symlink():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    collected = value["collected"]
    outcomes = value["outcomes"]
    if (
        not valid_stats(value.get("stats"))
        or not isinstance(value.get("phases"), dict)
        or any(
            not valid_phases({node: phases}) if phases else outcomes.get(node) != "not-executed"
            for node, phases in value.get("phases", {}).items()
        )
        or value.get("profiling_target", {}).get("report_only") is not True
        or set(value.get("phases", {})) != set(collected)
        or not collected
        or len(collected) != len(set(collected))
        or not all(SAFE_NODE.fullmatch(node) for node in collected)
        or set(outcomes) != set(collected)
        or any(
            outcome not in {"passed", "failed", "skipped", "not-executed"}
            for outcome in outcomes.values()
        )
    ):
        return None
    result = {
        "stats": value["stats"],
        "phases": value["phases"],
        "fixtures": value["fixtures"],
        "profiling_target": value["profiling_target"],
        "collected_sha256": digest(sorted(collected)),
        "outcomes": outcomes,
        "exit_status": value["exit_status"],
        "evidence": value.get("evidence"),
        "subtests": value.get("subtests", {}),
        "profile": value.get("profile"),
    }
    return result if valid_evidence(result, root) else None


def full_check_passed(receipt: dict[str, Any]) -> bool:
    tests = receipt.get("tests")
    return bool(
        receipt["state"] == "completed"
        and receipt["exit_status"] == 0
        and receipt["selection"]["canonical"]
        and receipt["source_before"]["clean"]
        and receipt["source_before"] == receipt["source_after"]
        and (
            receipt["target"] not in TEST_TARGETS
            or (
                tests
                and valid_stats(tests.get("stats"))
                and tests["exit_status"] == 0
                and tests["outcomes"]
                and all(result in {"passed", "skipped"} for result in tests["outcomes"].values())
            )
        )
    )


def write_receipt(path: Path, value: dict[str, Any]) -> None:
    content = json.dumps(value, indent=2, sort_keys=True) + "\n"
    with FileLock(str(path.parent / ".lock"), timeout=10):
        temporary = path.with_suffix(".tmp")
        temporary.write_text(content, encoding="utf-8", newline="\n")
        temporary.chmod(0o600)
        temporary.replace(path)


def run(target: str, command: list[str], root: Path = ROOT) -> int:
    if target not in TARGETS or not command or command[0] not in {"python", "uv"}:
        raise ValueError("unknown validation target or executable")
    directory = root / "artifacts/validation"
    if not directory.resolve().is_relative_to(root.resolve()):
        raise ValueError("validation receipts must stay inside the checkout")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (uuid.uuid4().hex + ".json")
    started = time.monotonic()
    receipt: dict[str, Any] = {
        "format": FORMAT,
        "scope": "repository-validation",
        "id": path.stem,
        "target": target,
        "source_before": source_identity(root),
        "source_after": None,
        "selection": selection(target, command),
        "profile": {
            "platform": sys.platform,
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "started_at": datetime.now(UTC).isoformat(),
        "duration_seconds": None,
        "state": "running",
        "exit_status": None,
        "tests": None,
        "full_check_passed": False,
        "production_qualified": False,
        "check_purpose": entrypoints(root).get("make:" + target),
        "execution_origin": execution_origin(),
    }
    write_receipt(path, receipt)
    status = 127
    state = "completed"
    child = None
    with tempfile.TemporaryDirectory(prefix="fishhat-test-results-") as temporary:
        report = Path(temporary) / "tests.json"
        invocation = list(command)
        environment = dict(os.environ)
        if target in TEST_TARGETS and command[1:3] == ["-m", "pytest"]:
            invocation[3:3] = ["-p", "scripts.validation_pytest"]
            environment["FISHHAT_TEST_REPORT"] = str(report)
            environment["FISHHAT_TEST_ORIGIN"] = path.stem
        try:
            child = subprocess.Popen(invocation, cwd=root, env=environment)
            status = child.wait()
            if status < 0:
                state, status = "interrupted", 128 - status
        except KeyboardInterrupt:
            state, status = "interrupted", 130
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        except OSError:
            print("Validation executable could not be started", file=sys.stderr)
        finally:
            try:
                receipt["tests"] = (
                    read_test_results(report, root) if target in TEST_TARGETS else None
                )
                if receipt["tests"] and receipt["tests"]["evidence"]["origin"] != path.stem:
                    receipt["tests"] = None
                receipt["source_after"] = source_identity(root)
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                receipt["source_after"] = None
            if status == 0 and target in TEST_TARGETS and receipt["tests"] is None:
                status = 2
                print("Required test statistics/results are missing or invalid", file=sys.stderr)
            receipt.update(
                state=state,
                exit_status=status,
                duration_seconds=round(time.monotonic() - started, 6),
            )
            receipt["full_check_passed"] = full_check_passed(receipt)
            write_receipt(path, receipt)
    print(
        json.dumps(
            {
                "receipt": path.relative_to(root).as_posix(),
                "exit_status": status,
                "full_check_passed": receipt["full_check_passed"],
            }
        ),
        file=sys.stderr,
    )
    return status


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["run"])
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    args, command = parser.parse_known_args()
    if command[:1] == ["--"]:
        command = command[1:]
    try:
        status = run(args.target, command)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit("validation receipt could not be recorded") from None
    raise SystemExit(status)


if __name__ == "__main__":
    main()
