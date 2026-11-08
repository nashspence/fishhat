"""Enroll selected controller tooling on an explicit disposable Linux runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from scripts.run_stats import RunStats, valid_stats
from scripts.validation import source_identity
from scripts.validation_timeouts import current, invocation, watchdog

VERSION = "1:8.2.2+ds-0ubuntu1.18"
PACKAGES = ("qemu-system-x86", "qemu-utils")
QEMU = Path("/usr/bin/qemu-system-x86_64")
COMMAND_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}


class EnrollmentError(RuntimeError):
    def __init__(self, stage: str, reason: str) -> None:
        self.stage = stage
        self.reason = reason
        super().__init__(f"{stage}: {reason}")


@contextmanager
def stage(name: str) -> Iterator[None]:
    started = time.perf_counter()
    print(f"native-controller stage={name} status=started", flush=True)
    try:
        yield
    except BaseException:
        print(
            f"native-controller stage={name} status=failed "
            f"elapsed_seconds={time.perf_counter() - started:.6f}",
            flush=True,
        )
        raise
    else:
        print(
            f"native-controller stage={name} status=passed "
            f"elapsed_seconds={time.perf_counter() - started:.6f}",
            flush=True,
        )


def machine_facts() -> dict[str, Any]:
    fields = dict(
        line.split("=", 1)
        for line in Path("/etc/os-release").read_text().splitlines()
        if "=" in line
    )
    return {
        "platform": sys.platform,
        "machine": platform.machine(),
        "uid": os.geteuid(),
        "distribution": fields.get("ID", "").strip('"'),
        "distribution_version": fields.get("VERSION_ID", "").strip('"'),
        "pid1": Path("/proc/1/comm").read_text().strip(),
        "cgroup_v2": Path("/sys/fs/cgroup/cgroup.controllers").is_file(),
    }


def enroll(environment: Mapping[str, str], *, confirmed: bool) -> dict[str, Any]:
    expected = {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "ImageOS": "ubuntu24",
        "GITHUB_REF": "refs/heads/main",
    }
    if (
        not confirmed
        or any(environment.get(key) != value for key, value in expected.items())
        or environment.get("GITHUB_EVENT_NAME") not in {"push", "workflow_dispatch"}
    ):
        raise EnrollmentError("enrollment", "explicit-disposable-main-runner-required")
    temporary = Path(environment.get("RUNNER_TEMP", ""))
    if not temporary.is_absolute() or not temporary.is_dir():
        raise EnrollmentError("enrollment", "runner-temporary-directory-unavailable")
    if sys.platform != "linux":
        raise EnrollmentError("enrollment", "selected-controller-host-required")
    try:
        facts = machine_facts()
    except OSError:
        raise EnrollmentError("enrollment", "host-facts-unavailable") from None
    if (
        facts["platform"] != "linux"
        or facts["machine"] != "x86_64"
        or facts["uid"] == 0
        or facts["distribution"] != "ubuntu"
        or facts["distribution_version"] != "24.04"
        or facts["pid1"] != "systemd"
        or facts["cgroup_v2"] is not True
    ):
        raise EnrollmentError("enrollment", "selected-controller-host-required")
    return facts


def run(command: list[str], name: str, nominal: float, *, capture: bool = False) -> str:
    try:
        result = subprocess.run(
            command,
            env=COMMAND_ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=watchdog(nominal),
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise EnrollmentError(name, "observation-deadline") from None
    except OSError:
        raise EnrollmentError(name, "command-unavailable") from None
    if result.returncode != 0:
        raise EnrollmentError(name, f"command-exit-{result.returncode}")
    return result.stdout or ""


def root_run(command: list[str], name: str, nominal: float) -> None:
    # The root watchdog can kill privileged descendants. Its observer allows
    # the maintained force-kill grace to finish before timing out itself.
    run(
        [
            "/usr/bin/sudo",
            "-n",
            "/usr/bin/timeout",
            "-k",
            format(watchdog(5), ".17g"),
            format(watchdog(nominal), ".17g"),
            "/usr/bin/env",
            "-i",
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG=C",
            "LC_ALL=C",
            "DEBIAN_FRONTEND=noninteractive",
            *command,
        ],
        name,
        nominal + 10,
    )


def provision() -> dict[str, Any]:
    contact = current().units(30, unit_seconds=1, maximum=2**31 - 1)
    options = [
        "-o",
        f"Acquire::http::Timeout={contact}",
        "-o",
        f"Acquire::https::Timeout={contact}",
        "-o",
        "Acquire::Retries=0",
        "-o",
        f"DPkg::Lock::Timeout={contact}",
    ]
    with stage("package-update"):
        root_run(["/usr/bin/apt-get", *options, "update", "-qq"], "package-update", 300)
    with stage("package-install"):
        root_run(
            [
                "/usr/bin/apt-get",
                *options,
                "install",
                "-y",
                "--no-install-recommends",
                *(f"{name}={VERSION}" for name in PACKAGES),
            ],
            "package-install",
            600,
        )
    with stage("tool-identity"):
        output = run(
            [
                "/usr/bin/dpkg-query",
                "-W",
                "-f",
                "${Package}\t${Version}\t${Architecture}\n",
                *PACKAGES,
            ],
            "tool-identity",
            10,
            capture=True,
        )
        packages: dict[str, str] = {}
        for line in output.splitlines():
            fields = line.split("\t")
            if len(fields) != 3 or fields[0] in packages or fields[1:] != [VERSION, "amd64"]:
                raise EnrollmentError("tool-identity", "package-identity-mismatch")
            packages[fields[0]] = fields[1]
        if set(packages) != set(PACKAGES):
            raise EnrollmentError("tool-identity", "package-identity-mismatch")
        version = run([str(QEMU), "--version"], "tool-identity", 10, capture=True)
        lines = version.splitlines()
        if not lines or lines[0].split()[:4] != ["QEMU", "emulator", "version", "8.2.2"]:
            raise EnrollmentError("tool-identity", "binary-version-mismatch")
        try:
            with QEMU.open("rb") as stream:
                binary_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
        except OSError:
            raise EnrollmentError("tool-identity", "binary-unavailable") from None
        return {"packages": packages, "qemu_version": "8.2.2", "binary_sha256": binary_sha256}


@invocation
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-hosted-only", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        facts = enroll(os.environ, confirmed=args.github_hosted_only)
    except EnrollmentError as error:
        print(f"Refusing: {error.reason}", file=sys.stderr)
        return 2
    before = source_identity()
    metrics = RunStats()
    report: dict[str, Any] = {
        "format": "fishhat-native-controller-enrollment/v1",
        "scope": "disposable-controller-prerequisites-only",
        "guest_booted": False,
        "native_tools_qualified": False,
        "production_qualified": False,
        "host": facts,
        "source_before": before,
    }
    status = 0
    try:
        if not before["clean"]:
            raise EnrollmentError("source", "clean-unchanged-source-required")
        report["controller"] = provision()
        report["status"] = "passed"
    except EnrollmentError as error:
        status = 1
        report.update(status="failed", problem={"stage": error.stage, "reason": error.reason})
    report["source_after"] = source_identity()
    if status == 0 and report["source_after"] != before:
        status = 1
        report.update(
            status="failed",
            problem={"stage": "source", "reason": "clean-unchanged-source-required"},
        )
    report["statistics"] = metrics.finish()
    if not valid_stats(report["statistics"]):
        raise ValueError("invalid required controller statistics")
    report["watchdogs"] = current().report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "native_tools_qualified": False}))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
