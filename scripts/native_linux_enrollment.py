"""Enroll selected controller tooling on an explicit disposable Linux runner."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import platform
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from scripts.native_linux_exhaustion import (
    qualify_allocation_cleanup,
    qualify_exhaustion,
    qualify_partial_quota,
    qualify_release_reuse,
)
from scripts.native_linux_guest import Guest, GuestBootError, guest_session, provision_tools
from scripts.native_linux_images import GuestInputError, GuestInputs, guest_inputs
from scripts.native_linux_processes import qualify_process_kill
from scripts.native_linux_reboot import (
    REBOOT,
    GuestRebootError,
    RebootObservationInterrupted,
    host_custody,
    observe_removed_resources,
    qualify_reboot,
)
from scripts.native_linux_restart import qualify_restart
from scripts.native_linux_restore import qualify_restore
from scripts.native_linux_restored_boot import qualify_restored_boot
from scripts.native_linux_snapshots import DiskSnapshots, qualify_capture
from scripts.native_linux_storage import GuestStorageError, qualify_storage
from scripts.native_linux_transport import qualify_transport_loss
from scripts.run_stats import RunStats, valid_stats
from scripts.validation import source_identity
from scripts.validation_timeouts import Deadline, current, invocation, watchdog

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


def controller_remaining(deadline: Deadline) -> float:
    remaining = deadline.remaining()
    if remaining <= 0:
        raise EnrollmentError("controller-probe", "observation-deadline")
    return remaining


def child_exited(process: subprocess.Popen[bytes]) -> bool:
    # WNOWAIT retains our child identity until cleanup; poll() would reap it.
    return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def start_controller(endpoint: Path, identity: str) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [
            str(QEMU),
            "-no-user-config",
            "-machine",
            "none",
            "-accel",
            "tcg",
            "-S",
            "-nodefaults",
            "-display",
            "none",
            "-monitor",
            "none",
            "-nic",
            "none",
            "-m",
            "128M",
            "-smp",
            "1",
            "-uuid",
            identity,
            "-qmp",
            f"unix:{endpoint},server=on,wait=off",
        ],
        cwd=endpoint.parent,
        env=COMMAND_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        umask=0o077,
    )


def stop_controller(process: subprocess.Popen[bytes]) -> None:
    with stage("controller-cleanup"):
        try:
            child_exited(process)
            if os.getpgid(process.pid) != process.pid:
                os.kill(process.pid, signal.SIGKILL)
                process.wait(timeout=watchdog(5))
                raise EnrollmentError("controller-cleanup", "process-group-mismatch")
            os.killpg(process.pid, signal.SIGTERM)
            # A suspended owned controller must receive its pending termination.
            os.killpg(process.pid, signal.SIGCONT)
            grace = Deadline.after(5)
            while not child_exited(process) and grace.remaining() > 0:
                time.sleep(min(0.02, grace.remaining()))
            # Our unreaped leader still reserves the group identity. Kill any
            # remaining owned members before reaping it and releasing that ID.
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=watchdog(5))
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return
            raise EnrollmentError("controller-cleanup", "process-group-remains")
        except (OSError, subprocess.TimeoutExpired):
            raise EnrollmentError("controller-cleanup", "owned-process-not-reaped") from None


def controller_executable(
    process: subprocess.Popen[bytes], expected: str, deadline: Deadline
) -> None:
    if child_exited(process) or os.getpgid(process.pid) != process.pid:
        raise EnrollmentError("controller-identity", "owned-controller-unavailable")
    digest = hashlib.sha256()
    with Path(f"/proc/{process.pid}/exe").open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            controller_remaining(deadline)
            digest.update(chunk)
    controller_remaining(deadline)
    if digest.hexdigest() != expected:
        raise EnrollmentError("controller-identity", "executable-mismatch")


def controller_connection(
    endpoint: Path, process: subprocess.Popen[bytes], deadline: Deadline
) -> socket.socket:
    while True:
        if child_exited(process):
            raise EnrollmentError("controller-identity", "owned-controller-unavailable")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(controller_remaining(deadline))
            connection.connect(str(endpoint))
            return connection
        except (FileNotFoundError, ConnectionRefusedError):
            connection.close()
            time.sleep(min(0.02, controller_remaining(deadline)))
        except BaseException:
            connection.close()
            raise


def qmp_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate QMP fields")
    return result


def qmp_constant(value: str) -> None:
    raise ValueError("non-JSON QMP constant")


def qmp_version_matches(value: Any, expected: dict[str, int]) -> bool:
    qemu = value.get("qemu") if isinstance(value, dict) else None
    return (
        isinstance(qemu, dict)
        and qemu == expected
        and all(type(part) is int for part in qemu.values())
    )


class Qmp:
    def __init__(self, connection: socket.socket, deadline: Deadline) -> None:
        self.connection = connection
        self.deadline = deadline
        self.pending = b""
        self.identifier = 0

    def receive(self) -> dict[str, Any]:
        parts: list[bytes] = []
        size = 0
        chunk, self.pending = self.pending, b""
        while True:
            controller_remaining(self.deadline)
            end = chunk.find(b"\n")
            part = chunk if end < 0 else chunk[:end]
            parts.append(part)
            size += len(part)
            if size > 65536:
                raise EnrollmentError("controller-probe", "invalid-control-frame")
            if end >= 0:
                self.pending = chunk[end + 1 :]
                break
            self.connection.settimeout(controller_remaining(self.deadline))
            chunk = self.connection.recv(4096)
            if not chunk:
                raise EnrollmentError("controller-probe", "control-connection-closed")
        try:
            value = json.loads(
                b"".join(parts).decode("utf-8"),
                object_pairs_hook=qmp_fields,
                parse_constant=qmp_constant,
            )
        except (ValueError, UnicodeError, RecursionError):
            raise EnrollmentError("controller-probe", "invalid-control-frame") from None
        if not isinstance(value, dict):
            raise EnrollmentError("controller-probe", "invalid-control-frame")
        return value

    def command(self, name: str) -> dict[str, Any]:
        self.identifier += 1
        self.connection.settimeout(controller_remaining(self.deadline))
        self.connection.sendall(
            json.dumps({"execute": name, "id": self.identifier}).encode("ascii") + b"\n"
        )
        while True:
            response = self.receive()
            if "event" in response and not {"return", "error", "id"} & response.keys():
                continue
            if (
                type(response.get("id")) is not int
                or response.get("id") != self.identifier
                or "error" in response
                or "event" in response
            ):
                raise EnrollmentError("controller-probe", "uncorrelated-or-rejected-command")
            value = response.get("return")
            if not isinstance(value, dict):
                raise EnrollmentError("controller-probe", "invalid-control-response")
            return value


@contextmanager
def owned_controller(
    temporary: Path,
    launch: Callable[[Path, str], subprocess.Popen[bytes]] | None = None,
    *,
    enrollment: str | None = None,
) -> Iterator[tuple[subprocess.Popen[bytes], Path, str]]:
    if enrollment is not None:
        try:
            if str(uuid.UUID(enrollment)) != enrollment:
                raise ValueError("noncanonical enrollment")
        except (ValueError, TypeError, AttributeError):
            raise EnrollmentError("controller-identity", "invalid-fixture-enrollment") from None
    with tempfile.TemporaryDirectory(prefix="fhc-", dir=temporary) as directory:
        endpoint = Path(directory) / "qmp"
        identity = enrollment if enrollment is not None else str(uuid.uuid4())
        process = (start_controller if launch is None else launch)(endpoint, identity)
        try:
            yield process, endpoint, identity
        finally:
            stop_controller(process)


@contextmanager
def controller_channel(
    process: subprocess.Popen[bytes],
    endpoint: Path,
    identity: str,
    binary_sha256: str,
    deadline: Deadline,
) -> Iterator[Qmp]:
    version = {"major": 8, "minor": 2, "micro": 2}
    try:
        controller_executable(process, binary_sha256, deadline)
        with controller_connection(endpoint, process, deadline) as connection:
            peer = struct.unpack(
                "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if peer != (process.pid, os.geteuid(), os.getegid()):
                raise EnrollmentError("controller-identity", "control-peer-mismatch")
            qmp = Qmp(connection, deadline)
            greeting = qmp.receive().get("QMP")
            greeting_version = greeting.get("version") if isinstance(greeting, dict) else None
            if not qmp_version_matches(greeting_version, version):
                raise EnrollmentError("controller-identity", "greeting-version-mismatch")
            if qmp.command("qmp_capabilities") != {}:
                raise EnrollmentError("controller-probe", "capabilities-rejected")
            if not qmp_version_matches(qmp.command("query-version"), version):
                raise EnrollmentError("controller-identity", "query-version-mismatch")
            if qmp.command("query-uuid").get("UUID") != identity:
                raise EnrollmentError("controller-identity", "instance-mismatch")
            status = qmp.command("query-status")
            if status.get("running") is not False or status.get("status") != "prelaunch":
                raise EnrollmentError("controller-identity", "controller-not-quiescent")
            if qmp.command("query-kvm").get("enabled") is not False:
                raise EnrollmentError("controller-identity", "unexpected-accelerator")
            controller_executable(process, binary_sha256, deadline)
            yield qmp
    except TimeoutError:
        raise EnrollmentError("controller-probe", "observation-deadline") from None
    except OSError:
        raise EnrollmentError("controller-probe", "controller-unavailable") from None


def probe_controller(binary_sha256: str, temporary: Path) -> dict[str, Any]:
    deadline = Deadline.after(30)
    try:
        with owned_controller(temporary) as (process, endpoint, identity):
            with controller_channel(process, endpoint, identity, binary_sha256, deadline):
                pass
        return {
            "instance_uuid": identity,
            "qmp_version": {"major": 8, "minor": 2, "micro": 2},
            "executable_sha256": binary_sha256,
            "unix_peer_verified": True,
            "accelerator": "tcg",
            "machine": "none",
            "status": "prelaunch",
            "running": False,
            "process_reaped": True,
            "temporary_resources_removed": True,
        }
    except OSError:
        raise EnrollmentError("controller-probe", "controller-unavailable") from None


def controller_faults(binary_sha256: str, temporary: Path, results: list[dict[str, Any]]) -> None:
    expected = {
        "socket-setup": {
            ("controller-identity", "owned-controller-unavailable"),
            ("controller-probe", "controller-unavailable"),
        },
        "controller-loss": {
            ("controller-probe", "controller-unavailable"),
            ("controller-probe", "control-connection-closed"),
        },
        "control-stall": {("controller-probe", "observation-deadline")},
    }
    for scenario, problems in expected.items():
        metrics = RunStats()
        process: subprocess.Popen[bytes] | None = None
        endpoint: Path | None = None
        case: dict[str, Any] = {
            "scenario": scenario,
            "scope": "disposable-controller-injected-fault-only",
            "status": "failed",
            "expected_failure_verified": False,
            "identity_verified_before_fault": False,
            "fault_injection_verified": False,
            "process_reaped": False,
            "temporary_resources_removed": False,
        }
        results.append(case)

        def launch(
            address: Path,
            identity: str,
            *,
            socket_fault: bool = scenario == "socket-setup",
            record: dict[str, Any] = case,
        ) -> subprocess.Popen[bytes]:
            nonlocal process, endpoint
            endpoint = address
            if socket_fault:
                address.mkdir(mode=0o700)
                record["fault_injection_verified"] = address.is_dir()
            process = start_controller(address, identity)
            return process

        try:
            with stage(f"fault-{scenario}"):
                try:
                    deadline = Deadline.after(30)
                    with owned_controller(temporary, launch) as (child, address, identity):
                        with controller_channel(
                            child, address, identity, binary_sha256, deadline
                        ) as qmp:
                            if scenario == "socket-setup":
                                raise EnrollmentError(
                                    "controller-faults", "setup-fault-not-observed"
                                )
                            case["identity_verified_before_fault"] = True
                            os.kill(
                                child.pid,
                                signal.SIGKILL if scenario == "controller-loss" else signal.SIGSTOP,
                            )
                            while True:
                                controller_remaining(deadline)
                                if scenario == "controller-loss":
                                    transitioned = child_exited(child)
                                else:
                                    transitioned = (
                                        os.waitid(
                                            os.P_PID,
                                            child.pid,
                                            os.WSTOPPED | os.WNOHANG | os.WNOWAIT,
                                        )
                                        is not None
                                    )
                                if transitioned:
                                    case["fault_injection_verified"] = True
                                    break
                                time.sleep(min(0.02, controller_remaining(deadline)))
                            # This is a new fault-observation stage, not a reset
                            # of the shared controller-acquisition deadline.
                            qmp.deadline = Deadline.after(1)
                            qmp.command("query-status")
                except EnrollmentError as error:
                    case["problem"] = {"stage": error.stage, "reason": error.reason}
                except OSError:
                    case["problem"] = {
                        "stage": "controller-faults",
                        "reason": "fault-injection-unavailable",
                    }
                else:
                    case["status"] = "passed"
                case["process_reaped"] = process is not None and process.returncode is not None
                case["temporary_resources_removed"] = (
                    endpoint is not None and not endpoint.parent.exists()
                )
                problem = case.get("problem", {})
                case["expected_failure_verified"] = (
                    (problem.get("stage"), problem.get("reason")) in problems
                    and case["fault_injection_verified"]
                    and (scenario == "socket-setup" or case["identity_verified_before_fault"])
                    and case["process_reaped"]
                    and case["temporary_resources_removed"]
                )
                if not case["expected_failure_verified"]:
                    raise EnrollmentError("controller-faults", "required-failure-proof-missing")
        finally:
            case["statistics"] = metrics.finish()
            if not valid_stats(case["statistics"]):
                raise ValueError("invalid required controller fault statistics")


@contextmanager
def admitted_guest_controller(guest: Guest, binary_sha256: str, temporary: Path) -> Iterator[Path]:
    with owned_controller(temporary, guest.launch, enrollment=guest.enrollment) as (
        process,
        endpoint,
        identity,
    ):
        guest.report["control_endpoint"] = str(endpoint)
        with stage("guest-controller"):
            with controller_channel(
                process, endpoint, identity, binary_sha256, Deadline.after(30)
            ) as qmp:
                guest.listener()
                if qmp.command("cont") != {}:
                    raise GuestBootError("guest-start-rejected")
                guest.report["controller_verified"] = {
                    "instance_uuid": identity,
                    "qmp_version": {"major": 8, "minor": 2, "micro": 2},
                    "executable_sha256": binary_sha256,
                    "unix_peer_verified": True,
                    "machine": "pc-q35-8.2",
                    "accelerator": "tcg",
                    "memory_mib": 2048,
                    "vcpus": 2,
                    "started_from_verified_prelaunch": True,
                }
        guest.verify_process = lambda deadline: controller_executable(
            process, binary_sha256, deadline
        )
        yield endpoint


def captured_guest_checks(
    guest: Guest,
    custody: dict[str, Any],
    snapshots: DiskSnapshots,
    temporary: Path,
    binary_sha256: str,
    report: dict[str, Any],
) -> None:
    qualify_restore(
        guest,
        custody,
        snapshots,
        report["snapshot_capture"],
        temporary,
        stage,
        report["private_restore"],
    )
    report["restored_boot"] = {}
    qualify_restored_boot(
        guest,
        custody,
        snapshots,
        report["snapshot_capture"],
        temporary,
        stage,
        lambda child: admitted_guest_controller(child, binary_sha256, temporary),
        report["restored_boot"],
    )


def boot_guest(
    inputs: GuestInputs,
    tools: dict[str, Any],
    binary_sha256: str,
    temporary: Path,
    report: dict[str, Any],
    *,
    storage_failure: bool = False,
    reboot_failure: bool = False,
) -> None:
    if storage_failure and reboot_failure:
        raise GuestRebootError("conflicting-guest-faults")
    with stage("guest-session"):
        with guest_session(inputs, temporary, run, tools, QEMU, report) as guest:
            with admitted_guest_controller(guest, binary_sha256, temporary) as endpoint:
                with stage("guest-readiness"):
                    assert guest.verify_process is not None
                    guest.ready(guest.verify_process)
                with stage("guest-refusals"):
                    guest.refusals()
                if not storage_failure:
                    report["reboot"] = {}
                    with stage("guest-reboot"):
                        if reboot_failure:
                            qualify_reboot(
                                guest,
                                endpoint,
                                stage,
                                temporary,
                                report["reboot"],
                                interrupt_observation=True,
                            )
                        else:
                            qualify_reboot(guest, endpoint, stage, temporary, report["reboot"])
                    with stage("guest-refusals-after-reboot"):
                        guest.refusals()
                report["storage"] = {}
                with stage("guest-storage"):
                    qualify_storage(guest, stage, report["storage"], inject_failure=storage_failure)
                report["process_kill"] = {}
                with stage("guest-process-kill"):
                    qualify_process_kill(guest, stage, temporary, report["process_kill"])
                report["transport_loss"] = {}
                with stage("guest-transport-loss"):
                    qualify_transport_loss(guest, stage, temporary, report["transport_loss"])
                report["exhaustion"] = {}
                with stage("guest-exhaustion"):
                    qualify_exhaustion(guest, stage, temporary, report["exhaustion"])
                report["allocation_release_reuse"] = {}
                with stage("guest-allocation-release-reuse"):
                    qualify_release_reuse(
                        guest, stage, temporary, report["allocation_release_reuse"]
                    )
                report["allocation_cleanup"] = {}
                with stage("guest-allocation-cleanup"):
                    qualify_allocation_cleanup(
                        guest, stage, temporary, report["allocation_cleanup"]
                    )
                report["partial_quota"] = {}
                with stage("guest-partial-quota"):
                    qualify_partial_quota(guest, stage, temporary, report["partial_quota"])
                with stage("snapshot-source-custody"):
                    custody = host_custody(guest, endpoint, Deadline.after(30))
                    report["snapshot_source_custody"] = custody
            report["snapshot_capture"] = {}
            report["private_restore"] = {}
            with stage("guest-cold-snapshot-capture"):
                qualify_capture(
                    guest,
                    custody,
                    temporary,
                    stage,
                    report["snapshot_capture"],
                    consume=lambda snapshots: captured_guest_checks(
                        guest, custody, snapshots, temporary, binary_sha256, report
                    ),
                )
            report["retained_restart"] = {}
            with stage("guest-retained-input-cold-restart"):
                qualify_restart(
                    guest,
                    custody,
                    temporary,
                    stage,
                    lambda child: admitted_guest_controller(child, binary_sha256, temporary),
                    report["retained_restart"],
                )


def endpoint_closed(endpoint: dict[str, Any]) -> None:
    port = endpoint.get("port")
    if (
        endpoint.get("address") != "127.0.0.1"
        or endpoint.get("owned_listener") is not True
        or type(port) is not int
        or not 0 < port < 65536
    ):
        raise GuestStorageError("cleanup-endpoint-not-verified")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as observer:
            observer.settimeout(watchdog(3))
            result = observer.connect_ex(("127.0.0.1", port))
    except OSError:
        raise GuestStorageError("cleanup-endpoint-observation-unavailable") from None
    if result != errno.ECONNREFUSED:
        raise GuestStorageError("cleanup-endpoint-still-available")


def verify_restored_boot_cleanup(restored: dict[str, Any]) -> None:
    if (
        restored.get("status") != "passed"
        or restored.get("restored_boot_verified") is not True
        or restored.get("private_inputs", {}).get("temporary_resources_removed") is not True
        or restored.get("writable_inputs", {}).get("writer_absence_verified") is not True
        or not isinstance(restored.get("controller_custody"), dict)
    ):
        raise GuestBootError("restored-boot-proof-incomplete")
    restored["cleanup"] = observe_removed_resources(restored["controller_custody"], standalone=True)
    restored["resources_destroyed_with_guest"] = True


def verify_guest_cleanup(guest: dict[str, Any], inputs: dict[str, Any]) -> None:
    # Destroy the whole owned guest, not a guessed set of mounts or descendants.
    # Context owners verify their directory identities before removing resources.
    if (
        guest.get("process_reaped") is not True
        or guest.get("temporary_resources_removed") is not True
        or inputs.get("temporary_resources_removed") is not True
        or inputs.get("base_preserved") is not True
        or not isinstance(guest.get("storage"), dict)
        or not isinstance(guest.get("endpoint"), dict)
    ):
        raise GuestStorageError("guest-resources-not-removed")
    endpoint_closed(guest["endpoint"])
    guest["endpoint"]["closed_after_cleanup"] = True
    guest["storage"]["resources_destroyed_with_guest"] = True
    if isinstance(guest.get("reboot"), dict):
        guest["reboot"]["resources_destroyed_with_guest"] = True
    if isinstance(guest.get("private_restore"), dict):
        restore = guest["private_restore"]
        if (
            restore.get("status") != "passed"
            or restore.get("temporary_resources_removed") is not True
        ):
            raise GuestBootError("private-restore-proof-incomplete")
        restore["resources_destroyed_with_guest"] = True
    if isinstance(guest.get("restored_boot"), dict):
        verify_restored_boot_cleanup(guest["restored_boot"])
    if isinstance(guest.get("retained_restart"), dict):
        restart = guest["retained_restart"]
        if restart.get("status") != "passed" or not isinstance(
            restart.get("controller_custody"), dict
        ):
            raise GuestBootError("restart-proof-incomplete")
        restart["cleanup"] = observe_removed_resources(restart["controller_custody"])
        restart["resources_destroyed_with_guest"] = True
    if isinstance(guest.get("process_kill"), dict):
        guest["process_kill"]["resources_destroyed_with_guest"] = True
    if isinstance(guest.get("transport_loss"), dict):
        guest["transport_loss"]["resources_destroyed_with_guest"] = True
    if isinstance(guest.get("exhaustion"), dict):
        guest["exhaustion"]["resources_destroyed_with_guest"] = True
    if isinstance(guest.get("allocation_release_reuse"), dict):
        guest["allocation_release_reuse"]["resources_destroyed_with_guest"] = True
    if isinstance(guest.get("allocation_cleanup"), dict):
        guest["allocation_cleanup"]["resources_destroyed_with_guest"] = True
    if isinstance(guest.get("snapshot_capture"), dict):
        guest["snapshot_capture"]["resources_destroyed_with_guest"] = True
    if isinstance(guest.get("partial_quota"), dict):
        guest["partial_quota"]["resources_destroyed_with_guest"] = True


def guest_storage_faults(
    tools: dict[str, Any], binary_sha256: str, temporary: Path, results: list[dict[str, Any]]
) -> None:
    metrics = RunStats()
    case: dict[str, Any] = {
        "scenario": "after-control-mount",
        "scope": "disposable-guest-partial-storage-setup-only",
        "status": "failed",
        "enrollment": str(uuid.uuid4()),
        "expected_failure_verified": False,
        "unrelated_state_preserved": False,
        "guest_inputs": {},
        "guest": {},
    }
    results.append(case)
    try:
        with stage("guest-storage-fault"):
            with tempfile.TemporaryDirectory(prefix="fishhat-canary-", dir=temporary) as folder:
                canary = Path(folder) / "unrelated"
                value = uuid.uuid4().bytes
                canary.write_bytes(value)
                identity = canary.lstat()
                try:
                    with guest_inputs(
                        case["enrollment"], temporary, run, stage, case["guest_inputs"]
                    ) as inputs:
                        boot_guest(
                            inputs,
                            tools,
                            binary_sha256,
                            temporary,
                            case["guest"],
                            storage_failure=True,
                        )
                except GuestStorageError as error:
                    case["problem"] = {"stage": error.stage, "reason": error.reason}
                finally:
                    after = canary.lstat()
                    case["unrelated_state_preserved"] = (
                        after.st_dev,
                        after.st_ino,
                        after.st_mode,
                    ) == (
                        identity.st_dev,
                        identity.st_ino,
                        identity.st_mode,
                    ) and canary.read_bytes() == value
                verify_guest_cleanup(case["guest"], case["guest_inputs"])
                case["expected_failure_verified"] = (
                    case.get("problem")
                    == {"stage": "guest-storage", "reason": "injected-after-control-mount"}
                    and case["guest"].get("boot_verified") is True
                    and case["guest"]["storage"].get("fault_injection_verified") is True
                    and case["guest"]["storage"].get("permissions_verified") is False
                    and case["guest"]["storage"].get("status") == "failed"
                    and case["unrelated_state_preserved"]
                )
                if not case["expected_failure_verified"]:
                    raise GuestStorageError("required-storage-failure-proof-missing")
    except OSError:
        raise GuestStorageError("storage-fault-observation-unavailable") from None
    finally:
        case["statistics"] = metrics.finish()
        if not valid_stats(case["statistics"]):
            raise ValueError("invalid required guest storage fault statistics")


def verify_interrupted_reboot_cleanup(case: dict[str, Any]) -> None:
    guest, inputs = case["guest"], case["guest_inputs"]
    reboot = guest.get("reboot", {})
    phases = reboot.get("phases", [])
    if (
        case.get("problem")
        != {"stage": "guest-reboot", "reason": "injected-before-restart-observation"}
        or reboot.get("fault_injection_verified") is not True
        or reboot.get("continuity_outcome") != "unobserved"
        or reboot.get("status") != "failed"
        or reboot.get("reboot_continuity_qualified") is not False
        or "after_identity" in reboot
        or "storage" in guest
        or [p["phase"] for p in phases] != ["prepare", "request", "independent-boot"]
        or [p["status"] for p in phases] != ["passed", "passed", "failed"]
        or phases[-1].get("interruption_kind") != "controlled-controller-observer-exception"
        or phases[-1].get("outcome") != "unobserved"
    ):
        raise GuestRebootError("required-reboot-interruption-missing")
    request = phases[1]
    acknowledged = (
        request.get("observed_exit_status") == 0
        and request.get("outcome") == "request-acknowledged"
        and isinstance(request.get("original_reply"), str)
    )
    lost = (
        request.get("observed_exit_status") == 255
        and request.get("outcome") == "unobserved"
        and "original_reply" not in request
    )
    if (
        request.get("command") != REBOOT
        or type(request.get("observed_exit_status")) is not int
        or request.get("mutation_reissued") is not False
        or not (acknowledged or lost)
        or not all(valid_stats(p.get("statistics")) for p in phases)
    ):
        raise GuestRebootError("original-reboot-request-not-preserved")
    if (
        guest.get("boot_verified") is not True
        or guest.get("identity") != reboot.get("before_identity")
        or guest.get("status") != "failed"
        or guest.get("process_reaped") is not True
        or guest.get("temporary_resources_removed") is not True
        or inputs.get("temporary_resources_removed") is not True
        or inputs.get("base_preserved") is not True
        or reboot.get("unrelated_host_canary_preserved") is not True
        or case.get("unrelated_state_preserved") is not True
    ):
        raise GuestRebootError("reboot-resources-not-removed")
    case["cleanup_observation"] = observe_removed_resources(phases[0]["host_custody"])
    endpoint_closed(guest["endpoint"])
    guest["endpoint"]["closed_after_cleanup"] = True
    reboot.update(resources_destroyed_with_guest=True, failed_restart_cleanup_qualified=True)
    case.update(expected_failure_verified=True, failed_restart_cleanup_qualified=True)


def guest_reboot_faults(
    tools: dict[str, Any], binary_sha256: str, temporary: Path, results: list[dict[str, Any]]
) -> None:
    metrics = RunStats()
    case: dict[str, Any] = {
        "scenario": "before-restart-observation",
        "scope": "disposable-guest-interrupted-reboot-observation-only",
        "status": "failed",
        "enrollment": str(uuid.uuid4()),
        "expected_failure_verified": False,
        "failed_restart_cleanup_qualified": False,
        "unrelated_state_preserved": False,
        "guest_inputs": {},
        "guest": {},
    }
    results.append(case)
    try:
        with stage("guest-reboot-fault"):
            with tempfile.TemporaryDirectory(prefix="fishhat-canary-", dir=temporary) as folder:
                canary = Path(folder) / "unrelated"
                content = uuid.uuid4().bytes
                canary.write_bytes(content)
                before = canary.lstat()
                try:
                    with guest_inputs(
                        case["enrollment"], temporary, run, stage, case["guest_inputs"]
                    ) as inputs:
                        boot_guest(
                            inputs,
                            tools,
                            binary_sha256,
                            temporary,
                            case["guest"],
                            reboot_failure=True,
                        )
                except RebootObservationInterrupted as error:
                    case["problem"] = {"stage": error.stage, "reason": error.reason}
                finally:
                    after = canary.lstat()
                    case["unrelated_state_preserved"] = (
                        after.st_dev,
                        after.st_ino,
                        after.st_mode,
                    ) == (
                        before.st_dev,
                        before.st_ino,
                        before.st_mode,
                    ) and canary.read_bytes() == content
                verify_interrupted_reboot_cleanup(case)
    except OSError:
        raise GuestRebootError("reboot-fault-observation-unavailable") from None
    finally:
        case["statistics"] = metrics.finish()
        if not valid_stats(case["statistics"]):
            raise ValueError("invalid required reboot fault statistics")


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
        "scope": "disposable-authenticated-guest-fixture-only",
        "fixture_enrollment": str(uuid.uuid4()),
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
        with stage("controller-probe"):
            report["controller_probe"] = probe_controller(
                report["controller"]["binary_sha256"], Path(os.environ["RUNNER_TEMP"])
            )
        report["controller_faults"] = []
        controller_faults(
            report["controller"]["binary_sha256"],
            Path(os.environ["RUNNER_TEMP"]),
            report["controller_faults"],
        )
        report["guest_tools"] = provision_tools(run, root_run, stage)
        report["guest_inputs"] = {}
        with stage("guest-inputs"):
            with guest_inputs(
                report["fixture_enrollment"],
                Path(os.environ["RUNNER_TEMP"]),
                run,
                stage,
                report["guest_inputs"],
            ) as inputs:
                report["guest"] = {}
                boot_guest(
                    inputs,
                    report["guest_tools"],
                    report["controller"]["binary_sha256"],
                    Path(os.environ["RUNNER_TEMP"]),
                    report["guest"],
                )
        with stage("guest-cleanup-observation"):
            verify_guest_cleanup(report["guest"], report["guest_inputs"])
        report["guest_storage_faults"] = []
        guest_storage_faults(
            report["guest_tools"],
            report["controller"]["binary_sha256"],
            Path(os.environ["RUNNER_TEMP"]),
            report["guest_storage_faults"],
        )
        report["guest_reboot_faults"] = []
        guest_reboot_faults(
            report["guest_tools"],
            report["controller"]["binary_sha256"],
            Path(os.environ["RUNNER_TEMP"]),
            report["guest_reboot_faults"],
        )
        report["status"] = "passed"
    except (EnrollmentError, GuestInputError, GuestBootError) as error:
        status = 1
        report.update(status="failed", problem={"stage": error.stage, "reason": error.reason})
    report["guest_booted"] = report.get("guest", {}).get("boot_verified") is True
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
