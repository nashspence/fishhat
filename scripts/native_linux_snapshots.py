"""Capture cold disk bytes from an already stopped, owned disposable guest."""

from __future__ import annotations

import copy
import errno
import os
import shutil
import socket
import stat
import tempfile
import uuid
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scripts.native_linux_guest import Guest, GuestBootError
from scripts.native_linux_images import DISK_BYTES, QEMU_IMG, digest, identity, image_info
from scripts.native_linux_reboot import phase
from scripts.run_stats import RunStats, valid_stats
from scripts.validation_timeouts import watchdog


class SnapshotError(GuestBootError):
    stage = "guest-snapshot"


def require(value: Any, reason: str) -> None:
    if not value:
        raise SnapshotError(reason)


def absent_process(pid: int, *, group: bool = False) -> None:
    require(type(pid) is int and pid > 1, "invalid-controller-identity")
    try:
        (os.killpg if group else os.kill)(pid, 0)
    except ProcessLookupError:
        return
    raise SnapshotError("controller-still-present")


def stopped_source(guest: Guest, custody: dict[str, Any]) -> dict[str, Any]:
    process = guest.process
    require(process is not None and process.returncode is not None, "controller-not-reaped")
    assert process is not None
    require(custody.get("pid") == custody.get("pgid") == process.pid, "controller-mismatch")
    controller = custody.get("controller", {})
    require(
        controller == guest.report.get("controller_verified")
        and controller.get("instance_uuid") == guest.enrollment
        and controller.get("unix_peer_verified") is True
        and controller.get("started_from_verified_prelaunch") is True,
        "controller-admission-missing",
    )
    require(guest.observed is not None, "guest-not-admitted")
    assert guest.observed is not None
    guest.validate_profile(guest.observed)
    absent_process(process.pid)
    absent_process(process.pid, group=True)
    address = custody.get("control_socket", {}).get("path")
    require(isinstance(address, str) and bool(address), "control-endpoint-mismatch")
    control = Path(address)
    arguments = process.args
    require(
        isinstance(arguments, list) and arguments.count("-qmp") == 1, "controller-command-mismatch"
    )
    assert isinstance(arguments, list)
    index = arguments.index("-qmp")
    require(
        index + 1 < len(arguments) and arguments[index + 1] == f"unix:{control},server=on,wait=off",
        "control-endpoint-mismatch",
    )
    for path in (control, control.parent):
        require(not path.exists() and not path.is_symlink(), "control-endpoint-remains")
    require(
        custody["endpoint"] == {"address": "127.0.0.1", "port": guest.port, "listener_owned": True},
        "ssh-endpoint-mismatch",
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as observer:
        observer.settimeout(watchdog(3))
        require(
            observer.connect_ex(("127.0.0.1", guest.port)) == errno.ECONNREFUSED,
            "ssh-endpoint-remains",
        )
    guest.inputs.verify(guest.enrollment)
    guest.verify_tools()
    require(
        custody["input_directory"]
        == {"path": str(guest.inputs.directory), "identity": guest.inputs.directory_identity},
        "input-directory-mismatch",
    )
    require(
        custody["private_directory"]
        == {"path": str(guest.directory), "identity": guest.directory_identity},
        "private-directory-mismatch",
    )
    require(
        custody["private_files"]
        == {
            name: {"path": str(guest.path(name)), "identity": v[0]}
            for name, v in guest.files.items()
        },
        "private-input-mismatch",
    )
    disks: dict[str, dict[str, Any]] = {
        name: {"path": str(guest.inputs.path(name, guest.enrollment)), "identity": v}
        for name, v in guest.inputs.files.items()
    }
    require(custody["disks"] == disks, "source-disk-mismatch")
    for name, value in disks.items():
        path = guest.inputs.path(name, guest.enrollment)
        value.update(bytes=path.stat().st_size, sha256=digest(path))
    return {
        "enrollment": guest.enrollment,
        "boot_identity": copy.deepcopy(guest.observed),
        "pid": process.pid,
        "pgid": process.pid,
        "process_absent": True,
        "group_absent": True,
        "control_endpoint_removed": True,
        "ssh_endpoint_closed": True,
        "disks": disks,
    }


def inspect_disk(guest: Guest, path: Path, name: str, *, standalone: bool) -> dict[str, Any]:
    info = image_info(guest.command, path)
    require(info["virtual-size"] == DISK_BYTES[name], "disk-extent-mismatch")
    require(not info.get("snapshots") and not info.get("corrupt", False), "unexpected-image-state")
    backing = info.get("backing-filename")
    full = info.get("full-backing-filename", backing)
    if not standalone and name == "root.qcow2":
        expected = str(guest.inputs.path("base.img", guest.enrollment))
        require(
            backing == full == expected and info.get("backing-filename-format") == "qcow2",
            "foreign-backing-image",
        )
    else:
        require(backing is None and full is None, "foreign-backing-image")
    return info


@dataclass
class DiskSnapshots:
    enrollment: str
    directory: Path
    directory_identity: tuple[int, int]
    files: dict[str, tuple[tuple[int, int], str]] = field(default_factory=dict)
    active: bool = False

    def path(self, name: str, enrollment: str) -> Path:
        require(self.active and enrollment == self.enrollment, "snapshot-not-admitted")
        require(set(self.files) == set(DISK_BYTES), "incomplete-snapshot")
        require(
            identity(self.directory, directory=True) == self.directory_identity,
            "snapshot-directory-replaced",
        )
        require(name in self.files, "unenrolled-snapshot")
        path = self.directory / name
        require(
            (identity(path), digest(path)) == self.files[name]
            and stat.S_IMODE(path.lstat().st_mode) == 0o400,
            "snapshot-changed",
        )
        return path

    def verify(self) -> None:
        for name in DISK_BYTES:
            self.path(name, self.enrollment)


def convert_disk(guest: Guest, snapshots: DiskSnapshots, name: str) -> dict[str, Any]:
    source = guest.inputs.path(name, guest.enrollment)
    source_info = inspect_disk(guest, source, name, standalone=False)
    require(
        identity(snapshots.directory, directory=True) == snapshots.directory_identity,
        "snapshot-directory-replaced",
    )
    target = snapshots.directory / name
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    enrolled = identity(target)
    guest.command(
        [str(QEMU_IMG), "create", "-q", "-f", "qcow2", str(target), str(DISK_BYTES[name])],
        "snapshot-create",
        30,
    )
    require(identity(target) == enrolled, "snapshot-file-replaced")
    guest.command(
        [
            str(QEMU_IMG),
            "convert",
            "-q",
            "-n",
            "-f",
            "qcow2",
            "-O",
            "qcow2",
            "-t",
            "writethrough",
            str(source),
            str(target),
        ],
        "snapshot-convert",
        600,
    )
    require(identity(target) == enrolled, "snapshot-file-replaced")
    observed = inspect_disk(guest, target, name, standalone=True)
    guest.command([str(QEMU_IMG), "check", "-q", "-f", "qcow2", str(target)], "snapshot-check", 120)
    guest.command(
        [str(QEMU_IMG), "compare", "-q", "-f", "qcow2", "-F", "qcow2", str(source), str(target)],
        "snapshot-compare",
        300,
    )
    require(identity(target) == enrolled, "snapshot-file-replaced")
    descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        require(
            (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino) == enrolled,
            "snapshot-file-replaced",
        )
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    snapshots.files[name] = enrolled, digest(target)
    return {
        "name": name,
        "virtual_bytes": observed["virtual-size"],
        "source_image_observation": source_info,
        "captured_image_observation": observed,
        "bytes": target.stat().st_size,
        "sha256": snapshots.files[name][1],
        "identity": enrolled,
        "standalone": True,
        "logical_contents_equal": True,
        "structure_checked": True,
        "synced": True,
        "read_only": True,
    }


@contextmanager
def cold_snapshots(
    guest: Guest,
    custody: dict[str, Any],
    temporary: Path,
    progress: Callable[[str], AbstractContextManager[None]],
    report: dict[str, Any],
) -> Iterator[DiskSnapshots]:
    metrics = RunStats()
    report.update(
        status="failed",
        scope="owned-disposable-cold-disk-bytes-only",
        phases=[],
        mechanism="offline-qcow2-convert-existing-standalone-target",
        consistency="cold-bytes-after-controller-termination",
        capture_verified=False,
        snapshot_restore_qualified=False,
        product_authority_qualified=False,
        source_preserved=False,
        snapshots_preserved_until_cleanup=False,
        temporary_resources_removed=False,
    )
    snapshots: DiskSnapshots | None = None
    complete = False
    try:
        with phase(report, "stopped-source") as item:
            before = stopped_source(guest, custody)
            item["observation"] = before
            version = guest.command([str(QEMU_IMG), "--version"], "snapshot-tool", 10, capture=True)
            require(version.split()[:3] == ["qemu-img", "version", "8.2.2"], "image-tool-mismatch")
            tool = digest(QEMU_IMG)
            report["image_tool"] = {"version": "8.2.2", "binary_sha256": tool}
        directory = Path(tempfile.mkdtemp(prefix="fhs-", dir=temporary))
        snapshots = DiskSnapshots(guest.enrollment, directory, identity(directory, directory=True))
        report["directory"] = {"path": str(directory), "identity": snapshots.directory_identity}
        for name in DISK_BYTES:
            with progress("snapshot-" + name), phase(report, name) as item:
                require(stopped_source(guest, custody) == before, "source-changed")
                require(digest(QEMU_IMG) == tool, "image-tool-changed")
                item["observation"] = convert_disk(guest, snapshots, name)
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            require(
                (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino)
                == snapshots.directory_identity,
                "snapshot-directory-replaced",
            )
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        snapshots.active = True
        snapshots.verify()
        report["capture_verified"] = True
        try:
            yield snapshots
        finally:
            with phase(report, "preservation") as item:
                snapshots.verify()
                require(stopped_source(guest, custody) == before, "source-changed")
                require(digest(QEMU_IMG) == tool, "image-tool-changed")
                item["source_after"] = stopped_source(guest, custody)
                report.update(source_preserved=True, snapshots_preserved_until_cleanup=True)
        complete = True
    except OSError:
        raise SnapshotError("snapshot-resource-unavailable") from None
    finally:
        try:
            if snapshots is not None:
                snapshots.active = False
                require(
                    identity(snapshots.directory, directory=True) == snapshots.directory_identity,
                    "snapshot-directory-replaced",
                )
                shutil.rmtree(snapshots.directory)
                report["temporary_resources_removed"] = not snapshots.directory.exists()
            if complete and report["temporary_resources_removed"]:
                report["status"] = "passed"
        finally:
            report["statistics"] = metrics.finish()
            if not valid_stats(report["statistics"]):
                report["status"] = "failed"
                raise ValueError("invalid required snapshot statistics")


def qualify_capture(
    guest: Guest,
    custody: dict[str, Any],
    temporary: Path,
    progress: Callable[[str], AbstractContextManager[None]],
    report: dict[str, Any],
) -> None:
    metrics = RunStats()
    try:
        with tempfile.TemporaryDirectory(
            prefix="fishhat-snapshot-canary-", dir=temporary
        ) as folder:
            canary = Path(folder) / "unrelated"
            content = uuid.uuid4().bytes
            canary.write_bytes(content)
            canary.chmod(0o600)
            original = (identity(canary), canary.stat().st_mtime_ns, canary.stat().st_mode)
            try:
                with cold_snapshots(guest, custody, temporary, progress, report) as snapshots:
                    snapshots.verify()
                    try:
                        snapshots.path("root.qcow2", str(uuid.uuid4()))
                    except SnapshotError as error:
                        require(error.reason == "snapshot-not-admitted", "wrong-refusal")
                    else:
                        raise SnapshotError("foreign-snapshot-handle-accepted")
                    report["foreign_enrollment_refused"] = True
                try:
                    snapshots.path("root.qcow2", guest.enrollment)
                except SnapshotError as error:
                    require(error.reason == "snapshot-not-admitted", "wrong-refusal")
                else:
                    raise SnapshotError("stale-snapshot-handle-accepted")
                report["stale_handle_refused"] = True
            finally:
                require(
                    canary.read_bytes() == content
                    and (identity(canary), canary.stat().st_mtime_ns, canary.stat().st_mode)
                    == original,
                    "unrelated-canary-changed",
                )
                report["unrelated_canary_preserved"] = True
    except BaseException:
        report["status"] = "failed"
        raise
    finally:
        report["qualification_statistics"] = metrics.finish()
        if not valid_stats(report["qualification_statistics"]):
            report["status"] = "failed"
            raise ValueError("invalid required snapshot qualification statistics")
