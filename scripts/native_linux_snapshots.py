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
from typing import TYPE_CHECKING, Any

from scripts.native_linux_guest import Guest, GuestBootError
from scripts.native_linux_images import DISK_BYTES, QEMU_IMG, digest, identity, image_info
from scripts.native_linux_reboot import phase
from scripts.run_stats import RunStats, valid_stats
from scripts.validation_timeouts import watchdog

if TYPE_CHECKING:
    from scripts.native_linux_restart import RetainedBootInputs
    from scripts.native_linux_successor import CaptureLifetime


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
    _admitted: tuple[Any, ...] | None = field(default=None, repr=False)

    _source_owner: CaptureLifetime | None = field(default=None, repr=False)

    def source_observation(self, enrollment: str) -> dict[str, Any]:
        require(self._source_owner is not None, "capture-source-not-admitted")
        assert self._source_owner is not None
        require(self._source_owner.bound_to(self), "foreign-capture-source-handle")
        return self._source_owner.observation(enrollment)

    def advance_source(
        self,
        enrollment: str,
        progress: Callable[[str], AbstractContextManager[None]],
        launch: Callable[[Guest], AbstractContextManager[Path]],
        report: dict[str, Any],
    ) -> dict[str, Any]:
        require(self._source_owner is not None, "capture-source-not-admitted")
        assert self._source_owner is not None
        require(self._source_owner.bound_to(self), "foreign-capture-source-handle")
        return self._source_owner.advance(enrollment, progress, launch, report)

    def restore_observation(
        self, guest: Guest, custody: dict[str, Any], expected: dict[str, Any]
    ) -> dict[str, Any]:
        require(self._source_owner is not None, "capture-source-not-admitted")
        assert self._source_owner is not None
        require(self._source_owner.bound_to(self), "foreign-capture-source-handle")
        return self._source_owner.restore_observation(guest, custody, expected)

    def restore_boot_inputs(
        self,
        guest: Guest,
        custody: dict[str, Any],
        expected: dict[str, Any],
        report: dict[str, Any],
    ) -> AbstractContextManager[RetainedBootInputs]:
        require(self._source_owner is not None, "capture-source-not-admitted")
        assert self._source_owner is not None
        require(self._source_owner.bound_to(self), "foreign-capture-source-handle")
        return self._source_owner.restore_boot_inputs(guest, custody, expected, report)

    def closure(self) -> tuple[Any, ...]:
        return (
            self.enrollment,
            self.directory,
            self.directory_identity,
            tuple(sorted(self.files.items())),
        )

    def admit(self) -> None:
        require(self._admitted is None and not self.active, "snapshot-already-admitted")
        require(set(self.files) == set(DISK_BYTES), "incomplete-snapshot")
        self._admitted = self.closure()
        self.active = True
        try:
            self.verify()
        except BaseException:
            self.active = False
            raise

    def path(self, name: str, enrollment: str) -> Path:
        require(
            self.active and self._admitted is not None and enrollment == self.enrollment,
            "snapshot-not-admitted",
        )
        require(self.closure() == self._admitted, "snapshot-input-custody-changed")
        require(set(self.files) == set(DISK_BYTES), "incomplete-snapshot")
        require(
            identity(self.directory, directory=True) == self.directory_identity,
            "snapshot-directory-replaced",
        )
        require(
            {p.name for p in self.directory.iterdir()} == set(DISK_BYTES),
            "unexpected-snapshot-input",
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


def copy_disk(
    guest: Guest,
    source: Path,
    directory: Path,
    directory_identity: tuple[int, int],
    name: str,
    *,
    standalone: bool,
    read_only: bool,
    purpose: str,
    verify: Callable[[], None],
) -> dict[str, Any]:
    require(name in DISK_BYTES and purpose in {"snapshot", "restore"}, "unexpected-copy")
    verify()
    source_info = inspect_disk(guest, source, name, standalone=standalone)
    verify()
    require(identity(directory, directory=True) == directory_identity, "copy-directory-replaced")
    target = directory / name
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    enrolled = identity(target)

    def verify_output() -> None:
        verify()
        require(
            identity(directory, directory=True) == directory_identity, "copy-directory-replaced"
        )
        require(identity(target) == enrolled, "copy-file-replaced")

    def command(arguments: list[str], action: str, nominal: float) -> None:
        verify_output()
        guest.command(arguments, purpose + "-" + action, nominal)
        verify_output()

    command(
        [str(QEMU_IMG), "create", "-q", "-f", "qcow2", str(target), str(DISK_BYTES[name])],
        "create",
        30,
    )
    initialized = inspect_disk(guest, target, name, standalone=True)
    verify_output()
    command(
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
        "convert",
        600,
    )
    verify_output()
    observed = inspect_disk(guest, target, name, standalone=True)
    verify_output()
    command([str(QEMU_IMG), "check", "-q", "-f", "qcow2", str(target)], "check", 120)
    command(
        [str(QEMU_IMG), "compare", "-q", "-f", "qcow2", "-F", "qcow2", str(source), str(target)],
        "compare",
        300,
    )
    descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        require(
            (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino) == enrolled,
            "copy-file-replaced",
        )
        os.fchmod(descriptor, 0o400 if read_only else 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    verify_output()
    return {
        "name": name,
        "virtual_bytes": observed["virtual-size"],
        "source_image_observation": source_info,
        "initialized_image_observation": initialized,
        "copied_image_observation": observed,
        "bytes": target.stat().st_size,
        "sha256": digest(target),
        "identity": enrolled,
        "standalone": True,
        "logical_contents_equal": True,
        "structure_checked": True,
        "synced": True,
        "read_only": read_only,
    }


def convert_disk(guest: Guest, snapshots: DiskSnapshots, name: str) -> dict[str, Any]:
    value = copy_disk(
        guest,
        guest.inputs.path(name, guest.enrollment),
        snapshots.directory,
        snapshots.directory_identity,
        name,
        standalone=False,
        read_only=True,
        purpose="snapshot",
        verify=guest.verify_tools,
    )
    snapshots.files[name] = value["identity"], value["sha256"]
    value["captured_image_observation"] = value.pop("copied_image_observation")
    return value


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
    created_identity: tuple[int, int] | None = None
    complete = False
    owner: CaptureLifetime | None = None
    try:
        with phase(report, "stopped-source") as item:
            before = stopped_source(guest, custody)
            item["observation"] = copy.deepcopy(before)
            version = guest.command([str(QEMU_IMG), "--version"], "snapshot-tool", 10, capture=True)
            require(version.split()[:3] == ["qemu-img", "version", "8.2.2"], "image-tool-mismatch")
            tool = digest(QEMU_IMG)
            report["image_tool"] = {"version": "8.2.2", "binary_sha256": tool}
        directory = Path(tempfile.mkdtemp(prefix="fhs-", dir=temporary))
        created_identity = identity(directory, directory=True)
        snapshots = DiskSnapshots(guest.enrollment, directory, created_identity)
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
        snapshots.admit()
        report["capture_verified"] = True
        from scripts.native_linux_successor import CaptureLifetime

        owner = CaptureLifetime(guest, custody, snapshots, before, temporary, report, QEMU_IMG)
        snapshots._source_owner = owner
        body_error: BaseException | None = None
        try:
            yield snapshots
        except BaseException as error:
            body_error = error
            raise
        finally:
            try:
                after = owner.observation(guest.enrollment)
                with phase(report, "preservation") as item:
                    snapshots.verify()
                    require(digest(QEMU_IMG) == tool, "image-tool-changed")
                    item["source_after"] = after
                    report.update(
                        source_preserved=not owner.advanced,
                        snapshots_preserved_until_cleanup=True,
                    )
                    if owner.advanced:
                        report["observed_successor_preserved"] = True
            except BaseException as error:
                report["preservation_problem"] = {
                    "type": type(error).__name__,
                    "reason": getattr(error, "reason", "unclassified"),
                }
                if body_error is None:
                    raise
        complete = True
    except OSError:
        raise SnapshotError("snapshot-resource-unavailable") from None
    finally:
        try:
            if owner is not None:
                owner.expire()
            if snapshots is not None:
                snapshots.active = False
                assert created_identity is not None
                require(
                    identity(directory, directory=True) == created_identity,
                    "snapshot-directory-replaced",
                )
                shutil.rmtree(directory)
                report["temporary_resources_removed"] = not directory.exists()
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
    *,
    consume: Callable[[DiskSnapshots], None] | None = None,
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
                    if consume is not None:
                        consume(snapshots)
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
