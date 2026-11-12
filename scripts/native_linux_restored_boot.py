"""Boot privately restored fixture disks under an exact owned writable lifetime."""

from __future__ import annotations

import copy
import os
import stat
import subprocess
import tempfile
import uuid
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scripts.native_linux_guest import Guest, GuestBootError
from scripts.native_linux_images import DISK_BYTES, digest, identity
from scripts.native_linux_restart import (
    canary_configuration,
    observe_replacement,
    phase,
    problem,
    stopped_replacement,
)
from scripts.native_linux_restore import (
    RestoredDisks,
    capture_projection,
    private_restored_disks,
    sync_directory,
)
from scripts.native_linux_snapshots import DiskSnapshots
from scripts.run_stats import RunStats, valid_stats


class RestoredBootError(GuestBootError):
    stage = "guest-restored-boot"


def require(value: Any, reason: str) -> None:
    if not value:
        raise RestoredBootError(reason)


@dataclass
class WritableInputs:
    owner: RestoredDisks
    enrollment: str = field(init=False)
    directory: Path = field(init=False)
    directory_identity: tuple[int, int] = field(init=False)
    files: dict[str, tuple[int, int]] = field(init=False)
    active: bool = True
    controller: Guest | None = field(default=None, repr=False)
    process: subprocess.Popen[bytes] | None = field(default=None, repr=False)
    _closure: tuple[Any, ...] = field(init=False, repr=False)
    _arguments: Any = field(default=None, repr=False)
    _bound_controller: Guest | None = field(default=None, repr=False)
    _bound_process: subprocess.Popen[bytes] | None = field(default=None, repr=False)
    _closed: bool = False

    def __post_init__(self) -> None:
        self.owner.verify()
        self.enrollment = self.owner.enrollment
        self.directory = self.owner.directory
        self.directory_identity = self.owner.directory_identity
        self.files = {name: value[0] for name, value in self.owner.files.items()}
        self._closure = self.closure()

    def closure(self) -> tuple[Any, ...]:
        return (
            self.enrollment,
            self.directory,
            self.directory_identity,
            tuple(sorted(self.files.items())),
            id(self.owner),
            self.owner.closure(),
        )

    def verify(self, enrollment: str) -> None:
        require(self.active and enrollment == self.enrollment, "writable-input-handle-expired")
        require(self.owner.active and self.closure() == self._closure, "writable-closure-changed")
        require(self.owner.closure() == self.owner._admitted, "restored-input-custody-changed")
        require(set(self.files) == set(DISK_BYTES), "incomplete-writable-inputs")
        require(
            identity(self.directory, directory=True) == self.directory_identity,
            "directory-replaced",
        )
        require({p.name for p in self.directory.iterdir()} == set(DISK_BYTES), "unexpected-input")
        for name, expected in self.files.items():
            path = self.directory / name
            require(
                identity(path) == expected and stat.S_IMODE(path.lstat().st_mode) == 0o600,
                "writable-input-replaced",
            )
        if self.process is None:
            self.owner.verify()
        else:
            require(
                (self.owner._writer is self or (self._closed and self.owner._writer is None))
                and self.controller is not None
                and self.controller is self._bound_controller
                and self.controller.inputs is self
                and self.controller.process is self.process
                and self.process is self._bound_process
                and self.process.args == self._arguments,
                "writable-controller-changed",
            )

    def path(self, name: str, enrollment: str) -> Path:
        self.verify(enrollment)
        require(name in self.files, "unenrolled-writable-input")
        return self.directory / name

    def prepare(self, controller: Guest) -> None:
        self.verify(controller.enrollment)
        require(self.controller is None and controller.process is None, "controller-already-bound")
        self.controller = self._bound_controller = controller

    def started(self, process: subprocess.Popen[bytes]) -> None:
        # Called only after the unchanged Guest.launch returned its exact child.
        self.process = self._bound_process = process
        self._arguments = copy.deepcopy(process.args)
        self.owner._writer = self

    def finish(self, report: dict[str, Any]) -> None:
        if self.process is not None:
            require(
                self.controller is self._bound_controller
                and self.controller is not None
                and self.controller.process is self.process
                and self.process is self._bound_process
                and self.process.args == self._arguments,
                "writable-controller-changed",
            )
            assert self.controller is not None
            report["stopped_controller"] = stopped_replacement(self.controller)
            report["writer_absence_verified"] = True
            self._closed = True
            self.owner._writer = None
            self.verify(self.enrollment)
            for name, expected in self.files.items():
                fd = os.open(self.directory / name, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    value = os.fstat(fd)
                    require((value.st_dev, value.st_ino) == expected, "writable-input-replaced")
                    os.fsync(fd)
                finally:
                    os.close(fd)
            sync_directory(self.owner)
            report["written_files_synced"] = True
            final = {
                name: (value, digest(self.directory / name)) for name, value in self.files.items()
            }
            self.verify(self.enrollment)
            self.owner._written_files = tuple(sorted(final.items()))
            self.owner._writer = None
            self.owner.verify()
            report["written_files"] = copy.deepcopy(final)
            report["writer_absence_verified"] = True
        else:
            self.verify(self.enrollment)
            self.owner.verify()
            report["writer_never_started"] = True


class RestoredGuest(Guest):
    def launch(self, endpoint: Path, enrollment: str) -> subprocess.Popen[bytes]:
        require(isinstance(self.inputs, WritableInputs), "unbound-restored-inputs")
        assert isinstance(self.inputs, WritableInputs)
        self.inputs.prepare(self)
        process = super().launch(endpoint, enrollment)
        self.inputs.started(process)
        return process


@contextmanager
def writable_inputs(owner: RestoredDisks, report: dict[str, Any]) -> Iterator[WritableInputs]:
    metrics = RunStats()
    handle: WritableInputs | None = None
    complete = False
    report.update(status="failed", lifetime_ended=False, writer_absence_verified=False)
    try:
        handle = WritableInputs(owner)
        report["admitted_files"] = copy.deepcopy(owner.files)
        try:
            yield handle
            complete = True
        except BaseException as error:
            report["problem"] = problem(error)
            raise
        finally:
            try:
                handle.finish(report)
            except BaseException as error:
                report["cleanup_problem"] = problem(error)
                raise
        report["status"] = "passed" if complete else "failed"
    finally:
        if handle is not None:
            handle.active = False
        report["lifetime_ended"] = True
        report["statistics"] = metrics.finish()
        if not valid_stats(report["statistics"]):
            report["status"] = "failed"
            raise ValueError("invalid required restored writable-input statistics")


def boot_restored(
    source: Guest,
    custody: dict[str, Any],
    restored: RestoredDisks,
    snapshots: DiskSnapshots,
    capture: dict[str, Any],
    progress: Callable[[str], AbstractContextManager[None]],
    launch: Callable[[Guest], AbstractContextManager[Path]],
    report: dict[str, Any],
) -> None:
    with snapshots.restore_boot_inputs(
        source, custody, capture_projection(capture), report["boot_inputs"]
    ) as retained:
        with writable_inputs(restored, report["writable_inputs"]) as disks:
            with phase(report, "input-admission") as item:
                child = retained.guest(
                    source.enrollment, report["guest"], inputs=disks, guest_type=RestoredGuest
                )
                try:
                    disks.path("root.qcow2", str(uuid.uuid4()))
                except RestoredBootError as error:
                    require(error.reason == "writable-input-handle-expired", "wrong-input-refusal")
                else:
                    raise RestoredBootError("foreign-writable-handle-accepted")
                item["foreign_enrollment_refused"] = True
                item["private_disks"] = copy.deepcopy(disks.files)
                item["original_disks_excluded"] = all(
                    value not in source.inputs.files.values() for value in disks.files.values()
                )
                require(item["original_disks_excluded"], "source-disk-reused")
            with progress("guest-private-restored-boot"), launch(child) as endpoint:
                with phase(report, "prelaunch") as item:
                    retained.verify()
                    disks.verify(source.enrollment)
                    require(
                        child.report["controller_verified"]
                        == retained.expected["controller_profile"],
                        "restored-controller-profile-changed",
                    )
                    item["controller"] = copy.deepcopy(child.report["controller_verified"])
                observe_replacement(
                    child, retained.source, endpoint, canary_configuration(source), report
                )
                retained.verify()
                disks.verify(source.enrollment)
            require(child.observed is not None, "restored-boot-never-admitted")
        try:
            disks.path("root.qcow2", source.enrollment)
        except RestoredBootError as error:
            require(error.reason == "writable-input-handle-expired", "wrong-input-refusal")
        else:
            raise RestoredBootError("expired-writable-handle-accepted")
        report["expired_writable_handle_refused"] = True
    try:
        retained.guest(source.enrollment, {})
    except RuntimeError as error:
        require(
            getattr(error, "reason", None) == "boot-input-handle-expired", "wrong-input-refusal"
        )
    else:
        raise RestoredBootError("expired-boot-handle-accepted")
    report["expired_boot_handle_refused"] = True


def qualify_restored_boot(
    source: Guest,
    custody: dict[str, Any],
    snapshots: DiskSnapshots,
    capture: dict[str, Any],
    temporary: Path,
    progress: Callable[[str], AbstractContextManager[None]],
    launch: Callable[[Guest], AbstractContextManager[Path]],
    report: dict[str, Any],
) -> None:
    metrics = RunStats()
    report.update(
        status="failed",
        scope="owned-disposable-private-restored-boot-only",
        mechanism="sealed-capture-private-disks-and-exact-retained-boot-inputs",
        consistency="cold-bytes-after-controller-termination",
        phases=[],
        private_inputs={},
        writable_inputs={},
        boot_inputs={},
        guest={},
        restored_boot_verified=False,
        snapshot_restore_qualified=False,
        product_authority_qualified=False,
    )
    before = copy.deepcopy(source.observed)
    original_report = copy.deepcopy({k: v for k, v in source.report.items() if v is not report})
    try:
        with tempfile.TemporaryDirectory(prefix="fhrb-", dir=temporary) as folder:
            canary = Path(folder) / "unrelated"
            content = uuid.uuid4().bytes
            canary.write_bytes(content)
            canary.chmod(0o600)
            original = identity(canary), canary.stat().st_mtime_ns, canary.stat().st_mode
            try:
                with private_restored_disks(
                    source,
                    custody,
                    snapshots,
                    capture,
                    temporary,
                    progress,
                    report["private_inputs"],
                ) as restored:
                    boot_restored(
                        source, custody, restored, snapshots, capture, progress, launch, report
                    )
            finally:
                require(
                    canary.read_bytes() == content
                    and (identity(canary), canary.stat().st_mtime_ns, canary.stat().st_mode)
                    == original,
                    "unrelated-restored-boot-canary-changed",
                )
                report["unrelated_canary_preserved"] = True
        require(source.observed == before, "original-boot-admission-changed")
        require(
            {k: v for k, v in source.report.items() if v is not report} == original_report,
            "original-guest-evidence-changed",
        )
        report.update(
            status="passed", restored_boot_verified=True, original_guest_evidence_preserved=True
        )
    except BaseException as error:
        report["problem"] = problem(error)
        if isinstance(error, OSError):
            report["resource_failure"] = {"errno": error.errno, "type": type(error).__name__}
        raise
    finally:
        report["statistics"] = metrics.finish()
        if not valid_stats(report["statistics"]):
            report["status"] = "failed"
            raise ValueError("invalid required restored-boot statistics")
