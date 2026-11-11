"""Prepare complete private disposable disks from active verified sealed captures."""

from __future__ import annotations

import copy
import os
import shutil
import stat
import tempfile
import uuid
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scripts.native_linux_guest import Guest
from scripts.native_linux_images import DISK_BYTES, QEMU_IMG, digest, identity
from scripts.native_linux_restart import phase, problem
from scripts.native_linux_snapshots import DiskSnapshots, SnapshotError, copy_disk, stopped_source
from scripts.run_stats import RunStats, valid_stats


class RestoreError(SnapshotError):
    stage = "guest-restore"


def require(value: Any, reason: str) -> None:
    if not value:
        raise RestoreError(reason)


def capture_projection(capture: dict[str, Any]) -> dict[str, Any]:
    require(
        capture.get("scope") == "owned-disposable-cold-disk-bytes-only"
        and capture.get("capture_verified") is True
        and capture.get("snapshot_restore_qualified") is False
        and capture.get("product_authority_qualified") is False,
        "verified-capture-missing",
    )
    phases = capture.get("phases")
    require(isinstance(phases, list), "complete-capture-missing")
    assert isinstance(phases, list)
    require(
        [p.get("phase") for p in phases] == ["stopped-source", *DISK_BYTES]
        and all(p.get("status") == "passed" for p in phases),
        "complete-capture-missing",
    )
    return copy.deepcopy(
        {
            "source": phases[0]["observation"],
            "directory": capture["directory"],
            "image_tool": capture["image_tool"],
            "files": {
                p["phase"]: (p["observation"]["identity"], p["observation"]["sha256"])
                for p in phases[1:]
            },
        }
    )


@dataclass
class RestoreSource:
    guest: Guest
    custody: dict[str, Any]
    snapshots: DiskSnapshots
    expected: dict[str, Any]

    def verify(self) -> None:
        snapshots, expected = self.snapshots, self.expected
        require(snapshots.enrollment == self.guest.enrollment, "foreign-snapshot-enrollment")
        require(
            {"path": str(snapshots.directory), "identity": snapshots.directory_identity}
            == expected["directory"]
            and snapshots.files == expected["files"],
            "captured-snapshot-custody-changed",
        )
        snapshots.verify()
        require(
            {p.name for p in snapshots.directory.iterdir()} == set(DISK_BYTES),
            "unexpected-snapshot-input",
        )
        require(stopped_source(self.guest, self.custody) == expected["source"], "source-changed")
        require(
            expected["image_tool"]["version"] == "8.2.2"
            and digest(QEMU_IMG) == expected["image_tool"]["binary_sha256"],
            "image-tool-changed",
        )


@dataclass
class RestoredDisks:
    enrollment: str
    directory: Path
    directory_identity: tuple[int, int]
    files: dict[str, tuple[tuple[int, int], str]] = field(default_factory=dict)
    active: bool = False
    _admitted: tuple[Any, ...] | None = field(default=None, repr=False)
    _writer: object | None = field(default=None, repr=False)
    _written_files: tuple[tuple[str, tuple[tuple[int, int], str]], ...] | None = field(
        default=None, repr=False
    )

    def closure(self) -> tuple[Any, ...]:
        return (
            self.enrollment,
            self.directory,
            self.directory_identity,
            tuple(sorted(self.files.items())),
        )

    def admit(self) -> None:
        require(self._admitted is None and not self.active, "restore-already-admitted")
        require(set(self.files) == set(DISK_BYTES), "incomplete-restored-inputs")
        self._admitted = self.closure()
        self.active = True
        self.verify()

    def path(self, name: str, enrollment: str) -> Path:
        require(self.active and enrollment == self.enrollment, "restore-not-admitted")
        require(self._writer is None, "restored-writer-active")
        require(self.closure() == self._admitted, "restored-input-custody-changed")
        require(set(self.files) == set(DISK_BYTES), "incomplete-restored-inputs")
        require(
            identity(self.directory, directory=True) == self.directory_identity,
            "restore-directory-replaced",
        )
        require(name in self.files, "unenrolled-restored-input")
        path = self.directory / name
        expected = self.files if self._written_files is None else dict(self._written_files)
        require(
            (identity(path), digest(path)) == expected[name]
            and stat.S_IMODE(path.lstat().st_mode) == 0o600,
            "restored-input-changed",
        )
        return path

    def verify(self) -> None:
        for name in DISK_BYTES:
            self.path(name, self.enrollment)
        require(
            {p.name for p in self.directory.iterdir()} == set(DISK_BYTES),
            "unexpected-restored-input",
        )


def sync_directory(owner: RestoredDisks) -> None:
    descriptor = os.open(owner.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        require(
            (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino) == owner.directory_identity,
            "restore-directory-replaced",
        )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def remove_owned(
    owner: RestoredDisks, directory: Path, enrolled: tuple[int, int], report: dict[str, Any]
) -> None:
    owner.active = False
    with phase(report, "cleanup") as item:
        require(owner._writer is None, "restored-writer-still-active")
        require(
            identity(directory, directory=True) == enrolled,
            "restore-directory-replaced",
        )
        paths = [directory / name for name in DISK_BYTES]
        shutil.rmtree(directory)
        item["paths"] = [
            {"path": str(p), "absent": not p.exists() and not p.is_symlink()}
            for p in [*paths, directory]
        ]
        require(all(p["absent"] for p in item["paths"]), "restored-input-remains")
        report["temporary_resources_removed"] = True


@contextmanager
def private_restored_disks(
    guest: Guest,
    custody: dict[str, Any],
    snapshots: DiskSnapshots,
    capture: dict[str, Any],
    temporary: Path,
    progress: Callable[[str], AbstractContextManager[None]],
    report: dict[str, Any],
) -> Iterator[RestoredDisks]:
    metrics = RunStats()
    owner: RestoredDisks | None = None
    created_identity: tuple[int, int] | None = None
    complete = False
    report.update(
        status="failed",
        scope="owned-disposable-private-restored-disk-inputs-only",
        mechanism="offline-sealed-qcow2-to-exclusive-standalone-inputs",
        phases=[],
        restored_inputs_admitted=False,
        originals_preserved=False,
        temporary_resources_removed=False,
        snapshot_restore_qualified=False,
        product_authority_qualified=False,
    )
    try:
        with phase(report, "input-admission") as item:
            source = RestoreSource(
                guest, copy.deepcopy(custody), snapshots, capture_projection(capture)
            )
            source.verify()
            version = guest.command([str(QEMU_IMG), "--version"], "restore-tool", 10, capture=True)
            require(version.split()[:3] == ["qemu-img", "version", "8.2.2"], "image-tool-mismatch")
            source.verify()
            item["observation"] = copy.deepcopy(source.expected)
        directory = Path(tempfile.mkdtemp(prefix="fhri-", dir=temporary))
        created_identity = identity(directory, directory=True)
        owner = RestoredDisks(guest.enrollment, directory, created_identity)
        report["directory"] = {"path": str(directory), "identity": owner.directory_identity}
        for name in DISK_BYTES:
            with progress("restore-" + name), phase(report, name) as item:
                source.verify()
                value = copy_disk(
                    guest,
                    snapshots.path(name, guest.enrollment),
                    owner.directory,
                    owner.directory_identity,
                    name,
                    standalone=True,
                    read_only=False,
                    purpose="restore",
                    verify=source.verify,
                )
                value["restored_image_observation"] = value.pop("copied_image_observation")
                owner.files[name] = value["identity"], value["sha256"]
                item["observation"] = value
        with phase(report, "complete-input-admission") as item:
            source.verify()
            sync_directory(owner)
            owner.admit()
            item["files"] = copy.deepcopy(owner.files)
            report["restored_inputs_admitted"] = True
        try:
            yield owner
        except BaseException as error:
            report["problem"] = problem(error)
            if isinstance(error, OSError):
                report["resource_failure"] = {"errno": error.errno, "type": type(error).__name__}
            raise
        finally:
            with phase(report, "preservation") as item:
                source.verify()
                owner.verify()
                item["observation"] = copy.deepcopy(source.expected)
                item["restored_files"] = copy.deepcopy(
                    owner.files if owner._written_files is None else dict(owner._written_files)
                )
                report["originals_preserved"] = True
        complete = True
    except BaseException as error:
        report.setdefault("problem", problem(error))
        if isinstance(error, OSError):
            report["resource_failure"] = {"errno": error.errno, "type": type(error).__name__}
        raise
    finally:
        try:
            if owner is not None:
                try:
                    assert created_identity is not None
                    remove_owned(owner, directory, created_identity, report)
                except BaseException as error:
                    report["cleanup_problem"] = problem(error)
                    raise
            if complete and report["temporary_resources_removed"]:
                report["status"] = "passed"
        finally:
            report["statistics"] = metrics.finish()
            if not valid_stats(report["statistics"]):
                report["status"] = "failed"
                raise ValueError("invalid required private restore statistics")


def qualify_restore(
    guest: Guest,
    custody: dict[str, Any],
    snapshots: DiskSnapshots,
    capture: dict[str, Any],
    temporary: Path,
    progress: Callable[[str], AbstractContextManager[None]],
    report: dict[str, Any],
) -> None:
    metrics = RunStats()
    try:
        with tempfile.TemporaryDirectory(prefix="fhr-canary-", dir=temporary) as folder:
            canary = Path(folder) / "unrelated"
            content = uuid.uuid4().bytes
            canary.write_bytes(content)
            canary.chmod(0o600)
            original = identity(canary), canary.stat().st_mtime_ns, canary.stat().st_mode
            try:
                with private_restored_disks(
                    guest, custody, snapshots, capture, temporary, progress, report
                ) as owner:
                    owner.verify()
                    try:
                        owner.path("root.qcow2", str(uuid.uuid4()))
                    except RestoreError as error:
                        require(error.reason == "restore-not-admitted", "wrong-restore-refusal")
                    else:
                        raise RestoreError("foreign-restored-input-accepted")
                    report["foreign_enrollment_refused"] = True
                try:
                    owner.path("root.qcow2", guest.enrollment)
                except RestoreError as error:
                    require(error.reason == "restore-not-admitted", "wrong-restore-refusal")
                else:
                    raise RestoreError("expired-restored-input-accepted")
                report["expired_handle_refused"] = True
            finally:
                require(
                    canary.read_bytes() == content
                    and (identity(canary), canary.stat().st_mtime_ns, canary.stat().st_mode)
                    == original,
                    "unrelated-restore-canary-changed",
                )
                report["unrelated_canary_preserved"] = True
    except BaseException:
        report["status"] = "failed"
        raise
    finally:
        report["qualification_statistics"] = metrics.finish()
        if not valid_stats(report["qualification_statistics"]):
            report["status"] = "failed"
            raise ValueError("invalid required private restore qualification statistics")
