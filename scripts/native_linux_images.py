"""Prepare pinned guest inputs inside one explicitly enrolled disposable fixture."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import uuid
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from scripts.run_stats import RunStats, valid_stats

IMAGE_URL = "https://cloud-images.ubuntu.com/releases/noble/release-20261017/ubuntu-24.04-server-cloudimg-amd64.img"
IMAGE_SHA256 = "04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94"
IMAGE_BYTES = 621284352
BASE_VIRTUAL_BYTES = 3758096384
DISK_BYTES = {"root.qcow2": 16 * 1024**3, "control.qcow2": 2 * 1024**3, "data.qcow2": 4 * 1024**3}
QEMU_IMG = Path("/usr/bin/qemu-img")

# A bounded isolated child owns the network read; it cannot inherit proxy or
# authentication state, follow redirects, or overwrite an existing destination.
DOWNLOAD_WORKER = Path(__file__).with_name("native_linux_download.py")


class GuestInputError(RuntimeError):
    stage = "guest-inputs"

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class Command(Protocol):
    def __call__(
        self, command: list[str], name: str, nominal: float, *, capture: bool = False
    ) -> str: ...


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def identity(path: Path, *, directory: bool = False) -> tuple[int, int]:
    value = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected(value.st_mode)
        or value.st_uid != os.geteuid()
        or (not directory and value.st_nlink != 1)
        or stat.S_IMODE(value.st_mode) not in ({0o700} if directory else {0o600, 0o400})
    ):
        raise GuestInputError("foreign-or-unprotected-resource")
    return value.st_dev, value.st_ino


class BootInputs(Protocol):
    enrollment: str
    directory: Path
    directory_identity: tuple[int, int]
    files: dict[str, tuple[int, int]]

    def path(self, name: str, enrollment: str) -> Path: ...

    def verify(self, enrollment: str) -> None: ...


@dataclass
class GuestInputs:
    enrollment: str
    directory: Path
    directory_identity: tuple[int, int]
    files: dict[str, tuple[int, int]] = field(default_factory=dict)

    def register(self, name: str) -> None:
        if name not in {"base.img", *DISK_BYTES} or name in self.files:
            raise GuestInputError("unexpected-resource")
        self.files[name] = identity(self.directory / name)

    def path(self, name: str, enrollment: str) -> Path:
        if enrollment != self.enrollment:
            raise GuestInputError("fixture-enrollment-mismatch")
        if identity(self.directory, directory=True) != self.directory_identity:
            raise GuestInputError("fixture-directory-replaced")
        if name not in self.files:
            raise GuestInputError("unenrolled-resource")
        path = self.directory / name
        if identity(path) != self.files[name]:
            raise GuestInputError("enrolled-resource-replaced")
        expected = 0o400 if name == "base.img" else 0o600
        if stat.S_IMODE(path.lstat().st_mode) != expected:
            raise GuestInputError("resource-permissions-changed")
        return path

    def verify(self, enrollment: str) -> None:
        if set(self.files) != {"base.img", *DISK_BYTES}:
            raise GuestInputError("incomplete-guest-inputs")
        for name in self.files:
            self.path(name, enrollment)
        base = self.path("base.img", enrollment)
        if base.stat().st_size != IMAGE_BYTES or digest(base) != IMAGE_SHA256:
            raise GuestInputError("base-image-changed")


def image_info(command: Command, path: Path) -> dict[str, Any]:
    text = command(
        [str(QEMU_IMG), "info", "--output=json", "-f", "qcow2", str(path)],
        "guest-image-inspect",
        30,
        capture=True,
    )
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        raise GuestInputError("invalid-image-observation") from None
    if (
        not isinstance(value, dict)
        or value.get("format") != "qcow2"
        or type(value.get("virtual-size")) is not int
        or value.get("encrypted", False) is not False
        or value.get("data-file") is not None
    ):
        raise GuestInputError("unexpected-image-format")
    specific = value.get("format-specific", {"type": "qcow2", "data": {}})
    if (
        not isinstance(specific, dict)
        or specific.get("type") != "qcow2"
        or not isinstance(specific.get("data"), dict)
        or specific["data"].get("data-file") is not None
        or specific["data"].get("encrypt") is not None
    ):
        raise GuestInputError("unexpected-image-format")
    return value


@contextmanager
def guest_inputs(
    enrollment: str,
    temporary: Path,
    command: Command,
    progress: Callable[[str], AbstractContextManager[None]],
    report: dict[str, Any],
) -> Iterator[GuestInputs]:
    # Admission belongs to the caller; this token binds all paths and commands
    # to that one enrollment, rather than accepting an existing disk or image.
    try:
        if str(uuid.UUID(enrollment)) != enrollment:
            raise ValueError("noncanonical enrollment")
    except (ValueError, TypeError, AttributeError):
        raise GuestInputError("invalid-fixture-enrollment") from None
    metrics = RunStats()
    directory: Path | None = None
    owner: GuestInputs | None = None
    complete = False
    report.update(
        status="failed",
        enrollment=enrollment,
        scope="disposable-authenticated-image-and-owned-disks-only",
        authentication="pinned-from-canonical-signed-release",
        image_url=IMAGE_URL,
        image_sha256=IMAGE_SHA256,
        base_preserved=False,
        temporary_resources_removed=False,
    )
    try:
        directory = Path(tempfile.mkdtemp(prefix="fhi-", dir=temporary))
        owner = GuestInputs(enrollment, directory, identity(directory, directory=True))
        with progress("guest-image-tool"):
            version = command([str(QEMU_IMG), "--version"], "guest-image-tool", 10, capture=True)
            if version.split()[:3] != ["qemu-img", "version", "8.2.2"]:
                raise GuestInputError("image-tool-version-mismatch")
            tool_sha256 = digest(QEMU_IMG)
            report["image_tool"] = {"version": "8.2.2", "binary_sha256": tool_sha256}
        with progress("guest-image-download"):
            from scripts.validation_timeouts import watchdog

            base = directory / "base.img"
            command(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    str(DOWNLOAD_WORKER),
                    str(base),
                    IMAGE_URL,
                    str(watchdog(30)),
                    str(IMAGE_BYTES),
                ],
                "guest-image-download",
                600,
            )
            identity(base)
            if base.stat().st_size != IMAGE_BYTES or digest(base) != IMAGE_SHA256:
                raise GuestInputError("unauthenticated-image")
            base.chmod(0o400)
            owner.register("base.img")
            info = image_info(command, owner.path("base.img", enrollment))
            if (
                info["virtual-size"] != BASE_VIRTUAL_BYTES
                or info.get("backing-filename") is not None
            ):
                raise GuestInputError("unexpected-base-image")
            report["base"] = {
                "bytes": IMAGE_BYTES,
                "virtual_bytes": BASE_VIRTUAL_BYTES,
                "format": "qcow2",
                "read_only": True,
            }
        with progress("guest-image-disks"):
            disks = []
            for name, size in DISK_BYTES.items():
                path = directory / name
                descriptor = os.open(
                    path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                )
                os.close(descriptor)
                owner.register(name)
                arguments = [str(QEMU_IMG), "create", "-q", "-f", "qcow2"]
                if name == "root.qcow2":
                    arguments += ["-F", "qcow2", "-b", str(owner.path("base.img", enrollment))]
                arguments += [str(owner.path(name, enrollment)), str(size)]
                command(arguments, "guest-image-create", 30)
                observed = image_info(command, owner.path(name, enrollment))
                if observed["virtual-size"] != size:
                    raise GuestInputError("disk-extent-mismatch")
                backing = observed.get("full-backing-filename", observed.get("backing-filename"))
                if name == "root.qcow2":
                    if (
                        backing != str(owner.path("base.img", enrollment))
                        or observed.get("backing-filename-format") != "qcow2"
                    ):
                        raise GuestInputError("foreign-backing-image")
                elif backing is not None:
                    raise GuestInputError("foreign-backing-image")
                disks.append(
                    {
                        "name": name,
                        "format": "qcow2",
                        "virtual_bytes": size,
                        "backing": "base.img" if name == "root.qcow2" else None,
                    }
                )
            report["disks"] = disks
            owner.verify(enrollment)
        try:
            yield owner
        finally:
            owner.verify(enrollment)
            if digest(QEMU_IMG) != tool_sha256:
                raise GuestInputError("image-tool-changed")
            report["base_preserved"] = True
        complete = True
    except OSError:
        raise GuestInputError("guest-input-resource-unavailable") from None
    finally:
        try:
            if directory is not None:
                # Refuse a substituted root; unlink links beneath our own root
                # without following them to unrelated data.
                try:
                    same = (
                        owner is not None
                        and identity(directory, directory=True) == owner.directory_identity
                    )
                except OSError:
                    same = False
                if not same:
                    raise GuestInputError("fixture-directory-replaced")
                try:
                    shutil.rmtree(directory)
                except OSError:
                    raise GuestInputError("guest-input-cleanup-failed") from None
                report["temporary_resources_removed"] = not directory.exists()
                if complete and report["temporary_resources_removed"]:
                    report["status"] = "passed"
        finally:
            report["statistics"] = metrics.finish()
            if not valid_stats(report["statistics"]):
                raise ValueError("invalid required guest input statistics")
