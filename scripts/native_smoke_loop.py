"""Retain exact image and kernel loop handles for disposable smoke consumers."""

from __future__ import annotations

import copy
import errno
import os
import stat
import struct
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, TypeVar

from scripts.validation_timeouts import Deadline

IMAGE_BYTES = 768 * 1024 * 1024
LOOP_CONFIGURE = 0x4C0A
LOOP_GET_STATUS64 = 0x4C05
LOOP_CTL_GET_FREE = 0x4C82
AUTOCLEAR = 4
INFO = struct.Struct("=5Q4I64s64s32s2Q")
T = TypeVar("T")


def require(value: Any, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def live(end: float) -> None:
    import math

    require(
        type(end) in {int, float} and math.isfinite(end) and Deadline(end).remaining() > 0,
        "loop-deadline-unavailable",
    )


def token(value: str) -> str:
    require(
        type(value) is str and str(uuid.UUID(value)) == value and uuid.UUID(value).version == 4,
        "loop-enrollment-unavailable",
    )
    return value


def metadata(value: os.stat_result) -> dict[str, int]:
    return {
        "device": value.st_dev,
        "inode": value.st_ino,
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode": value.st_mode,
        "links": value.st_nlink,
        "bytes": value.st_size,
    }


def kernel_device(device: int) -> int:
    # loop_info64 uses the kernel's new_encode_dev representation.
    major, minor = os.major(device), os.minor(device)
    return (minor & 0xFF) | (major << 8) | ((minor & ~0xFF) << 12)


def ioctl(descriptor: int, request: int, argument: int | bytearray = 0) -> int:
    from fcntl import ioctl as call

    result = call(descriptor, request, argument)
    require(type(result) is int, "loop-kernel-result-unavailable")
    return result


@dataclass
class ImageLease:
    _directory: int
    _descriptor: int
    _identity: dict[str, int]
    _directory_identity: dict[str, int]
    _closed: bool = False

    @classmethod
    def create(cls, arena: Path, end: float) -> ImageLease:
        live(end)
        directory = os.open(arena, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptor = None
        try:
            parent = os.fstat(directory)
            require(
                parent.st_uid == os.geteuid() and stat.S_IMODE(parent.st_mode) == 0o700,
                "loop-private-directory-unavailable",
            )
            descriptor = os.open(
                "image",
                os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory,
            )
            os.fchmod(descriptor, 0o600)
            os.ftruncate(descriptor, IMAGE_BYTES)
            os.fsync(descriptor)
            result = cls(directory, descriptor, metadata(os.fstat(descriptor)), metadata(parent))
            result.check(end)
            return result
        except BaseException as error:
            failures: list[BaseException] = [error]
            for handle in (descriptor, directory):
                if handle is not None:
                    try:
                        os.close(handle)
                    except OSError as cleanup:
                        failures.append(cleanup)
            if len(failures) > 1:
                raise BaseExceptionGroup(
                    "image admission and handle cleanup failed", failures
                ) from None
            raise

    def check(self, end: float) -> dict[str, int]:
        live(end)
        require(not self._closed, "loop-image-lease-ended")
        parent = metadata(os.fstat(self._directory))
        require(
            all(
                parent[k] == self._directory_identity[k]
                for k in ("device", "inode", "uid", "gid", "mode")
            ),
            "loop-private-directory-changed",
        )
        actual = metadata(os.fstat(self._descriptor))
        named = metadata(os.stat("image", dir_fd=self._directory, follow_symlinks=False))
        require(actual == named == self._identity, "loop-image-custody-changed")
        require(
            stat.S_ISREG(actual["mode"])
            and stat.S_IMODE(actual["mode"]) == 0o600
            and actual["uid"] == os.geteuid()
            and actual["links"] == 1
            and actual["bytes"] == IMAGE_BYTES,
            "loop-image-custody-unavailable",
        )
        return dict(actual)

    def descriptor(self, end: float) -> int:
        self.check(end)
        return self._descriptor

    def close(self) -> None:
        require(not self._closed, "loop-image-lease-ended")
        self._closed = True
        failures = []
        for descriptor in (self._descriptor, self._directory):
            try:
                os.close(descriptor)
            except OSError as error:
                failures.append(error)
        if failures:
            raise ExceptionGroup("image handle cleanup failed", failures)


class Kernel(Protocol):
    def allocate(self) -> int: ...
    def configure(self, descriptor: int, image: int, enrollment: str) -> None: ...
    def observe(self, descriptor: int) -> dict[str, Any]: ...
    def close(self, descriptor: int) -> None: ...


def close_failed_admission(descriptor: int, primary: BaseException) -> None:
    try:
        os.close(descriptor)
    except OSError as cleanup:
        raise BaseExceptionGroup(
            "kernel admission and handle cleanup failed", [primary, cleanup]
        ) from None


class KernelLoops:
    def __init__(self, devices: Path = Path("/dev")):
        self.devices = devices

    def allocate(self) -> int:
        require(os.geteuid() == 0, "loop-root-owner-required")
        control = os.open(self.devices / "loop-control", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            value = os.fstat(control)
            require(
                stat.S_ISCHR(value.st_mode)
                and value.st_uid == 0
                and (os.major(value.st_rdev), os.minor(value.st_rdev)) == (10, 237),
                "loop-control-custody-unavailable",
            )
            number = ioctl(control, LOOP_CTL_GET_FREE)
            require(type(number) is int and number >= 0, "loop-device-number-unavailable")
        except BaseException as error:
            close_failed_admission(control, error)
            raise
        else:
            os.close(control)
        descriptor = os.open(
            self.devices / ("loop" + str(number)), os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        try:
            value = os.fstat(descriptor)
            require(
                stat.S_ISBLK(value.st_mode)
                and value.st_uid == 0
                and os.major(value.st_rdev) == 7
                and os.minor(value.st_rdev) == number,
                "loop-block-device-custody-unavailable",
            )
            return descriptor
        except BaseException as error:
            close_failed_admission(descriptor, error)
            raise

    def configure(self, descriptor: int, image: int, enrollment: str) -> None:
        name = token(enrollment).encode()
        info = INFO.pack(0, 0, 0, 0, 0, 0, 0, 0, AUTOCLEAR, name, b"", b"", 0, 0)
        buffer = bytearray(struct.pack("=II", image, 0) + info + bytes(64))
        ioctl(descriptor, LOOP_CONFIGURE, buffer)

    def observe(self, descriptor: int) -> dict[str, Any]:
        node = os.fstat(descriptor)
        require(stat.S_ISBLK(node.st_mode) and node.st_uid == 0, "loop-block-device-changed")
        buffer = bytearray(INFO.size)
        ioctl(descriptor, LOOP_GET_STATUS64, buffer)
        (
            device,
            inode,
            rdevice,
            offset,
            size,
            number,
            encryption,
            key_size,
            flags,
            name,
            crypt,
            key,
            *reserved,
        ) = INFO.unpack(buffer)
        require(
            os.major(node.st_rdev) == 7
            and number == os.minor(node.st_rdev)
            and not any((rdevice, offset, size, encryption, key_size, *reserved))
            and flags == AUTOCLEAR
            and crypt == bytes(64)
            and key == bytes(32),
            "loop-association-custody-unavailable",
        )
        enrollment = name.rstrip(b"\0").decode("ascii")
        token(enrollment)
        require(name == enrollment.encode().ljust(64, b"\0"), "loop-association-name-unavailable")
        return {
            "node": {"device": node.st_dev, "inode": node.st_ino, "rdevice": node.st_rdev},
            "backing_device": device,
            "backing_inode": inode,
            "number": number,
            "flags": flags,
            "enrollment": enrollment,
        }

    def close(self, descriptor: int) -> None:
        # Autoclear ends only this held association when all references are gone.
        # Never issue LOOP_CLR_FD or act on a device pathname supplied in a claim.
        os.close(descriptor)


def same_claim(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            same_claim(actual[k], v) for k, v in expected.items()
        )
    return bool(actual == expected)


@dataclass
class LoopLease:
    _image: ImageLease
    _kernel: Kernel
    _descriptor: int
    _identity: dict[str, Any]
    _closed: bool = False

    @classmethod
    def acquire(cls, image: ImageLease, kernel: Kernel, enrollment: str, end: float) -> LoopLease:
        live(end)
        token(enrollment)
        identity = image.check(end)
        descriptor = kernel.allocate()
        try:
            live(end)
            kernel.configure(descriptor, image.descriptor(end), enrollment)
            observed = kernel.observe(descriptor)
            require(
                observed["backing_device"] == kernel_device(identity["device"])
                and observed["backing_inode"] == identity["inode"]
                and observed["enrollment"] == enrollment,
                "loop-backing-custody-mismatch",
            )
            result = cls(
                image,
                kernel,
                descriptor,
                {"image": identity, "association": copy.deepcopy(observed)},
            )
            result.check(result.claim(), end)
            return result
        except BaseException as error:
            try:
                kernel.close(descriptor)
            except OSError as cleanup:
                raise BaseExceptionGroup(
                    "loop admission and handle cleanup failed", [error, cleanup]
                ) from None
            raise

    def claim(self) -> dict[str, Any]:
        require(not self._closed, "loop-lease-ended")
        return copy.deepcopy(self._identity)

    def check(self, claim: Any, end: float) -> None:
        live(end)
        require(not self._closed, "loop-lease-ended")
        require(same_claim(claim, self._identity), "loop-foreign-claim-refused")
        require(self._image.check(end) == self._identity["image"], "loop-image-changed")
        require(
            same_claim(self._kernel.observe(self._descriptor), self._identity["association"]),
            "loop-association-changed",
        )

    def use(self, claim: Any, end: float, operation: Callable[[int], T]) -> T:
        self.check(claim, end)
        return operation(self._descriptor)

    def close(self) -> None:
        require(not self._closed, "loop-lease-ended")
        self._closed = True
        self._kernel.close(self._descriptor)


def association_absent(descriptor: int) -> bool:
    try:
        ioctl(descriptor, LOOP_GET_STATUS64, bytearray(INFO.size))
    except OSError as error:
        if error.errno == errno.ENXIO:
            return True
        raise
    return False
