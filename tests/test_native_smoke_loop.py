"""Observe pinned-file and loop-handle behavior without native mount/loop effects."""

from __future__ import annotations

import copy
import errno
import os
import stat
import struct
import uuid
from types import SimpleNamespace

import pytest

from scripts import native_smoke_loop as loop

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/native_smoke_loop.py", "scripts/validation_timeouts.py"],
    "scope": "actual unprivileged private-image descriptors and inode substitution, isolated binary loop UAPI observations and atomic configuration/effect ordering, retained lease refusal and failure preservation without native block/mount/format operations",
    "relationship": "no-product-claim",
    "reason": "Isolated kernel calls and ordinary pinned files do not qualify a native loop association, mounted fixture or product owner.",
    "claims": [],
}


def end():
    from scripts.validation_timeouts import Deadline

    return Deadline.after(10).end


@pytest.fixture
def image(tmp_path):
    arena = tmp_path / "arena"
    arena.mkdir(mode=0o700)
    value = loop.ImageLease.create(arena, end())
    yield value, arena
    if not value._closed:
        value.close()


class FakeKernel:
    def __init__(self, image):
        self.image = image
        self.enrollment = None
        self.calls = []
        self.problem = None
        self.row = None
        self.fd = None
        self.close_problem = False

    def allocate(self):
        self.calls.append("allocate")
        if self.problem == "allocation":
            raise OSError(errno.ENODEV, "controlled")
        self.fd = os.dup(self.image.descriptor(end()))
        return self.fd

    def configure(self, descriptor, image, enrollment):
        self.calls.append("configure")
        assert descriptor == self.fd and image == self.image.descriptor(end())
        if self.problem == "occupied":
            raise OSError(errno.EBUSY, "controlled competing association")
        self.enrollment = enrollment
        self.row = {
            "node": {"device": 3, "inode": 44, "rdevice": os.makedev(7, 123)},
            "backing_device": loop.kernel_device(self.image._identity["device"]),
            "backing_inode": self.image._identity["inode"],
            "number": 123,
            "flags": loop.AUTOCLEAR,
            "enrollment": enrollment,
        }

    def observe(self, descriptor):
        self.calls.append("observe")
        assert descriptor == self.fd
        if self.problem == "unavailable":
            raise OSError(errno.EIO, "controlled unavailable witness")
        result = copy.deepcopy(self.row)
        if self.problem == "foreign":
            result["backing_inode"] += 1
        return result

    def close(self, descriptor):
        self.calls.append("close")
        os.close(descriptor)
        if self.close_problem:
            raise OSError(errno.EIO, "controlled close outcome unavailable")


@pytest.fixture
def owned(image):
    value, arena = image
    kernel = FakeKernel(value)
    lease = loop.LoopLease.acquire(value, kernel, str(uuid.uuid4()), end())
    yield lease, kernel, arena
    if not lease._closed:
        lease.close()


def test_actual_private_image_is_exclusive_owner_only_pinned_and_retained(image):
    value, arena = image
    original = value.check(end())
    assert original["bytes"] == loop.IMAGE_BYTES == 768 * 1024 * 1024
    assert stat.S_IMODE(original["mode"]) == 0o600 and original["links"] == 1
    assert original["uid"] == os.geteuid() and original["inode"] > 0
    with pytest.raises(FileExistsError):
        loop.ImageLease.create(arena, end())
    assert value.check(end()) == original
    descriptor = value.descriptor(end())
    os.pwrite(descriptor, b"owned-content", 0)
    assert value.check(end()) == original
    assert os.pread(descriptor, 13, 0) == b"owned-content"
    value.close()
    assert (arena / "image").exists()
    with pytest.raises(ValueError):
        value.descriptor(end())


@pytest.mark.parametrize(
    "change", ["symlink", "substitution", "hardlink", "mode", "extent", "directory-mode"]
)
def test_changed_image_or_private_directory_cannot_authorize_effects(image, change):
    value, arena = image
    if change in {"symlink", "substitution"}:
        (arena / "image").rename(arena / "original")
        if change == "symlink":
            (arena / "image").symlink_to(arena / "original")
        else:
            (arena / "image").write_bytes(b"foreign")
            (arena / "image").chmod(0o600)
    elif change == "hardlink":
        os.link(arena / "image", arena / "additional")
    elif change == "mode":
        (arena / "image").chmod(0o644)
    elif change == "extent":
        os.ftruncate(value._descriptor, 1)
    else:
        arena.chmod(0o755)
    kernel = FakeKernel(value)
    with pytest.raises((OSError, ValueError)):
        loop.LoopLease.acquire(value, kernel, str(uuid.uuid4()), end())
    assert kernel.calls == []
    if change == "substitution":
        assert (arena / "image").read_bytes() == b"foreign"


@pytest.mark.parametrize(
    "change", ["symlink", "public-directory", "preexisting-image", "preexisting-link"]
)
def test_image_creation_refuses_unowned_input_without_replacing_it(tmp_path, change):
    arena = tmp_path / "arena"
    arena.mkdir(mode=0o700)
    unrelated = tmp_path / "unrelated"
    unrelated.write_bytes(b"preserve")
    source = arena
    if change == "symlink":
        source = tmp_path / "link"
        source.symlink_to(arena, target_is_directory=True)
    elif change == "public-directory":
        arena.chmod(0o755)
    elif change == "preexisting-image":
        (arena / "image").write_bytes(b"preserve")
    else:
        (arena / "image").symlink_to(unrelated)
    with pytest.raises((ValueError, OSError)):
        loop.ImageLease.create(source, end())
    assert unrelated.read_bytes() == b"preserve"
    if change.startswith("preexisting"):
        assert (arena / "image").read_bytes() == b"preserve"


def test_retained_lease_checks_before_effect_and_only_releases_its_own_handle(owned):
    lease, kernel, _ = owned
    effects = []
    claim = lease.claim()
    assert lease.use(claim, end(), lambda fd: effects.append(fd) or "formatted") == "formatted"
    assert effects == [kernel.fd] and kernel.calls[:3] == ["allocate", "configure", "observe"]
    assert kernel.enrollment == claim["association"]["enrollment"]
    prior = list(kernel.calls)
    lease.close()
    assert kernel.calls == [*prior, "close"]
    with pytest.raises(OSError):
        os.fstat(kernel.fd)
    assert lease._image.check(end()) == claim["image"]


@pytest.mark.parametrize(
    "change",
    [
        "enrollment",
        "inode",
        "device",
        "number",
        "flags",
        "boolean",
        "extra",
        "missing",
        "foreign-path",
    ],
)
def test_foreign_claim_cannot_reach_effects_or_close_foreign_resources(owned, change):
    lease, kernel, arena = owned
    claim = lease.claim()
    if change in {"enrollment", "number", "flags"}:
        claim["association"][change] = str(uuid.uuid4()) if change == "enrollment" else -1
    elif change == "inode":
        claim["image"]["inode"] += 1
    elif change == "device":
        claim["association"]["node"]["rdevice"] += 1
    elif change == "boolean":
        claim["association"]["flags"] = True
    elif change == "extra":
        claim["extra"] = True
    elif change == "missing":
        del claim["association"]["enrollment"]
    else:
        claim["association"]["path"] = str(arena / "foreign")
    calls = list(kernel.calls)
    effects = []
    with pytest.raises(ValueError):
        lease.use(claim, end(), effects.append)
    assert not effects and kernel.calls == calls
    assert lease.claim() != claim and lease._image.check(end()) == lease.claim()["image"]


@pytest.mark.parametrize("problem", ["allocation", "occupied", "unavailable", "foreign"])
def test_failed_or_competing_admission_preserves_primary_failure_and_avoids_effects(image, problem):
    value, arena = image
    kernel = FakeKernel(value)
    kernel.problem = problem
    with pytest.raises((OSError, ValueError)) as caught:
        loop.LoopLease.acquire(value, kernel, str(uuid.uuid4()), end())
    assert (arena / "image").exists()
    if problem == "allocation":
        assert kernel.calls == ["allocate"]
    else:
        assert kernel.calls[-1] == "close"
        with pytest.raises(OSError):
            os.fstat(kernel.fd)
    if problem == "occupied":
        assert caught.value.errno == errno.EBUSY
        assert kernel.calls == ["allocate", "configure", "close"]


def test_original_and_cleanup_errors_remain_distinct(image):
    value, _ = image
    kernel = FakeKernel(value)
    kernel.problem = "occupied"
    kernel.close_problem = True
    with pytest.raises(ExceptionGroup) as caught:
        loop.LoopLease.acquire(value, kernel, str(uuid.uuid4()), end())
    primary, cleanup = caught.value.exceptions
    assert primary.errno == errno.EBUSY and cleanup.errno == errno.EIO
    assert kernel.calls == ["allocate", "configure", "close"]


@pytest.mark.parametrize("problem", ["foreign", "unavailable", "image"])
def test_live_observation_change_refuses_effect_but_still_releases_exact_handle(owned, problem):
    lease, kernel, arena = owned
    claim = lease.claim()
    if problem == "image":
        (arena / "image").chmod(0o644)
    else:
        kernel.problem = problem
    effects = []
    with pytest.raises((ValueError, OSError)):
        lease.use(claim, end(), effects.append)
    assert not effects
    lease.close()
    assert kernel.calls[-1] == "close"


def test_closed_lease_cannot_adopt_a_reused_descriptor(owned):
    lease, kernel, arena = owned
    claim = lease.claim()
    descriptor = kernel.fd
    lease.close()
    replacement = os.open(arena / "image", os.O_RDWR)
    if replacement != descriptor:
        os.dup2(replacement, descriptor)
    calls = list(kernel.calls)
    try:
        with pytest.raises(ValueError):
            lease.use(claim, end(), lambda _fd: pytest.fail("stale effect"))
        with pytest.raises(ValueError):
            lease.close()
        assert kernel.calls == calls and os.fstat(descriptor).st_ino == claim["image"]["inode"]
    finally:
        os.close(descriptor)
        if replacement != descriptor:
            os.close(replacement)


def test_close_failure_is_reported_and_never_retried_against_reused_handle(owned):
    lease, kernel, _ = owned
    kernel.close_problem = True
    with pytest.raises(OSError):
        lease.close()
    assert lease._closed
    calls = list(kernel.calls)
    with pytest.raises(ValueError):
        lease.close()
    assert kernel.calls == calls


@pytest.mark.parametrize("expiry", [True, float("inf"), float("nan"), 0.0])
def test_unavailable_deadline_refuses_image_and_loop_effects(image, expiry):
    value, arena = image
    kernel = FakeKernel(value)
    with pytest.raises(ValueError):
        loop.LoopLease.acquire(value, kernel, str(uuid.uuid4()), expiry)
    with pytest.raises(ValueError):
        loop.ImageLease.create(arena, expiry)
    assert not kernel.calls


def test_configuration_is_one_atomic_autoclear_request_with_pinned_image_fd(monkeypatch):
    requests = []
    monkeypatch.setattr(loop, "ioctl", lambda *args: requests.append(args) or 0)
    enrollment = str(uuid.uuid4())
    loop.KernelLoops().configure(41, 42, enrollment)
    ((descriptor, operation, raw),) = requests
    assert descriptor == 41 and operation == loop.LOOP_CONFIGURE and len(raw) == 304
    assert struct.unpack_from("=II", raw) == (42, 0)
    row = loop.INFO.unpack_from(raw, 8)
    assert row[:8] == (0,) * 8 and row[8] == loop.AUTOCLEAR
    assert row[9] == enrollment.encode().ljust(64, b"\0") and not any(raw[240:])


@pytest.fixture
def binary_observation(monkeypatch):
    enrollment = str(uuid.uuid4())
    values = [123, 456, 0, 0, 0, 17, 0, 0, loop.AUTOCLEAR, enrollment.encode(), b"", b"", 0, 0]
    node = SimpleNamespace(
        st_mode=stat.S_IFBLK | 0o660, st_uid=0, st_dev=7, st_ino=88, st_rdev=os.makedev(7, 17)
    )
    monkeypatch.setattr(loop.os, "fstat", lambda _: node)
    calls = []

    def get(descriptor, request, argument):
        calls.append((descriptor, request))
        argument[:] = loop.INFO.pack(*values)
        return 0

    monkeypatch.setattr(loop, "ioctl", get)
    return values, node, enrollment, calls


def test_binary_observer_exposes_only_exact_association_metadata(binary_observation):
    _, _, enrollment, calls = binary_observation
    result = loop.KernelLoops().observe(41)
    assert result == {
        "node": {"device": 7, "inode": 88, "rdevice": os.makedev(7, 17)},
        "backing_device": 123,
        "backing_inode": 456,
        "number": 17,
        "flags": loop.AUTOCLEAR,
        "enrollment": enrollment,
    }
    assert calls == [(41, loop.LOOP_GET_STATUS64)]


@pytest.mark.parametrize(
    "field",
    [
        "rdevice",
        "offset",
        "extent",
        "number",
        "encryption",
        "key-size",
        "flags",
        "name",
        "crypt",
        "key",
        "reserved",
        "node-kind",
        "node-owner",
        "node-device",
    ],
)
def test_binary_observer_refuses_foreign_or_unsupported_associations(binary_observation, field):
    values, node, _, _ = binary_observation
    changes = {
        "rdevice": 2,
        "offset": 3,
        "extent": 4,
        "number": 5,
        "encryption": 6,
        "key-size": 7,
        "flags": 8,
        "name": 9,
        "crypt": 10,
        "key": 11,
        "reserved": 12,
    }
    if field in changes:
        index = changes[field]
        values[index] = b"invalid" if index in {9, 10, 11} else 999
    elif field == "node-kind":
        node.st_mode = stat.S_IFREG | 0o600
    elif field == "node-owner":
        node.st_uid = 1000
    else:
        node.st_rdev = os.makedev(8, 17)
    with pytest.raises(ValueError):
        loop.KernelLoops().observe(41)


@pytest.mark.parametrize("failure", [None, errno.ENXIO, errno.EIO, errno.ENOTTY, errno.EACCES])
def test_only_explicit_kernel_unbound_observation_proves_absence(monkeypatch, failure):
    def get(*_args):
        if failure is not None:
            raise OSError(failure, "controlled")
        return 0

    monkeypatch.setattr(loop, "ioctl", get)
    if failure not in {None, errno.ENXIO}:
        with pytest.raises(OSError):
            loop.association_absent(41)
    else:
        assert loop.association_absent(41) is (failure == errno.ENXIO)


@pytest.mark.parametrize(
    "major,minor,encoded",
    [(0, 0, 0), (8, 1, 0x801), (259, 65537, 0x10010301), (4095, 1048575, 0xFFFFFFFF)],
)
def test_backing_device_uses_kernel_uapi_values(major, minor, encoded):
    assert loop.kernel_device(os.makedev(major, minor)) == encoded


@pytest.fixture
def allocation_observation(monkeypatch):
    control = SimpleNamespace(st_mode=stat.S_IFCHR | 0o660, st_uid=0, st_rdev=os.makedev(10, 237))
    block = SimpleNamespace(st_mode=stat.S_IFBLK | 0o660, st_uid=0, st_rdev=os.makedev(7, 17))
    calls = []
    state = SimpleNamespace(control=control, block=block, uid=0, number=17, denied=None)

    def open_node(path, flags):
        calls.append(("open", path.name, flags))
        if state.denied == path.name:
            raise OSError(errno.ELOOP, "controlled path substitution")
        return 51 if path.name == "loop-control" else 52

    def inspect(fd):
        return control if fd == 51 else block

    def kernel_call(fd, operation, argument=0):
        calls.append(("ioctl", fd, operation, argument))
        return state.number

    monkeypatch.setattr(
        loop,
        "os",
        SimpleNamespace(
            geteuid=lambda: state.uid,
            open=open_node,
            fstat=inspect,
            close=lambda fd: calls.append(("close", fd)),
            major=os.major,
            minor=os.minor,
            O_RDWR=os.O_RDWR,
            O_NOFOLLOW=os.O_NOFOLLOW,
            O_CLOEXEC=os.O_CLOEXEC,
        ),
    )
    monkeypatch.setattr(loop, "ioctl", kernel_call)
    return state, calls


def test_kernel_allocation_checks_exact_control_and_block_identities_without_retries(
    allocation_observation,
):
    _, calls = allocation_observation
    assert loop.KernelLoops().allocate() == 52
    assert calls == [
        ("open", "loop-control", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC),
        ("ioctl", 51, loop.LOOP_CTL_GET_FREE, 0),
        ("close", 51),
        ("open", "loop17", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC),
    ]


@pytest.mark.parametrize(
    "change",
    [
        "uid",
        "control-kind",
        "control-owner",
        "control-device",
        "block-kind",
        "block-owner",
        "block-major",
        "block-minor",
        "control-link",
        "block-link",
        "negative-number",
        "boolean-number",
    ],
)
def test_substituted_device_cannot_be_allocated_or_reconfigured(allocation_observation, change):
    state, calls = allocation_observation
    if change == "uid":
        state.uid = 1000
    elif change == "control-kind":
        state.control.st_mode = stat.S_IFREG | 0o600
    elif change == "control-owner":
        state.control.st_uid = 1000
    elif change == "control-device":
        state.control.st_rdev = os.makedev(10, 238)
    elif change == "block-kind":
        state.block.st_mode = stat.S_IFREG | 0o600
    elif change == "block-owner":
        state.block.st_uid = 1000
    elif change == "block-major":
        state.block.st_rdev = os.makedev(8, 17)
    elif change == "block-minor":
        state.block.st_rdev = os.makedev(7, 18)
    elif change == "control-link":
        state.denied = "loop-control"
    elif change == "block-link":
        state.denied = "loop17"
    elif change == "negative-number":
        state.number = -1
    else:
        state.number = True
    with pytest.raises((OSError, ValueError)):
        loop.KernelLoops().allocate()
    assert all(row[2] == loop.LOOP_CTL_GET_FREE for row in calls if row[0] == "ioctl")
    if change == "uid":
        assert not calls
    elif change.startswith("block-") and change != "block-link":
        assert calls[-1] == ("close", 52)
    elif change != "control-link" and change != "block-link":
        assert calls[-1] == ("close", 51)


@pytest.mark.parametrize(
    "enrollment",
    ["", "not-an-enrollment", str(uuid.UUID(int=0)), "1" * 36, 1, True],
    ids=["empty", "malformed", "not-fresh", "malformed-width", "integer", "boolean"],
)
def test_unavailable_enrollment_is_refused_before_kernel_effects(image, enrollment):
    value, _ = image
    kernel = FakeKernel(value)
    with pytest.raises(ValueError):
        loop.LoopLease.acquire(value, kernel, enrollment, end())
    assert not kernel.calls


def test_private_image_is_owner_only_even_under_permissive_umask(tmp_path):
    arena = tmp_path / "private"
    arena.mkdir(mode=0o700)
    previous = os.umask(0)
    try:
        value = loop.ImageLease.create(arena, end())
    finally:
        os.umask(previous)
    try:
        assert stat.S_IMODE((arena / "image").stat().st_mode) == 0o600
        assert value.check(end())["uid"] == os.geteuid()
    finally:
        value.close()


@pytest.mark.parametrize("stage", ["control", "block"])
def test_kernel_allocation_preserves_observation_and_cleanup_failure(
    allocation_observation, monkeypatch, stage
):
    state, calls = allocation_observation
    if stage == "control":
        state.control.st_uid = 1000
    else:
        state.block.st_uid = 1000
    descriptor = 51 if stage == "control" else 52
    normal = loop.os.close

    def close(fd):
        normal(fd)
        if fd == descriptor:
            raise OSError(errno.EIO, "controlled cleanup unavailable")

    monkeypatch.setattr(loop.os, "close", close)
    with pytest.raises(ExceptionGroup) as caught:
        loop.KernelLoops().allocate()
    primary, cleanup = caught.value.exceptions
    assert isinstance(primary, ValueError) and cleanup.errno == errno.EIO
    assert calls[-1] == ("close", descriptor)
