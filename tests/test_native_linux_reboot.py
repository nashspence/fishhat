"""Exercise reboot tooling with substituted guest/kernel/SSH; never reboot a host."""

from __future__ import annotations

import ast
import copy
import errno
import hashlib
import io
import json
import os
import shlex
import socket
import stat
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager, nullcontext, redirect_stdout
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

from scripts import native_linux_enrollment as native
from scripts import native_linux_guest as guests
from scripts import native_linux_images as images
from scripts import native_linux_reboot as reboot
from scripts.run_stats import RunStats, valid_stats
from scripts.validation_timeouts import Deadline, watchdog

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/native_linux_reboot.py",
        "scripts/native_linux_guest.py",
        "scripts/native_linux_enrollment.py",
    ],
    "scope": "controlled execution of persistent-root canary admission, guarded prior-byte comparison and different-byte persistence/readback/fsync, exact disk identity queries, delayed new-boot observations with bounded read-only timeout recovery and deterministic shared observation-budget exhaustion, exact host custody, original request acknowledgement/loss, stale/foreign command refusal, admission ordering, selected pre-admission observer interruption, independent whole-resource absence and required scoped statistics",
    "relationship": "no-product-claim",
    "reason": "Guest devices/filesystem/boot/SSH and controller observations are substituted. Actual embedded canary I/O also runs against unprivileged temporary file descriptors; private sockets and short child processes challenge custody/absence guards. No QEMU, native canary advance/reboot, product continuity or writer authority is qualified.",
    "claims": [],
}


class Facilities:
    """Only in-memory files/devices and substituted read-only utility output."""

    def __init__(self):
        self.enrollment, self.boot, self.nonce, self.fs_uuid = (str(uuid.uuid4()) for _ in range(4))
        self.root = "/var/lib/fhr-" + uuid.UUID(self.enrollment).hex
        self.meta, self.files, self.fds, self.offsets = {}, {}, {}, {}
        self.events = []
        self.mountinfo = ""
        self.pid = 50
        self.disk_rows = {}
        for i, role in enumerate(("root", "control", "data")):
            path = "/dev/vd" + chr(ord("a") + i)
            self.meta[path] = self.metadata(
                stat.S_IFBLK | 0o600, 0, i + 1, rdev=os.makedev(8, i * 16)
            )
            self.disk_rows[path] = {
                "path": path,
                "type": "disk",
                "size": images.DISK_BYTES[role + ".qcow2"],
                "serial": "fh-" + role,
                "maj:min": "8:" + str(i * 16),
                "ro": False,
            }
        self.meta["/dev/vda1"] = self.metadata(stat.S_IFBLK | 0o600, 0, 5, rdev=os.makedev(8, 1))
        for path, inode in (("/", 2), ("/var/lib", 10)):
            self.meta[path] = self.metadata(stat.S_IFDIR | 0o755, os.makedev(8, 1), inode)
        self.mount = {
            "source": "/dev/vda1",
            "target": "/",
            "fstype": "ext4",
            "uuid": self.fs_uuid,
            "maj:min": "8:1",
            "options": "rw,relatime",
        }
        self.partition = {
            "path": "/dev/vda1",
            "type": "part",
            "pkname": "/dev/vda",
            "uuid": self.fs_uuid,
            "fstype": "ext4",
            "maj:min": "8:1",
        }
        self.c = {
            "enrollment": self.enrollment,
            "boot_id": self.boot,
            "nonce": self.nonce,
            "sizes": {k.removesuffix(".qcow2"): v for k, v in images.DISK_BYTES.items()},
        }

    @staticmethod
    def metadata(mode, device, inode, *, rdev=0):
        return SimpleNamespace(
            st_mode=mode,
            st_dev=device,
            st_ino=inode,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
            st_size=0,
            st_rdev=rdev,
        )

    def path(self, value):
        h = self

        class Path(PurePosixPath):
            def lstat(self):
                if str(self) not in h.meta:
                    raise FileNotFoundError(str(self))
                return copy.copy(h.meta[str(self)])

            stat = lstat

            def resolve(self, *, strict):
                assert strict
                for role, name in (("root", "a"), ("control", "b"), ("data", "c")):
                    if str(self) == "/dev/disk/by-id/virtio-fh-" + role:
                        return Path("/dev/vd" + name)
                assert str(self) in h.meta
                return self

            def exists(self):
                return str(self) in h.meta

            def is_symlink(self):
                return self.exists() and stat.S_ISLNK(self.lstat().st_mode)

            def read_text(self):
                return {
                    "/etc/fishhat-fixture-enrollment": h.enrollment,
                    "/proc/sys/kernel/random/boot_id": h.boot,
                    "/proc/self/mountinfo": h.mountinfo,
                }[str(self)]

            def read_bytes(self):
                assert str(self) == "/proc/self/exe"
                return b"controlled-guest-interpreter"

        return Path(str(value))

    def open(self, path, flags, mode=0o777, *, dir_fd=None):
        path = str(PurePosixPath(self.fds[dir_fd]) / path) if dir_fd is not None else str(path)
        if flags & os.O_CREAT:
            assert flags & os.O_EXCL and path not in self.meta
            self.meta[path] = self.metadata(stat.S_IFREG | mode, os.makedev(8, 1), 101)
            self.files[path] = b""
            self.events.append("create:" + path)
        if path not in self.meta:
            raise FileNotFoundError(path)
        if stat.S_ISLNK(self.meta[path].st_mode):
            raise OSError(errno.ELOOP, "controlled-symlink")
        if flags & os.O_DIRECTORY:
            assert stat.S_ISDIR(self.meta[path].st_mode)
        fd = 100 + len(self.fds)
        assert fd not in self.fds
        self.fds[fd], self.offsets[fd] = path, 0
        return fd

    def mkdir(self, name, *, mode, dir_fd):
        path = str(PurePosixPath(self.fds[dir_fd]) / name)
        assert path not in self.meta
        self.meta[path] = self.metadata(stat.S_IFDIR | mode, os.makedev(8, 1), 100)
        self.events.append("mkdir:" + path)

    def close(self, fd):
        del self.fds[fd], self.offsets[fd]

    def write(self, fd, content):
        path, offset = self.fds[fd], self.offsets[fd]
        self.files[path] = (
            self.files[path][:offset] + bytes(content) + self.files[path][offset + len(content) :]
        )
        self.meta[path].st_size = len(self.files[path])
        self.offsets[fd] += len(content)
        self.events.append("write:" + path)
        return len(content)

    def read(self, fd, size):
        offset = self.offsets[fd]
        result = self.files[self.fds[fd]][offset : offset + size]
        self.offsets[fd] += len(result)
        return result

    def seek(self, fd, position, whence):
        assert whence == os.SEEK_SET and position == 0
        self.offsets[fd] = position
        return position

    def run(self, arguments, **kwargs):
        assert kwargs["check"] and kwargs["timeout"] > 0 and kwargs["stderr"] == subprocess.DEVNULL
        assert kwargs["env"] == {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
        }
        if arguments[0] == "/usr/bin/findmnt":
            value = {"filesystems": [self.mount]}
        else:
            assert arguments[0] == "/usr/bin/lsblk" and "--nodeps" in arguments
            value = {
                "blockdevices": [
                    self.disk_rows[arguments[-1]] if "--bytes" in arguments else self.partition
                ]
            }
        return SimpleNamespace(stdout=json.dumps(value))

    def execute(self, c):
        self.pid += 1
        tree = ast.parse(reboot.PROGRAM)
        tree.body = [node for node in tree.body if not isinstance(node, ast.Import)]
        calls = {
            k: getattr(os, k)
            for k in (
                "O_RDONLY",
                "O_WRONLY",
                "O_RDWR",
                "O_CREAT",
                "O_EXCL",
                "O_DIRECTORY",
                "O_NOFOLLOW",
                "SEEK_SET",
                "makedev",
            )
        }
        calls.update(
            geteuid=lambda: 0,
            getpid=lambda: self.pid,
            open=self.open,
            close=self.close,
            mkdir=self.mkdir,
            read=self.read,
            write=self.write,
            lseek=self.seek,
            fstat=lambda fd: copy.copy(self.meta[self.fds[fd]]),
            fsync=lambda fd: self.events.append("fsync:" + self.fds[fd]),
            readlink=lambda p: "/usr/bin/python3.12",
        )
        output = io.StringIO()
        with redirect_stdout(output):
            exec(
                compile(tree, "<controlled-reboot>", "exec"),
                dict(
                    hashlib=hashlib,
                    json=json,
                    os=SimpleNamespace(**calls),
                    pathlib=SimpleNamespace(Path=self.path),
                    stat=stat,
                    subprocess=SimpleNamespace(
                        run=self.run, DEVNULL=subprocess.DEVNULL, PIPE=subprocess.PIPE
                    ),
                    sys=SimpleNamespace(argv=["program", json.dumps(c)]),
                    time=time,
                    uuid=uuid,
                ),
            )
        return json.loads(output.getvalue())

    def invoke(self, mode):
        return self.execute({**self.c, "mode": mode, "probe": str(uuid.uuid4()), "seconds": 60})

    def prepare(self):
        v = self.invoke("prepare")
        self.c.update(identity=v["identity"], image=v["observer"]["executable"])
        return v


def test_canary_program_reads_back_fsyncs_and_reobserves_exact_persistent_disk_state():
    h = Facilities()
    prepared = h.prepare()
    assert prepared["canary_fsynced"] is True and not h.fds
    assert {"fsync:" + h.root + "/canary", "fsync:" + h.root, "fsync:/var/lib"} <= set(h.events)
    assert prepared["identity"]["content"].encode() == h.files[h.root + "/canary"]
    h.boot = h.c["boot_id"] = str(uuid.uuid4())
    h.events.clear()
    first, second = h.invoke("inspect"), h.invoke("inspect")
    assert first["identity"] == second["identity"] == prepared["identity"]
    assert first["boot_id"] != prepared["boot_id"] and first["probe"] != second["probe"]
    assert first["observer"]["pid"] != second["observer"]["pid"]
    assert first["canary_fsynced"] is second["canary_fsynced"] is False
    assert first["denied_canary_absent"] and not h.events and not h.fds


@pytest.mark.parametrize(
    "change",
    [
        "enrollment",
        "boot",
        "capacity",
        "serial",
        "device",
        "parent-device",
        "parent-owner",
        "parent-mode",
        "root-readonly",
        "partition-parent",
        "mounted-target",
        "existing-directory",
    ],
)
def test_canary_prepare_refuses_foreign_storage_before_creating_state(change):
    h = Facilities()
    if change in ("enrollment", "boot"):
        h.c["enrollment" if change == "enrollment" else "boot_id"] = str(uuid.uuid4())
    elif change in ("capacity", "serial", "device"):
        key, value = {
            "capacity": ("size", 1),
            "serial": ("serial", "foreign"),
            "device": ("maj:min", "8:99"),
        }[change]
        h.disk_rows["/dev/vda"][key] = value
    elif change == "parent-device":
        h.meta["/var/lib"].st_dev += 1
    elif change == "parent-owner":
        h.meta["/var/lib"].st_uid = 1000
    elif change == "parent-mode":
        h.meta["/var/lib"].st_mode |= 0o002
    elif change == "root-readonly":
        h.mount["options"] = "ro"
    elif change == "partition-parent":
        h.partition["pkname"] = "/dev/vdb"
    elif change == "mounted-target":
        h.mountinfo = "1 2 8:1 / " + h.root + " rw - ext4 /dev/vda1 rw\n"
    else:
        h.meta[h.root] = h.metadata(stat.S_IFDIR | 0o700, os.makedev(8, 1), 100)
    before = copy.deepcopy(h.meta)
    with pytest.raises((ValueError, OSError)):
        h.invoke("prepare")
    assert before == h.meta and not h.events and not h.fds


@pytest.mark.parametrize(
    "change",
    [
        "bytes",
        "inode",
        "owner",
        "links",
        "mode",
        "directory",
        "symlink",
        "mount",
        "filesystem",
        "disk",
        "denied",
    ],
)
def test_inspect_refuses_changed_root_canary_without_mutating_it(change):
    h = Facilities()
    h.prepare()
    file = h.meta[h.root + "/canary"]
    if change == "bytes":
        h.files[h.root + "/canary"] = b"x" * file.st_size
    elif change == "inode":
        file.st_ino += 1
    elif change == "owner":
        file.st_uid = 1000
    elif change == "links":
        file.st_nlink = 2
    elif change == "mode":
        file.st_mode = stat.S_IFREG | 0o644
    elif change == "directory":
        h.meta[h.root].st_ino += 1
    elif change == "symlink":
        file.st_mode = stat.S_IFLNK | 0o777
    elif change == "mount":
        h.mountinfo = "1 2 8:1 / " + h.root + "/canary rw - ext4 /dev/vda1 rw\n"
    elif change == "filesystem":
        h.mount["uuid"] = h.partition["uuid"] = str(uuid.uuid4())
    elif change == "disk":
        h.disk_rows["/dev/vdc"]["size"] += 1
    else:
        h.meta[h.root + "/denied"] = copy.copy(file)
    before = copy.deepcopy(h.meta)
    h.events.clear()
    with pytest.raises((ValueError, OSError)):
        h.invoke("inspect")
    assert before == h.meta and not h.events and not h.fds


class ControlledGuest:
    remote = guests.Guest.remote
    guarded = guests.Guest.guarded
    validate = guests.Guest.validate
    validate_profile = guests.Guest.validate_profile

    def __init__(self):
        self.h = Facilities()
        self.enrollment = self.h.enrollment
        self.accounts = ("admin", "peer")
        self.observed = self.info(self.h.boot)
        self.original = copy.deepcopy(self.observed)
        self.after_boot = str(uuid.uuid4())
        self.report = {"identity": self.observed}
        self.requests = []
        self.observations = []
        self.sequence = ["new"]
        self.request_loss = False
        self.failure = None
        self.change = None

    def info(self, boot):
        return {
            "distribution": "ubuntu",
            "distribution_version": "24.04",
            "machine": "x86_64",
            "kernel": guests.KERNEL,
            "pid1": "systemd",
            "cgroup_v2": True,
            "boot_id": boot,
            "dmi_uuid": self.enrollment,
            "enrollment": self.enrollment,
            "instance_id": self.enrollment,
            "ssh_principal": "admin",
            "packages": guests.GUEST_PACKAGES,
            "cloud_init_complete": True,
            "accounts": {"admin": {"uid": 1000, "gid": 1000}, "peer": {"uid": 1001, "gid": 1001}},
        }

    def observe(self, deadline):
        assert deadline.remaining() > 0
        step = self.sequence.pop(0) if self.sequence else "new"
        self.observations.append(step)
        failures = {
            "down": ("guest-ssh", "command-exit-255"),
            "timeout": ("guest-ssh", "observation-deadline"),
            "error": ("guest-ssh", "command-exit-1"),
            "foreign-timeout": ("controller-identity", "observation-deadline"),
            "ssh-unavailable": ("guest-ssh", "command-unavailable"),
            "guard-refused": ("guest-ssh", "command-exit-73"),
        }
        if step in failures:
            raise native.EnrollmentError(*failures[step])
        if step not in ("old", "stuck"):
            self.h.boot = self.after_boot
        if step == "stuck":
            self.sequence.append("stuck")
        value = self.info(self.h.boot)
        if step == "incomplete":
            value["cloud_init_complete"] = False
        if step == "foreign":
            value["enrollment"] = str(uuid.uuid4())
        if step == "malformed":
            value["cloud_init_complete"] = 1
        return value

    def ssh(self, remote, *, deadline, nominal=15):
        assert deadline.remaining() > 0 and nominal > 0
        parts = shlex.split(remote)
        expected, action = json.loads(parts[-2]), json.loads(parts[-1])
        assert expected is not None
        actual = self.info(self.h.boot)
        if expected != actual:
            if self.failure == "guard-accepted":
                return ""
            raise native.EnrollmentError("guest-ssh", "command-exit-73")
        if action == reboot.REBOOT:
            self.requests.append(action)
            if self.failure == "request":
                raise native.EnrollmentError("guest-ssh", "command-exit-1")
            if self.failure == "request-timeout":
                raise native.EnrollmentError("guest-ssh", "observation-deadline")
            if self.request_loss:
                raise native.EnrollmentError("guest-ssh", "command-exit-255")
            return ""
        assert action[:4] == ["/usr/bin/python3", "-I", "-S", "-c"] and action[4] == reboot.PROGRAM
        assert self.observed == self.original
        result = self.h.execute(json.loads(action[-1]))
        if self.change:
            self.change(result)
        return json.dumps(result)


@pytest.fixture
def controlled(monkeypatch):
    guest = ControlledGuest()
    calls = []

    def custody(g, endpoint, deadline):
        assert g is guest and deadline.remaining() > 0
        assert guest.observed == guest.original
        calls.append(endpoint)
        if guest.failure == "host" and len(calls) == 2:
            return {"pid": 99}
        return {"pid": 42, "endpoint": "owned", "disks": "exact"}

    monkeypatch.setattr(reboot, "host_custody", custody)
    monkeypatch.setattr(reboot, "time", SimpleNamespace(sleep=lambda seconds: None))
    return guest, calls


@pytest.mark.parametrize("lost", [False, True], ids=["request-acknowledged", "request-reply-lost"])
def test_reboot_coordinator_requires_independent_new_boot_canary_custody_and_scoped_stats(
    controlled, tmp_path, lost
):
    guest, calls = controlled
    guest.sequence = ["timeout", "old", "down", "incomplete", "new", "new"]
    guest.request_loss = lost
    report = {}
    reboot.qualify_reboot(guest, tmp_path / "qmp", lambda name: nullcontext(), tmp_path, report)
    assert report["status"] == "passed" and report["reboot_continuity_qualified"] is True
    assert (
        report["resources_destroyed_with_guest"] is False
        and report["failed_restart_cleanup_qualified"] is False
        and report["snapshot_restore_qualified"] is False
    )
    assert len(guest.requests) == 1 and len(calls) == 2
    assert (
        report["before_identity"] == guest.original
        and report["after_identity"] == guest.observed == guest.report["identity"]
    )
    assert guest.original["boot_id"] != guest.observed["boot_id"]
    assert [p["phase"] for p in report["phases"]] == [
        "prepare",
        "request",
        "independent-boot",
        "independent-canary",
        "refusals",
        "final-observation",
    ]
    request = report["phases"][1]
    assert (
        request["outcome"] == ("unobserved" if lost else "request-acknowledged")
        and request["observed_exit_status"] == (255 if lost else 0)
        and request["mutation_reissued"] is False
    )
    boot = report["phases"][2]
    assert boot["observations"][:3] == [
        {"transport_outcome": "unobserved", "reason": "observation-deadline"},
        {"identity": guest.original},
        {"transport_outcome": "unobserved", "exit_status": 255},
    ]
    assert boot["observations"][-1] == {"identity": report["after_identity"]}
    assert report["phases"][4]["refused"] == ["stale-boot", "foreign-enrollment"]
    assert (
        report["unrelated_host_canary_preserved"]
        and valid_stats(report["statistics"])
        and not list(tmp_path.iterdir())
    )
    assert all(p["status"] == "passed" and valid_stats(p["statistics"]) for p in report["phases"])
    observations = [p["observation"] for p in report["phases"] if "observation" in p]
    assert (
        len({o["probe"] for o in observations}) == 4
        and len({o["observer"]["pid"] for o in observations}) == 4
    )
    assert all(o["identity"] == observations[0]["identity"] for o in observations)


@pytest.mark.parametrize(
    "failure",
    [
        "request",
        "request-timeout",
        "error",
        "foreign",
        "malformed",
        "host",
        "guard-accepted",
        "stuck",
        "foreign-timeout",
        "ssh-unavailable",
        "guard-refused",
    ],
)
def test_reboot_failures_preserve_old_admission_original_observations_and_stats(
    controlled, tmp_path, monkeypatch, failure
):
    guest, _ = controlled
    if failure in (
        "error",
        "foreign",
        "malformed",
        "stuck",
        "foreign-timeout",
        "ssh-unavailable",
        "guard-refused",
    ):
        guest.sequence = [failure]
    else:
        guest.failure = failure
    if failure == "stuck":
        budget = reboot.current().seconds(2)
        remaining, budgets, sleeps = [budget], [], []
        deadline = SimpleNamespace(remaining=lambda: remaining[0])

        def after(nominal):
            budgets.append(nominal)
            return deadline

        def sleep(seconds):
            assert 0 < seconds <= remaining[0]
            sleeps.append(seconds)
            remaining[0] -= seconds

        monkeypatch.setattr(reboot, "Deadline", SimpleNamespace(after=after))
        monkeypatch.setattr(reboot.time, "sleep", sleep)
    report = {}
    with pytest.raises((native.EnrollmentError, guests.GuestBootError)) as caught:
        reboot.qualify_reboot(guest, tmp_path / "qmp", lambda name: nullcontext(), tmp_path, report)
    assert report["status"] == "failed" and report["reboot_continuity_qualified"] is False
    assert guest.observed == guest.original and len(guest.requests) == 1
    assert report["phases"][-1]["status"] == "failed" and valid_stats(report["statistics"])
    assert all(valid_stats(p["statistics"]) for p in report["phases"])
    assert report["unrelated_host_canary_preserved"] and not list(tmp_path.iterdir())
    if failure == "stuck":
        assert isinstance(caught.value, reboot.GuestRebootError)
        assert caught.value.reason == "new-boot-not-observed"
        assert budgets == [300] and sum(sleeps) == budget and remaining == [0]
        assert sleeps == [budget / 2, budget / 2]
        assert guest.observations == ["stuck", "stuck"]
        assert report["phases"][-1]["phase"] == "independent-boot"
        assert report["phases"][-1]["observations"] == [
            {"identity": guest.original},
            {"identity": guest.original},
        ]
    if failure in ("request", "request-timeout"):
        assert not guest.observations and report["phases"][-1]["phase"] == "request"
    elif failure in ("error", "foreign-timeout", "ssh-unavailable", "guard-refused"):
        assert guest.observations == [failure]


def test_reboot_query_timeouts_exhaust_original_shared_budget_without_replaying_mutation(
    controlled, tmp_path, monkeypatch
):
    guest, calls = controlled
    guest.sequence = ["timeout", "timeout"]
    budget = reboot.current().seconds(2)
    remaining, sleeps, budgets = [budget], [], []
    deadline = SimpleNamespace(remaining=lambda: remaining[0])

    def after(nominal):
        budgets.append(nominal)
        return deadline

    def sleep(seconds):
        sleeps.append(seconds)
        remaining[0] -= seconds

    monkeypatch.setattr(reboot, "Deadline", SimpleNamespace(after=after))
    monkeypatch.setattr(reboot.time, "sleep", sleep)
    report = {}
    with pytest.raises(reboot.GuestRebootError, match="new-boot-not-observed"):
        reboot.qualify_reboot(guest, tmp_path / "qmp", lambda name: nullcontext(), tmp_path, report)
    assert budgets == [300] and sum(sleeps) == budget and remaining[0] == 0
    assert guest.observations == ["timeout", "timeout"]
    assert guest.observed == guest.original and len(guest.requests) == 1 and len(calls) == 1
    assert report["status"] == "failed" and report["reboot_continuity_qualified"] is False
    assert "after_identity" not in report and report["phases"][-1]["status"] == "failed"
    assert report["phases"][-1]["observations"] == [
        {"transport_outcome": "unobserved", "reason": "observation-deadline"},
        {"transport_outcome": "unobserved", "reason": "observation-deadline"},
    ]
    assert report["unrelated_host_canary_preserved"] and not list(tmp_path.iterdir())
    assert valid_stats(report["statistics"])
    assert all(valid_stats(p["statistics"]) for p in report["phases"])


@pytest.mark.parametrize(
    "change",
    ["probe", "mode", "enrollment", "boot_id", "content", "inode", "image", "denied", "fsync"],
)
def test_reboot_rejects_inexact_prepared_or_fresh_canary_evidence(controlled, tmp_path, change):
    guest, _ = controlled

    def corrupt(value):
        if value["mode"] != "inspect":
            return
        if change in ("probe", "mode", "enrollment", "boot_id"):
            value[change] = str(uuid.uuid4())
        elif change == "content":
            value["identity"]["content"] += "foreign"
        elif change == "inode":
            value["identity"]["file"]["inode"] += 1
        elif change == "image":
            value["observer"]["executable"]["sha256"] = "0" * 64
        elif change == "denied":
            value["denied_canary_absent"] = 1
        else:
            value["canary_fsynced"] = True

    guest.change = corrupt
    report = {}
    with pytest.raises(reboot.GuestRebootError):
        reboot.qualify_reboot(guest, tmp_path / "qmp", lambda name: nullcontext(), tmp_path, report)
    assert report["status"] == "failed" and not report["reboot_continuity_qualified"]
    assert guest.observed == guest.original and report["unrelated_host_canary_preserved"]
    assert valid_stats(report["statistics"]) and report["phases"][-1]["status"] == "failed"
    failed = report["phases"][-1]
    assert json.loads(failed["original_reply"]) == failed["observation"]
    assert failed["request"]["mode"] == "inspect"


def test_reboot_missing_required_stats_cannot_qualify(controlled, tmp_path, monkeypatch):
    guest, _ = controlled
    monkeypatch.setattr(reboot, "RunStats", lambda: SimpleNamespace(finish=lambda: {}))
    report = {}
    with pytest.raises(ValueError, match="invalid required reboot statistics"):
        reboot.qualify_reboot(guest, tmp_path / "qmp", lambda name: nullcontext(), tmp_path, report)
    assert report["status"] == "failed" and report["reboot_continuity_qualified"] is False
    assert report["phases"][0]["status"] == "failed" and guest.observed == guest.original
    assert not guest.requests and report["statistics"] == {}


@pytest.fixture
def host_guest(tmp_path, monkeypatch):
    folder = tmp_path / "inputs"
    folder.mkdir(mode=0o700)
    content = b"controlled-base"
    monkeypatch.setattr(images, "IMAGE_BYTES", len(content))
    monkeypatch.setattr(images, "IMAGE_SHA256", hashlib.sha256(content).hexdigest())
    inputs = images.GuestInputs(str(uuid.uuid4()), folder, images.identity(folder, directory=True))
    for name in ("base.img", *images.DISK_BYTES):
        path = folder / name
        path.write_bytes(content)
        path.chmod(0o400 if name == "base.img" else 0o600)
        inputs.register(name)
    endpoint_dir = tmp_path / "control"
    endpoint_dir.mkdir(mode=0o700)
    endpoint = endpoint_dir / "qmp"
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    channel.bind(str(endpoint))
    endpoint.chmod(0o700)
    pid = os.getpid()
    state = {"verified": 0, "listener": True}

    def verify(deadline):
        assert deadline.remaining() > 0
        state["verified"] += 1

    def listener():
        if not state["listener"]:
            raise guests.GuestBootError("controlled-listener-mismatch")

    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    guest = SimpleNamespace(
        directory=private,
        directory_identity=images.identity(private, directory=True),
        process=SimpleNamespace(pid=pid),
        verify_process=verify,
        listener=listener,
        inputs=inputs,
        enrollment=inputs.enrollment,
        files={},
        verify_tools=lambda: None,
        report={
            "controller_verified": {"instance_uuid": inputs.enrollment, "unix_peer_verified": True}
        },
        port=12345,
    )
    monkeypatch.setattr(reboot.os, "getpgid", lambda process: pid)
    try:
        yield guest, endpoint, state
    finally:
        channel.close()


def test_host_custody_pins_existing_owned_inputs_controller_and_private_endpoint(host_guest):
    guest, endpoint, state = host_guest
    first = reboot.host_custody(guest, endpoint, Deadline.after(10))
    second = reboot.host_custody(guest, endpoint, Deadline.after(10))
    assert first == second and state["verified"] == 2
    assert first["pid"] == first["pgid"] == guest.process.pid
    assert first["base_image_verified"] and first["private_inputs_verified"]
    assert set(first["disks"]) == {"base.img", *images.DISK_BYTES}


@pytest.mark.parametrize(
    "change", ["base", "disk", "directory", "socket", "listener", "group", "identity"]
)
def test_host_custody_refuses_replaced_unprotected_or_foreign_resources(
    host_guest, monkeypatch, change
):
    guest, endpoint, state = host_guest
    if change == "base":
        path = guest.inputs.directory / "base.img"
        path.chmod(0o600)
        path.write_bytes(b"foreign")
        path.chmod(0o400)
    elif change == "disk":
        replacement = guest.inputs.directory / "foreign"
        replacement.write_bytes(b"foreign")
        replacement.chmod(0o600)
        replacement.replace(guest.inputs.directory / "data.qcow2")
    elif change == "directory":
        endpoint.parent.chmod(0o755)
    elif change == "socket":
        endpoint.chmod(0o777)
    elif change == "listener":
        state["listener"] = False
    elif change == "group":
        monkeypatch.setattr(reboot.os, "getpgid", lambda process: process + 1)
    else:
        guest.report["controller_verified"]["instance_uuid"] = str(uuid.uuid4())
    with pytest.raises((reboot.GuestRebootError, guests.GuestBootError, images.GuestInputError)):
        reboot.host_custody(guest, endpoint, Deadline.after(10))


def test_new_boot_profile_observation_does_not_rebind_existing_mutation_admission():
    guest = ControlledGuest()
    after = guest.info(guest.after_boot)
    guest.validate_profile(after)
    with pytest.raises(guests.GuestBootError, match="guest-boot-or-identity-changed"):
        guest.validate(after)
    assert guest.observed == guest.original


@pytest.mark.parametrize("change", ["content", "shared-disks", "owner", "image"])
def test_invalid_preparation_keeps_original_reply_and_never_requests_reboot(
    controlled, tmp_path, change
):
    guest, _ = controlled

    def corrupt(value):
        if value["mode"] != "prepare":
            return
        if change == "content":
            value["identity"]["content"] += "foreign"
        elif change == "shared-disks":
            disks = value["identity"]["disks"]
            for key in ("device", "major", "minor"):
                disks["control"][key] = disks["root"][key]
        elif change == "owner":
            value["identity"]["file"]["uid"] = 1000
        else:
            value["observer"]["executable"]["path"] = "/foreign/python"

    guest.change = corrupt
    report = {}
    with pytest.raises(reboot.GuestRebootError):
        reboot.qualify_reboot(guest, tmp_path / "qmp", lambda name: nullcontext(), tmp_path, report)
    assert not guest.requests and guest.observed == guest.original
    assert report["status"] == "failed" and report["reboot_continuity_qualified"] is False
    failed = report["phases"][0]
    assert (
        failed["status"] == "failed"
        and json.loads(failed["original_reply"]) == failed["observation"]
    )
    assert valid_stats(failed["statistics"]) and valid_stats(report["statistics"])


@pytest.mark.parametrize("lost", [False, True], ids=["acknowledged", "reply-unobserved"])
def test_controlled_reboot_interruption_preserves_request_without_admitting_or_replaying(
    controlled, tmp_path, lost
):
    guest, custody_calls = controlled
    guest.request_loss = lost
    report = {}
    with pytest.raises(reboot.RebootObservationInterrupted) as failure:
        reboot.qualify_reboot(
            guest,
            tmp_path / "qmp",
            lambda name: nullcontext(),
            tmp_path,
            report,
            interrupt_observation=True,
        )
    assert failure.value.reason == "injected-before-restart-observation"
    assert report["status"] == "failed" and report["fault_injection_verified"] is True
    assert report["continuity_outcome"] == "unobserved" and "after_identity" not in report
    assert (
        report["reboot_continuity_qualified"] is report["failed_restart_cleanup_qualified"] is False
    )
    assert report["snapshot_restore_qualified"] is report["resources_destroyed_with_guest"] is False
    assert guest.observed == guest.original == report["before_identity"]
    assert guest.report["identity"] == guest.original and guest.observations == []
    assert guest.requests == [reboot.REBOOT] and len(custody_calls) == 1
    prepare, request, interrupted = report["phases"]
    assert [p["status"] for p in report["phases"]] == ["passed", "passed", "failed"]
    assert prepare["observation"]["canary_fsynced"] is True
    assert prepare["observation"]["identity"]["content"].startswith("reboot:" + guest.enrollment)
    assert request["command"] == reboot.REBOOT and request["mutation_reissued"] is False
    assert request["outcome"] == ("unobserved" if lost else "request-acknowledged")
    assert request["observed_exit_status"] == (255 if lost else 0)
    assert ("original_reply" in request) is (not lost)
    assert interrupted["phase"] == "independent-boot" and "identity" not in interrupted
    assert interrupted["outcome"] == "unobserved"
    assert interrupted["interruption_kind"] == "controlled-controller-observer-exception"
    assert report["unrelated_host_canary_preserved"] and not list(tmp_path.iterdir())
    assert all(valid_stats(p["statistics"]) for p in report["phases"])
    assert valid_stats(report["statistics"])


@pytest.mark.parametrize("failure", ["request", "request-timeout", "foreign-custody"])
def test_unexpected_reboot_error_cannot_satisfy_the_selected_observer_interruption(
    controlled, tmp_path, monkeypatch, failure
):
    guest, _ = controlled
    guest.failure = failure
    if failure == "foreign-custody":

        def refuse(*args):
            raise reboot.GuestRebootError("foreign-custody")

        monkeypatch.setattr(reboot, "host_custody", refuse)
    report = {}
    with pytest.raises(RuntimeError) as raised:
        reboot.qualify_reboot(
            guest,
            tmp_path / "qmp",
            lambda name: nullcontext(),
            tmp_path,
            report,
            interrupt_observation=True,
        )
    assert not isinstance(raised.value, reboot.RebootObservationInterrupted)
    assert report["status"] == "failed" and report["fault_injection_verified"] is False
    assert not report["reboot_continuity_qualified"] and "after_identity" not in report
    assert guest.observed == guest.original and guest.observations == []
    assert len(guest.requests) == int(failure != "foreign-custody")
    assert valid_stats(report["statistics"]) and not list(tmp_path.iterdir())


def cleanup_custody(tmp_path):
    """Actual unprivileged files/short child; all guest observations are substituted."""
    folders = {name: tmp_path / name for name in ("inputs", "private", "control")}
    for directory in folders.values():
        directory.mkdir(mode=0o700)
    child = subprocess.Popen([sys.executable, "-I", "-S", "-c", "pass"], start_new_session=True)
    child.wait(timeout=watchdog(5))
    files = {}
    for name in ("base.img", *images.DISK_BYTES):
        p = folders["inputs"] / name
        p.write_bytes(b"controlled fixture disk")
        p.chmod(0o400 if name == "base.img" else 0o600)
        files[name] = {"path": str(p), "identity": images.identity(p)}
    private = folders["private"] / "admin"
    private.write_bytes(b"controlled fixture input")
    private.chmod(0o600)
    endpoint = folders["control"] / "qmp"
    endpoint.write_bytes(b"controlled endpoint")
    return {
        "pid": child.pid,
        "pgid": child.pid,
        "control_socket": {"path": str(endpoint)},
        "input_directory": {
            "path": str(folders["inputs"]),
            "identity": images.identity(folders["inputs"], directory=True),
        },
        "private_directory": {
            "path": str(folders["private"]),
            "identity": images.identity(folders["private"], directory=True),
        },
        "private_files": {"admin": {"path": str(private), "identity": images.identity(private)}},
        "disks": files,
    }


def remove_controlled_resources(custody):
    for entries in (custody["disks"], custody["private_files"]):
        for value in entries.values():
            Path(value["path"]).unlink()
    endpoint = Path(custody["control_socket"]["path"])
    endpoint.unlink()
    for directory in (custody["input_directory"], custody["private_directory"]):
        Path(directory["path"]).rmdir()
    endpoint.parent.rmdir()


@pytest.mark.parametrize(
    "change",
    [
        "none",
        "disk",
        "private",
        "directory",
        "socket",
        "symlink",
        "foreign-path",
        "missing-disk",
        "no-private",
        "group",
    ],
)
def test_reboot_cleanup_independently_requires_exact_owned_path_and_process_absence(
    tmp_path, change
):
    custody = cleanup_custody(tmp_path)
    remove_controlled_resources(custody)
    unrelated = tmp_path / "unrelated"
    unrelated.write_bytes(b"preserve me")
    if change in ("disk", "private", "directory", "socket", "symlink"):
        path = (
            Path(custody["disks"]["root.qcow2"]["path"])
            if change == "disk"
            else Path(custody["private_files"]["admin"]["path"])
            if change == "private"
            else Path(custody["control_socket"]["path"])
            if change == "socket"
            else Path(custody["private_directory"]["path"])
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        if change == "directory":
            path.mkdir()
        elif change == "symlink":
            path.symlink_to(tmp_path / "absent-unrelated-target")
        else:
            path.write_bytes(b"still present")
    elif change == "foreign-path":
        custody["disks"]["root.qcow2"]["path"] = str(unrelated)
    elif change == "missing-disk":
        del custody["disks"]["data.qcow2"]
    elif change == "no-private":
        custody["private_files"] = {}
    elif change == "group":
        custody["pgid"] += 1
    if change == "none":
        value = reboot.observe_removed_resources(custody)
        assert (
            value["status"] == "passed"
            and value["process_absent"] is value["process_group_absent"] is True
        )
        assert len(value["paths"]) == 9 and all(x["absent"] is True for x in value["paths"])
        assert (
            valid_stats(value["statistics"])
            and value["statistics"]["scope"] == "process-excludes-children"
        )
    else:
        with pytest.raises(reboot.GuestRebootError):
            reboot.observe_removed_resources(custody)
    assert unrelated.read_bytes() == b"preserve me"


@pytest.mark.parametrize("identity", ["process", "group"])
def test_live_foreign_process_or_group_is_observed_and_never_signalled(
    tmp_path, monkeypatch, identity
):
    custody = cleanup_custody(tmp_path)
    remove_controlled_resources(custody)
    child = subprocess.Popen(
        [sys.executable, "-I", "-S", "-c", "import time; time.sleep(30)"], start_new_session=True
    )
    try:
        custody.update(pid=child.pid, pgid=child.pid)
        if identity == "group":

            def absent_leader(pid, signal):
                assert pid == child.pid and signal == 0
                raise ProcessLookupError()

            monkeypatch.setattr(reboot, "os", SimpleNamespace(kill=absent_leader, killpg=os.killpg))
        with pytest.raises(reboot.GuestRebootError):
            reboot.observe_removed_resources(custody)
        assert child.poll() is None
    finally:
        child.terminate()
        child.wait(timeout=watchdog(5))


@pytest.mark.parametrize(
    "mode",
    [
        "expected",
        "lost",
        "wrong-error",
        "no-error",
        "not-injected",
        "admission",
        "request",
        "unclean",
        "unrelated",
        "endpoint",
    ],
)
def test_interrupted_reboot_case_requires_exact_injection_original_request_and_complete_cleanup(
    tmp_path, monkeypatch, mode
):
    results, events = [], []
    holder = {}

    @contextmanager
    def inputs(enrollment, temporary, command, progress, report):
        assert temporary == tmp_path and uuid.UUID(enrollment).version == 4
        custody = cleanup_custody(tmp_path)
        holder["custody"] = custody
        report.update(enrollment=enrollment)
        events.append("inputs")
        try:
            yield SimpleNamespace(enrollment=enrollment)
        finally:
            remove_controlled_resources(custody)
            report.update(temporary_resources_removed=True, base_preserved=True)
            events.append("inputs-removed")

    def boot(owner, tools, digest, temporary, report, *, reboot_failure):
        assert reboot_failure is True and temporary == tmp_path and digest == "c" * 64
        assert tools == {"controlled": True}
        before = {"enrollment": owner.enrollment, "boot_id": str(uuid.uuid4())}
        stats = RunStats().finish()
        report.update(
            status="failed",
            boot_verified=True,
            identity=before,
            temporary_resources_removed=True,
            process_reaped=mode != "unclean",
            endpoint={"address": "127.0.0.1", "port": 2222, "owned_listener": True},
        )
        report["reboot"] = {
            "status": "failed",
            "before_identity": copy.deepcopy(before),
            "fault_injection_verified": mode != "not-injected",
            "continuity_outcome": "unobserved",
            "reboot_continuity_qualified": False,
            "failed_restart_cleanup_qualified": False,
            "snapshot_restore_qualified": False,
            "unrelated_host_canary_preserved": True,
            "phases": [
                {
                    "phase": "prepare",
                    "status": "passed",
                    "host_custody": holder["custody"],
                    "statistics": stats,
                },
                {
                    "phase": "request",
                    "status": "passed",
                    "command": reboot.REBOOT,
                    "mutation_reissued": mode == "request",
                    "outcome": "request-acknowledged",
                    "observed_exit_status": 0,
                    "original_reply": "",
                    "statistics": stats,
                },
                {
                    "phase": "independent-boot",
                    "status": "failed",
                    "outcome": "unobserved",
                    "interruption_kind": "controlled-controller-observer-exception",
                    "statistics": stats,
                },
            ],
        }
        if mode == "admission":
            report["identity"] = dict(before, boot_id=str(uuid.uuid4()))
        if mode == "unrelated":
            next(tmp_path.glob("fishhat-canary-*/unrelated")).write_bytes(b"changed")
        if mode == "lost":
            request = report["reboot"]["phases"][1]
            request.update(observed_exit_status=255, outcome="unobserved")
            del request["original_reply"]
        events.append("request-and-interruption")
        if mode == "no-error":
            return
        if mode == "wrong-error":
            raise reboot.GuestRebootError("injected-before-restart-observation")
        raise reboot.RebootObservationInterrupted()

    def observe(endpoint):
        assert events == ["inputs", "request-and-interruption", "inputs-removed"]
        assert endpoint["owned_listener"] is True
        events.append("endpoint-observed")
        if mode == "endpoint":
            raise native.GuestStorageError("cleanup-endpoint-still-available")

    monkeypatch.setattr(native, "guest_inputs", inputs)
    monkeypatch.setattr(native, "boot_guest", boot)
    monkeypatch.setattr(native, "endpoint_closed", observe)
    if mode in ("expected", "lost"):
        native.guest_reboot_faults({"controlled": True}, "c" * 64, tmp_path, results)
    else:
        with pytest.raises(RuntimeError):
            native.guest_reboot_faults({"controlled": True}, "c" * 64, tmp_path, results)
    case = results[0]
    assert case["status"] == "failed" and case["scenario"] == "before-restart-observation"
    assert (
        case["expected_failure_verified"]
        is case["failed_restart_cleanup_qualified"]
        is (mode in ("expected", "lost"))
    )
    assert case["guest"]["reboot"]["reboot_continuity_qualified"] is False
    assert (
        valid_stats(case["statistics"])
        and case["statistics"]["scope"] == "process-excludes-children"
    )
    assert not list(tmp_path.iterdir())
    assert ("endpoint-observed" in events) is (mode in ("expected", "lost", "endpoint"))


def test_conflicting_guest_faults_refuse_before_creating_or_starting_resources(
    tmp_path, monkeypatch
):
    def unavailable(*args):
        pytest.fail("conflicting faults must refuse before guest setup")

    monkeypatch.setattr(native, "guest_session", unavailable)
    report = {}
    with pytest.raises(reboot.GuestRebootError, match="conflicting-guest-faults"):
        native.boot_guest(
            SimpleNamespace(),
            {},
            "c" * 64,
            tmp_path,
            report,
            storage_failure=True,
            reboot_failure=True,
        )
    assert report == {} and not list(tmp_path.iterdir())


def test_guarded_canary_advance_keeps_exact_prior_and_same_file_custody():
    h = Facilities()
    prepared = h.prepare()
    prior = copy.deepcopy(prepared["identity"])
    before_metadata = copy.deepcopy(h.meta)
    desired = str(uuid.uuid4())
    assert desired != h.c["nonce"]
    request = {
        **{k: v for k, v in h.c.items() if k != "identity"},
        "mode": "advance",
        "nonce": desired,
        "prior_nonce": h.c["nonce"],
        "prior_identity": copy.deepcopy(prior),
        "probe": str(uuid.uuid4()),
        "seconds": 60,
    }
    original_request = copy.deepcopy(request)
    assert h.files[h.root + "/canary"] == prior["content"].encode()
    h.events.clear()
    advanced = h.execute(request)
    expected = ("reboot:" + h.enrollment + "\n" + desired + "\n").encode()
    assert advanced["previous_identity"] == prior
    assert advanced["identity"]["content"].encode() == h.files[h.root + "/canary"] == expected
    assert advanced["identity"]["sha256"] == hashlib.sha256(expected).hexdigest()
    assert advanced["identity"]["file"] == prior["file"]
    assert advanced["canary_fsynced"] is True and advanced["probe"] == request["probe"]
    assert advanced["observer"]["executable"] == prepared["observer"]["executable"]
    assert h.meta == before_metadata and not h.fds
    assert h.events == ["write:" + h.root + "/canary", "fsync:" + h.root + "/canary"]
    assert request == original_request and prepared["identity"] == prior
    h.c.update(nonce=desired, identity=copy.deepcopy(advanced["identity"]))
    h.events.clear()
    inspected = h.invoke("inspect")
    assert inspected["identity"] == advanced["identity"] and inspected["canary_fsynced"] is False
    assert inspected["probe"] != advanced["probe"] and not h.events and not h.fds


def advance_request(h):
    return {
        **{k: copy.deepcopy(v) for k, v in h.c.items() if k != "identity"},
        "mode": "advance",
        "nonce": str(uuid.uuid4()),
        "prior_nonce": h.c["nonce"],
        "prior_identity": copy.deepcopy(h.c["identity"]),
        "probe": str(uuid.uuid4()),
        "seconds": 60,
    }


@pytest.mark.parametrize(
    "change",
    [
        "same-nonce",
        "invalid-prior-nonce",
        "missing-prior",
        "prior-content",
        "prior-hash",
        "prior-inode",
        "prior-boolean",
        "prior-directory",
        "prior-disk",
        "current-bytes",
        "current-inode",
        "current-owner",
        "current-links",
        "current-mode",
        "directory",
        "filesystem",
        "disk",
        "denied",
        "interpreter",
        "enrollment",
        "boot",
        "symlink",
        "excessive",
        "truncated",
    ],
)
def test_guarded_canary_advance_refuses_inexact_prior_before_writes(change):
    h = Facilities()
    h.prepare()
    request = advance_request(h)
    path = h.root + "/canary"
    if change == "same-nonce":
        request["nonce"] = request["prior_nonce"]
    elif change == "invalid-prior-nonce":
        request["prior_nonce"] = "not-a-nonce"
    elif change == "missing-prior":
        request.pop("prior_identity")
    elif change == "prior-content":
        request["prior_identity"]["content"] = "foreign"
    elif change == "prior-hash":
        request["prior_identity"]["sha256"] = "0" * 64
    elif change == "prior-inode":
        request["prior_identity"]["file"]["inode"] += 1
    elif change == "prior-boolean":
        request["prior_identity"]["file"]["uid"] = False
    elif change == "prior-directory":
        request["prior_identity"]["directory"]["inode"] += 1
    elif change == "prior-disk":
        request["prior_identity"]["disks"]["root"]["device"] += 1
    elif change == "current-bytes":
        h.files[path] = b"x" * len(h.files[path])
    elif change in ("current-inode", "current-owner", "current-links", "current-mode", "symlink"):
        field, value = {
            "current-inode": ("st_ino", h.meta[path].st_ino + 1),
            "current-owner": ("st_uid", 1000),
            "current-links": ("st_nlink", 2),
            "current-mode": ("st_mode", stat.S_IFREG | 0o644),
            "symlink": ("st_mode", stat.S_IFLNK | 0o777),
        }[change]
        setattr(h.meta[path], field, value)
    elif change == "directory":
        h.meta[h.root].st_ino += 1
    elif change == "filesystem":
        h.mount["uuid"] = h.partition["uuid"] = str(uuid.uuid4())
    elif change == "disk":
        h.disk_rows["/dev/vdc"]["size"] += 1
    elif change == "denied":
        h.meta[h.root + "/denied"] = h.metadata(stat.S_IFREG | 0o600, os.makedev(8, 1), 999)
    elif change == "interpreter":
        request["image"]["sha256"] = "0" * 64
    elif change == "enrollment":
        request["enrollment"] = str(uuid.uuid4())
    elif change == "boot":
        request["boot_id"] = str(uuid.uuid4())
    else:
        h.files[path] = h.files[path] + b"x" if change == "excessive" else h.files[path][:-1]
        h.meta[path].st_size = len(h.files[path])
    original = copy.deepcopy((h.meta, h.files))
    h.events.clear()
    with pytest.raises((ValueError, OSError, KeyError)):
        h.execute(request)
    assert (h.meta, h.files) == original and not h.events and not h.fds


def canary_io(os_owner=os):
    tree = ast.parse(reboot.PROGRAM)
    selected = [
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name in {"require", "canary_contents"}
    ]
    assert {n.name for n in selected} == {"require", "canary_contents"}
    namespace = {"os": os_owner}
    exec(
        compile(ast.Module(body=selected, type_ignores=[]), "<actual-canary-io>", "exec"), namespace
    )
    return namespace["canary_contents"]


@pytest.mark.parametrize("mode", ["prepare", "inspect", "advance", "partial-write"])
def test_actual_canary_io_uses_unprivileged_fd_with_exact_bytes_and_custody(tmp_path, mode):
    path = tmp_path / "canary"
    expected = None if mode == "prepare" else b"old"
    replacement = None if mode == "inspect" else b"new"
    path.write_bytes(b"" if expected is None else expected)
    path.chmod(0o600)
    before = path.stat()
    writes = []

    def write(fd, data):
        part = data[:1] if mode == "partial-write" else data
        writes.append(part)
        return os.write(fd, part)

    owner = SimpleNamespace(
        lseek=os.lseek, read=os.read, write=write, fsync=os.fsync, SEEK_SET=os.SEEK_SET
    )
    with path.open("r+b", buffering=0) as file:
        actual = canary_io(owner)(file.fileno(), expected, replacement)
    assert actual == path.read_bytes() == (expected if replacement is None else replacement)
    after = path.stat()
    assert (before.st_dev, before.st_ino, before.st_mode) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
    )
    assert b"".join(writes) == (replacement or b"")


@pytest.mark.parametrize(
    "contents,expected,replacement",
    [
        (b"old", b"bad", b"new"),
        (b"ol", b"old", b"new"),
        (b"oldx", b"old", b"new"),
        (b"old", b"old", b"old"),
        (b"old", b"old", b"long"),
        (b"old", None, b"new"),
    ],
    ids=["wrong-prior", "short", "excessive", "identical", "extent", "occupied-prepare"],
)
def test_actual_canary_io_refuses_wrong_prior_without_kernel_write(
    tmp_path, contents, expected, replacement
):
    path = tmp_path / "canary"
    path.write_bytes(contents)
    before = path.stat()
    events = []
    owner = SimpleNamespace(
        lseek=os.lseek,
        read=os.read,
        write=lambda *a: events.append("write"),
        fsync=lambda *a: events.append("fsync"),
        SEEK_SET=os.SEEK_SET,
    )
    with path.open("r+b", buffering=0) as file:
        with pytest.raises(ValueError):
            canary_io(owner)(file.fileno(), expected, replacement)
    assert not events and path.read_bytes() == contents
    after = path.stat()
    fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_uid",
        "st_gid",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    assert tuple(getattr(before, name) for name in fields) == tuple(
        getattr(after, name) for name in fields
    )


@pytest.mark.parametrize("failure", ["zero-write", "write-error", "fsync-error", "readback"])
def test_actual_canary_io_failure_cannot_report_success(tmp_path, failure):
    path = tmp_path / "canary"
    path.write_bytes(b"old")
    synced = False

    def write(fd, content):
        if failure == "zero-write":
            return 0
        if failure == "write-error":
            raise OSError(errno.ENOSPC, "controlled-private-error")
        return os.write(fd, content)

    def sync(fd):
        nonlocal synced
        if failure == "fsync-error":
            raise OSError(errno.EIO, "controlled-private-error")
        os.fsync(fd)
        synced = True

    def read(fd, size):
        return b"corrupt" if failure == "readback" and synced else os.read(fd, size)

    owner = SimpleNamespace(
        lseek=os.lseek, read=read, write=write, fsync=sync, SEEK_SET=os.SEEK_SET
    )
    with path.open("r+b", buffering=0) as file:
        with pytest.raises((ValueError, OSError)):
            canary_io(owner)(file.fileno(), b"old", b"new")


class CanaryAdvanceGuest:
    def __init__(self, facilities, failure=None):
        self.h, self.failure = facilities, failure
        self.enrollment = facilities.enrollment
        self.observed = {"boot_id": facilities.boot}
        self.requests = []

    def validate_profile(self, value):
        reboot.require(value == self.observed, "controlled-foreign-profile")

    def remote(self, observed, arguments):
        self.validate_profile(observed)
        assert arguments[:5] == ["/usr/bin/python3", "-I", "-S", "-c", reboot.PROGRAM]
        return arguments

    def ssh(self, arguments, *, deadline, nominal):
        assert deadline.remaining() > 0 and nominal == 75
        c = json.loads(arguments[-1])
        self.requests.append(c)
        result = self.h.execute(c)
        number = len(self.requests)
        if self.failure == "malformed" and number == 1:
            return "controlled-private-reply"
        if self.failure == "array" and number == 1:
            return "[]"
        if self.failure == "unobserved-write" and number == 2:
            raise native.EnrollmentError("guest-ssh", "command-exit-19")
        if number == 2:
            if self.failure == "fsync-lie":
                result["canary_fsynced"] = False
            elif self.failure == "prior-lie":
                result["previous_identity"] = {}
            elif self.failure == "prior-boolean":
                result["previous_identity"]["file"]["uid"] = False
            elif self.failure == "observer-string":
                result["observer"] = "controlled-private-reply"
            elif self.failure == "custody":
                result["identity"]["file"]["inode"] += 1
            elif self.failure == "probe":
                result["probe"] = str(uuid.uuid4())
            elif self.failure == "boot":
                result["boot_id"] = str(uuid.uuid4())
            elif self.failure == "enrollment":
                result["enrollment"] = str(uuid.uuid4())
        if self.failure == "readback" and number == 3:
            result["identity"]["sha256"] = "0" * 64
        return json.dumps(result)


def test_canary_advance_coordinator_preserves_original_witnesses_and_measured_readback():
    h = Facilities()
    prepared = h.prepare()
    before = copy.deepcopy(h.c)
    guest = CanaryAdvanceGuest(h)
    report = {}
    accepted = reboot.qualify_canary_advance(guest, guest.observed, h.c, Deadline.after(30), report)
    assert report["status"] == "passed" and valid_stats(report["statistics"])
    assert report["snapshot_restore_qualified"] is report["product_authority_qualified"] is False
    assert [x["phase"] for x in report["phases"]] == [
        "prior-observation",
        "persist-different-bytes",
        "independent-readback",
    ]
    assert all(p["status"] == "passed" and valid_stats(p["statistics"]) for p in report["phases"])
    assert [x["mode"] for x in guest.requests] == ["inspect", "advance", "inspect"]
    assert len({x["probe"] for x in guest.requests}) == 3
    assert report["phases"][1]["request"] == guest.requests[1]
    for phase in report["phases"]:
        assert json.loads(phase["original_reply"]) == phase["observation"]
        assert phase["request"]["probe"] == phase["observation"]["probe"]
    assert report["prior_canary"] == prepared["identity"] == before["identity"]
    assert report["written_canary"] == report["observed_canary"] == accepted["identity"]
    assert accepted["nonce"] != before["nonce"] and h.c == before
    assert h.files[h.root + "/canary"] == accepted["identity"]["content"].encode() and not h.fds


@pytest.mark.parametrize(
    "failure",
    [
        "malformed",
        "array",
        "unobserved-write",
        "fsync-lie",
        "prior-lie",
        "observer-string",
        "prior-boolean",
        "custody",
        "probe",
        "boot",
        "enrollment",
        "readback",
        "missing-identity",
        "missing-image",
    ],
)
def test_canary_advance_coordinator_refuses_missing_uncertain_or_forged_evidence(failure):
    h = Facilities()
    h.prepare()
    c = copy.deepcopy(h.c)
    if failure.startswith("missing-"):
        c.pop(failure.removeprefix("missing-"))
    original = copy.deepcopy(c)
    guest = CanaryAdvanceGuest(h, failure)
    report = {}
    with pytest.raises((reboot.GuestRebootError, native.EnrollmentError)) as caught:
        reboot.qualify_canary_advance(guest, guest.observed, c, Deadline.after(30), report)
    assert report["status"] == "failed" and valid_stats(report["statistics"]) and not h.fds
    assert all(valid_stats(p["statistics"]) for p in report["phases"])
    assert (
        c == original
        and report["snapshot_restore_qualified"] is report["product_authority_qualified"] is False
    )
    if failure.startswith("missing-"):
        assert not guest.requests
    if failure == "unobserved-write":
        assert caught.value.stage == "guest-ssh" and caught.value.reason == "command-exit-19"
        assert len(guest.requests) == 2


def test_canary_advance_invalid_measurement_cannot_qualify(monkeypatch):
    h = Facilities()
    h.prepare()
    guest = CanaryAdvanceGuest(h)
    report = {}
    monkeypatch.setattr(reboot, "valid_stats", lambda _: False)
    with pytest.raises(ValueError, match="invalid required"):
        reboot.qualify_canary_advance(guest, guest.observed, h.c, Deadline.after(30), report)
    assert report["status"] == "failed" and len(guest.requests) == 1 and not h.fds


@pytest.mark.parametrize("collision", ["nonce", "challenge"])
def test_canary_advance_cannot_adopt_repeated_nonce_or_challenges(monkeypatch, collision):
    h = Facilities()
    h.prepare()
    guest = CanaryAdvanceGuest(h)
    report = {}
    fixed = uuid.UUID(h.c["nonce"]) if collision == "nonce" else uuid.uuid4()
    reason = "canary-nonce-not-distinct" if collision == "nonce" else "canary-challenge-reused"
    with monkeypatch.context() as patch:
        patch.setattr(reboot.uuid, "uuid4", lambda: fixed)
        with pytest.raises(reboot.GuestRebootError, match=reason):
            reboot.qualify_canary_advance(guest, guest.observed, h.c, Deadline.after(30), report)
    assert report["status"] == "failed" and valid_stats(report["statistics"]) and not h.fds
    assert len(guest.requests) == (1 if collision == "nonce" else 3)
