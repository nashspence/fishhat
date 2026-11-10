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
import time
import uuid
from contextlib import nullcontext, redirect_stdout
from pathlib import PurePosixPath
from types import SimpleNamespace

import pytest

from scripts import native_linux_enrollment as native
from scripts import native_linux_guest as guests
from scripts import native_linux_images as images
from scripts import native_linux_reboot as reboot
from scripts.run_stats import valid_stats
from scripts.validation_timeouts import Deadline

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/native_linux_reboot.py",
        "scripts/native_linux_guest.py",
        "scripts/native_linux_enrollment.py",
    ],
    "scope": "controlled execution of persistent-root canary admission/readback/fsync and disk identity queries, delayed new-boot observations with bounded read-only timeout recovery, exact host custody, original request acknowledgement/loss, stale/foreign command refusal, admission ordering and required scoped statistics",
    "relationship": "no-product-claim",
    "reason": "Guest devices/filesystem/boot/SSH and controller observations are substituted. A real unprivileged private socket only challenges host-custody checks; no QEMU, native guest reboot, product continuity or writer authority is qualified.",
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
        self.files[path] = self.files[path][:offset] + bytes(content)
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
    monkeypatch.setattr(reboot.time, "sleep", lambda seconds: None)
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
        monkeypatch.setattr(
            reboot, "Deadline", SimpleNamespace(after=lambda nominal: Deadline.after(0.02))
        )
    report = {}
    with pytest.raises((native.EnrollmentError, guests.GuestBootError)):
        reboot.qualify_reboot(guest, tmp_path / "qmp", lambda name: nullcontext(), tmp_path, report)
    assert report["status"] == "failed" and report["reboot_continuity_qualified"] is False
    assert guest.observed == guest.original and len(guest.requests) == 1
    assert report["phases"][-1]["status"] == "failed" and valid_stats(report["statistics"])
    assert all(valid_stats(p["statistics"]) for p in report["phases"])
    assert report["unrelated_host_canary_preserved"] and not list(tmp_path.iterdir())
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

    guest = SimpleNamespace(
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
