"""Execute exhaustion tooling with substituted filesystems, kernel and SSH."""

from __future__ import annotations

import ast
import copy
import ctypes
import errno
import hashlib
import io
import json
import os
import stat
import struct
import subprocess
import time
import uuid
from contextlib import nullcontext, redirect_stdout
from pathlib import PurePosixPath
from types import SimpleNamespace

import pytest

from scripts import native_linux_enrollment as native
from scripts import native_linux_exhaustion as exhaustion
from scripts.run_stats import valid_stats
from scripts.validation_timeouts import Deadline, watchdog

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/native_linux_exhaustion.py",
        "scripts/native_linux_storage.py",
        "scripts/native_linux_enrollment.py",
    ],
    "scope": "controlled execution of fixed quota preparation, kernel-allocation worker and independent observer, foreign/stale/mounted admission refusal, exact selected-profile errno preservation, matching outside-project allocation and global space evidence, finite fail-safe allocation, exact release/reuse and idempotent known release, known allocation destruction and independently observed absence/retry after an unadmitted reply, canaries, teardown evidence and mandatory measurement scope",
    "relationship": "no-product-claim",
    "reason": "All guest filesystem, quota, kernel, process and SSH facilities are substituted. Passing tooling checks cannot qualify actual native operations or product owners; real enrolled main-only evidence remains required.",
    "claims": [],
}


def execute(program, namespace):
    tree = ast.parse(program)
    tree.body = [node for node in tree.body if not isinstance(node, ast.Import)]
    output = io.StringIO()
    with redirect_stdout(output):
        exec(compile(tree, "<controlled-exhaustion>", "exec"), namespace)
    return json.loads(output.getvalue())


class Harness:
    """In-memory facilities; never mount, set quotas, fill disks or invoke SSH."""

    def __init__(self):
        self.enrollment, self.boot, self.token = (str(uuid.uuid4()) for _ in range(3))
        self.root = "/run/fhs-" + uuid.UUID(self.enrollment).hex
        self.meta, self.files, self.fds, self.projects = {}, {}, {}, {}
        self.removed = {}
        self.mountinfo = ""
        self.events = []
        self.allocations = []
        self.uid = 0
        self.pid = 40
        self.code = errno.ENOSPC
        self.enforced = True
        self.allocation_overhead = 4096
        self.clock = 0
        self.next_fd = 100
        self.state = {"root": self.directory(self.root, 10, 1, 0, 0o711)}
        for i, role in enumerate(("control", "data"), 11):
            uid = 0 if role == "control" else 1000
            self.state[role] = {
                "directory": self.directory(self.root + "/" + role, i, 2, uid, 0o700),
                "device": {
                    "path": "/dev/vd" + ("b" if role == "control" else "c"),
                    "device": i,
                    "major": 1,
                    "minor": i,
                    "bytes": i * 1024**3,
                    "serial": "fh-" + role,
                },
                "uuid": str(uuid.uuid4()),
            }
        self.guest = SimpleNamespace(
            enrollment=self.enrollment,
            accounts=("admin", "peer"),
            observed={"boot_id": self.boot, "accounts": {"admin": {"uid": 1000, "gid": 1000}}},
            report={
                "storage": {
                    "status": "passed",
                    "permissions_verified": True,
                    "filesystems": self.state,
                }
            },
        )
        self.c = exhaustion.configuration(self.guest)
        self.c["task"] = self.token
        self.c["target"] = self.root + "/data/exhaustion-" + uuid.UUID(self.token).hex
        self.c["project_id"] = uuid.UUID(self.token).int % 2147483646 + 1
        self.c.update(seconds=60)
        self.storage = copy.deepcopy(self.c["storage"])
        self.q = {
            "present": False,
            "project_id": self.c["project_id"],
            "hard_bytes": 0,
            "soft_bytes": 0,
            "used_bytes": 0,
            "inodes": 0,
            "inode_hard": 0,
            "inode_soft": 0,
        }
        self.mounted = False
        self.bad_attributes = False
        self.bad_quota = False
        self.worker_change = None

    def directory(self, path, device, inode, uid, mode):
        self.meta[path] = SimpleNamespace(
            st_dev=device,
            st_ino=inode,
            st_uid=uid,
            st_gid=uid,
            st_mode=stat.S_IFDIR | mode,
            st_nlink=1,
            st_size=0,
            st_blocks=0,
        )
        return {
            k: getattr(
                self.meta[path], "st_" + ("dev" if k == "device" else "ino" if k == "inode" else k)
            )
            for k in ("device", "inode", "uid", "gid")
        } | {"mode": mode}

    def path(self, value):
        h = self

        class Path(PurePosixPath):
            def lstat(self):
                if str(self) not in h.meta:
                    raise FileNotFoundError()
                return copy.copy(h.meta[str(self)])

            def exists(self):
                return str(self) in h.meta

            def is_symlink(self):
                return False

            def is_mount(self):
                return h.mounted

            def mkdir(self, *, mode):
                assert not self.exists()
                h.events.append("mkdir")
                h.directory(str(self), 12, 500, 0, mode)
                h.projects[str(self)] = 0

            def read_text(self):
                if str(self).endswith("fixture-enrollment"):
                    return h.enrollment
                if str(self).endswith("boot_id"):
                    return h.boot
                if str(self) == "/proc/self/mountinfo":
                    return h.mountinfo
                if str(self) == "/proc/self/status":
                    return "CapEff:\t0000000000000000\n"
                raise AssertionError(str(self))

            def read_bytes(self):
                assert str(self) == "/proc/self/exe"
                return b"fixed-guest-interpreter"

            def unlink(self):
                h.unlink(self)

        return Path(str(value))

    def open(self, path, flags, mode=0o777, *, dir_fd=None):
        path = str(PurePosixPath(self.fds[dir_fd]) / path) if dir_fd is not None else str(path)
        if flags & os.O_CREAT:
            assert path not in self.meta
            dev = self.state["control" if "/control/" in path else "data"]["directory"]["device"]
            self.meta[path] = SimpleNamespace(
                st_dev=dev,
                st_ino=600 + len(self.meta),
                st_uid=self.uid,
                st_gid=self.uid,
                st_mode=stat.S_IFREG | mode,
                st_nlink=1,
                st_size=0,
                st_blocks=0,
            )
            self.projects[path] = self.projects.get(str(PurePosixPath(path).parent), 0)
            self.events.append("create:" + PurePosixPath(path).name)
            if self.projects[path]:
                self.q["inodes"] += 1
        assert path in self.meta
        self.next_fd += 1
        self.fds[self.next_fd] = path
        return self.next_fd

    def close(self, fd):
        path = self.fds.pop(fd)
        if path in self.removed and path not in self.fds.values():
            self.removed.pop(path)
            if self.projects.get(path) == self.c["project_id"]:
                self.q["inodes"] -= 1

    def fstat(self, fd):
        path = self.fds[fd]
        return copy.copy(self.meta[path] if path in self.meta else self.removed[path])

    def listdir(self, fd):
        path = self.fds[fd]
        return [PurePosixPath(p).name for p in self.meta if str(PurePosixPath(p).parent) == path]

    def unlink(self, path, *, dir_fd=None):
        path = str(PurePosixPath(self.fds[dir_fd]) / path) if dir_fd is not None else str(path)
        value = self.meta.pop(path)
        value.st_nlink = 0
        self.events.append("unlink:" + PurePosixPath(path).name)
        self.files.pop(path, None)
        if path in self.fds.values():
            self.removed[path] = value
        elif self.projects.get(path) == self.c["project_id"]:
            self.q["inodes"] -= 1

    def rmdir(self, path, *, dir_fd):
        path = str(PurePosixPath(self.fds[dir_fd]) / path)
        assert not any(str(PurePosixPath(p).parent) == path for p in self.meta)
        value = self.meta.pop(path)
        value.st_nlink = 0
        self.removed[path] = value
        self.events.append("rmdir")

    def chown(self, path, uid, gid):
        self.meta[str(path)].st_uid = uid
        self.meta[str(path)].st_gid = gid
        self.events.append("chown")

    def write(self, fd, data):
        v = self.meta[self.fds[fd]]
        v.st_size += len(data)
        v.st_blocks = (v.st_size + 511) // 512
        self.events.append("write:" + PurePosixPath(self.fds[fd]).name)
        return len(data)

    def allocate(self, fd, offset, length):
        self.events.append("fallocate")
        self.allocations.append((self.fds[fd], offset, length))
        project = self.projects[self.fds[fd]]
        overhead = self.allocation_overhead if project else 0
        if project and self.enforced and offset + length + overhead > self.q["hard_bytes"]:
            raise OSError(self.code, "controlled kernel error")
        v = self.meta[self.fds[fd]]
        v.st_size = offset + length
        v.st_blocks = (v.st_size + overhead) // 512
        if project:
            self.q["used_bytes"] = v.st_blocks * 512

    def truncate(self, fd, size):
        assert size == 0 and self.projects[self.fds[fd]] == self.c["project_id"]
        self.events.append("truncate")
        value = self.meta[self.fds[fd]]
        value.st_size = value.st_blocks = 0
        self.q["used_bytes"] = 0

    def ioctl(self, fd, operation, buffer):
        assert operation in (0x801C581F, 0x401C5820) and len(buffer) == 28
        path = self.fds[fd]
        if operation == 0x401C5820:
            values = struct.unpack("=5I8s", buffer)
            assert values[3] == 0 and not values[0] & 0x200
            assert self.projects[path] == self.c["project_id"]
            self.projects[path] = 0
            self.q["inodes"] -= 1
            self.events.append("project-reset")
            return buffer
        return struct.pack(
            "=5I8s",
            0x200 if stat.S_ISDIR(self.meta[path].st_mode) and self.projects.get(path, 0) else 0,
            0,
            0,
            self.projects.get(path, 0) + (1 if self.bad_attributes else 0),
            0,
            b"\0" * 8,
        )

    def quotactl(self, operation, device, project, buffer):
        assert (
            operation == (0x5803 << 8) | 2
            and device == b"/dev/vdc"
            and project == self.c["project_id"]
        )
        if not self.q["present"]:
            return -1
        q = self.q
        payload = struct.pack(
            "=bbHI6Q",
            1,
            2,
            0,
            project,
            q["hard_bytes"] // 512,
            q["soft_bytes"] // 512,
            q["inode_hard"],
            q["inode_soft"],
            q["used_bytes"] // 512,
            q["inodes"],
        )
        if self.bad_quota:
            payload = bytes([2]) + payload[1:]
        ctypes.memmove(buffer, payload, len(payload))
        return 0

    def run(self, args, **kwargs):
        assert kwargs["check"] is True and kwargs["timeout"] > 0
        if args[0] == "/usr/sbin/xfs_quota":
            self.events.append("quota-mutate")
            assert args[1:6] == ["-x", "-D", "/dev/null", "-P", "/dev/null"]
            command = args[7]
            assert args[-1] == self.root + "/data"
            if command.startswith("project -s -d 0 -p "):
                assert command.endswith(str(self.c["project_id"]))
                self.projects[self.c["target"]] = self.c["project_id"]
                self.q.update(present=True, inodes=1)
            else:
                assert command in (
                    f"limit -p bhard={exhaustion.CAPACITY} {self.c['project_id']}",
                    f"limit -p bhard=0 {self.c['project_id']}",
                )
                self.q["hard_bytes"] = 0 if "bhard=0 " in command else exhaustion.CAPACITY
            return SimpleNamespace(stdout="")
        cfg = json.loads(args[-1])
        if args[-2] == exhaustion.STORAGE_PROGRAM:
            self.events.append("storage-read")
            if any(
                cfg[k] != self.storage[k]
                for k in ("enrollment", "boot_id", "state", "devices", "uuids")
            ):
                raise subprocess.CalledProcessError(1, args)
            return SimpleNamespace(stdout=json.dumps({**self.state, "canaries_verified": True}))
        assert args[-2] == exhaustion.WORKER
        assert (
            kwargs["user"] == kwargs["group"] == 1000
            and kwargs["extra_groups"] == []
            and kwargs["start_new_session"]
            and kwargs["umask"] == 0o077
        )
        self.uid = 1000
        self.pid += 1
        try:
            result = execute(exhaustion.WORKER, self.namespace(cfg))
        finally:
            self.uid = 0
        if self.worker_change:
            self.worker_change(result)
        return SimpleNamespace(stdout=json.dumps(result))

    def namespace(self, c):
        operating_system = SimpleNamespace(**vars(os))
        operating_system.geteuid = operating_system.getuid = lambda: self.uid
        operating_system.getgid = operating_system.getegid = lambda: self.uid
        operating_system.getgroups = lambda: []
        operating_system.getpid = lambda: self.pid
        operating_system.open = self.open
        operating_system.close = self.close
        operating_system.listdir = self.listdir
        operating_system.unlink = self.unlink
        operating_system.rmdir = self.rmdir
        operating_system.chown = self.chown
        operating_system.fstat = self.fstat
        operating_system.posix_fallocate = self.allocate
        operating_system.ftruncate = self.truncate
        operating_system.pwrite = lambda fd, data, offset: len(data)
        operating_system.write = self.write
        operating_system.fsync = lambda fd: self.events.append("fsync")
        operating_system.statvfs = lambda path: SimpleNamespace(f_frsize=4096, f_bavail=800000)
        operating_system.readlink = lambda path: "/usr/bin/python3.12"
        lib = SimpleNamespace(quotactl=lambda *args: self.quotactl(*args))
        return dict(
            copy=copy,
            ctypes=SimpleNamespace(
                CDLL=lambda *args, **kw: lib,
                get_errno=lambda: errno.ENOENT,
                c_int=ctypes.c_int,
                c_char_p=ctypes.c_char_p,
                c_void_p=ctypes.c_void_p,
                create_string_buffer=ctypes.create_string_buffer,
            ),
            errno=errno,
            fcntl=SimpleNamespace(ioctl=self.ioctl),
            hashlib=hashlib,
            json=json,
            os=operating_system,
            pathlib=SimpleNamespace(Path=self.path),
            pwd=SimpleNamespace(getpwnam=lambda name: SimpleNamespace(pw_uid=1000, pw_gid=1000)),
            stat=stat,
            struct=struct,
            subprocess=SimpleNamespace(
                run=self.run,
                DEVNULL=subprocess.DEVNULL,
                PIPE=subprocess.PIPE,
                CalledProcessError=subprocess.CalledProcessError,
            ),
            sys=SimpleNamespace(argv=["program", json.dumps(c)]),
            time=time,
            uuid=uuid,
        )

    def invoke(self, mode):
        self.c["mode"] = mode
        if mode in ("cleanup", "inspect-cleanup"):
            self.pid += 1
        return execute(exhaustion.PROGRAM, self.namespace(self.c))

    def prepare(self):
        value = self.invoke("prepare")
        self.c["identity"] = value["identity"]
        return value

    def fill(self):
        value = self.invoke("fill")
        self.c["allocation"] = value["allocation"]
        return value


def test_prepare_refuses_all_foreign_stale_and_mounted_claims_before_effects():
    h = Harness()
    value = h.prepare()
    assert value["refusals_verified"] == list(exhaustion.REFUSALS)
    assert value["quota_before"]["used_bytes"] == 0
    assert value["quota"]["hard_bytes"] == exhaustion.CAPACITY and value["quota"]["used_bytes"] == 0
    first = h.events.index("mkdir")
    assert h.events[:first].count("storage-read") >= 12
    assert not any(x == "quota-mutate" for x in h.events[:first])
    assert h.projects[h.c["target"]] == h.c["project_id"]
    assert value["identity"]["directory"]["uid"] == 1000
    assert value["allocation_retained_until_guest_cleanup"] is True


def test_fixed_workers_and_fresh_observer_record_real_syscall_result_and_preserve_custody():
    h = Harness()
    h.prepare()
    filled = h.fill()
    observed = h.invoke("observe")
    assert filled["allocation"]["failure"] == {
        "errno": 28,
        "name": "ENOSPC",
        "syscall": "posix_fallocate",
        "offset": exhaustion.CAPACITY - exhaustion.CHUNK,
        "length": exhaustion.CHUNK,
    }
    assert observed["allocation"]["failure"] == filled["allocation"]["failure"]
    assert filled["allocation"]["pid"] != observed["allocation"]["pid"]
    assert observed["quota"] == filled["quota"]
    assert observed["allocation"]["inode"] == filled["allocation"]["inode"]
    assert observed["control_write"]["device"] == 11 and observed["control_write"]["fsynced"]
    assert observed["allocation"]["outside_write"]["device"] == 12
    outside = observed["allocation"]["outside_write"]
    assert outside["project_id"] == 0 and outside["bytes"] == outside["length"] == exhaustion.CHUNK
    assert (
        outside["allocated_bytes"] >= exhaustion.CHUNK and outside["syscall"] == "posix_fallocate"
    )
    assert h.allocations[-1][0].startswith(h.root + "/data/outside-") and h.allocations[-1][1:] == (
        0,
        exhaustion.CHUNK,
    )
    assert not any("outside-" in p or "witness-" in p for p in h.meta)
    assert observed["guest_canaries_preserved"]


@pytest.mark.parametrize("code", [errno.EDQUOT, errno.EIO, errno.EACCES])
def test_fixed_worker_reports_actual_errno_without_relabeling(code):
    h = Harness()
    h.prepare()
    h.code = code
    value = h.fill()
    assert value["allocation"]["failure"]["errno"] == code
    assert value["allocation"]["failure"]["name"] == errno.errorcode[code]
    with pytest.raises(exhaustion.GuestExhaustionError, match="enospc"):
        exhaustion.validate_allocation(value["allocation"], h.c, "fill")


def test_missing_enforcement_stops_at_finite_fixture_budget_and_cannot_qualify():
    h = Harness()
    h.prepare()
    h.enforced = False
    result = h.run(
        [
            "/usr/bin/python3",
            "-I",
            "-S",
            "-c",
            exhaustion.WORKER,
            json.dumps({**h.c, "mode": "fill", "directory": h.c["identity"]["directory"]}),
        ],
        check=True,
        timeout=watchdog(60),
        user=1000,
        group=1000,
        extra_groups=[],
        start_new_session=True,
        umask=0o077,
    )
    value = json.loads(result.stdout)
    assert value["failure"] is None and value["size_after"] == 32 * exhaustion.CHUNK
    assert h.events.count("fallocate") == 32
    with pytest.raises(exhaustion.GuestExhaustionError):
        exhaustion.validate_allocation(value, h.c, "fill")


@pytest.mark.parametrize(
    "key",
    [
        "enrollment",
        "boot_id",
        "device",
        "uuid",
        "directory",
        "mounted-target",
        "existing-target",
        "quota-in-use",
    ],
)
def test_changed_or_foreign_preparation_refuses_before_any_mutation(key):
    h = Harness()
    if key in ("enrollment", "boot_id"):
        h.c["storage"][key] = str(uuid.uuid4())
    elif key == "device":
        h.c["storage"]["devices"]["data"]["path"] = "/dev/foreign"
    elif key == "uuid":
        h.c["storage"]["uuids"]["data"] = str(uuid.uuid4())
    elif key == "directory":
        h.c["storage"]["state"]["data"]["directory"]["inode"] += 1
    elif key == "mounted-target":
        h.c["target"] = h.root + "/data"
    elif key == "existing-target":
        h.directory(h.c["target"], 12, 900, 0, 0o700)
    else:
        h.q.update(present=True, inodes=1)
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        h.prepare()
    assert not any(x in h.events for x in ("mkdir", "quota-mutate", "fallocate", "chown"))


@pytest.mark.parametrize(
    "key",
    ["directory", "mount", "project", "quota-version", "quota-limit", "task", "allocation-inode"],
)
def test_changed_live_resource_is_rejected_before_allocation(key):
    h = Harness()
    h.prepare()
    if key == "directory":
        h.meta[h.c["target"]].st_ino += 1
    elif key == "mount":
        h.mounted = True
    elif key == "project":
        h.bad_attributes = True
    elif key == "quota-version":
        h.bad_quota = True
    elif key == "quota-limit":
        h.q["hard_bytes"] += 512
    elif key == "task":
        h.c["identity"]["task"] = str(uuid.uuid4())
    else:
        h.fill()
        h.c["allocation"]["inode"] += 1
    h.events.clear()
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        h.invoke("observe" if key == "allocation-inode" else "fill")
    assert "fallocate" not in h.events


@pytest.mark.parametrize("key", ["actor", "capabilities", "image", "inode", "size"])
def test_supervisor_checks_unprivileged_worker_against_independent_file_and_image(key):
    h = Harness()
    h.prepare()

    def change(value):
        if key == "actor":
            value["actor"] = {"uid": 0, "gid": 0}
        elif key == "capabilities":
            value["effective_capabilities"] = 1
        elif key == "image":
            value["executable"]["sha256"] = "0" * 64
        elif key == "inode":
            value["inode"] += 1
        else:
            value["size_after"] += 1

    h.worker_change = change
    with pytest.raises(ValueError, match="refused"):
        h.fill()


def controlled_guest(h, change=None):
    def guarded(argv, enrollment, boot, *, deadline, nominal):
        assert enrollment == h.enrollment and boot == h.boot and deadline.remaining() > 0
        assert argv[:4] == ["/usr/bin/python3", "-I", "-S", "-c"] and argv[4] == exhaustion.PROGRAM
        h.c = json.loads(argv[-1])
        h.q["project_id"] = h.c["project_id"]
        value = h.invoke(h.c["mode"])
        if change:
            change(value)
        return json.dumps(value)

    h.guest.guarded = guarded
    return h.guest


def test_coordinator_runs_three_guarded_observations_and_preserves_host_canary_and_stats(tmp_path):
    h = Harness()
    report = {}
    stages = []

    def progress(name):
        stages.append(name)
        return nullcontext()

    exhaustion.qualify_exhaustion(controlled_guest(h), progress, tmp_path, report)
    assert stages == ["exhaustion-prepare", "exhaustion-fill", "exhaustion-independent-observer"]
    assert report["status"] == "passed" and report["unrelated_host_canary_preserved"]
    assert report["resources_destroyed_with_guest"] is False
    assert valid_stats(report["statistics"]) and not list(tmp_path.iterdir())
    assert (
        report["fill"]["allocation"]["failure"]["name"]
        == report["observe"]["allocation"]["failure"]["name"]
        == "ENOSPC"
    )


@pytest.mark.parametrize(
    "change",
    [
        "wrong-error",
        "missing-error",
        "wrong-type",
        "missing-canary",
        "wrong-quota",
        "wrong-inode",
        "same-process",
        "outside-write",
        "control-write",
        "malformed",
    ],
)
def test_coordinator_cannot_accept_missing_forged_or_inexact_proof_and_keeps_stats(
    change, tmp_path
):
    h = Harness()
    report = {}

    def mutate(value):
        if value["mode"] != "observe":
            return
        if change == "wrong-error":
            value["allocation"]["failure"].update(errno=122, name="EDQUOT")
        elif change == "missing-error":
            value["allocation"]["failure"] = None
        elif change == "wrong-type":
            value["allocation"]["effective_capabilities"] = False
        elif change == "missing-canary":
            value["guest_canaries_preserved"] = 1
        elif change == "wrong-quota":
            value["quota"]["hard_bytes"] = True
        elif change == "wrong-inode":
            value["allocation"]["inode"] += 1
        elif change == "same-process":
            value["allocation"]["pid"] = report["fill"]["allocation"]["pid"]
        elif change == "outside-write":
            value["allocation"]["outside_write"]["device"] = 11
        elif change == "control-write":
            value["control_write"]["fsynced"] = False
        else:
            value["identity"] = None

    with pytest.raises(exhaustion.GuestExhaustionError):
        exhaustion.qualify_exhaustion(
            controlled_guest(h, mutate), lambda name: nullcontext(), tmp_path, report
        )
    assert report["status"] == "failed" and not report["resources_destroyed_with_guest"]
    assert report["unrelated_host_canary_preserved"] and valid_stats(report["statistics"])
    assert not list(tmp_path.iterdir())
    if change == "wrong-error":
        assert report["observe"]["allocation"]["failure"]["name"] == "EDQUOT"


@pytest.mark.parametrize("raw", ["[]", "null", "{bad"], ids=["list", "null", "invalid-json"])
def test_invalid_remote_reply_is_never_evidence(raw):
    h = Harness()
    h.guest.guarded = lambda *args, **kwargs: raw
    with pytest.raises(exhaustion.GuestExhaustionError, match="invalid-exhaustion"):
        exhaustion.invoke(h.guest, "prepare", h.c, Deadline.after(10))


@pytest.mark.parametrize("missing", ["guest", "storage"])
def test_missing_prerequisites_preserve_failed_stats_without_effects(missing, tmp_path):
    h = Harness()
    report = {}
    if missing == "guest":
        h.guest.observed = None
    else:
        h.guest.report["storage"]["permissions_verified"] = False
    with pytest.raises(exhaustion.GuestExhaustionError):
        exhaustion.qualify_exhaustion(h.guest, lambda name: nullcontext(), tmp_path, report)
    assert report["status"] == "failed" and valid_stats(report["statistics"]) and not h.events


def test_failed_storage_observation_still_leaves_owner_cleanup_responsibility_visible(tmp_path):
    h = Harness()
    report = {}
    guest = controlled_guest(h)

    def refused(*args, **kwargs):
        raise exhaustion.GuestExhaustionError("controlled-observer-failure")

    guest.guarded = refused
    with pytest.raises(exhaustion.GuestExhaustionError):
        exhaustion.qualify_exhaustion(guest, lambda name: nullcontext(), tmp_path, report)
    assert (
        report["unrelated_host_canary_preserved"] and not report["resources_destroyed_with_guest"]
    )
    assert valid_stats(report["statistics"])


def test_exhaustion_cleanup_flag_is_recorded_only_after_whole_guest_owner_observations(monkeypatch):
    value = {
        "process_reaped": True,
        "temporary_resources_removed": True,
        "storage": {},
        "endpoint": {},
        "exhaustion": {"resources_destroyed_with_guest": False},
        "allocation_release_reuse": {
            "resources_destroyed_with_guest": False,
            "per_allocation_destruction_qualified": False,
        },
    }
    inputs = {"temporary_resources_removed": True, "base_preserved": True}
    monkeypatch.setattr(native, "endpoint_closed", lambda endpoint: None)
    native.verify_guest_cleanup(value, inputs)
    assert value["exhaustion"]["resources_destroyed_with_guest"] is True
    assert value["allocation_release_reuse"]["resources_destroyed_with_guest"] is True
    assert value["allocation_release_reuse"]["per_allocation_destruction_qualified"] is False
    value["exhaustion"]["resources_destroyed_with_guest"] = False
    value["allocation_release_reuse"]["resources_destroyed_with_guest"] = False
    value["process_reaped"] = False
    with pytest.raises(native.GuestStorageError):
        native.verify_guest_cleanup(value, inputs)
    assert value["exhaustion"]["resources_destroyed_with_guest"] is False
    assert value["allocation_release_reuse"]["resources_destroyed_with_guest"] is False


def test_project_limit_crossing_includes_allocated_blocks_beyond_logical_size():
    h = Harness()
    h.prepare()
    filled = h.fill()
    allocation = filled["allocation"]
    assert allocation["size_after"] == 15 * exhaustion.CHUNK
    assert allocation["allocated_bytes"] == allocation["size_after"] + 4096
    assert filled["quota"]["used_bytes"] == allocation["allocated_bytes"]
    assert (
        filled["quota"]["hard_bytes"] - filled["quota"]["used_bytes"]
        < allocation["failure"]["length"]
    )
    exhaustion.validate_rejection(filled, h.c, "fill")


def test_errno_alone_cannot_prove_project_exhaustion_before_the_hard_bound():
    h = Harness()
    h.prepare()
    filled = h.fill()
    filled["quota"]["used_bytes"] = exhaustion.CHUNK
    filled["allocation"]["allocated_bytes"] = exhaustion.CHUNK
    with pytest.raises(exhaustion.GuestExhaustionError, match="bound-not-reached"):
        exhaustion.validate_rejection(filled, h.c, "fill")


@pytest.mark.parametrize(
    "changed", ["project", "length", "syscall", "allocation", "global-space", "space-type"]
)
def test_independent_proof_requires_matching_outside_allocation_and_available_filesystem(
    changed, tmp_path
):
    h = Harness()
    report = {}

    def alter(value):
        if value["mode"] != "observe":
            return
        outside = value["allocation"]["outside_write"]
        if changed == "project":
            outside["project_id"] = value["identity"]["project_id"]
        elif changed == "length":
            outside["length"] = 21
        elif changed == "syscall":
            outside["syscall"] = "write"
        elif changed == "allocation":
            outside["allocated_bytes"] = 21
        elif changed == "global-space":
            value["filesystem_space"].update(available_blocks=1, available_bytes=4096)
        else:
            value["filesystem_space"]["available_blocks"] = True

    with pytest.raises(exhaustion.GuestExhaustionError):
        exhaustion.qualify_exhaustion(
            controlled_guest(h, alter), lambda name: nullcontext(), tmp_path, report
        )
    assert report["status"] == "failed" and valid_stats(report["statistics"])


def test_exact_release_frees_capacity_and_repeated_observation_does_not_repeat_effect():
    h = Harness()
    h.prepare()
    h.fill()
    first = h.invoke("release")
    exhaustion.validate_release(first, h.c, "release", already_empty=False)
    assert first["allocation_after"]["size"] == first["allocation_after"]["allocated_bytes"] == 0
    assert h.events.count("truncate") == 1
    assert first["release_effect"] == {"syscall": "ftruncate", "length": 0, "fsynced": True}
    h.events.clear()
    observed = h.invoke("inspect-release")
    repeated = h.invoke("release")
    for value, mode in ((observed, "inspect-release"), (repeated, "release")):
        exhaustion.validate_release(value, h.c, mode, already_empty=True)
        assert value["allocation_before"] == value["allocation_after"] == first["allocation_after"]
        assert value["release_effect"] == {"syscall": None, "length": None, "fsynced": False}
    assert "truncate" not in h.events and "fallocate" not in h.events


def test_fresh_reuse_runs_same_inode_and_project_as_nonroot_then_releases_again():
    h = Harness()
    h.prepare()
    original = h.fill()["allocation"]
    h.invoke("release")
    reused = h.invoke("reuse")
    exhaustion.validate_common(reused, h.c, "reuse")
    exhaustion.validate_allocation(reused["allocation"], h.c, "reuse")
    value = reused["allocation"]
    assert value["inode"] == original["inode"] and value["project_id"] == original["project_id"]
    assert value["size_before"] == 0 and value["size_after"] == exhaustion.CHUNK
    assert value["failure"] is None and value["actor"] == {"uid": 1000, "gid": 1000}
    h.c["allocation"] = value
    final = h.invoke("release")
    exhaustion.validate_release(final, h.c, "release", already_empty=False)
    assert final["quota"]["used_bytes"] == 0


@pytest.mark.parametrize(
    "change",
    [
        "inode",
        "project",
        "directory",
        "actor",
        "boot",
        "mounted",
        "hardlink",
        "mode",
        "size",
        "blocks",
    ],
)
def test_release_refuses_foreign_stale_or_changed_state_before_truncating(change):
    h = Harness()
    h.prepare()
    h.fill()
    allocation = h.meta[h.c["target"] + "/allocation"]
    if change == "inode":
        h.c["allocation"]["inode"] += 1
    elif change == "project":
        h.bad_attributes = True
    elif change == "directory":
        h.meta[h.c["target"]].st_ino += 1
    elif change == "actor":
        h.c["actor"] = {"uid": 0, "gid": 0}
    elif change == "boot":
        h.c["boot_id"] = str(uuid.uuid4())
    elif change == "mounted":
        h.mounted = True
    elif change == "hardlink":
        allocation.st_nlink = 2
    elif change == "mode":
        allocation.st_mode = stat.S_IFREG | 0o644
    elif change == "size":
        allocation.st_size -= 1
    else:
        allocation.st_blocks += 1
    h.events.clear()
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        h.invoke("release")
    assert "truncate" not in h.events and "fallocate" not in h.events


@pytest.mark.parametrize("mode", ["inspect-release", "reuse"])
def test_unreleased_allocation_cannot_qualify_release_observation_or_reuse(mode):
    h = Harness()
    h.prepare()
    h.fill()
    h.events.clear()
    with pytest.raises(ValueError):
        h.invoke(mode)
    assert "truncate" not in h.events and "fallocate" not in h.events


def source_exhaustion(h, tmp_path):
    source = {}
    guest = controlled_guest(h)
    exhaustion.qualify_exhaustion(guest, lambda name: nullcontext(), tmp_path, source)
    guest.report["exhaustion"] = source
    return guest


def test_release_coordinator_observes_capacity_retries_reuses_and_releases_exact_resource(tmp_path):
    h = Harness()
    guest = source_exhaustion(h, tmp_path)
    report = {}
    exhaustion.qualify_release_reuse(guest, lambda name: nullcontext(), tmp_path, report)
    assert report["status"] == "passed"
    assert [v["scenario"] for v in report["cases"]] == [
        "release",
        "independent-release",
        "repeat-release",
        "fresh-reuse",
        "final-release",
        "final-observer",
    ]
    assert all(v["status"] == "passed" and valid_stats(v["statistics"]) for v in report["cases"])
    assert valid_stats(report["statistics"]) and report["unrelated_host_canary_preserved"]
    assert report["resources_destroyed_with_guest"] is False
    assert report["per_allocation_destruction_qualified"] is False
    assert h.events.count("truncate") == 2 and not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "change",
    [
        "inode",
        "remaining-capacity",
        "released-size",
        "retry-effect",
        "reuse-error",
        "reuse-identity",
        "missing-canary",
    ],
)
def test_release_coordinator_rejects_inexact_witness_and_retains_failed_case_stats(
    change, tmp_path
):
    h = Harness()
    guest = source_exhaustion(h, tmp_path)
    report = {}

    def alter(value):
        if value["mode"] == "reuse":
            if change == "reuse-error":
                value["allocation"]["failure"] = {"errno": 28, "name": "ENOSPC"}
            elif change == "reuse-identity":
                value["allocation"]["inode"] += 1
            return
        if value["mode"] != "inspect-release":
            return
        if change == "inode":
            value["allocation_after"]["inode"] += 1
        elif change == "remaining-capacity":
            value["quota"]["used_bytes"] = exhaustion.CAPACITY
        elif change == "released-size":
            value["allocation_after"]["size"] = 1
        elif change == "retry-effect":
            value["already_empty"] = False
        elif change == "missing-canary":
            value["guest_canaries_preserved"] = 1

    controlled_guest(h, alter)
    with pytest.raises(exhaustion.GuestExhaustionError):
        exhaustion.qualify_release_reuse(guest, lambda name: nullcontext(), tmp_path, report)
    assert report["status"] == "failed" and report["cases"][-1]["status"] == "failed"
    assert valid_stats(report["statistics"]) and all(
        valid_stats(v["statistics"]) for v in report["cases"]
    )
    assert (
        report["unrelated_host_canary_preserved"] and not report["resources_destroyed_with_guest"]
    )
    assert not list(tmp_path.iterdir())


def test_release_requires_current_verified_exhaustion_and_preserves_failed_statistics(tmp_path):
    h = Harness()
    report = {}
    with pytest.raises(exhaustion.GuestExhaustionError, match="exhaustion-not-verified"):
        exhaustion.qualify_release_reuse(h.guest, lambda name: nullcontext(), tmp_path, report)
    assert not h.events and valid_stats(report["statistics"]) and report["status"] == "failed"


def released_allocation(h):
    h.prepare()
    h.fill()
    return h.invoke("release")


def test_known_cleanup_destroys_only_empty_owned_resources_and_retries_without_effects():
    h = Harness()
    released_allocation(h)
    before = copy.deepcopy(h.c["identity"])
    value = h.invoke("cleanup")
    assert value["identity"] == before and value["already_absent"] is False
    assert value["cleanup_effects"] == dict.fromkeys(
        ("unlink", "project_reset", "limit_reset", "rmdir"), True
    )
    assert value["refusals_verified"] == list(exhaustion.CLEANUP_REFUSALS)
    assert value["allocation_before"]["inode"] == h.c["allocation"]["inode"]
    assert value["unlinked_allocation_links"] == value["removed_directory_links"] == 0
    assert h.c["target"] not in h.meta and h.c["target"] + "/allocation" not in h.meta
    assert (
        value["quota"]["hard_bytes"]
        == value["quota"]["used_bytes"]
        == value["quota"]["inodes"]
        == 0
    )
    h.events.clear()
    observed = h.invoke("inspect-cleanup")
    repeated = h.invoke("cleanup")
    for result in (observed, repeated):
        assert result["identity"] == before and result["already_absent"] is True
        assert result["target_absent"] is result["allocation_absent"] is True
        assert not any(result["cleanup_effects"].values()) and result["allocation_before"] is None
    assert observed["observer"]["pid"] != repeated["observer"]["pid"] != value["observer"]["pid"]
    assert set(h.events) == {"storage-read"} and not h.fds and not h.removed


@pytest.mark.parametrize(
    "change",
    [
        "inode",
        "directory",
        "actor",
        "boot",
        "project",
        "quota",
        "extra-inode",
        "size",
        "blocks",
        "hardlink",
        "mode",
        "extra-entry",
        "mounted",
        "directory-bind-mount",
        "allocation-bind-mount",
    ],
)
def test_known_cleanup_refuses_unowned_or_unreleased_live_state_before_any_effect(change):
    h = Harness()
    released_allocation(h)
    allocation = h.meta[h.c["target"] + "/allocation"]
    if change == "inode":
        h.c["allocation"]["inode"] += 1
    elif change == "directory":
        h.meta[h.c["target"]].st_ino += 1
    elif change == "actor":
        h.c["actor"] = {"uid": 0, "gid": 0}
    elif change == "boot":
        h.c["boot_id"] = str(uuid.uuid4())
    elif change == "project":
        h.bad_attributes = True
    elif change == "quota":
        h.q["hard_bytes"] += 512
    elif change == "extra-inode":
        h.q["inodes"] += 1
    elif change == "size":
        allocation.st_size = 1
    elif change == "blocks":
        allocation.st_blocks = 1
    elif change == "hardlink":
        allocation.st_nlink = 2
    elif change == "mode":
        allocation.st_mode = stat.S_IFREG | 0o644
    elif change == "extra-entry":
        h.close(h.open(h.c["target"] + "/foreign", os.O_CREAT | os.O_EXCL, 0o600))
    elif change == "mounted":
        h.mounted = True
    else:
        target = h.c["target"] + ("/allocation" if change == "allocation-bind-mount" else "")
        h.mountinfo = "42 1 0:1 / " + target + " rw - xfs /dev/vdc rw\n"
    before = copy.deepcopy(h.meta)
    h.events.clear()
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        h.invoke("cleanup")
    assert h.meta == before
    assert not any(
        e.startswith(("unlink:", "quota-mutate", "project-reset", "rmdir", "create:", "truncate"))
        for e in h.events
    )
    assert not h.fds


@pytest.mark.parametrize("mode", ["cleanup", "inspect-cleanup"])
def test_absent_target_with_unreleased_limits_cannot_be_guessed_as_cleaned(mode):
    h = Harness()
    released_allocation(h)
    h.invoke("cleanup")
    h.q["hard_bytes"] = exhaustion.CAPACITY
    h.events.clear()
    with pytest.raises(ValueError):
        h.invoke(mode)
    assert set(h.events) <= {"storage-read"}


def test_read_only_cleanup_observer_refuses_a_still_present_resource():
    h = Harness()
    released_allocation(h)
    h.events.clear()
    with pytest.raises(ValueError):
        h.invoke("inspect-cleanup")
    assert set(h.events) <= {"storage-read"}


def source_release(h, tmp_path):
    guest = source_exhaustion(h, tmp_path)
    source = {}
    exhaustion.qualify_release_reuse(guest, lambda name: nullcontext(), tmp_path, source)
    guest.report["allocation_release_reuse"] = source
    return guest


def test_cleanup_controller_recovers_unadmitted_reply_by_independent_absence_and_retry(tmp_path):
    h = Harness()
    guest = source_release(h, tmp_path)
    report = {}
    exhaustion.qualify_allocation_cleanup(guest, lambda name: nullcontext(), tmp_path, report)
    assert report["status"] == "passed" and report["per_allocation_destruction_qualified"] is True
    assert (
        report["partial_setup_recovery_qualified"]
        is report["resources_destroyed_with_guest"]
        is False
    )
    assert report["cleanup_outcome"] == "absent-observed-independently"
    assert report["original_reply_validated_after_independent_observation"] is True
    assert [c["scenario"] for c in report["cases"]] == [
        "unadmitted-cleanup-reply",
        "independent-absence",
        "repeat-cleanup",
        "final-absence",
    ]
    first = report["cases"][0]
    assert first["mutation_reply_admitted"] is False and first["cleanup_outcome"] == "unobserved"
    assert first["observer_interruption_kind"] == "controlled-exception-before-reply-admission"
    assert first["unadmitted_reply"]["cleanup_effects"]["unlink"] is True
    assert all(c["status"] == "passed" and valid_stats(c["statistics"]) for c in report["cases"])
    assert valid_stats(report["statistics"]) and report["unrelated_host_canary_preserved"]
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "change",
    [
        "effect",
        "inode",
        "canary",
        "quota",
        "observer",
        "repeat-effect",
        "repeat-mode",
        "repeat-pid",
    ],
)
def test_cleanup_controller_rejects_inexact_evidence_and_preserves_failure_statistics(
    change, tmp_path
):
    h = Harness()
    guest = source_release(h, tmp_path)
    report = {}
    original_pid = None

    def alter(value):
        nonlocal original_pid
        if value["mode"] == "cleanup" and not value["already_absent"]:
            original_pid = value["observer"]["pid"]
            if change == "effect":
                value["cleanup_effects"]["unlink"] = False
            elif change == "inode":
                value["allocation_before"]["inode"] += 1
            elif change == "canary":
                value["guest_canaries_preserved"] = 1
            elif change == "quota":
                value["quota"]["hard_bytes"] = exhaustion.CAPACITY
            elif change == "observer":
                value["observer"]["pid"] = 0
        elif value["mode"] == "cleanup":
            if change == "repeat-effect":
                value["cleanup_effects"]["unlink"] = True
            elif change == "repeat-mode":
                value["mode"] = "foreign"
            elif change == "repeat-pid":
                value["observer"]["pid"] = original_pid

    controlled_guest(h, alter)
    with pytest.raises(exhaustion.GuestExhaustionError):
        exhaustion.qualify_allocation_cleanup(guest, lambda name: nullcontext(), tmp_path, report)
    assert report["status"] == "failed" and report["cases"][-1]["status"] == "failed"
    assert report["per_allocation_destruction_qualified"] is False
    assert valid_stats(report["statistics"]) and all(
        valid_stats(c["statistics"]) for c in report["cases"]
    )
    assert report["unrelated_host_canary_preserved"] and not list(tmp_path.iterdir())


def test_cleanup_requires_current_independently_verified_release_before_any_guest_call(tmp_path):
    h = Harness()
    guest = source_exhaustion(h, tmp_path)
    h.events.clear()
    report = {}
    with pytest.raises(exhaustion.GuestExhaustionError, match="allocation-release-not-verified"):
        exhaustion.qualify_allocation_cleanup(guest, lambda name: nullcontext(), tmp_path, report)
    assert not h.events and valid_stats(report["statistics"]) and report["status"] == "failed"


def test_cleanup_missing_required_measurements_cannot_report_qualification(tmp_path, monkeypatch):
    h = Harness()
    guest = source_release(h, tmp_path)
    report = {}
    monkeypatch.setattr(exhaustion, "RunStats", lambda: SimpleNamespace(finish=lambda: {}))
    with pytest.raises(ValueError, match="invalid required allocation cleanup statistics"):
        exhaustion.qualify_allocation_cleanup(guest, lambda name: nullcontext(), tmp_path, report)
    assert report["status"] == "failed" and report["per_allocation_destruction_qualified"] is False
    assert report["cases"][0]["status"] == "failed"
    assert report["statistics"] == report["cases"][0]["statistics"] == {}
    assert report["unrelated_host_canary_preserved"] and not list(tmp_path.iterdir())
