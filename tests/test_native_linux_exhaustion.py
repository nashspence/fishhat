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
    "scope": "controlled execution of fixed quota preparation, kernel-allocation worker and independent observer, foreign/stale/mounted admission refusal, exact selected-profile errno preservation, matching outside-project allocation and global space evidence, finite fail-safe allocation, canaries, teardown evidence and mandatory measurement scope",
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
                if str(self) == "/proc/self/status":
                    return "CapEff:\t0000000000000000\n"
                raise AssertionError(str(self))

            def read_bytes(self):
                assert str(self) == "/proc/self/exe"
                return b"fixed-guest-interpreter"

            def unlink(self):
                h.events.append("unlink:" + self.name)
                del h.meta[str(self)]
                h.files.pop(str(self), None)

        return Path(str(value))

    def open(self, path, flags, mode=0o777):
        path = str(path)
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

    def ioctl(self, fd, operation, buffer):
        assert operation == 0x801C581F and len(buffer) == 28
        path = self.fds[fd]
        return struct.pack(
            "=5I8s",
            0x200 if stat.S_ISDIR(self.meta[path].st_mode) else 0,
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
                assert command == f"limit -p bhard={exhaustion.CAPACITY} {self.c['project_id']}"
                self.q["hard_bytes"] = exhaustion.CAPACITY
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
        operating_system.close = lambda fd: self.fds.pop(fd)
        operating_system.chown = self.chown
        operating_system.fstat = lambda fd: copy.copy(self.meta[self.fds[fd]])
        operating_system.posix_fallocate = self.allocate
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
    }
    inputs = {"temporary_resources_removed": True, "base_preserved": True}
    monkeypatch.setattr(native, "endpoint_closed", lambda endpoint: None)
    native.verify_guest_cleanup(value, inputs)
    assert value["exhaustion"]["resources_destroyed_with_guest"] is True
    value["exhaustion"]["resources_destroyed_with_guest"] = False
    value["process_reaped"] = False
    with pytest.raises(native.GuestStorageError):
        native.verify_guest_cleanup(value, inputs)
    assert value["exhaustion"]["resources_destroyed_with_guest"] is False


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
