"""Observe real quota exhaustion only in an enrolled disposable guest allocation."""

from __future__ import annotations

import json
import tempfile
import uuid
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from scripts.native_linux_guest import Guest, GuestBootError
from scripts.native_linux_storage import PACKAGES
from scripts.native_linux_storage import PROGRAM as STORAGE_PROGRAM
from scripts.run_stats import RunStats, valid_stats
from scripts.validation_timeouts import Deadline, current

# These are capacities of one disposable fixture, never product collection bounds.
CAPACITY = 16 * 1024 * 1024
CHUNK = 1024 * 1024
REFUSALS = (
    "foreign-enrollment",
    "stale-boot",
    "foreign-device",
    "foreign-filesystem",
    "stale-directory",
    "mounted-target",
)

# Each allocation has a small fail-safe budget even if quota enforcement breaks.
# A second independent invocation probes the already exhausted allocation.
WORKER = r"""
import errno, fcntl, hashlib, json, os, pathlib, stat, struct, sys, time
c = json.loads(sys.argv[1])
def require(value):
    if not value:
        raise ValueError("exhaustion-worker-refused")
require(c["mode"] in ("fill", "probe", "reuse"))
require(os.getuid() == os.geteuid() == c["actor"]["uid"] >= 1000)
require(os.getgid() == os.getegid() == c["actor"]["gid"] and not os.getgroups())
status = dict(row.split(":", 1) for row in pathlib.Path("/proc/self/status").read_text().splitlines())
require(int(status["CapEff"], 16) == 0)
require(pathlib.Path("/etc/fishhat-fixture-enrollment").read_text().strip() == c["enrollment"])
require(pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip() == c["boot_id"])
path = pathlib.Path(c["target"])
v = path.lstat()
require(stat.S_ISDIR(v.st_mode) and {"device": v.st_dev, "inode": v.st_ino, "uid": v.st_uid, "gid": v.st_gid, "mode": stat.S_IMODE(v.st_mode)} == c["directory"])
flags = os.O_RDWR | os.O_NOFOLLOW
if c["mode"] == "fill":
    flags |= os.O_CREAT | os.O_EXCL
fd = os.open(path / "allocation", flags, 0o600)
try:
    v = os.fstat(fd)
    require(stat.S_ISREG(v.st_mode) and v.st_nlink == 1 and v.st_uid == c["actor"]["uid"] and v.st_gid == c["actor"]["gid"] and stat.S_IMODE(v.st_mode) == 0o600)
    require(v.st_dev == c["directory"]["device"])
    attributes = struct.unpack("=5I8s", fcntl.ioctl(fd, 0x801c581f, bytes(28)))
    require(attributes[3] == c["project_id"])
    if c["mode"] != "fill":
        require(v.st_ino == c["allocation_inode"])
    if c["mode"] == "reuse":
        require(v.st_size == 0)
    before = v.st_size
    offset = before
    failure = None
    end = time.monotonic() + c["seconds"]
    for _ in range(32 if c["mode"] == "fill" else 1):
        require(time.monotonic() < end)
        try:
            os.posix_fallocate(fd, offset, c["chunk_bytes"])
        except OSError as error:
            failure = {"errno": error.errno, "name": errno.errorcode.get(error.errno, "UNKNOWN"), "syscall": "posix_fallocate", "offset": offset, "length": c["chunk_bytes"]}
            break
        if c["mode"] == "probe":
            break
        require(os.pwrite(fd, b"fixture-allocation\n", offset) == 19)
        os.fsync(fd)
        offset += c["chunk_bytes"]
    after = os.fstat(fd)
    result = {"mode": c["mode"], "actor": c["actor"], "supplementary_groups": [], "effective_capabilities": 0, "pid": os.getpid(), "executable": {"path": os.readlink("/proc/self/exe"), "sha256": hashlib.sha256(pathlib.Path("/proc/self/exe").read_bytes()).hexdigest()}, "project_id": attributes[3], "device": after.st_dev, "inode": after.st_ino, "size_before": before, "size_after": after.st_size, "allocated_bytes": after.st_blocks * 512, "failure": failure}
finally:
    os.close(fd)
if c["mode"] == "probe":
    # A separate write on the same XFS filesystem, outside this project, must work.
    outside = pathlib.Path(c["outside"])
    fd = os.open(outside, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        attributes = struct.unpack("=5I8s", fcntl.ioctl(fd, 0x801c581f, bytes(28)))
        require(attributes[3] == 0)
        os.posix_fallocate(fd, 0, c["chunk_bytes"])
        require(os.pwrite(fd, b"unrelated-allocation\n", 0) == 21)
        os.fsync(fd)
        v = os.fstat(fd)
        result["outside_write"] = {"device": v.st_dev, "inode": v.st_ino, "uid": v.st_uid, "gid": v.st_gid, "bytes": v.st_size, "allocated_bytes": v.st_blocks * 512, "project_id": attributes[3], "syscall": "posix_fallocate", "offset": 0, "length": c["chunk_bytes"], "fsynced": True}
    finally:
        os.close(fd)
        outside.unlink()
print(json.dumps(result, sort_keys=True))
"""

# Read-only kernel ABIs are fixed by the selected Linux x86_64 profile:
# linux/fs.h FS_IOC_FSGETXATTR and linux/dqblk_xfs.h Q_XGETQUOTA. Quota writes
# use the already pinned xfsprogs. No global quota mapping or mount is changed.
PROGRAM = r"""
import copy, ctypes, errno, fcntl, hashlib, json, os, pathlib, pwd, stat, struct, subprocess, sys, time, uuid
c = json.loads(sys.argv[1])
end = time.monotonic() + c["seconds"]
def require(value):
    if not value:
        raise ValueError("guest-exhaustion-refused")
def command(arguments, **kwargs):
    remaining = end - time.monotonic()
    require(remaining > 0)
    return subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, text=True, timeout=remaining, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}, **kwargs).stdout
def directory(path):
    v = path.lstat()
    require(stat.S_ISDIR(v.st_mode))
    return {"device": v.st_dev, "inode": v.st_ino, "uid": v.st_uid, "gid": v.st_gid, "mode": stat.S_IMODE(v.st_mode)}
require(os.geteuid() == 0 and c["mode"] in ("prepare", "fill", "observe", "release", "inspect-release", "reuse"))
require(str(uuid.UUID(c["task"])) == c["task"])
root = pathlib.Path("/run/fhs-" + uuid.UUID(c["enrollment"]).hex)
target = root / "data" / ("exhaustion-" + uuid.UUID(c["task"]).hex)
require(c["target"] == str(target))
admin = pwd.getpwnam(c["admin"])
require({"uid": admin.pw_uid, "gid": admin.pw_gid} == c["actor"] and admin.pw_uid >= 1000)
require(c["capacity_bytes"] == 16 * 1024 * 1024 and c["chunk_bytes"] == 1024 * 1024)
require(c["project_id"] == (uuid.UUID(c["task"]).int % 2147483646) + 1)
def admission(claim, *, fresh=False):
    require(claim["target"] == str(target))
    storage = copy.deepcopy(c["storage"])
    storage.update({k: claim[k] for k in ("enrollment", "boot_id", "state", "devices", "uuids")})
    storage.update(mode="verify", seconds=max(0.1, end - time.monotonic()))
    observed = json.loads(command(["/usr/bin/python3", "-I", "-S", "-c", c["storage_program"], json.dumps(storage, sort_keys=True)]))
    require(observed == {**storage["state"], "canaries_verified": True})
    require(directory(root) == c["storage"]["state"]["root"])
    # An existing mount or substituted directory must never become a fresh target.
    if fresh:
        require(not target.exists() and not target.is_symlink())
    elif c["mode"] != "prepare":
        require(directory(target) == c["identity"]["directory"] and not target.is_mount())
    return observed
claim = {k: c["storage"][k] for k in ("enrollment", "boot_id", "state", "devices", "uuids")}
claim["target"] = str(target)
admission(claim, fresh=c["mode"] == "prepare")
def quota():
    # fs_disk_quota is 112 bytes, aligned to 64 bits; block units are 512 bytes.
    lib = ctypes.CDLL(None, use_errno=True)
    call = lib.quotactl
    call.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
    call.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(112)
    result = call((0x5803 << 8) | 2, c["storage"]["devices"]["data"]["path"].encode(), c["project_id"], buffer)
    if result != 0:
        code = ctypes.get_errno()
        require(code == errno.ENOENT)
        return {"present": False, "project_id": c["project_id"], "hard_bytes": 0, "soft_bytes": 0, "used_bytes": 0, "inodes": 0, "inode_hard": 0, "inode_soft": 0}
    version, flags, mask, project, hard, soft, ihard, isoft, used, inodes = struct.unpack_from("=bbHI6Q", buffer.raw)
    require(version == 1 and flags == 2 and project == c["project_id"])
    return {"present": True, "project_id": project, "hard_bytes": hard * 512, "soft_bytes": soft * 512, "used_bytes": used * 512, "inodes": inodes, "inode_hard": ihard, "inode_soft": isoft}
def attributes():
    fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        values = struct.unpack("=5I8s", fcntl.ioctl(fd, 0x801c581f, bytes(28)))
    finally:
        os.close(fd)
    return {"project_id": values[3], "inherit": bool(values[0] & 0x200)}
def check_identity():
    identity = c["identity"]
    require(identity["task"] == c["task"] and identity["enrollment"] == c["enrollment"] and identity["boot_id"] == c["boot_id"])
    require(identity["project_id"] == c["project_id"] and identity["target"] == str(target))
    require(directory(target) == identity["directory"] and attributes() == {"project_id": c["project_id"], "inherit": True})
    value = quota()
    require(value["present"] and value["hard_bytes"] == c["capacity_bytes"] and value["soft_bytes"] == value["inode_hard"] == value["inode_soft"] == 0)
    require(0 <= value["used_bytes"] <= c["capacity_bytes"])
    return value
def worker(mode):
    w = {k: c[k] for k in ("actor", "enrollment", "boot_id", "project_id", "chunk_bytes", "seconds")}
    w.update(mode=mode, target=str(target), directory=c["identity"]["directory"], outside=str(root / "data" / ("outside-" + uuid.UUID(c["task"]).hex)))
    if mode in ("probe", "reuse"):
        w["allocation_inode"] = c["allocation"]["inode"]
    result = json.loads(command(["/usr/bin/python3", "-I", "-S", "-c", c["worker"], json.dumps(w, sort_keys=True)], user=admin.pw_uid, group=admin.pw_gid, extra_groups=[], umask=0o077, start_new_session=True, cwd=target))
    require(result["actor"] == c["actor"] and result["supplementary_groups"] == [] and result["effective_capabilities"] == 0)
    image = {"path": os.readlink("/proc/self/exe"), "sha256": hashlib.sha256(pathlib.Path("/proc/self/exe").read_bytes()).hexdigest()}
    require(result["executable"] == image)
    fd = os.open(target / "allocation", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        v = os.fstat(fd)
        require(stat.S_ISREG(v.st_mode) and v.st_nlink == 1 and v.st_uid == admin.pw_uid and v.st_gid == admin.pw_gid and stat.S_IMODE(v.st_mode) == 0o600)
        require(v.st_dev == result["device"] == c["identity"]["directory"]["device"] and v.st_ino == result["inode"])
        require(v.st_size == result["size_after"] and v.st_blocks * 512 == result["allocated_bytes"])
    finally:
        os.close(fd)
    return result
def allocation_snapshot(fd):
    v = os.fstat(fd)
    require(stat.S_ISREG(v.st_mode) and v.st_nlink == 1 and v.st_uid == admin.pw_uid and v.st_gid == admin.pw_gid and stat.S_IMODE(v.st_mode) == 0o600)
    require(v.st_dev == c["identity"]["directory"]["device"] and v.st_ino == c["allocation"]["inode"])
    attrs = struct.unpack("=5I8s", fcntl.ioctl(fd, 0x801c581f, bytes(28)))
    require(attrs[3] == c["project_id"])
    return {"device": v.st_dev, "inode": v.st_ino, "uid": v.st_uid, "gid": v.st_gid, "mode": stat.S_IMODE(v.st_mode), "project_id": attrs[3], "size": v.st_size, "allocated_bytes": v.st_blocks * 512}
def release_allocation():
    before = check_identity()
    fd = os.open(target / "allocation", (os.O_RDWR if c["mode"] == "release" else os.O_RDONLY) | os.O_NOFOLLOW)
    try:
        original = allocation_snapshot(fd)
        if original["size"] != 0:
            require(original["size"] == c["allocation"]["size_after"] and original["allocated_bytes"] == c["allocation"]["allocated_bytes"])
        already_empty = original["size"] == 0
        if c["mode"] == "release" and not already_empty:
            os.ftruncate(fd, 0)
            os.fsync(fd)
        after = allocation_snapshot(fd)
        require(after["size"] == 0 and after["allocated_bytes"] <= original["allocated_bytes"])
        if not already_empty:
            require(after["allocated_bytes"] + c["chunk_bytes"] <= original["allocated_bytes"])
    finally:
        os.close(fd)
    value = check_identity()
    require(value["used_bytes"] <= before["used_bytes"] and value["used_bytes"] + c["chunk_bytes"] <= c["capacity_bytes"])
    return {"identity": c["identity"], "quota_before": before, "quota": value, "allocation_before": original, "allocation_after": after, "already_empty": already_empty, "release_effect": {"syscall": "ftruncate" if c["mode"] == "release" and not already_empty else None, "length": 0 if c["mode"] == "release" and not already_empty else None, "fsynced": c["mode"] == "release" and not already_empty}}
if c["mode"] == "prepare":
    before = quota()
    require(before["hard_bytes"] == before["soft_bytes"] == before["used_bytes"] == before["inodes"] == before["inode_hard"] == before["inode_soft"] == 0)
    refusals = []
    for name in c["refusals"]:
        wrong = copy.deepcopy(claim)
        if name == "foreign-enrollment":
            wrong["enrollment"] = str(uuid.uuid4())
        elif name == "stale-boot":
            wrong["boot_id"] = str(uuid.uuid4())
        elif name == "foreign-device":
            wrong["devices"]["data"]["path"] = "/dev/foreign"
        elif name == "foreign-filesystem":
            wrong["uuids"]["data"] = str(uuid.uuid4())
        elif name == "stale-directory":
            wrong["state"]["data"]["directory"]["inode"] += 1
        elif name == "mounted-target":
            wrong["target"] = str(root / "data")
        else:
            raise ValueError("unknown-exhaustion-challenge")
        try:
            admission(wrong, fresh=True)
        except (ValueError, subprocess.CalledProcessError):
            require(not target.exists() and quota() == before)
            admission(claim, fresh=True)
            refusals.append(name)
        else:
            raise ValueError("foreign-exhaustion-claim-accepted")
    target.mkdir(mode=0o700)
    # No shared /etc/projects or /etc/projid input is consulted or modified.
    base = ["/usr/sbin/xfs_quota", "-x", "-D", "/dev/null", "-P", "/dev/null"]
    command([*base, "-c", "project -s -d 0 -p " + str(target) + " " + str(c["project_id"]), str(root / "data")])
    require(attributes() == {"project_id": c["project_id"], "inherit": True})
    command([*base, "-c", "limit -p bhard=" + str(c["capacity_bytes"]) + " " + str(c["project_id"]), str(root / "data")])
    os.chown(target, admin.pw_uid, admin.pw_gid)
    value = quota()
    require(value["present"] and value["hard_bytes"] == c["capacity_bytes"] and value["soft_bytes"] == value["used_bytes"] == 0 and value["inodes"] == 1)
    identity = {"enrollment": c["enrollment"], "boot_id": c["boot_id"], "task": c["task"], "target": str(target), "project_id": c["project_id"], "directory": directory(target)}
    result = {"identity": identity, "quota_before": before, "quota": value, "refusals_verified": refusals}
elif c["mode"] in ("release", "inspect-release"):
    result = release_allocation()
else:
    before = check_identity()
    result = {"identity": c["identity"], "quota_before": before, "allocation": worker("fill" if c["mode"] == "fill" else "reuse" if c["mode"] == "reuse" else "probe"), "quota": check_identity()}
    if c["mode"] == "observe":
        # Independent control-plane progress is on the separate control disk.
        witness = root / "control" / ("exhaustion-witness-" + uuid.UUID(c["task"]).hex)
        fd = os.open(witness, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            require(os.write(fd, b"control-progress\n") == 17)
            os.fsync(fd)
            v = os.fstat(fd)
            require(v.st_dev == c["storage"]["state"]["control"]["directory"]["device"])
            result["control_write"] = {"device": v.st_dev, "inode": v.st_ino, "uid": v.st_uid, "bytes": v.st_size, "fsynced": True}
        finally:
            os.close(fd)
            witness.unlink()
admission(claim)
space = os.statvfs(root / "data")
result["filesystem_space"] = {"device": c["storage"]["state"]["data"]["directory"]["device"], "block_bytes": space.f_frsize, "available_blocks": space.f_bavail, "available_bytes": space.f_frsize * space.f_bavail}
result.update(mode=c["mode"], guest_canaries_preserved=True, allocation_retained_until_guest_cleanup=True)
print(json.dumps(result, sort_keys=True))
"""


class GuestExhaustionError(GuestBootError):
    stage = "guest-exhaustion"


def configuration(guest: Guest) -> dict[str, Any]:
    if guest.observed is None:
        raise GuestExhaustionError("guest-not-verified")
    storage = guest.report.get("storage", {})
    if storage.get("status") != "passed" or storage.get("permissions_verified") is not True:
        raise GuestExhaustionError("storage-not-verified")
    state = storage["filesystems"]
    token = str(uuid.uuid4())
    return {
        "enrollment": guest.enrollment,
        "boot_id": guest.observed["boot_id"],
        "admin": guest.accounts[0],
        "actor": guest.observed["accounts"][guest.accounts[0]],
        "task": token,
        "target": "/run/fhs-"
        + uuid.UUID(guest.enrollment).hex
        + "/data/exhaustion-"
        + uuid.UUID(token).hex,
        "project_id": uuid.UUID(token).int % 2147483646 + 1,
        "capacity_bytes": CAPACITY,
        "chunk_bytes": CHUNK,
        "refusals": list(REFUSALS),
        "storage_program": STORAGE_PROGRAM,
        "worker": WORKER,
        "storage": {
            "enrollment": guest.enrollment,
            "boot_id": guest.observed["boot_id"],
            "admin": guest.accounts[0],
            "admin_identity": guest.observed["accounts"][guest.accounts[0]],
            "packages": PACKAGES,
            "devices": {r: state[r]["device"] for r in ("control", "data")},
            "uuids": {r: state[r]["uuid"] for r in ("control", "data")},
            "filesystems": {"control": "ext4", "data": "xfs"},
            "sizes": {r: state[r]["device"]["bytes"] for r in ("control", "data")},
            "state": state,
        },
    }


def invoke(guest: Guest, mode: str, c: dict[str, Any], deadline: Deadline) -> dict[str, Any]:
    c = {**c, "mode": mode, "seconds": min(current().seconds(60), deadline.remaining())}
    if c["seconds"] <= 0:
        raise GuestExhaustionError("exhaustion-deadline")
    raw = guest.guarded(
        ["/usr/bin/python3", "-I", "-S", "-c", PROGRAM, json.dumps(c, sort_keys=True)],
        guest.enrollment,
        c["boot_id"],
        deadline=deadline,
        nominal=75,
    )
    try:
        value = json.loads(raw)
    except (ValueError, RecursionError):
        raise GuestExhaustionError("invalid-exhaustion-observation") from None
    if not isinstance(value, dict):
        raise GuestExhaustionError("invalid-exhaustion-observation")
    return value


def require(value: Any, reason: str) -> None:
    if not value:
        raise GuestExhaustionError(reason)


def validate_identity(value: dict[str, Any], c: dict[str, Any]) -> None:
    identity = value.get("identity")
    if not isinstance(identity, dict):
        raise GuestExhaustionError("exhaustion-identity-mismatch")
    for key in ("enrollment", "boot_id", "task", "target", "project_id"):
        require(
            type(identity.get(key)) is type(c[key]) and identity[key] == c[key],
            "exhaustion-identity-mismatch",
        )
    d = identity.get("directory")
    if not isinstance(d, dict) or set(d) != {"device", "inode", "uid", "gid", "mode"}:
        raise GuestExhaustionError("exhaustion-directory-mismatch")
    require(
        all(type(d[k]) is int and d[k] > 0 for k in ("device", "inode")),
        "exhaustion-directory-mismatch",
    )
    for key in ("uid", "gid"):
        require(type(d[key]) is int and d[key] == c["actor"][key], "exhaustion-directory-mismatch")
    require(
        type(d["mode"]) is int
        and d["mode"] == 0o700
        and d["device"] == c["storage"]["state"]["data"]["directory"]["device"],
        "exhaustion-directory-mismatch",
    )


def validate_quota(value: Any, c: dict[str, Any]) -> None:
    require(isinstance(value, dict) and value.get("present") is True, "exhaustion-quota-mismatch")
    expected = {
        "project_id": c["project_id"],
        "hard_bytes": CAPACITY,
        "soft_bytes": 0,
        "inode_hard": 0,
        "inode_soft": 0,
    }
    for key, want in expected.items():
        require(type(value.get(key)) is int and value[key] == want, "exhaustion-quota-mismatch")
    require(
        type(value.get("used_bytes")) is int
        and 0 <= value["used_bytes"] <= CAPACITY
        and type(value.get("inodes")) is int
        and value["inodes"] >= 1,
        "exhaustion-quota-mismatch",
    )


def validate_allocation(value: Any, c: dict[str, Any], mode: str) -> None:
    require(
        isinstance(value, dict) and value.get("mode") == mode and value.get("actor") == c["actor"],
        "exhaustion-worker-mismatch",
    )
    require(
        value.get("supplementary_groups") == []
        and type(value.get("effective_capabilities")) is int
        and value["effective_capabilities"] == 0,
        "exhaustion-worker-mismatch",
    )
    for key in ("pid", "inode", "size_after", "allocated_bytes"):
        require(type(value.get(key)) is int and value[key] > 0, "exhaustion-allocation-mismatch")
    require(
        value["size_after"] <= CAPACITY
        and value["allocated_bytes"] <= CAPACITY
        and value.get("project_id") == c["project_id"]
        and value.get("device") == c["identity"]["directory"]["device"],
        "exhaustion-allocation-mismatch",
    )
    failure = value.get("failure")
    if mode == "reuse":
        require(
            type(value.get("size_before")) is int
            and value["size_before"] == 0
            and value["size_after"] == CHUNK
            and value["allocated_bytes"] >= CHUNK
            and failure is None,
            "fresh-allocation-reuse-not-observed",
        )
    else:
        failure = value.get("failure")
        # Linux XFS project-quota reservation failures return ENOSPC. Preserve that
        # actual errno; quota usage and a matching outside allocation establish scope.
        require(
            isinstance(failure, dict)
            and failure
            == {
                "errno": 28,
                "name": "ENOSPC",
                "syscall": "posix_fallocate",
                "offset": value["size_after"],
                "length": CHUNK,
            },
            "expected-project-quota-enospc-not-observed",
        )
    image = value.get("executable")
    require(
        isinstance(image, dict)
        and image.get("path") == "/usr/bin/python3.12"
        and isinstance(image.get("sha256"), str)
        and len(image["sha256"]) == 64
        and all(ch in "0123456789abcdef" for ch in image["sha256"]),
        "exhaustion-executable-mismatch",
    )


def validate_common(value: dict[str, Any], c: dict[str, Any], mode: str) -> None:
    require(
        value.get("mode") == mode
        and value.get("guest_canaries_preserved") is True
        and value.get("allocation_retained_until_guest_cleanup") is True,
        "exhaustion-outcome-mismatch",
    )
    validate_identity(value, c)
    validate_quota(value.get("quota"), c)
    space = value.get("filesystem_space")
    if not isinstance(space, dict):
        raise GuestExhaustionError("filesystem-space-observation-missing")
    for key in ("device", "block_bytes", "available_blocks", "available_bytes"):
        require(
            type(space.get(key)) is int and space[key] > 0, "filesystem-space-observation-missing"
        )
    require(
        space["device"] == c["storage"]["state"]["data"]["directory"]["device"]
        and space["available_bytes"] == space["block_bytes"] * space["available_blocks"]
        and space["available_bytes"] > CHUNK,
        "whole-filesystem-space-unavailable",
    )


def validate_rejection(value: dict[str, Any], c: dict[str, Any], mode: str) -> None:
    validate_allocation(value.get("allocation"), c, mode)
    require(
        value["quota"]["used_bytes"] >= value["allocation"]["allocated_bytes"] > 0
        and value["quota"]["used_bytes"] + value["allocation"]["failure"]["length"]
        > value["quota"]["hard_bytes"],
        "project-quota-bound-not-reached",
    )


def validate_outside(value: Any, c: dict[str, Any]) -> None:
    validate_witness(value, c["identity"]["directory"]["device"], c["actor"]["uid"], CHUNK)
    for key, expected in (
        ("gid", c["actor"]["gid"]),
        ("project_id", 0),
        ("offset", 0),
        ("length", CHUNK),
    ):
        require(
            type(value.get(key)) is int and value[key] == expected,
            "matching-outside-allocation-missing",
        )
    require(
        value.get("syscall") == "posix_fallocate"
        and type(value.get("allocated_bytes")) is int
        and value["allocated_bytes"] >= CHUNK,
        "matching-outside-allocation-missing",
    )


def validate_witness(value: Any, device: int, uid: int, length: int) -> None:
    require(
        isinstance(value, dict) and value.get("fsynced") is True,
        "exhaustion-independent-write-missing",
    )
    for key, want in (("device", device), ("uid", uid), ("bytes", length)):
        require(
            type(value.get(key)) is int and value[key] == want,
            "exhaustion-independent-write-missing",
        )
    require(
        type(value.get("inode")) is int and value["inode"] > 0,
        "exhaustion-independent-write-missing",
    )


def qualify_exhaustion(
    guest: Guest,
    progress: Callable[[str], AbstractContextManager[None]],
    temporary: Path,
    report: dict[str, Any],
) -> None:
    metrics = RunStats()
    report.update(
        status="failed",
        scope="disposable-guest-project-quota-exhaustion-only",
        mechanism="xfs-project-quota-hard-block-limit",
        capacity_bytes=CAPACITY,
        chunk_bytes=CHUNK,
        resources_destroyed_with_guest=False,
        unrelated_host_canary_preserved=False,
    )
    try:
        c = configuration(guest)
        report.update(enrollment=c["enrollment"], boot_id=c["boot_id"], task=c["task"])
        deadline = Deadline.after(240)
        with tempfile.TemporaryDirectory(
            prefix="fishhat-exhaustion-canary-", dir=temporary
        ) as name:
            canary = Path(name) / "unrelated"
            content = uuid.uuid4().bytes
            canary.write_bytes(content)
            before = canary.lstat()
            try:
                with progress("exhaustion-prepare"):
                    prepared = invoke(guest, "prepare", c, deadline)
                    report["prepare"] = prepared
                    validate_common(prepared, c, "prepare")
                    require(
                        prepared.get("refusals_verified") == list(REFUSALS)
                        and prepared["quota"]["used_bytes"] == 0,
                        "exhaustion-admission-mismatch",
                    )
                    c["identity"] = prepared["identity"]
                with progress("exhaustion-fill"):
                    filled = invoke(guest, "fill", c, deadline)
                    report["fill"] = filled
                    validate_common(filled, c, "fill")
                    require(filled["identity"] == c["identity"], "exhaustion-identity-changed")
                    validate_rejection(filled, c, "fill")
                    c["allocation"] = filled["allocation"]
                with progress("exhaustion-independent-observer"):
                    observed = invoke(guest, "observe", c, deadline)
                    report["observe"] = observed
                    validate_common(observed, c, "observe")
                    validate_rejection(observed, c, "probe")
                    require(
                        observed["identity"] == c["identity"]
                        and observed["quota"] == filled["quota"],
                        "exhaustion-identity-changed",
                    )
                    for key in ("inode", "device", "executable", "size_after", "allocated_bytes"):
                        require(
                            observed["allocation"][key] == filled["allocation"][key],
                            "exhaustion-allocation-changed",
                        )
                    require(
                        observed["allocation"]["pid"] != filled["allocation"]["pid"],
                        "independent-exhaustion-observer-missing",
                    )
                    validate_witness(
                        observed.get("control_write"),
                        c["storage"]["state"]["control"]["directory"]["device"],
                        0,
                        17,
                    )
                    validate_outside(observed["allocation"].get("outside_write"), c)
            finally:
                after = canary.lstat()
                report["unrelated_host_canary_preserved"] = (
                    before.st_dev,
                    before.st_ino,
                    before.st_mode,
                ) == (after.st_dev, after.st_ino, after.st_mode) and canary.read_bytes() == content
                require(report["unrelated_host_canary_preserved"], "unrelated-host-canary-changed")
        report["status"] = "passed"
    except OSError:
        raise GuestExhaustionError("exhaustion-observation-unavailable") from None
    finally:
        report["statistics"] = metrics.finish()
        if not valid_stats(report["statistics"]):
            raise ValueError("invalid required guest exhaustion statistics")


def validate_release(
    value: dict[str, Any], c: dict[str, Any], mode: str, *, already_empty: bool
) -> None:
    validate_common(value, c, mode)
    require(
        value["identity"] == c["identity"] and value.get("already_empty") is already_empty,
        "release-observation-mismatch",
    )
    for name in ("allocation_before", "allocation_after"):
        snapshot = value.get(name)
        if not isinstance(snapshot, dict):
            raise GuestExhaustionError("release-allocation-identity-mismatch")
        expected = {
            "device": c["identity"]["directory"]["device"],
            "inode": c["allocation"]["inode"],
            "uid": c["actor"]["uid"],
            "gid": c["actor"]["gid"],
            "mode": 0o600,
            "project_id": c["project_id"],
        }
        for key, want in expected.items():
            require(
                type(snapshot.get(key)) is int and snapshot[key] == want,
                "release-allocation-identity-mismatch",
            )
        for key in ("size", "allocated_bytes"):
            require(
                type(snapshot.get(key)) is int and snapshot[key] >= 0,
                "release-allocation-state-mismatch",
            )
    mutated = mode == "release" and not already_empty
    require(
        value.get("release_effect")
        == {
            "syscall": "ftruncate" if mutated else None,
            "length": 0 if mutated else None,
            "fsynced": mutated,
        }
        and type(value["release_effect"]["fsynced"]) is bool,
        "release-effect-observation-mismatch",
    )
    before, after = value["allocation_before"], value["allocation_after"]
    require(
        after["size"] == 0 and after["allocated_bytes"] <= before["allocated_bytes"],
        "release-capacity-not-observed",
    )
    if already_empty:
        require(before == after and before["size"] == 0, "release-retry-changed-allocation")
    else:
        require(
            before["size"] == c["allocation"]["size_after"]
            and before["allocated_bytes"] == c["allocation"]["allocated_bytes"]
            and after["allocated_bytes"] + CHUNK <= before["allocated_bytes"],
            "release-capacity-not-observed",
        )
    require(
        value["quota"]["used_bytes"] <= value["quota_before"]["used_bytes"]
        and value["quota"]["used_bytes"] + CHUNK <= CAPACITY,
        "release-capacity-not-observed",
    )


def release_configuration(guest: Guest) -> dict[str, Any]:
    c = configuration(guest)
    source = guest.report.get("exhaustion", {})
    require(
        source.get("status") == "passed"
        and source.get("enrollment") == c["enrollment"]
        and source.get("boot_id") == c["boot_id"],
        "exhaustion-not-verified",
    )
    c["identity"] = source["prepare"]["identity"]
    c["allocation"] = source["fill"]["allocation"]
    for name in ("task", "target", "project_id"):
        c[name] = c["identity"][name]
    validate_identity({"identity": c["identity"]}, c)
    validate_allocation(c["allocation"], c, "fill")
    return c


def qualify_release_reuse(
    guest: Guest,
    progress: Callable[[str], AbstractContextManager[None]],
    temporary: Path,
    report: dict[str, Any],
) -> None:
    metrics = RunStats()
    report.update(
        status="failed",
        scope="disposable-guest-known-allocation-release-reuse-only",
        resources_destroyed_with_guest=False,
        per_allocation_destruction_qualified=False,
        unrelated_host_canary_preserved=False,
        cases=[],
    )
    try:
        c = release_configuration(guest)
        report.update(
            enrollment=c["enrollment"], boot_id=c["boot_id"], task=c["task"], identity=c["identity"]
        )
        deadline = Deadline.after(240)
        with tempfile.TemporaryDirectory(prefix="fishhat-release-canary-", dir=temporary) as name:
            canary = Path(name) / "unrelated"
            contents = uuid.uuid4().bytes
            canary.write_bytes(contents)
            before = canary.lstat()
            try:
                phases = (
                    ("release", "release", False),
                    ("independent-release", "inspect-release", True),
                    ("repeat-release", "release", True),
                    ("fresh-reuse", "reuse", False),
                    ("final-release", "release", False),
                    ("final-observer", "inspect-release", True),
                )
                for scenario, mode, empty in phases:
                    with progress("allocation-" + scenario):
                        case: dict[str, Any] = {"scenario": scenario, "status": "failed"}
                        report["cases"].append(case)
                        observations = RunStats()
                        try:
                            value = invoke(guest, mode, c, deadline)
                            case["observation"] = value
                            if mode == "reuse":
                                validate_common(value, c, mode)
                                validate_allocation(value.get("allocation"), c, mode)
                                require(
                                    value["identity"] == c["identity"]
                                    and value["allocation"]["inode"] == c["allocation"]["inode"]
                                    and value["allocation"]["executable"]
                                    == c["allocation"]["executable"]
                                    and value["allocation"]["pid"] != c["allocation"]["pid"],
                                    "reuse-allocation-identity-mismatch",
                                )
                                require(
                                    value["quota"]["used_bytes"]
                                    >= value["allocation"]["allocated_bytes"]
                                    >= CHUNK,
                                    "reuse-quota-observation-mismatch",
                                )
                                c["allocation"] = value["allocation"]
                            else:
                                validate_release(value, c, mode, already_empty=empty)
                            case["status"] = "passed"
                        finally:
                            case["statistics"] = observations.finish()
                            if not valid_stats(case["statistics"]):
                                raise ValueError(
                                    "invalid required allocation release case statistics"
                                )
            finally:
                after = canary.lstat()
                report["unrelated_host_canary_preserved"] = (
                    before.st_dev,
                    before.st_ino,
                    before.st_mode,
                ) == (after.st_dev, after.st_ino, after.st_mode) and canary.read_bytes() == contents
                require(report["unrelated_host_canary_preserved"], "unrelated-host-canary-changed")
        report["status"] = "passed"
    except OSError:
        raise GuestExhaustionError("release-observation-unavailable") from None
    finally:
        report["statistics"] = metrics.finish()
        if not valid_stats(report["statistics"]):
            raise ValueError("invalid required allocation release statistics")
