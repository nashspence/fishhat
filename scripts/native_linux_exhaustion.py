"""Observe real quota exhaustion only in an enrolled disposable guest allocation."""

from __future__ import annotations

import json
import tempfile
import uuid
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from scripts.native_linux_guest import Guest, GuestBootError, command_failed
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

CLEANUP_REFUSALS = (
    "foreign-enrollment",
    "stale-boot",
    "foreign-project",
    "stale-directory",
    "foreign-actor",
    "mounted-target",
    "replaced-allocation",
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
require(os.geteuid() == 0 and c["mode"] in ("prepare", "fill", "observe", "release", "inspect-release", "reuse", "cleanup", "inspect-cleanup", "prepare-partial", "observe-partial", "cleanup-partial"))
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
    elif c["mode"] not in ("prepare", "prepare-partial", "observe-partial", "cleanup-partial"):
        if c["mode"] not in ("cleanup", "inspect-cleanup") or target.exists() or target.is_symlink():
            require(directory(target) == c["identity"]["directory"] and not target.is_mount())
    return observed
claim = {k: c["storage"][k] for k in ("enrollment", "boot_id", "state", "devices", "uuids")}
claim["target"] = str(target)
admission(claim, fresh=c["mode"] in ("prepare", "prepare-partial"))
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
def empty_quota(value):
    return all(value[name] == 0 for name in ("hard_bytes", "soft_bytes", "used_bytes", "inodes", "inode_hard", "inode_soft"))
def descriptor_directory(fd):
    v = os.fstat(fd)
    require(stat.S_ISDIR(v.st_mode))
    return {"device": v.st_dev, "inode": v.st_ino, "uid": v.st_uid, "gid": v.st_gid, "mode": stat.S_IMODE(v.st_mode)}
def cleanup_preflight(identity, allocation):
    require(identity == c["identity"] and allocation == c["allocation"])
    check_identity()
    require(not target.is_mount())
    mounts = pathlib.Path("/proc/self/mountinfo").read_text().splitlines()
    require(not any(row.split()[4] in (str(target), str(target / "allocation")) for row in mounts))
    descriptor = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        require(descriptor_directory(descriptor) == identity["directory"])
        require(os.listdir(descriptor) == ["allocation"])
        fd = os.open("allocation", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        try:
            value = allocation_snapshot(fd)
            require(value["size"] == value["allocated_bytes"] == 0)
            q = quota()
            require(q["used_bytes"] == 0 and q["inodes"] == 2)
            require(directory(target) == identity["directory"])
            return value, q
        finally:
            os.close(fd)
    finally:
        os.close(descriptor)
def cleanup_challenges():
    refusals = []
    for name in c["cleanup_refusals"]:
        identity, allocation = copy.deepcopy(c["identity"]), copy.deepcopy(c["allocation"])
        if name in ("foreign-enrollment", "stale-boot"):
            identity["enrollment" if name == "foreign-enrollment" else "boot_id"] = str(uuid.uuid4())
        elif name == "foreign-project":
            identity["project_id"] += 1
        elif name == "stale-directory":
            identity["directory"]["inode"] += 1
        elif name == "foreign-actor":
            identity["directory"]["uid"] += 1
        elif name == "mounted-target":
            identity["target"] = str(root / "data")
        else:
            allocation["inode"] += 1
        try:
            cleanup_preflight(identity, allocation)
        except ValueError:
            cleanup_preflight(c["identity"], c["allocation"])
            refusals.append(name)
        else:
            raise ValueError("foreign-cleanup-claim-accepted")
    return refusals
def cleanup_allocation():
    identity = c["identity"]
    require(all(identity[k] == c[k] for k in ("enrollment", "boot_id", "task", "project_id", "target")))
    effects = {"unlink": False, "project_reset": False, "limit_reset": False, "rmdir": False}
    result = {"identity": identity, "allocation_before": None, "quota_before": quota(), "cleanup_effects": effects, "unlinked_allocation_links": None, "removed_directory_links": None, "refusals_verified": []}
    if not target.exists() and not target.is_symlink():
        require(empty_quota(result["quota_before"]))
        result["already_absent"] = True
    else:
        require(c["mode"] == "cleanup")
        result["refusals_verified"] = cleanup_challenges()
        value, before = cleanup_preflight(identity, c["allocation"])
        result.update(allocation_before=value, quota_before=before, already_absent=False)
        # The disposable fixture is serial and its allocation worker has exited.
        # Pinned descriptors here do not qualify concurrent product reclamation.
        parent = os.open(root / "data", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptor = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            require(descriptor_directory(parent) == c["storage"]["state"]["data"]["directory"])
            require(descriptor_directory(descriptor) == identity["directory"])
            require(os.listdir(descriptor) == ["allocation"])
            fd = os.open("allocation", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                require(allocation_snapshot(fd) == value)
                os.unlink("allocation", dir_fd=descriptor)
                effects["unlink"] = True
                os.fsync(descriptor)
                result["unlinked_allocation_links"] = os.fstat(fd).st_nlink
                require(result["unlinked_allocation_links"] == 0)
            finally:
                os.close(fd)
            require(os.listdir(descriptor) == [])
            attributes_before = list(struct.unpack("=5I8s", fcntl.ioctl(descriptor, 0x801c581f, bytes(28))))
            require(attributes_before[3] == c["project_id"] and attributes_before[0] & 0x200)
            attributes_before[0] &= ~0x200
            attributes_before[3] = 0
            # Linux x86_64 fs.h FS_IOC_FSSETXATTR, applied to the pinned directory.
            fcntl.ioctl(descriptor, 0x401c5820, struct.pack("=5I8s", *attributes_before))
            effects["project_reset"] = True
            attributes_after = struct.unpack("=5I8s", fcntl.ioctl(descriptor, 0x801c581f, bytes(28)))
            require(attributes_after[3] == 0 and not attributes_after[0] & 0x200)
            os.fsync(descriptor)
            base = ["/usr/sbin/xfs_quota", "-x", "-D", "/dev/null", "-P", "/dev/null"]
            command([*base, "-c", "limit -p bhard=0 " + str(c["project_id"]), str(root / "data")])
            effects["limit_reset"] = True
            require(directory(target) == identity["directory"] and not target.is_mount())
            os.rmdir(target.name, dir_fd=parent)
            effects["rmdir"] = True
            result["removed_directory_links"] = os.fstat(descriptor).st_nlink
            require(result["removed_directory_links"] == 0)
            os.fsync(parent)
        finally:
            os.close(descriptor)
            os.close(parent)
    value = quota()
    while not empty_quota(value):
        remaining = end - time.monotonic()
        require(remaining > 0)
        time.sleep(min(0.05, remaining))
        value = quota()
    require(not target.exists() and not target.is_symlink())
    result.update(quota=value, target_absent=True, allocation_absent=True, observer={"pid": os.getpid(), "executable": {"path": os.readlink("/proc/self/exe"), "sha256": hashlib.sha256(pathlib.Path("/proc/self/exe").read_bytes()).hexdigest()}})
    return result
def partial_image():
    return {"path": os.readlink("/proc/self/exe"), "sha256": hashlib.sha256(pathlib.Path("/proc/self/exe").read_bytes()).hexdigest()}
def process_ticks(pid):
    try:
        value = pathlib.Path("/proc/" + str(pid) + "/stat").read_text()
    except FileNotFoundError:
        return None
    return int(value.rsplit(")", 1)[1].split()[19])
def partial_process():
    value = {"pid": os.getpid(), "start_ticks": process_ticks(os.getpid()), "executable": partial_image()}
    require(type(value["start_ticks"]) is int and value["start_ticks"] > 0)
    require(value["executable"] == c["partial_image"])
    return value
def partial_handle(fd):
    # Read-only Linux file_handle query; XFS handles include inode generation.
    lib = ctypes.CDLL(None, use_errno=True)
    call = lib.name_to_handle_at
    call.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_int]
    call.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(136)
    struct.pack_into("=II", buffer, 0, 128, 0)
    mount = ctypes.c_int()
    require(call(fd, b"", buffer, ctypes.byref(mount), 0x1000) == 0)
    size, kind = struct.unpack_from("=Ii", buffer.raw)
    require(0 < size <= 128 and 0 < kind < 255 and mount.value > 0)
    return {"mount_id": mount.value, "type": kind, "bytes": buffer.raw[8:8 + size].hex()}
def record_path():
    return root / "control" / ("quota-custody-" + uuid.UUID(c["task"]).hex + ".json")
def partial_expected():
    return {"kind": "disposable-guest-quota-custody", "enrollment": c["enrollment"], "boot_id": c["boot_id"], "task": c["task"], "target": str(target), "project_id": c["project_id"], "actor": c["actor"], "capacity_bytes": c["capacity_bytes"], "storage": c["storage"]["state"]}
def record_metadata(v):
    require(stat.S_ISREG(v.st_mode) and v.st_nlink == 1 and v.st_uid == v.st_gid == 0 and stat.S_IMODE(v.st_mode) == 0o600)
    require(v.st_dev == c["storage"]["state"]["control"]["directory"]["device"])
    return {"device": v.st_dev, "inode": v.st_ino, "uid": v.st_uid, "gid": v.st_gid, "mode": stat.S_IMODE(v.st_mode), "links": v.st_nlink, "size": v.st_size, "mtime_ns": v.st_mtime_ns, "ctime_ns": v.st_ctime_ns}
def write_record(value):
    content = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    require(0 < len(content) <= 32768)
    fd = os.open(record_path(), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        position = 0
        while position < len(content):
            size = os.write(fd, content[position:])
            require(size > 0)
            position += size
        os.fsync(fd)
        require(record_metadata(os.fstat(fd))["size"] == len(content))
    finally:
        os.close(fd)
    fd = os.open(root / "control", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        require(descriptor_directory(fd) == c["storage"]["state"]["control"]["directory"])
        os.fsync(fd)
    finally:
        os.close(fd)
def read_record():
    fd = os.open(record_path(), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = record_metadata(os.fstat(fd))
        require(0 < before["size"] <= 32768)
        content = bytearray()
        while len(content) <= 32768:
            block = os.read(fd, 32769 - len(content))
            if not block:
                break
            content.extend(block)
        require(0 < len(content) <= 32768 and len(content) == before["size"])
        require(record_metadata(os.fstat(fd)) == before)
    finally:
        os.close(fd)
    value = json.loads(content)
    require(content == json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    expected = partial_expected()
    require(set(value) == {*expected, "directory", "directory_handle", "origin"})
    require(all(value[k] == v for k, v in expected.items()))
    d = value["directory"]
    require(set(d) == {"device", "inode", "uid", "gid", "mode"})
    require(d["device"] == c["storage"]["state"]["data"]["directory"]["device"] and type(d["inode"]) is int and d["inode"] > 0)
    require(d["uid"] == d["gid"] == 0 and d["mode"] == 0o700)
    origin = value["origin"]
    require(set(origin) == {"pid", "start_ticks", "executable"})
    require(all(type(origin[k]) is int and origin[k] > 0 for k in ("pid", "start_ticks")) and origin["executable"] == c["partial_image"])
    before["sha256"] = hashlib.sha256(content).hexdigest()
    if "custody" in c or "identity" in c:
        require(c.get("custody") == before and c.get("identity") == value)
    return value, before
def partial_mount_guard():
    paths = [row.split()[4] for row in pathlib.Path("/proc/self/mountinfo").read_text().splitlines()]
    require(not any(p == str(record_path()) or p == str(target) or p.startswith(str(target) + "/") for p in paths))
def partial_observation():
    identity, custody = read_record()
    observer = partial_process()
    exited = process_ticks(identity["origin"]["pid"]) != identity["origin"]["start_ticks"]
    require(c["mode"] == "prepare-partial" or exited)
    partial_mount_guard()
    require(not target.is_symlink())
    q = quota()
    require(q["soft_bytes"] == q["used_bytes"] == q["inode_hard"] == q["inode_soft"] == 0 and q["hard_bytes"] in (0, c["capacity_bytes"]))
    current_directory, attrs = None, None
    if not target.exists():
        require(empty_quota(q))
        state = "absent"
    else:
        require(not target.is_mount())
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            current_directory = descriptor_directory(fd)
            require(current_directory == directory(target) and os.listdir(fd) == [])
            require(partial_handle(fd) == identity["directory_handle"])
            require(all(current_directory[k] == identity["directory"][k] for k in ("device", "inode", "mode")))
            owner = {k: current_directory[k] for k in ("uid", "gid")}
            require(owner in ({"uid": 0, "gid": 0}, c["actor"]))
            a = struct.unpack("=5I8s", fcntl.ioctl(fd, 0x801c581f, bytes(28)))
            attrs = {"project_id": a[3], "inherit": bool(a[0] & 0x200)}
        finally:
            os.close(fd)
        pair = (attrs["project_id"], attrs["inherit"])
        require(pair in ((0, False), (c["project_id"], True)))
        require(q["inodes"] == (1 if attrs["project_id"] else 0))
        if attrs["project_id"]:
            require(q["present"])
            if owner == {"uid": 0, "gid": 0}:
                state = "limit" if q["hard_bytes"] else "project"
            else:
                require(q["hard_bytes"] == c["capacity_bytes"])
                state = "ready"
        elif q["hard_bytes"]:
            state = "cleanup-project-reset"
        else:
            state = "directory" if owner == {"uid": 0, "gid": 0} else "cleanup-limit-reset"
    return {"identity": identity, "custody": custody, "state": state, "directory": current_directory, "attributes": attrs, "quota": q, "target_absent": state == "absent", "origin_exited": exited, "observer": observer, "mutation_effects": {"project_reset": False, "limit_reset": False, "rmdir": False}, "refusals_verified": [], "custody_retained_until_guest_cleanup": True, "directory_retained_until_guest_cleanup": state != "absent", "allocation_retained_until_guest_cleanup": False, "guest_canaries_preserved": True}
def partial_checkpoint(name):
    if c.get("partial_exit_after") == name:
        sys.exit(42)
def prepare_partial():
    require(c.get("partial_exit_after") in (None, "directory", "project", "limit"))
    require(not record_path().exists() and not record_path().is_symlink() and empty_quota(quota()))
    target.mkdir(mode=0o700)
    d = directory(target)
    require(d["uid"] == d["gid"] == 0 and d["mode"] == 0o700)
    fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        require(descriptor_directory(fd) == d)
        handle = partial_handle(fd)
    finally:
        os.close(fd)
    write_record({**partial_expected(), "directory": d, "directory_handle": handle, "origin": partial_process()})
    require(partial_observation()["state"] == "directory")
    partial_checkpoint("directory")
    base = ["/usr/sbin/xfs_quota", "-x", "-D", "/dev/null", "-P", "/dev/null"]
    command([*base, "-c", "project -s -d 0 -p " + str(target) + " " + str(c["project_id"]), str(root / "data")])
    require(partial_observation()["state"] == "project")
    partial_checkpoint("project")
    command([*base, "-c", "limit -p bhard=" + str(c["capacity_bytes"]) + " " + str(c["project_id"]), str(root / "data")])
    require(partial_observation()["state"] == "limit")
    partial_checkpoint("limit")
    os.chown(target, admin.pw_uid, admin.pw_gid)
    value = partial_observation()
    require(value["state"] == "ready")
    return value
def admit_partial(custody, identity):
    actual, observed = read_record()
    require(custody == observed and identity == actual)
    return partial_observation()
def partial_challenges():
    refused = []
    for name in ("foreign-enrollment", "stale-boot", "foreign-project", "stale-directory", "foreign-actor", "mounted-target", "replaced-custody"):
        custody, identity = copy.deepcopy(c["custody"]), copy.deepcopy(c["identity"])
        if name in ("foreign-enrollment", "stale-boot"):
            identity["enrollment" if name == "foreign-enrollment" else "boot_id"] = str(uuid.uuid4())
        elif name == "foreign-project":
            identity["project_id"] += 1
        elif name == "stale-directory":
            identity["directory"]["inode"] += 1
        elif name == "foreign-actor":
            identity["actor"]["uid"] += 1
        elif name == "mounted-target":
            identity["target"] = str(root / "data")
        else:
            custody["inode"] += 1
        try:
            admit_partial(custody, identity)
        except ValueError:
            admit_partial(c["custody"], c["identity"])
            refused.append(name)
        else:
            raise ValueError("foreign-partial-cleanup-claim-accepted")
    return refused
def cleanup_partial():
    require(c.get("partial_exit_after") in (None, "cleanup-project-reset", "cleanup-limit-reset", "cleanup-rmdir"))
    require("custody" in c and "identity" in c)
    before = admit_partial(c["custody"], c["identity"])
    effects = {"project_reset": False, "limit_reset": False, "rmdir": False}
    refused = []
    removed_links = None
    if before["state"] != "absent":
        refused = partial_challenges()
        parent = os.open(root / "data", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            require(descriptor_directory(parent) == c["storage"]["state"]["data"]["directory"])
            fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                require(descriptor_directory(fd) == before["directory"] and os.listdir(fd) == []
                        and partial_handle(fd) == c["identity"]["directory_handle"])
                if before["attributes"]["project_id"]:
                    a = list(struct.unpack("=5I8s", fcntl.ioctl(fd, 0x801c581f, bytes(28))))
                    require(a[3] == c["project_id"] and a[0] & 0x200)
                    a[0] &= ~0x200
                    a[3] = 0
                    fcntl.ioctl(fd, 0x401c5820, struct.pack("=5I8s", *a))
                    os.fsync(fd)
                    a = struct.unpack("=5I8s", fcntl.ioctl(fd, 0x801c581f, bytes(28)))
                    require(a[3] == 0 and not a[0] & 0x200)
                    effects["project_reset"] = True
                    partial_checkpoint("cleanup-project-reset")
                if before["quota"]["hard_bytes"]:
                    base = ["/usr/sbin/xfs_quota", "-x", "-D", "/dev/null", "-P", "/dev/null"]
                    command([*base, "-c", "limit -p bhard=0 " + str(c["project_id"]), str(root / "data")])
                    require(empty_quota(quota()))
                    effects["limit_reset"] = True
                    partial_checkpoint("cleanup-limit-reset")
                partial_mount_guard()
                require(directory(target) == before["directory"] and not target.is_mount())
                os.rmdir(target.name, dir_fd=parent)
                removed_links = os.fstat(fd).st_nlink
                require(removed_links == 0)
                os.fsync(parent)
                effects["rmdir"] = True
                partial_checkpoint("cleanup-rmdir")
            finally:
                os.close(fd)
        finally:
            os.close(parent)
    result = partial_observation()
    require(result["state"] == "absent")
    result.update(before=before, mutation_effects=effects, removed_directory_links=removed_links, refusals_verified=refused)
    return result
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
elif c["mode"] in ("prepare-partial", "observe-partial", "cleanup-partial"):
    result = prepare_partial() if c["mode"] == "prepare-partial" else cleanup_partial() if c["mode"] == "cleanup-partial" else partial_observation()
elif c["mode"] in ("cleanup", "inspect-cleanup"):
    result = cleanup_allocation()
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
result.update(mode=c["mode"], guest_canaries_preserved=True)
result.setdefault("allocation_retained_until_guest_cleanup", c["mode"] not in ("cleanup", "inspect-cleanup"))
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
        "cleanup_refusals": list(CLEANUP_REFUSALS),
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


class CleanupObserverInterrupted(Exception):
    """An injected controller exception before admitting a completed cleanup reply."""


def cleanup_configuration(guest: Guest) -> dict[str, Any]:
    c = release_configuration(guest)
    source = guest.report.get("allocation_release_reuse", {})
    require(
        source.get("status") == "passed"
        and source.get("identity") == c["identity"]
        and len(source.get("cases", [])) == 6,
        "allocation-release-not-verified",
    )
    last = source["cases"][-1]
    require(
        last.get("scenario") == "final-observer" and last.get("status") == "passed",
        "allocation-release-not-verified",
    )
    validate_release(last["observation"], c, "inspect-release", already_empty=True)
    return c


def validate_cleanup(value: dict[str, Any], c: dict[str, Any], *, mutated: bool) -> None:
    require(
        value.get("mode") == ("cleanup" if mutated else "inspect-cleanup")
        and value.get("identity") == c["identity"]
        and value.get("guest_canaries_preserved") is True
        and value.get("allocation_retained_until_guest_cleanup") is False
        and value.get("already_absent") is (not mutated)
        and value.get("target_absent") is value.get("allocation_absent") is True,
        "cleanup-observation-mismatch",
    )
    validate_identity(value, c)
    expected = dict.fromkeys(("unlink", "project_reset", "limit_reset", "rmdir"), mutated)
    require(
        value.get("cleanup_effects") == expected
        and all(type(v) is bool for v in value["cleanup_effects"].values()),
        "cleanup-effect-mismatch",
    )
    for field in ("quota", "quota_before"):
        q = value.get(field)
        if not isinstance(q, dict):
            raise GuestExhaustionError("cleanup-quota-mismatch")
        require(type(q.get("present")) is bool, "cleanup-quota-mismatch")
        require(
            type(q.get("project_id")) is int and q["project_id"] == c["project_id"],
            "cleanup-quota-mismatch",
        )
        for name in (
            "hard_bytes",
            "soft_bytes",
            "used_bytes",
            "inodes",
            "inode_hard",
            "inode_soft",
        ):
            want = (
                CAPACITY
                if field == "quota_before" and mutated and name == "hard_bytes"
                else 2
                if field == "quota_before" and mutated and name == "inodes"
                else 0
            )
            require(type(q.get(name)) is int and q[name] == want, "cleanup-quota-mismatch")
    if mutated:
        before = value.get("allocation_before")
        if not isinstance(before, dict):
            raise GuestExhaustionError("cleanup-allocation-mismatch")
        for name, want in {
            "device": c["identity"]["directory"]["device"],
            "inode": c["allocation"]["inode"],
            "uid": c["actor"]["uid"],
            "gid": c["actor"]["gid"],
            "mode": 0o600,
            "project_id": c["project_id"],
            "size": 0,
            "allocated_bytes": 0,
        }.items():
            require(
                type(before.get(name)) is int and before[name] == want,
                "cleanup-allocation-mismatch",
            )
        require(
            type(value.get("unlinked_allocation_links")) is int
            and value["unlinked_allocation_links"] == 0
            and type(value.get("removed_directory_links")) is int
            and value["removed_directory_links"] == 0
            and value.get("refusals_verified") == list(CLEANUP_REFUSALS),
            "cleanup-destruction-not-observed",
        )
    else:
        require(
            value.get("allocation_before")
            is value.get("unlinked_allocation_links")
            is value.get("removed_directory_links")
            is None
            and value.get("refusals_verified") == [],
            "cleanup-retry-had-effects",
        )
    observer = value.get("observer")
    require(
        isinstance(observer, dict)
        and type(observer.get("pid")) is int
        and observer["pid"] > 0
        and observer.get("executable") == c["allocation"]["executable"],
        "cleanup-observer-mismatch",
    )


def cleanup_case(
    guest: Guest,
    c: dict[str, Any],
    deadline: Deadline,
    report: dict[str, Any],
    scenario: str,
    mode: str,
    original: dict[str, Any] | None,
    observed_pids: set[int],
) -> dict[str, Any]:
    case: dict[str, Any] = {"scenario": scenario, "status": "failed"}
    report["cases"].append(case)
    metrics = RunStats()
    try:
        value = invoke(guest, mode, c, deadline)
        if scenario == "unadmitted-cleanup-reply":
            case.update(
                unadmitted_reply=value, mutation_reply_admitted=False, cleanup_outcome="unobserved"
            )
            try:
                raise CleanupObserverInterrupted()
            except CleanupObserverInterrupted:
                case["observer_interruption_kind"] = "controlled-exception-before-reply-admission"
        else:
            case["observation"] = value
            require(value.get("mode") == mode, "cleanup-observation-mismatch")
            # Retried cleanup against absence must be indistinguishable from a
            # read-only absence observer except for its explicitly recorded mode.
            check = {**value, "mode": "inspect-cleanup"} if mode == "cleanup" else value
            validate_cleanup(check, c, mutated=False)
            if scenario == "independent-absence":
                require(original is not None, "cleanup-reply-not-retained")
                assert original is not None
                validate_cleanup(original, c, mutated=True)
                observed_pids.add(original["observer"]["pid"])
            require(
                value["observer"]["pid"] not in observed_pids,
                "independent-cleanup-observer-missing",
            )
            observed_pids.add(value["observer"]["pid"])
            if scenario == "independent-absence":
                report.update(
                    cleanup_outcome="absent-observed-independently",
                    original_reply_validated_after_independent_observation=True,
                )
        case["status"] = "passed"
        return value
    finally:
        case["statistics"] = metrics.finish()
        if not valid_stats(case["statistics"]):
            case["status"] = "failed"
            raise ValueError("invalid required allocation cleanup case statistics")


def qualify_allocation_cleanup(
    guest: Guest,
    progress: Callable[[str], AbstractContextManager[None]],
    temporary: Path,
    report: dict[str, Any],
) -> None:
    metrics = RunStats()
    report.update(
        status="failed",
        scope="disposable-guest-known-allocation-destruction-only",
        resources_destroyed_with_guest=False,
        per_allocation_destruction_qualified=False,
        partial_setup_recovery_qualified=False,
        unrelated_host_canary_preserved=False,
        cleanup_outcome="unobserved",
        cases=[],
    )
    try:
        c = cleanup_configuration(guest)
        report.update(
            enrollment=c["enrollment"], boot_id=c["boot_id"], task=c["task"], identity=c["identity"]
        )
        deadline = Deadline.after(240)
        with tempfile.TemporaryDirectory(prefix="fishhat-cleanup-canary-", dir=temporary) as name:
            canary = Path(name) / "unrelated"
            contents = uuid.uuid4().bytes
            canary.write_bytes(contents)
            before = canary.lstat()
            try:
                observed_pids: set[int] = set()
                original = None
                for scenario, mode in (
                    ("unadmitted-cleanup-reply", "cleanup"),
                    ("independent-absence", "inspect-cleanup"),
                    ("repeat-cleanup", "cleanup"),
                    ("final-absence", "inspect-cleanup"),
                ):
                    with progress("allocation-" + scenario):
                        value = cleanup_case(
                            guest, c, deadline, report, scenario, mode, original, observed_pids
                        )
                        if original is None:
                            original = value
            finally:
                after = canary.lstat()
                report["unrelated_host_canary_preserved"] = (
                    before.st_dev,
                    before.st_ino,
                    before.st_mode,
                ) == (after.st_dev, after.st_ino, after.st_mode) and canary.read_bytes() == contents
                require(report["unrelated_host_canary_preserved"], "unrelated-host-canary-changed")
        report.update(status="passed", per_allocation_destruction_qualified=True)
    except OSError:
        raise GuestExhaustionError("cleanup-observation-unavailable") from None
    finally:
        report["statistics"] = metrics.finish()
        if not valid_stats(report["statistics"]):
            report.update(status="failed", per_allocation_destruction_qualified=False)
            raise ValueError("invalid required allocation cleanup statistics")


PARTIAL_SCENARIOS = (
    ("directory-interruption", "directory", None, False),
    ("project-interruption", "project", None, False),
    ("limit-interruption", "limit", None, False),
    ("unadmitted-prepare-reply", None, None, True),
    ("cleanup-project-interruption", None, "cleanup-project-reset", False),
    ("cleanup-limit-interruption", None, "cleanup-limit-reset", False),
    ("cleanup-remove-interruption", None, "cleanup-rmdir", False),
)
PARTIAL_REFUSALS = (
    "foreign-enrollment",
    "stale-boot",
    "foreign-project",
    "stale-directory",
    "foreign-actor",
    "mounted-target",
    "replaced-custody",
)


class PartialReplyNotAdmitted(Exception):
    """A controlled observer exception after preparation completed."""


def partial_configuration(guest: Guest) -> dict[str, Any]:
    c = configuration(guest)
    prior = guest.report.get("allocation_cleanup", {})
    require(
        prior.get("status") == "passed"
        and prior.get("per_allocation_destruction_qualified") is True
        and prior.get("enrollment") == c["enrollment"]
        and prior.get("boot_id") == c["boot_id"],
        "known-allocation-cleanup-not-verified",
    )
    c["partial_image"] = guest.report["exhaustion"]["fill"]["allocation"]["executable"]
    c["partial_exit_after"] = None
    return c


def partial_identity(value: dict[str, Any], c: dict[str, Any]) -> dict[str, Any]:
    identity = value.get("identity")
    if not isinstance(identity, dict):
        raise GuestExhaustionError("partial-custody-identity-mismatch")
    expected = {
        k: c[k]
        for k in (
            "enrollment",
            "boot_id",
            "task",
            "target",
            "project_id",
            "actor",
            "capacity_bytes",
        )
    }
    expected.update(kind="disposable-guest-quota-custody", storage=c["storage"]["state"])
    require(
        set(identity) == {*expected, "directory", "directory_handle", "origin"}
        and all(identity[k] == v for k, v in expected.items()),
        "partial-custody-identity-mismatch",
    )
    d = identity["directory"]
    require(
        isinstance(d, dict) and set(d) == {"device", "inode", "uid", "gid", "mode"},
        "partial-custody-directory-mismatch",
    )
    require(
        all(type(d[k]) is int for k in d)
        and d["inode"] > 0
        and d["device"] == c["storage"]["state"]["data"]["directory"]["device"]
        and d["uid"] == d["gid"] == 0
        and d["mode"] == 0o700,
        "partial-custody-directory-mismatch",
    )
    handle = identity.get("directory_handle")
    require(
        isinstance(handle, dict)
        and set(handle) == {"mount_id", "type", "bytes"}
        and type(handle["mount_id"]) is int
        and handle["mount_id"] > 0
        and type(handle["type"]) is int
        and 0 < handle["type"] < 255
        and isinstance(handle["bytes"], str)
        and 0 < len(handle["bytes"]) <= 256
        and len(handle["bytes"]) % 2 == 0
        and all(v in "0123456789abcdef" for v in handle["bytes"]),
        "partial-directory-handle-mismatch",
    )
    for name in ("origin", "observer"):
        proc = identity[name] if name == "origin" else value.get(name)
        require(
            isinstance(proc, dict)
            and set(proc) == {"pid", "start_ticks", "executable"}
            and all(type(proc[k]) is int and proc[k] > 0 for k in ("pid", "start_ticks"))
            and proc["executable"] == c["partial_image"],
            "partial-process-identity-mismatch",
        )
    custody = value.get("custody")
    if not isinstance(custody, dict):
        raise GuestExhaustionError("partial-custody-file-mismatch")
    require(
        set(custody)
        == {
            "device",
            "inode",
            "uid",
            "gid",
            "mode",
            "links",
            "size",
            "mtime_ns",
            "ctime_ns",
            "sha256",
        },
        "partial-custody-file-mismatch",
    )
    require(
        all(type(custody[k]) is int for k in custody if k != "sha256")
        and custody["device"] == c["storage"]["state"]["control"]["directory"]["device"]
        and custody["inode"] > 0
        and custody["uid"] == custody["gid"] == 0
        and custody["mode"] == 0o600
        and custody["links"] == 1
        and 0 < custody["size"] <= 32768
        and custody["mtime_ns"] >= 0
        and custody["ctime_ns"] >= 0,
        "partial-custody-file-mismatch",
    )
    digest = custody["sha256"]
    require(
        isinstance(digest, str)
        and len(digest) == 64
        and all(v in "0123456789abcdef" for v in digest),
        "partial-custody-file-mismatch",
    )
    if "custody" in c or "identity" in c:
        require(
            c.get("custody") == custody and c.get("identity") == identity,
            "partial-custody-replaced",
        )
    return identity


def partial_state(value: dict[str, Any], c: dict[str, Any], identity: dict[str, Any]) -> str:
    q = value.get("quota")
    if not isinstance(q, dict):
        raise GuestExhaustionError("partial-quota-mismatch")
    require(
        type(q.get("present")) is bool
        and type(q.get("project_id")) is int
        and q["project_id"] == c["project_id"],
        "partial-quota-mismatch",
    )
    for name in ("hard_bytes", "soft_bytes", "used_bytes", "inodes", "inode_hard", "inode_soft"):
        require(type(q.get(name)) is int and q[name] >= 0, "partial-quota-mismatch")
    require(
        q["soft_bytes"] == q["used_bytes"] == q["inode_hard"] == q["inode_soft"] == 0
        and q["hard_bytes"] in (0, CAPACITY),
        "partial-quota-mismatch",
    )
    d, attrs = value.get("directory"), value.get("attributes")
    if d is None:
        require(
            attrs is None and q["hard_bytes"] == q["inodes"] == 0, "partial-absence-not-observed"
        )
        return "absent"
    require(
        isinstance(d, dict)
        and set(d) == set(identity["directory"])
        and all(type(d[k]) is int for k in d)
        and all(d[k] == identity["directory"][k] for k in ("device", "inode", "mode")),
        "partial-live-directory-mismatch",
    )
    if not isinstance(attrs, dict):
        raise GuestExhaustionError("partial-live-attributes-mismatch")
    require(
        set(attrs) == {"project_id", "inherit"}
        and type(attrs["project_id"]) is int
        and type(attrs["inherit"]) is bool,
        "partial-live-attributes-mismatch",
    )
    pair = (attrs["project_id"], attrs["inherit"])
    require(
        pair in ((0, False), (c["project_id"], True))
        and q["inodes"] == (1 if attrs["project_id"] else 0),
        "partial-live-attributes-mismatch",
    )
    owner = {k: d[k] for k in ("uid", "gid")}
    require(owner in ({"uid": 0, "gid": 0}, c["actor"]), "partial-live-owner-mismatch")
    if attrs["project_id"]:
        require(q["present"] is True, "partial-quota-mismatch")
        if owner == {"uid": 0, "gid": 0}:
            return "limit" if q["hard_bytes"] else "project"
        require(q["hard_bytes"] == CAPACITY, "partial-quota-mismatch")
        return "ready"
    if q["hard_bytes"]:
        return "cleanup-project-reset"
    return "directory" if owner == {"uid": 0, "gid": 0} else "cleanup-limit-reset"


def validate_partial(
    value: dict[str, Any], c: dict[str, Any], mode: str, state: str | None
) -> None:
    require(
        value.get("mode") == mode
        and value.get("guest_canaries_preserved") is True
        and value.get("custody_retained_until_guest_cleanup") is True
        and value.get("allocation_retained_until_guest_cleanup") is False,
        "partial-observation-mismatch",
    )
    identity = partial_identity(value, c)
    observed = partial_state(value, c, identity)
    require(
        value.get("state") == observed
        and (state is None or observed == state)
        and value.get("target_absent") is (observed == "absent")
        and value.get("directory_retained_until_guest_cleanup") is (observed != "absent"),
        "partial-state-not-observed",
    )
    exited = mode != "prepare-partial"
    require(value.get("origin_exited") is exited, "partial-origin-exit-not-observed")
    if exited:
        require(
            (value["observer"]["pid"], value["observer"]["start_ticks"])
            != (identity["origin"]["pid"], identity["origin"]["start_ticks"]),
            "independent-partial-observer-missing",
        )
    expected = {"project_reset": False, "limit_reset": False, "rmdir": False}
    if mode == "cleanup-partial":
        before = value.get("before")
        if not isinstance(before, dict):
            raise GuestExhaustionError("partial-cleanup-before-missing")
        validate_partial({**before, "mode": "observe-partial"}, c, "observe-partial", None)
        present = before["state"] != "absent"
        expected = {
            "project_reset": present and before["attributes"]["project_id"] != 0,
            "limit_reset": before["quota"]["hard_bytes"] != 0,
            "rmdir": present,
        }
        require(
            type(value.get("removed_directory_links")) is int
            and value["removed_directory_links"] == 0
            if present
            else value.get("removed_directory_links") is None,
            "partial-cleanup-links-not-observed",
        )
        require(
            value.get("refusals_verified") == (list(PARTIAL_REFUSALS) if present else []),
            "partial-cleanup-refusals-missing",
        )
    else:
        require(value.get("refusals_verified") == [], "partial-observer-had-effects")
    require(
        value.get("mutation_effects") == expected
        and all(type(v) is bool for v in value["mutation_effects"].values()),
        "partial-cleanup-effects-mismatch",
    )


def partial_phase(
    guest: Guest,
    c: dict[str, Any],
    deadline: Deadline,
    case: dict[str, Any],
    name: str,
    mode: str,
    state: str | None,
    *,
    exit_expected: bool = False,
    unadmitted: bool = False,
) -> dict[str, Any] | None:
    phase: dict[str, Any] = {
        "phase": name,
        "mode": mode,
        "status": "failed",
        "outcome": "unobserved",
    }
    case["phases"].append(phase)
    metrics = RunStats()
    try:
        value = invoke(guest, mode, c, deadline)
        if unadmitted:
            phase["unadmitted_reply"] = value
            try:
                raise PartialReplyNotAdmitted()
            except PartialReplyNotAdmitted:
                phase.update(
                    status="passed",
                    mutation_reply_admitted=False,
                    interruption_kind="controlled-exception-before-reply-admission",
                )
            return value
        phase["observation"] = value
        require(not exit_expected, "planned-guest-exit-not-observed")
        validate_partial(value, c, mode, state)
        phase.update(status="passed", outcome="observed-" + value["state"])
        return value
    except RuntimeError as error:
        if not exit_expected or not command_failed(error, 42):
            raise
        phase.update(
            status="passed",
            observed_remote_exit=42,
            interruption_kind="controlled-guest-process-exit-after-checkpoint",
        )
        return None
    finally:
        phase["statistics"] = metrics.finish()
        if not valid_stats(phase["statistics"]):
            phase["status"] = "failed"
            raise ValueError("invalid required partial quota phase statistics")


def partial_case(
    guest: Guest,
    progress: Callable[[str], AbstractContextManager[None]],
    case: dict[str, Any],
    scenario: str,
    setup_exit: str | None,
    cleanup_exit: str | None,
    unadmitted: bool,
) -> None:
    metrics = RunStats()
    case.update(scenario=scenario, status="failed", phases=[], cleanup_outcome="unobserved")
    try:
        c = partial_configuration(guest)
        c["partial_exit_after"] = setup_exit
        case.update(
            task=c["task"],
            enrollment=c["enrollment"],
            boot_id=c["boot_id"],
            setup_checkpoint=setup_exit,
            cleanup_checkpoint=cleanup_exit,
        )
        deadline = Deadline.after(300)
        with progress("partial-quota-" + scenario):
            original = partial_phase(
                guest,
                c,
                deadline,
                case,
                "prepare",
                "prepare-partial",
                "ready",
                exit_expected=setup_exit is not None,
                unadmitted=unadmitted,
            )
            observed = partial_phase(
                guest,
                c,
                deadline,
                case,
                "independent-setup",
                "observe-partial",
                setup_exit or "ready",
            )
            assert observed is not None
            c["custody"], c["identity"] = observed["custody"], observed["identity"]
            case.update(
                custody=c["custody"],
                identity=c["identity"],
                setup_outcome="observed-" + observed["state"],
            )
            if unadmitted:
                require(original is not None, "partial-setup-reply-not-retained")
                assert original is not None
                validate_partial(original, c, "prepare-partial", "ready")
                case["original_reply_validated_after_independent_observation"] = True
            c["partial_exit_after"] = cleanup_exit
            if cleanup_exit is not None:
                partial_phase(
                    guest,
                    c,
                    deadline,
                    case,
                    "interrupted-cleanup",
                    "cleanup-partial",
                    None,
                    exit_expected=True,
                )
                expected = "absent" if cleanup_exit == "cleanup-rmdir" else cleanup_exit
                partial_phase(
                    guest,
                    c,
                    deadline,
                    case,
                    "independent-partial-cleanup",
                    "observe-partial",
                    expected,
                )
                case["interrupted_cleanup_outcome"] = "observed-" + expected
            c["partial_exit_after"] = None
            partial_phase(guest, c, deadline, case, "cleanup", "cleanup-partial", "absent")
            partial_phase(
                guest, c, deadline, case, "independent-absence", "observe-partial", "absent"
            )
            case["cleanup_outcome"] = "absent-observed-independently"
            partial_phase(guest, c, deadline, case, "repeat-cleanup", "cleanup-partial", "absent")
            partial_phase(guest, c, deadline, case, "final-absence", "observe-partial", "absent")
        case["status"] = "passed"
    finally:
        case["statistics"] = metrics.finish()
        if not valid_stats(case["statistics"]):
            case["status"] = "failed"
            raise ValueError("invalid required partial quota case statistics")


def qualify_partial_quota(
    guest: Guest,
    progress: Callable[[str], AbstractContextManager[None]],
    temporary: Path,
    report: dict[str, Any],
) -> None:
    metrics = RunStats()
    report.update(
        status="failed",
        scope="disposable-guest-partial-quota-setup-recovery-only",
        cases=[],
        resources_destroyed_with_guest=False,
        unrelated_host_canary_preserved=False,
        selected_controlled_recovery_qualified=False,
        unqualified_windows=[
            "before-custody-record-fsync",
            "unplanned-process-or-OS-crash",
            "reboot-or-restored-copy",
            "concurrent-product-writers",
        ],
    )
    try:
        with tempfile.TemporaryDirectory(
            prefix="fishhat-partial-quota-canary-", dir=temporary
        ) as name:
            canary = Path(name) / "unrelated"
            content = uuid.uuid4().bytes
            canary.write_bytes(content)
            before = canary.lstat()
            try:
                for scenario, setup, cleanup, unadmitted in PARTIAL_SCENARIOS:
                    case: dict[str, Any] = {}
                    report["cases"].append(case)
                    partial_case(guest, progress, case, scenario, setup, cleanup, unadmitted)
            finally:
                after = canary.lstat()
                report["unrelated_host_canary_preserved"] = (
                    before.st_dev,
                    before.st_ino,
                    before.st_mode,
                ) == (after.st_dev, after.st_ino, after.st_mode) and canary.read_bytes() == content
                require(report["unrelated_host_canary_preserved"], "unrelated-host-canary-changed")
        report.update(status="passed", selected_controlled_recovery_qualified=True)
    except OSError:
        raise GuestExhaustionError("partial-quota-observation-unavailable") from None
    finally:
        report["statistics"] = metrics.finish()
        if not valid_stats(report["statistics"]):
            report.update(status="failed", selected_controlled_recovery_qualified=False)
            raise ValueError("invalid required partial quota statistics")
