"""Qualify owned guest filesystems and account separation inside a disposable VM."""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from shlex import join as shell_join
from typing import Any

from scripts.native_linux_guest import Guest, GuestBootError
from scripts.native_linux_images import DISK_BYTES
from scripts.run_stats import RunStats, valid_stats
from scripts.validation_timeouts import Deadline, current

PACKAGES = {
    "coreutils": "9.4-3ubuntu6.3",
    "e2fsprogs": "1.47.0-2.4~exp1ubuntu4.1",
    "mount": "2.39.3-9ubuntu6.6",
    "util-linux": "2.39.3-9ubuntu6.6",
    "xfsprogs": "6.6.0-1ubuntu2.1",
}
FILESYSTEMS = {"control": "ext4", "data": "xfs"}

# The full guest identity guard executes before this program. Its own admission
# checks precede filesystem creation and never authorize formatting a host disk.
PROGRAM = r"""
import json, os, pathlib, pwd, stat, subprocess, sys, time, uuid
c = json.loads(sys.argv[1])
mode = c["mode"]
end = time.monotonic() + c["seconds"]
def require(value):
    if not value:
        raise ValueError("guest-storage-refused")
def command(arguments):
    remaining = end - time.monotonic()
    require(remaining > 0)
    return subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, text=True, timeout=remaining, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}).stdout
def metadata(path):
    v = path.lstat()
    require(stat.S_ISDIR(v.st_mode) and not path.is_symlink())
    return {"device": v.st_dev, "inode": v.st_ino, "uid": v.st_uid, "gid": v.st_gid, "mode": stat.S_IMODE(v.st_mode)}
require(os.geteuid() == 0 and mode in ("probe", "control", "data", "verify"))
require(str(uuid.UUID(c["enrollment"])) == c["enrollment"])
require(pathlib.Path("/etc/fishhat-fixture-enrollment").read_text().strip() == c["enrollment"])
require(pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip() == c["boot_id"])
admin = pwd.getpwnam(c["admin"])
require({"uid": admin.pw_uid, "gid": admin.pw_gid} == c["admin_identity"] and admin.pw_uid >= 1000)
rows = command(["/usr/bin/dpkg-query", "-W", "-f", "${Package}\t${Version}\n", *c["packages"]]).splitlines()
require(len(rows) == len(c["packages"]))
packages = dict(row.split("\t", 1) for row in rows)
require(packages == c["packages"])
root = pathlib.Path("/run/fhs-" + uuid.UUID(c["enrollment"]).hex)
roles = ("control", "data")
def device(role):
    p = pathlib.Path("/dev/disk/by-id/virtio-fh-" + role).resolve(strict=True)
    v = p.stat()
    require(stat.S_ISBLK(v.st_mode))
    output = json.loads(command(["/usr/bin/lsblk", "--json", "--bytes", "--paths", "--output", "NAME,PATH,TYPE,SIZE,SERIAL,MAJ:MIN,RO,MOUNTPOINTS", str(p)]))["blockdevices"]
    require(len(output) == 1)
    row = output[0]
    require(not row.get("children") and row["type"] == "disk" and row["ro"] is False)
    require(row["path"] == str(p) and row["serial"] == "fh-" + role and type(row["size"]) is int and row["size"] == c["sizes"][role])
    major, minor = (int(value) for value in row["maj:min"].split(":"))
    require(os.makedev(major, minor) == v.st_rdev)
    facts = {"path": str(p), "major": major, "minor": minor, "device": v.st_rdev, "bytes": row["size"], "serial": row["serial"]}
    if mode != "probe":
        require(facts == c["devices"][role])
    return facts, row
pairs = {role: device(role) for role in roles}
require(pairs["control"][0]["path"] != pairs["data"][0]["path"])
require((pairs["control"][0]["major"], pairs["control"][0]["minor"]) != (pairs["data"][0]["major"], pairs["data"][0]["minor"]))
def fresh(role):
    require(not any(pairs[role][1]["mountpoints"]))
    signatures = json.loads(command(["/usr/sbin/wipefs", "--no-act", "--json", "--output", "DEVICE,OFFSET,TYPE,UUID", pairs[role][0]["path"]]))
    require(signatures == {"signatures": []})
def filesystem(role):
    path = pairs[role][0]["path"]
    rows = command(["/usr/sbin/blkid", "--probe", "--output", "export", path]).splitlines()
    values = dict(row.split("=", 1) for row in rows)
    require(len(values) == len(rows) and values.get("DEVNAME") == path)
    require(values.get("TYPE") == c["filesystems"][role] and values.get("UUID") == c["uuids"][role])
    require(not any(name in ("PTTYPE", "PTUUID") or name.startswith("PART_ENTRY_") for name in values))
    return {"filesystem": values["TYPE"], "uuid": values["UUID"]}
def snapshot(role):
    facts, row = device(role)
    path = root / role
    v = metadata(path)
    uid, gid = (0, 0) if role == "control" else (admin.pw_uid, admin.pw_gid)
    fs = filesystem(role)
    require(row["mountpoints"] == [str(path)])
    require(v["device"] == facts["device"] and v["uid"] == uid and v["gid"] == gid and v["mode"] == 0o700)
    mounts = json.loads(command(["/usr/bin/findmnt", "--json", "--mountpoint", str(path), "--output", "SOURCE,TARGET,FSTYPE,OPTIONS,MAJ:MIN"]))["filesystems"]
    require(len(mounts) == 1)
    mount = mounts[0]
    require(mount["source"] == facts["path"] and mount["target"] == str(path) and mount["fstype"] == fs["filesystem"] and mount["maj:min"] == row["maj:min"])
    options = set(mount["options"].split(","))
    require({"rw", "nodev", "nosuid"} <= options)
    if role == "data":
        require(bool({"prjquota", "pquota"} & options) and "noquota" not in options)
    return {"device": facts, **fs, "directory": v, "mount_options": sorted(options)}
def canary(role, appended=False):
    return (role + ":" + c["enrollment"] + "\n" + ("admin-write\n" if appended else "")).encode()
def create_canary(role):
    path = root / role / "canary"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(canary(role))
        stream.flush()
        os.fsync(stream.fileno())
    if role == "data":
        os.chown(path, admin.pw_uid, admin.pw_gid)
if mode == "probe":
    require(not root.exists() and not root.is_symlink())
    for role in roles:
        fresh(role)
    result = {"packages": packages, "devices": {role: pairs[role][0] for role in roles}, "mount_root_absent": True}
else:
    for role in roles:
        require(str(uuid.UUID(c["uuids"][role])) == c["uuids"][role])
    require(c["uuids"]["control"] != c["uuids"]["data"])
    if mode == "control":
        require(not root.exists() and not root.is_symlink())
        for role in roles:
            fresh(role)
        root.mkdir(mode=0o711)
        os.chmod(root, 0o711)
        for role in roles:
            (root / role).mkdir(mode=0o700)
    else:
        require(metadata(root) == c["state"]["root"])
        require(snapshot("control") == c["state"]["control"])
    if mode in ("control", "data"):
        role = mode
        fresh(role)
        path = root / role
        require(metadata(path)["uid"] == 0 and metadata(path)["mode"] == 0o700)
        if role == "control":
            command(["/usr/sbin/mkfs.ext4", "-q", "-U", c["uuids"][role], pairs[role][0]["path"]])
        else:
            command(["/usr/sbin/mkfs.xfs", "-q", "-m", "uuid=" + c["uuids"][role], pairs[role][0]["path"]])
        options = "nodev,nosuid" + (",prjquota" if role == "data" else "")
        command(["/usr/bin/mount", "-t", c["filesystems"][role], "-o", options, pairs[role][0]["path"], str(path)])
        os.chmod(path, 0o700)
        if role == "data":
            os.chown(path, admin.pw_uid, admin.pw_gid)
        create_canary(role)
        result = {"root": metadata(root), role: snapshot(role)}
    else:
        require(snapshot("data") == c["state"]["data"])
        for role in roles:
            path = root / role / "canary"
            v = path.lstat()
            uid, gid = (0, 0) if role == "control" else (admin.pw_uid, admin.pw_gid)
            require(stat.S_ISREG(v.st_mode) and v.st_nlink == 1 and v.st_uid == uid and v.st_gid == gid and stat.S_IMODE(v.st_mode) == 0o600)
            require(path.read_bytes() == canary(role, role == "data"))
        require(not (root / "data" / "permission-probe").exists() and not (root / "data" / "renamed-probe").exists())
        result = {"root": metadata(root), "control": snapshot("control"), "data": snapshot("data"), "canaries_verified": True}
print(json.dumps(result, sort_keys=True))
"""

PERMISSIONS = r"""
import errno, json, os, pathlib, pwd, stat, sys, uuid
c = json.loads(sys.argv[1])
def require(value):
    if not value:
        raise ValueError("guest-permission-refused")
role = c["role"]
require(role in ("admin", "peer"))
account = c["accounts"][role]
require(os.getuid() == os.geteuid() == account["uid"] and os.getgid() == os.getegid() == account["gid"] and pwd.getpwuid(os.geteuid()).pw_name == account["name"])
require(pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip() == c["boot_id"] and pathlib.Path("/etc/fishhat-fixture-enrollment").read_text().strip() == c["enrollment"])
root = pathlib.Path("/run/fhs-" + uuid.UUID(c["enrollment"]).hex)
for name in ("control", "data"):
    p = root / name
    v = p.lstat()
    observed = {"device": v.st_dev, "inode": v.st_ino, "uid": v.st_uid, "gid": v.st_gid, "mode": stat.S_IMODE(v.st_mode)}
    require(stat.S_ISDIR(v.st_mode) and observed == c["state"][name]["directory"])
denied = []
def deny(name, action):
    try:
        action()
    except OSError as error:
        require(error.errno in (errno.EACCES, errno.EPERM))
        denied.append(name)
    else:
        raise ValueError("guest-permission-unexpectedly-allowed")
def create(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(descriptor)
for name in (("control", "data") if role == "peer" else ("control",)):
    path = root / name
    deny(name + ":read", lambda: (path / "canary").read_bytes())
    deny(name + ":list", lambda: list(path.iterdir()))
    deny(name + ":create", lambda: create(path / "permission-probe"))
    deny(name + ":unlink", lambda: (path / "canary").unlink())
allowed = []
if role == "admin":
    path = root / "data"
    require((path / "canary").read_bytes() == ("data:" + c["enrollment"] + "\n").encode())
    create(path / "permission-probe")
    (path / "permission-probe").rename(path / "renamed-probe")
    (path / "renamed-probe").unlink()
    descriptor = os.open(path / "canary", os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(b"admin-write\n")
        stream.flush()
        os.fsync(stream.fileno())
    allowed = ["data:read", "data:create", "data:rename", "data:unlink", "data:write"]
print(json.dumps({"role": role, "account": account, "boot_id": c["boot_id"], "enrollment": c["enrollment"], "denied": denied, "allowed": allowed}, sort_keys=True))
"""


class GuestStorageError(GuestBootError):
    stage = "guest-storage"


def decode(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        raise GuestStorageError("invalid-storage-observation") from None
    if not isinstance(value, dict):
        raise GuestStorageError("invalid-storage-observation")
    return value


@dataclass
class Storage:
    guest: Guest
    report: dict[str, Any]
    deadline: Deadline
    devices: dict[str, Any] = field(default_factory=dict)
    state: dict[str, Any] = field(default_factory=dict)
    uuids: dict[str, str] = field(
        default_factory=lambda: {role: str(uuid.uuid4()) for role in FILESYSTEMS}
    )

    def configuration(self) -> dict[str, Any]:
        if self.guest.observed is None:
            raise GuestStorageError("guest-not-verified")
        admin, peer = self.guest.accounts
        return {
            "enrollment": self.guest.enrollment,
            "boot_id": self.guest.observed["boot_id"],
            "admin": admin,
            "admin_identity": self.guest.observed["accounts"][admin],
            "accounts": {
                role: {"name": name, **self.guest.observed["accounts"][name]}
                for role, name in (("admin", admin), ("peer", peer))
            },
            "packages": PACKAGES,
            "sizes": {role: DISK_BYTES[role + ".qcow2"] for role in FILESYSTEMS},
            "filesystems": FILESYSTEMS,
            "uuids": self.uuids,
            "devices": self.devices,
            "state": self.state,
        }

    def root(self, mode: str, *, nominal: float = 60) -> dict[str, Any]:
        c = self.configuration()
        c.update(mode=mode, seconds=min(nominal * current().scale, self.deadline.remaining()))
        if c["seconds"] <= 0:
            raise GuestStorageError("storage-deadline")
        result = self.guest.guarded(
            ["/usr/bin/python3", "-I", "-S", "-c", PROGRAM, json.dumps(c, sort_keys=True)],
            self.guest.enrollment,
            c["boot_id"],
            deadline=self.deadline,
            nominal=nominal,
        )
        return decode(result)

    def probe(self) -> None:
        value = self.root("probe", nominal=15)
        if (
            set(value) != {"packages", "devices", "mount_root_absent"}
            or value["packages"] != PACKAGES
            or value["mount_root_absent"] is not True
            or not isinstance(value["devices"], dict)
            or set(value["devices"]) != set(FILESYSTEMS)
        ):
            raise GuestStorageError("storage-admission-mismatch")
        for role, device in value["devices"].items():
            if (
                not isinstance(device, dict)
                or set(device) != {"path", "major", "minor", "device", "bytes", "serial"}
                or not isinstance(device["path"], str)
                or re.fullmatch(r"/dev/vd[a-z]+", device["path"]) is None
                or type(device["bytes"]) is not int
                or device["bytes"] != DISK_BYTES[role + ".qcow2"]
                or device["serial"] != "fh-" + role
                or any(
                    type(device[n]) is not int or device[n] < 0
                    for n in ("major", "minor", "device")
                )
                or device["major"] == 0
                or device["device"] == 0
            ):
                raise GuestStorageError("storage-admission-mismatch")
        control, data = (value["devices"][role] for role in FILESYSTEMS)
        if (
            control["path"] == data["path"]
            or control["device"] == data["device"]
            or (control["major"], control["minor"])
            == (
                data["major"],
                data["minor"],
            )
        ):
            raise GuestStorageError("storage-device-not-independent")
        self.devices = value["devices"]
        self.report["admission"] = value

    def mounted(self, role: str) -> None:
        if role not in FILESYSTEMS:
            raise GuestStorageError("unknown-storage-role")
        if set(self.devices) != set(FILESYSTEMS):
            raise GuestStorageError("storage-not-admitted")
        if role == "data" and set(self.state) != {"root", "control"}:
            raise GuestStorageError("storage-not-prepared")
        value = self.root(role)
        if set(value) != {"root", role}:
            raise GuestStorageError("invalid-storage-observation")

        def directory(v: Any, uid: int, gid: int, mode: int) -> bool:
            return (
                isinstance(v, dict)
                and set(v) == {"device", "inode", "uid", "gid", "mode"}
                and all(type(v[n]) is int and v[n] >= 0 for n in v)
                and v["device"] > 0
                and v["inode"] > 0
                and (v["uid"], v["gid"], v["mode"]) == (uid, gid, mode)
            )

        root = value["root"]
        observed = value[role]
        c = self.configuration()
        uid, gid = (
            (0, 0)
            if role == "control"
            else (c["admin_identity"]["uid"], c["admin_identity"]["gid"])
        )
        if (
            not directory(root, 0, 0, 0o711)
            or not isinstance(observed, dict)
            or set(observed) != {"device", "filesystem", "uuid", "directory", "mount_options"}
            or observed["device"] != self.devices[role]
            or observed["filesystem"] != FILESYSTEMS[role]
            or observed["uuid"] != self.uuids[role]
            or not directory(observed["directory"], uid, gid, 0o700)
            or observed["directory"]["device"] != self.devices[role]["device"]
            or observed["directory"]["device"] == root["device"]
            or not isinstance(observed["mount_options"], list)
            or not all(isinstance(option, str) for option in observed["mount_options"])
            or observed["mount_options"] != sorted(set(observed["mount_options"]))
            or not {"rw", "nodev", "nosuid"} <= set(observed["mount_options"])
            or (role == "data" and not {"prjquota", "pquota"} & set(observed["mount_options"]))
            or (role == "data" and "noquota" in observed["mount_options"])
        ):
            raise GuestStorageError("storage-filesystem-mismatch")
        previous = self.state.get("root")
        if previous is not None and root != previous:
            raise GuestStorageError("storage-directory-changed")
        self.state.update(value)
        self.report["filesystems"] = dict(self.state)

    def permissions(self, role: str) -> None:
        if role not in {"admin", "peer"}:
            raise GuestStorageError("unknown-storage-role")
        if set(self.state) != {"root", "control", "data"}:
            raise GuestStorageError("storage-not-prepared")
        c = self.configuration()
        c["role"] = role
        result = decode(
            self.guest.ssh(
                shell_join(
                    [
                        "/usr/bin/python3",
                        "-I",
                        "-S",
                        "-c",
                        PERMISSIONS,
                        json.dumps(c, sort_keys=True),
                    ]
                ),
                role=role,
                deadline=self.deadline,
            )
        )
        names = ("control", "data") if role == "peer" else ("control",)
        expected = {
            "role": role,
            "account": c["accounts"][role],
            "boot_id": c["boot_id"],
            "enrollment": c["enrollment"],
            "denied": [
                name + ":" + action
                for name in names
                for action in ("read", "list", "create", "unlink")
            ],
            "allowed": []
            if role == "peer"
            else ["data:" + action for action in ("read", "create", "rename", "unlink", "write")],
        }
        if result != expected:
            raise GuestStorageError("permission-observation-mismatch")
        self.report.setdefault("permissions", {})[role] = result


def qualify_storage(
    guest: Guest,
    progress: Callable[[str], AbstractContextManager[None]],
    report: dict[str, Any],
    *,
    inject_failure: bool = False,
) -> None:
    metrics = RunStats()
    report.update(
        status="failed",
        scope="disposable-guest-filesystems-and-permissions-only",
        enrollment=guest.enrollment,
        permissions_verified=False,
        resources_destroyed_with_guest=False,
    )
    try:
        storage = Storage(guest, report, Deadline.after(180))
        with progress("storage-admission"):
            storage.probe()
        with progress("storage-control"):
            storage.mounted("control")
        if inject_failure:
            report["fault_injection_verified"] = True
            raise GuestStorageError("injected-after-control-mount")
        with progress("storage-data"):
            storage.mounted("data")
        with progress("storage-permissions"):
            storage.permissions("admin")
            storage.permissions("peer")
            final = storage.root("verify", nominal=15)
            if final != {**storage.state, "canaries_verified": True}:
                raise GuestStorageError("storage-final-observation-mismatch")
        report.update(status="passed", permissions_verified=True)
    finally:
        report["statistics"] = metrics.finish()
        if not valid_stats(report["statistics"]):
            raise ValueError("invalid required guest storage statistics")
