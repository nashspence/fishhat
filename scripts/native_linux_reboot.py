"""Observe guarded canary bytes and graceful reboot in an enrolled disposable guest."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import tempfile
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Any

from scripts.native_linux_guest import Guest, GuestBootError, command_failed
from scripts.native_linux_images import DISK_BYTES, identity
from scripts.run_stats import RunStats, valid_stats
from scripts.validation_timeouts import Deadline, current

REBOOT = ["/usr/bin/systemctl", "--no-wall", "--no-block", "reboot"]

# This helper runs after the existing full guest identity/SSH guard. It never
# formats or mounts a disk; the canary lives on the owned persistent root disk.
PROGRAM = r"""
import hashlib, json, os, pathlib, stat, subprocess, sys, time, uuid
c = json.loads(sys.argv[1])
end = time.monotonic() + c["seconds"]
def require(value):
    if not value:
        raise ValueError("guest-reboot-custody-refused")
def canary_contents(fd, expected, replacement=None):
    require(isinstance(expected, bytes) or expected is None)
    require(isinstance(replacement, bytes) or replacement is None)
    require(expected is not None or replacement is not None)
    limit = len(expected if expected is not None else replacement)
    require(limit > 0)
    def read():
        os.lseek(fd, 0, os.SEEK_SET)
        actual = bytearray()
        while len(actual) <= limit:
            block = os.read(fd, limit + 1 - len(actual))
            if not block:
                break
            actual.extend(block)
        return bytes(actual)
    before = read()
    require(before == (expected if expected is not None else b""))
    if replacement is None:
        return before
    require(expected is None or (len(expected) == len(replacement) and expected != replacement))
    os.lseek(fd, 0, os.SEEK_SET)
    position = 0
    while position < len(replacement):
        count = os.write(fd, replacement[position:])
        require(0 < count <= len(replacement) - position)
        position += count
    os.fsync(fd)
    actual = read()
    require(actual == replacement)
    return actual
def command(arguments):
    remaining = end - time.monotonic()
    require(remaining > 0)
    return subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, text=True, timeout=remaining, env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LANG":"C","LC_ALL":"C"}).stdout
def row(arguments):
    value = json.loads(command(arguments))["blockdevices"]
    require(len(value) == 1 and not value[0].get("children"))
    return value[0]
require(os.geteuid() == 0 and c["mode"] in ("prepare", "inspect", "advance"))
require(str(uuid.UUID(c["enrollment"])) == c["enrollment"] and str(uuid.UUID(c["nonce"])) == c["nonce"] and str(uuid.UUID(c["probe"])) == c["probe"])
require(pathlib.Path("/etc/fishhat-fixture-enrollment").read_text().strip() == c["enrollment"])
require(pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip() == c["boot_id"])
disks = {}
for role in ("root", "control", "data"):
    path = pathlib.Path("/dev/disk/by-id/virtio-fh-" + role).resolve(strict=True)
    v = path.stat()
    require(stat.S_ISBLK(v.st_mode))
    d = row(["/usr/bin/lsblk","--json","--bytes","--paths","--nodeps","--output","PATH,TYPE,SIZE,SERIAL,MAJ:MIN,RO",str(path)])
    require(d["path"] == str(path) and d["type"] == "disk" and d["ro"] is False and d["serial"] == "fh-" + role)
    require(type(d["size"]) is int and d["size"] == c["sizes"][role])
    major, minor = (int(part) for part in d["maj:min"].split(":"))
    require(os.makedev(major, minor) == v.st_rdev)
    disks[role] = {"path":str(path),"device":v.st_rdev,"major":major,"minor":minor,"bytes":d["size"],"serial":d["serial"]}
require(len({d["device"] for d in disks.values()}) == 3)
mounts = json.loads(command(["/usr/bin/findmnt","--json","--mountpoint","/","--output","SOURCE,TARGET,FSTYPE,UUID,MAJ:MIN,OPTIONS"]))["filesystems"]
require(len(mounts) == 1)
m = mounts[0]
require(m["target"] == "/" and m["fstype"] == "ext4" and "rw" in m["options"].split(","))
require(str(uuid.UUID(m["uuid"])) == m["uuid"])
source = pathlib.Path(m["source"]).resolve(strict=True)
v = source.stat()
require(stat.S_ISBLK(v.st_mode) and v.st_rdev == pathlib.Path("/").stat().st_dev)
p = row(["/usr/bin/lsblk","--json","--paths","--nodeps","--output","PATH,TYPE,PKNAME,UUID,FSTYPE,MAJ:MIN",str(source)])
require(p["path"] == str(source) and p["type"] == "part" and p["pkname"] == disks["root"]["path"] and p["uuid"] == m["uuid"] and p["fstype"] == "ext4" and p["maj:min"] == m["maj:min"])
major, minor = (int(part) for part in m["maj:min"].split(":"))
require(os.makedev(major, minor) == v.st_rdev)
filesystem = {"path":str(source),"device":v.st_rdev,"uuid":m["uuid"],"filesystem":"ext4"}
root = pathlib.Path("/var/lib/fhr-" + uuid.UUID(c["enrollment"]).hex)
content = ("reboot:" + c["enrollment"] + "\n" + c["nonce"] + "\n").encode()
if c["mode"] == "advance":
    require("identity" not in c and str(uuid.UUID(c["prior_nonce"])) == c["prior_nonce"] and c["prior_nonce"] != c["nonce"])
    require({"path":os.readlink("/proc/self/exe"),"sha256":hashlib.sha256(pathlib.Path("/proc/self/exe").read_bytes()).hexdigest()} == c["image"])
    prior_content = ("reboot:" + c["enrollment"] + "\n" + c["prior_nonce"] + "\n").encode()
require(not (root / "denied").exists() and not (root / "denied").is_symlink())
mountpoints = [line.split()[4] for line in pathlib.Path("/proc/self/mountinfo").read_text().splitlines()]
require(not any(p == str(root) or p.startswith(str(root) + "/") for p in mountpoints))
def metadata(v, directory=False):
    require((stat.S_ISDIR if directory else stat.S_ISREG)(v.st_mode) and v.st_dev == filesystem["device"] and v.st_uid == v.st_gid == 0 and stat.S_IMODE(v.st_mode) == (0o700 if directory else 0o600))
    require(directory or v.st_nlink == 1)
    return {"device":v.st_dev,"inode":v.st_ino,"uid":v.st_uid,"gid":v.st_gid,"mode":stat.S_IMODE(v.st_mode),**({} if directory else {"links":v.st_nlink,"size":v.st_size})}
ancestor = os.open("/var/lib", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    v = os.fstat(ancestor)
    require(stat.S_ISDIR(v.st_mode) and v.st_dev == filesystem["device"] and v.st_uid == v.st_gid == 0 and not stat.S_IMODE(v.st_mode) & 0o022)
    require(v == pathlib.Path("/var/lib").lstat())
    if c["mode"] == "prepare":
        require(not root.exists() and not root.is_symlink() and "identity" not in c)
        os.mkdir(root.name, mode=0o700, dir_fd=ancestor)
    parent = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=ancestor)
    try:
        directory = metadata(os.fstat(parent), True)
        require(directory == metadata(root.lstat(), True))
        flags = os.O_NOFOLLOW | (os.O_RDWR | os.O_CREAT | os.O_EXCL if c["mode"] == "prepare" else os.O_RDWR if c["mode"] == "advance" else os.O_RDONLY)
        fd = os.open("canary", flags, 0o600, dir_fd=parent)
        try:
            if c["mode"] == "advance":
                prior_file = metadata(os.fstat(fd))
                require(prior_file == metadata((root / "canary").lstat()))
                previous = canary_contents(fd, prior_content)
                previous_identity = {"disks":disks,"root_filesystem":filesystem,"directory":directory,"file":prior_file,"content":previous.decode(),"sha256":hashlib.sha256(previous).hexdigest()}
                require(json.dumps(previous_identity, sort_keys=True) == json.dumps(c["prior_identity"], sort_keys=True) and metadata(os.fstat(fd)) == prior_file)
                actual = canary_contents(fd, prior_content, content)
            else:
                actual = canary_contents(fd, None, content) if c["mode"] == "prepare" else canary_contents(fd, content)
            file = metadata(os.fstat(fd))
            require(file["size"] == len(content) and file == metadata((root / "canary").lstat()))
            require(actual == content and metadata(os.fstat(fd)) == file)
            if c["mode"] == "advance":
                require(file == prior_file)
        finally:
            os.close(fd)
        if c["mode"] == "prepare":
            os.fsync(parent)
    finally:
        os.close(parent)
    require(os.fstat(ancestor) == pathlib.Path("/var/lib").lstat())
    if c["mode"] == "prepare":
        os.fsync(ancestor)
finally:
    os.close(ancestor)
value = {"disks":disks,"root_filesystem":filesystem,"directory":directory,"file":file,"content":content.decode(),"sha256":hashlib.sha256(content).hexdigest()}
if c["mode"] == "inspect":
    require(value == c["identity"])
require(not (root / "denied").exists() and not (root / "denied").is_symlink())
print(json.dumps({"mode":c["mode"],"probe":c["probe"],"enrollment":c["enrollment"],"boot_id":c["boot_id"],"identity":value,"canary_fsynced":c["mode"] in ("prepare", "advance"),**({"previous_identity":previous_identity} if c["mode"] == "advance" else {}),"denied_canary_absent":True,"observer":{"pid":os.getpid(),"executable":{"path":os.readlink("/proc/self/exe"),"sha256":hashlib.sha256(pathlib.Path("/proc/self/exe").read_bytes()).hexdigest()}}},sort_keys=True))
"""


class GuestRebootError(GuestBootError):
    stage = "guest-reboot"


class RebootObservationInterrupted(GuestRebootError):
    """The selected fixture fault, never an inference from an arbitrary error."""

    def __init__(self) -> None:
        super().__init__("injected-before-restart-observation")


def require(value: Any, reason: str) -> None:
    if not value:
        raise GuestRebootError(reason)


@contextmanager
def phase(report: dict[str, Any], name: str) -> Iterator[dict[str, Any]]:
    item: dict[str, Any] = {"phase": name, "status": "failed"}
    report["phases"].append(item)
    metrics = RunStats()
    try:
        yield item
        item["status"] = "passed"
    finally:
        item["statistics"] = metrics.finish()
        if not valid_stats(item["statistics"]):
            item["status"] = "failed"
            raise ValueError("invalid required reboot phase statistics")


def host_custody(guest: Guest, endpoint: Path, deadline: Deadline) -> dict[str, Any]:
    require(guest.process is not None and guest.verify_process is not None, "controller-missing")
    assert guest.process is not None and guest.verify_process is not None
    guest.verify_process(deadline)
    guest.listener()
    guest.inputs.verify(guest.enrollment)
    guest.verify_tools()
    for name in guest.files:
        guest.path(name)
    controller = guest.report.get("controller_verified", {})
    require(
        controller.get("instance_uuid") == guest.enrollment
        and controller.get("unix_peer_verified") is True,
        "initial-controller-identity-missing",
    )
    parent = identity(endpoint.parent, directory=True)
    socket = endpoint.lstat()
    require(
        stat.S_ISSOCK(socket.st_mode)
        and socket.st_uid == os.geteuid()
        and socket.st_gid == os.getegid()
        and socket.st_nlink == 1
        and stat.S_IMODE(socket.st_mode) == 0o700,
        "control-endpoint-changed",
    )
    require(os.getpgid(guest.process.pid) == guest.process.pid, "controller-group-changed")
    return {
        "controller": copy.deepcopy(controller),
        "pid": guest.process.pid,
        "pgid": guest.process.pid,
        "endpoint": {"address": "127.0.0.1", "port": guest.port, "listener_owned": True},
        "control_socket": {
            "path": str(endpoint),
            "device": socket.st_dev,
            "inode": socket.st_ino,
            "parent": parent,
        },
        "input_directory": {
            "path": str(guest.inputs.directory),
            "identity": guest.inputs.directory_identity,
        },
        "private_directory": {
            "path": str(guest.directory),
            "identity": guest.directory_identity,
        },
        "private_files": {
            name: {"path": str(guest.path(name)), "identity": value[0]}
            for name, value in guest.files.items()
        },
        "disks": {
            name: {"path": str(guest.inputs.path(name, guest.enrollment)), "identity": value}
            for name, value in guest.inputs.files.items()
        },
        "private_inputs_verified": True,
        "base_image_verified": "base.img" in guest.inputs.files,
    }


def invoke(
    guest: Guest,
    observed: dict[str, Any],
    c: dict[str, Any],
    mode: str,
    deadline: Deadline,
    evidence: dict[str, Any],
    *,
    used_probes: set[str] | None = None,
) -> dict[str, Any]:
    require(mode in ("prepare", "inspect", "advance"), "invalid-canary-mode")
    c = {
        **c,
        "mode": mode,
        "boot_id": observed["boot_id"],
        "probe": str(uuid.uuid4()),
        "seconds": min(current().seconds(60), deadline.remaining()),
    }
    if used_probes is not None:
        require(c["probe"] not in used_probes, "canary-challenge-reused")
        used_probes.add(c["probe"])
    require(c["seconds"] > 0, "canary-observation-deadline")
    evidence["request"] = {k: c[k] for k in ("mode", "probe", "enrollment", "boot_id")}
    if mode == "advance":
        evidence["request"].update(
            {
                k: copy.deepcopy(c[k])
                for k in ("nonce", "prior_nonce", "prior_identity", "image", "sizes", "seconds")
            }
        )
    raw = guest.ssh(
        guest.remote(observed, ["/usr/bin/python3", "-I", "-S", "-c", PROGRAM, json.dumps(c)]),
        deadline=deadline,
        nominal=75,
    )
    evidence["original_reply"] = raw
    try:
        value = json.loads(raw)
    except (ValueError, RecursionError):
        raise GuestRebootError("invalid-canary-observation") from None
    evidence["observation"] = value
    if not isinstance(value, dict):
        raise GuestRebootError("invalid-canary-observation")
    require(
        value.get("mode") == mode
        and value.get("probe") == c["probe"]
        and value.get("enrollment") == guest.enrollment
        and value.get("boot_id") == observed["boot_id"]
        and value.get("canary_fsynced") is (mode in ("prepare", "advance"))
        and value.get("denied_canary_absent") is True,
        "canary-observation-mismatch",
    )
    if mode == "advance":
        observer = value.get("observer")
        require(
            isinstance(value.get("previous_identity"), dict)
            and json.dumps(value["previous_identity"], sort_keys=True)
            == json.dumps(c.get("prior_identity"), sort_keys=True)
            and isinstance(observer, dict)
            and observer.get("executable") == c.get("image"),
            "canary-prior-identity-mismatch",
        )
    return value


def validate_canary(value: dict[str, Any], c: dict[str, Any]) -> dict[str, Any]:
    v = value.get("identity")
    if not isinstance(v, dict):
        raise GuestRebootError("canary-identity-missing")
    require(
        set(v) == {"disks", "root_filesystem", "directory", "file", "content", "sha256"},
        "canary-identity-mismatch",
    )
    content = "reboot:" + c["enrollment"] + "\n" + c["nonce"] + "\n"
    require(
        v["content"] == content and v["sha256"] == hashlib.sha256(content.encode()).hexdigest(),
        "canary-content-mismatch",
    )
    disks = v["disks"]
    require(isinstance(disks, dict) and set(disks) == {"root", "control", "data"}, "disk-mismatch")
    for role, disk in disks.items():
        require(
            isinstance(disk, dict)
            and set(disk) == {"path", "device", "major", "minor", "bytes", "serial"}
            and all(
                type(disk[k]) is int and disk[k] >= 0 for k in ("device", "major", "minor", "bytes")
            )
            and disk["device"] == os.makedev(disk["major"], disk["minor"])
            and disk["bytes"] == c["sizes"][role]
            and disk["serial"] == "fh-" + role
            and isinstance(disk["path"], str)
            and disk["path"].startswith("/dev/"),
            "disk-mismatch",
        )
    require(len({disk["device"] for disk in disks.values()}) == 3, "shared-disk-identity")
    filesystem = v["root_filesystem"]
    require(
        isinstance(filesystem, dict)
        and set(filesystem) == {"path", "device", "uuid", "filesystem"}
        and filesystem["filesystem"] == "ext4"
        and type(filesystem["device"]) is int
        and filesystem["device"] > 0
        and isinstance(filesystem["path"], str)
        and filesystem["path"].startswith("/dev/"),
        "root-filesystem-mismatch",
    )
    try:
        require(
            str(uuid.UUID(filesystem["uuid"])) == filesystem["uuid"], "root-filesystem-mismatch"
        )
    except (ValueError, AttributeError, TypeError):
        raise GuestRebootError("root-filesystem-mismatch") from None
    for name, mode in (("directory", 0o700), ("file", 0o600)):
        item = v[name]
        require(
            isinstance(item, dict)
            and set(item)
            == {"device", "inode", "uid", "gid", "mode"}
            | ({"links", "size"} if name == "file" else set())
            and all(type(x) is int for x in item.values())
            and item["device"] == filesystem["device"]
            and item["inode"] > 0
            and item["uid"] == item["gid"] == 0
            and item["mode"] == mode,
            "canary-metadata-mismatch",
        )
    require(v["file"]["links"] == 1 and v["file"]["size"] == len(content), "canary-file-mismatch")
    proc = value.get("observer")
    if not isinstance(proc, dict):
        raise GuestRebootError("canary-observer-missing")
    require(
        isinstance(proc, dict)
        and type(proc.get("pid")) is int
        and proc["pid"] > 0
        and isinstance(proc.get("executable"), dict),
        "canary-observer-missing",
    )
    image = proc["executable"]
    require(
        image.get("path") == "/usr/bin/python3.12"
        and isinstance(image.get("sha256"), str)
        and len(image["sha256"]) == 64
        and all(x in "0123456789abcdef" for x in image["sha256"]),
        "canary-observer-image-mismatch",
    )
    if "identity" in c:
        require(
            json.dumps(v, sort_keys=True) == json.dumps(c["identity"], sort_keys=True)
            and image == c["image"],
            "retained-canary-changed",
        )
    return v


def qualify_canary_advance(
    guest: Guest,
    observed: dict[str, Any],
    c: dict[str, Any],
    deadline: Deadline,
    report: dict[str, Any],
    *,
    prior_probes: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    metrics = RunStats()
    report.update(
        status="failed",
        scope="owned-disposable-canary-byte-advance-only",
        phases=[],
        snapshot_restore_qualified=False,
        product_authority_qualified=False,
    )
    original = copy.deepcopy(c)
    used_probes = set(prior_probes)
    complete = False
    try:
        guest.validate_profile(observed)
        require(c.get("enrollment") == guest.enrollment, "foreign-canary-enrollment")
        require(
            isinstance(c.get("identity"), dict) and isinstance(c.get("image"), dict),
            "admitted-prior-canary-required",
        )
        with phase(report, "prior-observation") as item:
            previous = invoke(
                guest, observed, c, "inspect", deadline, item, used_probes=used_probes
            )
            prior = validate_canary(previous, c)
        nonce = str(uuid.uuid4())
        require(nonce != c["nonce"], "canary-nonce-not-distinct")
        request = {
            "enrollment": c["enrollment"],
            "sizes": copy.deepcopy(c["sizes"]),
            "nonce": nonce,
            "prior_nonce": c["nonce"],
            "prior_identity": copy.deepcopy(prior),
            "image": copy.deepcopy(c["image"]),
        }
        with phase(report, "persist-different-bytes") as item:
            written = invoke(
                guest, observed, request, "advance", deadline, item, used_probes=used_probes
            )
            resulting = validate_canary(written, request)
            require(
                {k: v for k, v in resulting.items() if k not in ("content", "sha256")}
                == {k: v for k, v in prior.items() if k not in ("content", "sha256")}
                and resulting["content"] != prior["content"],
                "canary-advance-custody-changed",
            )
        accepted = {
            "enrollment": c["enrollment"],
            "sizes": copy.deepcopy(c["sizes"]),
            "nonce": nonce,
            "identity": copy.deepcopy(resulting),
            "image": copy.deepcopy(c["image"]),
        }
        with phase(report, "independent-readback") as item:
            after = invoke(
                guest, observed, accepted, "inspect", deadline, item, used_probes=used_probes
            )
            validate_canary(after, accepted)
        require(
            len({p["request"]["probe"] for p in report["phases"]}) == 3,
            "canary-challenge-reused",
        )
        require(c == original, "prior-canary-configuration-changed")
        report.update(
            prior_canary=copy.deepcopy(prior),
            written_canary=copy.deepcopy(resulting),
            observed_canary=copy.deepcopy(after["identity"]),
        )
        complete = True
        return accepted
    finally:
        report["statistics"] = metrics.finish()
        if not valid_stats(report["statistics"]):
            report["status"] = "failed"
            raise ValueError("invalid required canary advance statistics")
        if complete:
            report["status"] = "passed"


def new_boot(
    guest: Guest, before: dict[str, Any], evidence: dict[str, Any], deadline: Deadline
) -> dict[str, Any]:
    evidence["observations"] = []
    while deadline.remaining() > 0:
        try:
            value = guest.observe(deadline)
        except RuntimeError as error:
            if command_failed(error, 255):
                observation = {"transport_outcome": "unobserved", "exit_status": 255}
            elif (
                getattr(error, "stage", None) == "guest-ssh"
                and getattr(error, "reason", None) == "observation-deadline"
            ):
                # This call only reads identity. Its timeout supplies no boot
                # outcome; retry that read within the original shared deadline.
                observation = {"transport_outcome": "unobserved", "reason": "observation-deadline"}
            else:
                raise
            evidence["observations"].append(observation)
        else:
            evidence["observations"].append({"identity": value})
            require(type(value.get("cloud_init_complete")) is bool, "invalid-reboot-readiness")
            guest.validate_profile({**value, "cloud_init_complete": True})
            require(
                {k: v for k, v in value.items() if k not in ("boot_id", "cloud_init_complete")}
                == {k: v for k, v in before.items() if k not in ("boot_id", "cloud_init_complete")},
                "reboot-guest-identity-changed",
            )
            if value["boot_id"] != before["boot_id"] and value["cloud_init_complete"]:
                return value
        time.sleep(min(current().seconds(1), max(0, deadline.remaining())))
    raise GuestRebootError("new-boot-not-observed")


def refuse_stale(
    guest: Guest, before: dict[str, Any], after: dict[str, Any], deadline: Deadline
) -> list[str]:
    path = "/var/lib/fhr-" + uuid.UUID(guest.enrollment).hex + "/denied"
    refused = []
    for name, expected in (
        ("stale-boot", before),
        ("foreign-enrollment", {**after, "enrollment": str(uuid.uuid4())}),
    ):
        try:
            guest.ssh(guest.remote(expected, ["/usr/bin/touch", path]), deadline=deadline)
        except RuntimeError as error:
            if not command_failed(error, 73):
                raise
            refused.append(name)
        else:
            raise GuestRebootError("stale-reboot-command-accepted")
    return refused


def qualify_reboot(
    guest: Guest,
    endpoint: Path,
    progress: Callable[[str], AbstractContextManager[None]],
    temporary: Path,
    report: dict[str, Any],
    *,
    interrupt_observation: bool = False,
) -> None:
    metrics = RunStats()
    report.update(
        status="failed",
        scope="disposable-guest-graceful-reboot-only",
        mechanism="guarded-systemd-no-block-reboot-same-controller",
        phases=[],
        resources_destroyed_with_guest=False,
        unrelated_host_canary_preserved=False,
        reboot_continuity_qualified=False,
        failed_restart_cleanup_qualified=False,
        snapshot_restore_qualified=False,
        fault_injection_verified=False,
    )
    try:
        require(guest.observed is not None, "guest-not-verified")
        assert guest.observed is not None
        before = copy.deepcopy(guest.observed)
        guest.validate(before)
        c = {
            "enrollment": guest.enrollment,
            "nonce": str(uuid.uuid4()),
            "sizes": {k.removesuffix(".qcow2"): v for k, v in DISK_BYTES.items()},
        }
        report["before_identity"] = before
        deadline = Deadline.after(300)
        with tempfile.TemporaryDirectory(prefix="fishhat-reboot-canary-", dir=temporary) as folder:
            canary = Path(folder) / "unrelated"
            content = uuid.uuid4().bytes
            canary.write_bytes(content)
            original = canary.lstat()
            try:
                with progress("reboot-prepare"), phase(report, "prepare") as p:
                    p["host_custody"] = host_custody(guest, endpoint, deadline)
                    p["observation"] = prepared = invoke(guest, before, c, "prepare", deadline, p)
                    c["identity"] = validate_canary(prepared, c)
                    c["image"] = prepared["observer"]["executable"]
                with progress("reboot-request"), phase(report, "request") as p:
                    p.update(command=REBOOT, outcome="unobserved", mutation_reissued=False)
                    try:
                        p["original_reply"] = guest.guarded(
                            REBOOT, guest.enrollment, before["boot_id"], deadline=deadline
                        )
                    except RuntimeError as error:
                        if not command_failed(error, 255):
                            raise
                        p["observed_exit_status"] = 255
                    else:
                        p.update(observed_exit_status=0, outcome="request-acknowledged")
                with progress("reboot-independent-boot"), phase(report, "independent-boot") as p:
                    if interrupt_observation:
                        require(guest.observed == before, "reboot-admission-changed-early")
                        p.update(
                            outcome="unobserved",
                            interruption_kind="controlled-controller-observer-exception",
                        )
                        report.update(
                            fault_injection_verified=True,
                            continuity_outcome="unobserved",
                        )
                        raise RebootObservationInterrupted()
                    p["identity"] = after = new_boot(guest, before, p, deadline)
                with (
                    progress("reboot-independent-canary"),
                    phase(report, "independent-canary") as p,
                ):
                    p["observation"] = observed = invoke(guest, after, c, "inspect", deadline, p)
                    validate_canary(observed, c)
                with progress("reboot-refusals"), phase(report, "refusals") as p:
                    p["refused"] = refuse_stale(guest, before, after, deadline)
                    p["observation"] = observed = invoke(guest, after, c, "inspect", deadline, p)
                    validate_canary(observed, c)
                with progress("reboot-final-observation"), phase(report, "final-observation") as p:
                    p["identity"] = fresh = guest.observe(deadline)
                    guest.validate_profile(fresh)
                    require(fresh == after, "reboot-identity-changed-again")
                    p["observation"] = observed = invoke(guest, fresh, c, "inspect", deadline, p)
                    validate_canary(observed, c)
                    p["host_custody"] = host_custody(guest, endpoint, deadline)
                    require(
                        p["host_custody"] == report["phases"][0]["host_custody"],
                        "reboot-host-custody-changed",
                    )
            finally:
                actual = canary.lstat()
                report["unrelated_host_canary_preserved"] = (
                    actual.st_dev,
                    actual.st_ino,
                    actual.st_mode,
                ) == (
                    original.st_dev,
                    original.st_ino,
                    original.st_mode,
                ) and canary.read_bytes() == content
                require(report["unrelated_host_canary_preserved"], "unrelated-host-canary-changed")
        # The new boot gains local admission only after all independent
        # identity/canary/custody and stale-command checks have passed.
        require(guest.observed == before, "reboot-admission-changed-early")
        guest.observed = copy.deepcopy(after)
        guest.report["identity"] = copy.deepcopy(after)
        report.update(after_identity=after, continuity_outcome="new-boot-observed-independently")
        report.update(status="passed", reboot_continuity_qualified=True)
    except OSError:
        raise GuestRebootError("reboot-observation-unavailable") from None
    finally:
        report["statistics"] = metrics.finish()
        if not valid_stats(report["statistics"]):
            report.update(status="failed", reboot_continuity_qualified=False)
            raise ValueError("invalid required reboot statistics")


def observe_removed_resources(
    custody: dict[str, Any], *, standalone: bool = False
) -> dict[str, Any]:
    """Read exact retained paths and IDs after their lifecycle owners cleaned up."""
    metrics = RunStats()
    result: dict[str, Any] = {"status": "failed", "paths": [], "process_group_absent": False}
    try:
        pid = custody["pid"]
        require(type(pid) is int and pid > 0 and custody["pgid"] == pid, "invalid-cleanup-process")
        for observe in (os.kill, os.killpg):
            try:
                observe(pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise GuestRebootError("cleanup-process-still-present")
        result.update(pid=pid, pgid=pid, process_absent=True, process_group_absent=True)
        inputs = Path(custody["input_directory"]["path"])
        private = Path(custody["private_directory"]["path"])
        endpoint = Path(custody["control_socket"]["path"])
        require(
            inputs.is_absolute()
            and private.is_absolute()
            and endpoint.is_absolute()
            and len({inputs, private, endpoint.parent}) == 3,
            "invalid-cleanup-directories",
        )
        files = []
        expected_disks = set(DISK_BYTES) if standalone else {"base.img", *DISK_BYTES}
        require(set(custody["disks"]) == expected_disks, "invalid-cleanup-disks")
        if standalone:
            require(
                custody.get("base_image_verified") is False
                and custody.get("private_inputs_verified") is True,
                "unverified-cleanup-profile",
            )
        require(bool(custody["private_files"]), "missing-cleanup-private-inputs")
        for parent, entries in ((inputs, custody["disks"]), (private, custody["private_files"])):
            for name, value in entries.items():
                path = Path(value["path"])
                require(path.parent == parent and path.name == name, "invalid-cleanup-file")
                files.append(path)
        for path in (*files, endpoint, inputs, private, endpoint.parent):
            try:
                path.lstat()
            except FileNotFoundError:
                result["paths"].append({"path": str(path), "absent": True})
            else:
                raise GuestRebootError("cleanup-owned-path-still-present")
        result["status"] = "passed"
        return result
    except OSError:
        raise GuestRebootError("cleanup-observation-unavailable") from None
    finally:
        result["statistics"] = metrics.finish()
        if not valid_stats(result["statistics"]):
            result["status"] = "failed"
            raise ValueError("invalid required reboot cleanup statistics")
