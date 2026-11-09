"""Observe an owned guest workload's admission, termination and kernel reaping."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
import uuid
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from scripts.native_linux_guest import Guest, GuestBootError
from scripts.run_stats import RunStats, valid_stats
from scripts.validation_timeouts import Deadline, current

REFUSALS = (
    "foreign-pid",
    "stale-start-ticks",
    "foreign-executable",
    "foreign-arguments",
    "foreign-actor",
    "foreign-enrollment",
    "stale-boot",
    "foreign-task",
)

# This fixed worker neither forks nor executes application code. Its readiness
# frame follows a durable progress write, then it waits within a finite budget.
WORKER = r"""
import os, pathlib, sys, time
path, token, seconds = sys.argv[1:]
frame = (token + "\n").encode()
fd = os.open(pathlib.Path(path) / "progress", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, "wb") as stream:
    stream.write(frame)
    stream.flush()
    os.fsync(stream.fileno())
os.write(1, frame)
time.sleep(float(seconds))
"""

# Executed only through Guest.guarded in the enrolled disposable VM. The caller
# supplies no arbitrary program, signal or target PID. The unreaped child and
# pidfd retain ownership even when a claimed identity is refused.
PROGRAM = r"""
import copy, errno, hashlib, json, os, pathlib, pwd, select, signal, stat, subprocess, sys, time, uuid
c = json.loads(sys.argv[1])
end = time.monotonic() + c["seconds"]
def require(value):
    if not value:
        raise ValueError("guest-process-refused")
def remaining(limit):
    value = limit - time.monotonic()
    require(value > 0)
    return value
def directory(path):
    v = path.lstat()
    require(stat.S_ISDIR(v.st_mode))
    return {"device": v.st_dev, "inode": v.st_ino, "uid": v.st_uid, "gid": v.st_gid, "mode": stat.S_IMODE(v.st_mode)}
def fixture():
    require(pathlib.Path("/etc/fishhat-fixture-enrollment").read_text().strip() == c["enrollment"])
    require(pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip() == c["boot_id"])
def stable(v):
    return (v.st_dev, v.st_ino, v.st_mode, v.st_uid, v.st_gid, v.st_nlink, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
def snapshot(path, expected, uid, gid):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        v = os.fstat(stream.fileno())
        require(stat.S_ISREG(v.st_mode) and v.st_nlink == 1 and v.st_uid == uid and v.st_gid == gid and stat.S_IMODE(v.st_mode) == 0o600)
        value = stream.read(len(expected) + 1)
        require(value == expected and stable(os.fstat(stream.fileno())) == stable(v))
    return {"device": v.st_dev, "inode": v.st_ino, "uid": uid, "gid": gid, "mode": 0o600, "sha256": hashlib.sha256(value).hexdigest()}
def executable(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o022)
        while block := stream.read(65536):
            remaining(end)
            value.update(block)
        require(stable(os.fstat(stream.fileno())) == stable(before))
    return {"path": os.readlink(path), "sha256": value.hexdigest()}
require(os.geteuid() == 0 and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL)
require(c["scenario"] in ("kill", "after-process-admission"))
require(str(uuid.UUID(c["enrollment"])) == c["enrollment"] and str(uuid.UUID(c["task"])) == c["task"])
fixture()
admin = pwd.getpwnam(c["admin"])
require({"uid": admin.pw_uid, "gid": admin.pw_gid} == c["actor"] and admin.pw_uid >= 1000)
require(hasattr(os, "pidfd_open") and hasattr(os, "P_PIDFD") and hasattr(signal, "pidfd_send_signal"))
root = pathlib.Path("/run/fhs-" + uuid.UUID(c["enrollment"]).hex)
require(directory(root) == c["state"]["root"])
for role in ("control", "data"):
    require(directory(root / role) == c["state"][role]["directory"])
def canaries():
    return {role: snapshot(root / role / "canary", (role + ":" + c["enrollment"] + "\n" + ("admin-write\n" if role == "data" else "")).encode(), *( (0, 0) if role == "control" else (admin.pw_uid, admin.pw_gid))) for role in ("control", "data")}
before = canaries()
trusted_executable = executable("/proc/self/exe")
require(trusted_executable["path"] == "/usr/bin/python3.12")
task = root / "data" / ("process-" + uuid.UUID(c["task"]).hex)
task.mkdir(mode=0o700)
os.chown(task, admin.pw_uid, admin.pw_gid)
arguments = ["/usr/bin/python3", "-I", "-S", "-c", c["worker"], str(task), c["task"], str(c["seconds"] + c["cleanup_seconds"])]
argv = b"\0".join(value.encode() for value in arguments) + b"\0"
child = None
handle = None
admitted = None
requested = False
injected = False
refusals = []
progress = None
termination = None
class Injected(Exception):
    pass
def exited():
    return os.waitid(os.P_PIDFD, handle, os.WEXITED | os.WNOHANG | os.WNOWAIT)
def identity():
    fixture()
    require(exited() is None)
    info = dict(line.split(":", 1) for line in pathlib.Path("/proc/self/fdinfo/" + str(handle)).read_text().splitlines())
    require(int(info["Pid"]) == child.pid)
    base = pathlib.Path("/proc/" + str(child.pid))
    fields = (base / "stat").read_text().rpartition(")")[2].split()
    require(int(fields[1]) == os.getpid() and int(fields[2]) == int(fields[3]) == child.pid)
    status = dict(line.split(":", 1) for line in (base / "status").read_text().splitlines())
    require([int(v) for v in status["Uid"].split()] == [admin.pw_uid] * 4)
    require([int(v) for v in status["Gid"].split()] == [admin.pw_gid] * 4)
    require(not status["Groups"].split())
    require((base / "cmdline").read_bytes() == argv)
    image = executable(str(base / "exe"))
    require(image == trusted_executable)
    return {"pid": child.pid, "parent_pid": os.getpid(), "process_group": int(fields[2]), "session": int(fields[3]), "start_ticks": int(fields[19]), "uid": admin.pw_uid, "gid": admin.pw_gid, "executable": image, "arguments_sha256": hashlib.sha256(argv).hexdigest(), "enrollment": c["enrollment"], "boot_id": c["boot_id"], "task": c["task"]}
def kill_target(claim):
    require(claim == admitted and identity() == admitted)
    signal.pidfd_send_signal(handle, signal.SIGKILL)
def readiness():
    frame = (c["task"] + "\n").encode()
    value = b""
    while len(value) < len(frame):
        require(select.select([child.stdout], [], [], remaining(end))[0])
        part = os.read(child.stdout.fileno(), len(frame) - len(value))
        require(part)
        value += part
    require(value == frame)
def challenge():
    changes = {
        "foreign-pid": ("pid", os.getpid()),
        "stale-start-ticks": ("start_ticks", admitted["start_ticks"] + 1),
        "foreign-executable": ("executable", {"path": "/foreign", "sha256": "0" * 64}),
        "foreign-arguments": ("arguments_sha256", "0" * 64),
        "foreign-actor": ("uid", 0),
        "foreign-enrollment": ("enrollment", str(uuid.uuid4())),
        "stale-boot": ("boot_id", str(uuid.uuid4())),
        "foreign-task": ("task", str(uuid.uuid4())),
    }
    for name, (key, value) in changes.items():
        claim = copy.deepcopy(admitted)
        claim[key] = value
        try:
            kill_target(claim)
        except ValueError:
            require(identity() == admitted)
            refusals.append(name)
        else:
            raise ValueError("guest-process-unexpectedly-signaled")
def reap():
    global handle
    if handle is None:
        # Popen's own child has never been reaped, so its PID cannot be reused.
        handle = os.pidfd_open(child.pid, 0)
    cleanup_kill = exited() is None
    if cleanup_kill:
        signal.pidfd_send_signal(handle, signal.SIGKILL)
    limit = time.monotonic() + c["cleanup_seconds"]
    require(select.select([handle], [], [], remaining(limit))[0])
    value = exited()
    require(value is not None and value.si_pid == child.pid)
    result = child.wait(timeout=remaining(limit))
    require(value.si_code == os.CLD_KILLED and value.si_status == signal.SIGKILL and result == -signal.SIGKILL)
    try:
        signal.pidfd_send_signal(handle, 0)
    except ProcessLookupError as error:
        require(error.errno == errno.ESRCH)
    else:
        raise ValueError("guest-stale-handle-accepted")
    return {"pid": child.pid, "code": "CLD_KILLED", "signal": signal.SIGKILL, "returncode": result, "reaped": True, "stale_handle_refused": True, "cleanup_kill": cleanup_kill}
try:
    child = subprocess.Popen(arguments, user=admin.pw_uid, group=admin.pw_gid, extra_groups=[], umask=0o077, start_new_session=True, cwd=task, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    handle = os.pidfd_open(child.pid, 0)
    readiness()
    progress = snapshot(task / "progress", (c["task"] + "\n").encode(), admin.pw_uid, admin.pw_gid)
    admitted = identity()
    challenge()
    require(identity() == admitted)
    if c["scenario"] == "after-process-admission":
        injected = True
        raise Injected()
    kill_target(admitted)
    requested = True
    require(select.select([handle], [], [], remaining(end))[0])
except Injected:
    pass
finally:
    try:
        if child is not None:
            termination = reap()
    finally:
        if child is not None and child.stdout is not None:
            child.stdout.close()
        if handle is not None:
            os.close(handle)
require(canaries() == before)
require(progress == snapshot(task / "progress", (c["task"] + "\n").encode(), admin.pw_uid, admin.pw_gid))
print(json.dumps({"scenario": c["scenario"], "status": "failed" if injected else "passed", "enrollment": c["enrollment"], "boot_id": c["boot_id"], "task": c["task"], "identity": admitted, "progress": progress, "refusals_verified": refusals, "requested_kill": requested, "setup_failure_injected": injected, "termination": termination, "guest_canaries_preserved": True, "task_resources_retained_for_guest_cleanup": True}, sort_keys=True))
"""


class GuestProcessError(GuestBootError):
    stage = "guest-process"


def positive_integer(value: Any) -> bool:
    return type(value) is int and value > 0


def sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def arguments_sha256(c: dict[str, Any]) -> str:
    task = (
        "/run/fhs-" + uuid.UUID(c["enrollment"]).hex + "/data/process-" + uuid.UUID(c["task"]).hex
    )
    arguments = [
        "/usr/bin/python3",
        "-I",
        "-S",
        "-c",
        WORKER,
        task,
        c["task"],
        str(c["seconds"] + c["cleanup_seconds"]),
    ]
    return hashlib.sha256(b"\0".join(v.encode() for v in arguments) + b"\0").hexdigest()


def validate(value: Any, c: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GuestProcessError("invalid-process-observation")
    expected = {
        "scenario": c["scenario"],
        "status": "passed" if c["scenario"] == "kill" else "failed",
        "enrollment": c["enrollment"],
        "boot_id": c["boot_id"],
        "task": c["task"],
        "refusals_verified": list(REFUSALS),
        "requested_kill": c["scenario"] == "kill",
        "setup_failure_injected": c["scenario"] != "kill",
        "guest_canaries_preserved": True,
        "task_resources_retained_for_guest_cleanup": True,
    }
    if set(value) != {*expected, "identity", "progress", "termination"} or any(
        type(value.get(key)) is not type(want) or value[key] != want
        for key, want in expected.items()
    ):
        raise GuestProcessError("process-outcome-mismatch")
    identity = value["identity"]
    if not isinstance(identity, dict) or set(identity) != {
        "pid",
        "parent_pid",
        "process_group",
        "session",
        "start_ticks",
        "uid",
        "gid",
        "executable",
        "arguments_sha256",
        "enrollment",
        "boot_id",
        "task",
    }:
        raise GuestProcessError("process-identity-mismatch")
    if (
        not all(
            positive_integer(identity[key])
            for key in (
                "pid",
                "parent_pid",
                "process_group",
                "session",
                "start_ticks",
                "uid",
                "gid",
            )
        )
        or identity["pid"] == identity["parent_pid"]
        or identity["process_group"] != identity["pid"]
        or identity["session"] != identity["pid"]
        or any(identity[key] != c[key] for key in ("enrollment", "boot_id", "task"))
        or any(identity[key] != c["actor"][key] for key in ("uid", "gid"))
        or not isinstance(identity["executable"], dict)
        or set(identity["executable"]) != {"path", "sha256"}
        or identity["executable"]["path"] != "/usr/bin/python3.12"
        or not sha256(identity["executable"]["sha256"])
        or identity["arguments_sha256"] != arguments_sha256(c)
    ):
        raise GuestProcessError("process-identity-mismatch")
    progress = value["progress"]
    if (
        not isinstance(progress, dict)
        or set(progress) != {"device", "inode", "uid", "gid", "mode", "sha256"}
        or not all(positive_integer(progress[key]) for key in ("device", "inode"))
        or any(
            type(progress[key]) is not int or progress[key] != c["actor"][key]
            for key in ("uid", "gid")
        )
        or type(progress["mode"]) is not int
        or progress["mode"] != 0o600
        or progress["device"] != c["state"]["data"]["directory"]["device"]
        or progress["sha256"] != hashlib.sha256((c["task"] + "\n").encode()).hexdigest()
    ):
        raise GuestProcessError("process-progress-mismatch")
    termination = value["termination"]
    expected_termination = {
        "pid": identity["pid"],
        "code": "CLD_KILLED",
        "signal": 9,
        "returncode": -9,
        "reaped": True,
        "stale_handle_refused": True,
    }
    if (
        not isinstance(termination, dict)
        or set(termination) != {*expected_termination, "cleanup_kill"}
        or any(
            type(termination.get(key)) is not type(want) or termination[key] != want
            for key, want in expected_termination.items()
        )
        or type(termination["cleanup_kill"]) is not bool
        or termination["cleanup_kill"] is not (c["scenario"] != "kill")
    ):
        raise GuestProcessError("process-termination-mismatch")
    return value


def configuration(guest: Guest, scenario: str, deadline: Deadline) -> dict[str, Any]:
    if guest.observed is None:
        raise GuestProcessError("guest-not-verified")
    storage = guest.report.get("storage", {})
    if storage.get("status") != "passed" or storage.get("permissions_verified") is not True:
        raise GuestProcessError("storage-not-verified")
    c = {
        "scenario": scenario,
        "task": str(uuid.uuid4()),
        "enrollment": guest.enrollment,
        "boot_id": guest.observed["boot_id"],
        "admin": guest.accounts[0],
        "actor": guest.observed["accounts"][guest.accounts[0]],
        "state": storage["filesystems"],
        "worker": WORKER,
        "seconds": min(current().seconds(45), deadline.remaining() - current().seconds(5)),
        "cleanup_seconds": current().seconds(5),
    }
    if c["seconds"] <= 0:
        raise GuestProcessError("process-deadline")
    return c


def process_case(guest: Guest, scenario: str, deadline: Deadline, case: dict[str, Any]) -> None:
    metrics = RunStats()
    try:
        c = configuration(guest, scenario, deadline)
        result = guest.guarded(
            ["/usr/bin/python3", "-I", "-S", "-c", PROGRAM, json.dumps(c, sort_keys=True)],
            guest.enrollment,
            c["boot_id"],
            deadline=deadline,
            nominal=60,
        )
        try:
            value = json.loads(result)
        except (ValueError, RecursionError):
            raise GuestProcessError("invalid-process-observation") from None
        case.update(validate(value, c))
    finally:
        case["statistics"] = metrics.finish()
        if not valid_stats(case["statistics"]):
            raise ValueError("invalid required guest process statistics")


def qualify_process_kill(
    guest: Guest,
    progress: Callable[[str], AbstractContextManager[None]],
    temporary: Path,
    report: dict[str, Any],
) -> None:
    metrics = RunStats()
    report.update(
        status="failed",
        scope="disposable-guest-owned-process-kill-only",
        enrollment=guest.enrollment,
        resources_destroyed_with_guest=False,
        unrelated_host_canary_preserved=False,
        cases=[],
    )
    try:
        deadline = Deadline.after(180)
        with tempfile.TemporaryDirectory(prefix="fishhat-process-canary-", dir=temporary) as name:
            canary = Path(name) / "unrelated"
            content = uuid.uuid4().bytes
            canary.write_bytes(content)
            before = canary.lstat()
            try:
                for scenario in ("kill", "after-process-admission"):
                    with progress("process-" + scenario):
                        case: dict[str, Any] = {"scenario": scenario, "status": "failed"}
                        report["cases"].append(case)
                        process_case(guest, scenario, deadline, case)
            finally:
                after = canary.lstat()
                report["unrelated_host_canary_preserved"] = (
                    before.st_dev,
                    before.st_ino,
                    before.st_mode,
                ) == (after.st_dev, after.st_ino, after.st_mode) and canary.read_bytes() == content
                if not report["unrelated_host_canary_preserved"]:
                    raise GuestProcessError("unrelated-host-canary-changed")
        report["status"] = "passed"
    except OSError:
        raise GuestProcessError("process-observation-unavailable") from None
    finally:
        report["statistics"] = metrics.finish()
        if not valid_stats(report["statistics"]):
            raise ValueError("invalid required guest process statistics")
