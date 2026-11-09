"""Observe owned SSH loss separately from independently managed guest work."""

from __future__ import annotations

import copy
import errno
import hashlib
import json
import os
import re
import select
import signal
import subprocess
import tempfile
import uuid
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil

from scripts.native_linux_guest import Guest, GuestBootError
from scripts.native_linux_processes import positive_integer, sha256
from scripts.run_stats import RunStats, valid_stats
from scripts.validation_timeouts import Deadline, current, watchdog

# A fixed fixture workload, independently parented by the guest service manager.
# The root-owned gate controls progress; transport loss is not a cancellation.
WORKER = r"""
import os, pathlib, stat, sys, time
path, token, seconds = sys.argv[1:]
root = pathlib.Path(path)
end = time.monotonic() + float(seconds)
fd = os.open(root / "progress", os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
with os.fdopen(fd, "wb") as stream:
    stream.write(("started:" + token + "\n").encode())
    stream.flush()
    os.fsync(stream.fileno())
    while True:
        if time.monotonic() >= end:
            raise TimeoutError("fixture-work-deadline")
        try:
            fd = os.open(root / "advance", os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            time.sleep(min(0.05, end - time.monotonic()))
            continue
        with os.fdopen(fd, "rb") as gate:
            v = os.fstat(gate.fileno())
            assert stat.S_ISREG(v.st_mode) and v.st_uid == v.st_gid == 0 and stat.S_IMODE(v.st_mode) == 0o444
            assert gate.read(len(token) + 2) == (token + "\n").encode()
        break
    stream.write(("continued:" + token + "\ncompleted:" + token + "\n").encode())
    stream.flush()
    os.fsync(stream.fileno())
"""

# Root fixture control is reached only through Guest.remote's full identity guard.
# All mutations are confined to one fresh task and its exact transient invocation.
PROGRAM = r"""
import hashlib, json, os, pathlib, pwd, re, select, stat, subprocess, sys, time, uuid
PROPERTIES = ("Id", "Transient", "Type", "RemainAfterExit", "User", "Group", "MainPID", "ExecMainPID", "InvocationID", "ControlGroup", "ActiveState", "SubState", "Result", "ExecMainCode", "ExecMainStatus")
def require(value):
    if not value:
        raise ValueError("guest-transport-refused")
def remaining():
    value = end - time.monotonic()
    require(value > 0)
    return value
def directory(path):
    v = path.lstat()
    require(stat.S_ISDIR(v.st_mode))
    return {"device": v.st_dev, "inode": v.st_ino, "uid": v.st_uid, "gid": v.st_gid, "mode": stat.S_IMODE(v.st_mode)}
def stable(v):
    return (v.st_dev, v.st_ino, v.st_mode, v.st_uid, v.st_gid, v.st_nlink, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
def read_file(path, uid, gid, mode, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        v = os.fstat(stream.fileno())
        require(stat.S_ISREG(v.st_mode) and v.st_nlink == 1 and v.st_uid == uid and v.st_gid == gid and stat.S_IMODE(v.st_mode) == mode)
        value = stream.read(maximum + 1)
        require(len(value) <= maximum and stable(v) == stable(os.fstat(stream.fileno())))
    return value, {"device": v.st_dev, "inode": v.st_ino, "uid": uid, "gid": gid, "mode": mode, "sha256": hashlib.sha256(value).hexdigest()}
def write_file(path, content, uid=0, gid=0, mode=0o600):
    remaining()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        os.fchown(stream.fileno(), uid, gid)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
def command(arguments):
    return subprocess.run(arguments, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}, text=True, timeout=remaining()).stdout
def units():
    return command(["/usr/bin/systemctl", "list-units", "--all", "--full", "--plain", "--no-legend", "--no-pager", unit]).strip()
def properties():
    text = command(["/usr/bin/systemctl", "show", "--no-pager", "--property=" + ",".join(PROPERTIES), unit])
    rows = [line.split("=", 1) for line in text.splitlines()]
    require(all(len(row) == 2 for row in rows))
    value = dict(rows)
    require(len(rows) == len(value) and set(value) == set(PROPERTIES))
    require(value["Id"] == unit and value["Transient"] == value["RemainAfterExit"] == "yes" and value["Type"] == "exec")
    require(value["User"] == c["admin"] and value["Group"] == str(admin.pw_gid))
    require(re.fullmatch("[a-f0-9]{32}", value["InvocationID"]) is not None)
    return value
def image(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o022)
        while block := stream.read(65536):
            remaining()
            h.update(block)
        require(stable(before) == stable(os.fstat(stream.fileno())))
    return {"path": os.readlink(path), "sha256": h.hexdigest()}
def process(pid):
    base = pathlib.Path("/proc/" + str(pid))
    fields = (base / "stat").read_text().rpartition(")")[2].split()
    status = dict(line.split(":", 1) for line in (base / "status").read_text().splitlines())
    return {"pid": pid, "parent_pid": int(fields[1]), "start_ticks": int(fields[19]), "uids": [int(v) for v in status["Uid"].split()], "gids": [int(v) for v in status["Gid"].split()], "groups": sorted(int(v) for v in status["Groups"].split()), "executable": image(str(base / "exe")), "arguments_sha256": hashlib.sha256((base / "cmdline").read_bytes()).hexdigest(), "cgroups": (base / "cgroup").read_text().splitlines()}
def arguments():
    return ["/usr/bin/python3", "-I", "-S", "-c", c["worker"], str(task), c["task"], str(c["runtime_seconds"])]
def admit_work(value):
    pid = int(value["MainPID"])
    require(pid > 1 and value["ExecMainPID"] == str(pid) and value["ActiveState"] == "active" and value["SubState"] == "running")
    observed = process(pid)
    expected_argv = hashlib.sha256(b"\0".join(v.encode() for v in arguments()) + b"\0").hexdigest()
    require(observed["parent_pid"] == 1 and observed["uids"] == [admin.pw_uid] * 4 and observed["gids"] == [admin.pw_gid] * 4)
    require(observed["groups"] == sorted(os.getgrouplist(c["admin"], admin.pw_gid)))
    require(observed["executable"] == image("/proc/self/exe") and observed["executable"]["path"] == "/usr/bin/python3.12" and observed["arguments_sha256"] == expected_argv)
    require(value["ControlGroup"] == "/system.slice/" + unit and observed["cgroups"] == ["0::" + value["ControlGroup"]])
    return {"unit": unit, "invocation": value["InvocationID"], "process": observed, "enrollment": c["enrollment"], "boot_id": c["boot_id"], "task": c["task"]}
def canaries():
    result = {}
    for role in ("control", "data"):
        expected = (role + ":" + c["enrollment"] + "\n" + ("admin-write\n" if role == "data" else "")).encode()
        uid, gid = (0, 0) if role == "control" else (admin.pw_uid, admin.pw_gid)
        value, identity = read_file(root / role / "canary", uid, gid, 0o600, len(expected))
        require(value == expected)
        result[role] = identity
    return result
def progress():
    started = ("started:" + c["task"] + "\n").encode()
    completed = started + ("continued:" + c["task"] + "\ncompleted:" + c["task"] + "\n").encode()
    value, identity = read_file(task / "progress", admin.pw_uid, admin.pw_gid, 0o600, len(completed))
    require(value in (b"", started, completed))
    return {"stage": "completed" if value == completed else "started" if value == started else "pending", "file": identity}
def gate(name):
    expected = (c["task"] + "\n").encode()
    try:
        value, identity = read_file(task / name, 0, 0, 0o444, len(expected))
    except FileNotFoundError:
        pending = task / (name + "-pending")
        write_file(pending, expected, mode=0o444)
        os.link(pending, task / name, follow_symlinks=False)
        pending.unlink()
        fd = os.open(task, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        value, identity = read_file(task / name, 0, 0, 0o444, len(expected))
    require(value == expected)
    return identity
def initialize(config):
    global c, end, root, task, unit, admin
    c = config
    end = time.monotonic() + c["seconds"]
    require(os.geteuid() == 0)
    for name in ("enrollment", "boot_id", "task"):
        require(str(uuid.UUID(c[name])) == c[name])
    require(pathlib.Path("/etc/fishhat-fixture-enrollment").read_text().strip() == c["enrollment"])
    require(pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip() == c["boot_id"])
    admin = pwd.getpwnam(c["admin"])
    require(admin.pw_uid >= 1000 and {"uid": admin.pw_uid, "gid": admin.pw_gid} == c["actor"])
    root = pathlib.Path("/run/fhs-" + uuid.UUID(c["enrollment"]).hex)
    require(directory(root) == c["state"]["root"])
    for role in ("control", "data"):
        require(directory(root / role) == c["state"][role]["directory"])
    task = root / "data" / ("transport-" + uuid.UUID(c["task"]).hex)
    unit = "fht-" + uuid.UUID(c["task"]).hex + ".service"
    canaries()
def start():
    global end
    require(not units())
    task.mkdir(mode=0o755)
    task.chmod(0o755)
    write_file(task / "progress", b"", admin.pw_uid, admin.pw_gid)
    identity = None
    published = False
    try:
        command([
            '/usr/bin/systemd-run',
            '--quiet',
            '--no-ask-password',
            '--expand-environment=no',
            '--unit=' + unit,
            '--property=Type=exec',
            '--remain-after-exit',
            '--uid=' + c['admin'],
            '--gid=' + str(admin.pw_gid),
            '--property=NoNewPrivileges=yes',
            '--property=KillMode=control-group',
            '--property=RuntimeMaxSec=' + str(c['runtime_seconds']),
            '--property=TimeoutStopSec=' + str(c['cleanup_seconds']),
            '--',
            *arguments(),
        ])
        identity = admit_work(properties())
        while progress()["stage"] != "started":
            time.sleep(min(0.05, remaining()))
        require(admit_work(properties()) == identity)
        # This fixed-schema private frame has no application-controlled fields.
        manifest = {"identity": identity, "directory": directory(task), "origin": process(os.getpid()), "canaries": canaries()}
        write_file(task / "manifest", json.dumps(manifest, sort_keys=True).encode())
        os.write(1, (c["task"] + "\n").encode())
        published = True
        while not (task / "release-origin").exists():
            time.sleep(min(0.05, remaining()))
        expected = (c["task"] + "\n").encode()
        require(read_file(task / "release-origin", 0, 0, 0o444, len(expected))[0] == expected)
    finally:
        if not published and identity is not None:
            end = time.monotonic() + c["cleanup_seconds"]
            require(properties()["InvocationID"] == identity["invocation"])
            command(["/usr/bin/systemctl", "stop", unit])
def manifest():
    value, unused = read_file(task / "manifest", 0, 0, 0o600, 32768)
    result = json.loads(value)
    require(set(result) == {"identity", "directory", "origin", "canaries"})
    require(directory(task) == result["directory"] and result["directory"]["uid"] == result["directory"]["gid"] == 0 and result["directory"]["mode"] == 0o755)
    require(result["canaries"] == canaries())
    return result
def observation(saved):
    value = properties()
    while value["SubState"] == "running" and (task / "advance").exists():
        time.sleep(min(0.05, remaining()))
        value = properties()
    identity = saved["identity"]
    require(identity["unit"] == unit and identity["invocation"] == value["InvocationID"])
    require(all(identity[name] == c[name] for name in ("enrollment", "boot_id", "task")))
    require(int(value["ExecMainPID"]) == identity["process"]["pid"])
    work = progress()
    if value["SubState"] == "running":
        require(admit_work(value) == identity and work["stage"] == "started")
        outcome = "running"
    else:
        require(value["ActiveState"] == "active" and value["SubState"] == "exited" and value["MainPID"] == "0")
        require(value["Result"] == "success" and value["ExecMainCode"] == "1" and value["ExecMainStatus"] == "0" and work["stage"] == "completed")
        outcome = "completed-successfully"
    return {"identity": identity, "outcome": outcome, "progress": work, "service": value, "guest_canaries_preserved": True}
def origin_gone(saved):
    original = saved["origin"]
    try:
        handle = os.pidfd_open(original["pid"], 0)
    except ProcessLookupError:
        return True
    try:
        if select.select([handle], [], [], 0)[0]:
            return True
        try:
            observed = process(original["pid"])
        except (FileNotFoundError, ProcessLookupError):
            require(select.select([handle], [], [], 0)[0])
            return True
        if observed["start_ticks"] != original["start_ticks"]:
            return True
        require(observed == original)
        return False
    finally:
        os.close(handle)
def cleanup_result(saved):
    require(not units() and origin_gone(saved))
    require(not pathlib.Path("/sys/fs/cgroup/system.slice", unit).exists())
    return {"identity": saved["identity"], "unit_removed": True, "origin_exited": True, "guest_canaries_preserved": canaries() == saved["canaries"], "task_resources_retained_for_guest_cleanup": True}
def control(mode, claim):
    saved = manifest()
    if mode == "cleanup" and claim == saved["identity"] and not units():
        return cleanup_result(saved)
    before = observation(saved)
    if mode in ("advance", "cleanup") and claim != saved["identity"]:
        return {"refused": True, "outcome": before["outcome"], "identity": saved["identity"]}
    if mode == "advance":
        gate("advance")
        return {"accepted": True, "identity": saved["identity"], "gate": "advance"}
    if mode == "finish":
        while before["outcome"] != "completed-successfully":
            time.sleep(min(0.05, remaining()))
            before = observation(saved)
    elif mode == "cleanup":
        gate("release-origin")
        while not origin_gone(saved):
            time.sleep(min(0.05, remaining()))
        require(properties()["InvocationID"] == claim["invocation"])
        command(["/usr/bin/systemctl", "stop", unit])
        while units():
            time.sleep(min(0.05, remaining()))
        return cleanup_result(saved)
    else:
        require(mode == "observe")
    return before
if __name__ == "__main__":
    config, mode, claim = sys.argv[1:]
    initialize(json.loads(config))
    if mode == "start":
        start()
    else:
        print(json.dumps(control(mode, json.loads(claim)), sort_keys=True))
"""


class GuestTransportError(GuestBootError):
    stage = "guest-transport"


def require(value: Any, reason: str) -> None:
    if not value:
        raise GuestTransportError(reason)


def remaining(deadline: Deadline) -> float:
    value = deadline.remaining()
    require(value > 0, "transport-deadline")
    return value


def file_digest(path: Path, deadline: Deadline) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        while block := stream.read(65536):
            remaining(deadline)
            value.update(block)
        after = os.fstat(stream.fileno())
    require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
        "transport-executable-changed",
    )
    return value.hexdigest()


def argv_hash(arguments: list[str]) -> str:
    return hashlib.sha256(b"\0".join(v.encode() for v in arguments) + b"\0").hexdigest()


@dataclass
class Client:
    guest: Guest
    process: subprocess.Popen[bytes]
    handle: int
    arguments: list[str]
    deadline: Deadline

    def exited(self) -> Any:
        return os.waitid(os.P_PIDFD, self.handle, os.WEXITED | os.WNOHANG | os.WNOWAIT)

    def identity(self) -> dict[str, Any]:
        require(self.exited() is None, "transport-not-active")
        self.guest.listener()
        if self.guest.verify_process is None:
            raise GuestTransportError("owned-guest-unavailable")
        self.guest.verify_process(self.deadline)
        self.guest.verify_tools()
        info = dict(
            line.split(":", 1)
            for line in Path(f"/proc/self/fdinfo/{self.handle}").read_text().splitlines()
        )
        require(int(info["Pid"]) == self.process.pid, "transport-handle-mismatch")
        base = Path(f"/proc/{self.process.pid}")
        fields = (base / "stat").read_text().rpartition(")")[2].split()
        require(int(fields[1]) == os.getpid(), "transport-parent-mismatch")
        require(int(fields[2]) == int(fields[3]) == self.process.pid, "transport-session-mismatch")
        actor = dict(line.split(":", 1) for line in (base / "status").read_text().splitlines())
        require(
            [int(v) for v in actor["Uid"].split()] == [os.geteuid()] * 4
            and [int(v) for v in actor["Gid"].split()] == [os.getegid()] * 4,
            "transport-actor-mismatch",
        )
        require(
            os.readlink(base / "exe") == "/usr/bin/ssh"
            and file_digest(base / "exe", self.deadline) == self.guest.tools["sha256"]["ssh"]
            and (base / "cmdline").read_bytes()
            == b"\0".join(v.encode() for v in self.arguments) + b"\0",
            "transport-executable-or-arguments-mismatch",
        )
        sockets = psutil.Process(self.process.pid).net_connections(kind="tcp")
        require(len(sockets) == 1, "transport-connection-mismatch")
        connection = sockets[0]
        require(
            connection.status == psutil.CONN_ESTABLISHED
            and connection.laddr.ip == "127.0.0.1"
            and 0 < connection.laddr.port < 65536
            and connection.raddr.ip == "127.0.0.1"
            and connection.raddr.port == self.guest.port,
            "transport-connection-mismatch",
        )
        return {
            "pid": self.process.pid,
            "parent_pid": os.getpid(),
            "start_ticks": int(fields[19]),
            "uid": os.geteuid(),
            "gid": os.getegid(),
            "executable_sha256": self.guest.tools["sha256"]["ssh"],
            "arguments_sha256": argv_hash(self.arguments),
            "enrollment": self.guest.enrollment,
            "local_port": connection.laddr.port,
            "guest_port": self.guest.port,
        }

    def readiness(self, token: str) -> None:
        frame = (token + "\n").encode()
        value = b""
        if self.process.stdout is None:
            raise GuestTransportError("transport-output-unavailable")
        while len(value) < len(frame):
            require(
                select.select([self.process.stdout], [], [], remaining(self.deadline))[0],
                "transport-progress-unavailable",
            )
            part = os.read(self.process.stdout.fileno(), len(frame) - len(value))
            require(part, "transport-progress-unavailable")
            value += part
        require(value == frame, "transport-progress-mismatch")

    def break_transport(self, claim: dict[str, Any], admitted: dict[str, Any]) -> None:
        require(claim == admitted and self.identity() == admitted, "transport-claim-mismatch")
        remaining(self.deadline)
        signal.pidfd_send_signal(self.handle, signal.SIGKILL)
        require(
            select.select([self.handle], [], [], remaining(self.deadline))[0],
            "transport-not-exited",
        )

    def reap(self) -> dict[str, Any]:
        cleanup_kill = self.exited() is None
        if cleanup_kill:
            signal.pidfd_send_signal(self.handle, signal.SIGKILL)
        grace = Deadline.after(5)
        require(select.select([self.handle], [], [], remaining(grace))[0], "transport-not-exited")
        value = self.exited()
        result = self.process.wait(timeout=grace.remaining())
        require(
            value is not None
            and value.si_pid == self.process.pid
            and value.si_code == os.CLD_KILLED
            and value.si_status == signal.SIGKILL,
            "transport-termination-mismatch",
        )
        require(result == -9, "transport-not-reaped")
        try:
            signal.pidfd_send_signal(self.handle, 0)
        except ProcessLookupError as error:
            require(error.errno == errno.ESRCH, "transport-stale-handle-error")
        else:
            raise GuestTransportError("transport-stale-handle-accepted")
        return {
            "pid": self.process.pid,
            "code": "CLD_KILLED",
            "signal": 9,
            "returncode": -9,
            "reaped": True,
            "stale_handle_refused": True,
            "cleanup_kill": cleanup_kill,
        }


@contextmanager
def owned_client(guest: Guest, arguments: list[str], deadline: Deadline) -> Iterator[Client]:
    process = subprocess.Popen(
        arguments,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        umask=0o077,
    )
    handle: int | None = None
    client: Client | None = None
    try:
        handle = os.pidfd_open(process.pid, 0)
        client = Client(guest, process, handle, arguments, deadline)
        yield client
    finally:
        try:
            if process.returncode is None:
                if client is not None:
                    client.reap()
                else:
                    # The unreaped child cannot have had its PID reused.
                    process.kill()
                    process.wait(timeout=watchdog(5))
        finally:
            if process.stdout is not None:
                process.stdout.close()
            if handle is not None:
                os.close(handle)


def action(c: dict[str, Any], mode: str, claim: Any = None) -> list[str]:
    return [
        "/usr/bin/python3",
        "-I",
        "-S",
        "-c",
        PROGRAM,
        json.dumps(c, sort_keys=True),
        mode,
        json.dumps(claim, sort_keys=True),
    ]


def observe(
    guest: Guest, c: dict[str, Any], mode: str, deadline: Deadline, claim: Any = None
) -> dict[str, Any]:
    config = {**c, "seconds": remaining(deadline)}
    text = guest.guarded(
        action(config, mode, claim),
        c["enrollment"],
        c["boot_id"],
        deadline=deadline,
        nominal=90,
    )
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        raise GuestTransportError("invalid-transport-observation") from None
    if not isinstance(value, dict):
        raise GuestTransportError("invalid-transport-observation")
    return value


def validate_observation(value: dict[str, Any], c: dict[str, Any]) -> dict[str, Any]:
    require(
        set(value) == {"identity", "outcome", "progress", "service", "guest_canaries_preserved"}
        and value["guest_canaries_preserved"] is True
        and value["outcome"] in {"running", "completed-successfully"},
        "work-observation-mismatch",
    )
    identity = value["identity"]
    if not isinstance(identity, dict):
        raise GuestTransportError("work-identity-mismatch")
    require(
        isinstance(identity, dict)
        and set(identity) == {"unit", "invocation", "process", "enrollment", "boot_id", "task"}
        and identity["unit"] == "fht-" + uuid.UUID(c["task"]).hex + ".service"
        and isinstance(identity["invocation"], str)
        and re.fullmatch(r"[a-f0-9]{32}", identity["invocation"]) is not None
        and all(identity[name] == c[name] for name in ("enrollment", "boot_id", "task")),
        "work-identity-mismatch",
    )
    process = identity["process"]
    require(
        isinstance(process, dict)
        and set(process)
        == {
            "pid",
            "parent_pid",
            "start_ticks",
            "uids",
            "gids",
            "groups",
            "executable",
            "arguments_sha256",
            "cgroups",
        }
        and positive_integer(process["pid"])
        and positive_integer(process["start_ticks"])
        and type(process["parent_pid"]) is int
        and process["parent_pid"] == 1
        and process["uids"] == [c["actor"]["uid"]] * 4
        and process["gids"] == [c["actor"]["gid"]] * 4
        and isinstance(process["groups"], list)
        and all(type(v) is int and v >= 0 for v in process["groups"])
        and process["cgroups"] == ["0::/system.slice/" + identity["unit"]]
        and isinstance(process["executable"], dict)
        and set(process["executable"]) == {"path", "sha256"}
        and process["executable"]["path"] == "/usr/bin/python3.12"
        and sha256(process["executable"]["sha256"])
        and process["arguments_sha256"] == work_arguments_hash(c),
        "work-process-mismatch",
    )
    validate_outcome(value, c)
    return identity


def work_arguments_hash(c: dict[str, Any]) -> str:
    task = (
        "/run/fhs-" + uuid.UUID(c["enrollment"]).hex + "/data/transport-" + uuid.UUID(c["task"]).hex
    )
    return argv_hash(
        ["/usr/bin/python3", "-I", "-S", "-c", WORKER, task, c["task"], str(c["runtime_seconds"])]
    )


def validate_outcome(value: dict[str, Any], c: dict[str, Any]) -> None:
    completed = value["outcome"] == "completed-successfully"
    progress = value["progress"]
    service = value["service"]
    require(
        isinstance(progress, dict) and set(progress) == {"stage", "file"}, "work-progress-mismatch"
    )
    expected = "started:" + c["task"] + "\n"
    if completed:
        expected += "continued:" + c["task"] + "\ncompleted:" + c["task"] + "\n"
    file = progress["file"]
    require(
        progress["stage"] == ("completed" if completed else "started")
        and isinstance(file, dict)
        and set(file) == {"device", "inode", "uid", "gid", "mode", "sha256"}
        and all(positive_integer(file[name]) for name in ("device", "inode"))
        and file["device"] == c["state"]["data"]["directory"]["device"]
        and type(file["mode"]) is int
        and file["mode"] == 0o600
        and all(
            type(file[name]) is int and file[name] == c["actor"][name] for name in ("uid", "gid")
        )
        and file["sha256"] == hashlib.sha256(expected.encode()).hexdigest(),
        "work-progress-mismatch",
    )
    expected_service = {
        "Id": value["identity"]["unit"],
        "Transient": "yes",
        "Type": "exec",
        "RemainAfterExit": "yes",
        "User": c["admin"],
        "Group": str(c["actor"]["gid"]),
        "InvocationID": value["identity"]["invocation"],
        "ActiveState": "active",
        "SubState": "exited" if completed else "running",
        "MainPID": "0" if completed else str(value["identity"]["process"]["pid"]),
        "ExecMainPID": str(value["identity"]["process"]["pid"]),
    }
    expected_service.update(
        Result="success", ExecMainCode="1" if completed else "0", ExecMainStatus="0"
    )
    require(
        isinstance(service, dict)
        and set(service) == {*expected_service, "ControlGroup"}
        and service["ControlGroup"]
        in (
            {"", "/system.slice/" + value["identity"]["unit"]}
            if completed
            else {"/system.slice/" + value["identity"]["unit"]}
        )
        and all(service.get(key) == want for key, want in expected_service.items()),
        "work-service-outcome-mismatch",
    )


def client_challenges(client: Client, admitted: dict[str, Any]) -> list[str]:
    changes = {
        "foreign-pid": ("pid", os.getpid()),
        "stale-start-ticks": ("start_ticks", admitted["start_ticks"] + 1),
        "foreign-executable": ("executable_sha256", "0" * 64),
        "foreign-arguments": ("arguments_sha256", "0" * 64),
        "foreign-actor": ("uid", admitted["uid"] + 1),
        "foreign-enrollment": ("enrollment", str(uuid.uuid4())),
        "foreign-connection": ("guest_port", admitted["guest_port"] % 65535 + 1),
    }
    refusals = []
    for name, (key, value) in changes.items():
        claim = {**admitted, key: value}
        try:
            client.break_transport(claim, admitted)
        except GuestTransportError:
            require(client.identity() == admitted, "refusal-damaged-transport")
            refusals.append(name)
        else:
            raise GuestTransportError("foreign-transport-accepted")
    return refusals


def work_challenges(
    guest: Guest, c: dict[str, Any], identity: dict[str, Any], deadline: Deadline
) -> list[str]:
    refusals = []
    changes = {
        "foreign-unit": ("unit", "fht-" + uuid.uuid4().hex + ".service"),
        "stale-invocation": ("invocation", "0" * 32),
        "foreign-task": ("task", str(uuid.uuid4())),
        "stale-boot": ("boot_id", str(uuid.uuid4())),
    }
    for name, (key, value) in changes.items():
        claim = copy.deepcopy(identity)
        claim[key] = value
        for mode in ("advance", "cleanup"):
            result = observe(guest, c, mode, deadline, claim)
            require(
                result == {"refused": True, "outcome": "running", "identity": identity},
                "foreign-work-accepted",
            )
        result = observe(guest, c, "observe", deadline)
        require(
            validate_observation(result, c) == identity and result["outcome"] == "running",
            "refusal-damaged-work",
        )
        refusals.append(name)
    return refusals


class ObserverInterrupted(Exception):
    """A controlled observer interruption after an accepted progress request."""


def configuration(guest: Guest, deadline: Deadline) -> dict[str, Any]:
    if guest.observed is None:
        raise GuestTransportError("guest-not-verified")
    storage = guest.report.get("storage", {})
    require(
        storage.get("status") == "passed" and storage.get("permissions_verified") is True,
        "storage-not-verified",
    )
    require(
        all(hasattr(os, name) for name in ("pidfd_open", "P_PIDFD", "waitid"))
        and hasattr(signal, "pidfd_send_signal"),
        "transport-kernel-facility-unavailable",
    )
    return {
        "task": str(uuid.uuid4()),
        "enrollment": guest.enrollment,
        "boot_id": guest.observed["boot_id"],
        "admin": guest.accounts[0],
        "actor": guest.observed["accounts"][guest.accounts[0]],
        "state": storage["filesystems"],
        "worker": WORKER,
        "runtime_seconds": remaining(deadline),
        "seconds": remaining(deadline),
        "cleanup_seconds": current().seconds(5),
    }


def transport_case(guest: Guest, scenario: str, deadline: Deadline, case: dict[str, Any]) -> None:
    metrics = RunStats()
    identity: dict[str, Any] | None = None
    c: dict[str, Any] | None = None
    try:
        c = configuration(guest, deadline)
        case.update(
            enrollment=c["enrollment"],
            boot_id=c["boot_id"],
            task=c["task"],
            runtime_seconds=c["runtime_seconds"],
        )
        require(guest.observed is not None, "guest-not-verified")
        arguments, _ = guest.ssh_command(
            guest.remote(guest.observed, action(c, "start")), deadline=deadline, nominal=90
        )
        with owned_client(guest, arguments, deadline) as client:
            client.readiness(c["task"])
            admitted = client.identity()
            case["transport_identity"] = admitted
            before = observe(guest, c, "observe", deadline)
            identity = validate_observation(before, c)
            require(before["outcome"] == "running", "work-not-running-before-loss")
            case["before_loss"] = before
            case["transport_refusals"] = client_challenges(client, admitted)
            case["work_refusals"] = work_challenges(guest, c, identity, deadline)
            client.break_transport(admitted, admitted)
            case.update(transport_broken=True, work_outcome_after_transport_loss="unknown")
            case["transport_termination"] = client.reap()
        after = observe(guest, c, "observe", deadline)
        require(
            validate_observation(after, c) == identity and after["outcome"] == "running",
            "work-not-observed-after-loss",
        )
        require(after["progress"] == before["progress"], "unexpected-work-restart")
        case["after_reconnect"] = after
        case["work_outcome_after_transport_loss"] = "running-observed-independently"
        expected = {"accepted": True, "identity": identity, "gate": "advance"}
        try:
            reply = observe(guest, c, "advance", deadline, identity)
            if scenario == "after-advance-interruption":
                raise ObserverInterrupted()
            require(reply == expected, "work-advance-refused")
        except ObserverInterrupted:
            case.update(
                observer_interruption_injected=True,
                observer_interruption_kind="controlled-exception-before-reply-admission",
                work_outcome_after_observer_interruption="unknown",
            )
        # Repeat only the idempotent progress request, never the task launch.
        require(observe(guest, c, "advance", deadline, identity) == expected, "work-retry-refused")
        completed = observe(guest, c, "finish", deadline)
        require(
            validate_observation(completed, c) == identity
            and completed["outcome"] == "completed-successfully",
            "work-outcome-unobserved",
        )
        require(
            completed["progress"]["file"]["inode"] == before["progress"]["file"]["inode"],
            "work-progress-replaced",
        )
        case.update(completed=completed, retry_preserved_invocation=True)
        if scenario == "after-advance-interruption":
            case["work_outcome_after_observer_interruption"] = (
                "completed-successfully-observed-independently"
            )
    finally:
        try:
            if c is not None and identity is not None:
                cleanup_deadline = Deadline.after(30)
                cleanup = observe(guest, c, "cleanup", cleanup_deadline, identity)
                require(
                    cleanup
                    == {
                        "identity": identity,
                        "unit_removed": True,
                        "origin_exited": True,
                        "guest_canaries_preserved": True,
                        "task_resources_retained_for_guest_cleanup": True,
                    },
                    "transport-cleanup-incomplete",
                )
                require(
                    observe(guest, c, "cleanup", cleanup_deadline, identity) == cleanup,
                    "cleanup-retry-mismatch",
                )
                case["cleanup"] = cleanup
        finally:
            case["statistics"] = metrics.finish()
            if not valid_stats(case["statistics"]):
                raise ValueError("invalid required guest transport statistics")

    case["status"] = "passed"


def qualify_transport_loss(
    guest: Guest,
    progress: Callable[[str], AbstractContextManager[None]],
    temporary: Path,
    report: dict[str, Any],
) -> None:
    metrics = RunStats()
    report.update(
        status="failed",
        scope="disposable-guest-owned-ssh-loss-only",
        enrollment=guest.enrollment,
        resources_destroyed_with_guest=False,
        unrelated_host_canary_preserved=False,
        cases=[],
    )
    try:
        deadline = Deadline.after(480)
        with tempfile.TemporaryDirectory(prefix="fishhat-transport-canary-", dir=temporary) as name:
            canary = Path(name) / "unrelated"
            content = uuid.uuid4().bytes
            canary.write_bytes(content)
            before = canary.lstat()
            try:
                for scenario in ("transport-loss", "after-advance-interruption"):
                    with progress("transport-" + scenario):
                        case: dict[str, Any] = {
                            "scenario": scenario,
                            "status": "failed",
                            "observer_interruption_injected": False,
                        }
                        report["cases"].append(case)
                        transport_case(guest, scenario, deadline, case)
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
        raise GuestTransportError("transport-observation-unavailable") from None
    finally:
        report["statistics"] = metrics.finish()
        if not valid_stats(report["statistics"]):
            raise ValueError("invalid required guest transport statistics")
