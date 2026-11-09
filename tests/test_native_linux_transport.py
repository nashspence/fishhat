"""Controlled transport/service faults; actual native evidence runs on main."""

from __future__ import annotations

import ast
import copy
import errno
import hashlib
import io
import json
import os
import re
import signal
import stat
import subprocess
import uuid
from contextlib import nullcontext
from pathlib import PurePosixPath
from types import SimpleNamespace

import pytest

from scripts import native_linux_enrollment as native
from scripts import native_linux_transport as transport
from scripts.run_stats import valid_stats
from scripts.validation_timeouts import Deadline, current

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/native_linux_transport.py",
        "scripts/native_linux_guest.py",
        "scripts/native_linux_enrollment.py",
    ],
    "scope": "controlled execution of the fixed worker and service supervisor, exact client/service/actor/progress admission, refusal-before-effect ordering, transport reaping, independent continuation/outcome, interruption/retry, owned cleanup and required statistics",
    "relationship": "no-product-claim",
    "reason": "Embedded programs execute against substituted kernel, filesystem, SSH and service-manager facilities. These are tooling checks; main-only disposable guest evidence remains necessary and native owners remain unqualified.",
    "claims": [],
}


@pytest.fixture(autouse=True)
def substitute_host_kernel_facilities(monkeypatch):
    # Local locked Python builds need not expose Linux pidfds. Availability and
    # syscalls here are controlled; native execution must require the real API.
    operating_system = SimpleNamespace(**vars(os))
    operating_system.P_PIDFD = 3
    operating_system.pidfd_open = lambda pid, flags: 99
    signals = SimpleNamespace(**vars(signal))
    signals.pidfd_send_signal = lambda handle, value: None
    monkeypatch.setattr(transport, "os", operating_system)
    monkeypatch.setattr(transport, "signal", signals)


def controlled_program(program, namespace):
    # Execute maintained statements, replacing only imported outside facilities.
    tree = ast.parse(program)
    tree.body = [node for node in tree.body if not isinstance(node, ast.Import)]
    exec(compile(tree, "<controlled-fixture>", "exec"), namespace)


def metadata(device, inode, uid, mode, size=0):
    return SimpleNamespace(
        st_dev=device,
        st_ino=inode,
        st_uid=uid,
        st_gid=uid,
        st_mode=mode,
        st_nlink=1,
        st_size=size,
        st_mtime_ns=100,
        st_ctime_ns=100,
    )


class Harness:
    """No real SSH, root command, service manager or process is used."""

    def __init__(self, change=None):
        self.change = change
        self.enrollment, self.boot, self.token = (str(uuid.uuid4()) for _ in range(3))
        self.root = "/run/fhs-" + uuid.UUID(self.enrollment).hex
        self.task = self.root + "/data/transport-" + uuid.UUID(self.token).hex
        self.unit = "fht-" + uuid.UUID(self.token).hex + ".service"
        self.invocation = "a" * 32
        self.files, self.meta, self.descriptors = {}, {}, {}
        self.next_fd = 100
        self.clock = 0
        self.events = []
        self.frame = b""
        self.running = False
        self.exists = False
        self.origin_exited = False
        self.state = {"root": self.directory(self.root, 17, 1, 0, 0o711)}
        for index, role in enumerate(("control", "data"), 18):
            uid = 0 if role == "control" else 1000
            self.state[role] = {
                "directory": self.directory(self.root + "/" + role, index, 2, uid, 0o700)
            }
            value = role + ":" + self.enrollment + "\n" + ("admin-write\n" if uid else "")
            self.file(self.root + "/" + role + "/canary", value.encode(), uid)
        for path in ("/proc/self/exe", "/proc/500/exe", "/proc/900/exe"):
            self.file(path, b"trusted-python", 0, mode=0o755)
        self.c = {
            "enrollment": self.enrollment,
            "boot_id": self.boot,
            "task": self.token,
            "admin": "admin",
            "actor": {"uid": 1000, "gid": 1000},
            "state": copy.deepcopy(self.state),
            "worker": transport.WORKER,
            "seconds": 20,
            "runtime_seconds": 20,
            "cleanup_seconds": 5,
        }
        self.ns = self.namespace()
        controlled_program(transport.PROGRAM, self.ns)

    def directory(self, path, device, inode, uid, mode):
        self.meta[path] = metadata(device, inode, uid, stat.S_IFDIR | mode)
        return {"device": device, "inode": inode, "uid": uid, "gid": uid, "mode": mode}

    def file(self, path, value, uid, mode=0o600):
        self.files[path] = value
        self.meta[path] = metadata(19, len(self.meta) + 100, uid, stat.S_IFREG | mode, len(value))

    def path(self, value, *parts):
        h = self

        class Path(PurePosixPath):
            def lstat(self):
                if str(self) not in h.meta:
                    raise FileNotFoundError()
                return copy.copy(h.meta[str(self)])

            def exists(self):
                return str(self) in h.meta

            def mkdir(self, *, mode):
                assert str(self) == h.task and str(self) not in h.meta
                h.events.append("task-created")
                h.directory(str(self), 19, 700, 0, mode)

            def chmod(self, mode):
                h.meta[str(self)].st_mode = stat.S_IFDIR | mode

            def unlink(self):
                h.events.append("unlink:" + self.name)
                del h.files[str(self)]
                del h.meta[str(self)]

            def read_text(self):
                return h.read_text(str(self))

            def read_bytes(self):
                if str(self).endswith("/cmdline"):
                    if str(self).startswith("/proc/900"):
                        arguments = h.ns["arguments"]()
                        return b"\0".join(v.encode() for v in arguments) + b"\0"
                    return b"owned-origin\0"
                return h.files[str(self)]

        return Path(value, *parts)

    def read_text(self, path):
        if path.endswith("fixture-enrollment"):
            return str(uuid.uuid4()) if self.change == "enrollment" else self.enrollment
        if path.endswith("boot_id"):
            return str(uuid.uuid4()) if self.change == "boot" else self.boot
        if path.endswith("/stat"):
            worker = path.startswith("/proc/900")
            fields = ["0"] * 20
            fields[0:4] = ["S", "1" if worker else "400", "900", "900"]
            fields[19] = "77"
            if self.change == "parent" and worker:
                fields[1] = "999"
            return "900 (python3) " + " ".join(fields)
        if path.endswith("/status"):
            uid = "1000" if path.startswith("/proc/900") else "0"
            return (
                "Uid:\t"
                + " ".join([uid] * 4)
                + "\nGid:\t"
                + " ".join([uid] * 4)
                + "\nGroups:\t"
                + uid
            )
        if path.endswith("/cgroup"):
            return "0::/system.slice/" + (
                self.unit if path.startswith("/proc/900") else "ssh.service"
            )
        return self.files[path].decode()

    def open(self, path, flags, mode=0o600):
        path = str(path)
        if flags & os.O_CREAT:
            if path in self.meta and flags & os.O_EXCL:
                raise FileExistsError()
            self.file(path, b"", 0, mode)
            self.events.append("create:" + PurePosixPath(path).name)
        if path not in self.meta:
            raise FileNotFoundError()
        self.next_fd += 1
        self.descriptors[self.next_fd] = (path, flags)
        return self.next_fd

    def stream(self, fd, mode):
        h = self
        path, flags = self.descriptors[fd]

        class Stream(io.BytesIO):
            def fileno(self):
                return fd

            def flush(self):
                if mode == "wb":
                    h.files[path] = self.getvalue()
                    h.meta[path].st_size = len(self.getvalue())

            def close(self):
                self.flush()
                super().close()

        result = Stream(self.files[path])
        if flags & os.O_APPEND:
            result.seek(0, 2)
        return result

    def builtin_open(self, path, mode):
        return self.stream(self.open(path, os.O_RDONLY), mode)

    def chown(self, fd, uid, gid):
        v = self.meta[self.descriptors[fd][0]]
        v.st_uid, v.st_gid = uid, gid

    def link(self, source, target, **options):
        assert options == {"follow_symlinks": False} and str(target) not in self.meta
        self.files[str(target)] = self.files[str(source)]
        self.meta[str(target)] = copy.copy(self.meta[str(source)])
        self.events.append("publish:" + target.name)
        if target.name == "advance":
            self.complete()
        if target.name == "release-origin":
            self.origin_exited = True

    def sleep(self, seconds):
        self.clock += seconds
        if self.frame and self.task + "/release-origin" not in self.meta:
            self.file(self.task + "/release-origin", (self.token + "\n").encode(), 0, 0o444)
            self.origin_exited = True

    def complete(self):
        self.running = False
        self.files[self.task + "/progress"] += (
            "continued:" + self.token + "\ncompleted:" + self.token + "\n"
        ).encode()
        self.meta[self.task + "/progress"].st_size = len(self.files[self.task + "/progress"])

    def properties(self):
        return {
            "Id": self.unit,
            "Transient": "no" if self.change == "transient" else "yes",
            "Type": "exec",
            "RemainAfterExit": "yes",
            "User": "foreign" if self.change == "user" else "admin",
            "Group": "1000",
            "MainPID": "900" if self.running else "0",
            "ExecMainPID": "900",
            "InvocationID": self.invocation,
            "ControlGroup": "/system.slice/" + self.unit,
            "ActiveState": "active",
            "SubState": "running" if self.running else "exited",
            "Result": "success",
            "ExecMainCode": "0" if self.running else "1",
            "ExecMainStatus": "0",
        }

    def run(self, arguments, **options):
        assert options["check"] and options["timeout"] > 0
        assert options["stdin"] == options["stderr"] == subprocess.DEVNULL
        if arguments[0] == "/usr/bin/systemd-run":
            self.events.append("launch")
            assert "--property=Type=exec" in arguments
            assert "--expand-environment=no" in arguments and "--remain-after-exit" in arguments
            assert "--uid=admin" in arguments and "--gid=1000" in arguments
            assert "--wait" not in arguments and "--collect" not in arguments
            self.exists = self.running = True
            if self.change != "no-progress":
                self.files[self.task + "/progress"] = ("started:" + self.token + "\n").encode()
                self.meta[self.task + "/progress"].st_size = len(
                    self.files[self.task + "/progress"]
                )
            return SimpleNamespace(stdout="")
        if arguments[1] == "list-units":
            return SimpleNamespace(
                stdout=(self.unit + " loaded active running\n") if self.exists else ""
            )
        if arguments[1] == "show":
            assert self.exists
            return SimpleNamespace(
                stdout="\n".join(k + "=" + v for k, v in self.properties().items())
            )
        assert arguments == ["/usr/bin/systemctl", "stop", self.unit]
        self.events.append("stop")
        self.exists = self.running = False
        return SimpleNamespace(stdout="")

    def write(self, fd, frame):
        assert fd == 1
        if self.change == "frame-failure":
            raise BrokenPipeError()
        self.frame += frame
        return len(frame)

    def namespace(self):
        fake_os = SimpleNamespace(
            **{
                name: getattr(os, name)
                for name in (
                    "O_RDONLY",
                    "O_WRONLY",
                    "O_CREAT",
                    "O_EXCL",
                    "O_NOFOLLOW",
                    "O_DIRECTORY",
                    "O_APPEND",
                )
            },
            geteuid=lambda: 1000 if self.change == "root" else 0,
            getpid=lambda: 500,
            open=self.open,
            fdopen=self.stream,
            fstat=lambda fd: copy.copy(self.meta[self.descriptors[fd][0]]),
            fchown=self.chown,
            fsync=lambda fd: self.events.append("fsync"),
            close=lambda fd: None,
            readlink=lambda path: "/usr/bin/python3.12",
            getgrouplist=lambda user, gid: [1000],
            pidfd_open=lambda pid, flags: 999,
            write=self.write,
            link=self.link,
        )
        return {
            "__name__": "controlled_fixture",
            "os": fake_os,
            "pathlib": SimpleNamespace(Path=self.path),
            "pwd": SimpleNamespace(getpwnam=lambda name: SimpleNamespace(pw_uid=1000, pw_gid=1000)),
            "subprocess": SimpleNamespace(
                run=self.run, DEVNULL=subprocess.DEVNULL, PIPE=subprocess.PIPE
            ),
            "time": SimpleNamespace(monotonic=lambda: self.clock, sleep=self.sleep),
            "select": SimpleNamespace(
                select=lambda *args: ([999] if self.origin_exited else [], [], [])
            ),
            "open": self.builtin_open,
            "json": json,
            "hashlib": hashlib,
            "uuid": uuid,
            "re": re,
            "stat": stat,
        }

    def initialize(self):
        self.ns["initialize"](copy.deepcopy(self.c))

    def start(self):
        self.initialize()
        self.ns["start"]()
        # Model the still-waiting originating invocation independently of the
        # synchronous controlled interpreter used to inspect its code above.
        del self.files[self.task + "/release-origin"]
        del self.meta[self.task + "/release-origin"]
        self.origin_exited = False
        return self.ns["control"]("observe", None)


def test_supervisor_binds_real_statements_and_retry_never_relaunches():
    h = Harness()
    before = h.start()
    identity = transport.validate_observation(before, h.c)
    assert before["outcome"] == "running" and h.frame == (h.token + "\n").encode()
    assert identity["process"]["parent_pid"] == 1
    assert h.ns["control"]("observe", None) == before
    for _ in range(2):
        assert h.ns["control"]("advance", identity) == {
            "accepted": True,
            "identity": identity,
            "gate": "advance",
        }
    final = h.ns["control"]("finish", None)
    assert transport.validate_observation(final, h.c) == identity
    assert final["outcome"] == "completed-successfully"
    cleanup = h.ns["control"]("cleanup", identity)
    assert cleanup == h.ns["control"]("cleanup", identity)
    assert cleanup["unit_removed"] and cleanup["origin_exited"]
    assert cleanup["guest_canaries_preserved"]
    assert h.events.count("launch") == h.events.count("stop") == 1
    assert h.events.count("publish:advance") == 1
    assert h.events.index("create:advance-pending") < h.events.index("publish:advance")


@pytest.mark.parametrize(
    "field", ["unit", "invocation", "task", "boot_id", "enrollment", "process"]
)
@pytest.mark.parametrize("mode", ["advance", "cleanup"])
def test_foreign_or_stale_service_claims_cannot_advance_or_stop_work(field, mode):
    h = Harness()
    before = h.start()
    claim = copy.deepcopy(before["identity"])
    claim[field] = {} if field == "process" else "foreign"
    h.events.clear()
    refused = h.ns["control"](mode, claim)
    assert refused == {"refused": True, "outcome": "running", "identity": before["identity"]}
    assert h.ns["control"]("observe", None) == before
    assert not h.events and h.running


@pytest.mark.parametrize(
    "change", ["root", "enrollment", "boot", "actor", "data-directory", "canary"]
)
def test_complete_guest_admission_precedes_every_effect(change):
    h = Harness(change)
    if change == "actor":
        h.c["actor"]["uid"] = 0
    elif change == "data-directory":
        h.c["state"]["data"]["directory"]["inode"] += 1
    elif change == "canary":
        h.files[h.root + "/data/canary"] = b"foreign"
    with pytest.raises(ValueError, match="guest-transport-refused"):
        h.initialize()
    assert not h.events and not h.exists


@pytest.mark.parametrize("change", ["transient", "user", "parent", "no-progress", "frame-failure"])
def test_unadmitted_or_incomplete_service_never_publishes_success(change):
    h = Harness(change)
    h.initialize()
    with pytest.raises((ValueError, BrokenPipeError)):
        h.ns["start"]()
    assert not h.frame
    if change in {"no-progress", "frame-failure"}:
        assert h.events.count("stop") == 1 and not h.exists


@pytest.mark.parametrize(
    "field,value",
    [
        ("InvocationID", "b" * 32),
        ("ExecMainPID", "901"),
        ("User", "other"),
        ("Type", "simple"),
        ("Transient", "no"),
    ],
)
def test_independent_observer_rejects_replaced_or_misbound_service(field, value):
    h = Harness()
    h.start()
    properties = h.properties()
    properties[field] = value
    h.properties = lambda: properties
    h.events.clear()
    with pytest.raises(ValueError):
        h.ns["control"]("observe", None)
    assert not h.events


@pytest.mark.parametrize(
    "field,value",
    [
        ("Result", "timeout"),
        ("ExecMainCode", "2"),
        ("ExecMainStatus", "9"),
        ("MainPID", "900"),
        ("ActiveState", "failed"),
    ],
)
def test_work_success_requires_observed_completion_and_actual_service_exit(field, value):
    h = Harness()
    before = h.start()
    h.ns["control"]("advance", before["identity"])
    properties = h.properties()
    properties[field] = value
    h.properties = lambda: properties
    with pytest.raises(ValueError):
        h.ns["control"]("finish", None)


def test_fixed_worker_fsyncs_progress_and_requires_published_gate_before_continuing():
    h = Harness()
    h.initialize()
    h.directory(h.task, 19, 700, 0, 0o755)
    h.file(h.task + "/progress", b"", 1000)

    def publish(seconds):
        assert h.files[h.task + "/progress"] == ("started:" + h.token + "\n").encode()
        assert "fsync" in h.events
        h.file(h.task + "/advance", (h.token + "\n").encode(), 0, 0o444)

    h.ns["time"].sleep = publish
    h.ns["sys"] = SimpleNamespace(argv=["worker", h.task, h.token, "20"])
    controlled_program(transport.WORKER, h.ns)
    assert (
        h.files[h.task + "/progress"]
        == (
            "started:" + h.token + "\ncontinued:" + h.token + "\ncompleted:" + h.token + "\n"
        ).encode()
    )
    assert h.events.count("fsync") == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("outcome", "failed"),
        ("guest_canaries_preserved", 1),
        ("identity", None),
        ("service", {}),
        ("progress", {}),
    ],
)
def test_controller_rejects_missing_or_falsely_typed_work_observation(field, value):
    h = Harness()
    report = h.start()
    report[field] = value
    with pytest.raises(transport.GuestTransportError):
        transport.validate_observation(report, h.c)


@pytest.mark.parametrize(
    "field,value",
    [
        ("pid", True),
        ("parent_pid", True),
        ("uids", [0] * 4),
        ("arguments_sha256", "a" * 64),
        ("cgroups", []),
    ],
)
def test_controller_rejects_inexact_work_process_identity(field, value):
    h = Harness()
    report = h.start()
    report["identity"]["process"][field] = value
    with pytest.raises(transport.GuestTransportError):
        transport.validate_observation(report, h.c)


class ClientHarness:
    def __init__(self, monkeypatch):
        self.events = []
        self.killed = self.reaped = False
        self.argv = ["/usr/bin/ssh", "fixed-arguments"]
        self.enrollment = str(uuid.uuid4())
        self.frame = (str(uuid.uuid4()) + "\n").encode()
        self.output = SimpleNamespace(
            fileno=lambda: 11, close=lambda: self.events.append("stdout-closed")
        )
        self.process = SimpleNamespace(
            pid=400, returncode=None, stdout=self.output, wait=self.wait, kill=self.kill
        )
        self.guest = SimpleNamespace(
            enrollment=self.enrollment,
            port=2222,
            listener=lambda: self.events.append("listener"),
            verify_process=lambda deadline: self.events.append("guest-process"),
            verify_tools=lambda: self.events.append("tools"),
            tools={"sha256": {"ssh": "a" * 64}},
        )
        self.namespace = SimpleNamespace(**vars(os))
        self.namespace.P_PIDFD = 3
        self.namespace.waitid = self.waitid
        self.namespace.pidfd_open = lambda pid, flags: 99
        self.namespace.close = lambda fd: self.events.append("handle-closed")
        self.namespace.readlink = lambda path: "/usr/bin/ssh"
        self.namespace.read = lambda fd, count: self.read(count)
        self.fields = ["0"] * 20
        self.fields[0:4] = ["S", str(os.getpid()), "400", "400"]
        self.fields[19] = "77"
        monkeypatch.setattr(transport, "os", self.namespace)
        monkeypatch.setattr(transport, "Path", self.path)
        monkeypatch.setattr(transport, "file_digest", lambda path, deadline: "a" * 64)
        monkeypatch.setattr(
            transport, "signal", SimpleNamespace(SIGKILL=9, pidfd_send_signal=self.send)
        )
        self.select = SimpleNamespace(select=lambda readers, *args: (readers, [], []))
        monkeypatch.setattr(transport, "select", self.select)
        self.connections = [
            SimpleNamespace(
                status="ESTABLISHED",
                laddr=SimpleNamespace(ip="127.0.0.1", port=30000),
                raddr=SimpleNamespace(ip="127.0.0.1", port=2222),
            )
        ]
        monkeypatch.setattr(
            transport,
            "psutil",
            SimpleNamespace(
                CONN_ESTABLISHED="ESTABLISHED",
                Process=lambda pid: SimpleNamespace(net_connections=lambda **kw: self.connections),
            ),
        )
        self.client = transport.Client(self.guest, self.process, 99, self.argv, Deadline.after(20))

    def path(self, path):
        h = self

        class Path(PurePosixPath):
            def read_text(self):
                if "/fdinfo/" in str(self):
                    return "Pid:\t400"
                if self.name == "stat":
                    return "400 (ssh) " + " ".join(h.fields)
                return (
                    "Uid:\t"
                    + " ".join([str(os.geteuid())] * 4)
                    + "\nGid:\t"
                    + " ".join([str(os.getegid())] * 4)
                )

            def read_bytes(self):
                return b"\0".join(v.encode() for v in h.argv) + b"\0"

        return Path(path)

    def read(self, count):
        result, self.frame = self.frame[:count], self.frame[count:]
        return result

    def kill(self):
        self.killed = True
        self.events.append("kill")

    def send(self, fd, sig):
        assert fd == 99
        if self.reaped:
            raise ProcessLookupError(errno.ESRCH, "gone")
        assert sig == 9
        self.kill()

    def waitid(self, kind, fd, flags):
        assert kind == self.namespace.P_PIDFD and fd == 99 and flags & os.WNOWAIT
        return (
            SimpleNamespace(si_pid=400, si_code=os.CLD_KILLED, si_status=9) if self.killed else None
        )

    def wait(self, *, timeout):
        assert self.killed and timeout > 0
        self.reaped = True
        self.process.returncode = -9
        self.events.append("reap")
        return -9


def test_client_refuses_all_foreign_claims_then_kills_reaps_only_pinned_connection(monkeypatch):
    h = ClientHarness(monkeypatch)
    admitted = h.client.identity()
    refusals = transport.client_challenges(h.client, admitted)
    assert len(refusals) == 7 and not h.killed
    h.client.break_transport(admitted, admitted)
    result = h.client.reap()
    assert result == {
        "pid": 400,
        "code": "CLD_KILLED",
        "signal": 9,
        "returncode": -9,
        "reaped": True,
        "stale_handle_refused": True,
        "cleanup_kill": False,
    }
    assert h.events.count("kill") == h.events.count("reap") == 1
    assert "listener" in h.events and "guest-process" in h.events and "tools" in h.events


@pytest.mark.parametrize(
    "change", ["parent", "session", "connection", "listener", "exited", "birth"]
)
def test_changed_live_client_refuses_signal_before_effect(monkeypatch, change):
    h = ClientHarness(monkeypatch)
    admitted = h.client.identity()
    if change == "parent":
        h.fields[1] = "999"
    elif change == "session":
        h.fields[3] = "999"
    elif change == "connection":
        h.connections[0].raddr.port = 2223
    elif change == "listener":
        h.guest.listener = lambda: (_ for _ in ()).throw(transport.GuestTransportError("listener"))
    elif change == "exited":
        h.killed = True
    else:
        h.fields[19] = "78"
    with pytest.raises(transport.GuestTransportError):
        h.client.break_transport(admitted, admitted)
    assert "kill" not in h.events


@pytest.mark.parametrize("setup_failure", [False, True])
def test_owned_client_always_cleans_spawned_child_and_handle(monkeypatch, setup_failure):
    h = ClientHarness(monkeypatch)

    def popen(arguments, **options):
        assert arguments == h.argv and options["start_new_session"] and options["umask"] == 0o077
        assert options["stdin"] == options["stderr"] == subprocess.DEVNULL
        assert options["env"] == native.COMMAND_ENV
        return h.process

    monkeypatch.setattr(
        transport,
        "subprocess",
        SimpleNamespace(Popen=popen, DEVNULL=subprocess.DEVNULL, PIPE=subprocess.PIPE),
    )
    if setup_failure:

        def failed_pin(pid, flags):
            raise OSError("pin unavailable")

        h.namespace.pidfd_open = failed_pin
        with pytest.raises(OSError):
            with transport.owned_client(h.guest, h.argv, h.client.deadline):
                pytest.fail("unreachable")
    else:
        with pytest.raises(RuntimeError):
            with transport.owned_client(h.guest, h.argv, h.client.deadline):
                raise RuntimeError("controlled setup failure")
    assert h.killed and h.reaped and "stdout-closed" in h.events
    assert ("handle-closed" in h.events) is not setup_failure


@pytest.mark.parametrize("valid", [False, True])
def test_readiness_requires_exact_full_progress_frame(monkeypatch, valid):
    h = ClientHarness(monkeypatch)
    token = h.frame.decode().strip()
    if not valid:
        h.frame = b"foreign-frame\n"
        with pytest.raises(transport.GuestTransportError):
            h.client.readiness(token)
    else:
        h.client.readiness(token)
    assert not h.killed


class Guest:
    def __init__(self):
        self.h = Harness()
        self.enrollment = self.h.enrollment
        self.accounts = ("admin", "peer")
        self.observed = {"boot_id": self.h.boot, "accounts": {"admin": {"uid": 1000, "gid": 1000}}}
        self.report = {
            "storage": {
                "status": "passed",
                "permissions_verified": True,
                "filesystems": self.h.state,
            }
        }
        self.modes = []
        self.response = None

    def remote(self, expected, action):
        assert expected == self.observed
        return json.dumps(action)

    def ssh_command(self, command, *, deadline, nominal):
        arguments = json.loads(command)
        assert arguments[4] == transport.PROGRAM and arguments[-2] == "start"
        c = json.loads(arguments[-3])
        self.h.c = c
        self.h.token = c["task"]
        self.h.task = self.h.root + "/data/transport-" + uuid.UUID(c["task"]).hex
        self.h.unit = "fht-" + uuid.UUID(c["task"]).hex + ".service"
        self.h.start()
        self.modes.append("start")
        return ["fixed-ssh"], deadline

    def guarded(self, arguments, enrollment, boot_id, *, deadline, nominal):
        assert (enrollment, boot_id) == (self.enrollment, self.h.boot)
        assert arguments[4] == transport.PROGRAM and deadline.remaining() > 0
        config = json.loads(arguments[-3])
        assert config["runtime_seconds"] == self.h.c["runtime_seconds"]
        assert 0 < config["seconds"] <= deadline.remaining() + current().seconds(1)
        mode, claim = arguments[-2], json.loads(arguments[-1])
        self.modes.append(mode)
        if self.response is not None:
            return self.response
        self.h.ns["end"] = self.h.clock + config["seconds"]
        return json.dumps(self.h.ns["control"](mode, claim))


class CaseClient:
    def __init__(self):
        self.broken = False

    def readiness(self, token):
        pass

    def identity(self):
        return {"pid": 400, "start_ticks": 77, "uid": 1000, "guest_port": 2222}

    def break_transport(self, claim, admitted):
        transport.require(claim == admitted, "wrong claim")
        self.broken = True

    def reap(self):
        assert self.broken
        return {"reaped": True, "returncode": -9}


@pytest.mark.parametrize("scenario", ["transport-loss", "after-advance-interruption"])
def test_coordinator_reconnects_observes_outcome_retries_same_work_and_cleans(
    monkeypatch, scenario
):
    guest = Guest()
    monkeypatch.setattr(transport.os, "P_PIDFD", 3, raising=False)
    client = CaseClient()
    monkeypatch.setattr(transport, "owned_client", lambda *args: nullcontext(client))
    case = {"status": "failed", "observer_interruption_injected": False}
    transport.transport_case(guest, scenario, Deadline.after(120), case)
    assert case["status"] == "passed" and client.broken
    assert case["runtime_seconds"] == guest.h.c["runtime_seconds"] > 0
    assert case["task"] == case["before_loss"]["identity"]["task"]
    assert case["before_loss"]["outcome"] == case["after_reconnect"]["outcome"] == "running"
    assert case["completed"]["outcome"] == "completed-successfully"
    assert case["work_outcome_after_transport_loss"] == "running-observed-independently"
    assert case["retry_preserved_invocation"]
    assert case["observer_interruption_injected"] is (scenario == "after-advance-interruption")
    assert guest.modes.count("start") == 1 and guest.modes.count("advance") == 6
    assert guest.modes.count("cleanup") == 6 and guest.modes[-2:] == ["cleanup", "cleanup"]
    assert case["cleanup"]["unit_removed"] and case["cleanup"]["origin_exited"]
    assert valid_stats(case["statistics"])


@pytest.mark.parametrize(
    "response",
    ["private-invalid", "null", "[]", "{}"],
    ids=["invalid-json", "null", "array", "empty-object"],
)
def test_missing_observation_retains_failed_case_stats_without_inventing_outcome(
    monkeypatch, response
):
    guest = Guest()
    guest.response = response
    monkeypatch.setattr(transport.os, "P_PIDFD", 3, raising=False)
    client = CaseClient()
    monkeypatch.setattr(transport, "owned_client", lambda *args: nullcontext(client))
    case = {"status": "failed"}
    with pytest.raises(transport.GuestTransportError):
        transport.transport_case(guest, "transport-loss", Deadline.after(120), case)
    assert case["status"] == "failed" and valid_stats(case["statistics"])
    assert "completed" not in case and not client.broken


def test_helper_preserves_host_canary_and_only_records_whole_guest_cleanup_after_owner_proof(
    monkeypatch, tmp_path
):
    guest = Guest()
    scenarios = []

    def case(g, scenario, deadline, result):
        assert g is guest and deadline.remaining() > 0
        scenarios.append(scenario)
        result.update(status="passed", statistics=transport.RunStats().finish())

    monkeypatch.setattr(transport, "transport_case", case)
    report = {}
    transport.qualify_transport_loss(guest, lambda name: nullcontext(), tmp_path, report)
    assert report["status"] == "passed" and report["unrelated_host_canary_preserved"]
    assert not report["resources_destroyed_with_guest"] and valid_stats(report["statistics"])
    assert scenarios == ["transport-loss", "after-advance-interruption"]
    assert not list(tmp_path.iterdir())
    guest_report = {
        "process_reaped": True,
        "temporary_resources_removed": True,
        "storage": {},
        "endpoint": {},
        "transport_loss": report,
    }
    monkeypatch.setattr(native, "endpoint_closed", lambda endpoint: None)
    native.verify_guest_cleanup(
        guest_report, {"temporary_resources_removed": True, "base_preserved": True}
    )
    assert report["resources_destroyed_with_guest"]


@pytest.mark.parametrize("change", ["owner", "mode", "token", "timeout"])
def test_worker_rejects_foreign_gate_or_deadline_without_recording_completion(change):
    h = Harness()
    h.initialize()
    h.directory(h.task, 19, 700, 0, 0o755)
    h.file(h.task + "/progress", b"", 1000)
    if change != "timeout":
        h.file(
            h.task + "/advance",
            (("foreign" if change == "token" else h.token) + "\n").encode(),
            1000 if change == "owner" else 0,
            0o600 if change == "mode" else 0o444,
        )
    h.ns["sys"] = SimpleNamespace(argv=["worker", h.task, h.token, "0.1"])
    with pytest.raises((AssertionError, TimeoutError)):
        controlled_program(transport.WORKER, h.ns)
    assert h.files[h.task + "/progress"] == ("started:" + h.token + "\n").encode()


@pytest.mark.parametrize("refusal", ["guest", "storage", "deadline", "kernel"])
def test_transport_requires_verified_facilities_before_spawning(monkeypatch, refusal):
    guest = Guest()
    monkeypatch.setattr(transport.os, "P_PIDFD", 3, raising=False)
    deadline = Deadline.after(60)
    if refusal == "guest":
        guest.observed = None
    elif refusal == "storage":
        guest.report["storage"]["permissions_verified"] = False
    elif refusal == "deadline":
        deadline = SimpleNamespace(remaining=lambda: 0)
    else:
        monkeypatch.delattr(transport.os, "P_PIDFD")
    case = {"status": "failed"}
    with pytest.raises(transport.GuestTransportError):
        transport.transport_case(guest, "transport-loss", deadline, case)
    assert not guest.modes and valid_stats(case["statistics"])


def test_transport_failure_preserves_unrelated_canary_and_required_stats(monkeypatch, tmp_path):
    guest = Guest()

    def fail(g, scenario, deadline, case):
        case["statistics"] = transport.RunStats().finish()
        raise transport.GuestTransportError("controlled failure")

    monkeypatch.setattr(transport, "transport_case", fail)
    report = {}
    with pytest.raises(transport.GuestTransportError):
        transport.qualify_transport_loss(guest, lambda name: nullcontext(), tmp_path, report)
    assert report["status"] == report["cases"][0]["status"] == "failed"
    assert (
        report["unrelated_host_canary_preserved"] and not report["resources_destroyed_with_guest"]
    )
    assert valid_stats(report["statistics"]) and valid_stats(report["cases"][0]["statistics"])
    assert not list(tmp_path.iterdir())


def test_unexpected_client_exit_is_reaped_but_cannot_qualify_transport_injection(monkeypatch):
    h = ClientHarness(monkeypatch)
    h.killed = True
    h.namespace.waitid = lambda *args: SimpleNamespace(
        si_pid=400, si_code=os.CLD_EXITED, si_status=0
    )

    def normal_exit(*, timeout):
        h.reaped = True
        h.process.returncode = 0
        return 0

    h.process.wait = normal_exit
    with pytest.raises(transport.GuestTransportError, match="termination-mismatch"):
        h.client.reap()
    assert h.reaped and "kill" not in h.events


@pytest.mark.parametrize("state", ["already-gone", "exited", "reused-pid", "exit-race", "alive"])
def test_origin_cleanup_observation_uses_birth_and_kernel_handle_without_signaling(state):
    h = Harness()
    h.start()
    saved = h.ns["manifest"]()
    if state == "already-gone":

        def absent(pid, flags):
            raise ProcessLookupError()

        h.ns["os"].pidfd_open = absent
    elif state == "exited":
        h.origin_exited = True
    elif state == "reused-pid":
        original = copy.deepcopy(saved["origin"])
        original["start_ticks"] += 1
        h.ns["process"] = lambda pid: original
    elif state == "exit-race":

        def raced(pid):
            h.origin_exited = True
            raise FileNotFoundError()

        h.ns["process"] = raced
    h.events.clear()
    assert h.ns["origin_gone"](saved) is (state != "alive")
    assert not h.events
