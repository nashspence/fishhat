"""Controlled execution of guest process guards; real guest proofs are separate."""

from __future__ import annotations

import builtins
import copy
import errno
import hashlib
import io
import json
import os
import signal
import stat
import uuid
from contextlib import nullcontext
from pathlib import PurePosixPath
from types import SimpleNamespace

import pytest

from scripts import native_linux_enrollment as native
from scripts import native_linux_processes as processes
from scripts.run_stats import valid_stats
from scripts.validation_timeouts import Deadline, current

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/native_linux_processes.py", "scripts/native_linux_enrollment.py"],
    "scope": "fixed worker progress, exact guest/process/actor/executable admission, pinned process signaling and kernel observation, refusal ordering, setup-failure cleanup, canary preservation and scoped statistics with substituted system calls",
    "relationship": "no-product-claim",
    "reason": "The maintained remote programs execute with controlled process, kernel and filesystem modules. These tooling challenges establish no real guest operation, native owner or production qualification.",
    "claims": [],
}


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
    """In-memory OS/process doubles; never signal or launch a real process."""

    def __init__(self, change=None):
        self.change = change
        self.enrollment = str(uuid.uuid4())
        self.boot = str(uuid.uuid4())
        self.task = str(uuid.uuid4())
        self.root = "/run/fhs-" + uuid.UUID(self.enrollment).hex
        self.events = []
        self.files = {}
        self.metadata = {}
        self.descriptors = {}
        self.next_fd = 100
        self.frame = b""
        self.killed = False
        self.reaped = False
        self.identity_reads = 0
        self.owner = 0
        self.arguments = []
        self.stdout = None
        self.handle_closed = False
        self.state = {"root": self.directory(self.root, 17, 7, 0, 0o711)}
        for index, role in enumerate(("control", "data"), 18):
            uid = 0 if role == "control" else 1000
            self.state[role] = {
                "directory": self.directory(self.root + "/" + role, index, 2, uid, 0o700)
            }
            content = (
                role + ":" + self.enrollment + "\n" + ("admin-write\n" if role == "data" else "")
            ).encode()
            self.file(self.root + "/" + role + "/canary", content, index, uid)
        self.file("/proc/self/exe", b"trusted-interpreter", 17, 0, mode=0o755)
        self.c = {
            "scenario": "kill",
            "task": self.task,
            "enrollment": self.enrollment,
            "boot_id": self.boot,
            "admin": "admin",
            "actor": {"uid": 1000, "gid": 1000},
            "state": copy.deepcopy(self.state),
            "worker": processes.WORKER,
            "seconds": 45,
            "cleanup_seconds": 5,
        }

    def directory(self, path, device, inode, uid, mode):
        self.metadata[path] = metadata(device, inode, uid, stat.S_IFDIR | mode)
        return {"device": device, "inode": inode, "uid": uid, "gid": uid, "mode": mode}

    def file(self, path, content, device, uid, mode=0o600):
        self.files[path] = content
        self.metadata[path] = metadata(
            device, len(self.metadata) + 100, uid, stat.S_IFREG | mode, len(content)
        )

    def path(self, path):
        h = self

        class Path:
            def __init__(self, value):
                self.value = str(value)

            def __str__(self):
                return self.value

            def __truediv__(self, name):
                return Path(str(PurePosixPath(self.value) / name))

            def read_text(self):
                if self.value.endswith("fixture-enrollment"):
                    return str(uuid.uuid4()) if h.change == "enrollment" else h.enrollment
                if self.value.endswith("boot_id"):
                    return str(uuid.uuid4()) if h.change == "boot" else h.boot
                if "/fdinfo/" in self.value:
                    return "Pid:\t" + ("999" if h.change == "pidfd" else "400")
                if self.value.endswith("/stat"):
                    h.identity_reads += 1
                    fields = ["0"] * 20
                    fields[0:4] = [
                        "S",
                        "999" if h.change == "parent" else "300",
                        "400",
                        "999" if h.change == "session" else "400",
                    ]
                    fields[19] = (
                        "43" if h.change == "birth-changed" and h.identity_reads > 1 else "42"
                    )
                    return "400 (python3) " + " ".join(fields)
                if self.value.endswith("/status"):
                    return (
                        "Uid:\t"
                        + " ".join(["0" if h.change == "uid" else "1000"] * 4)
                        + "\nGid:\t"
                        + " ".join(["0" if h.change == "gid" else "1000"] * 4)
                        + "\nGroups:\t"
                        + ("1000" if h.change == "groups" else "")
                    )
                raise AssertionError(self.value)

            def read_bytes(self):
                assert self.value == "/proc/400/cmdline"
                value = b"\0".join(v.encode() for v in h.arguments) + b"\0"
                return b"foreign" if h.change == "arguments" else value

            def lstat(self):
                value = copy.copy(h.metadata[self.value])
                if h.change == "root-directory" and self.value == h.root:
                    value.st_ino += 1
                if h.change == "data-directory" and self.value == h.root + "/data":
                    value.st_uid = 0
                return value

            def mkdir(self, *, mode):
                h.events.append("mkdir")
                h.directory(self.value, 19, 77, 0, mode)

        return Path(path)

    def open(self, path, mode="rb"):
        assert mode in ("rb", "wb")
        h = self
        key = str(path)
        if key == "/proc/400/exe":
            key = "/proc/self/exe"
        fd = self.next_fd
        self.next_fd += 1
        self.descriptors[fd] = key

        class Stream(io.BytesIO):
            def fileno(self):
                return fd

            def close(self):
                if not self.closed and mode == "wb":
                    h.files[key] = self.getvalue()
                    h.metadata[key].st_size = len(h.files[key])
                super().close()

        content = self.files[key]
        if self.change == "guest-canary" and key.endswith("/control/canary"):
            content = b"foreign"
        if self.change == "progress" and key.endswith("/progress") and mode == "rb":
            content = b"foreign"
        return Stream(content if mode == "rb" else b"")

    def os_open(self, path, flags, mode=None):
        key = str(path)
        assert flags & os.O_NOFOLLOW
        if flags & os.O_CREAT:
            assert flags & os.O_EXCL and key not in self.files and mode == 0o600
            self.file(key, b"", 19, self.owner)
            self.events.append("create-progress")
        fd = self.next_fd
        self.next_fd += 1
        self.descriptors[fd] = key
        return fd

    def fdopen(self, fd, mode):
        return self.open(self.descriptors[fd], mode)

    def fstat(self, fd):
        key = self.descriptors[fd]
        value = copy.copy(self.metadata[key])
        if self.change == "executable" and key == "/proc/self/exe" and self.arguments:
            value.st_uid = 1000
        return value

    def chown(self, path, uid, gid):
        assert (uid, gid) == (1000, 1000)
        value = self.metadata[str(path)]
        value.st_uid = uid
        value.st_gid = gid

    def read(self, fd, amount):
        assert fd == 12
        if self.change == "readiness":
            return b""
        if self.change == "partial-readiness":
            if "partial-frame" in self.events:
                return b""
            self.events.append("partial-frame")
            value, self.frame = self.frame[:2], self.frame[2:]
            return value
        value, self.frame = self.frame[:amount], self.frame[amount:]
        return value

    def write(self, fd, value):
        assert fd == 1 and self.events[-1] == "fsync-progress"
        self.events.append("ready")
        self.frame = value
        return len(value)

    def pidfd_open(self, pid, flags):
        assert pid == 400 and flags == 0 and not self.reaped
        self.events.append("pin")
        return 99

    def send_signal(self, fd, number):
        assert fd == 99
        if number == 0:
            assert self.reaped
            if self.change != "stale-handle":
                raise ProcessLookupError(errno.ESRCH, "controlled")
        else:
            assert number == signal.SIGKILL and not self.reaped
            self.events.append("signal")
            self.killed = True

    def waitid(self, kind, fd, flags):
        assert kind == 3 and fd == 99 and flags == 0x1000005
        if not self.killed:
            return None
        return SimpleNamespace(
            si_pid=400, si_code=1 if self.change == "wait-code" else 2, si_status=9
        )

    def select(self, reads, writes, errors, timeout):
        assert (
            not writes
            and not errors
            and 0 < timeout <= self.c["seconds"] + self.c["cleanup_seconds"]
        )
        if reads == [99]:
            return (reads if self.killed else []), [], []
        assert reads == [self.stdout]
        return (reads if self.frame else []), [], []

    def popen(self, arguments, **kwargs):
        assert arguments[:5] == ["/usr/bin/python3", "-I", "-S", "-c", processes.WORKER]
        assert kwargs == {
            "user": 1000,
            "group": 1000,
            "extra_groups": [],
            "umask": 0o077,
            "start_new_session": True,
            "cwd": kwargs["cwd"],
            "env": {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            "stdin": -3,
            "stdout": -1,
            "stderr": -3,
        }
        assert str(kwargs["cwd"]) == arguments[5]
        self.arguments = arguments
        self.events.append("launch")
        self.owner = 1000
        self.execute(processes.WORKER, ["-c", *arguments[5:]])
        self.owner = 0
        self.stdout = SimpleNamespace(
            fileno=lambda: 12, close=lambda: self.events.append("close-stdout")
        )

        def wait(*, timeout):
            assert self.killed and 0 < timeout <= self.c["cleanup_seconds"]
            self.events.append("reap")
            self.reaped = True
            return -9 if self.change != "returncode" else 0

        return SimpleNamespace(pid=400, stdout=self.stdout, wait=wait)

    def close(self, fd):
        assert fd == 99
        self.events.append("close-handle")
        self.handle_closed = True

    def execute(self, program, argv):
        output = []
        os_double = SimpleNamespace(
            geteuid=lambda: 1000 if self.change == "not-root" else 0,
            getpid=lambda: 300,
            open=self.os_open,
            fdopen=self.fdopen,
            fstat=self.fstat,
            chown=self.chown,
            pidfd_open=self.pidfd_open,
            read=self.read,
            write=self.write,
            readlink=lambda path: "/usr/bin/python3.12",
            waitid=self.waitid,
            close=self.close,
            fsync=lambda fd: self.events.append("fsync-progress"),
            P_PIDFD=3,
            WEXITED=4,
            WNOHANG=1,
            WNOWAIT=0x1000000,
            CLD_KILLED=2,
            O_NOFOLLOW=os.O_NOFOLLOW,
            O_RDONLY=os.O_RDONLY,
            O_WRONLY=os.O_WRONLY,
            O_CREAT=os.O_CREAT,
            O_EXCL=os.O_EXCL,
        )
        if self.change == "facility":
            del os_double.pidfd_open
        modules = {
            "copy": copy,
            "errno": errno,
            "hashlib": hashlib,
            "json": json,
            "os": os_double,
            "pathlib": SimpleNamespace(Path=self.path),
            "pwd": SimpleNamespace(
                getpwnam=lambda name: SimpleNamespace(
                    pw_uid=42 if self.change == "actor" else 1000, pw_gid=1000
                )
            ),
            "select": SimpleNamespace(select=self.select),
            "signal": SimpleNamespace(
                SIGCHLD=17,
                SIG_DFL=0,
                SIGKILL=9,
                getsignal=lambda number: 0,
                pidfd_send_signal=self.send_signal,
            ),
            "stat": stat,
            "subprocess": SimpleNamespace(Popen=self.popen, DEVNULL=-3, PIPE=-1),
            "sys": SimpleNamespace(argv=argv),
            "time": SimpleNamespace(
                monotonic=lambda: 100, sleep=lambda seconds: self.events.append("sleep")
            ),
            "uuid": uuid,
        }
        namespace = {
            "__builtins__": {
                **vars(builtins),
                "open": self.open,
                "__import__": lambda name, *args: modules[name],
                "print": lambda value: output.append(value),
            }
        }
        exec(compile(program, "<controlled-guest-process>", "exec"), namespace)
        return json.loads(output[0]) if output else None

    def run(self, scenario="kill"):
        self.c["scenario"] = scenario
        return self.execute(processes.PROGRAM, ["-c", json.dumps(self.c)])


@pytest.mark.parametrize("scenario", ["kill", "after-process-admission"])
def test_remote_program_observes_progress_refusals_kernel_termination_and_reaping(scenario):
    h = Harness()
    result = h.run(scenario)
    assert processes.validate(result, h.c) == result
    assert result["refusals_verified"] == list(processes.REFUSALS)
    assert (
        h.events.index("fsync-progress")
        < h.events.index("ready")
        < h.events.index("signal")
        < h.events.index("reap")
    )
    assert h.events.count("launch") == h.events.count("signal") == h.events.count("reap") == 1
    assert h.reaped and h.handle_closed and result["termination"]["stale_handle_refused"]
    assert result["requested_kill"] is (scenario == "kill")
    assert result["termination"]["cleanup_kill"] is (scenario != "kill")
    assert (
        result["guest_canaries_preserved"] and result["task_resources_retained_for_guest_cleanup"]
    )
    assert not any("remove" in event for event in h.events)


@pytest.mark.parametrize(
    "change",
    [
        "not-root",
        "enrollment",
        "boot",
        "actor",
        "root-directory",
        "data-directory",
        "guest-canary",
        "facility",
    ],
)
def test_guest_admission_refusals_precede_task_creation_or_launch(change):
    h = Harness(change)
    with pytest.raises(ValueError, match="guest-process-refused"):
        h.run()
    assert not h.events and not h.killed


@pytest.mark.parametrize(
    "change",
    [
        "readiness",
        "partial-readiness",
        "progress",
        "pidfd",
        "parent",
        "session",
        "uid",
        "gid",
        "groups",
        "arguments",
        "executable",
        "birth-changed",
    ],
)
def test_failed_setup_cleans_only_the_pinned_owned_child(change):
    h = Harness(change)
    with pytest.raises(ValueError, match="guest-process-refused"):
        h.run()
    assert h.reaped and h.handle_closed
    assert h.events.count("signal") == h.events.count("reap") == 1
    assert h.events.index("pin") < h.events.index("signal") < h.events.index("reap")


@pytest.mark.parametrize("change", ["wait-code", "returncode", "stale-handle"])
def test_missing_actual_kernel_termination_reaping_or_stale_handle_refusal_fails(change):
    h = Harness(change)
    with pytest.raises(ValueError):
        h.run()
    assert h.reaped and h.handle_closed


@pytest.mark.parametrize(
    "field,value",
    [
        ("requested_kill", 1),
        ("refusals_verified", []),
        ("identity", {}),
        ("progress", None),
        ("termination", None),
        ("guest_canaries_preserved", False),
        ("setup_failure_injected", True),
        ("status", "failed"),
    ],
)
def test_controller_rejects_missing_or_falsely_typed_observations(field, value):
    h = Harness()
    result = h.run()
    result[field] = value
    with pytest.raises(processes.GuestProcessError):
        processes.validate(result, h.c)


@pytest.mark.parametrize(
    "field,value",
    [
        ("pid", True),
        ("start_ticks", 0),
        ("parent_pid", 400),
        ("session", 999),
        ("uid", 0),
        ("executable", {"path": "/foreign", "sha256": "a" * 64}),
        ("arguments_sha256", "invalid"),
        ("enrollment", "foreign"),
    ],
)
def test_controller_rejects_inexact_process_identity(field, value):
    h = Harness()
    result = h.run()
    result["identity"][field] = value
    with pytest.raises(processes.GuestProcessError, match="identity"):
        processes.validate(result, h.c)


@pytest.mark.parametrize(
    "field,value",
    [
        ("device", 999),
        ("inode", True),
        ("uid", True),
        ("mode", True),
        ("sha256", "a" * 64),
    ],
)
def test_controller_rejects_inexact_progress_identity(field, value):
    h = Harness()
    result = h.run()
    result["progress"][field] = value
    with pytest.raises(processes.GuestProcessError, match="progress"):
        processes.validate(result, h.c)


@pytest.mark.parametrize(
    "field,value",
    [
        ("pid", 999),
        ("signal", True),
        ("code", "CLD_EXITED"),
        ("returncode", 0),
        ("reaped", False),
        ("stale_handle_refused", 1),
        ("cleanup_kill", True),
    ],
)
def test_controller_rejects_inexact_kernel_termination(field, value):
    h = Harness()
    result = h.run()
    result["termination"][field] = value
    with pytest.raises(processes.GuestProcessError, match="termination"):
        processes.validate(result, h.c)


class Guest:
    def __init__(self):
        self.harness = Harness()
        self.enrollment = self.harness.enrollment
        self.accounts = ("admin", "peer")
        self.observed = {
            "boot_id": self.harness.boot,
            "accounts": {"admin": {"uid": 1000, "gid": 1000}},
        }
        self.report = {
            "storage": {
                "status": "passed",
                "permissions_verified": True,
                "filesystems": self.harness.state,
            }
        }
        self.calls = []
        self.response = None

    def guarded(self, arguments, enrollment, boot, *, deadline, nominal):
        assert enrollment == self.enrollment and boot == self.observed["boot_id"]
        assert arguments[:5] == ["/usr/bin/python3", "-I", "-S", "-c", processes.PROGRAM]
        c = json.loads(arguments[-1])
        assert nominal == 60 and 0 < c["seconds"] <= min(45 * current().scale, deadline.remaining())
        assert c["cleanup_seconds"] == 5 * current().scale
        self.calls.append(c["scenario"])
        if self.response is not None:
            return self.response
        # The controller parser is tested here; the complete remote program's
        # controlled system behavior is challenged separately above.
        h = Harness()
        result = h.run(c["scenario"])
        result.update(enrollment=c["enrollment"], boot_id=c["boot_id"], task=c["task"])
        result["identity"].update(
            enrollment=c["enrollment"],
            boot_id=c["boot_id"],
            task=c["task"],
            arguments_sha256=processes.arguments_sha256(c),
        )
        result["progress"]["sha256"] = hashlib.sha256((c["task"] + "\n").encode()).hexdigest()
        return json.dumps(result)


def test_complete_controlled_helper_preserves_host_canary_and_never_claims_guest_cleanup(tmp_path):
    guest = Guest()
    report = {}
    stages = []

    def progress(name):
        stages.append(name)
        return nullcontext()

    processes.qualify_process_kill(guest, progress, tmp_path, report)
    assert report["status"] == "passed" and report["unrelated_host_canary_preserved"]
    assert not report["resources_destroyed_with_guest"]
    assert guest.calls == ["kill", "after-process-admission"]
    assert stages == ["process-kill", "process-after-process-admission"]
    assert valid_stats(report["statistics"]) and all(
        valid_stats(case["statistics"]) for case in report["cases"]
    )
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "response",
    ["private-invalid-response", "[]", "{}", "null"],
    ids=["invalid-json", "array", "empty-object", "null"],
)
def test_helper_retains_failed_case_statistics_without_claiming_success(tmp_path, response):
    guest = Guest()
    guest.response = response
    report = {}
    with pytest.raises(processes.GuestProcessError):
        processes.qualify_process_kill(guest, lambda name: nullcontext(), tmp_path, report)
    assert report["status"] == report["cases"][0]["status"] == "failed"
    assert (
        report["unrelated_host_canary_preserved"] and not report["resources_destroyed_with_guest"]
    )
    assert valid_stats(report["statistics"]) and valid_stats(report["cases"][0]["statistics"])
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("refusal", ["guest", "storage", "deadline"])
def test_helper_requires_verified_guest_storage_and_remaining_shared_budget(refusal):
    guest = Guest()
    deadline = Deadline.after(60)
    if refusal == "guest":
        guest.observed = None
    elif refusal == "storage":
        guest.report["storage"]["permissions_verified"] = False
    else:
        deadline = SimpleNamespace(remaining=lambda: 0)
    case = {"status": "failed"}
    with pytest.raises(processes.GuestProcessError):
        processes.process_case(guest, "kill", deadline, case)
    assert guest.calls == [] and valid_stats(case["statistics"])


@pytest.mark.parametrize("removed", [False, True])
def test_whole_guest_cleanup_claim_requires_resource_owners_and_endpoint_observation(
    monkeypatch, removed
):
    report = {
        "process_reaped": removed,
        "temporary_resources_removed": True,
        "endpoint": {"owned_listener": True},
        "storage": {},
        "process_kill": {"resources_destroyed_with_guest": False},
    }
    inputs = {"temporary_resources_removed": True, "base_preserved": True}
    calls = []
    monkeypatch.setattr(native, "endpoint_closed", lambda endpoint: calls.append(endpoint))
    if removed:
        native.verify_guest_cleanup(report, inputs)
        assert report["process_kill"]["resources_destroyed_with_guest"]
        assert len(calls) == 1
    else:
        with pytest.raises(native.GuestStorageError):
            native.verify_guest_cleanup(report, inputs)
        assert not report["process_kill"]["resources_destroyed_with_guest"] and not calls
