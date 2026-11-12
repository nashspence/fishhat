"""Controlled storage admission and guard witnesses; native execution is separate."""

from __future__ import annotations

import ast
import builtins
import copy
import errno
import io
import json
import os
import stat
import time
import uuid
from contextlib import contextmanager, nullcontext
from pathlib import PurePosixPath
from types import SimpleNamespace

import pytest

from scripts import native_linux_enrollment as native
from scripts import native_linux_storage as storage
from scripts.native_linux_images import DISK_BYTES
from scripts.run_stats import valid_stats
from scripts.validation_timeouts import Deadline, current

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/native_linux_storage.py", "scripts/native_linux_enrollment.py"],
    "scope": "owned guest block admission, mount/account observations, permission-guard ordering, partial setup refusal, observed lifecycle cleanup and scoped statistics with controlled system calls",
    "relationship": "no-product-claim",
    "reason": "Controlled RPC and execution of the production remote programs against substituted system modules challenge tooling guards only. No real guest, filesystem, account or native owner is qualified by these cases.",
    "claims": [],
}


def device(role):
    index = 1 if role == "control" else 2
    return {
        "path": "/dev/vd" + ("b" if index == 1 else "c"),
        "major": 252,
        "minor": 16 * index,
        "device": os.makedev(252, 16 * index),
        "bytes": DISK_BYTES[role + ".qcow2"],
        "serial": "fh-" + role,
    }


class Guest:
    def __init__(self):
        self.enrollment = str(uuid.uuid4())
        suffix = uuid.UUID(self.enrollment).hex[:16]
        self.accounts = ("fha" + suffix, "fhu" + suffix)
        self.observed = {
            "boot_id": str(uuid.uuid4()),
            "accounts": {
                self.accounts[0]: {"uid": 1000, "gid": 1000},
                self.accounts[1]: {"uid": 1001, "gid": 1001},
            },
        }
        self.calls = []
        self.mode = "normal"
        self.instance = None

    def snapshot(self, role):
        v = device(role)
        uid = 0 if role == "control" else 1000
        return {
            "device": v,
            "filesystem": storage.FILESYSTEMS[role],
            "uuid": self.instance.uuids[role],
            "directory": {"device": v["device"], "inode": 2, "uid": uid, "gid": uid, "mode": 0o700},
            "mount_options": sorted(
                ["rw", "nodev", "nosuid"] + (["prjquota"] if role == "data" else [])
            ),
        }

    def guarded(self, arguments, enrollment, boot, **kwargs):
        assert arguments[:5] == ["/usr/bin/python3", "-I", "-S", "-c", storage.PROGRAM]
        assert enrollment == self.enrollment and boot == self.observed["boot_id"]
        assert kwargs["deadline"].remaining() > 0 and kwargs["nominal"] in (15, 60)
        c = json.loads(arguments[-1])
        mode = c["mode"]
        assert 0 < c["seconds"] <= kwargs["nominal"] * current().scale
        self.calls.append(mode)
        if self.mode == "invalid-json":
            return "private-invalid-observation"
        if mode == "probe":
            value = {
                "packages": storage.PACKAGES,
                "devices": {r: device(r) for r in storage.FILESYSTEMS},
                "mount_root_absent": True,
            }
        elif mode in storage.FILESYSTEMS:
            value = {
                "root": {"device": 17, "inode": 23, "uid": 0, "gid": 0, "mode": 0o711},
                mode: self.snapshot(mode),
            }
        else:
            value = {**self.instance.state, "canaries_verified": True}
        return json.dumps(value)

    def ssh(self, remote, *, role, deadline):
        import shlex

        arguments = shlex.split(remote)
        assert arguments[:5] == ["/usr/bin/python3", "-I", "-S", "-c", storage.PERMISSIONS]
        c = json.loads(arguments[-1])
        assert deadline.remaining() > 0
        self.calls.append(role)
        names = ("control", "data") if role == "peer" else ("control",)
        return json.dumps(
            {
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
                else [
                    "data:" + action for action in ("read", "create", "rename", "unlink", "write")
                ],
            }
        )


@pytest.fixture
def subject():
    guest = Guest()
    report = {}
    instance = storage.Storage(guest, report, Deadline.after(180))
    guest.instance = instance
    return guest, instance, report


def test_admission_mount_permission_and_final_observations(subject):
    guest, instance, report = subject
    instance.probe()
    instance.mounted("control")
    instance.mounted("data")
    instance.permissions("admin")
    instance.permissions("peer")
    assert instance.root("verify") == {**instance.state, "canaries_verified": True}
    assert guest.calls == ["probe", "control", "data", "admin", "peer", "verify"]
    assert report["permissions"]["peer"]["allowed"] == []
    assert (
        instance.state["control"]["directory"]["device"]
        != instance.state["data"]["directory"]["device"]
    )


@pytest.mark.parametrize(
    "change",
    [
        "serial",
        "size",
        "device-type",
        "duplicate-path",
        "duplicate-device",
        "duplicate-number",
        "extra",
        "mount-root",
        "packages",
    ],
)
def test_invalid_device_admission_never_dispatches_format(subject, monkeypatch, change):
    guest, instance, _ = subject
    original = guest.guarded

    def altered(*args, **kwargs):
        value = json.loads(original(*args, **kwargs))
        if change == "serial":
            value["devices"]["control"]["serial"] = "fh-root"
        elif change == "size":
            value["devices"]["data"]["bytes"] = True
        elif change == "device-type":
            value["devices"]["control"]["major"] = False
        elif change == "duplicate-path":
            value["devices"]["data"]["path"] = value["devices"]["control"]["path"]
        elif change == "duplicate-device":
            value["devices"]["data"]["device"] = value["devices"]["control"]["device"]
        elif change == "duplicate-number":
            value["devices"]["data"]["major"] = value["devices"]["control"]["major"]
            value["devices"]["data"]["minor"] = value["devices"]["control"]["minor"]
        elif change == "extra":
            value["devices"]["foreign"] = device("control")
        elif change == "mount-root":
            value["mount_root_absent"] = False
        else:
            value["packages"] = {}
        return json.dumps(value)

    monkeypatch.setattr(guest, "guarded", altered)
    with pytest.raises(storage.GuestStorageError):
        instance.probe()
    assert guest.calls == ["probe"] and not instance.devices


@pytest.mark.parametrize(
    "change", ["uid", "mode", "uuid", "filesystem", "device", "quota", "root-inode"]
)
def test_false_mounted_observation_cannot_qualify_permissions(subject, monkeypatch, change):
    guest, instance, _ = subject
    instance.probe()
    instance.mounted("control")
    original = guest.guarded

    def altered(*args, **kwargs):
        value = json.loads(original(*args, **kwargs))
        if change == "uid":
            value["data"]["directory"]["uid"] = 0
        elif change == "mode":
            value["data"]["directory"]["mode"] = 0o777
        elif change == "uuid":
            value["data"]["uuid"] = str(uuid.uuid4())
        elif change == "filesystem":
            value["data"]["filesystem"] = "ext4"
        elif change == "device":
            value["data"]["directory"]["device"] = 17
        elif change == "quota":
            value["data"]["mount_options"].remove("prjquota")
        else:
            value["root"]["inode"] += 1
        return json.dumps(value)

    monkeypatch.setattr(guest, "guarded", altered)
    with pytest.raises(storage.GuestStorageError):
        instance.mounted("data")
    assert "admin" not in guest.calls and set(instance.state) == {"root", "control"}


def test_missing_identity_or_admission_refuses_before_dispatch(subject):
    guest, instance, _ = subject
    with pytest.raises(storage.GuestStorageError, match="storage-not-admitted"):
        instance.mounted("control")
    with pytest.raises(storage.GuestStorageError, match="storage-not-prepared"):
        instance.permissions("peer")
    guest.observed = None
    with pytest.raises(storage.GuestStorageError, match="guest-not-verified"):
        instance.probe()
    assert guest.calls == []


def test_partial_setup_fault_retains_statistics_and_never_formats_data(subject, monkeypatch):
    guest, instance, report = subject
    monkeypatch.setattr(storage, "Storage", lambda *args: instance)
    with pytest.raises(storage.GuestStorageError, match="injected-after-control-mount"):
        storage.qualify_storage(guest, lambda name: nullcontext(), report, inject_failure=True)
    assert guest.calls == ["probe", "control"]
    assert report["status"] == "failed" and report["fault_injection_verified"]
    assert not report["permissions_verified"] and not report["resources_destroyed_with_guest"]
    assert valid_stats(report["statistics"])


def test_controlled_complete_storage_run_keeps_teardown_unclaimed(subject, monkeypatch):
    guest, instance, report = subject
    monkeypatch.setattr(storage, "Storage", lambda *args: instance)
    storage.qualify_storage(guest, lambda name: nullcontext(), report)
    assert report["status"] == "passed" and report["permissions_verified"]
    assert not report["resources_destroyed_with_guest"] and valid_stats(report["statistics"])


class FormatReached(Exception):
    pass


def execute_program(subject, change=None, *, probe=False):
    _guest, instance, _ = subject
    c = instance.configuration()
    c.update(
        mode="probe" if probe else "control",
        seconds=60,
        devices={r: device(r) for r in storage.FILESYSTEMS},
    )
    rows = {}
    for role in storage.FILESYSTEMS:
        d = device(role)
        rows[d["path"]] = {
            "path": d["path"],
            "type": "disk",
            "size": d["bytes"],
            "serial": d["serial"],
            "maj:min": f"{d['major']}:{d['minor']}",
            "ro": False,
            "mountpoints": [None],
            "fstype": None,
            "uuid": None,
            "pttype": None,
        }
    row = rows["/dev/vdb"]
    row.update(
        {
            "serial": {"serial": "fh-root"},
            "size": {"size": True},
            "mounted": {"mountpoints": ["/foreign"]},
            "formatted": {"fstype": "ext4"},
            "readonly": {"ro": True},
            "partitions": {"children": [{"path": "/dev/vdb1"}]},
            "partition-table": {"pttype": "gpt"},
            "device-number": {"maj:min": "252:0"},
        }.get(change, {})
    )
    mutations = []
    output = []
    reads = []

    class Path:
        def __init__(self, value):
            self.value = str(value)

        def __str__(self):
            return self.value

        def __truediv__(self, name):
            return Path(str(PurePosixPath(self.value) / name))

        def resolve(self, *, strict):
            assert strict
            return Path("/dev/vdb" if self.value.endswith("fh-control") else "/dev/vdc")

        def stat(self):
            role = "control" if self.value == "/dev/vdb" else "data"
            return SimpleNamespace(
                st_mode=(stat.S_IFREG if change == "not-block" else stat.S_IFBLK) | 0o600,
                st_rdev=device(role)["device"],
            )

        def lstat(self):
            return SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o700, st_dev=17, st_ino=29, st_uid=0, st_gid=0
            )

        def read_text(self):
            if self.value.endswith("boot_id"):
                return str(uuid.uuid4()) if change == "boot" else c["boot_id"]
            return str(uuid.uuid4()) if change == "enrollment" else c["enrollment"]

        def exists(self):
            return change == "existing-root"

        def is_symlink(self):
            return False

        def mkdir(self, *, mode):
            mutations.append(("mkdir", self.value, mode))

    def command(args, **kwargs):
        reads.append(args)
        assert kwargs["check"] and 0 < kwargs["timeout"] <= 60 and kwargs["env"]["LC_ALL"] == "C"
        if args[0].endswith("wipefs"):
            assert args[1:4] == ["--no-act", "--json", "--output"]
            signatures = [{"type": "ext4"}] if change == "formatted" else []
            if change == "partition-table":
                signatures = [{"type": "gpt"}]
            return SimpleNamespace(stdout=json.dumps({"signatures": signatures}))
        if args[0].endswith("dpkg-query"):
            versions = {**storage.PACKAGES}
            if change == "packages":
                versions["mount"] = "foreign"
            return SimpleNamespace(stdout="\n".join(n + "\t" + v for n, v in versions.items()))
        if args[0].endswith("lsblk"):
            return SimpleNamespace(stdout=json.dumps({"blockdevices": [rows[args[-1]]]}))
        mutations.append(("command", args))
        raise FormatReached

    os_fake = SimpleNamespace(
        geteuid=lambda: 1000 if change == "not-root" else 0,
        makedev=os.makedev,
        chmod=lambda p, m: mutations.append(("chmod", str(p), m)),
    )
    modules = {
        "json": json,
        "os": os_fake,
        "pathlib": SimpleNamespace(Path=Path),
        "pwd": SimpleNamespace(
            getpwnam=lambda n: SimpleNamespace(
                pw_uid=42 if change == "account" else 1000, pw_gid=1000
            )
        ),
        "stat": stat,
        "subprocess": SimpleNamespace(run=command, DEVNULL=-3, PIPE=-1),
        "sys": SimpleNamespace(argv=["storage", json.dumps(c)]),
        "time": time,
        "uuid": uuid,
    }
    scope = {
        "__builtins__": {
            **vars(builtins),
            "__import__": lambda name, *args, **kwargs: modules[name],
            "print": output.append,
        }
    }
    try:
        exec(compile(storage.PROGRAM, "guest-storage", "exec"), scope)
    except Exception as error:
        return error, mutations, reads, output
    return None, mutations, reads, output


def test_production_probe_reads_only_owned_devices(subject):
    error, mutations, reads, output = execute_program(subject, probe=True)
    assert error is None and mutations == []
    value = json.loads(output[0])
    assert value["devices"] == {r: device(r) for r in storage.FILESYSTEMS}
    assert value["mount_root_absent"] and len(reads) == 5


def test_production_formatter_is_reached_only_after_both_admissions(subject):
    error, mutations, _, _ = execute_program(subject)
    assert isinstance(error, FormatReached)
    arguments = mutations[-1][1]
    assert arguments[:3] == ["/usr/sbin/mkfs.ext4", "-q", "-U"] and arguments[-1] == "/dev/vdb"
    assert "-F" not in arguments and "-f" not in arguments
    assert sum(m[0] == "mkdir" for m in mutations) == 3


@pytest.mark.parametrize(
    "change",
    [
        "serial",
        "size",
        "mounted",
        "formatted",
        "readonly",
        "partitions",
        "partition-table",
        "device-number",
        "not-block",
        "packages",
        "boot",
        "enrollment",
        "existing-root",
        "not-root",
        "account",
    ],
)
def test_production_program_refuses_before_any_mutation(subject, change):
    error, mutations, _, _ = execute_program(subject, change)
    assert isinstance(error, ValueError) and mutations == []


def permission_stream(events):
    class Stream(io.BytesIO):
        def fileno(self):
            return 17

        def write(self, value):
            events.append(("write", value))
            return super().write(value)

    return Stream()


def execute_permissions(subject, role, change=None):
    guest, instance, _ = subject
    instance.devices = {r: device(r) for r in storage.FILESYSTEMS}
    instance.state = {
        "root": {"device": 17, "inode": 23, "uid": 0, "gid": 0, "mode": 0o711},
        **{r: guest.snapshot(r) for r in storage.FILESYSTEMS},
    }
    c = instance.configuration()
    c["role"] = role
    events = []
    output = []
    account = c["accounts"][role]

    def denied():
        raise OSError(
            {"wrong-denial": errno.ENOENT}.get(change, errno.EACCES), "controlled refusal"
        )

    class Path:
        def __init__(self, value):
            self.value = str(value)

        def __str__(self):
            return self.value

        def __fspath__(self):
            return self.value

        def __truediv__(self, name):
            return Path(str(PurePosixPath(self.value) / name))

        def read_text(self):
            if self.value.endswith("boot_id"):
                return str(uuid.uuid4()) if change == "boot" else c["boot_id"]
            return str(uuid.uuid4()) if change == "enrollment" else c["enrollment"]

        def lstat(self):
            v = copy.deepcopy(c["state"][PurePosixPath(self.value).name]["directory"])
            if change == "inode":
                v["inode"] += 1
            return SimpleNamespace(
                st_mode=stat.S_IFDIR | v["mode"],
                st_dev=v["device"],
                st_ino=v["inode"],
                st_uid=v["uid"],
                st_gid=v["gid"],
            )

        def read_bytes(self):
            if "/control/" in self.value or role == "peer":
                return denied()
            return ("data:" + c["enrollment"] + "\n").encode()

        def iterdir(self):
            return denied()

        def unlink(self):
            if "/control/" in self.value or role == "peer":
                return denied()
            events.append("unlink")

        def rename(self, target):
            events.append("rename")

    def open_file(path, flags, *args):
        if "/control/" in str(path) or role == "peer":
            return denied()
        events.append("append" if flags & os.O_APPEND else "create")
        return 17

    fake_os = SimpleNamespace(
        getuid=lambda: 0 if change == "uid" else account["uid"],
        geteuid=lambda: account["uid"],
        getgid=lambda: account["gid"],
        getegid=lambda: account["gid"],
        open=open_file,
        close=lambda fd: events.append("close"),
        fdopen=lambda fd, mode: permission_stream(events),
        fsync=lambda fd: events.append("fsync"),
        O_WRONLY=os.O_WRONLY,
        O_CREAT=os.O_CREAT,
        O_EXCL=os.O_EXCL,
        O_NOFOLLOW=os.O_NOFOLLOW,
        O_APPEND=os.O_APPEND,
    )
    modules = {
        "errno": errno,
        "json": json,
        "os": fake_os,
        "pathlib": SimpleNamespace(Path=Path),
        "pwd": SimpleNamespace(getpwuid=lambda uid: SimpleNamespace(pw_name=account["name"])),
        "stat": stat,
        "sys": SimpleNamespace(argv=["permissions", json.dumps(c)]),
        "uuid": uuid,
    }
    scope = {
        "__builtins__": {
            **vars(builtins),
            "__import__": lambda name, *args, **kwargs: modules[name],
            "print": output.append,
        }
    }
    try:
        exec(compile(storage.PERMISSIONS, "guest-permissions", "exec"), scope)
    except Exception as error:
        return error, events, output
    return None, events, output


@pytest.mark.parametrize("role", ["admin", "peer"])
def test_production_permission_probe_observes_separate_accounts(subject, role):
    error, events, output = execute_permissions(subject, role)
    assert error is None
    value = json.loads(output[0])
    assert value["role"] == role and len(value["denied"]) == (8 if role == "peer" else 4)
    if role == "peer":
        assert events == [] and value["allowed"] == []
    else:
        assert events == [
            "create",
            "close",
            "rename",
            "unlink",
            "append",
            ("write", b"admin-write\n"),
            "fsync",
        ]


@pytest.mark.parametrize("change", ["uid", "boot", "enrollment", "inode", "wrong-denial"])
def test_production_permission_probe_refuses_false_identity_or_denial(subject, change):
    error, events, output = execute_permissions(subject, "admin", change)
    assert isinstance(error, ValueError) and events == [] and output == []


@pytest.mark.parametrize(
    "mode",
    [
        "closed",
        "open",
        "timeout-result",
        "observer-error",
        "wrong-address",
        "unowned",
        "bool-port",
        "zero-port",
        "large-port",
    ],
)
def test_cleanup_endpoint_requires_actual_refusal_on_the_exact_loopback_listener(monkeypatch, mode):
    endpoint = {"address": "127.0.0.1", "port": 2222, "owned_listener": True}
    mutations = {
        "wrong-address": {"address": "192.0.2.1"},
        "unowned": {"owned_listener": False},
        "bool-port": {"port": True},
        "zero-port": {"port": 0},
        "large-port": {"port": 65536},
    }
    endpoint.update(mutations.get(mode, {}))
    calls = []

    def connect(address):
        calls.append(address)
        if mode == "observer-error":
            raise OSError("private-observer-failure")
        return {"open": 0, "timeout-result": errno.ETIMEDOUT}.get(mode, errno.ECONNREFUSED)

    observer = SimpleNamespace(settimeout=lambda value: calls.append(value), connect_ex=connect)
    monkeypatch.setattr(native.socket, "socket", lambda *a: nullcontext(observer))
    if mode == "closed":
        native.endpoint_closed(endpoint)
        assert calls[-1] == ("127.0.0.1", 2222)
    else:
        with pytest.raises(storage.GuestStorageError, match="cleanup-endpoint") as error:
            native.endpoint_closed(endpoint)
        assert "private-observer-failure" not in str(error.value)
    if mode in mutations:
        assert calls == []


def cleanup_reports():
    guest = {
        "process_reaped": True,
        "temporary_resources_removed": True,
        "storage": {"resources_destroyed_with_guest": False},
        "endpoint": {"address": "127.0.0.1", "port": 2222, "owned_listener": True},
    }
    inputs = {"temporary_resources_removed": True, "base_preserved": True}
    return guest, inputs


@pytest.mark.parametrize(
    "missing",
    ["none", "process", "guest-private", "disks", "base", "storage", "endpoint", "still-listening"],
)
def test_cleanup_acceptance_follows_all_resource_owners_and_independent_endpoint_observer(
    monkeypatch, missing
):
    guest, inputs = cleanup_reports()
    cases = {
        "process": (guest, "process_reaped", False),
        "guest-private": (guest, "temporary_resources_removed", 1),
        "disks": (inputs, "temporary_resources_removed", False),
        "base": (inputs, "base_preserved", False),
        "storage": (guest, "storage", None),
        "endpoint": (guest, "endpoint", None),
    }
    if missing in cases:
        row, key, value = cases[missing]
        row[key] = value
    calls = []

    def observe(endpoint):
        assert guest["storage"]["resources_destroyed_with_guest"] is False
        calls.append(copy.deepcopy(endpoint))
        if missing == "still-listening":
            raise storage.GuestStorageError("cleanup-endpoint-still-available")

    monkeypatch.setattr(native, "endpoint_closed", observe)
    if missing == "none":
        native.verify_guest_cleanup(guest, inputs)
        assert guest["storage"]["resources_destroyed_with_guest"] is True
        assert guest["endpoint"]["closed_after_cleanup"] is True
    else:
        with pytest.raises(storage.GuestStorageError):
            native.verify_guest_cleanup(guest, inputs)
        assert (
            not isinstance(guest["storage"], dict)
            or not guest["storage"]["resources_destroyed_with_guest"]
        )
    assert len(calls) == int(missing in {"none", "still-listening"})


@pytest.mark.parametrize(
    "mode",
    [
        "expected",
        "wrong-failure",
        "no-failure",
        "not-injected",
        "unverified-boot",
        "unclean",
        "unrelated-changed",
    ],
)
def test_partial_storage_fault_requires_exact_failure_and_cleanup_without_changing_unrelated_state(
    tmp_path, monkeypatch, mode
):
    results = []
    events = []
    current_guest = {}

    @contextmanager
    def inputs(enrollment, temporary, command, progress, report):
        assert uuid.UUID(enrollment).version == 4 and temporary == tmp_path
        assert not (tmp_path / "owned-disk").exists()
        (tmp_path / "owned-disk").write_text("controlled disk")
        events.append("inputs")
        try:
            yield SimpleNamespace(enrollment=enrollment)
        finally:
            (tmp_path / "owned-disk").unlink()
            report.update(temporary_resources_removed=True, base_preserved=True)
            events.append("disks-removed")

    def boot(owner, tools, digest, temporary, report, *, storage_failure):
        assert storage_failure is True and digest == "c" * 64
        assert tools == {"controlled": True} and temporary == tmp_path
        assert owner.enrollment == results[0]["enrollment"]
        current_guest.update(enrollment=owner.enrollment)
        guest, _ = cleanup_reports()
        report.update(guest, boot_verified=mode != "unverified-boot", status="failed")
        report["storage"].update(
            status="failed",
            permissions_verified=False,
            fault_injection_verified=mode != "not-injected",
        )
        (tmp_path / "private-key").write_text("controlled private input")
        try:
            if mode == "unrelated-changed":
                next(tmp_path.glob("fishhat-canary-*/unrelated")).write_text("changed")
            if mode == "no-failure":
                return
            raise storage.GuestStorageError(
                "unexpected-guest-refusal"
                if mode == "wrong-failure"
                else "injected-after-control-mount"
            )
        finally:
            (tmp_path / "private-key").unlink()
            report["process_reaped"] = mode != "unclean"
            events.append("guest-reaped")

    def observe(endpoint):
        assert events == ["inputs", "guest-reaped", "disks-removed"]
        assert not (tmp_path / "owned-disk").exists() and not (tmp_path / "private-key").exists()
        events.append("endpoint-observed")

    monkeypatch.setattr(native, "guest_inputs", inputs)
    monkeypatch.setattr(native, "boot_guest", boot)
    monkeypatch.setattr(native, "endpoint_closed", observe)
    if mode == "expected":
        native.guest_storage_faults({"controlled": True}, "c" * 64, tmp_path, results)
    else:
        with pytest.raises(storage.GuestStorageError):
            native.guest_storage_faults({"controlled": True}, "c" * 64, tmp_path, results)
    case = results[0]
    assert case["expected_failure_verified"] is (mode == "expected")
    assert case["status"] == "failed" and case["scenario"] == "after-control-mount"
    assert case["unrelated_state_preserved"] is (mode != "unrelated-changed")
    assert (
        valid_stats(case["statistics"])
        and case["statistics"]["scope"] == "process-excludes-children"
    )
    assert not list(tmp_path.iterdir())
    assert events[:3] == ["inputs", "guest-reaped", "disks-removed"]
    assert ("endpoint-observed" in events) is (mode != "unclean")


@pytest.mark.parametrize("failure", ["none", "cleanup", "fault", "reboot-fault"])
def test_main_cannot_pass_storage_cleanup_or_fault_failure_and_preserves_statistics(
    tmp_path, monkeypatch, failure
):
    output = tmp_path / "report.json"
    source = {"commit": "a" * 40, "clean": True, "fingerprint": "b" * 64}
    events = []
    monkeypatch.setattr(native, "enroll", lambda *a, **k: {})
    monkeypatch.setattr(native, "source_identity", lambda: source)
    monkeypatch.setattr(native, "provision", lambda: {"binary_sha256": "c" * 64})
    monkeypatch.setattr(native, "probe_controller", lambda *a: {})
    monkeypatch.setattr(native, "controller_faults", lambda *a: None)
    monkeypatch.setattr(native, "provision_tools", lambda *a: {})
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))

    @contextmanager
    def inputs(*args):
        try:
            yield object()
        finally:
            events.append("input-cleanup")

    def boot(*args):
        args[-1].update(boot_verified=True)
        events.append("boot-storage")

    def cleanup(*args):
        events.append("cleanup-observation")
        if failure == "cleanup":
            raise storage.GuestStorageError("guest-resources-not-removed")

    def faults(*args):
        events.append("fault-observation")
        if failure == "fault":
            raise storage.GuestStorageError("required-storage-failure-proof-missing")

    monkeypatch.setattr(native, "guest_inputs", inputs)
    monkeypatch.setattr(native, "boot_guest", boot)
    monkeypatch.setattr(native, "verify_guest_cleanup", cleanup)
    monkeypatch.setattr(native, "guest_storage_faults", faults)

    def reboot_faults(*args):
        events.append("reboot-fault-observation")
        if failure == "reboot-fault":
            raise native.GuestBootError("required-reboot-interruption-missing")

    monkeypatch.setattr(native, "guest_reboot_faults", reboot_faults)

    def successor(*args):
        events.append("successor-timeline")
        args[-1].update(status="passed", observed_successor_verified=True)

    monkeypatch.setattr(native, "qualify_source_successor", successor)
    assert native.main(["--github-hosted-only", "--output", str(output)]) == int(failure != "none")
    report = json.loads(output.read_text())
    assert report["status"] == ("passed" if failure == "none" else "failed")
    assert report["source_before"] == report["source_after"] == source
    assert report["guest_booted"] is True
    assert report["native_tools_qualified"] is report["production_qualified"] is False
    assert (
        valid_stats(report["statistics"])
        and report["statistics"]["scope"] == "process-excludes-children"
    )
    assert events[:3] == ["boot-storage", "input-cleanup", "cleanup-observation"]
    assert "successor-timeline" not in events
    assert ("fault-observation" in events) is (failure != "cleanup")
    assert ("reboot-fault-observation" in events) is (failure not in ("cleanup", "fault"))


@pytest.mark.parametrize(
    "change",
    [
        "valid",
        "uuid",
        "type",
        "device",
        "partition-table",
        "partition-entry",
        "duplicate",
        "missing",
        "malformed",
    ],
)
def test_raw_filesystem_probe_bypasses_udev_and_refuses_foreign_or_ambiguous_identity(
    subject, change
):
    guest, instance, _ = subject
    c = instance.configuration()
    role = "data"
    d = device(role)
    values = {
        "DEVNAME": d["path"],
        "TYPE": "xfs",
        "UUID": instance.uuids[role],
        "USAGE": "filesystem",
    }
    values.update(
        {
            "uuid": {"UUID": str(uuid.uuid4())},
            "type": {"TYPE": "ext4"},
            "device": {"DEVNAME": "/dev/vda"},
            "partition-table": {"PTTYPE": "gpt"},
            "partition-entry": {"PART_ENTRY_UUID": str(uuid.uuid4())},
        }.get(change, {})
    )
    if change == "missing":
        del values["UUID"]
    output = "\n".join(name + "=" + value for name, value in values.items())
    if change == "duplicate":
        output += "\nUUID=" + instance.uuids[role]
    if change == "malformed":
        output = "private-malformed-output"
    calls = []

    def command(arguments):
        calls.append(arguments)
        assert arguments == ["/usr/sbin/blkid", "--probe", "--output", "export", d["path"]]
        return output

    tree = ast.parse(storage.PROGRAM)
    selected = ast.Module(
        body=[
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name in {"require", "filesystem"}
        ],
        type_ignores=[],
    )
    scope = {"c": c, "pairs": {role: (d, {})}, "command": command}
    exec(compile(selected, "guest-filesystem-probe", "exec"), scope)
    if change == "valid":
        assert scope["filesystem"](role) == {"filesystem": "xfs", "uuid": instance.uuids[role]}
    else:
        with pytest.raises(ValueError):
            scope["filesystem"](role)
    assert len(calls) == 1 and guest.calls == []
