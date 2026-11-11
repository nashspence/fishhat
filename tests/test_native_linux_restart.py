"""Controlled retained-input custody and cold replacement; no native tools run."""

from __future__ import annotations

import copy
import errno
import hashlib
import json
import os
import shlex
import socket
import subprocess
import sys
import tempfile
import uuid
from contextlib import contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_linux_enrollment as native
from scripts import native_linux_guest as guests
from scripts import native_linux_images as images
from scripts import native_linux_reboot as reboot
from scripts import native_linux_restart as restart
from scripts.run_stats import valid_stats
from scripts.validation_timeouts import watchdog

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/native_linux_restart.py",
        "scripts/native_linux_guest.py",
        "scripts/native_linux_enrollment.py",
    ],
    "scope": "exact protected boot-input lifetime and borrowing, accepted captured-source byte lineage and prior controller absence, original-disk replacement prelaunch/boot/canary/refusal ordering and separately bound admission, source evidence preservation and exact cleanup with required real statistics",
    "relationship": "no-product-claim",
    "reason": "SSH, guest disk/OS/canary observations and paused-controller admission are substituted. Real unprivileged files, private sockets, loopback probes and short Python children challenge custody and cleanup only. No QEMU, restored guest, native product or writer authority is qualified.",
    "claims": [],
}


def boot_identity(guest):
    return {
        "distribution": "ubuntu",
        "distribution_version": "24.04",
        "machine": "x86_64",
        "kernel": guests.KERNEL,
        "pid1": "systemd",
        "cgroup_v2": True,
        "dmi_uuid": guest.enrollment,
        "enrollment": guest.enrollment,
        "instance_id": guest.enrollment,
        "ssh_principal": guest.accounts[0],
        "packages": copy.deepcopy(guests.GUEST_PACKAGES),
        "cloud_init_complete": True,
        "boot_id": str(uuid.uuid4()),
        "accounts": {
            name: {"uid": 1000 + i, "gid": 1000 + i} for i, name in enumerate(guest.accounts)
        },
    }


def canary_observation(guest):
    content = "reboot:" + guest.enrollment + "\n" + str(uuid.uuid4()) + "\n"
    dev = os.makedev(8, 1)
    value = {
        "disks": {
            role: {
                "path": "/dev/vd" + chr(97 + i),
                "device": os.makedev(8, 16 * i),
                "major": 8,
                "minor": 16 * i,
                "bytes": size,
                "serial": "fh-" + role,
            }
            for i, (role, size) in enumerate(
                (k.removesuffix(".qcow2"), v) for k, v in images.DISK_BYTES.items()
            )
        },
        "root_filesystem": {
            "path": "/dev/vda1",
            "device": dev,
            "uuid": str(uuid.uuid4()),
            "filesystem": "ext4",
        },
        "directory": {"device": dev, "inode": 200, "uid": 0, "gid": 0, "mode": 0o700},
        "file": {
            "device": dev,
            "inode": 201,
            "uid": 0,
            "gid": 0,
            "mode": 0o600,
            "links": 1,
            "size": len(content.encode()),
        },
        "content": content,
        "sha256": hashlib.sha256(content.encode()).hexdigest(),
    }
    return {
        "mode": "prepare",
        "probe": str(uuid.uuid4()),
        "enrollment": guest.enrollment,
        "boot_id": guest.observed["boot_id"],
        "identity": value,
        "canary_fsynced": True,
        "denied_canary_absent": True,
        "observer": {
            "pid": 2001,
            "executable": {"path": "/usr/bin/python3.12", "sha256": "b" * 64},
        },
    }


class ControlledSSH:
    def __init__(self, fixture):
        self.f = fixture

    def value(self):
        f = self.f
        value = copy.deepcopy(f.before)
        value["boot_id"] = f.after
        if f.mode == "accounts-changed":
            value["accounts"][f.guest.accounts[0]]["uid"] += 100
        if f.mode == "foreign-profile":
            value["enrollment"] = str(uuid.uuid4())
        return value

    def __call__(self, arguments, name, nominal, *, capture=False):
        f = self.f
        assert name == "guest-ssh" and nominal > 0 and capture
        f.commands.append(arguments)
        assert f.child.process.pid != f.guest.process.pid and f.child.process.poll() is None
        parts = shlex.split(arguments[-1])
        assert parts[parts.index("-c") + 1] == guests.REMOTE
        expected, action = json.loads(parts[-2]), json.loads(parts[-1])
        value = self.value()
        if expected is None:
            f.reads += 1
            if f.mode == "readiness-error":
                raise native.EnrollmentError("guest-ssh", "command-exit-1")
            if f.mode == "read-timeout" and f.reads == 1:
                raise native.EnrollmentError("guest-ssh", "observation-deadline")
            if f.mode == "old-then-new" and f.reads == 1:
                value["boot_id"] = f.before["boot_id"]
            if f.mode == "incomplete-then-ready" and f.reads == 1:
                value["cloud_init_complete"] = False
            if f.mode == "changed-final" and f.reads > 1:
                value["boot_id"] = str(uuid.uuid4())
            return json.dumps(value)
        if expected != value:
            f.refused.append(expected)
            if f.mode == "stale-accepted":
                return ""
            raise native.EnrollmentError("guest-ssh", "command-exit-73")
        assert action[:5] == ["/usr/bin/python3", "-I", "-S", "-c", reboot.PROGRAM]
        c = json.loads(action[-1])
        assert c["mode"] == "inspect"
        result = copy.deepcopy(f.prepared)
        result.update(
            mode="inspect", probe=c["probe"], boot_id=value["boot_id"], canary_fsynced=False
        )
        if f.mode == "canary-changed":
            result["identity"]["sha256"] = "0" * 64
        if f.mode == "canary-enrollment-changed":
            result["enrollment"] = str(uuid.uuid4())
        if f.mode == "private-changed-after-read":
            (f.private / "seed.iso").write_bytes(b"controlled-substitution")
        if f.mode == "legitimate-source-writes":
            (f.inputs / "root.qcow2").write_bytes(b"controlled-guest-write")
        f.probes.append(c["probe"])
        return json.dumps(result)


@pytest.fixture
def fixture(tmp_path, tmp_path_factory, monkeypatch):
    directory, private = (tmp_path / n for n in ("inputs", "private"))
    # Keep private Unix-domain control endpoints in a short owned test root.
    temporary = tmp_path_factory.mktemp("fhrt") / "temporary"
    for path in (directory, private, temporary):
        path.mkdir(mode=0o700)
    base = b"controlled-base"
    monkeypatch.setattr(images, "IMAGE_BYTES", len(base))
    monkeypatch.setattr(images, "IMAGE_SHA256", hashlib.sha256(base).hexdigest())
    inputs = images.GuestInputs(
        str(uuid.uuid4()), directory, images.identity(directory, directory=True)
    )
    for name in ("base.img", *images.DISK_BYTES):
        p = directory / name
        p.write_bytes(base if name == "base.img" else name.encode())
        p.chmod(0o400 if name == "base.img" else 0o600)
        inputs.register(name)
    monkeypatch.setattr(guests, "tool_hashes", lambda: {"controlled": "a" * 64})
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    f = SimpleNamespace(
        mode="normal",
        commands=[],
        reads=0,
        refused=[],
        probes=[],
        child=None,
        after=str(uuid.uuid4()),
        inputs=directory,
        private=private,
        temporary=temporary,
    )
    report = {
        "key_fingerprints": {
            role: "SHA256:controlled-" + role for role in ("host", "admin", "peer")
        },
        "controller_verified": {
            "instance_uuid": inputs.enrollment,
            "unix_peer_verified": True,
            "started_from_verified_prelaunch": True,
            "executable_sha256": "c" * 64,
        },
    }
    guest = guests.Guest(
        inputs,
        private,
        ControlledSSH(f),
        {"sha256": {"controlled": "a" * 64}},
        report,
        port,
        Path("/controlled/qemu"),
        images.identity(private, directory=True),
    )
    for name in sorted(restart.PRIVATE_FILES):
        guest.write(name, "controlled-private-input-" + name)
    process = subprocess.Popen([sys.executable, "-I", "-S", "-c", "pass"], start_new_session=True)
    process.wait(timeout=watchdog(5))
    endpoint = temporary / "old-ended" / "qmp"
    process.args = ["controlled-qemu", "-qmp", f"unix:{endpoint},server=on,wait=off"]
    guest.process = process
    guest.observed = boot_identity(guest)
    report["identity"] = copy.deepcopy(guest.observed)
    f.guest, f.before = guest, copy.deepcopy(guest.observed)
    f.prepared = canary_observation(guest)
    report["reboot"] = {"phases": [{"observation": copy.deepcopy(f.prepared)}]}
    f.custody = {
        "pid": process.pid,
        "pgid": process.pid,
        "controller": copy.deepcopy(report["controller_verified"]),
        "endpoint": {"address": "127.0.0.1", "port": port, "listener_owned": True},
        "control_socket": {"path": str(endpoint)},
        "input_directory": {"path": str(directory), "identity": inputs.directory_identity},
        "private_directory": {"path": str(private), "identity": guest.directory_identity},
        "private_files": {
            name: {"path": str(guest.path(name)), "identity": value[0]}
            for name, value in guest.files.items()
        },
        "disks": {
            name: {"path": str(inputs.path(name, inputs.enrollment)), "identity": value}
            for name, value in inputs.files.items()
        },
    }
    monkeypatch.setattr(guests, "listening_endpoints", lambda pid: [("127.0.0.1", port)])
    monkeypatch.setattr(reboot, "time", SimpleNamespace(sleep=lambda seconds: None))
    f.expected_source = restart.stopped_source(guest, f.custody)
    report["snapshot_capture"] = {
        "status": "passed",
        "scope": "owned-disposable-cold-disk-bytes-only",
        "source_preserved": True,
        "temporary_resources_removed": True,
        "phases": [{"phase": "preservation", "source_after": copy.deepcopy(f.expected_source)}],
    }
    return f


@contextmanager
def controller(f, child):
    f.child = child
    with tempfile.TemporaryDirectory(prefix="controlled-controller-", dir=f.temporary) as folder:
        endpoint = Path(folder) / "qmp"
        with socket.socket(socket.AF_UNIX) as control:
            control.bind(str(endpoint))
            endpoint.chmod(0o700)
            process = subprocess.Popen(
                [sys.executable, "-I", "-S", "-c", "import sys;sys.stdin.buffer.read()"],
                stdin=subprocess.PIPE,
                start_new_session=True,
            )
            child.process = process
            process.args = ["controlled-qemu", "-qmp", f"unix:{endpoint},server=on,wait=off"]
            child.report["control_endpoint"] = str(endpoint)
            child.report["controller_verified"] = copy.deepcopy(
                f.guest.report["controller_verified"]
            )

            def verify(deadline):
                assert deadline.remaining() > 0 and process.poll() is None
                assert os.getpgid(process.pid) == process.pid

            child.verify_process = verify
            try:
                if f.mode == "prelaunch-refused":
                    raise native.EnrollmentError(
                        "controller-identity", "controlled-prelaunch-refusal"
                    )
                yield endpoint
            finally:
                process.stdin.close()
                try:
                    process.wait(timeout=watchdog(5))
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=watchdog(5))


def qualify(f, report):
    f.guest.report["retained_restart"] = report
    restart.qualify_restart(
        f.guest,
        f.custody,
        f.temporary,
        lambda name: nullcontext(),
        lambda child: controller(f, child),
        report,
    )


def private_inputs(f):
    rows = {}
    for path in f.private.iterdir():
        content = path.read_bytes()
        v = path.lstat()
        rows[path] = (
            content,
            v.st_dev,
            v.st_ino,
            v.st_uid,
            v.st_gid,
            v.st_mode,
            v.st_nlink,
            v.st_size,
            v.st_mtime_ns,
        )
    return rows


@pytest.mark.parametrize(
    "mode",
    ["normal", "old-then-new", "incomplete-then-ready", "read-timeout", "legitimate-source-writes"],
)
def test_exact_retained_inputs_fresh_binding_canary_refusals_and_complete_cleanup(fixture, mode):
    f = fixture
    f.mode = mode
    original = copy.deepcopy(f.guest.report)
    private = private_inputs(f)
    report = {}
    qualify(f, report)
    assert report["status"] == "passed" and report["original_guest_evidence_preserved"]
    assert {k: v for k, v in f.guest.report.items() if k != "retained_restart"} == original
    assert f.guest.observed == f.before and f.child.observed["boot_id"] == f.after
    assert f.child.process is not f.guest.process and f.child.process.returncode == 0
    assert f.child.verify_process is not f.guest.verify_process
    assert f.child.files == f.guest.files and f.child.directory == f.guest.directory
    assert private_inputs(f) == private
    assert report["boot_inputs"]["closure_before"] == report["boot_inputs"]["closure_after"]
    assert (
        report["boot_inputs"]["shared_private_inputs_preserved"]
        and report["boot_inputs"]["lifetime_ended"]
    )
    assert report["expired_handle_refused"] and not f.guest.boot_inputs_borrowed
    assert len(f.refused) == 2 and f.refused[0]["boot_id"] == f.before["boot_id"]
    assert len(f.probes) == len(set(f.probes)) == 3
    assert report["unrelated_canary_preserved"] and not list(f.temporary.iterdir())
    assert report["snapshot_restore_qualified"] is report["product_authority_qualified"] is False
    assert valid_stats(report["statistics"]) and valid_stats(report["boot_inputs"]["statistics"])
    assert all(p["status"] == "passed" and valid_stats(p["statistics"]) for p in report["phases"])
    assert report["phases"][-1]["observation"]["group_absent"]


def test_handle_rejects_expired_foreign_duplicate_and_concurrent_borrowing_before_effects(fixture):
    f = fixture
    report = {}
    with restart.retained_boot_inputs(
        f.guest, f.custody, report, expected_source=f.expected_source
    ) as owned:
        with pytest.raises(restart.GuestRestartError, match="foreign-boot-input-enrollment"):
            owned.guest(str(uuid.uuid4()), {})
        with pytest.raises(restart.GuestRestartError, match="boot-inputs-already-borrowed"):
            with restart.retained_boot_inputs(
                f.guest, f.custody, {}, expected_source=f.expected_source
            ):
                pytest.fail("concurrent borrowing admitted")
        child = owned.guest(f.guest.enrollment, {})
        assert child.process is child.verify_process is child.observed is None
        with pytest.raises(restart.GuestRestartError, match="already-borrowed"):
            owned.guest(f.guest.enrollment, {})
        assert not f.commands
    with pytest.raises(restart.GuestRestartError, match="expired"):
        owned.guest(f.guest.enrollment, {})
    assert report["status"] == "passed" and report["lifetime_ended"]
    assert valid_stats(report["statistics"]) and not f.guest.boot_inputs_borrowed


@pytest.mark.parametrize(
    "change",
    [
        "private-bytes",
        "private-mode",
        "private-replaced",
        "private-rebound",
        "tool",
        "port",
        "qemu",
        "profile",
        "disk-rebound",
        "disk-bytes",
        "base",
        "incomplete",
    ],
)
def test_changed_retained_closure_or_stopped_source_refuses_before_child_creation(
    fixture, monkeypatch, change
):
    f = fixture
    report = {}
    with pytest.raises((guests.GuestBootError, images.GuestInputError, OSError)):
        with restart.retained_boot_inputs(
            f.guest, f.custody, report, expected_source=f.expected_source
        ) as owned:
            if change in ("private-bytes", "private-rebound"):
                (f.private / "seed.iso").write_bytes(b"changed")
                if change == "private-rebound":
                    f.guest.register("seed.iso")
            elif change == "private-mode":
                (f.private / "admin").chmod(0o644)
            elif change == "private-replaced":
                candidate = f.private / "replacement"
                candidate.write_bytes(b"changed")
                candidate.chmod(0o600)
                candidate.replace(f.private / "seed.iso")
            elif change == "tool":
                monkeypatch.setattr(guests, "tool_hashes", lambda: {"controlled": "d" * 64})
            elif change == "port":
                f.guest.port += 1
            elif change == "qemu":
                f.guest.qemu = Path("/controlled/other")
            elif change == "profile":
                f.guest.report["controller_verified"]["executable_sha256"] = "d" * 64
            elif change == "disk-rebound":
                candidate = f.inputs / "replacement"
                candidate.write_bytes(b"changed")
                candidate.chmod(0o600)
                candidate.replace(f.inputs / "root.qcow2")
                f.guest.inputs.files["root.qcow2"] = images.identity(f.inputs / "root.qcow2")
            elif change == "disk-bytes":
                (f.inputs / "root.qcow2").write_bytes(b"changed")
            elif change == "base":
                base = f.inputs / "base.img"
                base.chmod(0o600)
                base.write_bytes(b"changed")
                base.chmod(0o400)
            else:
                del f.guest.files["host.pub"]
            owned.guest(f.guest.enrollment, {})
    assert not f.commands and f.child is None and report["status"] == "failed"
    assert valid_stats(report["statistics"])


@pytest.mark.parametrize(
    "mode",
    [
        "prelaunch-refused",
        "readiness-error",
        "foreign-profile",
        "accounts-changed",
        "canary-changed",
        "canary-enrollment-changed",
        "stale-accepted",
        "changed-final",
        "private-changed-after-read",
    ],
)
def test_failed_replacement_preserves_old_evidence_original_failure_and_owned_cleanup(
    fixture, mode
):
    f = fixture
    f.mode = mode
    before = copy.deepcopy(f.guest.observed)
    report = {}
    with pytest.raises((guests.GuestBootError, native.EnrollmentError, images.GuestInputError)):
        qualify(f, report)
    assert report["status"] == "failed" and f.guest.observed == before
    assert f.child.process.returncode == 0 and not list(f.temporary.iterdir())
    assert report["unrelated_canary_preserved"] and valid_stats(report["statistics"])
    assert report["snapshot_restore_qualified"] is report["product_authority_qualified"] is False
    assert all(valid_stats(p["statistics"]) for p in report["phases"])
    assert report["phases"][-1]["phase"] == "stopped-replacement"
    assert report["phases"][-1]["observation"]["process_absent"]
    if mode not in ("private-changed-after-read",):
        assert f.child.observed is None


@pytest.mark.parametrize("change", ["unreaped", "control-parent", "missing-admission"])
def test_old_controller_must_be_independently_gone_before_borrowing(fixture, change):
    f = fixture
    report = {}
    if change == "unreaped":
        f.guest.process.returncode = None
    elif change == "control-parent":
        Path(f.custody["control_socket"]["path"]).parent.mkdir()
    else:
        del f.guest.report["controller_verified"]
    with pytest.raises((guests.GuestBootError, images.GuestInputError, KeyError)):
        with restart.retained_boot_inputs(
            f.guest, f.custody, report, expected_source=f.expected_source
        ):
            pytest.fail("unproved source admitted")
    assert not f.commands and not f.guest.boot_inputs_borrowed
    assert report["status"] == "failed" and valid_stats(report["statistics"])


def test_live_process_cannot_be_adopted_as_an_absent_old_controller(fixture):
    f = fixture
    child = subprocess.Popen(
        [sys.executable, "-I", "-S", "-c", "import sys;sys.stdin.buffer.read()"],
        stdin=subprocess.PIPE,
        start_new_session=True,
    )
    original_pid = f.guest.process.pid
    try:
        f.guest.process.pid = child.pid
        f.custody["pid"] = f.custody["pgid"] = child.pid
        report = {}
        with pytest.raises(guests.GuestBootError, match="controller-still-present"):
            with restart.retained_boot_inputs(
                f.guest, f.custody, report, expected_source=f.expected_source
            ):
                pytest.fail("live source admitted")
        assert not f.commands and not f.guest.boot_inputs_borrowed
        assert report["status"] == "failed" and valid_stats(report["statistics"])
    finally:
        f.guest.process.pid = original_pid
        child.stdin.close()
        try:
            child.wait(timeout=watchdog(5))
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=watchdog(5))


@pytest.mark.parametrize(
    "change", ["missing-capture", "failed-capture", "wrong-recorded-source", "changed-source-bytes"]
)
def test_replacement_requires_the_exact_previously_accepted_capture_source(fixture, change):
    f = fixture
    captured = f.guest.report["snapshot_capture"]
    if change == "missing-capture":
        del f.guest.report["snapshot_capture"]
    elif change == "failed-capture":
        captured["status"] = "failed"
    elif change == "wrong-recorded-source":
        captured["phases"][-1]["source_after"]["disks"]["root.qcow2"]["sha256"] = "d" * 64
    else:
        (f.inputs / "root.qcow2").write_bytes(b"controlled-pre-admission-change")
    report = {}
    with pytest.raises(restart.GuestRestartError, match="accepted-"):
        qualify(f, report)
    assert report["status"] == "failed" and valid_stats(report["statistics"])
    assert not f.commands and f.child is None and not f.guest.boot_inputs_borrowed
    assert report["unrelated_canary_preserved"] and not list(f.temporary.iterdir())


def test_unknown_reaping_expires_the_handle_and_prevents_reborrowing(fixture):
    f = fixture
    report = {}
    child = None
    try:
        with pytest.raises(restart.GuestRestartError, match="replacement-not-reaped"):
            with restart.retained_boot_inputs(
                f.guest, f.custody, report, expected_source=f.expected_source
            ) as owned:
                child = owned.guest(f.guest.enrollment, {})
                with controller(f, child):
                    pass
                assert child.process.returncode == 0
                child.process.returncode = None
        assert not owned.active and f.guest.boot_inputs_borrowed
        assert report["status"] == "failed" and not report["lifetime_ended"]
        assert report["shared_private_inputs_preserved"] and valid_stats(report["statistics"])
        with pytest.raises(restart.GuestRestartError, match="boot-inputs-already-borrowed"):
            with restart.retained_boot_inputs(
                f.guest, f.custody, {}, expected_source=f.expected_source
            ):
                pytest.fail("unknown replacement accepted for another borrow")
        assert not list(f.temporary.iterdir()) and set(f.guest.files) == restart.PRIVATE_FILES
    finally:
        if child is not None and child.process is not None:
            child.process.returncode = 0


def test_controller_or_endpoint_still_present_cannot_prove_replacement_cleanup(fixture):
    f = fixture
    with restart.retained_boot_inputs(
        f.guest, f.custody, {}, expected_source=f.expected_source
    ) as owned:
        child = owned.guest(f.guest.enrollment, {})
        with controller(f, child):
            with pytest.raises(restart.GuestRestartError, match="replacement-not-reaped"):
                restart.stopped_replacement(child)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", child.port))
            listener.listen()
            with pytest.raises(restart.GuestRestartError, match="replacement-ssh-endpoint-remains"):
                restart.stopped_replacement(child)
        endpoint = Path(child.report["control_endpoint"])
        endpoint.parent.mkdir(mode=0o700)
        try:
            with pytest.raises(
                restart.GuestRestartError, match="replacement-control-endpoint-remains"
            ):
                restart.stopped_replacement(child)
        finally:
            endpoint.parent.rmdir()
        observed = restart.stopped_replacement(child)
        assert observed["process_absent"] and observed["group_absent"]
        assert observed["control_endpoint_removed"] and observed["ssh_endpoint_closed"]


def test_invalid_required_statistics_cannot_qualify_a_successful_replacement(fixture, monkeypatch):
    original = restart.RunStats

    class InvalidMetrics:
        def __init__(self):
            self.actual = original()

        def finish(self):
            self.actual.finish()
            return None

    monkeypatch.setattr(restart, "RunStats", InvalidMetrics)
    report = {}
    with pytest.raises(ValueError, match="invalid required"):
        qualify(fixture, report)
    assert report["status"] == report["boot_inputs"]["status"] == "failed"
    assert report["statistics"] is report["boot_inputs"]["statistics"] is None
    assert fixture.child.process.returncode == 0 and not list(fixture.temporary.iterdir())
    assert report["snapshot_restore_qualified"] is report["product_authority_qualified"] is False


def test_resource_failure_retains_safe_original_errno_and_cleanup(fixture):
    f = fixture

    @contextmanager
    def unavailable(child):
        with controller(f, child) as endpoint:
            if f.mode == "unavailable":
                raise OSError(errno.EACCES, "controlled-sensitive-output")
            yield endpoint

    f.mode = "unavailable"
    report = {}
    f.guest.report["retained_restart"] = report
    with pytest.raises(restart.GuestRestartError, match="restart-resource-unavailable"):
        restart.qualify_restart(
            f.guest, f.custody, f.temporary, lambda name: nullcontext(), unavailable, report
        )
    assert report["status"] == "failed" and valid_stats(report["statistics"])
    assert report["resource_failure"] == {"errno": errno.EACCES, "type": "PermissionError"}
    assert "controlled-sensitive-output" not in json.dumps(report)
    assert f.child.process.returncode == 0 and not list(f.temporary.iterdir())
    assert report["unrelated_canary_preserved"] and not f.guest.boot_inputs_borrowed
