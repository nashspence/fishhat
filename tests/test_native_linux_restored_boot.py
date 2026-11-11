"""Controlled restored-controller custody; native facilities are substituted."""

from __future__ import annotations

import copy
import os
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
from scripts import native_linux_restore as restore
from scripts import native_linux_restored_boot as restored
from scripts import native_linux_snapshots as snapshots
from scripts.run_stats import valid_stats
from scripts.validation_timeouts import watchdog
from tests.test_native_linux_restart import ControlledSSH, private_inputs
from tests.test_native_linux_restart import fixture as _restart_source
from tests.test_native_linux_restore import RestoreImages

restart_source = _restart_source

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/native_linux_restored_boot.py",
        "scripts/native_linux_restore.py",
        "scripts/native_linux_restart.py",
        "scripts/native_linux_guest.py",
        "scripts/native_linux_enrollment.py",
    ],
    "scope": "exact retained protected inputs, complete independent restored-disk admission to a fresh controller, explicit writable lifetime and reaped-controller closure, unchanged originals, stale/foreign/substituted/expired refusal, failure cleanup and valid real process statistics",
    "relationship": "no-product-claim",
    "reason": "QEMU/image tools, SSH/guest observations and verified prelaunch are substituted. Real private files, sockets and short unprivileged Python children test custody and lifecycle only; no native restored boot, full canary timeline or product authority is qualified.",
    "claims": [],
}


@pytest.fixture
def fixture(restart_source, monkeypatch):
    f = restart_source
    f.state = dict(
        mode="normal",
        calls=[],
        output={},
        snapshot_paths=[],
        restore_mode="normal",
        restoring=False,
        restore_paths=[],
    )
    f.tool = f.private.parent / "controlled-image-tool"
    f.tool.write_bytes(b"controlled-image-tool")
    f.tool.chmod(0o600)
    for module in (images, snapshots, restore):
        monkeypatch.setattr(module, "QEMU_IMG", f.tool)
    image = RestoreImages(f.inputs, f.tool, (f.inputs / "base.img").read_bytes(), f.state)
    ssh = ControlledSSH(f)

    def command(arguments, name, nominal, *, capture=False):
        if name != "guest-ssh":
            return image(arguments, name, nominal, capture=capture)
        value = ssh(arguments, name, nominal, capture=capture)
        if f.mode == "restored-writes" and f.child is not None:
            target = f.child.inputs.directory / "root.qcow2"
            target.write_bytes(target.read_bytes() + b"controlled-owned-writer")
        return value

    f.guest.command = command
    f.launched = []
    real_popen = subprocess.Popen

    def popen(arguments, **kwargs):
        assert arguments[0] == str(f.guest.qemu)
        f.launched.append(copy.deepcopy(arguments))
        process = real_popen(
            [sys.executable, "-I", "-S", "-c", "import sys;sys.stdin.buffer.read()"],
            stdin=subprocess.PIPE,
            start_new_session=True,
        )
        process.args = arguments
        return process

    monkeypatch.setattr(
        guests, "subprocess", SimpleNamespace(Popen=popen, DEVNULL=subprocess.DEVNULL)
    )
    return f


@contextmanager
def controller(f, child):
    f.child = child
    with tempfile.TemporaryDirectory(prefix="fhrbc-", dir=f.temporary) as directory:
        endpoint = Path(directory) / "qmp"
        with socket.socket(socket.AF_UNIX) as control:
            control.bind(str(endpoint))
            endpoint.chmod(0o700)
            process = child.launch(endpoint, child.enrollment)
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
                    raise restored.RestoredBootError("controlled-prelaunch-refusal")
                yield endpoint
            finally:
                process.stdin.close()
                try:
                    process.wait(timeout=watchdog(5))
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=watchdog(5))


def capture(f, report):
    return snapshots.cold_snapshots(
        f.guest, f.custody, f.temporary, lambda name: nullcontext(), report
    )


def prepared(f, sealed, captured, report):
    return restore.private_restored_disks(
        f.guest, f.custody, sealed, captured, f.temporary, lambda name: nullcontext(), report
    )


def qualify(f, sealed, captured, report):
    f.guest.report["restored_boot"] = report
    restored.qualify_restored_boot(
        f.guest,
        f.custody,
        sealed,
        captured,
        f.temporary,
        lambda name: nullcontext(),
        lambda child: controller(f, child),
        report,
    )


@pytest.mark.parametrize(
    "mode", ["normal", "old-then-new", "incomplete-then-ready", "read-timeout", "restored-writes"]
)
def test_fresh_private_boot_preserves_originals_and_closes_exact_writable_lifetime(fixture, mode):
    f = fixture
    f.mode = mode
    captured = {}
    report = {}
    original = copy.deepcopy(f.guest.report)
    private = private_inputs(f)
    disks = {
        p: (p.read_bytes(), images.identity(p), p.stat().st_mtime_ns) for p in f.inputs.iterdir()
    }
    with capture(f, captured) as sealed:
        sealed_before = copy.deepcopy(sealed.files)
        qualify(f, sealed, captured, report)
        assert sealed.files == sealed_before
        sealed.verify()
    assert report["status"] == "passed" and report["restored_boot_verified"]
    assert report["snapshot_restore_qualified"] is report["product_authority_qualified"] is False
    assert report["original_guest_evidence_preserved"] and report["unrelated_canary_preserved"]
    assert {k: v for k, v in f.guest.report.items() if k != "restored_boot"} == original
    assert private_inputs(f) == private
    assert {
        p: (p.read_bytes(), images.identity(p), p.stat().st_mtime_ns) for p in f.inputs.iterdir()
    } == disks
    assert f.child.inputs.directory != f.inputs and set(f.child.inputs.files) == set(
        images.DISK_BYTES
    )
    assert f.child.files == f.guest.files and f.child.directory == f.private
    assert f.child.process is not f.guest.process and f.child.process.returncode == 0
    assert f.child.observed["boot_id"] == f.after and f.guest.observed == f.before
    assert len(f.launched) == 1 and "-S" in f.launched[0]
    drives = [f.launched[0][i + 1] for i, a in enumerate(f.launched[0]) if a == "-drive"]
    for name in images.DISK_BYTES:
        assert any(
            "file=" + str(f.child.inputs.directory / name) + "," in value for value in drives
        )
        assert not any("file=" + str(f.inputs / name) + "," in value for value in drives)
    assert (
        report["writable_inputs"]["writer_absence_verified"]
        and report["writable_inputs"]["lifetime_ended"]
    )
    assert (
        report["private_inputs"]["originals_preserved"]
        and report["private_inputs"]["temporary_resources_removed"]
    )
    assert report["expired_writable_handle_refused"] and report["expired_boot_handle_refused"]
    assert not f.child.inputs.directory.exists() and not list(f.temporary.iterdir())
    assert report["boot_inputs"]["closure_before"] == report["boot_inputs"]["closure_after"]
    assert report["controller_custody"]["base_image_verified"] is False
    assert len(f.refused) == 2 and len(f.probes) == len(set(f.probes)) == 3
    initial = report["writable_inputs"]["admitted_files"]
    final = report["writable_inputs"]["written_files"]
    assert (initial == final) is (mode != "restored-writes")
    assert all(initial[n][0] == final[n][0] for n in images.DISK_BYTES)
    assert valid_stats(report["statistics"]) and valid_stats(
        report["writable_inputs"]["statistics"]
    )
    assert all(valid_stats(p["statistics"]) for p in report["phases"])


@pytest.mark.parametrize(
    "mode",
    [
        "prelaunch-refused",
        "readiness-error",
        "accounts-changed",
        "foreign-profile",
        "canary-changed",
        "canary-enrollment-changed",
        "stale-accepted",
        "changed-final",
        "private-changed-after-read",
        "legitimate-source-writes",
    ],
)
def test_failed_restored_boot_is_never_qualified_and_owned_controller_and_disks_are_removed(
    fixture, mode
):
    f = fixture
    f.mode = mode
    captured = {}
    report = {}
    with pytest.raises((RuntimeError, OSError)):
        with capture(f, captured) as sealed:
            qualify(f, sealed, captured, report)
    assert report["status"] == "failed" and report["restored_boot_verified"] is False
    assert report["problem"] and report["snapshot_restore_qualified"] is False
    assert f.child.process.returncode == 0 and not f.child.inputs.directory.exists()
    assert report["writable_inputs"]["writer_absence_verified"]
    assert report["private_inputs"]["temporary_resources_removed"]
    assert captured["temporary_resources_removed"] and not list(f.temporary.iterdir())
    assert valid_stats(report["statistics"]) and valid_stats(
        report["writable_inputs"]["statistics"]
    )


@pytest.mark.parametrize(
    "change",
    [
        "foreign",
        "expired",
        "missing",
        "extra",
        "replaced-disk",
        "mode",
        "owner-rebound",
        "directory-rebound",
        "files-rebound",
        "written-before-launch",
    ],
)
def test_invalid_writable_input_handles_refuse_before_controller_creation(fixture, change):
    f = fixture
    captured = {}
    report = {}
    writable = {}
    with pytest.raises((RuntimeError, OSError)):
        with capture(f, captured) as sealed, prepared(f, sealed, captured, report) as owner:
            with restored.writable_inputs(owner, writable) as handle:
                enrollment = f.guest.enrollment
                if change == "foreign":
                    enrollment = str(uuid.uuid4())
                elif change == "expired":
                    handle.active = False
                elif change == "missing":
                    (owner.directory / "control.qcow2").unlink()
                elif change == "extra":
                    (owner.directory / "unrelated").write_bytes(b"neighbor")
                elif change == "replaced-disk":
                    path = owner.directory / "root.qcow2"
                    path.unlink()
                    path.write_bytes(b"replaced")
                    path.chmod(0o600)
                elif change == "mode":
                    (owner.directory / "data.qcow2").chmod(0o400)
                elif change == "owner-rebound":
                    handle.owner = copy.copy(owner)
                elif change == "directory-rebound":
                    handle.directory = f.inputs
                elif change == "files-rebound":
                    handle.files["root.qcow2"] = f.guest.inputs.files["root.qcow2"]
                elif change == "written-before-launch":
                    (owner.directory / "root.qcow2").write_bytes(b"not-owned-writer")
                handle.path("root.qcow2", enrollment)
    assert not f.launched and report["status"] == "failed" and report["temporary_resources_removed"]
    assert not list(f.temporary.iterdir()) and valid_stats(writable["statistics"])


def test_cleanup_refuses_a_still_bound_writer_and_preserves_its_images(fixture):
    f = fixture
    captured = {}
    report = {}
    with capture(f, captured) as sealed:
        with pytest.raises(restore.RestoreError, match="restored-writer-still-active"):
            with prepared(f, sealed, captured, report) as owner:
                owner._writer = object()
        assert owner.directory.exists() and report["temporary_resources_removed"] is False
        assert report["cleanup_problem"]["reason"] == "restored-writer-still-active"
        owner._writer = None
        restore.remove_owned(owner, owner.directory, owner.directory_identity, report)
    assert not list(f.temporary.iterdir())


def test_writable_handle_expires_without_starting_a_controller(fixture):
    f = fixture
    captured = {}
    report = {}
    writable = {}
    with capture(f, captured) as sealed, prepared(f, sealed, captured, report) as owner:
        with restored.writable_inputs(owner, writable) as handle:
            handle.verify(f.guest.enrollment)
            assert handle.path("root.qcow2", f.guest.enrollment) == owner.directory / "root.qcow2"
        assert writable["writer_never_started"] and writable["status"] == "passed"
        with pytest.raises(restored.RestoredBootError, match="writable-input-handle-expired"):
            handle.path("root.qcow2", f.guest.enrollment)
    assert not f.launched and not list(f.temporary.iterdir())


def test_missing_required_writable_statistics_fails_without_claiming_success(fixture, monkeypatch):
    f = fixture
    captured = {}
    report = {}
    writable = {}
    with capture(f, captured) as sealed, prepared(f, sealed, captured, report) as owner:
        monkeypatch.setattr(restored, "valid_stats", lambda value: False)
        with pytest.raises(ValueError, match="invalid required restored writable-input statistics"):
            with restored.writable_inputs(owner, writable):
                pass
        assert writable["status"] == "failed"


def test_live_owned_controller_blocks_input_closure_and_deletion_until_reaped(fixture):
    f = fixture
    captured = {}
    report = {}
    writable = {}
    with capture(f, captured) as sealed, prepared(f, sealed, captured, report) as owner:
        with restored.retained_boot_inputs(
            f.guest, f.custody, {}, expected_source=restore.capture_projection(captured)["source"]
        ) as retained:
            with restored.writable_inputs(owner, writable) as handle:
                child = retained.guest(
                    f.guest.enrollment, {}, inputs=handle, guest_type=restored.RestoredGuest
                )
                with controller(f, child):
                    assert child.process.poll() is None
                    with pytest.raises(RuntimeError, match="replacement-not-reaped"):
                        handle.finish({})
                    with pytest.raises(restore.RestoreError, match="restored-writer-active"):
                        owner.path("root.qcow2", f.guest.enrollment)
                    assert owner.directory.exists() and owner._written_files is None
                    handle.path("root.qcow2", f.guest.enrollment).write_bytes(b"owned-write")
            assert writable["writer_absence_verified"] and writable["written_files_synced"]
            owner.verify()
    assert report["status"] == "passed" and not list(f.temporary.iterdir())


@pytest.mark.parametrize("field", ["controller", "process", "arguments", "inputs"])
def test_changed_live_controller_binding_is_refused(fixture, field):
    f = fixture
    captured = {}
    report = {}
    writable = {}
    with capture(f, captured) as sealed, prepared(f, sealed, captured, report) as owner:
        with restored.retained_boot_inputs(
            f.guest, f.custody, {}, expected_source=restore.capture_projection(captured)["source"]
        ) as retained:
            with restored.writable_inputs(owner, writable) as handle:
                child = retained.guest(
                    f.guest.enrollment, {}, inputs=handle, guest_type=restored.RestoredGuest
                )
                with controller(f, child):
                    saved = (
                        handle.controller,
                        child.process,
                        list(child.process.args),
                        child.inputs,
                    )
                    try:
                        if field == "controller":
                            handle.controller = copy.copy(child)
                        elif field == "process":
                            child.process = f.guest.process
                        elif field == "arguments":
                            child.process.args = ["changed"]
                        else:
                            child.inputs = f.guest.inputs
                        with pytest.raises(
                            restored.RestoredBootError, match="writable-controller-changed"
                        ):
                            handle.path("root.qcow2", f.guest.enrollment)
                    finally:
                        handle.controller, child.process, arguments, child.inputs = saved
                        child.process.args = arguments
    assert report["status"] == "passed" and not list(f.temporary.iterdir())


@pytest.mark.parametrize("missing", ["status", "boot", "inputs", "writer", "custody"])
def test_final_guest_teardown_refuses_missing_restored_boot_proofs(monkeypatch, missing):
    report = {
        "status": "passed",
        "restored_boot_verified": True,
        "private_inputs": {"temporary_resources_removed": True},
        "writable_inputs": {"writer_absence_verified": True},
        "controller_custody": {},
    }
    fields = {
        "status": "status",
        "boot": "restored_boot_verified",
        "inputs": "private_inputs",
        "writer": "writable_inputs",
        "custody": "controller_custody",
    }
    report.pop(fields[missing])
    observed = []
    monkeypatch.setattr(native, "observe_removed_resources", lambda value: observed.append(value))
    with pytest.raises(guests.GuestBootError, match="restored-boot-proof-incomplete"):
        native.verify_restored_boot_cleanup(report)
    assert not observed and not report.get("resources_destroyed_with_guest")


def test_final_guest_teardown_records_independent_original_resource_absence(monkeypatch):
    report = {
        "status": "passed",
        "restored_boot_verified": True,
        "private_inputs": {"temporary_resources_removed": True},
        "writable_inputs": {"writer_absence_verified": True},
        "controller_custody": {"owned": "original"},
    }
    observation = {"paths": [{"path": "/controlled/owned", "absent": True}]}

    def inspect(value):
        assert value is report["controller_custody"]
        return observation

    monkeypatch.setattr(native, "observe_removed_resources", inspect)
    native.verify_restored_boot_cleanup(report)
    assert report["cleanup"] is observation and report["resources_destroyed_with_guest"]
