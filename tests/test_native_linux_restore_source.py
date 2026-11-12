"""Controlled capture-owned restore guards; all native observations are substituted."""

from __future__ import annotations

import copy
import subprocess
import sys
import uuid
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from scripts import native_linux_guest as guests
from scripts import native_linux_restore as restore
from scripts import native_linux_restored_boot as restored
from scripts import native_linux_snapshots as snapshots
from scripts.run_stats import valid_stats
from tests.test_native_linux_restart import ControlledSSH
from tests.test_native_linux_restart import fixture as _restart_source
from tests.test_native_linux_restore import RestoreImages, observed_files
from tests.test_native_linux_restored_boot import controller as restored_controller
from tests.test_native_linux_successor import SuccessorSSH, advance, capture
from tests.test_native_linux_successor import fixture as _successor_source

successor_source = _successor_source
restart_source = _restart_source

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/native_linux_successor.py",
        "scripts/native_linux_snapshots.py",
        "scripts/native_linux_restore.py",
        "scripts/native_linux_restored_boot.py",
        "scripts/native_linux_restart.py",
    ],
    "scope": "exact active capture-owned original binding and separately witnessed later-source preservation, complete private restore and protected boot-input borrowing without caller-authorized byte drift, foreign/substituted/expired refusal, failure cleanup and required scoped statistics",
    "relationship": "no-product-claim",
    "reason": "Real unprivileged files, sockets and short Python children exercise custody. Image conversion, SSH/guest identity and native controller admission are explicitly substituted; no native advanced-source restored boot, full roundtrip or product authority is qualified.",
    "claims": [],
}


@pytest.fixture
def fixture(successor_source, monkeypatch):
    f = successor_source
    f.state.update(restore_mode="normal", restoring=False, restore_paths=[])
    monkeypatch.setattr(restore, "QEMU_IMG", f.tool)
    image = RestoreImages(f.inputs, f.tool, (f.inputs / "base.img").read_bytes(), f.state)
    successor_ssh, restored_ssh = SuccessorSSH(f), ControlledSSH(f)

    def command(arguments, name, nominal, *, capture=False):
        if name != "guest-ssh":
            return image(arguments, name, nominal, capture=capture)
        ssh = restored_ssh if isinstance(f.child, restored.RestoredGuest) else successor_ssh
        return ssh(arguments, name, nominal, capture=capture)

    f.guest.command = command
    real_popen = subprocess.Popen
    f.launched = []

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


def prepared(f, owned, captured, report):
    return restore.private_restored_disks(
        f.guest, f.custody, owned, captured, f.temporary, lambda _: nullcontext(), report
    )


def test_private_restore_preserves_the_witnessed_later_source_and_original_capture(fixture):
    f = fixture
    captured, transition, report = {}, {}, {}
    with capture(f, captured) as owned:
        original = copy.deepcopy(captured)
        sealed_files = observed_files(owned.directory.iterdir())
        later = advance(f, owned, transition)
        original_inputs = observed_files([*f.inputs.iterdir(), *f.private.iterdir()])
        with prepared(f, owned, captured, report) as copies:
            for name in snapshots.DISK_BYTES:
                assert (
                    copies.path(name, f.guest.enrollment).read_bytes()
                    == sealed_files[owned.directory / name][0]
                )
            assert report["restored_inputs_admitted"]
        assert captured == original and observed_files(sealed_files) == sealed_files
        assert observed_files(original_inputs) == original_inputs
        assert owned.source_observation(f.guest.enrollment) == later
        assert report["status"] == "passed" and report["originals_preserved"]
        assert report["temporary_resources_removed"] and valid_stats(report["statistics"])
    assert captured["status"] == "passed" and captured["observed_successor_preserved"]


@pytest.mark.parametrize("advanced", [False, True])
def test_restored_boot_borrows_the_current_anchor_but_expects_the_original_canary(
    fixture, advanced
):
    f = fixture
    captured, transition, report = {}, {}, {}
    with capture(f, captured) as owned:
        original = copy.deepcopy(captured)
        if advanced:
            later = advance(f, owned, transition)
            source_child = f.child
        else:
            later = owned.source_observation(f.guest.enrollment)
            source_child = f.guest
        later_inputs = observed_files([*f.inputs.iterdir(), *f.private.iterdir()])
        f.after = str(uuid.uuid4())
        f.reads = 0
        restored.qualify_restored_boot(
            f.guest,
            f.custody,
            owned,
            captured,
            f.temporary,
            lambda _: nullcontext(),
            lambda child: restored_controller(f, child),
            report,
        )
        assert report["status"] == "passed" and report["restored_boot_verified"]
        assert report["boot_inputs"]["source_before"] == later
        assert report["private_inputs"]["phases"][0]["source_before"] == later
        assert report["private_inputs"]["phases"][-2]["source_after"] == later
        assert (
            report["private_inputs"]["phases"][0]["observation"]["source"]
            == original["phases"][0]["observation"]
        )
        assert owned.source_observation(f.guest.enrollment) == later
        assert captured == original and observed_files(later_inputs) == later_inputs
        assert report["after_identity"]["boot_id"] not in {
            f.guest.observed["boot_id"],
            later["boot_identity"]["boot_id"],
        }
        observed = report["phases"][3]["observation"]["identity"]
        assert observed == f.prepared["identity"]
        if advanced:
            assert observed != transition["canary_advance"]["observed_canary"]
        assert f.child.process.returncode == 0 and not source_child.boot_inputs_borrowed
        assert report["boot_inputs"]["lifetime_ended"]
        assert report["writable_inputs"]["writer_absence_verified"]
        assert report["writable_inputs"]["written_files_synced"]
        assert all(
            valid_stats(report[k]["statistics"])
            for k in ("boot_inputs", "private_inputs", "writable_inputs")
        )
        assert valid_stats(report["statistics"])
        assert (
            report["snapshot_restore_qualified"] is report["product_authority_qualified"] is False
        )
    assert not list(f.temporary.iterdir())


@pytest.mark.parametrize(
    "mode",
    [
        "source-bytes",
        "original-projection",
        "later-as-original",
        "copied-guest",
        "wrong-custody",
        "copied-handle",
        "expired",
        "missing-owner",
        "tool",
        "private-input",
    ],
)
def test_witnessed_source_restore_rejects_unadmitted_bindings_before_effects(fixture, mode):
    f = fixture
    captured, transition, report = {}, {}, {}
    with capture(f, captured) as owned:
        later = advance(f, owned, transition)
        guest, custody, handle, expected = (
            f.guest,
            copy.deepcopy(f.custody),
            owned,
            copy.deepcopy(captured),
        )
        root, seed = f.inputs / "root.qcow2", f.private / "seed.iso"
        originals = root.read_bytes(), seed.read_bytes(), f.tool.read_bytes(), owned._source_owner
        try:
            if mode == "source-bytes":
                root.write_bytes(root.read_bytes() + b"unwitnessed")
            elif mode == "original-projection":
                expected["phases"][0]["observation"]["disks"]["root.qcow2"]["sha256"] = "0" * 64
            elif mode == "later-as-original":
                expected["phases"][0]["observation"] = copy.deepcopy(later)
            elif mode == "copied-guest":
                guest = copy.copy(guest)
            elif mode == "wrong-custody":
                custody["pid"] += 1
            elif mode == "copied-handle":
                handle = copy.copy(owned)
            elif mode == "expired":
                owned.active = False
            elif mode == "missing-owner":
                owned._source_owner = None
            elif mode == "tool":
                f.tool.write_bytes(b"substituted")
            else:
                seed.write_bytes(b"substituted")
            before = len(f.state["calls"])
            with pytest.raises(guests.GuestBootError):
                with restore.private_restored_disks(
                    guest, custody, handle, expected, f.temporary, lambda _: nullcontext(), report
                ):
                    pytest.fail("unadmitted restore")
            assert len(f.state["calls"]) == before and not f.state["restore_paths"]
            assert report["status"] == "failed" and not report["restored_inputs_admitted"]
            assert valid_stats(report["statistics"])
        finally:
            root.write_bytes(originals[0])
            seed.write_bytes(originals[1])
            f.tool.write_bytes(originals[2])
            owned._source_owner = originals[3]
            owned.active = True
        assert owned.source_observation(f.guest.enrollment) == later


@pytest.mark.parametrize("advanced", [False, True])
def test_boot_borrow_is_exact_current_source_bound_and_expires(fixture, advanced):
    f = fixture
    captured, transition, report = {}, {}, {}
    with capture(f, captured) as owned:
        current = (
            advance(f, owned, transition)
            if advanced
            else owned.source_observation(f.guest.enrollment)
        )
        expected = restore.capture_projection(captured)
        with owned.restore_boot_inputs(f.guest, f.custody, expected, report) as retained:
            assert retained.source_before == current
            assert retained.source is (f.child if advanced else f.guest)
            assert retained.source.boot_inputs_borrowed
            with pytest.raises(guests.GuestBootError, match="already-borrowed"):
                with owned.restore_boot_inputs(f.guest, f.custody, expected, {}):
                    pytest.fail("overlapping borrow")
            child = retained.guest(f.guest.enrollment, {})
            assert child.inputs is f.guest.inputs and child.files == f.guest.files
        with pytest.raises(guests.GuestBootError, match="expired"):
            retained.guest(f.guest.enrollment, {})
        assert report["status"] == "passed" and report["lifetime_ended"]
        assert valid_stats(report["statistics"])
        assert owned.source_observation(f.guest.enrollment) == current
    with pytest.raises(guests.GuestBootError, match="expired"):
        with owned.restore_boot_inputs(f.guest, f.custody, expected, {}):
            pytest.fail("expired capture cannot borrow")


def test_restore_keeps_original_failure_and_later_preservation_failure_with_cleanup(fixture):
    f = fixture
    captured, transition, report = {}, {}, {}
    with capture(f, captured) as owned:
        later = advance(f, owned, transition)
        path = f.inputs / "root.qcow2"
        content = path.read_bytes()
        try:
            with pytest.raises(guests.GuestBootError, match="source-changed"):
                with prepared(f, owned, captured, report):
                    path.write_bytes(content + b"unwitnessed")
                    raise restore.RestoreError("controlled-original-failure")
            assert report["status"] == "failed"
            assert report["problem"]["reason"] == "controlled-original-failure"
            preservation = report["phases"][-2]
            assert preservation["phase"] == "preservation" and preservation["status"] == "failed"
            assert preservation["problem"]["reason"] == "source-changed"
            assert report["temporary_resources_removed"] and valid_stats(report["statistics"])
            assert all(not p.exists() for p in f.state["restore_paths"])
        finally:
            path.write_bytes(content)
        assert owned.source_observation(f.guest.enrollment) == later


@pytest.mark.parametrize("mode", ["prelaunch-refused", "canary-changed", "missing-statistics"])
def test_failed_later_source_restored_boot_keeps_failure_and_removes_private_inputs(
    fixture, monkeypatch, mode
):
    f = fixture
    captured, transition, report = {}, {}, {}
    with capture(f, captured) as owned:
        later = advance(f, owned, transition)
        original = copy.deepcopy(captured)
        inputs = observed_files([*f.inputs.iterdir(), *f.private.iterdir()])
        f.after = str(uuid.uuid4())
        f.reads = 0
        f.mode = mode
        if mode == "missing-statistics":
            monkeypatch.setattr(restored, "valid_stats", lambda value: False)
        with pytest.raises((guests.GuestBootError, ValueError)):
            restored.qualify_restored_boot(
                f.guest,
                f.custody,
                owned,
                captured,
                f.temporary,
                lambda _: nullcontext(),
                lambda child: restored_controller(f, child),
                report,
            )
        assert report["status"] == "failed" and not report["restored_boot_verified"]
        assert report["problem"] and report["private_inputs"]["temporary_resources_removed"]
        assert f.child.process.returncode == 0
        assert observed_files(inputs) == inputs and captured == original
        assert owned.source_observation(f.guest.enrollment) == later
        assert all(not p.exists() for p in f.state["restore_paths"])
        assert valid_stats(report["statistics"])


def test_borrow_preserves_original_failure_separately_from_changed_source(fixture):
    f = fixture
    captured, transition, report = {}, {}, {}
    with capture(f, captured) as owned:
        later = advance(f, owned, transition)
        source = f.child
        path = f.inputs / "root.qcow2"
        content = path.read_bytes()
        try:
            with pytest.raises(guests.GuestBootError, match="source-changed"):
                with owned.restore_boot_inputs(
                    f.guest, f.custody, restore.capture_projection(captured), report
                ):
                    path.write_bytes(content + b"unwitnessed")
                    raise restore.RestoreError("controlled-borrow-failure")
            assert report["status"] == "failed"
            assert report["problem"]["reason"] == "controlled-borrow-failure"
            assert report["preservation_problem"]["reason"] == "source-changed"
            assert report["lifetime_ended"] and valid_stats(report["statistics"])
            assert not source.boot_inputs_borrowed
        finally:
            path.write_bytes(content)
        assert owned.source_observation(f.guest.enrollment) == later
