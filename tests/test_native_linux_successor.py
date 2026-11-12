"""Controlled witnessed successor lifetime; native image/guest facilities are substituted."""

from __future__ import annotations

import copy
import hashlib
import json
import shlex
import uuid
from contextlib import contextmanager, nullcontext

import pytest

from scripts import native_linux_enrollment as native
from scripts import native_linux_guest as guests
from scripts import native_linux_images as images
from scripts import native_linux_reboot as reboot
from scripts import native_linux_snapshots as snapshots
from scripts import native_linux_successor as successor
from scripts.run_stats import valid_stats
from tests.test_native_linux_restart import ControlledSSH, controller, private_inputs
from tests.test_native_linux_restart import fixture as _restart_source
from tests.test_native_linux_snapshots import ControlledImages

restart_source = _restart_source

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/native_linux_successor.py",
        "scripts/native_linux_snapshots.py",
        "scripts/native_linux_restart.py",
        "scripts/native_linux_reboot.py",
    ],
    "scope": "exact one-use active capture ownership, frozen original evidence and protected input metadata, fresh original-disk controller and boot/canary timeline, full stopped-source anchor admission, refused substitution and uncertainty, teardown and mandatory phase/run statistics",
    "relationship": "no-product-claim",
    "reason": "Image conversion, paused native controller and SSH/guest observations are substituted. Real unprivileged files, sockets and short Python children exercise custody, changed disk bytes, exact reaping and owned cleanup. No QEMU, native successor timeline, full restored roundtrip or product authority is qualified.",
    "claims": [],
}


class SuccessorSSH(ControlledSSH):
    def __call__(self, arguments, name, nominal, *, capture=False):
        f = self.f
        parts = shlex.split(arguments[-1])
        expected, action = json.loads(parts[-2]), json.loads(parts[-1])
        if expected is None or expected != self.value():
            return super().__call__(arguments, name, nominal, capture=capture)
        assert name == "guest-ssh" and capture and nominal > 0
        assert action[:5] == ["/usr/bin/python3", "-I", "-S", "-c", reboot.PROGRAM]
        request = json.loads(action[-1])
        f.requests.append(copy.deepcopy(request))
        assert f.child.process.poll() is None
        result = copy.deepcopy(f.current_canary)
        if request["mode"] == "advance":
            assert request["prior_identity"] == result["identity"]
            assert request["prior_nonce"] != request["nonce"]
            assert request["image"] == result["observer"]["executable"]
            if f.mode == "before-write-error":
                raise native.EnrollmentError("guest-ssh", "command-exit-19")
            result["previous_identity"] = copy.deepcopy(result["identity"])
            content = "reboot:" + f.guest.enrollment + "\n" + request["nonce"] + "\n"
            result["identity"].update(
                content=content, sha256=hashlib.sha256(content.encode()).hexdigest()
            )
            target = f.inputs / "root.qcow2"
            if f.mode != "lost-source-write":
                target.write_bytes(target.read_bytes() + content.encode())
            f.current_canary = copy.deepcopy(result)
            if f.mode == "write-outcome-unobserved":
                raise native.EnrollmentError("guest-ssh", "command-exit-19")
        else:
            assert request["mode"] == "inspect"
        result.update(
            mode=request["mode"],
            probe=request["probe"],
            boot_id=f.after,
            canary_fsynced=request["mode"] == "advance",
        )
        if f.mode == "bad-advance-reply" and request["mode"] == "advance":
            return "[false]"
        if (
            f.mode == "changed-readback"
            and request["mode"] == "inspect"
            and "previous_identity" in result
        ):
            result["identity"]["sha256"] = "0" * 64
        if f.mode == "private-changed-after-write" and request["mode"] == "advance":
            (f.private / "seed.iso").write_bytes(b"controlled-substitution")
        f.probes.append(request["probe"])
        return json.dumps(result)


@pytest.fixture
def fixture(restart_source, monkeypatch):
    f = restart_source
    f.state = {"mode": "normal", "calls": [], "output": {}, "snapshot_paths": []}
    f.tool = f.private.parent / "controlled-image-tool"
    f.tool.write_bytes(b"controlled-image-tool")
    f.tool.chmod(0o600)
    for module in (images, snapshots):
        monkeypatch.setattr(module, "QEMU_IMG", f.tool)
    image = ControlledImages(f.inputs, f.tool, (f.inputs / "base.img").read_bytes(), f.state)
    ssh = SuccessorSSH(f)
    f.requests = []
    f.current_canary = copy.deepcopy(f.prepared)

    def command(arguments, name, nominal, *, capture=False):
        return (ssh if name == "guest-ssh" else image)(arguments, name, nominal, capture=capture)

    f.guest.command = command
    return f


def capture(f, report):
    f.guest.report["snapshot_capture"] = report
    return snapshots.cold_snapshots(
        f.guest, f.custody, f.temporary, lambda _: nullcontext(), report
    )


def advance(f, owned, report, *, enrollment=None, launch=None):
    return owned.advance_source(
        f.guest.enrollment if enrollment is None else enrollment,
        lambda _: nullcontext(),
        (lambda child: controller(f, child)) if launch is None else launch,
        report,
    )


@pytest.mark.parametrize(
    "mode", ["normal", "old-then-new", "incomplete-then-ready", "read-timeout"]
)
def test_exact_active_capture_witnesses_different_bytes_and_separately_frozen_later_source(
    fixture, mode
):
    f = fixture
    f.mode = mode
    report, transition = {}, {}
    original_private = private_inputs(f)
    original_boot = copy.deepcopy(f.guest.observed)
    original_canary = copy.deepcopy(f.prepared)
    with capture(f, report) as owned:
        before = copy.deepcopy(report)
        sealed = {
            p: (p.read_bytes(), images.identity(p), p.stat().st_mode)
            for p in owned.directory.iterdir()
        }
        after = advance(f, owned, transition)
        assert transition["status"] == "passed" and owned._source_owner.advanced
        assert after == owned.source_observation(f.guest.enrollment) == transition["later_source"]
        assert after != before["phases"][0]["observation"]
        assert after["boot_identity"]["boot_id"] == f.after != original_boot["boot_id"]
        assert after["pid"] == f.child.process.pid != f.guest.process.pid
        assert (
            after["disks"]["root.qcow2"]["sha256"]
            != before["phases"][0]["observation"]["disks"]["root.qcow2"]["sha256"]
        )
        assert (
            report == before and f.guest.observed == original_boot and f.prepared == original_canary
        )
        assert sealed == {
            p: (p.read_bytes(), images.identity(p), p.stat().st_mode)
            for p in owned.directory.iterdir()
        }
        assert private_inputs(f) == original_private
        after["disks"]["root.qcow2"]["sha256"] = "0" * 64
        assert owned.source_observation(f.guest.enrollment) == transition["later_source"]
        assert len(f.requests) == 6 and len(set(f.probes)) == 6
        observed = transition["canary_advance"]
        assert observed["prior_canary"] == original_canary["identity"]
        assert observed["written_canary"] == observed["observed_canary"]
        assert observed["written_canary"]["content"] != original_canary["identity"]["content"]
        assert f.child.process.returncode == 0 and not f.guest.boot_inputs_borrowed
        assert valid_stats(transition["statistics"]) and valid_stats(observed["statistics"])
        assert all(
            valid_stats(p["statistics"]) and p["status"] == "passed" for p in transition["phases"]
        )
        assert (
            transition["snapshot_restore_qualified"]
            is transition["product_authority_qualified"]
            is False
        )
        with pytest.raises(snapshots.SnapshotError, match="already-attempted"):
            advance(f, owned, {})
    assert report["status"] == "passed" and report["source_preserved"] is False
    assert report["observed_successor_preserved"] and report["snapshots_preserved_until_cleanup"]
    assert report["temporary_resources_removed"] and not list(f.temporary.iterdir())
    with pytest.raises(snapshots.SnapshotError, match="expired"):
        owned.source_observation(f.guest.enrollment)


@pytest.mark.parametrize(
    "mode",
    [
        "foreign",
        "prepopulated",
        "changed-source",
        "changed-tool",
        "changed-private",
        "forged-capture",
        "forged-source",
        "missing-canary",
        "rebound-private-hash",
        "rebound-inputs",
        "snapshot-public-rebinding",
        "rebound-capture-report",
    ],
)
def test_unadmitted_or_substituted_source_cannot_start_a_controller(fixture, mode):
    f = fixture
    report, transition = {}, {}
    with pytest.raises((guests.GuestBootError, KeyError)):
        with capture(f, report) as owned:
            enrollment = f.guest.enrollment
            if mode == "foreign":
                enrollment = str(uuid.uuid4())
            elif mode == "prepopulated":
                transition["status"] = "passed"
            elif mode == "changed-source":
                (f.inputs / "root.qcow2").write_bytes(b"unwitnessed")
            elif mode == "changed-tool":
                f.tool.write_bytes(b"substituted-tool")
            elif mode == "changed-private":
                (f.private / "seed.iso").write_bytes(b"substituted")
            elif mode == "forged-capture":
                report["phases"][0]["observation"]["pid"] += 1
            elif mode == "forged-source":
                f.guest.report["identity"]["boot_id"] = str(uuid.uuid4())
            elif mode == "rebound-private-hash":
                value = f.guest.files["seed.iso"]
                f.guest.files["seed.iso"] = (value[0], "0" * 64)
            elif mode == "rebound-inputs":
                f.guest.inputs = copy.copy(f.guest.inputs)
            elif mode == "rebound-capture-report":
                f.guest.report["snapshot_capture"] = copy.deepcopy(report)
            elif mode == "snapshot-public-rebinding":
                value = owned.files["root.qcow2"]
                owned.files["root.qcow2"] = (value[0], "0" * 64)
            else:
                del f.guest.report["reboot"]
            advance(f, owned, transition, enrollment=enrollment)
    assert f.child is None and not f.requests
    assert report["status"] == "failed" and report["temporary_resources_removed"]


@pytest.mark.parametrize(
    "mode",
    [
        "lost-source-write",
        "before-write-error",
        "write-outcome-unobserved",
        "bad-advance-reply",
        "changed-readback",
        "private-changed-after-write",
        "prelaunch-refused",
        "accounts-changed",
        "foreign-profile",
        "readiness-error",
        "stale-accepted",
        "changed-final",
    ],
)
def test_failed_or_uncertain_successor_never_adopts_source_and_reaps_exact_child(fixture, mode):
    f = fixture
    f.mode = mode
    report, transition = {}, {}
    before = copy.deepcopy(f.guest.observed)
    with pytest.raises((guests.GuestBootError, native.EnrollmentError, ValueError)):
        with capture(f, report) as owned:
            advance(f, owned, transition)
    assert report["status"] == transition["status"] == "failed"
    assert transition["problem"] and f.guest.observed == before
    assert f.child.process.returncode == 0
    assert f.guest.boot_inputs_borrowed is (mode == "private-changed-after-write")
    assert not list(f.temporary.iterdir())
    assert valid_stats(report["statistics"]) and valid_stats(transition["statistics"])
    assert not owned._source_owner.advanced


def test_copied_owner_cannot_advance_a_different_capture_handle(fixture):
    f = fixture
    first, second = {}, {}
    with capture(f, first) as owned:
        # The same source may have another cold capture; its authority is separate.
        with capture(f, second) as other:
            original = owned._source_owner
            owned._source_owner = other._source_owner
            try:
                with pytest.raises(snapshots.SnapshotError, match="foreign-capture-source-handle"):
                    advance(f, owned, {})
                assert f.child is None and not f.requests
            finally:
                owned._source_owner = original
        f.guest.report["snapshot_capture"] = first


def test_late_byte_drift_cannot_be_adopted_by_editing_returned_observation(fixture):
    f = fixture
    report, transition = {}, {}
    with pytest.raises(snapshots.SnapshotError, match="source-changed"):
        with capture(f, report) as owned:
            after = advance(f, owned, transition)
            target = f.inputs / "root.qcow2"
            target.write_bytes(target.read_bytes() + b"unwitnessed-later-drift")
            after["disks"]["root.qcow2"].update(
                bytes=target.stat().st_size, sha256=images.digest(target)
            )
            transition["later_source"] = copy.deepcopy(after)
            owned.source_observation(f.guest.enrollment)
    assert report["status"] == "failed" and not report["source_preserved"]


def test_missing_successor_statistics_prevents_anchor_adoption(fixture, monkeypatch):
    original = successor.RunStats

    class Invalid:
        def __init__(self):
            self.actual = original()

        def finish(self):
            self.actual.finish()
            return None

    monkeypatch.setattr(successor, "RunStats", Invalid)
    report, transition = {}, {}
    with pytest.raises(ValueError, match="invalid required source successor statistics"):
        with capture(fixture, report) as owned:
            advance(fixture, owned, transition)
    assert transition["status"] == "failed" and transition["statistics"] is None
    assert not owned._source_owner.advanced and fixture.child.process.returncode == 0


def test_reused_prior_challenge_refuses_before_any_canary_write(fixture, monkeypatch):
    f = fixture
    original = successor.qualify_canary_advance

    def duplicate(*args, **kwargs):
        old = uuid.UUID(f.requests[0]["probe"])
        monkeypatch.setattr(reboot.uuid, "uuid4", lambda: old)
        return original(*args, **kwargs)

    monkeypatch.setattr(successor, "qualify_canary_advance", duplicate)
    report, transition = {}, {}
    with pytest.raises(guests.GuestBootError, match="canary-challenge-reused"):
        with capture(f, report) as owned:
            advance(f, owned, transition)
    assert len(f.requests) == 3 and {r["mode"] for r in f.requests} == {"inspect"}
    assert f.current_canary == f.prepared and f.child.process.returncode == 0
    assert not owned._source_owner.advanced and transition["status"] == "failed"


@pytest.mark.parametrize("mode", ["before", "after-write", "with-original-failure"])
def test_unproved_controller_absence_cannot_accept_an_anchor(fixture, monkeypatch, mode):
    f = fixture
    if mode == "with-original-failure":
        f.mode = "write-outcome-unobserved"

    def unproved(child):
        raise snapshots.SnapshotError("controlled-stop-unobserved")

    monkeypatch.setattr(successor, "stopped_replacement", unproved)
    if mode == "before":
        f.mode = "before-write-error"
    report, transition = {}, {}
    with pytest.raises(snapshots.SnapshotError, match="controlled-stop-unobserved"):
        with capture(f, report) as owned:
            advance(f, owned, transition)
    assert transition["status"] == "failed" and not owned._source_owner.advanced
    assert transition["cleanup_problem"]["reason"] == "controlled-stop-unobserved"
    if mode in ("before", "with-original-failure"):
        assert transition["problem"]["reason"] == "command-exit-19"
    assert f.child.process.returncode == 0 and not list(f.temporary.iterdir())


def test_claimed_stop_cannot_replace_actual_reaping_and_live_endpoint_checks(fixture, monkeypatch):
    f = fixture
    manager = None

    @contextmanager
    def still_live(child):
        nonlocal manager
        manager = controller(f, child)
        endpoint = manager.__enter__()
        yield endpoint

    monkeypatch.setattr(
        successor, "stopped_replacement", lambda _: {"process_absent": True, "group_absent": True}
    )
    report, transition = {}, {}
    try:
        with pytest.raises(
            guests.GuestBootError, match=r"controller-not-reaped|replacement-not-reaped"
        ):
            with capture(f, report) as owned:
                advance(f, owned, transition, launch=still_live)
        assert f.child.process.poll() is None and not owned._source_owner.advanced
        assert f.guest.boot_inputs_borrowed and transition["status"] == "failed"
    finally:
        if manager is not None:
            manager.__exit__(None, None, None)
    assert f.child.process.returncode == 0 and not list(f.temporary.iterdir())


@pytest.mark.parametrize("interrupted", [KeyboardInterrupt, SystemExit])
def test_interruption_retains_failure_reaps_child_and_expires_owner(fixture, interrupted):
    f = fixture

    @contextmanager
    def interrupt(child):
        with controller(f, child) as endpoint:
            yield endpoint
            raise interrupted()

    report, transition = {}, {}
    with pytest.raises(interrupted):
        with capture(f, report) as owned:
            advance(f, owned, transition, launch=interrupt)
    assert f.child.process.returncode == 0 and not owned._source_owner.advanced
    assert report["status"] == transition["status"] == "failed"
    assert transition["problem"]["type"] == interrupted.__name__
    assert valid_stats(transition["statistics"]) and not list(f.temporary.iterdir())


def test_ended_unadvanced_capture_cannot_authorize_a_later_controller(fixture):
    f = fixture
    report = {}
    with capture(f, report) as owned:
        assert owned.source_observation(f.guest.enrollment) == report["phases"][0]["observation"]
    with pytest.raises(snapshots.SnapshotError, match="expired"):
        advance(f, owned, {})
    assert f.child is None and report["source_preserved"] and report["status"] == "passed"
