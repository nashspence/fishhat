"""Controlled enrolled-timeline composition; all native facilities are substituted."""

from __future__ import annotations

import copy
import shutil
import socket
import uuid
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_linux_enrollment as native
from scripts import native_linux_guest as guests
from scripts.run_stats import RunStats, valid_stats
from tests.test_native_linux_restart import controller
from tests.test_native_linux_successor import fixture as _source_fixture
from tests.test_native_linux_successor import restart_source as _restart_source

restart_source = _restart_source
source_fixture = _source_fixture

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/native_linux_enrollment.py",
        "scripts/native_linux_successor.py",
        "scripts/native_linux_snapshots.py",
        "scripts/native_linux_reboot.py",
    ],
    "scope": "separate enrolled successor timeline composition, exact immutable pre-capture versus later-source records, refusal ordering, changed canary bytes, independent actual owned-path/process absence, failure propagation and required statistics",
    "relationship": "no-product-claim",
    "reason": "Initial guest/image acquisition, native prelaunch, reboot and SSH observations are explicit substitutions. Actual unprivileged files, sockets and short child processes exercise the maintained capture/successor owners and final resource absence checks. No local QEMU, native timeline, restored roundtrip or product authority is qualified.",
    "claims": [],
}


@pytest.fixture
def fixture(source_fixture, monkeypatch):
    f = source_fixture
    f.events = []
    f.endpoint = Path(f.custody["control_socket"]["path"])
    first = True

    def enrollment():
        nonlocal first
        if first:
            first = False
            return uuid.UUID(f.guest.enrollment)
        return uuid.uuid4()

    monkeypatch.setattr(native, "uuid", SimpleNamespace(uuid4=enrollment, UUID=uuid.UUID))

    def forbidden(*a, **k):
        pytest.fail("controlled timeline attempted a native command")

    monkeypatch.setattr(native, "run", forbidden)
    monkeypatch.setattr(native, "root_run", forbidden)

    @contextmanager
    def inputs(enrollment, temporary, command, progress, report):
        assert enrollment == f.guest.enrollment and temporary == f.temporary
        f.events.append("input-admission")
        metrics = RunStats()
        report.update(status="failed", enrollment=enrollment)
        complete = False
        try:
            f.guest.inputs.verify(enrollment)
            yield f.guest.inputs
            complete = True
        finally:
            f.guest.inputs.verify(enrollment)
            shutil.rmtree(f.inputs)
            report.update(
                status="passed" if complete else "failed",
                base_preserved=True,
                temporary_resources_removed=not f.inputs.exists(),
                statistics=metrics.finish(),
            )
            f.events.append("inputs-removed")

    @contextmanager
    def session(inputs, temporary, command, tools, qemu, report):
        assert inputs is f.guest.inputs and temporary == f.temporary
        metrics = RunStats()
        report.update(copy.deepcopy(f.guest.report), status="failed")
        f.guest.report = report
        complete = False
        try:
            yield f.guest
            complete = True
        finally:
            shutil.rmtree(f.private)
            report.update(
                status="passed" if complete else "failed",
                process_reaped=f.guest.process.returncode is not None,
                temporary_resources_removed=not f.private.exists(),
                statistics=metrics.finish(),
            )
            f.events.append("private-removed")

    @contextmanager
    def admitted(guest, binary, temporary):
        assert binary == "c" * 64 and temporary == f.temporary
        if guest is f.guest:
            f.events.append("original-controller")
            yield f.endpoint
            f.events.append("original-stopped")
        else:
            f.events.append("successor-controller")
            with controller(f, guest) as endpoint:
                yield endpoint
            f.events.append("successor-stopped")

    def ready(verify):
        f.guest.validate_profile(f.guest.observed)
        f.guest.report.update(
            boot_verified=True,
            identity=copy.deepcopy(f.guest.observed),
            endpoint={"address": "127.0.0.1", "port": f.guest.port, "owned_listener": True},
        )
        f.events.append("ready")

    def reboot(guest, endpoint, progress, temporary, report):
        assert guest is f.guest and endpoint == f.endpoint and temporary == f.temporary
        metrics = RunStats()
        if f.mode == "prepare-failure":
            metrics.finish()
            raise guests.GuestBootError("controlled-prepare-failure")
        report.update(
            status="passed",
            reboot_continuity_qualified=True,
            after_identity=copy.deepcopy(f.guest.observed),
            phases=[
                {
                    "phase": "prepare",
                    "status": "passed",
                    "statistics": RunStats().finish(),
                    "observation": copy.deepcopy(f.prepared),
                }
            ],
            statistics=metrics.finish(),
        )
        f.events.append("prepared-canary")

    monkeypatch.setattr(native, "guest_inputs", inputs)
    monkeypatch.setattr(native, "guest_session", session)
    monkeypatch.setattr(native, "admitted_guest_controller", admitted)
    monkeypatch.setattr(native, "qualify_reboot", reboot)
    monkeypatch.setattr(native, "host_custody", lambda *a: copy.deepcopy(f.custody))
    f.guest.verify_process = lambda d: None
    f.guest.ready = ready
    f.guest.refusals = lambda: f.events.append("original-refusals")
    return f


def qualify(f, report):
    native.qualify_source_successor({"controlled": True}, "c" * 64, f.temporary, report)


def test_composed_successor_keeps_original_evidence_distinct_and_probes_all_removed_resources(
    fixture,
):
    f = fixture
    report = {}
    qualify(f, report)
    assert report["status"] == "passed" and report["observed_successor_verified"]
    assert report["resources_destroyed_with_guest"]
    assert report["snapshot_restore_qualified"] is report["product_authority_qualified"] is False
    assert report["scope"] == "owned-disposable-source-successor-timeline-only"
    assert [x["phase"] for x in report["phases"]] == [
        "original-guest-admission",
        "original-source-custody",
        "capture-admission",
        "input-refusals",
        "observed-successor",
        "preservation-and-repeat-refusal",
        "expired-source-refusal",
        "cleanup",
    ]
    assert f.events == [
        "input-admission",
        "original-controller",
        "ready",
        "original-refusals",
        "prepared-canary",
        "original-refusals",
        "original-stopped",
        "successor-controller",
        "successor-stopped",
        "private-removed",
        "inputs-removed",
    ]
    capture, transition = report["capture"], report["transition"]
    original, later = report["original_capture"]["source"], report["later_source"]
    assert capture["phases"][0]["observation"] == original != later
    assert capture["phases"][-1]["source_after"] == later == transition["later_source"]
    assert original["boot_identity"]["boot_id"] != later["boot_identity"]["boot_id"]
    assert original["disks"]["root.qcow2"]["sha256"] != later["disks"]["root.qcow2"]["sha256"]
    assert not capture["source_preserved"] and capture["observed_successor_preserved"]
    assert report["original_capture"]["files"] == {
        p["phase"]: (p["observation"]["identity"], p["observation"]["sha256"])
        for p in capture["phases"][1:4]
    }
    assert [r["kind"] for r in report["phases"][3]["refused"]] == [
        "foreign-enrollment",
        "substituted-sealed-metadata",
        "prepopulated-successor-report",
    ]
    assert report["phases"][3]["source_after_refusals"] == original
    assert report["phases"][5]["repeat_refusal"]["reason"] == "capture-source-already-attempted"
    assert report["phases"][6]["reason"] == "capture-source-handle-expired"
    assert report["original_guest"]["endpoint"]["closed_after_cleanup"]
    cleanup = report["cleanup"]
    paths = set()
    for name in ("original_guest", "successor"):
        observed = cleanup[name]
        assert (
            observed["status"] == "passed"
            and observed["process_absent"]
            and observed["process_group_absent"]
        )
        assert len(observed["paths"]) == 19 and all(p["absent"] for p in observed["paths"])
        assert valid_stats(observed["statistics"])
        paths.update(p["path"] for p in observed["paths"])
    assert len(paths) == 21
    assert report["phases"][-1]["capture_directory"]["absent"]
    assert valid_stats(report["statistics"]) and all(
        valid_stats(p["statistics"]) for p in report["phases"]
    )
    assert not f.inputs.exists() and not f.private.exists() and not list(f.temporary.iterdir())


@pytest.mark.parametrize(
    "failure",
    [
        "prepare-failure",
        "before-write-error",
        "write-outcome-unobserved",
        "bad-advance-reply",
        "changed-readback",
        "prelaunch-refused",
    ],
)
def test_composition_failure_retains_original_outcome_and_never_qualifies(fixture, failure):
    f = fixture
    f.mode = failure
    report = {}
    with pytest.raises(RuntimeError):
        qualify(f, report)
    assert report["status"] == "failed" and report["observed_successor_verified"] is False
    assert report["resources_destroyed_with_guest"] is False and report["problem"]
    assert valid_stats(report["statistics"])
    assert not f.inputs.exists() and not f.private.exists() and not list(f.temporary.iterdir())
    if failure != "prepare-failure":
        assert f.child.process.returncode == 0


def test_composition_missing_whole_run_statistics_cannot_qualify(fixture, monkeypatch):
    real = native.RunStats

    class Invalid:
        def __init__(self):
            self.actual = real()

        def finish(self):
            self.actual.finish()
            return None

    monkeypatch.setattr(native, "RunStats", Invalid)
    report = {}
    with pytest.raises(ValueError, match="invalid required successor timeline statistics"):
        qualify(fixture, report)
    assert report["status"] == "failed" and report["observed_successor_verified"] is False
    assert report["statistics"] is None


@pytest.mark.parametrize(
    "failure",
    [
        "original-statistics",
        "input-statistics",
        "capture-statistics",
        "capture-qualification-statistics",
        "transition-statistics",
        "canary-statistics",
        "phase-statistics",
        "capture-lineage",
        "later-lineage",
        "retained-lifetime",
        "prepared-proof",
    ],
)
def test_partial_completed_owner_evidence_cannot_qualify_the_composition(
    fixture, monkeypatch, failure
):
    f = fixture
    verify = native.verify_source_successor_cleanup

    def incomplete(report):
        if failure == "original-statistics":
            report["original_guest"]["statistics"] = None
        elif failure == "input-statistics":
            report["guest_inputs"]["statistics"] = None
        elif failure == "capture-statistics":
            report["capture"]["statistics"] = None
        elif failure == "capture-qualification-statistics":
            report["capture"]["qualification_statistics"] = None
        elif failure == "transition-statistics":
            report["transition"]["statistics"] = None
        elif failure == "canary-statistics":
            report["transition"]["canary_advance"]["statistics"] = None
        elif failure == "phase-statistics":
            report["transition"]["phases"][0]["statistics"] = None
        elif failure == "capture-lineage":
            report["capture"]["phases"][0]["observation"]["pid"] += 1
        elif failure == "later-lineage":
            report["transition"]["later_source"]["pid"] += 1
        elif failure == "retained-lifetime":
            report["transition"]["boot_inputs"]["lifetime_ended"] = False
        else:
            report["original_guest"]["reboot"]["reboot_continuity_qualified"] = False
        verify(report)

    monkeypatch.setattr(native, "verify_source_successor_cleanup", incomplete)
    report = {}
    with pytest.raises(guests.GuestBootError):
        qualify(f, report)
    assert report["status"] == "failed" and report["observed_successor_verified"] is False
    assert report["resources_destroyed_with_guest"] is False
    assert f.child.process.returncode == 0 and valid_stats(report["statistics"])
    assert not f.inputs.exists() and not f.private.exists() and not list(f.temporary.iterdir())


@pytest.mark.parametrize("leftover", ["private-file", "capture-directory", "ssh-listener"])
def test_reported_teardown_cannot_replace_independent_actual_absence(
    fixture, monkeypatch, leftover
):
    f = fixture
    verify = native.verify_source_successor_cleanup

    def observe(report):
        path, listener = None, None
        try:
            if leftover == "private-file":
                path = f.private
                path.mkdir(mode=0o700)
                (path / "seed.iso").write_bytes(b"controlled-late-resource")
            elif leftover == "capture-directory":
                path = Path(report["capture"]["directory"]["path"])
                path.mkdir(mode=0o700)
            else:
                listener = socket.socket()
                listener.bind(("127.0.0.1", f.guest.port))
                listener.listen(1)
            verify(report)
        finally:
            if listener is not None:
                listener.close()
            if path is not None:
                shutil.rmtree(path)

    monkeypatch.setattr(native, "verify_source_successor_cleanup", observe)
    report = {}
    with pytest.raises(guests.GuestBootError):
        qualify(f, report)
    assert report["status"] == "failed" and report["observed_successor_verified"] is False
    assert report["resources_destroyed_with_guest"] is False and report["problem"]
    assert f.child.process.returncode == 0 and not list(f.temporary.iterdir())
