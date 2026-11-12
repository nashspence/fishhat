"""Controlled full comparison composition; all native facilities are substituted."""

from __future__ import annotations

import copy
import json
import shutil
import socket
import uuid
from contextlib import contextmanager
from pathlib import Path

import pytest
import yaml

from scripts import native_linux_enrollment as native
from scripts import native_linux_restored_boot as restored
from scripts import native_linux_roundtrip as comparison
from scripts.run_stats import valid_stats
from tests.test_native_linux_restart import fixture as _restart_source
from tests.test_native_linux_restore_source import fixture as _restore_source
from tests.test_native_linux_restored_boot import controller as restored_controller
from tests.test_native_linux_successor import fixture as _successor_source
from tests.test_native_linux_successor_timeline import fixture as _timeline_fixture

restart_source = _restart_source
successor_source = _successor_source
source_fixture = _restore_source
timeline_fixture = _timeline_fixture

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/native_linux_roundtrip.py",
        "scripts/native_linux_enrollment.py",
        "scripts/native_linux_restored_boot.py",
        ".github/workflows/ci.yml",
    ],
    "scope": "composed original capture, independently witnessed later source and private restored comparison; distinct original/later/restored evidence, incomplete-proof refusal, actual owned-path/process/endpoint absence, failure propagation, scoped statistics and separate explicitly enrolled main-only profile",
    "relationship": "no-product-claim",
    "reason": "Image conversion, initial guest/reboot, native prelaunch and SSH observations are substituted. Actual unprivileged files, sockets and short Python children exercise the maintained capture, successor and restore owners together. Native fixture execution and product checkpoint authority require independent evidence.",
    "claims": [],
}


@pytest.fixture
def fixture(timeline_fixture, monkeypatch):
    f = timeline_fixture
    previous = native.admitted_guest_controller
    f.controllers = []
    command = f.guest.command

    def writes(arguments, name, nominal, *, capture=False):
        result = command(arguments, name, nominal, capture=capture)
        if name == "guest-ssh" and isinstance(f.child, restored.RestoredGuest):
            path = f.child.inputs.directory / "root.qcow2"
            path.write_bytes(path.read_bytes() + b"controlled-restored-writer")
        return result

    f.guest.command = writes

    @contextmanager
    def admitted(guest, binary, temporary):
        f.controllers.append(guest)
        if isinstance(guest, restored.RestoredGuest):
            assert binary == "c" * 64 and temporary == f.temporary
            f.after = str(uuid.uuid4())
            f.reads = 0
            with restored_controller(f, guest) as endpoint:
                yield endpoint
        else:
            with previous(guest, binary, temporary) as endpoint:
                yield endpoint

    monkeypatch.setattr(native, "admitted_guest_controller", admitted)
    return f


def qualify(f, report):
    native.qualify_source_successor(
        {"controlled": True}, "c" * 64, f.temporary, report, restored_successor=True
    )


def assert_destroyed(f):
    assert all(g.process.returncode is not None for g in f.controllers)
    assert not f.inputs.exists() and not f.private.exists()
    assert not list(f.temporary.iterdir())


def test_full_comparison_keeps_original_later_and_written_records_separate_until_teardown(fixture):
    f = fixture
    report = {}
    qualify(f, report)
    result = report["restored_successor"]
    old, later = report["original_capture"], report["later_source"]
    assert report["status"] == result["status"] == "passed"
    assert result["comparison_verified"] and result["resources_destroyed_with_guest"]
    assert result["original_capture"] == old
    assert result["source_before"] == result["source_after"] == later != old["source"]
    assert result["original_canary"] == result["restored_canary"]
    assert result["later_canary"] == report["transition"]["canary_advance"]["observed_canary"]
    assert result["later_canary"]["content"] != result["original_canary"]["content"]
    assert result["later_canary"]["sha256"] != result["original_canary"]["sha256"]
    rb = result["restored_boot"]
    assert len({g.observed["boot_id"] for g in f.controllers}) == 3
    assert rb["boot_inputs"]["source_before"] == later
    assert rb["boot_inputs"]["closure_before"] == rb["boot_inputs"]["closure_after"]
    assert rb["private_inputs"]["phases"][0]["observation"] == old
    assert rb["writable_inputs"]["admitted_files"] != rb["writable_inputs"]["written_files"]
    assert rb["writable_inputs"]["written_files_synced"]
    assert len(f.probes) == len(set(f.probes)) == 9
    assert [p["phase"] for p in result["phases"]] == [
        "input-admission",
        "private-restored-boot",
        "independent-comparison",
        "shared-resource-cleanup",
    ]
    assert [p["phase"] for p in report["phases"]][-2:] == ["expired-source-refusal", "cleanup"]
    assert len(report["phases"]) == 8
    paths = set()
    for receipt in (*report["cleanup"].values(), rb["cleanup"]):
        assert receipt["status"] == "passed"
        assert receipt["process_absent"] and receipt["process_group_absent"]
        assert all(p["absent"] for p in receipt["paths"])
        paths.update(p["path"] for p in receipt["paths"])
        assert valid_stats(receipt["statistics"])
    assert len(rb["cleanup"]["paths"]) == 18 and len(paths) > 21
    assert rb["cleanup"]["ssh_endpoint_closed"]
    assert valid_stats(report["statistics"]) and valid_stats(result["statistics"])
    assert all(p["status"] == "passed" and valid_stats(p["statistics"]) for p in result["phases"])
    assert "shared teardown measured separately" in result["statistics_scope"]
    assert result["snapshot_restore_qualified"] is result["product_authority_qualified"] is False
    assert_destroyed(f)


@pytest.mark.parametrize(
    "change",
    [
        "prepopulated",
        "later-source",
        "same-canary",
        "fsync",
        "partial-advance",
        "advance-statistics",
    ],
)
def test_incomplete_source_proof_refuses_before_any_private_restore(fixture, monkeypatch, change):
    f = fixture
    actual = native.compare_restored_successor

    def compare(source, custody, snapshots, capture, transition, *args):
        saved = copy.deepcopy(transition)
        try:
            if change == "prepopulated":
                args[-1]["status"] = "passed"
            elif change == "later-source":
                transition["later_source"]["boot_identity"]["boot_id"] = str(uuid.uuid4())
            elif change == "same-canary":
                transition["later_canary"]["identity"] = copy.deepcopy(f.prepared["identity"])
            elif change == "fsync":
                transition["canary_advance"]["phases"][1]["observation"]["canary_fsynced"] = False
            elif change == "partial-advance":
                transition["canary_advance"]["phases"].pop()
            else:
                transition["canary_advance"].pop("statistics")
            actual(source, custody, snapshots, capture, transition, *args)
        finally:
            transition.clear()
            transition.update(saved)

    monkeypatch.setattr(native, "compare_restored_successor", compare)
    report = {}
    with pytest.raises(native.GuestBootError):
        qualify(f, report)
    assert report["status"] == "failed" and not report["observed_successor_verified"]
    assert len(f.controllers) == 2 and not f.state["restore_paths"]
    assert_destroyed(f)


@pytest.mark.parametrize(
    "change",
    [
        "status",
        "phase",
        "statistics",
        "identity",
        "challenge",
        "original-reply",
        "original-preservation",
        "refusals",
    ],
)
def test_partial_restored_evidence_cannot_claim_comparison_success(fixture, monkeypatch, change):
    f = fixture
    actual = comparison.qualify_restored_boot

    def boot(*args):
        actual(*args)
        report = args[-1]
        if change == "status":
            report["status"] = "failed"
        elif change == "phase":
            report["phases"].pop()
        elif change == "statistics":
            report["phases"][3].pop("statistics")
        elif change == "identity":
            report["after_identity"]["boot_id"] = f.guest.observed["boot_id"]
        elif change == "challenge":
            report["phases"][3]["observation"]["probe"] = f.probes[0]
        elif change == "original-reply":
            report["phases"][3]["original_reply"] = "{}"
        elif change == "original-preservation":
            report["private_inputs"]["originals_preserved"] = False
        else:
            report["phases"][4]["refused"] = []

    monkeypatch.setattr(comparison, "qualify_restored_boot", boot)
    report = {}
    with pytest.raises(native.GuestBootError):
        qualify(f, report)
    assert report["status"] == report["restored_successor"]["status"] == "failed"
    assert not report["restored_successor"]["comparison_verified"]
    assert report["restored_successor"]["problem"]
    assert len(f.controllers) == 3
    assert_destroyed(f)


@pytest.mark.parametrize("mode", ["prelaunch-refused", "canary-changed", "missing-statistics"])
def test_failed_restored_execution_keeps_original_problem_and_actual_cleanup(
    fixture, monkeypatch, mode
):
    f = fixture
    original = native.compare_restored_successor

    def compare(*args):
        f.mode = mode
        if mode == "missing-statistics":
            monkeypatch.setattr(restored, "valid_stats", lambda value: False)
        original(*args)

    monkeypatch.setattr(native, "compare_restored_successor", compare)
    report = {}
    with pytest.raises((native.GuestBootError, ValueError)):
        qualify(f, report)
    result = report["restored_successor"]
    assert report["status"] == result["status"] == "failed"
    assert not result["comparison_verified"] and result["problem"]
    assert result["restored_boot"]["status"] == "failed"
    assert result["restored_boot"]["problem"]
    assert result["restored_boot"]["private_inputs"]["temporary_resources_removed"]
    assert valid_stats(result["statistics"]) and valid_stats(report["statistics"])
    assert_destroyed(f)


def test_comparison_profile_still_refuses_without_explicit_runner_enrollment(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "false")

    def forbidden(*args, **kwargs):
        pytest.fail("unenrolled comparison profile attempted native provisioning")

    monkeypatch.setattr(native, "provision", forbidden)
    output = tmp_path / "absent" / "report.json"
    assert (
        native.main(
            ["--github-hosted-only", "--profile", "restored-successor", "--output", str(output)]
        )
        == 2
    )
    assert not output.parent.exists()


@pytest.mark.parametrize("kind", ["disk-path", "protected-path", "endpoint"])
def test_actual_restored_remnant_blocks_final_acceptance(fixture, monkeypatch, kind):
    f = fixture
    actual = native.verify_restored_boot_cleanup

    def cleanup(report):
        path = listener = None
        try:
            if kind == "endpoint":
                listener = socket.socket()
                listener.bind(("127.0.0.1", f.child.port))
                listener.listen(1)
            else:
                path = (
                    (f.child.inputs.directory / "root.qcow2")
                    if kind == "disk-path"
                    else (f.private / "seed.iso")
                )
                path.parent.mkdir(mode=0o700)
                path.write_bytes(b"controlled-leftover")
            actual(report)
        finally:
            if listener is not None:
                listener.close()
            if path is not None:
                shutil.rmtree(path.parent)

    monkeypatch.setattr(native, "verify_restored_boot_cleanup", cleanup)
    report = {}
    with pytest.raises(native.GuestBootError):
        qualify(f, report)
    assert report["status"] == "failed" and not report["resources_destroyed_with_guest"]
    assert report["restored_successor"]["status"] != "passed"
    assert_destroyed(f)


@pytest.mark.parametrize(
    "result", ["complete", "missing", "failed", "unobserved", "uncleaned", "raises"]
)
def test_enrolled_profile_requires_complete_comparison_and_preserves_scope(
    tmp_path, monkeypatch, result
):
    before = {"commit": "a" * 40, "clean": True, "fingerprint": "b" * 64}
    monkeypatch.setattr(native, "source_identity", lambda: before)
    monkeypatch.setattr(native, "enroll", lambda *a, **k: {"machine": "x86_64"})
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setattr(native, "provision", lambda: {"binary_sha256": "c" * 64})
    monkeypatch.setattr(native, "provision_tools", lambda *a: {"controlled": True})
    monkeypatch.setattr(native, "probe_controller", lambda *a: {"controlled": True})
    monkeypatch.setattr(native, "controller_faults", lambda *a: None)

    def forbidden(*a, **k):
        pytest.fail("separate comparison profile duplicated the baseline native suite")

    for name in ("guest_inputs", "boot_guest", "guest_storage_faults", "guest_reboot_faults"):
        monkeypatch.setattr(native, name, forbidden)
    calls = []

    def timeline(tools, binary, temporary, report, *, restored_successor):
        assert tools == {"controlled": True} and binary == "c" * 64 and temporary == tmp_path
        assert restored_successor is True
        calls.append("comparison")
        report.update(
            status="passed",
            observed_successor_verified=True,
            original_guest={"boot_verified": True},
        )
        if result == "raises":
            raise comparison.RestoredSuccessorError("controlled-comparison-failure")
        if result != "missing":
            report["restored_successor"] = {
                "status": "failed" if result == "failed" else "passed",
                "comparison_verified": result != "unobserved",
                "resources_destroyed_with_guest": result != "uncleaned",
            }

    monkeypatch.setattr(native, "qualify_source_successor", timeline)
    output = tmp_path / "report.json"
    code = native.main(
        ["--github-hosted-only", "--profile", "restored-successor", "--output", str(output)]
    )
    report = json.loads(output.read_text())
    assert calls == ["comparison"]
    assert code == (0 if result == "complete" else 1)
    assert report["status"] == ("passed" if result == "complete" else "failed")
    assert report["profile"] == "restored-successor" and report["guest_booted"]
    assert report["source_before"] == report["source_after"] == before
    assert valid_stats(report["statistics"])
    assert report["native_tools_qualified"] is report["production_qualified"] is False


def test_comparison_job_uses_same_enrollment_pins_budget_and_early_controls_as_baseline():
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.load((root / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)
    baseline = workflow["jobs"]["native-controller"]
    job = workflow["jobs"]["native-restored-successor"]
    for key in ("needs", "if", "runs-on"):
        assert job[key] == baseline[key]
    assert (
        job["env"]["FISHHAT_VALIDATION_NOMINAL_MINUTES"]
        == baseline["env"]["FISHHAT_VALIDATION_NOMINAL_MINUTES"]
        == "25"
    )
    assert "['native-restored-successor']" in job["timeout-minutes"]
    assert job["env"]["CHECK_PURPOSES"] == "validation-tooling"
    assert [s["uses"] for s in job["steps"] if "uses" in s] == [
        s["uses"] for s in baseline["steps"] if "uses" in s
    ]
    command = "\n".join(s.get("run", "") for s in job["steps"])
    assert "--github-hosted-only --profile restored-successor" in command
    assert "no native owner or product checkpoint qualification" in job["env"]["CHECK_SCOPE"]
    upload = next(s for s in job["steps"] if "upload-artifact@" in s.get("uses", ""))
    assert upload["if"] == "${{ always() }}"
    assert upload["with"]["path"] == "artifacts/native-roundtrip/restored-successor.json"
    assert upload["with"]["if-no-files-found"] == "error"
    assert "tests/test_native_linux_roundtrip.py" in str(workflow["jobs"]["watchdog-regressions"])
