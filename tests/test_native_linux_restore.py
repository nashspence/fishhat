"""Controlled private restore custody and cleanup; no native image tools run."""

from __future__ import annotations

import copy
import errno
import hashlib
import json
import shutil
import uuid
from contextlib import contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_linux_images as images
from scripts import native_linux_restore as restore
from scripts import native_linux_restore_interruption as interruption
from scripts import native_linux_snapshots as snapshots
from scripts.run_stats import valid_stats
from tests.test_native_linux_snapshots import ControlledImages
from tests.test_native_linux_snapshots import fixture as _snapshot_source

# Register the shared controlled source fixture under its receiving name.
snapshot_source = _snapshot_source

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/native_linux_restore.py",
        "scripts/native_linux_restore_interruption.py",
        "scripts/native_linux_snapshots.py",
        "scripts/native_linux_enrollment.py",
    ],
    "scope": "active sealed-capture lineage, exact stopped source and tool custody, complete exclusive standalone private restore input admission, no partial handles, foreign/stale/substituted input refusal, original preservation and actual failure/cleanup outcomes, fixed typed partial preparation before admission, real partial candidate/writer-gate refusals, unexpected-failure rejection and independent remnant checks with required scoped statistics",
    "relationship": "no-product-claim",
    "reason": "Image conversion/check/compare results are substituted over real unprivileged private files. No QEMU, native guest restore, product writer/checkpoint authority or production deployment is qualified.",
    "claims": [],
}


class RestoreImages(ControlledImages):
    def __call__(self, arguments, name, nominal, *, capture=False):
        if name == "restore-tool":
            self.state["restoring"] = True
            if self.state["restore_mode"] == "wrong-version":
                self.state["calls"].append((arguments, name, nominal, capture))
                return "qemu-img version 8.2.1"
        return super().__call__(arguments, name, nominal, capture=capture)

    def info(self, arguments, capture):
        value = json.loads(super().info(arguments, capture))
        path = Path(arguments[-1])
        mode = self.state["restore_mode"]
        if path in self.state["restore_paths"]:
            if mode == "malformed-info":
                return "controlled-private-payload"
            if mode == "wrong-extent":
                value["virtual-size"] += 1
            if mode == "wrong-format":
                value["format"] = "raw"
            if mode == "output-backing":
                value["backing-filename"] = str(self.directory / "base.img")
            if mode == "output-data":
                value["data-file"] = str(self.directory / "data.qcow2")
            if mode == "output-corrupt":
                value["corrupt"] = True
            if mode == "internal-snapshot":
                value["snapshots"] = [{"id": "1"}]
        elif self.state["restoring"] and mode == "source-backing":
            value["backing-filename"] = str(self.directory / "base.img")
        return json.dumps(value)

    def create(self, arguments, capture):
        result = super().create(arguments, capture)
        target = Path(arguments[-2])
        if self.state["restoring"]:
            self.state["restore_paths"].append(target)
            if self.state["restore_mode"] == "create-failed" and target.name == "control.qcow2":
                raise restore.RestoreError("controlled-create-failed")
        return result

    def convert(self, arguments, capture):
        source, target = map(Path, arguments[-2:])
        if source.parent == self.directory:
            return super().convert(arguments, capture)
        assert self.state["restoring"] and source in self.state["snapshot_paths"]
        assert source.stat().st_mode & 0o777 == 0o400
        assert target in self.state["restore_paths"] and source.name == target.name
        assert arguments[2:-2] == ["-q", "-n", "-f", "qcow2", "-O", "qcow2", "-t", "writethrough"]
        mode = self.state["restore_mode"]
        if mode == "convert-failed" and target.name == "control.qcow2":
            raise restore.RestoreError("controlled-convert-failed")
        target.write_bytes(source.read_bytes())
        if mode == "tool-changed":
            self.tool.write_bytes(b"changed-tool")
        if mode == "replaced-output":
            alternate = target.with_name("alternate")
            alternate.write_bytes(b"changed")
            alternate.chmod(0o600)
            alternate.replace(target)
        if mode == "directory-replaced":
            moved = target.parent.with_name("retained-restore-directory")
            target.parent.rename(moved)
            target.parent.mkdir(mode=0o700)
            (target.parent / "unrelated").write_bytes(b"preserve-substituted-root")
            self.state["moved"] = moved
        if mode == "resource-failure":
            raise PermissionError(errno.EACCES, "controlled-sensitive-payload")
        return ""

    def check(self, arguments, capture):
        if self.state["restoring"] and self.state["restore_mode"] == "check-failed":
            raise restore.RestoreError("controlled-check-failed")
        return super().check(arguments, capture)

    def compare(self, arguments, capture):
        if self.state["restoring"] and self.state["restore_mode"] == "compare-failed":
            raise restore.RestoreError("controlled-compare-failed")
        return super().compare(arguments, capture)


@pytest.fixture
def fixture(snapshot_source, monkeypatch):
    f = snapshot_source
    f.state.update(restore_mode="normal", restoring=False, restore_paths=[])
    f.guest.command = RestoreImages(f.inputs, f.tool, b"controlled-authenticated-base", f.state)
    monkeypatch.setattr(restore, "QEMU_IMG", f.tool)
    return f


def capture(f, report):
    return snapshots.cold_snapshots(
        f.guest, f.custody, f.temporary, lambda name: nullcontext(), report
    )


def prepared(f, sealed, captured, report):
    return restore.private_restored_disks(
        f.guest, f.custody, sealed, captured, f.temporary, lambda name: nullcontext(), report
    )


def observed_files(paths):
    return {
        p: (p.read_bytes(), images.identity(p), p.stat().st_mode, p.stat().st_mtime_ns)
        for p in paths
    }


def test_complete_private_restore_admits_only_three_verified_independent_disks_then_expires(
    fixture,
):
    f = fixture
    captured = {}
    report = {}
    originals = observed_files([*f.inputs.iterdir(), *f.private.iterdir()])
    with capture(f, captured) as sealed:
        original_snapshots = observed_files(sealed.directory.iterdir())
        with prepared(f, sealed, captured, report) as owned:
            assert owned.active and set(owned.files) == set(images.DISK_BYTES)
            assert {p.name for p in owned.directory.iterdir()} == set(images.DISK_BYTES)
            assert owned.directory not in (sealed.directory, f.inputs, f.private)
            for name in images.DISK_BYTES:
                target = owned.path(name, f.guest.enrollment)
                source = sealed.path(name, f.guest.enrollment)
                assert target.read_bytes() == source.read_bytes()
                assert images.identity(target) != images.identity(source)
                assert target.stat().st_mode & 0o777 == 0o600
            assert report["restored_inputs_admitted"] is True
            with pytest.raises(restore.RestoreError, match="restore-not-admitted"):
                owned.path("root.qcow2", str(uuid.uuid4()))
        assert not owned.active and not owned.directory.exists()
        with pytest.raises(restore.RestoreError, match="restore-not-admitted"):
            owned.path("root.qcow2", f.guest.enrollment)
        assert observed_files(sealed.directory.iterdir()) == original_snapshots
        assert observed_files(originals) == originals
    assert report["status"] == "passed" and report["originals_preserved"]
    assert report["temporary_resources_removed"] and not list(f.temporary.iterdir())
    assert report["snapshot_restore_qualified"] is report["product_authority_qualified"] is False
    assert (
        valid_stats(report["statistics"])
        and report["statistics"]["scope"] == "process-excludes-children"
    )
    assert [p["phase"] for p in report["phases"]] == [
        "input-admission",
        *images.DISK_BYTES,
        "complete-input-admission",
        "preservation",
        "cleanup",
    ]
    for item in report["phases"]:
        assert item["status"] == "passed" and valid_stats(item["statistics"])
    for item in report["phases"][1:4]:
        value = item["observation"]
        name = item["phase"]
        assert value["virtual_bytes"] == images.DISK_BYTES[name]
        assert (
            value["standalone"]
            is value["structure_checked"]
            is value["logical_contents_equal"]
            is value["synced"]
            is True
        )
        assert value["read_only"] is False
        assert "backing-filename" not in value["restored_image_observation"]
        assert (
            Path(
                value["source_image_observation"].get("filename", str(sealed.directory / name))
            ).parent
            == sealed.directory
        )
    cleanup = report["phases"][-1]
    assert len(cleanup["paths"]) == 4
    assert all(p["absent"] for p in cleanup["paths"])


@pytest.mark.parametrize(
    "mode",
    [
        "wrong-version",
        "malformed-info",
        "wrong-extent",
        "wrong-format",
        "source-backing",
        "output-backing",
        "output-data",
        "output-corrupt",
        "internal-snapshot",
        "create-failed",
        "convert-failed",
        "check-failed",
        "compare-failed",
        "tool-changed",
        "replaced-output",
        "resource-failure",
    ],
)
def test_failed_restore_never_yields_partial_inputs_preserves_originals_and_cleans(fixture, mode):
    f = fixture
    captured = {}
    report = {}
    originals = observed_files([*f.inputs.iterdir(), *f.private.iterdir()])
    tool = f.tool.read_bytes()
    with capture(f, captured) as sealed:
        snapshot_files = observed_files(sealed.directory.iterdir())
        f.state["restore_mode"] = mode
        try:
            with pytest.raises(
                (restore.RestoreError, snapshots.SnapshotError, images.GuestInputError, OSError)
            ):
                with prepared(f, sealed, captured, report):
                    pytest.fail("partial or invalid restoration cannot be admitted")
            assert report["status"] == "failed" and not report["restored_inputs_admitted"]
            assert valid_stats(report["statistics"])
            assert list(f.temporary.iterdir()) == [sealed.directory]
            assert (
                observed_files(snapshot_files) == snapshot_files
                and observed_files(originals) == originals
            )
            if f.state["restore_paths"]:
                assert report["temporary_resources_removed"]
            assert all(not p.exists() for p in f.state["restore_paths"])
            assert (
                report["snapshot_restore_qualified"]
                is report["product_authority_qualified"]
                is False
            )
            if mode == "resource-failure":
                assert report["resource_failure"] == {
                    "errno": errno.EACCES,
                    "type": "PermissionError",
                }
                assert "controlled-sensitive-payload" not in json.dumps(report)
        finally:
            f.tool.write_bytes(tool)


@pytest.mark.parametrize(
    "mode",
    [
        "expired",
        "foreign",
        "incomplete",
        "rebound-registry",
        "source-changed",
        "wrong-custody",
        "wrong-tool",
        "missing-anchor",
    ],
)
def test_invalid_capture_or_source_is_refused_before_any_restore_effect(fixture, mode):
    f = fixture
    captured = {}
    report = {}
    with capture(f, captured) as sealed:
        saved = (
            sealed.active,
            sealed.enrollment,
            copy.deepcopy(sealed.files),
            copy.deepcopy(f.custody),
            copy.deepcopy(captured),
            f.tool.read_bytes(),
        )
        disk = f.inputs / "root.qcow2"
        disk_bytes = disk.read_bytes()
        try:
            if mode == "expired":
                sealed.active = False
            elif mode == "foreign":
                sealed.enrollment = str(uuid.uuid4())
            elif mode == "incomplete":
                sealed.files.pop("data.qcow2")
            elif mode == "rebound-registry":
                item = sealed.files["root.qcow2"]
                sealed.files["root.qcow2"] = (item[0], "f" * 64)
            elif mode == "source-changed":
                disk.write_bytes(b"changed-source")
            elif mode == "wrong-custody":
                f.custody["pid"] += 1
            elif mode == "wrong-tool":
                f.tool.write_bytes(b"changed-tool")
            else:
                captured["capture_verified"] = False
            before = len(f.state["calls"])
            with pytest.raises(
                (restore.RestoreError, snapshots.SnapshotError, images.GuestInputError)
            ):
                with prepared(f, sealed, captured, report):
                    pytest.fail("unadmitted source")
            assert len(f.state["calls"]) == before and not f.state["restore_paths"]
            assert report["status"] == "failed" and valid_stats(report["statistics"])
        finally:
            sealed.active, sealed.enrollment, sealed.files, custody, evidence, tool = saved
            f.custody.clear()
            f.custody.update(custody)
            captured.clear()
            captured.update(evidence)
            disk.write_bytes(disk_bytes)
            f.tool.write_bytes(tool)


@pytest.mark.parametrize(
    "mode", ["foreign-name", "missing-disk", "rebound-file", "rebound-directory", "extra-file"]
)
def test_admitted_handle_refuses_rebinding_and_cleanup_preserves_foreign_neighbors(fixture, mode):
    f = fixture
    captured = {}
    report = {}
    foreign = f.temporary.parent / "unrelated"
    foreign.mkdir(mode=0o700)
    canary = foreign / "canary"
    canary.write_bytes(b"unrelated")
    canary.chmod(0o600)
    original = observed_files([canary])
    with capture(f, captured) as sealed:
        with pytest.raises(restore.RestoreError):
            with prepared(f, sealed, captured, report) as owned:
                directory = owned.directory
                if mode == "foreign-name":
                    owned.path("../unrelated/canary", f.guest.enrollment)
                elif mode == "missing-disk":
                    owned.files.pop("data.qcow2")
                    owned.verify()
                elif mode == "rebound-file":
                    p = directory / "root.qcow2"
                    p.write_bytes(b"changed")
                    owned.files[p.name] = (
                        images.identity(p),
                        hashlib.sha256(p.read_bytes()).hexdigest(),
                    )
                    owned.verify()
                elif mode == "rebound-directory":
                    owned.directory = foreign
                    owned.directory_identity = images.identity(foreign, directory=True)
                    owned.verify()
                else:
                    (directory / "unexpected").write_bytes(b"extra")
                    owned.verify()
        assert not directory.exists() and not owned.active
        assert observed_files(original) == original
        assert report["status"] == "failed" and report["temporary_resources_removed"]
        assert valid_stats(report["statistics"])


def test_substituted_restore_root_is_not_deleted_and_primary_and_cleanup_outcomes_are_retained(
    fixture,
):
    f = fixture
    captured = {}
    report = {}
    with capture(f, captured) as sealed:
        f.state["restore_mode"] = "directory-replaced"
        try:
            with pytest.raises(snapshots.SnapshotError):
                with prepared(f, sealed, captured, report):
                    pytest.fail("substituted root")
            paths = f.state["restore_paths"]
            root = paths[0].parent
            assert (root / "unrelated").read_bytes() == b"preserve-substituted-root"
            assert f.state["moved"].exists()
            assert report["status"] == "failed" and report["temporary_resources_removed"] is False
            assert report["problem"] and report["cleanup_problem"]
            assert (
                report["phases"][-1]["phase"] == "cleanup"
                and report["phases"][-1]["status"] == "failed"
            )
            assert valid_stats(report["statistics"])
        finally:
            shutil.rmtree(f.state["moved"])
            shutil.rmtree(root)


@pytest.mark.parametrize("mode", ["complete", "caller-failed", "missing-stats"])
def test_restore_qualification_keeps_refusals_canary_statistics_and_actual_failure(
    fixture, monkeypatch, mode
):
    f = fixture
    captured = {}
    report = {}
    with capture(f, captured) as sealed:
        if mode == "missing-stats":
            monkeypatch.setattr(restore, "valid_stats", lambda value: False)
        if mode == "caller-failed":
            real = restore.RestoredDisks.verify

            def verify(owner):
                real(owner)
                if report.get("restored_inputs_admitted"):
                    raise restore.RestoreError("controlled-use-failed")

            monkeypatch.setattr(restore.RestoredDisks, "verify", verify)

        def invoke():
            restore.qualify_restore(
                f.guest,
                f.custody,
                sealed,
                captured,
                f.temporary,
                lambda name: nullcontext(),
                report,
            )

        if mode == "complete":
            invoke()
            assert report["status"] == "passed"
            assert report["foreign_enrollment_refused"] and report["expired_handle_refused"]
        else:
            with pytest.raises((restore.RestoreError, ValueError)):
                invoke()
            assert report["status"] == "failed"
        assert report["unrelated_canary_preserved"]
        assert list(f.temporary.iterdir()) == [sealed.directory]
        assert valid_stats(report["statistics"]) and valid_stats(report["qualification_statistics"])


@pytest.mark.parametrize(
    "mode", ["output-backing", "output-data", "wrong-extent", "output-corrupt"]
)
def test_new_target_layout_is_observed_before_any_conversion_write(fixture, mode):
    f = fixture
    captured, report = {}, {}
    with capture(f, captured) as sealed:
        f.state["restore_mode"] = mode
        before = len(f.state["calls"])
        with pytest.raises((restore.RestoreError, snapshots.SnapshotError, images.GuestInputError)):
            with prepared(f, sealed, captured, report):
                pytest.fail("unadmitted target cannot receive converted bytes")
        calls = f.state["calls"][before:]
        assert any(name == "restore-create" for _, name, _, _ in calls)
        assert not any(name == "restore-convert" for _, name, _, _ in calls)
        assert report["temporary_resources_removed"] and not report["restored_inputs_admitted"]


def test_caller_failure_is_preserved_if_final_preservation_also_fails(fixture):
    f = fixture
    captured, report = {}, {}
    with capture(f, captured) as sealed:
        with pytest.raises(restore.RestoreError, match="restored-input-changed"):
            with prepared(f, sealed, captured, report) as owned:
                (owned.directory / "root.qcow2").write_bytes(b"changed-after-admission")
                raise restore.RestoreError("controlled-first-failure")
        assert report["problem"] == {
            "stage": "guest-restore",
            "reason": "controlled-first-failure",
            "type": "RestoreError",
        }
        assert report["phases"][-2]["problem"]["reason"] == "restored-input-changed"
        assert report["phases"][-1]["phase"] == "cleanup"
        assert report["phases"][-1]["status"] == "passed"
        assert report["status"] == "failed" and report["temporary_resources_removed"]
        assert valid_stats(report["statistics"])


@pytest.mark.parametrize("mode", ["passed", "failed", "resources-left"])
def test_final_fixture_cleanup_requires_actual_complete_private_restore_proof(monkeypatch, mode):
    from scripts import native_linux_enrollment as native

    private = {
        "status": "failed" if mode == "failed" else "passed",
        "temporary_resources_removed": mode != "resources-left",
    }
    guest = {
        "process_reaped": True,
        "temporary_resources_removed": True,
        "storage": {},
        "endpoint": {},
        "private_restore": private,
    }
    inputs = {"temporary_resources_removed": True, "base_preserved": True}
    observations = []
    monkeypatch.setattr(native, "endpoint_closed", lambda endpoint: observations.append(endpoint))
    if mode == "passed":
        native.verify_guest_cleanup(guest, inputs)
        assert private["resources_destroyed_with_guest"] is True
    else:
        with pytest.raises(native.GuestBootError, match="private-restore-proof-incomplete"):
            native.verify_guest_cleanup(guest, inputs)
        assert "resources_destroyed_with_guest" not in private
    assert observations == [guest["endpoint"]]


@pytest.mark.parametrize("failed", [False, True], ids=["complete", "restore-failure"])
def test_capture_composes_private_restore_only_during_its_verified_sealed_lifetime(fixture, failed):
    f = fixture
    captured, report = {}, {}
    f.state["restore_mode"] = "convert-failed" if failed else "normal"
    handles = []

    def consume(sealed):
        handles.append(sealed)
        assert sealed.active and captured["capture_verified"]
        restore.qualify_restore(
            f.guest, f.custody, sealed, captured, f.temporary, lambda name: nullcontext(), report
        )

    def invoke():
        snapshots.qualify_capture(
            f.guest, f.custody, f.temporary, lambda name: nullcontext(), captured, consume=consume
        )

    if failed:
        with pytest.raises(restore.RestoreError, match="controlled-convert-failed"):
            invoke()
    else:
        invoke()
        assert report["originals_preserved"]
        assert (
            report["phases"][0]["observation"]["source"] == captured["phases"][-1]["source_after"]
        )
    assert captured["status"] == report["status"] == ("failed" if failed else "passed")
    assert captured["source_preserved"] and captured["snapshots_preserved_until_cleanup"]
    assert captured["temporary_resources_removed"] and report["temporary_resources_removed"]
    assert len(handles) == 1 and not handles[0].active
    assert not list(f.temporary.iterdir())
    assert valid_stats(report["statistics"]) and valid_stats(captured["statistics"])


def interrupted_restore(f, owned, captured, report, progress=lambda _: nullcontext()):
    interruption.qualify_restore_interruption(
        f.guest, f.custody, owned, captured, f.temporary, progress, report
    )


def test_typed_partial_restore_uses_one_real_private_disk_and_preserves_failed_admission(fixture):
    f = fixture
    captured, report = {}, {}
    original = observed_files([*f.inputs.iterdir(), *f.private.iterdir()])
    with capture(f, captured) as owned:
        frozen = copy.deepcopy(captured)
        sealed = observed_files(owned.directory.iterdir())
        interrupted_restore(f, owned, captured, report)
        assert report["status"] == "observed" and report["interruption_verified"]
        assert report["no_writer_admitted"] and not report["resources_destroyed_with_guest"]
        private = report["private_inputs"]
        assert private["status"] == "failed" and not private["restored_inputs_admitted"]
        assert (
            private["problem"]
            == report["expected_failure"]
            == {
                "type": "PartialRestoreInterrupted",
                "stage": "guest-restore-interruption",
                "reason": "controlled-after-first-private-disk-before-admission",
            }
        )
        assert [p["phase"] for p in private["phases"]] == [
            "input-admission",
            "root.qcow2",
            "cleanup",
        ]
        assert len(f.state["restore_paths"]) == 1
        assert f.state["restore_paths"][0].name == "root.qcow2"
        assert all(not p.exists() for p in f.state["restore_paths"])
        assert report["writer_admission_failure"] == {
            "type": "RestoreError",
            "stage": "guest-restore",
            "reason": "restore-not-admitted",
        }
        assert (
            report["writer_gate"]["lifetime_ended"] and report["writer_gate"]["status"] == "failed"
        )
        assert set(report["refusals"]) == {
            "partial-admission",
            "partial-path",
            "foreign-enrollment",
            "substituted-directory",
            "expired-partial",
        }
        assert observed_files(original) == original and observed_files(sealed) == sealed
        assert captured == frozen and report["source_before"] == report["source_after"]
        assert list(f.temporary.iterdir()) == [owned.directory]
    interruption.finish_restore_interruption(report)
    assert report["status"] == "passed" and report["resources_destroyed_with_guest"]
    assert all(p["absent"] for p in report["phases"][-1]["paths"])
    for value in (report, private, report["writer_gate"]):
        assert valid_stats(value["statistics"])
    assert report["snapshot_restore_qualified"] is report["product_authority_qualified"] is False


@pytest.mark.parametrize(
    "mode",
    [
        "unexpected-error",
        "lookalike-interruption",
        "cleanup-error",
        "missing-cleanup",
        "missing-statistics",
        "boundary-skipped",
    ],
)
def test_unexpected_partial_restore_outcomes_cannot_qualify_and_keep_original_failure(
    fixture, monkeypatch, mode
):
    f = fixture
    captured, report = {}, {}
    actual_cleanup = restore.remove_owned

    def cleanup(*args):
        actual_cleanup(*args)
        if mode == "cleanup-error":
            raise restore.RestoreError("controlled-cleanup-error")
        args[-1]["temporary_resources_removed"] = False

    if mode in {"cleanup-error", "missing-cleanup"}:
        monkeypatch.setattr(restore, "remove_owned", cleanup)
    if mode == "missing-statistics":
        monkeypatch.setattr(interruption, "RunStats", lambda: SimpleNamespace(finish=lambda: None))
    if mode == "boundary-skipped":
        actual_restore = interruption.private_restored_disks

        def skipped(*args):
            values = list(args)
            expected = args[5]
            values[5] = lambda _: expected("unexpected-boundary")
            return actual_restore(*values)

        monkeypatch.setattr(interruption, "private_restored_disks", skipped)

    @contextmanager
    def progress(name):
        yield
        if name == "restore-root.qcow2":
            if mode == "unexpected-error":
                raise RuntimeError("controlled-unrelated-failure")
            if mode == "lookalike-interruption":
                raise interruption.PartialRestoreInterrupted()

    with capture(f, captured) as owned:
        original = observed_files(
            [*f.inputs.iterdir(), *f.private.iterdir(), *owned.directory.iterdir()]
        )
        with pytest.raises((RuntimeError, ValueError)):
            interrupted_restore(f, owned, captured, report, progress)
        assert report["status"] == "failed" and not report["resources_destroyed_with_guest"]
        assert all(not p.exists() for p in f.state["restore_paths"])
        assert observed_files(original) == original
        if mode == "cleanup-error":
            assert report["private_inputs"]["problem"]["type"] == "PartialRestoreInterrupted"
            assert (
                report["private_inputs"]["cleanup_problem"]["reason"] == "controlled-cleanup-error"
            )
        if mode == "lookalike-interruption":
            assert report["problem"]["reason"] == "unobserved-partial-interruption"
            assert not report["interruption_verified"]
        if mode == "boundary-skipped":
            assert report["private_inputs"]["restored_inputs_admitted"] is True
            assert report["problem"]["reason"] == "complete-inputs-unexpectedly-admitted"
        if mode != "missing-statistics":
            assert valid_stats(report["statistics"])


@pytest.mark.parametrize(
    "change",
    [
        "failure-type",
        "failure-reason",
        "writer-gate",
        "writer-statistics",
        "partial-admission",
        "cleanup-observation",
        "refusal",
        "phase",
        "statistics",
        "source",
        "partial-record",
        "private-remnant",
        "unrelated-remnant",
    ],
)
def test_missing_partial_failure_or_actual_cleanup_evidence_blocks_final_success(fixture, change):
    f = fixture
    captured, report = {}, {}
    with capture(f, captured) as owned:
        interrupted_restore(f, owned, captured, report)
    private = report["private_inputs"]
    remnant = None
    try:
        if change == "failure-type":
            private["problem"]["type"] = "RuntimeError"
        elif change == "failure-reason":
            report["expected_failure"]["reason"] = "unclassified"
        elif change == "writer-gate":
            report["writer_gate"]["status"] = "passed"
        elif change == "writer-statistics":
            report["writer_gate"]["statistics"] = None
        elif change == "partial-admission":
            private["restored_inputs_admitted"] = True
        elif change == "cleanup-observation":
            private["phases"][-1]["paths"] = []
        elif change == "refusal":
            report["refusals"].pop("foreign-enrollment")
        elif change == "phase":
            report["phases"].pop(2)
        elif change == "statistics":
            report["statistics"] = None
        elif change == "source":
            report["source_after"] = {}
        elif change == "partial-record":
            report["partial_candidate"]["files"] = {}
        else:
            remnant = (
                (Path(private["directory"]["path"]) / "root.qcow2")
                if change == "private-remnant"
                else Path(report["unrelated_canary"]["path"])
            )
            remnant.parent.mkdir(mode=0o700)
            remnant.write_bytes(b"controlled-leftover")
        with pytest.raises(interruption.RestoreInterruptionError):
            interruption.finish_restore_interruption(report)
        assert report["status"] == "failed" and not report["resources_destroyed_with_guest"]
    finally:
        if remnant is not None:
            shutil.rmtree(remnant.parent)
