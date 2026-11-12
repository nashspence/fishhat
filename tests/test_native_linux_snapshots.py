"""Controlled cold-capture custody; no image tool or guest runs locally."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import uuid
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_linux_guest as guests
from scripts import native_linux_images as images
from scripts import native_linux_snapshots as snapshots
from scripts.run_stats import valid_stats
from scripts.validation_timeouts import watchdog

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": [
        "scripts/native_linux_snapshots.py",
        "scripts/native_linux_successor.py",
        "scripts/native_linux_enrollment.py",
    ],
    "scope": "stopped enrolled disk custody, standalone complete logical capture, immutable admitted sealed-handle custody, complete input membership, one-time admission, original directory cleanup anchoring, frozen source evidence independent of mutable reports, source preservation and partial failure cleanup with required statistics",
    "relationship": "no-product-claim",
    "reason": "Image conversion/profile results are substituted. Real unprivileged files, loopback probes and short child processes challenge ownership and absence checks only. No QEMU, guest restore, native owner or product authority is qualified.",
    "claims": [],
}


class ControlledImages:
    def __init__(self, directory, tool, base, state):
        self.directory, self.tool, self.base, self.state = directory, tool, base, state

    def logical(self, path):
        value = path.read_bytes()
        return value + self.base if path == self.directory / "root.qcow2" else value

    def __call__(self, arguments, name, nominal, *, capture=False):
        self.state["calls"].append((arguments, name, nominal, capture))
        assert arguments[0] == str(self.tool)
        assert not {"-U", "--force-share", "--salvage", "--force", "-r", "-B"}.intersection(
            arguments
        )
        if arguments[1] == "--version":
            return "qemu-img version " + (
                "8.2.1" if self.state["mode"] == "wrong-tool" else "8.2.2"
            )
        return getattr(self, arguments[1])(arguments, capture)

    def info(self, arguments, capture):
        mode = self.state["mode"]
        assert arguments[2:5] == ["--output=json", "-f", "qcow2"] and capture
        path = Path(arguments[-1])
        target = path.parent != self.directory
        if mode == "malformed-info":
            return "controlled-private-output"
        info = {"format": "qcow2", "virtual-size": images.DISK_BYTES[path.name]}
        if not target and path.name == "root.qcow2":
            info.update(
                {
                    "backing-filename": str(self.directory / "base.img"),
                    "backing-filename-format": "qcow2",
                }
            )
        if target:
            assert path in self.state["snapshot_paths"]
            if mode == "wrong-size":
                info["virtual-size"] += 1
            if mode == "wrong-format":
                info["format"] = "raw"
            if mode == "output-backing":
                info["backing-filename"] = str(self.directory / "base.img")
            if mode == "external-data":
                info["data-file"] = str(self.directory / "data.qcow2")
            if mode == "corrupt-output":
                info["corrupt"] = True
            if mode == "internal-snapshot":
                info["snapshots"] = [{"id": "1"}]
        elif mode == "foreign-source-backing":
            info["backing-filename"] = str(self.directory.parent / "unrelated")
        return json.dumps(info)

    def create(self, arguments, capture):
        mode = self.state["mode"]
        target = Path(arguments[-2])
        assert target.stat().st_size == 0 and stat.S_IMODE(target.stat().st_mode) == 0o600
        assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700
        assert int(arguments[-1]) == images.DISK_BYTES[target.name]
        self.state["snapshot_paths"].append(target)
        target.write_bytes(b"controlled-empty-image")
        if mode == "create-failure":
            raise snapshots.SnapshotError("controlled-create-failure")
        if mode == "replaced-output":
            replacement = target.parent / "replacement"
            replacement.write_bytes(b"replaced")
            replacement.chmod(0o600)
            replacement.replace(target)
        return ""

    def convert(self, arguments, capture):
        mode = self.state["mode"]
        assert arguments[2:-2] == [
            "-q",
            "-n",
            "-f",
            "qcow2",
            "-O",
            "qcow2",
            "-t",
            "writethrough",
        ]
        source, target = map(Path, arguments[-2:])
        assert source.parent == self.directory and target.parent != self.directory
        assert source.name == target.name
        if mode == "convert-failure" and target.name == "control.qcow2":
            raise snapshots.SnapshotError("controlled-convert-failure")
        target.write_bytes(self.logical(source))
        if mode == "changed-source":
            source.write_bytes(source.read_bytes() + b"changed")
        if mode == "changed-tool":
            self.tool.write_bytes(b"changed-tool")
        return ""

    def check(self, arguments, capture):
        mode = self.state["mode"]
        assert arguments[2:5] == ["-q", "-f", "qcow2"]
        if mode == "check-failure":
            raise snapshots.SnapshotError("controlled-image-structural-failure")
        return ""

    def compare(self, arguments, capture):
        mode = self.state["mode"]
        assert arguments[1] == "compare" and arguments[2:-2] == ["-q", "-f", "qcow2", "-F", "qcow2"]
        source, target = map(Path, arguments[-2:])
        if mode == "compare-failure" or self.logical(source) != target.read_bytes():
            raise snapshots.SnapshotError("controlled-contents-differ")
        self.state["output"][target.name] = target.read_bytes()
        return ""


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    directory = tmp_path / "inputs"
    private = tmp_path / "private"
    temporary = tmp_path / "temporary"
    for path in (directory, private, temporary):
        path.mkdir(mode=0o700)
    base = b"controlled-authenticated-base"
    monkeypatch.setattr(images, "IMAGE_BYTES", len(base))
    monkeypatch.setattr(images, "IMAGE_SHA256", hashlib.sha256(base).hexdigest())
    enrollment = str(uuid.uuid4())
    inputs = images.GuestInputs(enrollment, directory, images.identity(directory, directory=True))
    for name in ("base.img", *images.DISK_BYTES):
        path = directory / name
        path.write_bytes(base if name == "base.img" else ("controlled-" + name).encode())
        path.chmod(0o400 if name == "base.img" else 0o600)
        inputs.register(name)
    tool = tmp_path / "image-tool"
    tool.write_bytes(b"controlled-image-tool")
    monkeypatch.setattr(images, "QEMU_IMG", tool)
    monkeypatch.setattr(snapshots, "QEMU_IMG", tool)
    monkeypatch.setattr(guests, "tool_hashes", lambda: {"controlled": "a" * 64})
    process = subprocess.Popen([sys.executable, "-I", "-S", "-c", "pass"], start_new_session=True)
    process.wait(timeout=watchdog(5))
    endpoint = tmp_path / "ended-controller" / "qmp"
    process.args = ["controlled-qemu", "-qmp", f"unix:{endpoint},server=on,wait=off"]
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    state = {"mode": "normal", "calls": [], "output": {}, "snapshot_paths": []}

    command = ControlledImages(directory, tool, base, state)

    report = {
        "controller_verified": {
            "instance_uuid": enrollment,
            "unix_peer_verified": True,
            "started_from_verified_prelaunch": True,
        }
    }
    guest = guests.Guest(
        inputs,
        private,
        command,
        {"sha256": {"controlled": "a" * 64}},
        report,
        port,
        Path("/controlled/qemu"),
        images.identity(private, directory=True),
    )
    guest.write("seed.iso", "controlled-seed")
    guest.process = process
    guest.observed = {
        "distribution": "ubuntu",
        "distribution_version": "24.04",
        "machine": "x86_64",
        "kernel": guests.KERNEL,
        "pid1": "systemd",
        "cgroup_v2": True,
        "dmi_uuid": enrollment,
        "enrollment": enrollment,
        "instance_id": enrollment,
        "ssh_principal": guest.accounts[0],
        "packages": guests.GUEST_PACKAGES,
        "cloud_init_complete": True,
        "boot_id": str(uuid.uuid4()),
        "accounts": {
            name: {"uid": 1000 + i, "gid": 1000 + i} for i, name in enumerate(guest.accounts)
        },
    }
    custody = {
        "pid": process.pid,
        "pgid": process.pid,
        "controller": copy.deepcopy(report["controller_verified"]),
        "endpoint": {"address": "127.0.0.1", "port": port, "listener_owned": True},
        "control_socket": {"path": str(endpoint)},
        "input_directory": {"path": str(directory), "identity": inputs.directory_identity},
        "private_directory": {"path": str(private), "identity": guest.directory_identity},
        "private_files": {
            name: {"path": str(guest.path(name)), "identity": v[0]}
            for name, v in guest.files.items()
        },
        "disks": {
            name: {"path": str(inputs.path(name, enrollment)), "identity": value}
            for name, value in inputs.files.items()
        },
    }
    return SimpleNamespace(
        guest=guest,
        custody=custody,
        state=state,
        temporary=temporary,
        inputs=directory,
        private=private,
        endpoint=endpoint,
        tool=tool,
    )


def capture(fixture, report):
    return snapshots.cold_snapshots(
        fixture.guest, fixture.custody, fixture.temporary, lambda name: nullcontext(), report
    )


def test_cold_capture_checks_exact_extents_complete_logical_contents_seals_and_cleans(fixture):
    f = fixture
    originals = {p: (p.read_bytes(), p.lstat()) for p in f.inputs.iterdir()}
    report = {}
    with capture(f, report) as owned:
        assert owned.active and set(owned.files) == set(images.DISK_BYTES)
        for name in images.DISK_BYTES:
            path = owned.path(name, f.guest.enrollment)
            assert path.read_bytes() == f.state["output"][name]
            assert stat.S_IMODE(path.stat().st_mode) == 0o400
        assert (
            owned.path("root.qcow2", f.guest.enrollment)
            .read_bytes()
            .endswith(b"controlled-authenticated-base")
        )
        assert report["capture_verified"] and report["snapshot_restore_qualified"] is False
    assert not owned.active and not owned.directory.exists()
    assert report["status"] == "passed" and report["source_preserved"]
    assert report["snapshots_preserved_until_cleanup"] and report["temporary_resources_removed"]
    assert report["product_authority_qualified"] is False
    assert (
        valid_stats(report["statistics"])
        and report["statistics"]["scope"] == "process-excludes-children"
    )
    assert len(report["phases"]) == 5 and all(
        valid_stats(p["statistics"]) for p in report["phases"]
    )
    assert {p: (p.read_bytes(), p.lstat()) for p in f.inputs.iterdir()} == originals
    assert not list(f.temporary.iterdir())
    with pytest.raises(snapshots.SnapshotError, match="snapshot-not-admitted"):
        owned.path("root.qcow2", f.guest.enrollment)


@pytest.mark.parametrize(
    "mode",
    [
        "wrong-tool",
        "malformed-info",
        "wrong-size",
        "wrong-format",
        "foreign-source-backing",
        "output-backing",
        "external-data",
        "corrupt-output",
        "internal-snapshot",
        "create-failure",
        "replaced-output",
        "convert-failure",
        "check-failure",
        "compare-failure",
        "changed-source",
        "changed-tool",
    ],
)
def test_invalid_or_interrupted_capture_never_yields_partial_handle_and_cleans(fixture, mode):
    f = fixture
    f.state["mode"] = mode
    originals = {
        p.name: (p.read_bytes(), images.identity(p), p.stat().st_mode) for p in f.inputs.iterdir()
    }
    report = {}
    with pytest.raises((snapshots.SnapshotError, images.GuestInputError)) as error:
        with capture(f, report):
            pytest.fail("invalid capture cannot yield an admitted handle")
    assert "controlled-private-output" not in str(error.value)
    assert report["status"] == "failed" and not report["capture_verified"]
    assert report["snapshot_restore_qualified"] is False
    assert valid_stats(report["statistics"]) and not list(f.temporary.iterdir())
    for name, original in originals.items():
        if mode != "changed-source" or name == "base.img":
            path = f.inputs / name
            assert (path.read_bytes(), images.identity(path), path.stat().st_mode) == original
    assert f.guest.directory.exists() and f.guest.path("seed.iso").read_text() == "controlled-seed"


@pytest.mark.parametrize(
    "mode",
    [
        "unreaped",
        "wrong-pid",
        "foreign-controller",
        "unverified-controller",
        "foreign-control-path",
        "foreign-endpoint",
        "live-control-parent",
        "wrong-input-directory",
        "wrong-private-directory",
        "wrong-disk-custody",
        "wrong-private-custody",
        "foreign-boot",
        "changed-seed",
    ],
)
def test_live_stale_foreign_custody_is_refused_before_capture_mutations(fixture, mode):
    f = fixture
    if mode == "unreaped":
        f.guest.process.returncode = None
    elif mode == "wrong-pid":
        f.custody["pid"] += 1
    elif mode == "foreign-controller":
        f.custody["controller"]["instance_uuid"] = str(uuid.uuid4())
    elif mode == "unverified-controller":
        f.guest.report["controller_verified"]["unix_peer_verified"] = False
    elif mode == "foreign-control-path":
        f.custody["control_socket"]["path"] = str(f.temporary / "foreign" / "qmp")
    elif mode == "foreign-endpoint":
        f.custody["endpoint"]["port"] += 1
    elif mode == "live-control-parent":
        f.endpoint.parent.mkdir()
    elif mode == "wrong-input-directory":
        f.custody["input_directory"]["path"] = str(f.temporary)
    elif mode == "wrong-private-directory":
        f.custody["private_directory"]["path"] = str(f.temporary)
    elif mode == "wrong-disk-custody":
        f.custody["disks"]["root.qcow2"]["path"] = str(f.temporary / "foreign")
    elif mode == "wrong-private-custody":
        f.custody["private_files"]["seed.iso"]["path"] = str(f.temporary / "foreign")
    elif mode == "foreign-boot":
        f.guest.observed["enrollment"] = str(uuid.uuid4())
    else:
        (f.private / "seed.iso").write_text("substituted")
    report = {}
    with pytest.raises(guests.GuestBootError):
        with capture(f, report):
            pytest.fail("foreign custody must not be admitted")
    assert f.state["calls"] == [] and not list(f.temporary.iterdir())
    assert report["status"] == "failed" and valid_stats(report["statistics"])


@pytest.mark.parametrize(
    "mode",
    [
        "foreign-enrollment",
        "foreign-name",
        "changed-bytes",
        "writable",
        "symlink",
        "hardlink",
        "directory-replaced",
    ],
)
def test_sealed_handles_refuse_foreign_substitution_before_use_and_preserve_neighbors(
    fixture, mode
):
    f = fixture
    foreign = f.temporary.parent / "foreign-image"
    foreign.write_bytes(b"unrelated-image")
    foreign.chmod(0o600)
    original = (images.identity(foreign), foreign.read_bytes(), foreign.stat().st_mode)
    report = {}
    moved = None
    try:
        with pytest.raises((snapshots.SnapshotError, images.GuestInputError)):
            with capture(f, report) as owned:
                path = owned.path("root.qcow2", f.guest.enrollment)
                before_calls = len(f.state["calls"])
                if mode == "foreign-enrollment":
                    owned.path("root.qcow2", str(uuid.uuid4()))
                elif mode == "foreign-name":
                    owned.path("../foreign-image", f.guest.enrollment)
                elif mode == "changed-bytes":
                    path.write_bytes(b"changed")
                elif mode == "writable":
                    path.chmod(0o600)
                elif mode in ("symlink", "hardlink"):
                    path.unlink()
                    if mode == "symlink":
                        path.symlink_to(foreign)
                    else:
                        os.link(foreign, path)
                else:
                    moved = owned.directory.with_name("retained-owned-directory")
                    owned.directory.rename(moved)
                    owned.directory.mkdir(mode=0o700)
                    (owned.directory / "unrelated").write_bytes(b"must-remain")
                try:
                    owned.path("root.qcow2", f.guest.enrollment)
                finally:
                    assert len(f.state["calls"]) == before_calls
        assert report["status"] == "failed" and valid_stats(report["statistics"])
        assert (
            foreign.read_bytes() == b"unrelated-image"
            and (images.identity(foreign), foreign.read_bytes(), foreign.stat().st_mode) == original
        )
        if moved is not None:
            assert (owned.directory / "unrelated").read_bytes() == b"must-remain"
            assert moved.exists() and report["temporary_resources_removed"] is False
        else:
            assert not owned.directory.exists()
    finally:
        if moved is not None:
            import shutil

            shutil.rmtree(moved)
            shutil.rmtree(owned.directory)


@pytest.mark.parametrize("group", [False, True], ids=["process", "group"])
def test_live_process_or_group_is_only_observed_and_never_stopped(group):
    child = subprocess.Popen(
        [sys.executable, "-I", "-S", "-c", "import time; time.sleep(30)"], start_new_session=True
    )
    try:
        with pytest.raises(snapshots.SnapshotError, match="controller-still-present"):
            snapshots.absent_process(child.pid, group=group)
        assert child.poll() is None
    finally:
        child.terminate()
        child.wait(timeout=watchdog(5))


@pytest.mark.parametrize("mode", ["complete", "use-failure", "conversion-failure", "missing-stats"])
def test_native_capture_coordinator_retains_refusals_unrelated_state_and_actual_failure(
    fixture, monkeypatch, mode
):
    f = fixture
    report = {}
    if mode == "conversion-failure":
        f.state["mode"] = "convert-failure"
    if mode == "missing-stats":
        monkeypatch.setattr(snapshots, "valid_stats", lambda _: False)
    if mode == "use-failure":
        original = snapshots.DiskSnapshots.verify

        def verify(owner):
            original(owner)
            if report.get("capture_verified"):
                raise snapshots.SnapshotError("controlled-use-failure")

        monkeypatch.setattr(snapshots.DiskSnapshots, "verify", verify)

    def invoke():
        snapshots.qualify_capture(
            f.guest, f.custody, f.temporary, lambda name: nullcontext(), report
        )

    if mode == "complete":
        invoke()
        assert report["status"] == "passed"
        assert report["foreign_enrollment_refused"] and report["stale_handle_refused"]
    else:
        with pytest.raises((snapshots.SnapshotError, ValueError)):
            invoke()
        assert report["status"] == "failed"
    assert report["unrelated_canary_preserved"] and not list(f.temporary.iterdir())
    assert valid_stats(report["statistics"]) and valid_stats(report["qualification_statistics"])
    assert report["snapshot_restore_qualified"] is report["product_authority_qualified"] is False


@pytest.mark.parametrize(
    "mode",
    [
        "enrollment",
        "directory",
        "directory-identity",
        "file-identity",
        "file-hash",
        "partial",
        "extra",
    ],
)
def test_admitted_capture_records_cannot_be_rewritten_to_adopt_new_custody(fixture, mode):
    f = fixture
    neighbor = f.temporary.parent / "unrelated-capture"
    neighbor.mkdir(mode=0o700)
    report = {}
    with pytest.raises(snapshots.SnapshotError, match="snapshot-input-custody-changed"):
        with capture(f, report) as owned:
            original_directory = owned.directory
            enrollment = owned.enrollment
            path = owned.path("root.qcow2", enrollment)
            for name in images.DISK_BYTES:
                target = neighbor / name
                target.write_bytes((owned.directory / name).read_bytes())
                target.chmod(0o400)
            preserved = {p.name: (p.read_bytes(), p.lstat()) for p in neighbor.iterdir()}
            before_calls = len(f.state["calls"])
            if mode == "enrollment":
                owned.enrollment = enrollment = str(uuid.uuid4())
            elif mode == "directory":
                owned.directory = neighbor
                owned.directory_identity = images.identity(neighbor, directory=True)
                owned.files = {
                    name: (images.identity(neighbor / name), images.digest(neighbor / name))
                    for name in images.DISK_BYTES
                }
            elif mode == "directory-identity":
                owned.directory_identity = images.identity(neighbor, directory=True)
            elif mode == "file-identity":
                replacement = path.with_name("replacement")
                replacement.write_bytes(path.read_bytes())
                replacement.chmod(0o400)
                replacement.replace(path)
                owned.files[path.name] = images.identity(path), images.digest(path)
            elif mode == "file-hash":
                path.chmod(0o600)
                path.write_bytes(b"different-sealed-bytes")
                path.chmod(0o400)
                owned.files[path.name] = images.identity(path), images.digest(path)
            elif mode == "partial":
                del owned.files["data.qcow2"]
            else:
                owned.files["extra.qcow2"] = owned.files["root.qcow2"]
            try:
                owned.path("root.qcow2", enrollment)
            finally:
                assert len(f.state["calls"]) == before_calls
    assert report["status"] == "failed" and not owned.active
    assert report["temporary_resources_removed"] and not original_directory.exists()
    assert {p.name: (p.read_bytes(), p.lstat()) for p in neighbor.iterdir()} == preserved
    assert valid_stats(report["statistics"]) and not list(f.temporary.iterdir())


def test_an_active_flag_does_not_admit_an_unsealed_capture_handle(fixture):
    f = fixture
    report = {}
    with capture(f, report) as owned:
        unsealed = snapshots.DiskSnapshots(
            owned.enrollment,
            owned.directory,
            owned.directory_identity,
            files=copy.deepcopy(owned.files),
            active=True,
        )
        before_calls = len(f.state["calls"])
        with pytest.raises(snapshots.SnapshotError, match="snapshot-not-admitted"):
            unsealed.path("root.qcow2", f.guest.enrollment)
        assert len(f.state["calls"]) == before_calls
        owned.verify()
    assert report["status"] == "passed" and report["temporary_resources_removed"]


def test_sealed_capture_cannot_be_readmitted_after_record_replacement(fixture):
    f = fixture
    report = {}
    with capture(f, report) as owned:
        original = copy.deepcopy(owned.files)
        with pytest.raises(snapshots.SnapshotError, match="snapshot-already-admitted"):
            owned.admit()
        owned.files["root.qcow2"] = owned.files["control.qcow2"]
        with pytest.raises(snapshots.SnapshotError, match="snapshot-already-admitted"):
            owned.admit()
        owned.files = original
        owned.verify()
    assert report["status"] == "passed" and report["temporary_resources_removed"]


@pytest.mark.parametrize("names", [[], ["root.qcow2"], [*images.DISK_BYTES, "extra.qcow2"]])
def test_incomplete_or_extra_capture_sets_are_not_admitted(fixture, names):
    f = fixture
    report = {}
    with capture(f, report) as owned:
        candidate = snapshots.DiskSnapshots(
            owned.enrollment,
            owned.directory,
            owned.directory_identity,
            files={name: owned.files.get(name, owned.files["root.qcow2"]) for name in names},
        )
        with pytest.raises(snapshots.SnapshotError, match="incomplete-snapshot"):
            candidate.admit()
        assert not candidate.active
        owned.verify()
    assert report["status"] == "passed" and report["temporary_resources_removed"]


def test_unrecorded_files_in_sealed_capture_are_refused_before_use(fixture):
    f = fixture
    report = {}
    with pytest.raises(snapshots.SnapshotError, match="unexpected-snapshot-input"):
        with capture(f, report) as owned:
            (owned.directory / "unrecorded").write_bytes(b"unrecorded-owned-file")
            before_calls = len(f.state["calls"])
            try:
                owned.path("root.qcow2", f.guest.enrollment)
            finally:
                assert len(f.state["calls"]) == before_calls
    assert report["status"] == "failed" and report["temporary_resources_removed"]
    assert valid_stats(report["statistics"]) and not list(f.temporary.iterdir())


def test_editing_report_cannot_authorize_changed_original_source_bytes(fixture):
    f = fixture
    report = {}
    with pytest.raises(
        snapshots.SnapshotError, match=r"source-changed|original-capture-evidence-changed"
    ):
        with capture(f, report):
            target = f.inputs / "root.qcow2"
            target.write_bytes(target.read_bytes() + b"unwitnessed-byte-drift")
            shown = report["phases"][0]["observation"]["disks"]["root.qcow2"]
            shown.update(bytes=target.stat().st_size, sha256=images.digest(target))
    assert report["status"] == "failed" and report["source_preserved"] is False
    assert report["temporary_resources_removed"] and valid_stats(report["statistics"])
