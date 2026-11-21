"""Ordinary-file static bootstrap mechanics with administrative enrollment replaced."""

import hashlib
import json
import os
import stat
import struct

import pytest

from scripts import bundle_install as installer

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/bundle_install.py"],
    "scope": "fixed complete source/notices closure, static ELF byte admission, sealing, refusal, interrupted preservation and linear byte work",
    "relationship": "no-product-claim",
    "reason": "Synthetic non-executed ELF data and replaced administrative ancestry exercise ordinary temporary files only. Real static invocation, loader exclusion, credentials, kernel permissions and native custody require independent enrolled-guest evidence.",
    "claims": [],
}


def elf(size=2048, change=None):
    raw = bytearray(b"\0" * size)
    raw[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIQQQIHHHHHH", raw, 16, 2, 62, 1, 0x400080, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", raw, 64, 1, 5, 0, 0x400000, 0, size, size, 4096)
    if change:
        change(raw)
    return bytes(raw)


def inputs(root, monkeypatch, size=2048, change=None):
    root.mkdir()
    values = {
        name: elf(size, change) if name == "busybox" else b"synthetic inert input\n" + b"a" * size
        for name, _, _ in installer.OWNER_BOOTSTRAP_INPUTS
    }
    for name, raw in values.items():
        (root / name).write_bytes(raw)
    monkeypatch.setattr(
        installer,
        "OWNER_BOOTSTRAP_INPUTS",
        tuple((name, len(raw), hashlib.sha256(raw).hexdigest()) for name, raw in values.items()),
    )
    return values


@pytest.fixture
def custody(tmp_path, monkeypatch):
    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)
    original = installer._directory_fd
    monkeypatch.setattr(installer, "_directory_fd", lambda path, **kwargs: original(path))
    monkeypatch.setattr("platform.machine", lambda: "x86_64")

    def enrolled(destination):
        assert destination.parent == parent
        return original(parent)

    monkeypatch.setattr(installer, "_protected_parent", enrolled)
    yield parent
    for directory, _, _ in os.walk(parent):
        os.chmod(directory, 0o700)


def snapshot(root):
    return {
        path.name: (path.stat().st_ino, stat.S_IMODE(path.stat().st_mode), path.read_bytes())
        for path in root.iterdir()
    }


def test_complete_approved_bytes_and_notices_are_retained_sealed_and_synced(
    tmp_path, custody, monkeypatch
):
    source = tmp_path / "inputs"
    values = inputs(source, monkeypatch)
    (source / "unselected").write_bytes(b"unrelated bytes")
    original = os.fsync
    synchronized = []

    def sync(descriptor):
        row = os.fstat(descriptor)
        synchronized.append((row.st_ino, stat.S_IMODE(row.st_mode)))
        original(descriptor)

    monkeypatch.setattr(os, "fsync", sync)
    destination = custody / "installed"
    executable = installer._install_owner_bootstrap(source, destination)
    assert executable == destination / "busybox"
    assert set(snapshot(destination)) == set(values)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o555
    assert (destination.stat().st_ino, 0o555) in synchronized
    assert (custody.stat().st_ino, 0o700) in synchronized
    for name, raw in values.items():
        path = destination / name
        mode = 0o555 if name == "busybox" else 0o444
        assert path.read_bytes() == raw
        assert path.stat().st_uid == os.geteuid() and stat.S_IMODE(path.stat().st_mode) == mode
        assert (path.stat().st_ino, mode) in synchronized
        (source / name).write_bytes(b"later source replacement")
        assert path.read_bytes() == raw
    assert (source / "unselected").read_bytes() == b"unrelated bytes"


@pytest.mark.parametrize("kind", ["directory", "file", "symlink"])
def test_existing_destination_and_unrelated_contents_are_preserved(
    tmp_path, custody, monkeypatch, kind
):
    source = tmp_path / "inputs"
    inputs(source, monkeypatch)
    retained = tmp_path / "retained"
    retained.mkdir()
    (retained / "canary").write_bytes(b"keep unrelated input")
    destination = custody / "existing"
    if kind == "directory":
        destination.mkdir()
        (destination / "canary").write_bytes(b"keep existing input")
    elif kind == "file":
        destination.write_bytes(b"keep existing input")
    else:
        destination.symlink_to(retained, target_is_directory=True)
    before = destination.lstat()
    with pytest.raises(FileExistsError):
        installer._install_owner_bootstrap(source, destination)
    assert destination.lstat() == before
    assert (retained / "canary").read_bytes() == b"keep unrelated input"
    if kind == "directory":
        assert (destination / "canary").read_bytes() == b"keep existing input"
    elif kind == "file":
        assert destination.read_bytes() == b"keep existing input"


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory"])
def test_special_sources_are_refused_without_following_or_blocking(
    tmp_path, custody, monkeypatch, kind
):
    source = tmp_path / "inputs"
    values = inputs(source, monkeypatch)
    path = source / "busybox"
    path.unlink()
    retained = tmp_path / "retained"
    retained.write_bytes(values["busybox"])
    if kind == "symlink":
        path.symlink_to(retained)
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        path.mkdir()
    with pytest.raises(ValueError, match="regular file"):
        installer._install_owner_bootstrap(source, custody / "failed")
    assert retained.read_bytes() == values["busybox"]
    assert stat.S_IMODE((custody / "failed").stat().st_mode) == 0o700


@pytest.mark.parametrize("name", [name for name, _, _ in installer.OWNER_BOOTSTRAP_INPUTS])
@pytest.mark.parametrize("change", ["short", "changed"])
def test_every_approved_input_identity_is_checked_before_elf_admission(
    tmp_path, custody, monkeypatch, name, change
):
    source = tmp_path / "inputs"
    values = inputs(source, monkeypatch)
    raw = values[name]
    (source / name).write_bytes(raw[:-1] if change == "short" else bytes([raw[0] ^ 1]) + raw[1:])

    def forbidden(*args):
        pytest.fail("untrusted complete input reached ELF admission")

    monkeypatch.setattr(installer, "_verify_owner_bootstrap_elf", forbidden)
    with pytest.raises(ValueError, match=r"size mismatch|untrusted"):
        installer._install_owner_bootstrap(source, custody / "failed")
    assert stat.S_IMODE((custody / "failed").stat().st_mode) == 0o700


@pytest.mark.parametrize(
    "field,offset,format,value",
    [
        ("magic", 0, "B", 0),
        ("class", 4, "B", 1),
        ("endian", 5, "B", 2),
        ("ident-version", 6, "B", 0),
        ("type", 16, "H", 3),
        ("machine", 18, "H", 183),
        ("version", 20, "I", 0),
        ("entry", 24, "Q", 0x800000),
        ("table-before-header", 32, "Q", 63),
        ("table-after-file", 32, "Q", 2040),
        ("header-size", 52, "H", 63),
        ("row-size", 54, "H", 55),
        ("row-count", 56, "H", 0),
        ("dynamic", 64, "I", 2),
        ("interpreter", 64, "I", 3),
        ("non-executable-entry", 68, "I", 4),
        ("segment-outside-file", 72, "Q", 2048),
        ("segment-larger-than-memory", 104, "Q", 1),
    ],
)
def test_static_elf_admission_rejects_dynamic_or_inconsistent_structure(
    tmp_path, custody, monkeypatch, field, offset, format, value
):
    source = tmp_path / "inputs"
    inputs(
        source, monkeypatch, change=lambda raw: struct.pack_into("<" + format, raw, offset, value)
    )
    with pytest.raises(ValueError, match="static bootstrap ELF"):
        installer._install_owner_bootstrap(source, custody / "failed")
    assert stat.S_IMODE((custody / "failed").stat().st_mode) == 0o700


def test_short_approved_bytes_cannot_bypass_static_elf_structure(tmp_path, custody, monkeypatch):
    source = tmp_path / "inputs"
    inputs(source, monkeypatch)
    (source / "busybox").write_bytes(b"synthetic bytes")
    monkeypatch.setattr(
        installer,
        "OWNER_BOOTSTRAP_INPUTS",
        tuple(
            (n, (source / n).stat().st_size, hashlib.sha256((source / n).read_bytes()).hexdigest())
            for n, _, _ in installer.OWNER_BOOTSTRAP_INPUTS
        ),
    )
    with pytest.raises(ValueError, match="ELF header"):
        installer._install_owner_bootstrap(source, custody / "failed")


@pytest.mark.parametrize("phase", ["copy", "elf", "seal", "parent-sync", "final-sync"])
def test_interrupted_candidate_stays_private_refused_and_preserved_across_fresh_retry(
    tmp_path, custody, monkeypatch, phase
):
    source = tmp_path / "inputs"
    values = inputs(source, monkeypatch)
    destination = custody / "interrupted"
    count = [0]
    copy = installer._copy_regular
    chmod = os.fchmod
    fsync = os.fsync

    def copy_then_interrupt(*args, **kwargs):
        copy(*args, **kwargs)
        count[0] += 1
        if count[0] == 3:
            raise OSError("controlled copy interruption")

    def interrupted(*args):
        raise OSError("controlled ELF interruption")

    def seal(descriptor, mode):
        if mode == 0o444:
            raise OSError("controlled sealing interruption")
        chmod(descriptor, mode)

    def sync(descriptor):
        info = os.fstat(descriptor)
        if phase == "parent-sync" and info.st_ino == custody.stat().st_ino:
            raise OSError("controlled parent sync interruption")
        if (
            phase == "final-sync"
            and info.st_ino == destination.stat().st_ino
            and stat.S_IMODE(info.st_mode) == 0o555
        ):
            raise OSError("controlled final sync interruption")
        fsync(descriptor)

    with monkeypatch.context() as patch:
        if phase == "copy":
            patch.setattr(installer, "_copy_regular", copy_then_interrupt)
        elif phase == "elf":
            patch.setattr(installer, "_verify_owner_bootstrap_elf", interrupted)
        elif phase == "seal":
            patch.setattr(os, "fchmod", seal)
        else:
            patch.setattr(os, "fsync", sync)
        with pytest.raises(OSError, match="interruption"):
            installer._install_owner_bootstrap(source, destination)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    before = snapshot(destination)
    with pytest.raises(FileExistsError):
        installer._install_owner_bootstrap(source, destination)
    retry = custody / "retry"
    assert installer._install_owner_bootstrap(source, retry) == retry / "busybox"
    assert snapshot(destination) == before and destination.stat().st_ino != retry.stat().st_ino
    assert {name: (retry / name).read_bytes() for name in values} == values


@pytest.mark.parametrize("gate", ["platform", "unprivileged", "architecture"])
def test_administrative_and_architecture_gates_refuse_before_candidate_creation(
    tmp_path, monkeypatch, gate
):
    destination = tmp_path / "unavailable"
    if gate == "platform":
        monkeypatch.setattr(installer.sys, "platform", "unsupported")
    elif gate == "unprivileged":
        monkeypatch.setattr(installer.os, "geteuid", lambda: 12345)
    else:
        monkeypatch.setattr(
            installer,
            "_protected_parent",
            lambda p: os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY),
        )
        monkeypatch.setattr("platform.machine", lambda: "aarch64")
    with pytest.raises(ValueError, match=r"custody|architecture"):
        installer._install_owner_bootstrap(tmp_path / "not-read", destination)
    assert not destination.exists()


def test_complete_copy_hash_static_validation_and_sealing_work_is_linear(
    tmp_path, custody, monkeypatch
):
    original_read, original_write, original_hash = os.read, os.write, hashlib.sha256
    work = [0]

    def read(*args):
        raw = original_read(*args)
        work[0] += len(raw)
        return raw

    def write(descriptor, data):
        value = original_write(descriptor, data)
        work[0] += value
        return value

    class Digest:
        def __init__(self):
            self.actual = original_hash()

        def update(self, raw):
            work[0] += len(raw)
            self.actual.update(raw)

        def hexdigest(self):
            return self.actual.hexdigest()

    samples = []
    for size in (16_384, 65_536, 262_144):
        source = tmp_path / str(size)
        values = inputs(source, monkeypatch, size=size)
        work[0] = 0
        with monkeypatch.context() as patch:
            patch.setattr(os, "read", read)
            patch.setattr(os, "write", write)
            patch.setattr(hashlib, "sha256", Digest)
            installed = installer._install_owner_bootstrap(source, custody / str(size))
        assert installed.is_file()
        assert {name: (installed.parent / name).read_bytes() for name in values} == values
        samples.append(
            {"complete_input_bytes": sum(map(len, values.values())), "work_bytes": work[0]}
        )
    (tmp_path / "static-bootstrap-work.json").write_text(json.dumps(samples, indent=2) + "\n")
    first = samples[0]
    assert all(
        row["work_bytes"] * first["complete_input_bytes"]
        <= 1.05 * first["work_bytes"] * row["complete_input_bytes"]
        for row in samples[1:]
    ), samples
