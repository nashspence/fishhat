"""Complete input-copy behavior; native custody requires the disposable profile."""

import errno
import hashlib
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import bundle_install
from tests.test_bundle_install import bundle_fixture, seal

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/bundle_install.py"],
    "scope": "complete protected-staging copy, input rejection and measured copy/hash/path work",
    "relationship": "no-product-claim",
    "reason": "Temporary-file tests replace only administrative parent enrollment. They exercise real descriptor-relative copies and hash verification, including substitutions, mutations and short writes. They do not establish native ownership or installed-owner authority.",
    "claims": [],
}


@pytest.fixture
def custody(tmp_path, monkeypatch):
    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)

    def enrolled_parent(destination):
        assert destination.parent == parent
        return os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    monkeypatch.setattr(bundle_install, "_protected_parent", enrolled_parent)
    return parent


def source_bundle(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    return source, bundle_fixture(source)


def test_staged_inputs_remain_exact_after_caller_mutates_original(tmp_path, custody):
    source, expected = source_bundle(tmp_path)
    before = {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    destination = custody / "verified"
    assert bundle_install._stage_verified(source, destination, expected) == destination
    (source / "locks/fixture.txt").write_text("caller replacement")
    (source / "wheels/fixture.whl").write_bytes(b"caller replacement")
    assert {
        p.relative_to(destination): p.read_bytes() for p in destination.rglob("*") if p.is_file()
    } == before
    assert bundle_install.verify(destination, expected)["production_qualified"] is False
    assert all(p.stat().st_mode & 0o077 == 0 for p in destination.rglob("*"))


@pytest.mark.parametrize("kind", ["file", "directory", "bundle-root"])
def test_staging_rejects_source_symlink_substitution(tmp_path, custody, kind):
    source, expected = source_bundle(tmp_path)
    if kind == "bundle-root":
        alias = tmp_path / "alias"
        alias.symlink_to(source, target_is_directory=True)
        with pytest.raises(OSError) as failure:
            bundle_install._stage_verified(alias, custody / "verified", expected)
        assert failure.value.errno in (errno.ELOOP, errno.ENOTDIR)
    else:
        target = source / ("wheels/fixture.whl" if kind == "file" else "wheels")
        moved = tmp_path / "retained"
        target.rename(moved)
        target.symlink_to(moved, target_is_directory=kind == "directory")
        with pytest.raises(ValueError, match="symbolic link"):
            bundle_install._stage_verified(source, custody / "verified", expected)
        assert moved.exists()


@pytest.mark.parametrize(
    "name",
    [pytest.param("foreign:name", id="colon"), pytest.param("foreign\\name", id="backslash")],
)
def test_staging_rejects_unsafe_source_names(tmp_path, custody, name):
    source, expected = source_bundle(tmp_path)
    (source / name).write_bytes(b"unclassified")
    with pytest.raises(ValueError, match="unsafe staging source name"):
        bundle_install._stage_verified(source, custody / "verified", expected)


@pytest.mark.parametrize("kind", ["directory", "file", "symlink"])
def test_staging_never_adopts_or_erases_existing_destination(tmp_path, custody, kind):
    source, expected = source_bundle(tmp_path)
    canary = tmp_path / "unrelated"
    canary.mkdir()
    (canary / "keep").write_bytes(b"unrelated bytes")
    destination = custody / "verified"
    if kind == "directory":
        destination.mkdir()
        (destination / "keep").write_bytes(b"retained bytes")
    elif kind == "file":
        destination.write_bytes(b"retained bytes")
    else:
        destination.symlink_to(canary, target_is_directory=True)
    with pytest.raises(FileExistsError):
        bundle_install._stage_verified(source, destination, expected)
    assert (canary / "keep").read_bytes() == b"unrelated bytes"
    if kind == "directory":
        assert (destination / "keep").read_bytes() == b"retained bytes"
    elif kind == "file":
        assert destination.read_bytes() == b"retained bytes"
    else:
        assert destination.is_symlink()


def test_untrusted_staged_manifest_never_invokes_installer(tmp_path, custody, monkeypatch):
    source, _ = source_bundle(tmp_path)

    def forbidden(*args, **kwargs):
        pytest.fail("candidate execution before verified input custody")

    monkeypatch.setattr(bundle_install, "subprocess", SimpleNamespace(run=forbidden))
    destination = custody / "incomplete"
    with pytest.raises(ValueError, match="manifest"):
        bundle_install._stage_verified(source, destination, "0" * 64)
    assert destination.is_dir()
    with pytest.raises(FileExistsError):
        bundle_install._stage_verified(source, destination, "0" * 64)


def test_staging_detects_source_truncation_during_copy(tmp_path, custody, monkeypatch):
    source, expected = source_bundle(tmp_path)
    target = source / "wheels/fixture.whl"
    inode = target.stat().st_ino
    real_read = os.read
    changed = False

    def read(descriptor, size):
        nonlocal changed
        if not changed and os.fstat(descriptor).st_ino == inode:
            changed = True
            target.write_bytes(b"")
        return real_read(descriptor, size)

    monkeypatch.setattr(bundle_install, "os", SimpleNamespace(**{**vars(os), "read": read}))
    with pytest.raises(ValueError, match="source changed"):
        bundle_install._stage_verified(source, custody / "incomplete", expected)
    assert changed


def test_protected_parent_refuses_nonadministrative_context(tmp_path, monkeypatch):
    monkeypatch.setattr(bundle_install, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(bundle_install, "os", SimpleNamespace(geteuid=lambda: 1000))
    with pytest.raises(ValueError, match="administrative custody"):
        bundle_install._protected_parent(tmp_path / "unavailable")
    assert not (tmp_path / "unavailable").exists()


def test_protected_directory_refuses_untrusted_temporary_ancestry(tmp_path):
    with pytest.raises((ValueError, OSError)):
        bundle_install._directory_fd(tmp_path, protected=True)


def test_complete_staging_copy_hash_and_path_work_is_linear(tmp_path, custody, monkeypatch):
    real_open, real_read, real_sha = os.open, os.read, bundle_install.sha256
    work = [0]

    def opened(path, *args, **kwargs):
        work[0] += len(os.fsencode(path))
        return real_open(path, *args, **kwargs)

    def read(descriptor, size):
        data = real_read(descriptor, size)
        work[0] += len(data)
        return data

    def digest(path):
        hashed = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1_048_576):
                work[0] += len(chunk)
                hashed.update(chunk)
        return hashed.hexdigest()

    samples = []
    for count in (64, 256, 1024):
        source = tmp_path / f"source-{count:04d}"
        source.mkdir()
        expected = bundle_fixture(source)
        manifest = bundle_install.verify(source, expected)
        for index in range(count):
            name = "wheels/" + "shared-prefix-" * 4 + f"{index:08d}.whl"
            path = source / name
            path.write_bytes(b"public synthetic artifact" * 4)
            manifest["files"][name] = {"size": path.stat().st_size, "sha256": real_sha(path)}
        expected = seal(source, manifest)
        logical = sum(
            p.stat().st_size + len(os.fsencode(p.relative_to(source)))
            for p in source.rglob("*")
            if p.is_file()
        )
        work[0] = 0
        with monkeypatch.context() as patch:
            patch.setattr(
                bundle_install, "os", SimpleNamespace(**{**vars(os), "open": opened, "read": read})
            )
            patch.setattr(bundle_install, "sha256", digest)
            staged = bundle_install._stage_verified(
                source, custody / f"staged-{count:04d}", expected
            )
        assert len(bundle_install.verify(staged, expected)["files"]) == count + 2
        final = staged / ("wheels/" + "shared-prefix-" * 4 + f"{count - 1:08d}.whl")
        final.write_bytes(b"changed final artifact")
        with pytest.raises(ValueError, match="artifact changed"):
            bundle_install.verify(staged, expected)
        samples.append({"files": count + 2, "input_bytes_and_names": logical, "work": work[0]})
    (tmp_path / "staging-work.json").write_text(json.dumps(samples, indent=2) + "\n")
    first = samples[0]
    for sample in samples[1:]:
        assert (
            sample["work"] * first["input_bytes_and_names"]
            <= 1.05 * first["work"] * sample["input_bytes_and_names"]
        ), samples


def test_short_writes_preserve_bytes_without_quadratic_copying(tmp_path, monkeypatch):
    real_read, real_write = os.read, os.write
    work = [0]

    class MeasuredBytes(bytes):
        def __getitem__(self, selection):
            result = super().__getitem__(selection)
            if isinstance(selection, slice):
                work[0] += len(result)
            return result

    def read(descriptor, size):
        result = real_read(descriptor, size)
        work[0] += len(result)
        return MeasuredBytes(result)

    def write(descriptor, data):
        result = real_write(descriptor, memoryview(data)[:1])
        work[0] += result
        return result

    source = tmp_path / "source"
    source.write_bytes(b"x" * 65536)
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    samples = []
    try:
        for size in (4096, 16384, 65536):
            source.write_bytes(b"x" * size)
            work[0] = 0
            destination = tmp_path / f"copied-{size}"
            with monkeypatch.context() as patch:
                patch.setattr(
                    bundle_install,
                    "os",
                    SimpleNamespace(**{**vars(os), "read": read, "write": write}),
                )
                bundle_install._copy_regular(parent, "source", destination)
            assert destination.read_bytes() == source.read_bytes()
            samples.append({"bytes": size, "copy_work": work[0]})
    finally:
        os.close(parent)
    (tmp_path / "short-write-work.json").write_text(json.dumps(samples, indent=2) + "\n")
    first = samples[0]
    for sample in samples[1:]:
        assert (
            sample["copy_work"] * first["bytes"] <= 1.05 * first["copy_work"] * sample["bytes"]
        ), samples


@pytest.mark.parametrize(
    "mode", [pytest.param(stat.S_IFIFO, id="fifo"), pytest.param(stat.S_IFCHR, id="device")]
)
def test_special_inode_is_rejected_before_opening_for_read(tmp_path, monkeypatch, mode):
    source = tmp_path / "input"
    source.write_bytes(b"public fixture")
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    real_open = os.open
    reads = []

    def opened(path, *args, **kwargs):
        if isinstance(path, str) and path.startswith("/proc/self/fd/"):
            reads.append(path)
            pytest.fail("special inode opened for I/O")
        return real_open(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(
            bundle_install,
            "os",
            SimpleNamespace(
                **{**vars(os), "open": opened, "fstat": lambda fd: SimpleNamespace(st_mode=mode)}
            ),
        )
        try:
            with pytest.raises(ValueError, match="not a regular file"):
                bundle_install._copy_regular(parent, "input", tmp_path / "unavailable")
        finally:
            os.close(parent)
    assert reads == [] and not (tmp_path / "unavailable").exists()


@pytest.mark.parametrize("relative", ["nested", "outer/nested"], ids=["direct", "deeper"])
def test_staging_refuses_to_consume_its_own_output(tmp_path, monkeypatch, relative):
    source, expected = source_bundle(tmp_path)
    destination = source / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    before = {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    monkeypatch.setattr(
        bundle_install,
        "_protected_parent",
        lambda target: os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW),
    )
    with pytest.raises(ValueError, match="source contains destination"):
        bundle_install._stage_verified(source, destination, expected)
    assert not destination.exists()
    assert {
        p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()
    } == before


def test_nested_copy_uses_linear_relative_path_work_and_constant_descriptors(tmp_path, monkeypatch):
    real_open, real_close, real_dup, real_read = os.open, os.close, os.dup, os.read
    work, descriptors, peak = [0], [0], [0]

    def opened(path, *args, **kwargs):
        work[0] += len(os.fsencode(path))
        descriptor = real_open(path, *args, **kwargs)
        descriptors[0] += 1
        peak[0] = max(peak[0], descriptors[0])
        return descriptor

    def duplicate(descriptor):
        result = real_dup(descriptor)
        descriptors[0] += 1
        peak[0] = max(peak[0], descriptors[0])
        return result

    def closed(descriptor):
        real_close(descriptor)
        descriptors[0] -= 1

    def read(descriptor, size):
        result = real_read(descriptor, size)
        work[0] += len(result)
        return result

    samples = []
    for depth in (8, 32, 128):
        source, destination = tmp_path / f"source-{depth}", tmp_path / f"target-{depth}"
        source.mkdir()
        destination.mkdir()
        relative = Path(*(["d"] * depth), "item.whl")
        item = source / relative
        item.parent.mkdir(parents=True)
        item.write_bytes(b"x" * (16 * depth))
        source_fd = real_open(source, os.O_RDONLY | os.O_DIRECTORY)
        target_fd = real_open(destination, os.O_RDONLY | os.O_DIRECTORY)
        work[0] = descriptors[0] = peak[0] = 0
        try:
            with monkeypatch.context() as patch:
                patch.setattr(
                    bundle_install,
                    "os",
                    SimpleNamespace(
                        **{
                            **vars(os),
                            "open": opened,
                            "dup": duplicate,
                            "close": closed,
                            "read": read,
                        }
                    ),
                )
                bundle_install._copy_tree(source_fd, target_fd)
        finally:
            real_close(source_fd)
            real_close(target_fd)
        assert (destination / relative).read_bytes() == item.read_bytes()
        assert descriptors[0] == 0 and peak[0] <= 5
        samples.append(
            {
                "depth": depth,
                "logical_bytes_and_names": 16 * depth + depth + len(os.fsencode(relative)),
                "work": work[0],
                "peak_owned_descriptors": peak[0],
            }
        )
    (tmp_path / "nested-copy-work.json").write_text(json.dumps(samples, indent=2) + "\n")
    first = samples[0]
    for sample in samples[1:]:
        assert (
            sample["work"] * first["logical_bytes_and_names"]
            <= 1.05 * first["work"] * sample["logical_bytes_and_names"]
        ), samples


def test_complete_staging_metadata_work_stays_linear_at_increasing_depth(
    tmp_path, custody, monkeypatch
):
    real_open, real_stat, real_lstat, real_scandir, real_read = (
        os.open,
        os.stat,
        os.lstat,
        os.scandir,
        os.read,
    )
    work = [0]

    def counted(function):
        def call(path, *args, **kwargs):
            work[0] += 1 if isinstance(path, int) else len(os.fsencode(path))
            return function(path, *args, **kwargs)

        return call

    def read(descriptor, size):
        result = real_read(descriptor, size)
        work[0] += len(result)
        return result

    samples = []
    for depth in (8, 32, 128, 384):
        source = tmp_path / f"metadata-source-{depth}"
        source.mkdir()
        expected = bundle_fixture(source)
        manifest = bundle_install.verify(source, expected)
        name = "/".join(["data", *(["d"] * depth), "item.whl"])
        path = source / name
        path.parent.mkdir(parents=True)
        path.write_bytes(b"x" * (16 * depth))
        manifest["files"][name] = {
            "size": path.stat().st_size,
            "sha256": bundle_install.sha256(path),
        }
        expected = seal(source, manifest)
        files = [path for path in source.rglob("*") if path.is_file()]
        logical = (
            sum(path.stat().st_size + len(os.fsencode(path.relative_to(source))) for path in files)
            + depth
        )
        work[0] = 0
        destination = custody / f"metadata-staged-{depth}"
        with monkeypatch.context() as patch:
            patch.setattr(os, "open", counted(real_open))
            patch.setattr(os, "stat", counted(real_stat))
            patch.setattr(os, "lstat", counted(real_lstat))
            patch.setattr(os, "scandir", counted(real_scandir))
            patch.setattr(os, "read", read)
            bundle_install._stage_verified(source, destination, expected)
        assert (destination / name).read_bytes() == path.read_bytes()
        samples.append(
            {"depth": depth, "input_bytes_and_names": logical, "copy_hash_metadata_work": work[0]}
        )
    (tmp_path / "complete-metadata-work.json").write_text(json.dumps(samples, indent=2) + "\n")
    first = samples[0]
    for sample in samples[1:]:
        assert (
            sample["copy_hash_metadata_work"] * first["input_bytes_and_names"]
            <= 1.05 * first["copy_hash_metadata_work"] * sample["input_bytes_and_names"]
        ), samples
