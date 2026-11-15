"""Ordinary-file installation mechanics; administrative authority is replaced."""

import hashlib
import io
import json
import os
import stat
import tarfile

import pytest

from scripts import bundle_install as installer

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/bundle_install.py"],
    "scope": "complete selected-archive copy, extraction, sealing, refusal and linear namespace work",
    "relationship": "no-product-claim",
    "reason": "Synthetic archives and replaced administrative parent enrollment exercise ordinary temporary files only. No interpreter, package installer, guest, credentials or privileged operation runs; the real pinned artifact and permissions require the separately enrolled native witness.",
    "claims": [],
}


def archive(path, count=1, *, link="python/bin/python", target="python3.12", kind=None):
    with tarfile.open(path, "w:gz") as output:
        for name, raw, mode in [
            ("python/bin/python3.12", b"synthetic non-executed binary", 0o775),
            *[
                (f"python/lib/module-{index}.py", b"synthetic input" * 8, 0o664)
                for index in range(count)
            ],
        ]:
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(raw), mode
            output.addfile(member, io.BytesIO(raw))
        member = tarfile.TarInfo(link)
        member.type, member.linkname = kind or tarfile.SYMTYPE, target
        output.addfile(member)
    return path.read_bytes()


@pytest.fixture
def custody(tmp_path, monkeypatch):
    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)

    def enrolled(destination):
        assert destination.parent == parent
        return os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    monkeypatch.setattr(installer, "_protected_parent", enrolled)
    yield parent
    # Restore write access only to these synthetic temporary directories so the
    # ordinary test user can reclaim them; this is not native cleanup evidence.
    for directory, _, _ in os.walk(parent):
        os.chmod(directory, 0o700)


def approve(monkeypatch, raw):
    monkeypatch.setattr(installer, "OWNER_PYTHON_BYTES", len(raw))
    monkeypatch.setattr(installer, "OWNER_PYTHON_SHA256", hashlib.sha256(raw).hexdigest())


def test_exact_archive_is_retained_and_complete_tree_sealed(tmp_path, custody, monkeypatch):
    source = tmp_path / "source.tar.gz"
    raw = archive(source, count=17)
    approve(monkeypatch, raw)
    destination = custody / "installed"
    executable = installer._install_owner_python(source, destination)
    assert executable == destination / "python/bin/python3.12"
    assert (destination / "runtime.tar.gz").read_bytes() == raw
    assert executable.read_bytes() == b"synthetic non-executed binary"
    assert (destination / "python/bin/python").is_symlink()
    assert (destination / "python/bin/python").resolve() == executable
    assert len(list((destination / "python/lib").glob("*.py"))) == 17
    assert stat.S_IMODE(destination.stat().st_mode) == 0o555
    assert stat.S_IMODE((destination / "runtime.tar.gz").stat().st_mode) == 0o400
    for path in (destination / "python").rglob("*"):
        if not path.is_symlink():
            expected = 0o555 if path.is_dir() or path == executable else 0o444
            assert stat.S_IMODE(path.stat().st_mode) == expected
    source.write_bytes(b"changed original input")
    assert (destination / "runtime.tar.gz").read_bytes() == raw


@pytest.mark.parametrize("kind", ["file", "directory", "symlink"])
def test_existing_destination_is_never_adopted_or_erased(tmp_path, custody, monkeypatch, kind):
    source = tmp_path / "source.tar.gz"
    approve(monkeypatch, archive(source))
    retained = tmp_path / "retained"
    retained.mkdir()
    canary = retained / "canary"
    canary.write_bytes(b"retained unrelated bytes")
    destination = custody / "installed"
    if kind == "file":
        destination.write_bytes(b"existing installation bytes")
    elif kind == "directory":
        destination.mkdir()
        (destination / "keep").write_bytes(b"existing installation bytes")
    else:
        destination.symlink_to(retained, target_is_directory=True)
    before = destination.lstat()
    with pytest.raises(FileExistsError):
        installer._install_owner_python(source, destination)
    assert destination.lstat() == before
    assert canary.read_bytes() == b"retained unrelated bytes"


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory"])
def test_source_substitutions_never_extract_or_execute(tmp_path, custody, monkeypatch, kind):
    retained = tmp_path / "retained.tar.gz"
    approve(monkeypatch, archive(retained))
    source = tmp_path / "source"
    if kind == "symlink":
        source.symlink_to(retained)
    elif kind == "fifo":
        os.mkfifo(source)
    else:
        source.mkdir()
    with pytest.raises(ValueError, match="regular file"):
        installer._install_owner_python(source, custody / "installed")
    assert not (custody / "installed/python").exists()
    assert retained.is_file()


@pytest.mark.parametrize("kind", ["truncated", "changed"])
def test_archive_identity_is_checked_before_extraction(tmp_path, custody, monkeypatch, kind):
    source = tmp_path / "source.tar.gz"
    raw = archive(source)
    approve(monkeypatch, raw)
    source.write_bytes(raw[:-1] if kind == "truncated" else bytes([raw[0] ^ 1]) + raw[1:])

    def forbidden(*args, **kwargs):
        pytest.fail("unverified archive reached extraction")

    monkeypatch.setattr(tarfile, "open", forbidden)
    destination = custody / "installed"
    with pytest.raises(ValueError, match=r"size mismatch|untrusted"):
        installer._install_owner_python(source, destination)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert not (destination / "python").exists()


def test_failed_extraction_stays_private_and_fresh_retry_preserves_attempt(
    tmp_path, custody, monkeypatch
):
    source = tmp_path / "source.tar.gz"
    raw = archive(source)
    approve(monkeypatch, raw)
    original = tarfile.open

    def interrupted(*args, **kwargs):
        raise OSError("controlled extraction interruption")

    failed = custody / "failed"
    with monkeypatch.context() as patch:
        patch.setattr(tarfile, "open", interrupted)
        with pytest.raises(OSError, match="interruption"):
            installer._install_owner_python(source, failed)
    assert stat.S_IMODE(failed.stat().st_mode) == 0o700
    assert (failed / "runtime.tar.gz").read_bytes() == raw
    assert not (failed / "python").exists()
    assert tarfile.open is original
    with pytest.raises(FileExistsError):
        installer._install_owner_python(source, failed)
    assert installer._install_owner_python(source, custody / "retry").is_file()
    assert (failed / "runtime.tar.gz").read_bytes() == raw


@pytest.mark.parametrize("kind", ["escape", "special"])
def test_extraction_retains_data_filter_defense(tmp_path, custody, monkeypatch, kind):
    source = tmp_path / "source.tar.gz"
    raw = archive(
        source,
        link="python/unsafe",
        target="../../outside",
        kind=tarfile.FIFOTYPE if kind == "special" else None,
    )
    approve(monkeypatch, raw)
    outside = tmp_path / "outside"
    outside.write_bytes(b"unrelated canary")
    with pytest.raises(tarfile.FilterError):
        installer._install_owner_python(source, custody / "installed")
    assert outside.read_bytes() == b"unrelated canary"
    assert stat.S_IMODE((custody / "installed").stat().st_mode) == 0o700


def test_unsupported_architecture_creates_no_candidate(tmp_path, custody, monkeypatch):
    source = tmp_path / "source.tar.gz"
    source.write_bytes(b"not read")
    monkeypatch.setattr("platform.machine", lambda: "aarch64")
    with pytest.raises(ValueError, match="architecture"):
        installer._install_owner_python(source, custody / "installed")
    assert not (custody / "installed").exists()


def test_complete_runtime_copy_extraction_and_sealing_work_is_linear(
    tmp_path, custody, monkeypatch
):
    work = [0]
    originals = {name: getattr(os, name) for name in ("open", "stat", "lstat", "read", "write")}

    def path_call(name):
        def observed(path, *args, **kwargs):
            work[0] += 1 if isinstance(path, int) else len(os.fsencode(path))
            return originals[name](path, *args, **kwargs)

        return observed

    def read(*args):
        result = originals["read"](*args)
        work[0] += len(result)
        return result

    def write(descriptor, data):
        result = originals["write"](descriptor, data)
        work[0] += result
        return result

    samples = []
    for count in (32, 128, 512):
        source = tmp_path / f"source-{count}.tar.gz"
        raw = archive(source, count=count)
        approve(monkeypatch, raw)
        work[0] = 0
        with monkeypatch.context() as patch:
            for name in ("open", "stat", "lstat"):
                patch.setattr(os, name, path_call(name))
            patch.setattr(os, "read", read)
            patch.setattr(os, "write", write)
            executable = installer._install_owner_python(source, custody / f"installed-{count}")
        assert len(list(executable.parent.parent.joinpath("lib").glob("*.py"))) == count
        logical = sum(len(member.name.encode()) + member.size for member in tarfile.open(source))
        samples.append({"files": count + 1, "input_bytes_and_names": logical, "work": work[0]})
    (tmp_path / "runtime-install-work.json").write_text(json.dumps(samples, indent=2) + "\n")
    first = samples[0]
    assert all(
        row["work"] * first["input_bytes_and_names"]
        <= 1.05 * first["work"] * row["input_bytes_and_names"]
        for row in samples[1:]
    ), samples
