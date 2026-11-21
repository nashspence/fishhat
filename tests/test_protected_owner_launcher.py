"""Ordinary-file launch materialization with administrative metadata replaced."""

import hashlib
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import bundle_install as installer
from scripts import owner_launcher as launcher
from tests.test_owner_launcher import elf

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/bundle_install.py"],
    "scope": "complete fixed launch bytes, target binding, ordinary-file sealing/refusal and interrupted preservation with administrative ancestry and uid metadata replaced",
    "relationship": "no-product-claim",
    "reason": "Temporary files and replaced root observations exercise copying only. Actual administrative/peer access, credentials and executable launch require independent hosted-guest witnesses.",
    "claims": [],
}

NAMES = {"launch", "launch.c", "targets.h", "launcher.json"}


@pytest.fixture
def custody(tmp_path, monkeypatch):
    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)
    original_directory = installer._directory_fd
    original_regular = installer._regular_source
    original_stat = os.stat
    monkeypatch.setattr(installer, "_directory_fd", lambda path, **kwargs: original_directory(path))

    def protected(destination):
        assert destination.parent == parent
        return original_directory(parent)

    def root_metadata(value):
        fields = {
            name: getattr(value, name)
            for name in (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
                "st_gid",
            )
        }
        return SimpleNamespace(**fields, st_uid=0)

    def regular(*args):
        descriptor, value = original_regular(*args)
        return descriptor, root_metadata(value)

    def metadata(path, *args, **kwargs):
        value = original_stat(path, *args, **kwargs)
        return root_metadata(value) if kwargs.get("dir_fd") is not None and path in NAMES else value

    monkeypatch.setattr(installer, "_protected_parent", protected)
    monkeypatch.setattr(installer, "_regular_source", regular)
    monkeypatch.setattr(installer.os, "stat", metadata)
    monkeypatch.setattr("platform.machine", lambda: "x86_64")
    yield parent
    for directory, _, _ in os.walk(parent):
        os.chmod(directory, 0o700)


def inputs(tmp_path):
    source = tmp_path / "inputs"
    source.mkdir(mode=0o700)
    interpreter = tmp_path / "selected-python"
    program = tmp_path / "selected-program.py"
    interpreter.write_bytes(b"inert interpreter bytes\n")
    interpreter.chmod(0o555)
    program.write_bytes(b"inert program bytes\n")
    program.chmod(0o444)
    targets = {
        name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for name, path in (("interpreter", interpreter), ("program", program))
    }
    values = {
        "launch": elf(),
        "launch.c": launcher.SOURCE.read_bytes(),
        "targets.h": launcher.target_header(str(interpreter), str(program)),
    }
    manifest = {
        "format": "fishhat-owner-launcher/v1",
        **targets,
        "files": {
            name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            for name, raw in values.items()
        },
        "build": {"output_executed": False},
    }
    values["launcher.json"] = launcher.canonical(manifest)
    for name, raw in values.items():
        path = source / name
        path.write_bytes(raw)
        path.chmod(0o600)
    return source, hashlib.sha256(values["launcher.json"]).hexdigest(), values, targets


def snapshot(root):
    return {
        p.name: (p.stat().st_ino, stat.S_IMODE(p.stat().st_mode), p.read_bytes())
        for p in root.iterdir()
    }


def test_complete_original_inputs_sealed_with_no_program_execution(tmp_path, custody, monkeypatch):
    source, expected, values, _ = inputs(tmp_path)
    before = snapshot(source)
    synchronized = []
    original_sync = os.fsync

    def sync(descriptor):
        value = os.fstat(descriptor)
        synchronized.append((value.st_ino, stat.S_IMODE(value.st_mode)))
        original_sync(descriptor)

    monkeypatch.setattr(os, "fsync", sync)
    destination = custody / "installed"
    assert (
        installer._install_owner_launcher(source, destination, expected) == destination / "launch"
    )
    assert {p.name: p.read_bytes() for p in destination.iterdir()} == values
    assert snapshot(source) == before
    assert stat.S_IMODE(destination.stat().st_mode) == 0o555
    assert (destination.stat().st_ino, 0o555) in synchronized
    for name in NAMES:
        assert stat.S_IMODE((destination / name).stat().st_mode) == (
            0o555 if name == "launch" else 0o444
        )
    sealed = snapshot(destination)
    with pytest.raises(FileExistsError):
        installer._install_owner_launcher(source, destination, expected)
    assert snapshot(destination) == sealed


@pytest.mark.parametrize(
    "case",
    [
        "manifest",
        "code",
        "target",
        "target-mode",
        "target-alias",
        "unclassified",
        "source-alias",
        "source-hardlink",
        "source-writable",
    ],
)
def test_unsafe_or_changed_inputs_refused_and_not_adopted(tmp_path, custody, case):
    source, expected, _, targets = inputs(tmp_path)
    if case == "manifest":
        expected = "0" * 64
    elif case == "code":
        (source / "launch.c").write_bytes(b"changed code")
    elif case == "target":
        path = Path(targets["program"]["path"])
        path.chmod(0o600)
        path.write_bytes(b"changed target")
        path.chmod(0o444)
    elif case == "target-mode":
        Path(targets["program"]["path"]).chmod(0o666)
    elif case == "target-alias":
        path = Path(targets["program"]["path"])
        path.rename(tmp_path / "original-program")
        path.symlink_to(tmp_path / "original-program")
    elif case == "unclassified":
        (source / "unexpected").write_bytes(b"unselected")
    elif case == "source-alias":
        (source / "launch.c").unlink()
        (source / "launch.c").symlink_to(launcher.SOURCE)
    elif case == "source-hardlink":
        os.link(source / "launch.c", tmp_path / "second-link")
    else:
        (source / "launch.c").chmod(0o666)
    destination = custody / "refused"
    with pytest.raises((ValueError, OSError)):
        installer._install_owner_launcher(source, destination, expected)
    if destination.exists():
        assert stat.S_IMODE(destination.stat().st_mode) == 0o700
        before = snapshot(destination)
        with pytest.raises(FileExistsError):
            installer._install_owner_launcher(source, destination, expected)
        assert snapshot(destination) == before


def test_interrupted_private_candidate_preserved_and_fresh_retry_disjoint(
    tmp_path, custody, monkeypatch
):
    source, expected, values, _ = inputs(tmp_path)
    original = installer._verify_owner_launcher_elf

    def interrupt(path):
        raise RuntimeError("synthetic interruption")

    monkeypatch.setattr(installer, "_verify_owner_launcher_elf", interrupt)
    destination = custody / "interrupted"
    with pytest.raises(RuntimeError, match="interruption"):
        installer._install_owner_launcher(source, destination, expected)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    before = snapshot(destination)
    monkeypatch.setattr(installer, "_verify_owner_launcher_elf", original)
    with pytest.raises(FileExistsError):
        installer._install_owner_launcher(source, destination, expected)
    retry = custody / "retry"
    assert installer._install_owner_launcher(source, retry, expected) == retry / "launch"
    assert snapshot(destination) == before
    assert {p.name: p.read_bytes() for p in retry.iterdir()} == values
    assert destination.stat().st_ino != retry.stat().st_ino
    assert {x[0] for x in before.values()}.isdisjoint(p.stat().st_ino for p in retry.iterdir())


@pytest.mark.parametrize(
    "item",
    [
        None,
        {},
        {"bytes": True, "sha256": "a" * 64},
        {"bytes": -1, "sha256": "a" * 64},
        {"bytes": 1, "sha256": "bad"},
        {"bytes": 1, "sha256": "a" * 64, "extra": True},
    ],
)
def test_malformed_file_identities_fail_closed(item):
    with pytest.raises(ValueError):
        installer._owner_launcher_file(item)


def test_complete_copy_hash_and_seal_work_remains_linear_across_byte_extents(
    tmp_path, custody, monkeypatch
):
    original_read, original_write, original_hash = os.read, os.write, hashlib.sha256
    work = [0]

    def read(*args):
        raw = original_read(*args)
        work[0] += len(raw)
        return raw

    def write(descriptor, raw):
        count = original_write(descriptor, raw)
        work[0] += count
        return count

    class Digest:
        def __init__(self, raw=b""):
            self.actual = original_hash()
            self.update(raw)

        def update(self, raw):
            work[0] += len(raw)
            self.actual.update(raw)

        def hexdigest(self):
            return self.actual.hexdigest()

    def file_digest(stream, name):
        assert name == "sha256"
        digest = Digest()
        while chunk := stream.read(65536):
            digest.update(chunk)
        return digest

    samples = []
    for size in (16384, 65536, 262144):
        temporary = tmp_path / str(size)
        temporary.mkdir()
        source, _, values, _ = inputs(temporary)
        values["launch"] += b"\0" * (size - len(values["launch"]))
        values["launch.c"] = b"/*" + b"a" * size + b"*/\n"
        manifest = json.loads(values["launcher.json"])
        for name in ("launch", "launch.c"):
            manifest["files"][name] = {
                "bytes": len(values[name]),
                "sha256": original_hash(values[name]).hexdigest(),
            }
            (source / name).write_bytes(values[name])
        values["launcher.json"] = launcher.canonical(manifest)
        (source / "launcher.json").write_bytes(values["launcher.json"])
        expected = original_hash(values["launcher.json"]).hexdigest()
        work[0] = 0
        with monkeypatch.context() as patch:
            patch.setattr(os, "read", read)
            patch.setattr(os, "write", write)
            patch.setattr(hashlib, "sha256", Digest)
            patch.setattr(hashlib, "file_digest", file_digest)
            executable = installer._install_owner_launcher(source, custody / str(size), expected)
        assert {p.name: p.read_bytes() for p in executable.parent.iterdir()} == values
        samples.append(
            {"complete_input_bytes": sum(map(len, values.values())), "work_bytes": work[0]}
        )
    (tmp_path / "launcher-materialization-work.json").write_text(
        json.dumps(samples, indent=2) + "\n"
    )
    first = samples[0]
    assert all(
        row["work_bytes"] * first["complete_input_bytes"]
        <= 1.05 * first["work_bytes"] * row["complete_input_bytes"]
        for row in samples[1:]
    ), samples
