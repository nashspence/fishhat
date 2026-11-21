"""Inert composition mechanics; administrative admission and child installers are replaced."""

import ast
import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from scripts import bundle_install as installer

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/bundle_install.py"],
    "scope": "fixed host command composition, exact bindings, ordinary-file custody, private interruption/refusal, complete copy extent and counted linear byte work",
    "relationship": "no-product-claim",
    "reason": "Inert payloads and replaced root admission and child materializers prove composition mechanics only. No candidate Python, launcher, host command or guest executes; actual selected-runtime/module origins, credentials and permissions need independent enrolled-guest witnesses.",
    "claims": [],
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def snapshot(root):
    return {
        str(path.relative_to(root)): (
            path.lstat().st_ino,
            stat.S_IMODE(path.lstat().st_mode),
            path.read_bytes() if path.is_file() and not path.is_symlink() else None,
        )
        for path in [root, *root.rglob("*")]
    }


@pytest.fixture
def custody(tmp_path, monkeypatch):
    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)
    source = tmp_path / "inputs"
    source.mkdir()
    bundle, runtime, launcher = (source / name for name in ("bundle", "runtime", "launcher"))
    for path in (bundle, runtime, launcher):
        path.write_bytes(b"inert approved inputs")
    original_directory = installer._directory_fd
    monkeypatch.setattr(installer, "_directory_fd", lambda p, **kw: original_directory(p))

    def enrolled(destination):
        assert destination.parent == parent
        return original_directory(parent)

    monkeypatch.setattr(installer, "_protected_parent", enrolled)
    model = {"calls": [], "command": b"inert static command bytes", "binding": None}

    def private(destination):
        assert stat.S_IMODE(destination.parent.stat().st_mode) == 0o700

    def selected_runtime(archive, destination):
        assert archive == runtime
        private(destination)
        model["calls"].append("runtime")
        executable = destination / "python/bin/python3.12"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"inert interpreter")
        executable.chmod(0o555)
        return executable

    def selected_wheels(inputs, destination, expected):
        assert inputs == bundle and expected == "a" * 64
        private(destination)
        model["calls"].append("wheels")
        library = destination / "lib"
        library.mkdir(parents=True)
        (library / "inert-package.py").write_bytes(b"inert selected wheel payload")
        return library

    def selected_launcher(inputs, destination, expected):
        assert inputs == launcher and expected == "b" * 64
        private(destination)
        model["calls"].append("launcher")
        destination.mkdir()
        executable = destination / "launch"
        executable.write_bytes(model["command"])
        executable.chmod(0o555)
        program = destination.parent / "host-ops.py"
        manifest = {
            "interpreter": {"path": str(destination.parent / "runtime/python/bin/python3.12")},
            "program": {"path": str(program), "sha256": digest(program.read_bytes())},
            "files": {
                "launch": {"bytes": len(model["command"]), "sha256": digest(model["command"])}
            },
        }
        if model["binding"] is not None:
            model["binding"](manifest)
        (destination / "launcher.json").write_text(json.dumps(manifest))
        return executable

    monkeypatch.setattr(installer, "_install_owner_python", selected_runtime)
    monkeypatch.setattr(installer, "_install_owner_wheels", selected_wheels)
    monkeypatch.setattr(installer, "_install_owner_launcher", selected_launcher)

    def install(destination):
        return installer._install_owner_entrypoint(
            bundle,
            runtime,
            launcher,
            destination,
            manifest_sha256="a" * 64,
            launcher_manifest_sha256="b" * 64,
        )

    model.update(parent=parent, source=source, install=install)
    yield model
    for directory, _, _ in os.walk(parent):
        os.chmod(directory, 0o700)


def test_complete_fixed_command_is_copied_and_sealed_without_execution(custody, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("candidate execution attempted")

    monkeypatch.setattr(installer.subprocess, "run", forbidden)
    monkeypatch.setattr(installer.subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "execve", forbidden)
    before = snapshot(custody["source"])
    destination = custody["parent"] / "complete"
    command = custody["install"](destination)
    assert command == destination / "host-ops"
    assert command.read_bytes() == custody["command"]
    assert command.stat().st_ino != (destination / "launcher/launch").stat().st_ino
    assert command.stat().st_nlink == 1
    assert stat.S_IMODE(command.stat().st_mode) == 0o555
    assert stat.S_IMODE((destination / "host-ops.py").stat().st_mode) == 0o444
    assert stat.S_IMODE(destination.stat().st_mode) == 0o555
    assert set(p.name for p in destination.iterdir()) == {
        "runtime",
        "packages",
        "launcher",
        "host-ops.py",
        "host-ops",
    }
    assert custody["calls"] == ["runtime", "wheels", "launcher"]
    assert snapshot(custody["source"]) == before


@pytest.mark.parametrize(
    "spelling",
    [
        "/approved/lib",
        "/approved/quote'and\"/lib",
        "/approved/line\nname/π/lib",
        "/approved/nonutf8-\udcff/lib",
    ],
    ids=["ascii", "quotes", "line-unicode", "filesystem-surrogate"],
)
def test_program_is_only_the_fixed_path_and_host_command_import(spelling):
    raw = installer._owner_entrypoint_program(Path(spelling))
    tree = ast.parse(raw)
    assert len(tree.body) == 4
    assert isinstance(tree.body[0], ast.Import) and tree.body[0].names[0].name == "sys"
    insertion = tree.body[1].value
    assert ast.unparse(insertion.func) == "sys.path.insert"
    assert [ast.literal_eval(argument) for argument in insertion.args] == [0, spelling]
    assert isinstance(tree.body[2], ast.ImportFrom) and tree.body[2].module == "fishhat_host.cli"
    assert [(name.name, name.asname) for name in tree.body[2].names] == [("main", None)]
    assert ast.unparse(tree.body[3]) == "raise SystemExit(main())"


@pytest.mark.parametrize(
    "spelling",
    ["relative/lib", "/approved/../lib", "/bad\0/lib"],
    ids=["relative", "parent", "nul"],
)
def test_program_refuses_unsafe_library_paths(spelling):
    with pytest.raises(ValueError, match="unsafe owner library path"):
        installer._owner_entrypoint_program(Path(spelling))


@pytest.mark.parametrize("kind", ["directory", "file", "symlink"])
def test_existing_destination_is_preserved_before_any_child_installation(custody, kind):
    destination = custody["parent"] / "existing"
    if kind == "directory":
        destination.mkdir()
        (destination / "keep").write_bytes(b"retained")
    elif kind == "file":
        destination.write_bytes(b"retained")
    else:
        destination.symlink_to(custody["source"], target_is_directory=True)
    before, source = destination.lstat(), snapshot(custody["source"])
    with pytest.raises(FileExistsError):
        custody["install"](destination)
    assert destination.lstat() == before
    assert snapshot(custody["source"]) == source
    assert custody["calls"] == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("interpreter-path", "/unapproved/python"),
        ("program-path", "/unapproved/program.py"),
        ("program-sha256", "0" * 64),
    ],
    ids=["interpreter", "program", "program-digest"],
)
def test_a_different_fixed_target_is_not_accepted_for_this_installation(custody, field, value):
    def change(manifest):
        target, key = field.split("-", 1)
        manifest[target][key] = value

    custody["binding"] = change
    destination = custody["parent"] / "wrong-binding"
    with pytest.raises(ValueError, match="target binding changed"):
        custody["install"](destination)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert not (destination / "host-ops").exists()


@pytest.mark.parametrize(
    "phase",
    [
        "_install_owner_python",
        "_install_owner_wheels",
        "_write_owner_entrypoint_program",
        "_install_owner_launcher",
        "_copy_regular",
        "_seal_owner_entrypoint",
    ],
)
def test_interruption_preserves_private_candidate_refuses_reuse_and_allows_fresh_retry(
    custody, monkeypatch, phase
):
    original = getattr(installer, phase)

    def interrupt(*args, **kwargs):
        original(*args, **kwargs)
        raise InterruptedError("inert installation interruption")

    monkeypatch.setattr(installer, phase, interrupt)
    destination = custody["parent"] / "interrupted"
    with pytest.raises(InterruptedError):
        custody["install"](destination)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    before = snapshot(destination)
    monkeypatch.setattr(installer, phase, original)
    with pytest.raises(FileExistsError):
        custody["install"](destination)
    assert snapshot(destination) == before
    retry = custody["parent"] / "retry"
    assert custody["install"](retry) == retry / "host-ops"
    assert retry.stat().st_ino != destination.stat().st_ino
    assert snapshot(destination) == before


def test_corrupt_command_copy_is_never_exposed(custody, monkeypatch):
    original = installer._copy_regular

    def corrupt(*args, **kwargs):
        original(*args, **kwargs)
        descriptor = os.open("host-ops", os.O_WRONLY, dir_fd=kwargs["parent"])
        try:
            os.write(descriptor, b"changed")
        finally:
            os.close(descriptor)

    monkeypatch.setattr(installer, "_copy_regular", corrupt)
    destination = custody["parent"] / "corrupt"
    with pytest.raises(ValueError, match="installed host command changed"):
        custody["install"](destination)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700


def test_command_copy_has_complete_extent_and_linear_byte_work(custody, monkeypatch, tmp_path):
    original_read = os.read
    original_write = os.write
    measurements = []
    for extent in (65536, 262144, 1048576, 4194304):
        custody["command"] = bytes(range(256)) * (extent // 256)
        counts = {"read": 0, "write": 0}

        def read(descriptor, size, *, counter=counts):
            value = original_read(descriptor, size)
            counter["read"] += len(value)
            return value

        def write(descriptor, raw, *, counter=counts):
            count = original_write(descriptor, raw)
            counter["write"] += count
            return count

        with monkeypatch.context() as measured:
            measured.setattr(os, "read", read)
            measured.setattr(os, "write", write)
            command = custody["install"](custody["parent"] / str(extent))
        assert command.read_bytes() == custody["command"]
        assert counts == {"read": extent, "write": extent}
        measurements.append({"extent": extent, **counts})
    (tmp_path / "entrypoint-composition-byte-work.json").write_text(json.dumps(measurements))


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory", "file-capability"])
def test_command_sealing_refuses_unsafe_final_file(tmp_path, monkeypatch, kind):
    source = tmp_path / "source"
    source.write_bytes(b"inert command")
    command = tmp_path / "host-ops"
    if kind == "symlink":
        command.symlink_to(source)
    elif kind == "hardlink":
        command.hardlink_to(source)
    elif kind == "directory":
        command.mkdir()
    else:
        command.write_bytes(b"inert command")
        monkeypatch.setattr(os, "listxattr", lambda descriptor: ["security.capability"])
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises((ValueError, OSError)):
            installer._seal_owner_entrypoint(descriptor)
    finally:
        os.close(descriptor)
    assert source.read_bytes() == b"inert command"
