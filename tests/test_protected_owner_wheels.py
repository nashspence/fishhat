"""Ordinary-file wheel mechanics with administrative enrollment replaced."""

import base64
import csv
import hashlib
import io
import json
import os
import platform
import stat
import sys
import zipfile
from pathlib import Path

import pytest

from scripts import bundle_install as installer

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/bundle_install.py"],
    "scope": "complete approved wheel payload materialization, rejection, sealing and fresh retry",
    "relationship": "no-product-claim",
    "reason": "Synthetic wheels and replaced administrative enrollment exercise ordinary temporary files only. No candidate module, installer process, credential change or guest operation executes; actual package imports and permissions require an enrolled native witness.",
    "claims": [],
}


def wheel(path, distribution, *, count=3, names=None, change=None, metadata=None):
    prefix = distribution.replace("-", "_") + "-1.0.dist-info/"
    values = {
        **{
            f"{distribution.replace('-', '_')}/module_{i}.py": b"synthetic bytes" * 8
            for i in range(count)
        },
        prefix + "METADATA": metadata
        or f"Metadata-Version: 2.1\nName: {distribution}\nVersion: 1.0\n".encode(),
        prefix + "WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        prefix + "licenses/LICENSE": b"synthetic license text",
        **(names or {}),
    }
    records = [
        [
            name,
            "sha256="
            + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode(),
            str(len(raw)),
        ]
        for name, raw in values.items()
    ]
    records.append([prefix + "RECORD", "", ""])
    if change:
        change(values, records, prefix)
    stream = io.StringIO()
    csv.writer(stream, lineterminator="\n").writerows(records)
    values[prefix + "RECORD"] = stream.getvalue().encode()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr("empty/", b"")
        for name, raw in values.items():
            output.writestr(name, raw)
    return values


def fixture(root, *, count=3, names=None, change=None, metadata=None, dependencies=1):
    root.mkdir()
    (root / "wheels").mkdir()
    (root / "locks").mkdir()
    distributions = ["fishhat-host", *(f"fixture-{i}" for i in range(dependencies))]
    payloads = {}
    for name in [*distributions, "unselected"]:
        path = root / "wheels" / (name.replace("-", "_") + "-1.0-py3-none-any.whl")
        payloads[path.name] = wheel(
            path,
            name,
            count=count,
            names=names if name == "fishhat-host" else None,
            change=change if name == "fishhat-host" else None,
            metadata=metadata if name == "fishhat-host" else None,
        )
    lock = root / "locks/host.txt"
    lock.write_text(
        "".join(
            f"{name}==1.0 --hash=sha256:{installer.sha256(root / 'wheels' / (name.replace('-', '_') + '-1.0-py3-none-any.whl'))}\n"
            for name in distributions
        )
    )
    manifest = {
        "format": "fishhat-scaffold-bundle/v1",
        "production_qualified": False,
        "profile": {
            "platform": sys.platform,
            "machine": platform.machine(),
            "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        },
        "components": {
            "host": {
                "distribution": "fishhat-host",
                "module": "fishhat_host",
                "lock": "locks/host.txt",
                "dependencies": distributions,
            }
        },
    }
    return seal(root, manifest), payloads, manifest


def seal(root, manifest):
    manifest["files"] = {
        p.relative_to(root).as_posix(): {"size": p.stat().st_size, "sha256": installer.sha256(p)}
        for directory in (root / "wheels", root / "locks")
        for p in directory.iterdir()
    }
    (root / "manifest.json").write_text(json.dumps(manifest))
    expected = installer.sha256(root / "manifest.json")
    sums = {**{n: v["sha256"] for n, v in manifest["files"].items()}, "manifest.json": expected}
    (root / "SHA256SUMS").write_text(
        "".join(f"{sums[n]}  {n}\n" for n in installer._ordered_names(sums))
    )
    return expected


@pytest.fixture
def custody(tmp_path, monkeypatch):
    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)
    original = installer._directory_fd
    monkeypatch.setattr(installer, "_directory_fd", lambda p, **kw: original(p))

    def enrolled(destination):
        assert destination.parent == parent
        return original(parent)

    monkeypatch.setattr(installer, "_protected_parent", enrolled)
    yield parent
    for directory, _, _ in os.walk(parent):
        os.chmod(directory, 0o700)


def test_complete_selected_payloads_inputs_and_metadata_are_sealed(tmp_path, custody):
    source = tmp_path / "bundle"
    expected, payloads, _ = fixture(source, count=17)
    destination = custody / "installed"
    library = installer._install_owner_wheels(source, destination, expected)
    assert library == destination / "lib"
    assert (library / "empty").is_dir()
    assert (destination / "manifest.json").read_bytes() == (source / "manifest.json").read_bytes()
    assert (destination / "locks/host.txt").read_bytes() == (source / "locks/host.txt").read_bytes()
    assert len(list((destination / "wheels").iterdir())) == 2
    for name, files in payloads.items():
        if name.startswith("unselected"):
            assert not (destination / "wheels" / name).exists()
            assert not (library / "unselected").exists()
            continue
        assert (destination / "wheels" / name).read_bytes() == (
            source / "wheels" / name
        ).read_bytes()
        for relative, raw in files.items():
            assert (library / relative).read_bytes() == raw
    for path in [destination, *destination.rglob("*")]:
        assert path.stat().st_uid == os.geteuid()
        assert stat.S_IMODE(path.stat().st_mode) == (0o555 if path.is_dir() else 0o444)
    (source / "wheels/fishhat_host-1.0-py3-none-any.whl").write_bytes(b"caller replacement")
    assert (library / "fishhat_host/module_0.py").read_bytes() == b"synthetic bytes" * 8


@pytest.mark.parametrize("kind", ["directory", "file", "symlink"])
def test_existing_destinations_and_unrelated_contents_are_preserved(tmp_path, custody, kind):
    source = tmp_path / "bundle"
    expected, _, _ = fixture(source)
    retained = tmp_path / "retained"
    retained.mkdir()
    (retained / "keep").write_bytes(b"preserved bytes")
    destination = custody / "installed"
    if kind == "directory":
        destination.mkdir()
        (destination / "keep").write_bytes(b"preserved bytes")
    elif kind == "file":
        destination.write_bytes(b"preserved bytes")
    else:
        destination.symlink_to(retained, target_is_directory=True)
    before = destination.lstat()
    with pytest.raises(FileExistsError):
        installer._install_owner_wheels(source, destination, expected)
    assert destination.lstat() == before
    assert (retained / "keep").read_bytes() == b"preserved bytes"


@pytest.mark.parametrize(
    "name",
    [
        "../outside",
        "/outside",
        "package/../outside",
        "package//module.py",
        "package/./module.py",
        "package\\module.py",
        "package:module.py",
        "fishhat_host-1.0.data/scripts/unsafe",
        "unsafe.pth",
        "unsafe.pyc",
        "sitecustomize.py",
        "usercustomize.py",
    ],
    ids=[
        "parent",
        "absolute",
        "nested-parent",
        "empty-part",
        "dot-part",
        "backslash",
        "drive",
        "spread",
        "path-hook",
        "bytecode",
        "site-hook",
        "user-hook",
    ],
)
def test_unsafe_or_unsupported_namespace_never_exposes_success(tmp_path, custody, name):
    expected, _, _ = fixture(tmp_path / "bundle", names={name: b"synthetic bytes"})
    destination = custody / "installed"
    with pytest.raises(ValueError, match=r"unsafe|unsupported"):
        installer._install_owner_wheels(tmp_path / "bundle", destination, expected)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert not (tmp_path / "outside").exists()


@pytest.mark.parametrize(
    "kind", ["missing", "extra", "duplicate", "weak-hash", "hash", "size", "self-hash"]
)
def test_invalid_record_never_becomes_an_installation(tmp_path, custody, kind):
    def change(values, rows, prefix):
        if kind == "missing":
            rows.pop(0)
        elif kind == "extra":
            rows.append(["extra", "sha256=invalid", "1"])
        elif kind == "duplicate":
            rows.append(rows[0])
        elif kind == "weak-hash":
            rows[0][1] = "sha1=invalid"
        elif kind == "hash":
            rows[0][1] = "sha256=invalid"
        elif kind == "size":
            rows[0][2] = "1"
        else:
            rows[-1][1] = "sha256=invalid"

    expected, _, _ = fixture(tmp_path / "bundle", change=change)
    destination = custody / "installed"
    with pytest.raises(ValueError, match=r"record|payload"):
        installer._install_owner_wheels(tmp_path / "bundle", destination, expected)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700


@pytest.mark.parametrize(
    "kind",
    ["name", "version", "wheel-version", "purelib", "duplicate-name", "tags", "missing-tags"],
)
def test_metadata_identity_and_format_are_explicit(tmp_path, custody, kind):
    def change(values, rows, prefix):
        path = prefix + (
            "WHEEL" if kind in ("wheel-version", "purelib", "tags", "missing-tags") else "METADATA"
        )
        if kind == "name":
            values[path] = values[path].replace(b"fishhat-host", b"other-host")
        elif kind == "version":
            values[path] = values[path].replace(b"Version: 1.0", b"Version: 2.0")
        elif kind == "wheel-version":
            values[path] = values[path].replace(b"Version: 1.0", b"Version: 2.0")
        elif kind == "purelib":
            values[path] = values[path].replace(b"true", b"unknown")
        elif kind == "tags":
            values[path] = values[path].replace(b"py3-none-any", b"py2-none-any")
        elif kind == "missing-tags":
            values[path] = values[path].replace(b"Tag: py3-none-any\n", b"")
        else:
            values[path] += b"Name: fishhat-host\n"

    expected, _, _ = fixture(tmp_path / "bundle", change=change)
    with pytest.raises(ValueError, match="metadata"):
        installer._install_owner_wheels(tmp_path / "bundle", custody / "installed", expected)


@pytest.mark.parametrize(
    "kind",
    [
        "untrusted-manifest",
        "changed-wheel",
        "missing-wheel",
        "duplicate-wheel",
        "duplicate-pin",
        "component",
    ],
)
def test_approved_selection_is_complete_exact_and_unambiguous(tmp_path, custody, kind):
    source = tmp_path / "bundle"
    expected, _, manifest = fixture(source)
    if kind == "untrusted-manifest":
        expected = "0" * 64
    elif kind == "changed-wheel":
        (source / "wheels/fishhat_host-1.0-py3-none-any.whl").write_bytes(b"changed")
    elif kind == "missing-wheel":
        (source / "wheels/fishhat_host-1.0-py3-none-any.whl").unlink()
        expected = seal(source, manifest)
    elif kind == "duplicate-wheel":
        (source / "wheels/fishhat_host-1.0-1-py3-none-any.whl").write_bytes(
            (source / "wheels/fishhat_host-1.0-py3-none-any.whl").read_bytes()
        )
        expected = seal(source, manifest)
    elif kind == "duplicate-pin":
        lock = source / "locks/host.txt"
        lock.write_text(lock.read_text() + lock.read_text().splitlines()[0] + "\n")
        expected = seal(source, manifest)
    else:
        manifest["components"]["host"]["module"] = "unselected"
        expected = seal(source, manifest)
    with pytest.raises(ValueError):
        installer._install_owner_wheels(source, custody / "installed", expected)
    assert not (custody / "installed").exists()


@pytest.mark.parametrize("at", ["payload", "seal", "sync"])
def test_failed_candidate_is_private_preserved_and_requires_fresh_retry(
    tmp_path, custody, monkeypatch, at
):
    source = tmp_path / "bundle"
    expected, _, _ = fixture(source)
    destination = custody / "interrupted"

    def fail(*args, **kwargs):
        raise OSError("controlled file-operation failure")

    with monkeypatch.context() as patch:
        patch.setattr(
            installer,
            {
                "payload": "_unpack_owner_wheel",
                "seal": "_seal_owner_wheels",
                "sync": "_wheel_directory",
            }[at],
            fail,
        )
        with pytest.raises(OSError):
            installer._install_owner_wheels(source, destination, expected)
    metadata = destination.stat()
    assert stat.S_IMODE(metadata.st_mode) == 0o700
    members = {entry.name for entry in destination.iterdir()}
    os.utime(destination, ns=(0, metadata.st_mtime_ns), follow_symlinks=False)
    before = destination.stat()
    with pytest.raises(FileExistsError):
        installer._install_owner_wheels(source, destination, expected)
    retry = custody / "retry"
    installer._install_owner_wheels(source, retry, expected)
    with os.scandir(destination) as entries:
        assert {entry.name for entry in entries} == members
    after = destination.stat()
    fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_uid",
        "st_gid",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    assert {name: getattr(after, name) for name in fields} == {
        name: getattr(before, name) for name in fields
    }
    assert retry.stat().st_ino != before.st_ino


@pytest.mark.parametrize("axis", ["members", "distributions", "payload-bytes", "path-depth"])
def test_complete_wheel_materialization_work_is_linear(tmp_path, custody, monkeypatch, axis):
    samples = []
    for scale in (8, 32, 128):
        source = tmp_path / ("bundle-" + str(scale))
        expected, payloads, _ = fixture(
            source,
            count=scale if axis == "members" else 3,
            dependencies=scale if axis == "distributions" else 1,
            names={"/".join(["deep"] * scale) + "/payload": b"synthetic"}
            if axis == "path-depth"
            else {"sized-payload": b"x" * (scale * 256)}
            if axis == "payload-bytes"
            else None,
        )
        extent = sum(
            p.stat().st_size + len(p.relative_to(source).as_posix())
            for p in source.rglob("*")
            if p.is_file()
        )
        for name, values in payloads.items():
            if name.startswith("unselected"):
                continue
            extent += sum(len(n) + len(b) for n, b in values.items())
        work = [0]
        original_hash, original_parts = installer.sha256, installer._member_parts
        original_read, original_write, original_open = os.read, os.write, os.open

        def hashed(path, counter=work, original=original_hash):
            counter[0] += 1 + path.stat().st_size
            return original(path)

        def parts(name, counter=work, original=original_parts):
            counter[0] += 1 + len(name)
            return original(name)

        def read(fd, count, counter=work, original=original_read):
            raw = original(fd, count)
            counter[0] += 1 + len(raw)
            return raw

        def write(fd, raw, counter=work, original=original_write):
            count = original(fd, raw)
            counter[0] += 1 + count
            return count

        def opened(path, flags, *args, counter=work, original=original_open, **kwargs):
            counter[0] += 1 + len(os.fspath(path))
            return original(path, flags, *args, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(installer, "sha256", hashed)
            patch.setattr(installer, "_member_parts", parts)
            patch.setattr(installer.os, "read", read)
            patch.setattr(installer.os, "write", write)
            patch.setattr(installer.os, "open", opened)
            library = installer._install_owner_wheels(source, custody / str(scale), expected)
        count = sum(1 for p in library.rglob("*") if p.is_file())
        assert count == sum(len(v) for n, v in payloads.items() if not n.startswith("unselected"))
        samples.append(
            {
                "scale": scale,
                "complete_input_and_payload_bytes": extent,
                "counted_byte_namespace_io_work": work[0],
                "installed_regular_files": count,
            }
        )
    observed = os.environ.get("FISHHAT_OWNER_WHEEL_WORK_OBSERVATIONS")
    if observed:
        p = Path(observed)
        existing = json.loads(p.read_text()) if p.exists() else {}
        existing[axis] = samples
        p.write_text(json.dumps(existing, indent=2) + "\n")
    first = samples[0]
    assert all(
        row["counted_byte_namespace_io_work"] * first["complete_input_and_payload_bytes"]
        <= 1.10 * first["counted_byte_namespace_io_work"] * row["complete_input_and_payload_bytes"]
        for row in samples[1:]
    ), samples
