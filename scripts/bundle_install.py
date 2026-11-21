from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import os
import re
import stat
import subprocess
import sys
from collections.abc import Generator, Iterable
from contextlib import closing
from pathlib import Path, PurePosixPath
from typing import Any


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1_048_576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ordered_names(names: Iterable[str]) -> list[str]:
    """Match Python lexical order with work linear in encoded filename bytes.

    A partition contains at most 256 byte values, so ordering that fixed alphabet
    adds no collection-size factor. Surrogate pass preserves lexical order for
    filesystem-surrogate spellings as well as ordinary Unicode names. Bootstrap
    verification stays standard-library-only, before candidate packages are trusted.
    """
    pending = [([(name.encode("utf-8", "surrogatepass"), name) for name in names], 0)]
    result: list[str] = []
    while pending:
        group, offset = pending.pop()
        if len(group) < 2:
            result.extend(name for _, name in group)
            continue
        children: dict[int, list[tuple[bytes, str]]] = {}
        for encoded, name in group:
            if offset == len(encoded):
                result.append(name)
            else:
                children.setdefault(encoded[offset], []).append((encoded, name))
        pending.extend((children[byte], offset + 1) for byte in sorted(children, reverse=True))
    return result


def _member_parts(name: str) -> tuple[str, ...]:
    member = PurePosixPath(name)
    if (
        not member.parts
        or member.is_absolute()
        or ".." in member.parts
        or "\\" in name
        or ":" in name
    ):
        raise ValueError("unsafe bundle member")
    return member.parts


class _BundleReader:
    """Keep member traversal relative to one pinned bundle directory on POSIX."""

    def __init__(self, root: Path) -> None:
        self.root = root.absolute()
        self.descriptor: int | None = None

    def __enter__(self) -> _BundleReader:
        if os.name == "posix":
            self.descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        else:
            self.root = self.root.resolve()
        return self

    def __exit__(self, *arguments: Any) -> None:
        if self.descriptor is not None:
            os.close(self.descriptor)

    def _member(self, name: str) -> tuple[int, os.stat_result]:
        parts = _member_parts(name)
        if self.descriptor is not None:
            parent = _source_directory(self.descriptor, parts[:-1])
            try:
                return _regular_source(parent, parts[-1])
            finally:
                os.close(parent)
        path = self.root / name
        if path.is_symlink() or not path.resolve().is_relative_to(self.root) or not path.is_file():
            raise ValueError("missing or unsafe bundle member")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("staging source is not a regular file")
            return descriptor, metadata
        except BaseException:
            os.close(descriptor)
            raise

    def _chunks(
        self, name: str, *, maximum: int | None = None, expected_size: int | None = None
    ) -> Generator[bytes, None, None]:
        descriptor, before = self._member(name)
        try:
            if maximum is not None and before.st_size > maximum:
                raise ValueError("untrusted or changed manifest")
            if expected_size is not None and before.st_size != expected_size:
                raise ValueError("bundle artifact changed")
            remaining = before.st_size
            while remaining:
                chunk = os.read(descriptor, min(1_048_576, remaining))
                if not chunk:
                    raise ValueError("bundle artifact changed")
                remaining -= len(chunk)
                yield chunk
            after = os.fstat(descriptor)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise ValueError("bundle artifact changed")
        finally:
            os.close(descriptor)

    def read(self, name: str, *, maximum: int | None = None) -> bytes:
        with closing(self._chunks(name, maximum=maximum)) as chunks:
            return b"".join(chunks)

    def text(self, name: str) -> str:
        with io.TextIOWrapper(io.BytesIO(self.read(name))) as stream:
            return stream.read()

    def digest(self, name: str, expected_size: int) -> str:
        result = hashlib.sha256()
        with closing(self._chunks(name, expected_size=expected_size)) as chunks:
            for chunk in chunks:
                result.update(chunk)
        return result.hexdigest()

    def names(self) -> set[str]:
        if self.descriptor is None:
            result = set()
            for path in self.root.rglob("*"):
                if path.is_symlink():
                    raise ValueError("bundle contains a symbolic link")
                if path.is_file():
                    result.add(path.relative_to(self.root).as_posix())
            return result
        result = set()
        parts: list[str] = []
        with closing(_source_events(self.descriptor)) as events:
            for kind, name, _ in events:
                if kind == "file":
                    result.add("/".join([*parts, name]))
                elif name and kind == "enter":
                    parts.append(name)
                elif name and kind == "leave":
                    parts.pop()
        return result


def verify(bundle: Path, expected: str) -> dict[str, Any]:
    with _BundleReader(bundle) as reader:
        raw = reader.read("manifest.json", maximum=2_000_000)
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("untrusted or changed manifest")
        manifest: dict[str, Any] = json.loads(raw.decode("utf-8"))
        if (
            manifest.get("format") != "fishhat-scaffold-bundle/v1"
            or manifest.get("production_qualified") is not False
        ):
            raise ValueError("unsupported bundle qualification")
        profile = manifest["profile"]
        if (
            profile["platform"] != sys.platform
            or profile["python"] != f"{sys.version_info.major}.{sys.version_info.minor}"
        ):
            raise ValueError("bundle platform or Python mismatch")
        import platform

        if profile["machine"].lower() != platform.machine().lower():
            raise ValueError("bundle architecture mismatch")
        files = manifest["files"]
        for name, metadata in files.items():
            if reader.digest(name, metadata["size"]) != metadata["sha256"]:
                raise ValueError("bundle artifact changed")
        locks: dict[str, set[str]] = {}
        for selection in manifest["components"].values():
            lock = selection["lock"]
            if lock not in files or not re.fullmatch(r"locks/[a-z0-9-]+\.txt", lock):
                raise ValueError("unverified component lock")
            if lock not in locks:
                entries = reader.text(lock).splitlines()
                if not entries or any(
                    not re.fullmatch(
                        r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.!+-]+ --hash=sha256:[a-f0-9]{64}", entry
                    )
                    for entry in entries
                ):
                    raise ValueError("component lock must contain hashed package pins only")
                locks[lock] = {entry.split("==")[0] for entry in entries}
            names = locks[lock]
            if names != set(selection["dependencies"]) or selection["distribution"] not in names:
                raise ValueError("component dependency inventory mismatch")
        if reader.names() != set(files) | {"manifest.json", "SHA256SUMS"}:
            raise ValueError("unclassified bundle contents")
        sums = {
            **{name: metadata["sha256"] for name, metadata in files.items()},
            "manifest.json": expected,
        }
        expected_sums = "".join(f"{sums[name]}  {name}\n" for name in _ordered_names(sums))
        if reader.text("SHA256SUMS") != expected_sums:
            raise ValueError("bundle checksum inventory changed")
        return manifest


def _directory_fd(path: Path, *, protected: bool = False) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    absolute = path.absolute()
    if ".." in absolute.parts:
        raise ValueError("unsafe staging ancestry")
    descriptor = os.open(absolute.anchor, flags)
    try:
        for part in (None, *absolute.parts[1:]):
            if part is not None:
                child = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            metadata = os.fstat(descriptor)
            if protected and (metadata.st_uid != 0 or metadata.st_mode & 0o022):
                raise ValueError("unprotected staging ancestry")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _protected_parent(destination: Path) -> int:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("protected staging requires Linux administrative custody")
    if destination.name in ("", ".", ".."):
        raise ValueError("unsafe staging destination")
    return _directory_fd(destination.parent, protected=True)


def _source_directory(root: int, parts: tuple[str, ...]) -> int:
    descriptor = os.dup(root)
    try:
        for part in parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _regular_source(parent: int, name: str) -> tuple[int, os.stat_result]:
    pinned = None
    descriptor = None
    try:
        if sys.platform == "linux":
            pinned = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=parent)
            before = os.fstat(pinned)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("staging source is not a regular file")
            descriptor = os.open(f"/proc/self/fd/{pinned}", os.O_RDONLY | os.O_NONBLOCK)
        else:
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("staging source is not a regular file")
            descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise ValueError("staging source identity changed")
        return descriptor, before
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        if pinned is not None:
            os.close(pinned)


def _copy_regular(
    source: int,
    name: str,
    destination: Path,
    *,
    parent: int | None = None,
    expected_size: int | None = None,
) -> None:
    descriptor, before = _regular_source(source, name)
    try:
        if expected_size is not None and before.st_size != expected_size:
            raise ValueError("runtime archive size mismatch")
        output = os.open(
            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
        )
        try:
            remaining = before.st_size
            while remaining:
                chunk = os.read(descriptor, min(1_048_576, remaining))
                if not chunk:
                    raise ValueError("staging source changed")
                remaining -= len(chunk)
                view = memoryview(chunk)
                offset = 0
                while offset < len(chunk):
                    written = os.write(output, view[offset:])
                    if written <= 0:
                        raise OSError("staging write did not progress")
                    offset += written
            after = os.fstat(descriptor)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise ValueError("staging source changed")
            os.fsync(output)
        finally:
            os.close(output)
    finally:
        os.close(descriptor)


def _file_identity(descriptor: int) -> tuple[int, int]:
    value = os.fstat(descriptor)
    return value.st_dev, value.st_ino


def _entry_names(descriptor: int) -> list[str]:
    with os.scandir(descriptor) as entries:
        return [entry.name for entry in entries]


def _directory_parent(descriptor: int, expected: tuple[int, int]) -> int:
    parent = os.open("..", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
    try:
        if _file_identity(parent) != expected:
            raise ValueError("staging directory ancestry changed")
        return parent
    except BaseException:
        os.close(parent)
        raise


def _source_events(
    root: int, forbidden: tuple[int, int] | None = None
) -> Generator[tuple[str, str, int], None, None]:
    """Walk a finite namespace with one current descriptor and retained identities."""
    current = os.dup(root)
    try:
        identity = _file_identity(current)
        if identity == forbidden:
            raise ValueError("staging source contains destination")
        active = {identity}
        frames = [(identity, "", _entry_names(current))]
        yield "enter", "", current
        while frames:
            identity, current_name, names = frames[-1]
            if not names:
                yield "leave", current_name, current
                if len(frames) == 1:
                    break
                parent = _directory_parent(current, frames[-2][0])
                os.close(current)
                current = parent
                active.remove(identity)
                frames.pop()
                continue
            name = names.pop()
            if name in (".", "..") or "\\" in name or ":" in name:
                raise ValueError("unsafe staging source name")
            metadata = os.stat(name, dir_fd=current, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError("bundle contains a symbolic link")
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                try:
                    child_identity = _file_identity(child)
                    if child_identity != (metadata.st_dev, metadata.st_ino):
                        raise ValueError("staging source directory changed")
                    if child_identity == forbidden:
                        raise ValueError("staging source contains destination")
                    if child_identity in active:
                        raise ValueError("staging source contains a directory cycle")
                    child_names = _entry_names(child)
                except BaseException:
                    os.close(child)
                    raise
                os.close(current)
                current = child
                active.add(child_identity)
                frames.append((child_identity, name, child_names))
                yield "enter", name, current
            elif stat.S_ISREG(metadata.st_mode):
                yield "file", name, current
            else:
                raise ValueError("staging source is not a regular file")
    finally:
        os.close(current)


def _copy_tree(source: int, destination: int) -> None:
    current = os.dup(destination)
    try:
        identities = [_file_identity(current)]
        with closing(_source_events(source, identities[0])) as events:
            for kind, name, descriptor in events:
                if kind == "file":
                    _copy_regular(descriptor, name, Path(name), parent=current)
                elif kind == "enter" and name:
                    os.mkdir(name, mode=0o700, dir_fd=current)
                    child = os.open(
                        name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current
                    )
                    os.close(current)
                    current = child
                    identities.append(_file_identity(current))
                elif kind == "leave":
                    os.fsync(current)
                    if name:
                        parent = _directory_parent(current, identities[-2])
                        os.close(current)
                        current = parent
                        identities.pop()
    finally:
        os.close(current)


def _stage_verified(bundle: Path, destination: Path, expected: str) -> Path:
    """Retain a complete verified candidate in a fresh protected Linux directory.

    This supplies input custody only. It does not commission an owner, execute an
    installer or qualify runtime authority. Failure leaves the private incomplete
    destination unavailable; existing destinations are never adopted or erased.
    """
    destination = destination.absolute()
    parent = _protected_parent(destination)
    source = None
    staged = None
    try:
        source = _directory_fd(bundle)
        if destination.is_relative_to(bundle.absolute()):
            raise ValueError("staging source contains destination")
        os.mkdir(destination.name, mode=0o700, dir_fd=parent)
        staged = _source_directory(parent, (destination.name,))
        _copy_tree(source, staged)
        verify(destination, expected)
        os.fsync(staged)
        os.fsync(parent)
        return destination
    finally:
        if staged is not None:
            os.close(staged)
        if source is not None:
            os.close(source)
        os.close(parent)


OWNER_PYTHON_URL = (
    "https://github.com/astral-sh/python-build-standalone/releases/download/20261026/"
    "cpython-3.12.16%2B20261026-x86_64-unknown-linux-gnu-install_only.tar.gz"
)
OWNER_PYTHON_SHA256 = "6a79e922e50006b601f29e688407659da1c2b86ebcd4e9c7254cf234be8b89de"
OWNER_PYTHON_BYTES = 67_921_566


def _runtime_walk_error(error: OSError) -> None:
    raise error


def _seal_python(root: Path) -> None:
    """Seal the complete authenticated distribution, including its internal aliases.

    This is called only after the fixed archive identity has been verified. It is
    not an extractor or validator for arbitrary caller-authored Python layouts.
    """
    for directory, directories, files in os.walk(
        root, topdown=False, followlinks=False, onerror=_runtime_walk_error
    ):
        for name in [*directories, *files]:
            path = Path(directory) / name
            metadata = path.lstat()
            if metadata.st_uid != os.geteuid():
                raise ValueError("foreign runtime member")
            if stat.S_ISLNK(metadata.st_mode):
                if not path.resolve(strict=True).is_relative_to(root):
                    raise ValueError("runtime alias escapes installation")
            elif stat.S_ISREG(metadata.st_mode):
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    os.fchmod(descriptor, 0o555 if metadata.st_mode & 0o111 else 0o444)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            elif not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("special runtime member")
        descriptor = _directory_fd(Path(directory))
        try:
            if os.fstat(descriptor).st_uid != os.geteuid():
                raise ValueError("foreign runtime directory")
            os.fchmod(descriptor, 0o555)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _install_owner_python(archive: Path, destination: Path) -> Path:
    """Install only the selected Linux runtime into a fresh protected prefix.

    Admission, transfer and durable owner commissioning belong to their callers.
    Until sealing completes, the destination stays private. A failed or unknown
    attempt is preserved, and an existing destination is never adopted or erased.
    No candidate interpreter, package installer or native owner is executed here.
    """
    import platform
    import tarfile

    destination = destination.absolute()
    parent = _protected_parent(destination)
    source = None
    installed = None
    try:
        if platform.machine().lower() != "x86_64":
            raise ValueError("unsupported owner runtime architecture")
        source = _directory_fd(archive.parent)
        os.mkdir(destination.name, mode=0o700, dir_fd=parent)
        installed = _source_directory(parent, (destination.name,))
        retained = destination / "runtime.tar.gz"
        _copy_regular(
            source,
            archive.name,
            Path("runtime.tar.gz"),
            parent=installed,
            expected_size=OWNER_PYTHON_BYTES,
        )
        if sha256(retained) != OWNER_PYTHON_SHA256:
            raise ValueError("untrusted owner runtime archive")
        with tarfile.open(retained, "r:gz") as distribution:
            distribution.extractall(destination, filter="data")
        runtime = destination / "python"
        executable = runtime / "bin/python3.12"
        if not stat.S_ISREG(executable.lstat().st_mode):
            raise ValueError("missing selected runtime executable")
        _seal_python(runtime)
        descriptor = os.open(retained, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fchmod(installed, 0o555)
        os.fsync(installed)
        os.fsync(parent)
        return executable
    finally:
        if installed is not None:
            os.close(installed)
        if source is not None:
            os.close(source)
        os.close(parent)


# Fixed administrator-selected inputs, never selected by a source or operation request.
OWNER_BOOTSTRAP_INPUTS = (
    ("busybox", 2_124_608, "dbac288c29ba568459550a2da9e7ae0ded6b1fc728ee9fad3044c44e62d6ac14"),
    (
        "busybox-static_1.36.1-6ubuntu3.1_amd64.deb",
        1_008_874,
        "944b2728f53ceb3916cec2c962873c9951e612408099601751db2a0a5d81e0ed",
    ),
    (
        "busybox_1.36.1.orig.tar.bz2",
        2_525_473,
        "b8cc24c9574d809e7279c3be349795c5d5ceb6fdf19ca709f80cde50e47de314",
    ),
    (
        "busybox_1.36.1-6ubuntu3.1.debian.tar.xz",
        84_488,
        "1c7d785cf1e1d5d09ddc22fe755e14327fb3799878a5d840fc611044ff05f022",
    ),
    (
        "busybox_1.36.1-6ubuntu3.1.dsc",
        2_711,
        "ffbee3f0383ea5a3e77033c2bcc1978dc9ae00ff8c9d0a362ee32f6e84254be8",
    ),
    (
        "busybox_1.36.1.orig.tar.bz2.asc",
        195,
        "d4a7082ba3cbc35b2fdb4f132a32e3789de66ce468b7b4858563f5f157c28afe",
    ),
    ("copyright", 1_110, "336d995e819d3a7a3fdbf3f5041c07094f75ee849acb3bb742b7503d45786329"),
    ("LICENSE", 18_348, "bbfc9843646d483c334664f651c208b9839626891d8f17604db2146962f43548"),
)


def _verify_owner_bootstrap_elf(executable: Path) -> None:
    """Check static ELF structure without loading or executing the approved bytes."""
    import struct

    descriptor = os.open(executable, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        size = os.fstat(source.fileno()).st_size
        header = source.read(64)
        if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
            raise ValueError("invalid static bootstrap ELF header")
        fields = struct.unpack_from("<HHIQQQIHHHHHH", header, 16)
        kind, machine, version, entry, offset = fields[:5]
        header_size, row_size, rows = fields[7:10]
        if (
            (kind, machine, version, header_size, row_size) != (2, 62, 1, 64, 56)
            or not rows
            or offset < 64
            or offset + rows * row_size > size
        ):
            raise ValueError("unsupported static bootstrap ELF layout")
        source.seek(offset)
        entry_loaded = False
        for _ in range(rows):
            row = source.read(row_size)
            if len(row) != row_size:
                raise ValueError("truncated static bootstrap ELF program table")
            segment, flags, start, address, _, extent, memory, _ = struct.unpack("<IIQQQQQQ", row)
            if segment in (2, 3):
                raise ValueError("dynamic static bootstrap ELF segment")
            if segment == 1:
                if start + extent > size or extent > memory:
                    raise ValueError("invalid static bootstrap ELF load extent")
                entry_loaded |= bool(flags & 1 and address <= entry < address + memory)
        if not entry_loaded:
            raise ValueError("static bootstrap ELF entry is not executable")


def _verify_owner_launcher_elf(executable: Path) -> None:
    """Read static launch bytes only; require a non-executable stack and W^X."""
    import struct

    _verify_owner_bootstrap_elf(executable)
    with executable.open("rb") as source:
        header = source.read(64)
        entry, offset = struct.unpack_from("<QQ", header, 24)
        row_size, rows = struct.unpack_from("<HH", header, 54)
        source.seek(offset)
        stacks = 0
        entry_loaded = False
        for _ in range(rows):
            segment, flags, _, address, _, extent, _, _ = struct.unpack(
                "<IIQQQQQQ", source.read(row_size)
            )
            if segment == 1:
                if flags & 3 == 3:
                    raise ValueError("writable executable launcher segment")
                entry_loaded |= bool(flags & 5 == 5 and address <= entry < address + extent)
            if segment == 0x6474E551:
                stacks += 1
                if flags != 6:
                    raise ValueError("unsafe launcher stack permissions")
        if stacks != 1 or not entry_loaded:
            raise ValueError("unsafe launcher execution layout")


def _owner_launcher_header(interpreter: str, program: str) -> bytes:
    declarations = []
    for name, value in (("OWNER_INTERPRETER", interpreter), ("OWNER_PROGRAM", program)):
        path = PurePosixPath(value)
        if not value.startswith("/") or ".." in path.parts or "\0" in value:
            raise ValueError("unsafe fixed launcher target")
        literal = "".join("\\x" + format(byte, "02x") for byte in os.fsencode(value))
        declarations.append("#define " + name + ' "' + literal + '"\n')
    return "".join(declarations).encode()


def _verify_owner_launch_target(value: dict[str, str], *, interpreter: bool) -> None:
    if set(value) != {"path", "sha256"} or not re.fullmatch("[0-9a-f]{64}", value["sha256"]):
        raise ValueError("invalid fixed launcher target identity")
    path = Path(value["path"])
    if not path.is_absolute():
        raise ValueError("relative fixed launcher target")
    parent = _directory_fd(path.parent, protected=True)
    descriptor = None
    try:
        descriptor, before = _regular_source(parent, path.name)
        if (
            before.st_uid != 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != (0o555 if interpreter else 0o444)
        ):
            raise ValueError("unprotected fixed launcher target")
        with os.fdopen(os.dup(descriptor), "rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        after = os.fstat(descriptor)
        if digest != value["sha256"] or (
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("fixed launcher target changed")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _verify_owner_launcher_sources(source: int, names: set[str]) -> None:
    if set(_entry_names(source)) != names:
        raise ValueError("incomplete fixed launcher input closure")
    for name in names:
        metadata = os.stat(name, dir_fd=source, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o6022
        ):
            raise ValueError("unprotected fixed launcher source")


def _owner_launcher_manifest(raw: bytes, expected: str, names: set[str]) -> dict[str, Any]:
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("untrusted fixed launcher manifest")
    manifest = json.loads(raw)
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"format", "interpreter", "program", "files", "build"}
        or manifest["format"] != "fishhat-owner-launcher/v1"
    ):
        raise ValueError("invalid fixed launcher manifest")
    if (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode() != raw:
        raise ValueError("noncanonical fixed launcher manifest")
    if not isinstance(manifest["files"], dict) or set(manifest["files"]) != names - {
        "launcher.json"
    }:
        raise ValueError("invalid fixed launcher files")
    return manifest


def _owner_launcher_file(item: Any) -> dict[str, Any]:
    if (
        not isinstance(item, dict)
        or set(item) != {"bytes", "sha256"}
        or type(item["bytes"]) is not int
        or item["bytes"] < 0
        or not isinstance(item["sha256"], str)
        or not re.fullmatch("[0-9a-f]{64}", item["sha256"])
    ):
        raise ValueError("invalid fixed launcher file identity")
    return item


def _install_owner_launcher(inputs: Path, destination: Path, expected: str) -> Path:
    """Admit only a fresh, explicitly approved static launch artifact closure.

    This materializer does not build or run a program, acquire privileges or
    commission an owner. The administrator approves the complete manifest hash.
    A rejected or interrupted destination is preserved privately for inspection.
    """
    import platform

    destination = destination.absolute()
    parent = _protected_parent(destination)
    source = None
    installed = None
    names = {"launch", "launch.c", "targets.h", "launcher.json"}
    try:
        if platform.machine().lower() != "x86_64" or not re.fullmatch("[0-9a-f]{64}", expected):
            raise ValueError("unsupported fixed launcher inputs")
        source = _directory_fd(inputs, protected=True)
        _verify_owner_launcher_sources(source, names)
        os.mkdir(destination.name, mode=0o700, dir_fd=parent)
        installed = _source_directory(parent, (destination.name,))
        _copy_regular(source, "launcher.json", Path("launcher.json"), parent=installed)
        raw = (destination / "launcher.json").read_bytes()
        manifest = _owner_launcher_manifest(raw, expected, names)
        for name in ("launch", "launch.c", "targets.h"):
            item = _owner_launcher_file(manifest["files"][name])
            _copy_regular(source, name, Path(name), parent=installed, expected_size=item["bytes"])
            if sha256(destination / name) != item["sha256"]:
                raise ValueError("fixed launcher file changed")
        for name in ("interpreter", "program"):
            item = manifest[name]
            if not isinstance(item, dict) or not all(
                isinstance(value, str) for value in item.values()
            ):
                raise ValueError("invalid fixed launcher target")
            _verify_owner_launch_target(item, interpreter=name == "interpreter")
        header = _owner_launcher_header(
            manifest["interpreter"]["path"], manifest["program"]["path"]
        )
        if (destination / "targets.h").read_bytes() != header:
            raise ValueError("fixed launcher configuration changed")
        executable = destination / "launch"
        _verify_owner_launcher_elf(executable)
        for name in sorted(names):
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=installed)
            try:
                os.fchmod(descriptor, 0o555 if name == "launch" else 0o444)
                if "security.capability" in os.listxattr(descriptor):
                    raise ValueError("unexpected launcher file capability")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.fsync(installed)
        os.fsync(parent)
        os.fchmod(installed, 0o555)
        os.fsync(installed)
        return executable
    except BaseException:
        if installed is not None:
            try:
                os.fchmod(installed, 0o700)
            except OSError:
                pass
        raise
    finally:
        for opened in (installed, source, parent):
            if opened is not None:
                os.close(opened)


def _install_owner_bootstrap(inputs: Path, destination: Path) -> Path:
    """Retain and seal the fixed static facility and complete source/notices.

    This materializer never executes a binary, extracts a package, invokes a
    maintainer script, changes credentials or activates an installed command.
    Only a fresh administrator-selected protected destination can be returned.
    Existing or failed candidates remain preserved and cannot be reused.
    The fixed build disables locale startup and uses internal account readers.
    Non-root multi-call startup may still consult root-controlled configuration.
    """
    import platform

    destination = destination.absolute()
    parent = _protected_parent(destination)
    source = None
    installed = None
    try:
        if platform.machine().lower() != "x86_64":
            raise ValueError("unsupported static bootstrap architecture")
        source = _directory_fd(inputs, protected=True)
        os.mkdir(destination.name, mode=0o700, dir_fd=parent)
        installed = _source_directory(parent, (destination.name,))
        for name, size, expected in OWNER_BOOTSTRAP_INPUTS:
            _copy_regular(source, name, Path(name), parent=installed, expected_size=size)
            if sha256(destination / name) != expected:
                raise ValueError("untrusted static bootstrap input")
        executable = destination / "busybox"
        _verify_owner_bootstrap_elf(executable)
        for name, _, _ in OWNER_BOOTSTRAP_INPUTS:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=installed)
            try:
                os.fchmod(descriptor, 0o555 if name == "busybox" else 0o444)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.fsync(installed)
        os.fsync(parent)
        os.fchmod(installed, 0o555)
        os.fsync(installed)
        return executable
    except BaseException:
        if installed is not None:
            try:
                os.fchmod(installed, 0o700)
            except OSError:
                pass
        raise
    finally:
        for opened in (installed, source, parent):
            if opened is not None:
                os.close(opened)


def _prepare_owner_state(destination: Path) -> Path:
    """Create only fresh protected storage; never commission or adopt an owner.

    The administrator selects the destination outside request/source authority.
    A failed attempt stays private and is never reused implicitly. Empty storage
    carries no owner identity, journal schema or checkpoint-write authority.
    """
    destination = destination.absolute()
    parent = _protected_parent(destination)
    child = None
    try:
        os.mkdir(destination.name, mode=0o700, dir_fd=parent)
        child = _source_directory(parent, (destination.name,))
        if os.fstat(child).st_uid != os.geteuid():
            raise ValueError("foreign owner state directory")
        os.fchmod(child, 0o700)
        os.fsync(child)
        os.fsync(parent)
        return destination
    finally:
        if child is not None:
            os.close(child)
        os.close(parent)


def _wheel_directory(root: int, parts: tuple[str, ...]) -> int:
    """Create/traverse one private relative path without recursive path rescans."""
    current = os.dup(root)
    try:
        for part in parts:
            try:
                os.mkdir(part, mode=0o700, dir_fd=current)
                os.fsync(current)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _owner_wheel_tag_compatible(tag: str) -> bool:
    """Recognize supported CPython/glibc wheel tags without loading candidate code."""
    pieces = tag.split("-")
    if len(pieces) != 3:
        return False
    language, abi, target = pieces
    current = f"cp{sys.version_info.major}{sys.version_info.minor}"
    generic = language in ("py3", f"py3{sys.version_info.minor}") and abi == "none"
    if target == "any":
        return generic
    stable = re.fullmatch(r"cp3([0-9]{1,2})", language)
    python = (
        generic
        or (language == current and abi in (current, "none"))
        or (abi == "abi3" and stable is not None and 2 <= int(stable[1]) <= sys.version_info.minor)
    )
    if not python or sys.platform != "linux":
        return False
    import platform

    if platform.machine().lower() != "x86_64":
        return False
    libc = os.confstr("CS_GNU_LIBC_VERSION") or ""
    match = re.fullmatch(r"glibc ([0-9]+)\.([0-9]+)", libc)
    if match is None:
        return False
    required = {"manylinux1_x86_64": 5, "manylinux2010_x86_64": 12, "manylinux2014_x86_64": 17}.get(
        target
    )
    modern = re.fullmatch(r"manylinux_2_([0-9]{1,2})_x86_64", target)
    if modern is not None:
        required = int(modern[1])
    return required is not None and (int(match[1]), int(match[2])) >= (2, required)


def _unpack_owner_wheel(wheel: Path, library: int, distribution: str, version: str) -> None:
    """Materialize an approved root-layout wheel, without hooks or script activation."""
    import base64
    import csv
    import email
    import zipfile

    prefix = distribution.replace("-", "_") + "-" + version + ".dist-info/"
    with zipfile.ZipFile(wheel) as archive:
        files = {}
        for member in archive.infolist():
            name = member.filename
            parts = _member_parts(name)
            if (
                member.orig_filename != name
                or "/".join(parts) + ("/" if member.is_dir() else "") != name
                or parts[0].endswith(".data")
                or name.endswith((".pth", ".pyc"))
                or parts[0] in ("sitecustomize.py", "usercustomize.py")
                or member.flag_bits & 1
                or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                or stat.S_IFMT(member.external_attr >> 16)
                not in (0, stat.S_IFDIR if member.is_dir() else stat.S_IFREG)
                or name in files
            ):
                raise ValueError("unsupported or ambiguous owner wheel namespace")
            files[name] = member
        for name, member in files.items():
            if member.is_dir():
                directory = _wheel_directory(library, _member_parts(name))
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        regular = {name: member for name, member in files.items() if not member.is_dir()}
        roots = {name.split("/", 1)[0] + "/" for name in regular if ".dist-info/" in name}
        if roots != {prefix}:
            raise ValueError("owner wheel metadata identity mismatch")
        metadata = email.message_from_bytes(archive.read(prefix + "METADATA"))
        wheel_metadata = email.message_from_bytes(archive.read(prefix + "WHEEL"))
        normalized = re.sub(r"[-_.]+", "-", str(metadata["Name"])).lower()
        if (
            len(metadata.get_all("Name", [])) != 1
            or len(metadata.get_all("Version", [])) != 1
            or normalized != distribution
            or metadata["Version"] != version
            or wheel_metadata.get_all("Wheel-Version", []) != ["1.0"]
            or wheel_metadata.get_all("Root-Is-Purelib", []) not in (["true"], ["false"])
        ):
            raise ValueError("unsupported owner wheel metadata")
        filename_tags = [
            set(part.split(".")) for part in wheel.name.removesuffix(".whl").split("-")[-3:]
        ]
        tags = wheel_metadata.get_all("Tag", [])
        if (
            len(set(tags)) != len(tags)
            or len(tags) != math.prod(len(part) for part in filename_tags)
            or any(
                len(tag.split("-")) != 3
                or any(
                    piece not in choices
                    for piece, choices in zip(tag.split("-"), filename_tags, strict=True)
                )
                for tag in tags
            )
            or not any(_owner_wheel_tag_compatible(tag) for tag in tags)
        ):
            raise ValueError("unsupported owner wheel metadata tags")
        records = {}
        for row in csv.reader(io.StringIO(archive.read(prefix + "RECORD").decode("utf-8"))):
            if len(row) != 3 or row[0] in records:
                raise ValueError("ambiguous owner wheel record")
            records[row[0]] = row[1:]
        if set(records) != set(regular) or records[prefix + "RECORD"] != ["", ""]:
            raise ValueError("incomplete owner wheel records")
        for name, member in regular.items():
            hash_text, size_text = records[name]
            digest = None
            if name != prefix + "RECORD":
                algorithm, separator, encoded = hash_text.partition("=")
                if (
                    not separator
                    or algorithm not in ("sha256", "sha384", "sha512")
                    or not size_text.isascii()
                    or not size_text.isdecimal()
                    or len(size_text) > 20
                    or int(size_text) != member.file_size
                ):
                    raise ValueError("invalid owner wheel record")
                digest = hashlib.new(algorithm)
            parts = _member_parts(name)
            parent = _wheel_directory(library, parts[:-1])
            descriptor = None
            try:
                descriptor = os.open(
                    parts[-1],
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=parent,
                )
                total = 0
                with archive.open(member) as source:
                    while chunk := source.read(1_048_576):
                        total += len(chunk)
                        if digest is not None:
                            digest.update(chunk)
                        view = memoryview(chunk)
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                raise OSError("owner wheel write made no progress")
                            view = view[written:]
                if total != member.file_size or (
                    digest is not None
                    and base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode() != encoded
                ):
                    raise ValueError("owner wheel payload changed")
                os.fsync(descriptor)
                os.fsync(parent)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                os.close(parent)


def _seal_owner_wheels(root: int) -> None:
    """Seal complete regular payloads using descriptor-relative traversal."""
    with closing(_source_events(root)) as events:
        for kind, name, current in events:
            if os.fstat(current).st_uid != os.geteuid():
                raise ValueError("foreign owner wheel directory")
            if kind == "file":
                descriptor, metadata = _regular_source(current, name)
                try:
                    if metadata.st_uid != os.geteuid():
                        raise ValueError("foreign owner wheel file")
                    os.fchmod(descriptor, 0o444)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            elif kind == "leave":
                if name:
                    os.fchmod(current, 0o555)
                os.fsync(current)


def _owner_wheel_selection(
    bundle: Path, manifest: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, tuple[str, str]], dict[str, str]]:
    selection = manifest["components"]["host"]
    if selection["distribution"] != "fishhat-host" or selection["module"] != "fishhat_host":
        raise ValueError("unexpected owner component")
    with _BundleReader(bundle) as reader:
        pins = {}
        for line in reader.text(selection["lock"]).splitlines():
            match = re.fullmatch(
                r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.!+-]+) --hash=sha256:([a-f0-9]{64})", line
            )
            if match is None:
                raise ValueError("invalid owner wheel pin")
            name = re.sub(r"[-_.]+", "-", match[1]).lower()
            if name in pins:
                raise ValueError("ambiguous owner wheel pin")
            pins[name] = (match[2], match[3])
        if set(pins) != set(selection["dependencies"]):
            raise ValueError("owner dependency selection changed")
    selected = {}
    for name, metadata in manifest["files"].items():
        if name.startswith("wheels/") and name.endswith(".whl"):
            parts = name.removeprefix("wheels/").split("-")
            distribution = re.sub(r"[-_.]+", "-", parts[0]).lower()
            if distribution not in pins:
                continue
            if (
                len(parts) not in (5, 6)
                or "/" in name.removeprefix("wheels/")
                or distribution in selected
                or (parts[1], metadata["sha256"]) != pins[distribution]
            ):
                raise ValueError("ambiguous or changed owner wheel")
            selected[distribution] = name
    if set(selected) != set(pins):
        raise ValueError("incomplete owner wheel closure")
    return selection, pins, selected


def _install_owner_wheels(bundle: Path, destination: Path, expected: str) -> Path:
    """Retain/seal only approved host wheel payloads in a fresh Linux prefix.

    This root-layout materializer does not resolve dependencies, activate console
    scripts, execute packages, initialize owner state or accept operation inputs.
    The independently approved manifest/lock owns the selected runtime closure.
    An interrupted candidate remains private and is never adopted implicitly.
    """
    destination = destination.absolute()
    parent = _protected_parent(destination)
    source = None
    installed = None
    wheels = None
    library = None
    try:
        source = _directory_fd(bundle, protected=True)
        manifest = verify(bundle, expected)
        selection, pins, selected = _owner_wheel_selection(bundle, manifest)
        os.mkdir(destination.name, mode=0o700, dir_fd=parent)
        installed = _source_directory(parent, (destination.name,))
        wheels = _wheel_directory(installed, ("wheels",))
        library = _wheel_directory(installed, ("lib",))
        for relative in ("manifest.json", selection["lock"]):
            parts = _member_parts(relative)
            source_parent = _source_directory(source, parts[:-1])
            target_parent = _wheel_directory(installed, parts[:-1])
            try:
                _copy_regular(source_parent, parts[-1], Path(parts[-1]), parent=target_parent)
            finally:
                os.close(source_parent)
                os.close(target_parent)
        if sha256(destination / "manifest.json") != expected:
            raise ValueError("owner manifest changed")
        lock = selection["lock"]
        if sha256(destination / lock) != manifest["files"][lock]["sha256"]:
            raise ValueError("owner lock changed")
        wheel_source = _source_directory(source, ("wheels",))
        try:
            for distribution, name in selected.items():
                filename = _member_parts(name)[-1]
                _copy_regular(
                    wheel_source,
                    filename,
                    Path(filename),
                    parent=wheels,
                    expected_size=manifest["files"][name]["size"],
                )
                retained = destination / "wheels" / filename
                if sha256(retained) != pins[distribution][1]:
                    raise ValueError("owner wheel changed")
                _unpack_owner_wheel(retained, library, distribution, pins[distribution][0])
        finally:
            os.close(wheel_source)
        _seal_owner_wheels(installed)
        os.fsync(parent)
        os.fchmod(installed, 0o555)
        os.fsync(installed)
        return destination / "lib"
    except BaseException:
        if installed is not None:
            try:
                os.fchmod(installed, 0o700)
            except OSError:
                pass
        raise
    finally:
        for descriptor in (library, wheels, installed, source, parent):
            if descriptor is not None:
                os.close(descriptor)


def _owner_entrypoint_program(library: Path) -> bytes:
    """Render one installation-bound import root, never a request-selected program."""
    if not library.is_absolute() or ".." in library.parts or "\0" in str(library):
        raise ValueError("unsafe owner library path")
    return (
        "import sys\n"
        f"sys.path.insert(0, {str(library)!a})\n"
        "from fishhat_host.cli import main\n"
        "raise SystemExit(main())\n"
    ).encode("ascii")


def _write_owner_entrypoint_program(installed: int, raw: bytes) -> None:
    descriptor = os.open(
        "host-ops.py",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=installed,
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fchmod(stream.fileno(), 0o444)
        os.fsync(stream.fileno())


def _seal_owner_entrypoint(installed: int) -> None:
    descriptor = os.open("host-ops", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=installed)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("unsafe installed host command")
        if "security.capability" in os.listxattr(descriptor):
            raise ValueError("unexpected host command file capability")
        os.fchmod(descriptor, 0o555)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(installed)
    os.fchmod(installed, 0o555)
    os.fsync(installed)


def _install_owner_entrypoint(
    bundle: Path,
    runtime_archive: Path,
    launcher_inputs: Path,
    destination: Path,
    *,
    manifest_sha256: str,
    launcher_manifest_sha256: str,
) -> Path:
    """Compose approved inputs into a fresh, fixed, protected host command.

    Installation authority selects every input and the destination. The outer
    directory stays private until the selected runtime, complete host-wheel
    closure, fixed program and exact static command have been synchronized.
    Existing and interrupted installations are preserved and refused. This
    materializer executes no candidate code and initializes no owner state.
    """
    destination = destination.absolute()
    parent = _protected_parent(destination)
    installed = None
    launcher = None
    try:
        os.mkdir(destination.name, mode=0o700, dir_fd=parent)
        installed = _source_directory(parent, (destination.name,))
        interpreter = _install_owner_python(runtime_archive, destination / "runtime")
        library = _install_owner_wheels(bundle, destination / "packages", manifest_sha256)
        program = destination / "host-ops.py"
        raw = _owner_entrypoint_program(library)
        _write_owner_entrypoint_program(installed, raw)
        executable = _install_owner_launcher(
            launcher_inputs, destination / "launcher", launcher_manifest_sha256
        )
        manifest = json.loads((destination / "launcher/launcher.json").read_bytes())
        if manifest["interpreter"]["path"] != str(interpreter) or manifest["program"] != {
            "path": str(program),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }:
            raise ValueError("host command target binding changed")
        launcher = _directory_fd(executable.parent, protected=True)
        expected = manifest["files"]["launch"]
        _copy_regular(
            launcher,
            executable.name,
            Path("host-ops"),
            parent=installed,
            expected_size=expected["bytes"],
        )
        command = destination / "host-ops"
        if sha256(command) != expected["sha256"]:
            raise ValueError("installed host command changed")
        _seal_owner_entrypoint(installed)
        os.fsync(parent)
        return command
    except BaseException:
        if installed is not None:
            try:
                os.fchmod(installed, 0o700)
            except OSError:
                pass
        raise
    finally:
        for descriptor in (launcher, installed, parent):
            if descriptor is not None:
                os.close(descriptor)


def install(
    bundle: Path, destination: Path, component: str, expected: str, *, timeout_seconds: float = 180
) -> Path:
    import venv

    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("invalid installation timeout")
    manifest = verify(bundle, expected)
    if component not in manifest["components"] or destination.exists():
        raise ValueError("unknown component or existing installation destination")
    lock = bundle / manifest["components"][component]["lock"]
    venv.EnvBuilder(with_pip=True, symlinks=sys.platform != "win32").create(destination)
    python = destination / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    command = [
        str(python),
        "-I",
        "-m",
        "pip",
        "--isolated",
        "install",
        "--no-index",
        "--no-cache-dir",
        "--require-hashes",
        "--only-binary=:all:",
        "--find-links",
        str(bundle / "wheels"),
        "-r",
        str(lock),
    ]
    subprocess.run(command, check=True, capture_output=True, timeout=timeout_seconds)
    return python


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify or install a reference-scaffold bundle using an independently trusted manifest hash"
    )
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--component")
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    try:
        if args.component is None and args.destination is None:
            verify(args.bundle, args.manifest_sha256)
        elif args.component is not None and args.destination is not None:
            install(args.bundle, args.destination, args.component, args.manifest_sha256)
        else:
            raise ValueError("component and destination must be selected together")
    except (ValueError, KeyError, OSError, subprocess.SubprocessError):
        raise SystemExit("scaffold bundle verification or installation failed") from None
    print(json.dumps({"passed": True, "production_qualified": False}))


if __name__ == "__main__":
    main()
