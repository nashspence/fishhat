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
