"""Protected current-checkpoint storage, separate from permission to run a writer.

The installed custodian supplies the context. This backend neither authenticates
clients nor establishes continuity or exclusion of old executors. Its stable
anchor serializes participating storage operations; writable journal authority
still needs those independently established facts.
"""

from __future__ import annotations

import copy
import os
import re
import stat
import sys
import threading
from collections.abc import Iterator, MutableMapping
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any

from fishhat_contracts.bounds import Bounds, bounds
from fishhat_contracts.validation import ContractError, canonical, strict_json, validate

FORMAT = "fishhat.checkpoint-store/v1"
ANCHOR = "anchor"
CURRENT = "current"
PENDING = ".pending"
_CHUNK = 65536
_HEAD = re.compile(r"[0-9a-f]{64}")


def _bounds(name: str) -> Bounds:
    return Bounds(
        id="owner.checkpoint-store." + name,
        work="O(P + B) complete protected path bytes and selected current-record bytes",
        extent="One exact commissioned binding and complete current checkpoint; no journal-history scan",
        limits=(("io_chunk_bytes", _CHUNK),),
        capacity=(
            "Protected authority storage capacity; uncertainty prevents continued publication",
        ),
        proofs=(
            "tests/test_protected_checkpoint_store.py::test_compare_and_swap_and_nonmutating_inspection",
        ),
        linear_proofs=tuple(
            "tests/test_protected_checkpoint_store.py::" + proof
            for proof in {
                "initialize": ("test_complete_path_work_is_linear_and_closes_on_rejection",),
                "open": (
                    "test_complete_path_work_is_linear_and_closes_on_rejection",
                    "test_complete_record_refusal_work_is_linear",
                ),
                "read": ("test_complete_record_refusal_work_is_linear",),
                "publish": ("test_complete_publication_work_is_linear",),
            }[name]
        ),
    )


def _require(value: bool, message: str) -> None:
    if not value:
        raise ContractError(message)


def _count(metrics: MutableMapping[str, int], name: str, amount: int = 1) -> None:
    metrics[name] = metrics.get(name, 0) + amount


def _directory_metadata(descriptor: int, *, private: bool) -> None:
    row = os.fstat(descriptor)
    _require(
        stat.S_ISDIR(row.st_mode)
        and row.st_uid == row.st_gid == 0
        and not row.st_mode & 0o7022
        and (not private or stat.S_IMODE(row.st_mode) == 0o700)
        and "security.capability" not in os.listxattr(descriptor),
        "protected checkpoint directory required",
    )


@contextmanager
def _directory(path: Path, metrics: MutableMapping[str, int]) -> Iterator[int]:
    _require(
        sys.platform == "linux" and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0),
        "administrative checkpoint custody required",
    )
    parts = path.parts
    _require(
        path.is_absolute() and parts[0] == "/" and ".." not in parts,
        "absolute checkpoint custody required",
    )
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        _directory_metadata(descriptor, private=len(parts) == 1)
        for index, part in enumerate(parts[1:], 1):
            child = os.open(part, flags, dir_fd=descriptor)
            previous, descriptor = descriptor, child
            os.close(previous)
            _count(metrics, "path_components_opened")
            _count(metrics, "path_bytes_opened", len(os.fsencode(part)))
            _directory_metadata(descriptor, private=index == len(parts) - 1)
        yield descriptor
    finally:
        os.close(descriptor)


def _regular(descriptor: int, *, anchor: bool = False) -> os.stat_result:
    row = os.fstat(descriptor)
    _require(
        stat.S_ISREG(row.st_mode)
        and row.st_uid == os.geteuid()
        and row.st_gid == os.getegid()
        and row.st_nlink == 1
        and stat.S_IMODE(row.st_mode) == 0o600
        and (not anchor or row.st_size == 0)
        and "security.capability" not in os.listxattr(descriptor),
        "private single-link checkpoint file required",
    )
    return row


def _identity(row: os.stat_result) -> dict[str, int]:
    return {"device": row.st_dev, "inode": row.st_ino}


def _head(value: Any) -> None:
    _require(
        value is None or (isinstance(value, str) and _HEAD.fullmatch(value) is not None),
        "invalid checkpoint head",
    )


def _binding(owner: dict[str, Any], journal_id: str) -> dict[str, Any]:
    validate("common.schema.json", owner, "Owner")
    validate("common.schema.json", journal_id, "UUID")
    return {"owner": copy.deepcopy(owner), "journal_id": journal_id}


def _decode_record(
    raw: bytes, binding: dict[str, Any], anchor_identity: dict[str, int]
) -> dict[str, Any]:
    value = strict_json(raw, max_bytes=len(raw))
    if not isinstance(value, dict):
        raise ContractError("checkpoint format changed")
    _require(
        set(value) == {"format", "owner", "journal_id", "anchor", "previous", "current"},
        "checkpoint format changed",
    )
    _require(
        value["format"] == FORMAT
        and value["owner"] == binding["owner"]
        and value["journal_id"] == binding["journal_id"],
        "checkpoint binding changed",
    )
    _require(
        value["anchor"] == anchor_identity
        and all(type(item) is int for item in value["anchor"].values()),
        "checkpoint anchor identity changed",
    )
    _head(value["previous"])
    _head(value["current"])
    _require(
        value["current"] is not None or value["previous"] is None,
        "checkpoint history binding changed",
    )
    _require(raw == canonical(value) + b"\n", "noncanonical checkpoint custody")
    return value


def _absent(directory: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ContractError("incomplete checkpoint publication retained")


def _layout(directory: int, *, fresh: bool = False) -> None:
    with os.scandir(directory) as entries:
        for entry in entries:
            _require(
                not fresh and entry.name in (ANCHOR, CURRENT),
                "fresh checkpoint custody required" if fresh else "foreign checkpoint custody",
            )


def _sync(descriptor: int, metrics: MutableMapping[str, int]) -> None:
    os.fsync(descriptor)
    _count(metrics, "successful_syncs")


def _write_pending(
    directory: int, value: dict[str, Any], metrics: MutableMapping[str, int]
) -> None:
    raw = canonical(value) + b"\n"
    _count(metrics, "record_bytes_serialized", len(raw))
    descriptor = os.open(
        PENDING,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=directory,
    )
    try:
        os.fchmod(descriptor, 0o600)
        _regular(descriptor)
        remaining = memoryview(raw)
        while remaining:
            count = os.write(descriptor, remaining[:_CHUNK])
            _require(count > 0, "checkpoint write made no progress")
            _count(metrics, "record_bytes_written", count)
            remaining = remaining[count:]
        _sync(descriptor, metrics)
    finally:
        os.close(descriptor)


class CheckpointStore:
    """An installed custodian's storage handle; not a writer-lease capability.

    The directory pair is independently selected installation context, never an
    operation parameter. The first Linux construction keeps authority outside
    the journal filesystem's capture boundary. A descriptor identity change is
    refused; relocation and restored custody need explicit recovery.
    """

    def __init__(self) -> None:
        self._stack = ExitStack()
        self._metrics: MutableMapping[str, int] = {}
        self._mutex = threading.Lock()
        self._pid = os.getpid()
        self._thread: int | None = None
        self._exclusive = False
        self._closed = False
        self._poisoned = False
        self._directory = -1
        self._anchor = -1
        self._anchor_identity: dict[str, int] = {}
        self._binding: dict[str, Any] = {}

    @classmethod
    def _pin(
        cls,
        authority: Path,
        journal: Path,
        owner: dict[str, Any],
        journal_id: str,
        metrics: MutableMapping[str, int] | None,
    ) -> CheckpointStore:
        store = cls()
        store._metrics = metrics if metrics is not None else {}
        store._binding = _binding(owner, journal_id)
        try:
            store._directory = store._stack.enter_context(_directory(authority, store._metrics))
            journal_fd = store._stack.enter_context(_directory(journal, store._metrics))
            _require(
                os.fstat(store._directory).st_dev != os.fstat(journal_fd).st_dev,
                "independent journal capture domain required",
            )
            return store
        except BaseException:
            store._stack.close()
            raise

    def _open_anchor(self, *, create: bool = False) -> None:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        if create:
            flags |= os.O_CREAT | os.O_EXCL
        self._anchor = os.open(ANCHOR, flags, 0o600, dir_fd=self._directory)
        self._stack.callback(os.close, self._anchor)
        if create:
            os.fchmod(self._anchor, 0o600)
        self._anchor_identity = _identity(_regular(self._anchor, anchor=True))
        if create:
            _sync(self._anchor, self._metrics)

    @classmethod
    @bounds(_bounds("initialize"))
    def initialize(
        cls,
        authority: Path,
        journal: Path,
        *,
        owner: dict[str, Any],
        journal_id: str,
        metrics: MutableMapping[str, int] | None = None,
    ) -> dict[str, Any]:
        """Publish fresh non-admitting checkpoint custody without adopting a candidate."""
        store = cls._pin(authority, journal, owner, journal_id, metrics)
        try:
            _layout(store._directory, fresh=True)
            store._open_anchor(create=True)
            with store.locked():
                value = {
                    "format": FORMAT,
                    **store._binding,
                    "anchor": store._anchor_identity,
                    "previous": None,
                    "current": None,
                }
                _write_pending(store._directory, value, store._metrics)
                os.link(
                    PENDING,
                    CURRENT,
                    src_dir_fd=store._directory,
                    dst_dir_fd=store._directory,
                    follow_symlinks=False,
                )
                os.unlink(PENDING, dir_fd=store._directory)
                _sync(store._directory, store._metrics)
                return copy.deepcopy(value)
        finally:
            store.close()

    @classmethod
    @bounds(_bounds("open"))
    def open(
        cls,
        authority: Path,
        journal: Path,
        *,
        owner: dict[str, Any],
        journal_id: str,
        metrics: MutableMapping[str, int] | None = None,
    ) -> CheckpointStore:
        """Verify existing custody; absence, conflicts and pending work remain fenced."""
        store = cls._pin(authority, journal, owner, journal_id, metrics)
        try:
            store._open_anchor()
            store.read()
            return store
        except BaseException:
            store.close()
            raise

    def _live(self) -> None:
        _require(os.getpid() == self._pid, "inherited checkpoint handle is unavailable")
        _require(not self._closed and not self._poisoned, "checkpoint handle is unavailable")

    def _anchor_current(self) -> None:
        held = _regular(self._anchor, anchor=True)
        linked = os.stat(ANCHOR, dir_fd=self._directory, follow_symlinks=False)
        _require(
            _identity(held) == _identity(linked) == self._anchor_identity,
            "checkpoint anchor changed",
        )

    @contextmanager
    def _locked(self, *, shared: bool) -> Iterator[CheckpointStore]:
        import fcntl

        self._live()
        _require(self._mutex.acquire(blocking=False), "checkpoint handle already in use")
        locked = False
        try:
            self._live()
            fcntl.flock(self._anchor, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
            locked = True
            self._thread = threading.get_ident()
            self._exclusive = not shared
            self._anchor_current()
            yield self
        finally:
            self._thread = None
            self._exclusive = False
            try:
                if locked and os.getpid() == self._pid:
                    fcntl.flock(self._anchor, fcntl.LOCK_UN)
            finally:
                self._mutex.release()

    @contextmanager
    def locked(self) -> Iterator[CheckpointStore]:
        """Retain the stable storage mutex; this grants no journal execution permission."""
        with self._locked(shared=False):
            yield self

    def _read(self) -> dict[str, Any]:
        self._anchor_current()
        _layout(self._directory)
        _absent(self._directory, PENDING)
        descriptor = os.open(
            CURRENT, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._directory
        )
        try:
            before = _regular(descriptor)
            parts = []
            while part := os.read(descriptor, _CHUNK):
                parts.append(part)
                _count(self._metrics, "record_bytes_read", len(part))
            after = _regular(descriptor)
            _require(
                (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "checkpoint changed while reading",
            )
            raw = b"".join(parts)
            _require(len(raw) == before.st_size, "checkpoint extent changed")
        finally:
            os.close(descriptor)
        return _decode_record(raw, self._binding, self._anchor_identity)

    @bounds(_bounds("read"))
    def read(self) -> dict[str, Any]:
        """Read the complete existing checkpoint without changing authority state."""
        with self._locked(shared=True):
            return self._read()

    @bounds(_bounds("publish"))
    def compare_and_swap(self, expected: str | None, current: str) -> dict[str, Any]:
        """Publish only under the held storage mutex after exact-current comparison."""
        self._live()
        _require(
            self._thread == threading.get_ident() and self._exclusive,
            "held exclusive checkpoint mutex required",
        )
        _head(expected)
        _head(current)
        _require(current is not None, "published checkpoint head required")
        before = self._read()
        _require(before["current"] == expected, "checkpoint compare conflict")
        if current == expected:
            return before
        value = {**before, "previous": expected, "current": current}
        try:
            _write_pending(self._directory, value, self._metrics)
            self._anchor_current()
            os.replace(PENDING, CURRENT, src_dir_fd=self._directory, dst_dir_fd=self._directory)
            _sync(self._directory, self._metrics)
        except BaseException:
            self._poisoned = True
            raise
        return copy.deepcopy(value)

    def close(self) -> None:
        if self._closed:
            return
        _require(os.getpid() == self._pid, "inherited checkpoint handle is unavailable")
        _require(self._mutex.acquire(blocking=False), "checkpoint handle is still in use")
        try:
            self._stack.close()
        finally:
            self._closed = True
            self._mutex.release()

    def __enter__(self) -> CheckpointStore:
        self._live()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
