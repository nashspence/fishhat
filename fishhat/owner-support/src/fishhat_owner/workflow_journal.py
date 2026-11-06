"""Durable append-only workflow custody; no native authority or execution.

The caller supplies a protected owner directory and independently approved schema
identity. One locked file belongs to one owner epoch. Missing stores never become
empty state, and interrupted/corrupt records never disappear during restoration.
"""

from __future__ import annotations

import copy
import hashlib
import os
import stat
import struct
import tempfile
import threading
import uuid
from collections.abc import Callable, Iterator, Mapping, MutableMapping
from contextlib import AbstractContextManager, ExitStack, contextmanager
from pathlib import Path
from typing import Any

from fishhat_contracts.bounds import Bounds, bounds
from fishhat_contracts.validation import ContractError, canonical, strict_json, validate

_MAGIC = b"fishhat.workflow-journal-store/v1\n"
_DOMAIN = b"fishhat.workflow-journal-frame/v1\x00"
_ZERO = bytes(32)
_CHUNK = 65536
_HEAD_MAGIC = b"fishhat.workflow-journal-head/v1\n"
_HEAD_DOMAIN = b"fishhat.workflow-journal-head-checksum/v1\x00"
Reader = Callable[[dict[str, Any]], None]
Checkpoint = Callable[[str | None, str], None]
WriterLease = AbstractContextManager[Checkpoint]


def _bounds(name: str) -> Bounds:
    return Bounds(
        id="workflow.journal-store." + name,
        work="O(B) selected new/replayed record bytes; cold open reads and validates each retained frame once",
        extent="Complete journal and selected records; no history or record-count ceiling",
        limits=(("io_chunk_bytes", _CHUNK),),
        capacity=(
            "Protected owner filesystem capacity; failure retains uncertainty and blocks appends",
        ),
        proofs=(
            "tests/test_workflow_journal.py::test_complete_workflow_survives_disk_restart_and_lost_replies",
        ),
        linear_proofs=(
            "tests/test_workflow_journal_growth.py::test_complete_multi_owner_workflow_is_linear",
        ),
    )


def _require(value: bool, message: str) -> None:
    if not value:
        raise ContractError(message)


@bounds(_bounds("genesis"))
def validate_journal_genesis(
    value: dict[str, Any],
    *,
    expected_owner: dict[str, Any] | None = None,
    expected_schema: dict[str, Any] | None = None,
) -> None:
    """Check the immutable owner/epoch/schema identity, never native storage authority."""
    _require(
        set(value) == {"format", "kind", "journal_id", "owner", "schema"}
        and value["format"] == "fishhat.workflow-journal-store/v1"
        and value["kind"] == "genesis",
        "workflow journal genesis format changed",
    )
    validate("common.schema.json", value["journal_id"], "UUID")
    validate("common.schema.json", value["owner"], "Owner")
    validate("common.schema.json", value["schema"], "SchemaIdentity")
    _require(
        expected_owner is None or value["owner"] == expected_owner,
        "workflow journal owner or epoch changed",
    )
    _require(
        expected_schema is None or value["schema"] == expected_schema,
        "workflow journal schema changed",
    )


class WorkflowJournal:
    """One exclusive writer with exact event replay and independently approved custody.

    Authorization of new protocol work belongs to the gate/member; every lookup
    requires current read authority. A failed append poisons that writer until a
    cold reopen verifies the entire file. An independently fsynced fixed-size HEAD
    detects deletion of complete accepted tail frames. Any uncommitted tail fails
    closed for explicit repair. A separately authenticated checkpoint enables
    read-only inspection of the committed prefix. Repair quarantines the exact
    suffix and requires durable native reconciliation before reopening. Rolling
    back both file and HEAD requires an independent protected monotone checkpoint
    to detect; native anti-rollback and filesystem qualification remain separate.
    """

    def __init__(self, fd: int, metrics: MutableMapping[str, int] | None) -> None:
        self._fd = fd
        self.metrics = metrics if metrics is not None else {}
        self._lock = threading.RLock()
        self._source_reads = 0
        self._head = _ZERO
        self._index: dict[str, tuple[dict[str, Any], bytes, bytes, bytes]] = {}
        self._genesis: dict[str, Any] = {}
        self._reader: Reader | None = None
        self._prefix_size: int | None = None
        self._prefix_local_head: tuple[str, int, int, bytes] | None = None
        self._writer = ExitStack()
        self._retain_head: Checkpoint | None = None
        self._failed = False
        self._closed = False
        self._path: Path | None = None

    def _acquire_writer(self, lease: WriterLease) -> None:
        checkpoint = self._writer.enter_context(lease)
        _require(callable(checkpoint), "independent writer lease lacks checkpoint authority")
        self._retain_head = checkpoint

    def _count(self, name: str, amount: int = 1) -> None:
        self.metrics[name] = self.metrics.get(name, 0) + amount

    def _encode(self, value: Any) -> bytes:
        data = canonical(value)
        self._count("bytes_serialized", len(data))
        return data

    def _hash(self, previous: bytes, size: bytes, data: bytes) -> bytes:
        checksum = hashlib.sha256()
        for part in (_DOMAIN, previous, size, data):
            checksum.update(part)
            self._count("bytes_hashed", len(part))
        return checksum.digest()

    def _write(self, data: bytes) -> None:
        self._write_on(self._fd, data)

    def _write_on(self, fd: int, data: bytes) -> None:
        remaining = memoryview(data)
        while remaining:
            written = os.write(fd, remaining[:_CHUNK])
            _require(written > 0, "workflow journal write made no progress")
            self._count("bytes_written", written)
            remaining = remaining[written:]

    def _read(self, length: int) -> bytes:
        return self._read_on(self._fd, length)

    def _read_on(self, fd: int, length: int) -> bytes:
        pieces = bytearray()
        while len(pieces) < length:
            part = os.read(fd, min(_CHUNK, length - len(pieces)))
            _require(bool(part), "workflow journal truncated record")
            pieces.extend(part)
            self._count("bytes_read", len(part))
        return bytes(pieces)

    def _sync(self) -> None:
        self._count("fsync_calls")
        os.fsync(self._fd)

    def _sync_directory(self) -> None:
        assert self._path is not None
        fd = os.open(self._path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            self._count("fsync_calls")
            os.fsync(fd)
        finally:
            os.close(fd)

    def _head_checksum(self, data: bytes) -> bytes:
        self._count("bytes_hashed", len(_HEAD_DOMAIN) + len(data))
        return hashlib.sha256(_HEAD_DOMAIN + data).digest()

    def _publish_head(self, checksum: bytes, sequence: int) -> None:
        self._write_local_head(checksum, sequence, os.fstat(self._fd).st_size)
        assert self._retain_head is not None
        self._retain_head(None if sequence == 0 else self.head, "sha256:" + checksum.hex())

    def _write_local_head(self, checksum: bytes, sequence: int, size: int) -> None:
        assert self._path is not None
        body = (
            _HEAD_MAGIC
            + uuid.UUID(self.journal_id).bytes
            + struct.pack(">QQ", sequence, size)
            + checksum
        )
        data = body + self._head_checksum(body)
        self._count("bytes_serialized", len(data))
        target = self._path.with_name(self._path.name + ".head")
        temporary = target.with_name(target.name + ".pending-" + str(uuid.uuid4()))
        fd = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600
        )
        try:
            self._write_on(fd, data)
            self._count("fsync_calls")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, target)
        self._sync_directory()

    def _read_head(self) -> tuple[str, int, int, bytes]:
        assert self._path is not None
        target = self._path.with_name(self._path.name + ".head")
        fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            _require(
                stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                "workflow journal HEAD is not protected regular custody",
            )
            _require(info.st_size == len(_HEAD_MAGIC) + 96, "workflow journal HEAD size changed")
            data = self._read_on(fd, info.st_size)
        finally:
            os.close(fd)
        body, checksum = data[:-32], data[-32:]
        self._count("bytes_parsed", len(data))
        _require(
            body.startswith(_HEAD_MAGIC) and self._head_checksum(body) == checksum,
            "workflow journal HEAD changed",
        )
        position = len(_HEAD_MAGIC)
        identity = str(uuid.UUID(bytes=body[position : position + 16]))
        sequence, size = struct.unpack(">QQ", body[position + 16 : position + 32])
        return identity, sequence, size, body[-32:]

    @staticmethod
    def _descriptor(path: str | Path, *, create: bool, read_only: bool = False) -> int:
        try:
            import fcntl
        except ModuleNotFoundError as exc:
            raise ContractError("workflow journal requires POSIX file custody") from exc

        flags = (os.O_RDONLY if read_only else os.O_RDWR) | os.O_CLOEXEC | os.O_NOFOLLOW
        if create:
            _require(
                not os.path.lexists(str(path) + ".head"),
                "workflow journal HEAD custody already exists",
            )
            flags |= os.O_CREAT | os.O_EXCL
        fd = os.open(path, flags, 0o600)
        try:
            info = os.fstat(fd)
            _require(stat.S_ISREG(info.st_mode), "workflow journal is not a regular file")
            _require(info.st_nlink == 1, "workflow journal has an aliased native file")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(fd)
            raise
        return fd

    @classmethod
    @bounds(_bounds("create"))
    def create(
        cls,
        path: str | Path,
        *,
        owner: dict[str, Any],
        schema: dict[str, Any],
        writer_lease: WriterLease,
        metrics: MutableMapping[str, int] | None = None,
    ) -> WorkflowJournal:
        """Explicitly create new owner custody and fsync both file and directory."""
        validate("common.schema.json", owner, "Owner")
        validate("common.schema.json", schema, "SchemaIdentity")
        journal = cls(cls._descriptor(path, create=True), metrics)
        journal._path = Path(path)
        try:
            journal._acquire_writer(writer_lease)
            genesis = {
                "format": "fishhat.workflow-journal-store/v1",
                "kind": "genesis",
                "journal_id": str(uuid.uuid4()),
                "owner": copy.deepcopy(owner),
                "schema": copy.deepcopy(schema),
            }
            validate_journal_genesis(genesis)
            journal._write(_MAGIC)
            data = journal._encode(genesis)
            length = struct.pack(">Q", len(data))
            checksum = journal._hash(_ZERO, length, data)
            journal._write(length)
            journal._write(data)
            journal._write(checksum)
            journal._sync()
            journal._genesis, journal._head = genesis, checksum
            journal._publish_head(checksum, 0)
            journal._count("frames_appended")
            return journal
        except BaseException:
            journal.close()
            raise

    @classmethod
    @bounds(_bounds("open"))
    def open(
        cls,
        path: str | Path,
        *,
        expected_owner: dict[str, Any],
        expected_schema: dict[str, Any],
        historical_readers: Mapping[tuple[str, str], Reader] | None = None,
        verified_prefix_head: str | None = None,
        writer_lease: WriterLease | None = None,
        metrics: MutableMapping[str, int] | None = None,
    ) -> WorkflowJournal:
        """Verify complete custody, or inspect an independently authenticated prefix.

        Writable access holds an independently commissioned exclusive lease through
        close, including guard, native acceptance and checkpoint publication. The same
        lease excludes every other copy of this logical journal and epoch. Its
        checkpoint compare-and-swap is backed by custody outside the rollback domain
        of the journal and HEAD. It verifies expected == current and durably sets
        the new head or raises. None means genesis requires absent custody. Reopen
        compares the verified local head to the independently retained current head
        without advancing it. Publication failures prevent acknowledgement.
        Only protected owner recovery supplies verified_prefix_head, from a current
        anti-rollback checkpoint independent of the journal and its HEAD. This
        selects a read-only view ending at that exact frame, even when the local
        HEAD was published ahead of independent custody. Only the checked prefix
        enters the index. A partial/invalid committed frame always fails.
        """
        validate("common.schema.json", expected_owner, "Owner")
        validate("common.schema.json", expected_schema, "SchemaIdentity")
        journal = cls(
            cls._descriptor(path, create=False, read_only=verified_prefix_head is not None), metrics
        )
        journal._path = Path(path)
        try:
            local_head = journal._read_head()
            head_id, head_sequence, head_size, head_digest = local_head
            size = os.fstat(journal._fd).st_size
            _require(
                (writer_lease is None) != (verified_prefix_head is None),
                "workflow journal requires one independent checkpoint for writable or prefix open",
            )
            if writer_lease is not None:
                journal._acquire_writer(writer_lease)
            _require(
                size == head_size or (verified_prefix_head is not None and size > head_size),
                "workflow journal truncated accepted history or uncommitted tail",
            )
            _require(journal._read(len(_MAGIC)) == _MAGIC, "workflow journal format changed")
            size = head_size
            offset, sequence = len(_MAGIC), 0
            while offset < size:
                _require(size - offset >= 40, "workflow journal truncated frame")
                length = journal._read(8)
                count = struct.unpack(">Q", length)[0]
                _require(0 < count <= size - offset - 40, "workflow journal truncated payload")
                data, checksum = journal._read(count), journal._read(32)
                _require(
                    journal._hash(journal._head, length, data) == checksum,
                    "workflow journal hash chain changed",
                )
                journal._count("bytes_parsed", count)
                record = strict_json(data, max_bytes=count)
                _require(
                    isinstance(record, dict) and journal._encode(record) == data,
                    "workflow journal noncanonical record",
                )
                if sequence == 0:
                    journal._load_genesis(
                        record, expected_owner, expected_schema, historical_readers
                    )
                else:
                    journal._load_event(record, data, checksum, sequence)
                journal._head = checksum
                journal._count("frames_read")
                offset += 40 + count
                sequence += 1
                if verified_prefix_head is not None and journal.head == verified_prefix_head:
                    journal._prefix_size = offset
                    journal._prefix_local_head = local_head
                    break
            if verified_prefix_head is not None:
                _require(
                    journal._prefix_size is not None, "independent checkpoint absent from journal"
                )
            _require(sequence > 0, "workflow journal missing genesis")
            _require(
                journal.journal_id == head_id
                and (
                    (
                        offset == head_size
                        and sequence == head_sequence + 1
                        and journal._head == head_digest
                    )
                    or (
                        offset < head_size
                        and sequence <= head_sequence
                        and journal._prefix_size == offset
                    )
                ),
                "workflow journal HEAD does not match complete history",
            )
            if journal._retain_head is not None:
                journal._retain_head(journal.head, journal.head)
                journal._sync()
                journal._sync_directory()
            return journal
        except BaseException:
            journal.close()
            raise

    @bounds(
        Bounds(
            id="workflow.journal-store.repair-tail",
            work="O(B) reads, hashes and quarantines every uncertain suffix byte once per attempt",
            extent="The complete suffix after the authenticated, already verified prefix",
            limits=(("io_chunk_bytes", _CHUNK),),
            capacity=("Insufficient quarantine capacity leaves live custody and admission fenced",),
            proofs=("tests/test_workflow_journal.py::test_uncertain_tail_repair_cost_and_custody",),
            linear_proofs=(
                "tests/test_workflow_journal.py::test_uncertain_tail_repair_cost_and_custody",
            ),
        )
    )
    def repair_tail(
        self, *, writer_lease: WriterLease, reconcile: Callable[[dict[str, Any], Path], bool]
    ) -> None:
        """Quarantine exact suffix bytes and require independent owner-native closure.

        reconcile is a protected receiving service, never a wire field. Under current
        repair authority it verifies this checkpoint and suffix against native custody,
        and durably establishes that dropping the suffix from the live journal loses
        no accepted work or outstanding obligations and permits no duplicate effect.
        A malformed suffix or interrupted append cannot itself prove nonacceptance.
        Unresolved effects return False. Closure is idempotent by journal, head and
        suffix digest across a crash before truncation. This view stays read-only.
        """
        with self._lock, writer_lease as retain_head:
            _require(
                not self._closed and self._prefix_size is not None,
                "workflow journal repair requires an authenticated committed prefix",
            )
            assert self._path is not None and self._prefix_size is not None
            retain_head(self.head, self.head)
            checkpoint = self._read_head()
            _require(
                checkpoint == self._prefix_local_head,
                "workflow journal checkpoint changed before repair",
            )
            tail_size = os.fstat(self._fd).st_size - self._prefix_size
            _require(tail_size > 0, "workflow journal has no uncertain tail")
            os.lseek(self._fd, self._prefix_size, os.SEEK_SET)
            fd, pending = tempfile.mkstemp(
                prefix=self._path.name + ".quarantine-pending-", dir=self._path.parent
            )
            hasher = hashlib.sha256()
            try:
                try:
                    remaining = tail_size
                    while remaining:
                        part = self._read(min(remaining, _CHUNK))
                        self._write_on(fd, part)
                        hasher.update(part)
                        self._count("bytes_hashed", len(part))
                        remaining -= len(part)
                    self._count("fsync_calls")
                    os.fsync(fd)
                finally:
                    os.close(fd)
                archive = self._path.with_name(
                    self._path.name + ".quarantine-" + hasher.hexdigest()
                )
                os.replace(pending, archive)
                self._sync_directory()
            finally:
                Path(pending).unlink(missing_ok=True)
            evidence = {
                "owner": self.owner,
                "journal_id": self.journal_id,
                "head": self.head,
                "sequence": len(self._index),
                "tail_size": tail_size,
                "tail_digest": "sha256:" + hasher.hexdigest(),
            }
            _require(
                reconcile(evidence, archive) is True, "uncertain journal tail lacks native closure"
            )
            _require(
                self._read_head() == checkpoint
                and os.fstat(self._fd).st_size == self._prefix_size + tail_size,
                "workflow journal custody changed during repair",
            )
            # The prefix itself has only a read descriptor and retains its inode lock.
            # Acquire write access solely for this authorized repair, on the same inode.
            fd = os.open(self._path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                _require(
                    os.path.samestat(os.fstat(fd), os.fstat(self._fd)),
                    "workflow journal repair target changed",
                )
                if checkpoint[2] != self._prefix_size:
                    # Publish the authenticated prefix before truncating: an interruption
                    # leaves the already supported old-HEAD-with-uncertain-tail shape.
                    self._write_local_head(self._head, len(self._index), self._prefix_size)
                os.ftruncate(fd, self._prefix_size)
                self._count("fsync_calls")
                os.fsync(fd)
            finally:
                os.close(fd)

    def _load_genesis(
        self,
        value: dict[str, Any],
        owner: dict[str, Any],
        schema: dict[str, Any],
        readers: Mapping[tuple[str, str], Reader] | None,
    ) -> None:
        validate_journal_genesis(value, expected_owner=owner)
        if value["schema"] != schema:
            key = (value["schema"]["uri"], value["schema"]["digest"])
            self._reader = (readers or {}).get(key)
            _require(
                value["schema"]["uri"] == schema["uri"] and self._reader is not None,
                "workflow journal historical reader is not independently installed",
            )
        self._genesis = value

    def _load_event(
        self, record: dict[str, Any], data: bytes, checksum: bytes, sequence: int
    ) -> None:
        _require(
            set(record) == {"kind", "sequence", "previous", "event_id", "request", "outcome"}
            and record["kind"] == "event"
            and type(record["sequence"]) is int
            and record["sequence"] == sequence
            and record["previous"] == self.head
            and isinstance(record["event_id"], str)
            and bool(record["event_id"])
            and record["event_id"] not in self._index,
            "workflow journal event identity or order changed",
        )
        if self._reader is not None:
            self._reader(record)
            _require(
                self._encode(record) == data, "workflow historical reader rewrote original bytes"
            )
        self._index[record["event_id"]] = (
            {**record, "receipt": self._receipt(record["event_id"], sequence, checksum)},
            data,
            self._encode(record["request"]),
            self._encode(record["outcome"]),
        )

    def _receipt(self, event_id: str, sequence: int, checksum: bytes) -> dict[str, Any]:
        return {
            "journal_id": self.journal_id,
            "event_id": event_id,
            "sequence": sequence,
            "digest": "sha256:" + checksum.hex(),
        }

    @property
    def head(self) -> str:
        return "sha256:" + self._head.hex()

    @property
    def owner(self) -> dict[str, Any]:
        return copy.deepcopy(self._genesis["owner"])

    @property
    def schema(self) -> dict[str, Any]:
        return copy.deepcopy(self._genesis["schema"])

    @property
    def journal_id(self) -> str:
        return str(self._genesis["journal_id"])

    @bounds(
        Bounds(
            id="workflow.journal-store.read-guard",
            work="O(1) per verified fixed-size head; no history or filesystem scan",
            extent="One exact held source checkpoint through the complete requested read",
            limits=(),
            capacity=(),
            proofs=("tests/test_workflow_journal.py::test_uncertain_tail_repair_cost_and_custody",),
            linear_proofs=(
                "tests/test_workflow_journal.py::test_uncertain_tail_repair_cost_and_custody",
            ),
        )
    )
    def read_guard(self, expected_head: str) -> AbstractContextManager[None]:
        """Pin one verified immutable head while reading its complete committed prefix."""
        return self._read_guard(expected_head)

    @contextmanager
    def _read_guard(self, expected_head: str) -> Iterator[None]:
        with self._lock:
            _require(not self._closed and not self._failed, "workflow journal reader unavailable")
            _require(expected_head == self.head, "workflow journal source head changed")
            self._count("source_read_guards")
            self._source_reads += 1
            try:
                yield
            finally:
                self._source_reads -= 1

    @bounds(_bounds("guard"))
    def guard(self, expected_head: str) -> AbstractContextManager[None]:
        """Hold the shared owner boundary through native acceptance or a new event.

        Several reference actors may use one installed store object. They share
        this lock and must present their retained predecessor before any new work;
        an actor-local mutex or append comparison alone cannot fence a stale
        actor's nonwriting native admission.
        """
        return self._guard(expected_head)

    @contextmanager
    def _guard(self, expected_head: str) -> Iterator[None]:
        with self._lock:
            _require(
                not self._closed
                and not self._failed
                and self._prefix_size is None
                and not self._source_reads,
                "workflow journal writer unavailable",
            )
            _require(expected_head == self.head, "workflow journal predecessor changed")
            yield

    @bounds(_bounds("lookup"))
    def lookup(self, event_id: str, *, read_authorized: bool) -> dict[str, Any] | None:
        _require(read_authorized is True, "current workflow journal read permission required")
        with self._lock:
            _require(not self._closed, "workflow journal closed")
            selected = self._index.get(event_id)
            if selected is None:
                return None
            self._count("replay_hits")
            self._count("bytes_returned", len(selected[1]))
            return copy.deepcopy(selected[0])

    @bounds(_bounds("outcome_bytes"))
    def outcome_bytes(self, event_id: str, *, read_authorized: bool) -> bytes:
        """Select original immutable outcome bytes without copying the full record.

        A delivery index hashes these bytes once on append or cold restoration.
        Repeated bounded chunk reads may reuse this immutable object; actual
        returned chunk bytes belong to that delivery boundary's measurements.
        """
        _require(read_authorized is True, "current workflow journal read permission required")
        with self._lock:
            _require(not self._closed, "workflow journal closed")
            selected = self._index.get(event_id)
            _require(selected is not None, "workflow journal outcome missing")
            assert selected is not None
            self._count("outcome_lookups")
            return selected[3]

    @bounds(_bounds("command_bytes"))
    def command_bytes(self, event_id: str, *, read_authorized: bool) -> bytes:
        """Select immutable accepted command bytes for bounded rediscovery reads."""
        _require(read_authorized is True, "current workflow journal read permission required")
        with self._lock:
            _require(not self._closed, "workflow journal closed")
            selected = self._index.get(event_id)
            _require(selected is not None, "workflow journal command missing")
            assert selected is not None
            self._count("command_lookups")
            return selected[2]

    @bounds(_bounds("append"))
    def append(
        self,
        event_id: str,
        request: Any,
        outcome: Any,
        *,
        expected_head: str,
    ) -> dict[str, Any]:
        """Commit exact new bytes before acknowledgment; the caller owns write authority."""
        with self._lock:
            _require(
                not self._closed
                and not self._failed
                and self._prefix_size is None
                and not self._source_reads,
                "workflow journal writer unavailable",
            )
            _require(
                isinstance(event_id, str) and bool(event_id), "workflow journal event id required"
            )
            request_bytes, outcome_bytes = self._encode(request), self._encode(outcome)
            previous = self._index.get(event_id)
            if previous is not None:
                _require(
                    request_bytes == previous[2] and outcome_bytes == previous[3],
                    "workflow journal changed accepted event",
                )
                self._count("replay_hits")
                self._count("bytes_returned", len(previous[1]))
                return copy.deepcopy(previous[0])
            _require(expected_head == self.head, "workflow journal predecessor changed")
            record = {
                "kind": "event",
                "sequence": len(self._index) + 1,
                "previous": self.head,
                "event_id": event_id,
                "request": copy.deepcopy(request),
                "outcome": copy.deepcopy(outcome),
            }
            data = self._encode(record)
            if self._reader is not None:
                self._reader(record)
                _require(
                    self._encode(record) == data,
                    "workflow historical reader rewrote original bytes",
                )
            length = struct.pack(">Q", len(data))
            checksum = self._hash(self._head, length, data)
            try:
                self._write(length)
                self._write(data)
                self._write(checksum)
                self._sync()
                self._publish_head(checksum, record["sequence"])
            except BaseException:
                self._failed = True
                raise
            result = {**record, "receipt": self._receipt(event_id, record["sequence"], checksum)}
            self._index[event_id] = (result, data, request_bytes, outcome_bytes)
            self._head = checksum
            self._count("frames_appended")
            self._count("bytes_returned", len(data))
            return copy.deepcopy(result)

    @bounds(_bounds("iter_events"))
    def iter_events(self, *, read_authorized: bool) -> Iterator[dict[str, Any]]:
        _require(read_authorized is True, "current workflow journal read permission required")
        _require(not self._closed, "workflow journal closed")
        # Dictionary insertion order is the already validated immutable log order.
        # Native restoration excludes concurrent appends while consuming this view.
        for record, data, _, _ in self._index.values():
            self._count("bytes_returned", len(data))
            yield copy.deepcopy(record)

    @bounds(_bounds("close"))
    def close(self) -> None:
        with self._lock:
            if not self._closed:
                try:
                    os.close(self._fd)
                finally:
                    self._closed = True
                    self._writer.close()
