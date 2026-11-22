"""Ordinary-file checkpoint mechanics with administrative enrollment replaced."""

import copy
import errno
import json
import os
import signal
import stat
from types import SimpleNamespace

import pytest
from fishhat_contracts import ContractError
from fishhat_contracts.validation import canonical
from fishhat_owner import checkpoint_store as store
from fishhat_owner import identity_store

from scripts.validation_timeouts import watchdog
from tests.checkpoint_process_support import child_process, ordinary_enrollment, receive, send
from tests.support import ROOT

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "fishhat/owner-support/src/fishhat_owner/checkpoint_store.py",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-journal.schema.json#/$defs/ProtocolRules",
    ],
    "scope": "ordinary-file current-checkpoint CAS, stable anchor, preserved failure custody and counted complete work",
    "relationship": "candidate",
    "reason": "Administrative directory and independent capture-domain enrollment are replaced for temporary files. These storage tests grant no writer authority and require separate protected installed/native observations.",
    "claims": [],
}


CHECK_OVERRIDES = {
    name: {
        **CHECK_PURPOSE,
        "authority": [
            "fishhat/owner-support/src/fishhat_owner/checkpoint_store.py#CheckpointStore."
            + ("compare_and_swap" if operation == "publish" else operation)
            for operation in operations
        ],
        "relationship": "scoped-witness",
        "claims": ["engineering:owner.checkpoint-store." + operation for operation in operations],
    }
    for name, operations in {
        "test_compare_and_swap_and_nonmutating_inspection": (
            "initialize",
            "open",
            "read",
            "publish",
        ),
        "test_complete_path_work_is_linear_and_closes_on_rejection": ("initialize", "open"),
        "test_complete_record_refusal_work_is_linear": ("open", "read"),
        "test_complete_publication_work_is_linear": ("publish",),
    }.items()
}


CHECK_OVERRIDES["test_released_parent_close_error_keeps_successor_owned"] = {
    **CHECK_PURPOSE,
    "authority": [
        "fishhat/owner-support/src/fishhat_owner/checkpoint_store.py",
        "fishhat/owner-support/src/fishhat_owner/identity_store.py",
    ],
    "scope": "complete descriptor handoff and cleanup after a controlled Linux close-after-release error",
    "relationship": "candidate",
    "reason": "Actual ordinary directory opens are used, administrative metadata is replaced, and close failure is injected only after releasing an owned descriptor. The wrapper refuses retries of released numbers so the counterexample cannot close an unrelated descriptor. This is not native fault qualification.",
    "claims": [],
}

OWNER = {
    "tool": "host-ops",
    "id": "73166c80-0fae-4ec1-9d7c-2cc7e4c43f5b",
    "epoch": "2f05d744-0b67-4fa6-bb36-1a556d64ae19",
}
JOURNAL = "861b4e8b-dd80-44c4-b270-624b7f9bd519"
FIRST, SECOND, THIRD = "1" * 64, "2" * 64, "3" * 64


@pytest.fixture
def enrolled(tmp_path):
    authority, journal = tmp_path / "authority", tmp_path / "journal"
    authority.mkdir(mode=0o700)
    journal.mkdir(mode=0o700)
    with ordinary_enrollment(tmp_path):
        yield authority, journal


def options():
    return {"owner": copy.deepcopy(OWNER), "journal_id": JOURNAL}


def initialize(paths):
    return store.CheckpointStore.initialize(*paths, **options())


def opened(paths, **changes):
    return store.CheckpointStore.open(*paths, **(options() | changes))


def snapshot(path):
    return {
        entry.name: (
            entry.lstat().st_ino,
            entry.lstat().st_mode,
            entry.lstat().st_mtime_ns,
            entry.lstat().st_nlink,
            entry.read_bytes() if entry.is_file() and not entry.is_symlink() else None,
        )
        for entry in path.iterdir()
    }


def test_compare_and_swap_and_nonmutating_inspection(enrolled):
    initial = initialize(enrolled)
    assert initial["current"] is initial["previous"] is None
    anchor = (enrolled[0] / store.ANCHOR).stat()
    before = snapshot(enrolled[0])
    with opened(enrolled) as checkpoint:
        assert checkpoint.read() == initial
        assert snapshot(enrolled[0]) == before
        with pytest.raises(ContractError, match="exclusive"):
            checkpoint.compare_and_swap(None, FIRST)
        with checkpoint.locked():
            first = checkpoint.compare_and_swap(None, FIRST)
            assert first["current"] == FIRST and first["previous"] is None
        before = snapshot(enrolled[0])
        with checkpoint.locked():
            assert checkpoint.compare_and_swap(FIRST, FIRST) == first
            with pytest.raises(ContractError, match="conflict"):
                checkpoint.compare_and_swap(None, SECOND)
        assert snapshot(enrolled[0]) == before
        with checkpoint.locked():
            second = checkpoint.compare_and_swap(FIRST, SECOND)
            assert second["current"] == SECOND and second["previous"] == FIRST
        assert checkpoint.read() == second
    with opened(enrolled) as checkpoint:
        assert checkpoint.read() == second
    assert (enrolled[0] / store.ANCHOR).stat().st_ino == anchor.st_ino
    assert (enrolled[0] / store.ANCHOR).read_bytes() == b""


def test_open_never_initializes_missing_custody(enrolled):
    with pytest.raises(FileNotFoundError):
        opened(enrolled)
    assert snapshot(enrolled[0]) == {}


@pytest.mark.parametrize("kind", ["file", "directory", "symlink"])
def test_initialization_preserves_existing_custody(enrolled, kind):
    path = enrolled[0] / "retained"
    if kind == "file":
        path.write_bytes(b"unrelated accepted custody")
    elif kind == "directory":
        path.mkdir()
    else:
        path.symlink_to(enrolled[1])
    before = snapshot(enrolled[0])
    with pytest.raises(ContractError, match="fresh"):
        initialize(enrolled)
    assert snapshot(enrolled[0]) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("journal_id", "72726796-2970-479b-9af8-ff5cfa6d16f5"),
        ("owner", {**OWNER, "tool": "app-ops"}),
        ("owner", {**OWNER, "epoch": "934c7883-c0fb-44e4-9835-1a986806721d"}),
        ("owner", {**OWNER, "id": "39013df1-d3db-4d2d-8eae-fb3bbf3aa024"}),
    ],
)
def test_exact_owner_epoch_and_journal_binding_is_required(enrolled, field, value):
    initialize(enrolled)
    before = snapshot(enrolled[0])
    with pytest.raises(ContractError, match="binding"):
        opened(enrolled, **{field: value})
    assert snapshot(enrolled[0]) == before


@pytest.mark.parametrize("kind", ["replace", "unlink", "hardlink", "chmod", "nonempty"])
def test_changed_stable_anchor_refuses_without_erasing_custody(enrolled, kind):
    initialize(enrolled)
    anchor = enrolled[0] / store.ANCHOR
    with opened(enrolled) as checkpoint:
        if kind == "replace":
            replacement = enrolled[0] / "replacement"
            replacement.touch(mode=0o600)
            replacement.replace(anchor)
        elif kind == "unlink":
            anchor.unlink()
        elif kind == "hardlink":
            os.link(anchor, enrolled[0] / "alias")
        elif kind == "chmod":
            anchor.chmod(0o640)
        else:
            anchor.write_bytes(b"foreign lock data")
        before = snapshot(enrolled[0])
        with pytest.raises((ContractError, FileNotFoundError)):
            with checkpoint.locked():
                pytest.fail("changed anchor admitted a publisher")
        assert snapshot(enrolled[0]) == before


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "chmod", "malformed", "pending"])
def test_foreign_current_or_pending_custody_is_preserved(enrolled, kind):
    initialize(enrolled)
    current = enrolled[0] / store.CURRENT
    if kind == "symlink":
        target = enrolled[1] / "copy"
        target.write_bytes(current.read_bytes())
        current.unlink()
        current.symlink_to(target)
    elif kind == "hardlink":
        os.link(current, enrolled[0] / "alias")
    elif kind == "chmod":
        current.chmod(0o640)
    elif kind == "malformed":
        current.write_bytes(b"not a checkpoint")
    else:
        (enrolled[0] / store.PENDING).write_bytes(b"uncertain publication")
    before = snapshot(enrolled[0])
    with pytest.raises((ContractError, OSError, ValueError)):
        opened(enrolled)
    assert snapshot(enrolled[0]) == before


def test_competing_handles_share_one_stable_anchor(enrolled):
    initialize(enrolled)
    with opened(enrolled) as first, opened(enrolled) as second:
        with first.locked():
            with pytest.raises(BlockingIOError):
                with second.locked():
                    pytest.fail("two storage publishers entered one anchor")
            first.compare_and_swap(None, FIRST)
        with second.locked():
            second.compare_and_swap(FIRST, SECOND)
        assert first.read()["current"] == SECOND


def test_shared_read_scope_cannot_publish(enrolled):
    initialize(enrolled)
    with opened(enrolled) as checkpoint:
        with checkpoint._locked(shared=True):
            with pytest.raises(ContractError, match="exclusive"):
                checkpoint.compare_and_swap(None, FIRST)
        assert checkpoint.read()["current"] is None


def test_close_cannot_release_a_held_storage_anchor(enrolled):
    initialize(enrolled)
    with opened(enrolled) as checkpoint:
        with checkpoint.locked():
            with pytest.raises(ContractError, match="still in use"):
                checkpoint.close()
            checkpoint.compare_and_swap(None, FIRST)
        assert checkpoint.read()["current"] == FIRST


def test_publication_failure_retains_pending_and_poisoned_handle(enrolled, monkeypatch):
    initialize(enrolled)
    with opened(enrolled) as checkpoint:

        def fail_replace(*args, **kwargs):
            raise OSError("controlled replacement failure")

        monkeypatch.setattr(store.os, "replace", fail_replace)
        with checkpoint.locked():
            with pytest.raises(OSError, match="controlled"):
                checkpoint.compare_and_swap(None, FIRST)
        assert {entry.name for entry in enrolled[0].iterdir()} == {
            store.ANCHOR,
            store.CURRENT,
            store.PENDING,
        }
        original = json.loads((enrolled[0] / store.CURRENT).read_bytes())
        proposed = json.loads((enrolled[0] / store.PENDING).read_bytes())
        assert original["current"] is None and proposed["current"] == FIRST
        with pytest.raises(ContractError, match="unavailable"):
            checkpoint.read()
        before = snapshot(enrolled[0])
        with pytest.raises(ContractError):
            opened(enrolled)
        assert snapshot(enrolled[0]) == before


def test_unconfirmed_directory_sync_preserves_published_predecessor(enrolled, monkeypatch):
    initialize(enrolled)
    with opened(enrolled) as checkpoint:
        with checkpoint.locked():
            checkpoint.compare_and_swap(None, FIRST)
        real_sync = store.os.fsync

        def fail_directory(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError("controlled directory sync failure")
            return real_sync(descriptor)

        monkeypatch.setattr(store.os, "fsync", fail_directory)
        with checkpoint.locked():
            with pytest.raises(OSError, match="controlled"):
                checkpoint.compare_and_swap(FIRST, SECOND)
        current = json.loads((enrolled[0] / store.CURRENT).read_bytes())
        assert current["current"] == SECOND and current["previous"] == FIRST
        with pytest.raises(ContractError, match="unavailable"):
            checkpoint.read()
    # A fresh read may inspect retained bytes; it establishes no writer authority.
    with opened(enrolled) as checkpoint:
        assert checkpoint.read() == current
        assert not callable(checkpoint)


def test_complete_record_refusal_work_is_linear(enrolled, monkeypatch):
    initialize(enrolled)
    current = enrolled[0] / store.CURRENT
    original = json.loads(current.read_bytes())
    real_read = store.os.read
    observed = []

    def counted_read(descriptor, count):
        value = real_read(descriptor, count)
        observed.append(len(value))
        return value

    monkeypatch.setattr(store.os, "read", counted_read)
    extents = []
    for size in (1024, 4096, 16384, 65536):
        raw = canonical(original | {"foreign": "x" * size}) + b"\n"
        current.write_bytes(raw)
        before = snapshot(enrolled[0])
        observed.clear()
        metrics = {}
        with pytest.raises(ContractError, match="format"):
            opened(enrolled, metrics=metrics)
        assert sum(observed) == metrics["record_bytes_read"] == len(raw)
        assert max(observed) <= 65536
        assert snapshot(enrolled[0]) == before
        extents.append((len(raw), sum(observed)))
    assert all(work == extent for extent, work in extents)


def test_complete_path_work_is_linear_and_closes_on_rejection(tmp_path, monkeypatch):
    real_os = store.os
    controlled_os = SimpleNamespace(**{name: getattr(real_os, name) for name in dir(real_os)})
    live = set()
    work = {"calls": 0, "bytes": 0}

    def opened(path, flags, *args, **kwargs):
        descriptor = real_os.open(path, flags, *args, **kwargs)
        assert descriptor not in live
        live.add(descriptor)
        work["calls"] += 1
        work["bytes"] += len(real_os.fsencode(path))
        return descriptor

    def closed(descriptor):
        assert descriptor in live
        real_os.close(descriptor)
        live.remove(descriptor)
        work["calls"] += 1

    def metadata(descriptor, *, private):
        assert descriptor in live and stat.S_ISDIR(real_os.fstat(descriptor).st_mode)
        work["calls"] += 1

    class ChargedPath(type(tmp_path)):
        @property
        def parts(self):
            values = super().parts
            work["calls"] += len(values)
            work["bytes"] += sum(len(real_os.fsencode(value)) for value in values)
            return values

    controlled_os.open = opened
    controlled_os.close = closed
    controlled_os.getresuid = lambda: (0, 0, 0)
    controlled_os.getresgid = lambda: (0, 0, 0)
    monkeypatch.setattr(store, "os", controlled_os)
    monkeypatch.setattr(store, "_directory_metadata", metadata)
    observed = []
    for depth in (4, 16, 64):
        path = tmp_path / str(depth)
        for _ in range(depth):
            path /= "part"
        path.mkdir(mode=0o700, parents=True)
        extent = len(real_os.fsencode(path))
        work.update(calls=0, bytes=0)
        with store._directory(ChargedPath(path), {}) as descriptor:
            assert descriptor in live
        assert live == set()
        observed.append((extent, sum(work.values())))
        refused = path / "refused"
        refused.symlink_to(tmp_path, target_is_directory=True)
        with pytest.raises(OSError):
            with store._directory(ChargedPath(refused), {}):
                pytest.fail("symlink ancestry was admitted")
        assert live == set()
    first_extent, first_work = observed[0]
    assert all(cost * first_extent <= 2 * first_work * extent for extent, cost in observed)


def test_complete_publication_work_is_linear(enrolled, monkeypatch):
    initialize(enrolled)
    work = {"calls": 0, "bytes": 0}
    real_read, real_write = store.os.read, store.os.write
    real_canonical, real_json = store.canonical, store.strict_json

    def read(descriptor, count):
        value = real_read(descriptor, count)
        work["calls"] += 1
        work["bytes"] += len(value)
        return value

    def write(descriptor, value):
        written = real_write(descriptor, value)
        work["calls"] += 1
        work["bytes"] += written
        return written

    def serialize(value):
        raw = real_canonical(value)
        work["calls"] += 1
        work["bytes"] += len(raw)
        return raw

    def parse(raw, **kwargs):
        work["calls"] += 1
        work["bytes"] += len(raw)
        return real_json(raw, **kwargs)

    monkeypatch.setattr(store.os, "read", read)
    monkeypatch.setattr(store.os, "write", write)
    monkeypatch.setattr(store, "canonical", serialize)
    monkeypatch.setattr(store, "strict_json", parse)
    expected, serial = None, 0
    observed = []
    for extent in (4, 16, 64):
        work.update(calls=0, bytes=0)
        with opened(enrolled) as checkpoint:
            with checkpoint.locked():
                for _ in range(extent):
                    serial += 1
                    current = f"{serial:064x}"
                    result = checkpoint.compare_and_swap(expected, current)
                    assert result["previous"] == expected and result["current"] == current
                    expected = current
        observed.append((extent, sum(work.values())))
        assert {path.name for path in enrolled[0].iterdir()} == {store.ANCHOR, store.CURRENT}
    first_extent, first_work = observed[0]
    assert all(cost * first_extent <= 2 * first_work * extent for extent, cost in observed)


def test_preserved_fixed_record_format_fixture():
    raw = (ROOT / "state/fixtures/v1/owner-checkpoint.json").read_bytes()
    expected = {
        "format": store.FORMAT,
        "owner": OWNER,
        "journal_id": JOURNAL,
        "anchor": {"device": 1, "inode": 2},
        "previous": FIRST,
        "current": SECOND,
    }
    assert store._decode_record(raw, store._binding(OWNER, JOURNAL), expected["anchor"]) == expected
    assert raw == canonical(expected) + b"\n"


@pytest.mark.parametrize(
    "kind", ["format", "extra", "missing", "head", "genesis", "anchor-type", "noncanonical"]
)
def test_closed_fixed_record_format_refuses_unsupported_bytes(kind):
    original = (ROOT / "state/fixtures/v1/owner-checkpoint.json").read_bytes()
    value = json.loads(original)
    if kind == "format":
        value["format"] = "fishhat.checkpoint-store/v2"
    elif kind == "extra":
        value["extra"] = True
    elif kind == "missing":
        value.pop("previous")
    elif kind == "head":
        value["current"] = "incomplete"
    elif kind == "genesis":
        value["current"] = None
    elif kind == "anchor-type":
        value["anchor"]["device"] = True
    raw = canonical(value) + (b"\n\n" if kind == "noncanonical" else b"\n")
    with pytest.raises(ContractError):
        store._decode_record(raw, store._binding(OWNER, JOURNAL), {"device": 1, "inode": 2})


@pytest.mark.parametrize("implementation", ["identity", "checkpoint"])
def test_released_parent_close_error_keeps_successor_owned(tmp_path, monkeypatch, implementation):
    module = identity_store if implementation == "identity" else store
    real_os = module.os
    controlled_os = SimpleNamespace(**{name: getattr(real_os, name) for name in dir(real_os)})
    live = set()
    injected = False
    released_retries = 0

    def opened(path, flags, *args, **kwargs):
        descriptor = real_os.open(path, flags, *args, **kwargs)
        assert descriptor not in live
        live.add(descriptor)
        return descriptor

    def closed(descriptor):
        nonlocal injected, released_retries
        if descriptor not in live:
            released_retries += 1
            raise OSError(errno.EBADF, "controlled released descriptor retry")
        real_os.close(descriptor)
        live.remove(descriptor)
        if not injected:
            injected = True
            raise OSError(errno.EIO, "controlled close-after-release failure")

    controlled_os.open, controlled_os.close = opened, closed
    controlled_os.getresuid = lambda: (0, 0, 0)
    controlled_os.getresgid = lambda: (0, 0, 0)
    monkeypatch.setattr(module, "os", controlled_os)
    monkeypatch.setattr(module, "_directory_metadata", lambda descriptor, *, private: None)
    try:
        with pytest.raises(OSError) as failure:
            if implementation == "identity":
                descriptor = module._walk(tmp_path)
                closed(descriptor)
                pytest.fail("controlled close failure was lost")
            else:
                with module._directory(tmp_path, {}):
                    pytest.fail("controlled close failure was lost")
        observed = {
            "errno": failure.value.errno,
            "unclosed_successors": len(live),
            "released_parent_retries": released_retries,
        }
        assert observed == {
            "errno": errno.EIO,
            "unclosed_successors": 0,
            "released_parent_retries": 0,
        }
    finally:
        for descriptor in live:
            real_os.close(descriptor)


def test_separate_processes_serialize_distinct_inode_journal_copies(enrolled):
    initialize(enrolled)
    journal_copy = enrolled[1].parent / "journal-copy"
    journal_copy.mkdir(mode=0o700)
    original, copied = enrolled[1] / "HEAD", journal_copy / "HEAD"
    original.write_bytes(b"selected logical journal bytes\n")
    copied.write_bytes(original.read_bytes())
    assert original.read_bytes() == copied.read_bytes()
    assert original.stat().st_ino != copied.stat().st_ino
    with opened(enrolled) as checkpoint:
        with child_process((enrolled[0], journal_copy), OWNER, JOURNAL, "storage") as (
            process,
            connection,
        ):
            assert receive(connection) == {"status": "ready", "current": None}
            with checkpoint.locked():
                send(connection, {"operation": "publish", "expected": None, "current": SECOND})
                assert receive(connection) == {"status": "blocked"}
                checkpoint.compare_and_swap(None, FIRST)
            send(connection, {"operation": "publish", "expected": FIRST, "current": SECOND})
            assert receive(connection) == {"status": "published", "current": SECOND}
            send(connection, {"operation": "close"})
            assert receive(connection) == {"status": "closed"}
            assert process.wait(timeout=watchdog(15)) == 0
        assert checkpoint.read()["current"] == SECOND


@pytest.mark.parametrize("kind", ["duplicate", "inherited"])
def test_remaining_descriptor_alias_keeps_storage_locked(enrolled, kind):
    import fcntl

    initialize(enrolled)
    descriptor = None
    if kind == "inherited":
        descriptor = os.open(enrolled[0] / store.ANCHOR, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with child_process(enrolled, OWNER, JOURNAL, "alias", inherited=descriptor) as (
            process,
            connection,
        ):
            assert receive(connection) == {"status": "alias-held"}
            if descriptor is not None:
                os.close(descriptor)
                descriptor = None
            before = snapshot(enrolled[0])
            with pytest.raises(BlockingIOError):
                opened(enrolled)
            assert snapshot(enrolled[0]) == before
            send(connection, {"operation": "release"})
            assert receive(connection) == {"status": "released"}
            assert process.wait(timeout=watchdog(15)) == 0
    finally:
        if descriptor is not None:
            os.close(descriptor)
    with opened(enrolled) as checkpoint:
        assert checkpoint.read()["current"] is None


def test_process_exit_before_acknowledgement_preserves_committed_checkpoint(enrolled):
    initialize(enrolled)
    with child_process(enrolled, OWNER, JOURNAL, "commit-without-ack") as (process, connection):
        with pytest.raises(EOFError):
            receive(connection)
        assert process.wait(timeout=watchdog(15)) == 0
    before = snapshot(enrolled[0])
    with opened(enrolled) as checkpoint:
        assert checkpoint.read()["current"] == FIRST
        with checkpoint.locked():
            with pytest.raises(ContractError, match="conflict"):
                checkpoint.compare_and_swap(None, FIRST)
    assert snapshot(enrolled[0]) == before


def test_process_interruption_preserves_pending_and_existing_checkpoint(enrolled):
    initialize(enrolled)
    original = (enrolled[0] / store.CURRENT).read_bytes()
    with child_process(enrolled, OWNER, JOURNAL, "pause-pending") as (process, connection):
        assert receive(connection) == {"status": "pending-synchronized"}
        process.terminate()
        assert process.wait(timeout=watchdog(15)) == -signal.SIGTERM
    assert (enrolled[0] / store.CURRENT).read_bytes() == original
    pending = json.loads((enrolled[0] / store.PENDING).read_bytes())
    assert pending["current"] == FIRST and pending["previous"] is None
    before = snapshot(enrolled[0])
    with pytest.raises(ContractError):
        opened(enrolled)
    assert snapshot(enrolled[0]) == before


@pytest.mark.parametrize("kind", ["replace", "unlink"])
def test_changed_anchor_cannot_escape_a_separate_process_holder(enrolled, kind):
    initialize(enrolled)
    original = (enrolled[0] / store.CURRENT).read_bytes()
    with child_process(enrolled, OWNER, JOURNAL, "alias") as (process, connection):
        assert receive(connection) == {"status": "alias-held"}
        anchor = enrolled[0] / store.ANCHOR
        if kind == "replace":
            replacement = enrolled[0] / "replacement"
            replacement.touch(mode=0o600)
            replacement.replace(anchor)
        else:
            anchor.unlink()
        before = snapshot(enrolled[0])
        with pytest.raises((ContractError, FileNotFoundError)):
            opened(enrolled)
        assert snapshot(enrolled[0]) == before
        send(connection, {"operation": "release"})
        assert receive(connection) == {"status": "released"}
        assert process.wait(timeout=watchdog(15)) == 0
    with pytest.raises((ContractError, FileNotFoundError)):
        opened(enrolled)
    assert snapshot(enrolled[0]) == before
    assert (enrolled[0] / store.CURRENT).read_bytes() == original
