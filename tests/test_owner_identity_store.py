"""Ordinary-file identity mechanics with administrative enrollment replaced."""

import copy
import os
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Barrier, Event

import pytest
from fishhat_contracts import ContractError
from fishhat_owner import identity_store as store
from fishhat_owner.migrations import HEAD

from scripts.validation_timeouts import watchdog

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": [
        "fishhat/owner-support/src/fishhat_owner/identity_store.py",
        "state/inventory.toml",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/Owner",
    ],
    "scope": "explicit ordinary-file identity genesis, installed schema inspection, preserved refusal/interruption and counted complete work",
    "relationship": "candidate",
    "reason": "Administrative enrollment is replaced for temporary SQLite files. Actual protected installed commands, credentials, filesystem custody and interruption require separate enrolled-guest observations.",
    "claims": [],
}

OWNER = {
    "tool": "host-ops",
    "id": "9e85b225-26c2-49f1-b631-5da0eb8b32c5",
    "epoch": "bb9c743d-5e47-438f-a820-1b8f52b323ec",
}


@pytest.fixture
def enrolled(tmp_path, monkeypatch):
    @contextmanager
    def directory(path):
        assert path.parent == tmp_path and path.is_dir()
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield descriptor
        finally:
            os.close(descriptor)

    monkeypatch.setattr(store, "_directory", directory)

    def fresh(name="private"):
        path = tmp_path / name
        path.mkdir(mode=0o700)
        return path

    return fresh


def snapshot(path):
    return {
        p.name: (
            p.lstat().st_ino,
            p.lstat().st_mode,
            p.lstat().st_mtime_ns,
            p.lstat().st_nlink,
            p.read_bytes() if p.is_file() and not p.is_symlink() else None,
        )
        for p in path.iterdir()
    }


def test_explicit_genesis_and_nonmutating_identity_inspection(enrolled):
    path = enrolled()
    result = store.initialize(path, OWNER)
    assert result == {"owner": OWNER, "schema_revision": HEAD, "generation": 0}
    assert set(snapshot(path)) == {store.DATABASE}
    data = path / store.DATABASE
    assert data.stat().st_nlink == 1 and stat.S_IMODE(data.stat().st_mode) == 0o600
    before = snapshot(path)
    assert store.inspect(path, OWNER) == result
    assert snapshot(path) == before
    with pytest.raises(ContractError, match="fresh"):
        store.initialize(path, OWNER)
    assert snapshot(path) == before


def test_open_does_not_turn_absence_into_empty_state(enrolled):
    path = enrolled()
    with pytest.raises(FileNotFoundError):
        store.inspect(path, OWNER)
    assert snapshot(path) == {}


@pytest.mark.parametrize("kind", ["file", "directory", "symlink"])
def test_existing_storage_is_preserved_without_adoption(enrolled, kind):
    path = enrolled()
    entry = path / "retained"
    if kind == "file":
        entry.write_bytes(b"existing data")
    elif kind == "directory":
        entry.mkdir()
    else:
        target = enrolled("other") / "target"
        target.write_bytes(b"unrelated bytes")
        entry.symlink_to(target)
    before = snapshot(path)
    with pytest.raises(ContractError, match="fresh"):
        store.initialize(path, OWNER)
    assert snapshot(path) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "a2d8c682-1b9f-4114-9d44-7fbf8a97b9b7"),
        ("epoch", "ebd20c94-eb71-4fb5-9b15-f5de7fe05843"),
        ("tool", "app-ops"),
    ],
)
def test_complete_owner_identity_including_role_is_checked(enrolled, field, value):
    path = enrolled()
    store.initialize(path, OWNER)
    other = {**OWNER, field: value}
    before = snapshot(path)
    with pytest.raises(ContractError, match="identity"):
        store.inspect(path, other)
    assert snapshot(path) == before


@pytest.mark.parametrize(
    "mutation",
    [
        "DROP INDEX requests_active",
        "CREATE TABLE foreign_data(value TEXT)",
        "UPDATE alembic_version SET version_num='foreign'",
        "PRAGMA user_version=2",
        "DELETE FROM meta",
        "INSERT INTO meta VALUES('foreign','foreign',0)",
        "UPDATE meta SET generation=-1",
    ],
    ids=[
        "missing-index",
        "extra-table",
        "foreign-revision",
        "wrong-version",
        "missing-owner",
        "multiple-owners",
        "negative-generation",
    ],
)
def test_incompatible_schema_and_identity_never_change_on_open(enrolled, mutation):
    path = enrolled()
    store.initialize(path, OWNER)
    with sqlite3.connect(path / store.DATABASE) as database:
        database.execute(mutation)
    before = snapshot(path)
    with pytest.raises(ContractError):
        store.inspect(path, OWNER)
    assert snapshot(path) == before


def test_malformed_database_is_retained(enrolled):
    path = enrolled()
    data = path / store.DATABASE
    data.write_bytes(b"unrecognized private bytes")
    data.chmod(0o600)
    before = snapshot(path)
    with pytest.raises(ContractError):
        store.inspect(path, OWNER)
    assert snapshot(path) == before


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "permissions"])
def test_database_custody_substitutions_are_refused(enrolled, kind):
    path = enrolled()
    store.initialize(path, OWNER)
    data = path / store.DATABASE
    if kind == "symlink":
        target = path / "retained"
        data.rename(target)
        data.symlink_to(target)
    elif kind == "hardlink":
        os.link(data, path / "alias")
    else:
        data.chmod(0o640)
    before = snapshot(path)
    with pytest.raises((ContractError, OSError)):
        store.inspect(path, OWNER)
    assert snapshot(path) == before


@pytest.mark.parametrize(
    "name",
    [store.PENDING, store.DATABASE + "-journal", store.DATABASE + "-wal", store.DATABASE + "-shm"],
)
def test_incomplete_or_unsupported_sidecars_block_without_repair(enrolled, name):
    path = enrolled()
    store.initialize(path, OWNER)
    (path / name).write_bytes(b"retained uncertain bytes")
    before = snapshot(path)
    with pytest.raises(ContractError, match="incomplete"):
        store.inspect(path, OWNER)
    assert snapshot(path) == before


def test_interrupted_genesis_is_preserved_and_fresh_retry_is_disjoint(enrolled, monkeypatch):
    path = enrolled()

    def interrupted(database, owner):
        database.execute("BEGIN EXCLUSIVE")
        database.execute("CREATE TABLE partial(value TEXT)")
        raise sqlite3.DatabaseError("controlled failure")

    with monkeypatch.context() as patch:
        patch.setattr(store, "_construct", interrupted)
        with pytest.raises(ContractError):
            store.initialize(path, OWNER)
    assert store.PENDING in snapshot(path) and store.DATABASE not in snapshot(path)
    before = snapshot(path)
    with pytest.raises(ContractError):
        store.inspect(path, OWNER)
    with pytest.raises(ContractError):
        store.initialize(path, OWNER)
    fresh = enrolled("retry")
    assert store.initialize(fresh, OWNER)["owner"] == OWNER
    assert snapshot(path) == before
    assert (fresh / store.DATABASE).stat().st_ino != (path / store.PENDING).stat().st_ino


@pytest.mark.parametrize("boundary", ["link", "unlink", "directory-sync"])
def test_publication_failure_preserves_known_or_uncertain_outcomes(enrolled, monkeypatch, boundary):
    path = enrolled()
    original_sync = os.fsync

    def fail(*args, **kwargs):
        raise OSError("controlled publication interruption")

    def sync(descriptor):
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            fail()
        original_sync(descriptor)

    with monkeypatch.context() as patch:
        if boundary == "directory-sync":
            patch.setattr(store.os, "fsync", sync)
        else:
            patch.setattr(store.os, boundary, fail)
        with pytest.raises(OSError):
            store.initialize(path, OWNER)
    before = snapshot(path)
    if boundary == "directory-sync":
        assert store.inspect(path, OWNER)["owner"] == OWNER
    else:
        with pytest.raises(ContractError):
            store.inspect(path, OWNER)
    with pytest.raises(ContractError):
        store.initialize(path, OWNER)
    assert snapshot(path) == before


def test_competing_initializers_do_not_adopt_or_replace_the_winner(enrolled):
    path = enrolled()
    barrier = Barrier(2)

    def initialize():
        barrier.wait(timeout=watchdog(10))
        try:
            return store.initialize(path, OWNER)
        except (ContractError, OSError):
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: initialize(), range(2)))
    assert sum(result is not None for result in results) == 1
    assert store.inspect(path, OWNER)["owner"] == OWNER
    assert set(snapshot(path)) == {store.DATABASE}


def test_concurrent_initialization_and_inspection_cannot_cross_private_publication(
    enrolled, monkeypatch
):
    path = enrolled()
    entered, release = Event(), Event()
    construct = store._construct

    def held(database, owner):
        entered.set()
        assert release.wait(timeout=watchdog(10))
        return construct(database, owner)

    with monkeypatch.context() as patch:
        patch.setattr(store, "_construct", held)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(store.initialize, path, OWNER)
            try:
                assert entered.wait(timeout=watchdog(10))
                before = snapshot(path)
                with pytest.raises(BlockingIOError):
                    store.initialize(path, OWNER)
                with pytest.raises(BlockingIOError):
                    store.inspect(path, OWNER)
                assert snapshot(path) == before
            finally:
                release.set()
            assert pending.result(timeout=watchdog(10))["owner"] == OWNER
    assert store.inspect(path, OWNER)["owner"] == OWNER
    assert set(snapshot(path)) == {store.DATABASE}


def test_complete_retained_rows_are_not_scanned_or_changed_by_identity_open(enrolled, monkeypatch):
    path = enrolled()
    store.initialize(path, OWNER)
    original_connect = store.sqlite3.connect
    allowed_reads = {"sqlite_master", "meta", "alembic_version"}
    observations = []
    for extent in (16, 64, 256):
        with original_connect(path / store.DATABASE) as database:
            database.executemany(
                "INSERT INTO requests VALUES(?,?,?,?,?)",
                [
                    (str(i), "a" * 64, "retained", "accepted", "none")
                    for i in range(extent // 4 if extent > 16 else 0, extent)
                ],
            )
        before = snapshot(path)
        steps = [0]

        def counted(*args, counter=steps, **kwargs):
            database = original_connect(*args, **kwargs)
            if kwargs.get("uri"):

                def progress():
                    counter[0] += 1
                    return 0

                def authorize(action, first, second, schema, trigger):
                    if action == sqlite3.SQLITE_READ:
                        assert first in allowed_reads
                    return sqlite3.SQLITE_OK

                database.set_progress_handler(progress, 1)
                database.set_authorizer(authorize)
            return database

        with monkeypatch.context() as patch:
            patch.setattr(store.sqlite3, "connect", counted)
            assert store.inspect(path, OWNER)["generation"] == 0
        assert snapshot(path) == before
        observations.append({"extent": extent, "steps": steps[0]})
    assert observations[0]["steps"] > 0
    assert max(row["steps"] for row in observations) <= observations[0]["steps"] * 1.05


def test_complete_ancestry_work_is_linear_and_handles_close_on_rejection(tmp_path, monkeypatch):
    original_open, original_close = os.open, os.close
    observed = []

    class ChargedPath(type(tmp_path)):
        @property
        def parts(self):
            components = super().parts
            # Returning the complete decomposition visits every component;
            # filesystem-call counts alone do not account for this Python work.
            work[0] += sum(1 + len(os.fsencode(component)) for component in components)
            return components

    with monkeypatch.context() as patch:
        patch.setattr(store, "_directory_metadata", lambda *args, **kwargs: None)
        for depth in (4, 16, 64):
            path = tmp_path / str(depth)
            for _ in range(depth):
                path = path / "part"
            path.mkdir(parents=True)
            work, opened = [0], set()
            path = ChargedPath(path)

            def counted(name, flags, *args, counter=work, active=opened, **kwargs):
                counter[0] += 1 + len(os.fsencode(name))
                descriptor = original_open(name, flags, *args, **kwargs)
                active.add(descriptor)
                return descriptor

            def close(descriptor, active=opened):
                active.remove(descriptor)
                original_close(descriptor)

            patch.setattr(store.os, "open", counted)
            patch.setattr(store.os, "close", close)
            descriptor = store._walk(path)
            assert os.fstat(descriptor).st_ino == path.stat().st_ino
            close(descriptor)
            alias = path / "alias"
            alias.symlink_to(path, target_is_directory=True)
            with pytest.raises(OSError):
                store._walk(alias)
            assert not opened
            observed.append({"input": len(os.fsencode(path)), "work": work[0]})
    first = observed[0]
    assert all(
        row["work"] * first["input"] <= first["work"] * row["input"] * 1.1 for row in observed
    )


@pytest.mark.parametrize(
    "owner", [{**OWNER, "id": "bad"}, {**OWNER, "epoch": "bad"}, {**OWNER, "extra": True}]
)
def test_invalid_identity_cannot_create_state(enrolled, owner):
    path = enrolled()
    with pytest.raises(ContractError):
        store.initialize(path, copy.deepcopy(owner))
    assert snapshot(path) == {}


@pytest.mark.parametrize(
    "width", [16, 64, 256, 1024], ids=["columns-16", "columns-64", "columns-256", "columns-1024"]
)
def test_foreign_wide_schema_is_rejected_before_unbounded_column_preparation(
    enrolled, monkeypatch, width
):
    path = enrolled()
    store.initialize(path, OWNER)
    original = sqlite3.connect
    with original(path / store.DATABASE) as database:
        database.execute(
            "CREATE TABLE foreign_wide("
            + ",".join("c" + str(i) + " TEXT" for i in range(width))
            + ")"
        )
    before = snapshot(path)
    observed = []

    class Connection(sqlite3.Connection):
        def setlimit(self, category, value):
            if getattr(self, "selected", False):
                observed.append(("limit", category, value))
            return super().setlimit(category, value)

        def execute(self, statement, *args, **kwargs):
            if getattr(self, "selected", False):
                assert observed and observed[0] == ("limit", sqlite3.SQLITE_LIMIT_COLUMN, 5)
            try:
                return super().execute(statement, *args, **kwargs)
            except sqlite3.DatabaseError as error:
                if getattr(self, "selected", False):
                    observed.append(("rejected", str(error)))
                raise

    def connect(*args, **kwargs):
        database = original(*args, factory=Connection, **kwargs)
        database.selected = bool(kwargs.get("uri"))
        return database

    with monkeypatch.context() as patch:
        patch.setattr(store.sqlite3, "connect", connect)
        with pytest.raises(ContractError):
            store.inspect(path, OWNER)
    assert any(row[0] == "rejected" and "too many columns" in row[1] for row in observed)
    assert snapshot(path) == before
