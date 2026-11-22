"""Explicit protected identity genesis and inspection, without operation admission.

The one genesis transaction and synchronized file/directory publication protect
its acknowledged owner/schema commitment. Failed private attempts are retained.
An identity record supplies neither writer continuity nor execution authority.
Path traversal visits each component once. Inspection compares the complete
installed schema catalogue without traversing accepted request histories.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import sys
from collections.abc import Iterator, Mapping
from contextlib import closing, contextmanager
from functools import cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

from alembic import command
from alembic.util.exc import CommandError
from fishhat_contracts import ContractError
from fishhat_contracts.validation import validate
from sqlalchemy import Connection, create_engine, event
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import NullPool

from fishhat_owner.migrations import HEAD, configuration

DATABASE = "owner.sqlite3"
PENDING = ".initializing"
Catalog = Mapping[tuple[str, str, str], str | None]


def _owner_key(owner: dict[str, Any]) -> str:
    validate("common.schema.json", owner, "Owner")
    return json.dumps([owner["tool"], owner["id"]], separators=(",", ":"))


def _directory_metadata(descriptor: int, *, private: bool) -> None:
    row = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(row.st_mode)
        or row.st_uid != 0
        or row.st_gid != 0
        or row.st_mode & 0o7022
        or (private and stat.S_IMODE(row.st_mode) != 0o700)
        or "security.capability" in os.listxattr(descriptor)
    ):
        raise ContractError("protected owner storage required")


def _walk(path: Path) -> int:
    parts = path.parts
    if not path.is_absolute() or parts[0] != "/" or ".." in parts:
        raise ContractError("absolute protected owner storage required")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        _directory_metadata(descriptor, private=len(parts) == 1)
        for index, part in enumerate(parts[1:], 1):
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            _directory_metadata(descriptor, private=index == len(parts) - 1)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def _directory(path: Path) -> Iterator[int]:
    if sys.platform != "linux" or os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
        raise ContractError("administrative owner storage custody required")
    descriptor = _walk(path)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _lock(descriptor: int, *, exclusive: bool) -> None:
    import fcntl

    # Coordinate this directory's genesis/publication only. This is not a
    # logical-owner writer lease and cannot fence another restored copy.
    operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    fcntl.flock(descriptor, operation | fcntl.LOCK_NB)


def _regular(descriptor: int) -> os.stat_result:
    row = os.fstat(descriptor)
    if (
        not stat.S_ISREG(row.st_mode)
        or row.st_uid != os.geteuid()
        or row.st_gid != os.getegid()
        or row.st_nlink != 1
        or stat.S_IMODE(row.st_mode) != 0o600
        or "security.capability" in os.listxattr(descriptor)
    ):
        raise ContractError("private single-link owner database required")
    return row


def _catalogue(database: sqlite3.Connection) -> dict[tuple[str, str, str], str | None]:
    result: dict[tuple[str, str, str], str | None] = {}
    for kind, name, table, sql in database.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema"
    ):
        if (
            not all(isinstance(value, str) for value in (kind, name, table))
            or not (sql is None or isinstance(sql, str))
            or (kind, name, table) in result
        ):
            raise ContractError("invalid owner schema catalogue")
        result[kind, name, table] = sql
    return result


def _construct(database: sqlite3.Connection, owner: dict[str, Any] | None) -> tuple[Catalog, int]:
    engine = create_engine("sqlite://", creator=lambda: database, poolclass=NullPool)

    @event.listens_for(engine, "begin")
    def begin(connection: Connection) -> None:
        connection.exec_driver_sql("BEGIN EXCLUSIVE")

    try:
        with engine.begin() as connection:
            command.upgrade(configuration(connection), HEAD)
            if owner is not None:
                connection.exec_driver_sql(
                    "INSERT INTO meta(owner,epoch,generation) VALUES(?,?,0)",
                    (_owner_key(owner), owner["epoch"]),
                )
            catalogue = _catalogue(database)
            # Derive the admitted field width from the trusted installed schema,
            # including SQLite's own catalogue shape. Row counts stay unbounded.
            width = len(database.execute("PRAGMA table_info(sqlite_schema)").fetchall())
            for kind, table, _ in catalogue:
                if kind == "table":
                    fields = database.execute("SELECT * FROM pragma_table_info(?)", (table,))
                    width = max(width, sum(1 for _ in fields))
            return MappingProxyType(catalogue), width
    finally:
        engine.dispose()


@cache
def _installed_schema() -> tuple[Catalog, int]:
    return _construct(sqlite3.connect(":memory:", isolation_level=None), None)


def _absent(directory: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ContractError("incomplete owner database custody")


def _sidecars_absent(directory: int, name: str) -> None:
    for suffix in ("-journal", "-wal", "-shm"):
        _absent(directory, name + suffix)


def _uri(directory: int, name: str, *, inspect: bool) -> str:
    # The pinned directory descriptor and fixed basename supply the entire URI.
    suffix = "mode=ro&immutable=1" if inspect else "mode=rw"
    return f"file:/proc/self/fd/{directory}/{name}?{suffix}"


def _inspect(directory: int, name: str, owner: dict[str, Any]) -> dict[str, Any]:
    expected = _owner_key(owner)
    _sidecars_absent(directory, name)
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        before = _regular(descriptor)
        installed, width = _installed_schema()
        with closing(sqlite3.connect(_uri(directory, name, inspect=True), uri=True)) as database:
            # Apply the closed installed format before SQLite parses foreign DDL;
            # exact schema comparison would otherwise happen after code generation.
            database.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, width)
            if hasattr(database, "enable_load_extension"):
                database.enable_load_extension(False)
            database.execute("PRAGMA trusted_schema=OFF")
            database.execute("PRAGMA query_only=ON")
            if _catalogue(database) != installed:
                raise ContractError("installed owner schema required")
            if database.execute("PRAGMA user_version").fetchone() != (1,):
                raise ContractError("unsupported owner schema version")
            if database.execute("PRAGMA journal_mode").fetchone() != ("delete",):
                raise ContractError("unsupported owner storage profile")
            if database.execute("SELECT version_num FROM alembic_version").fetchall() != [(HEAD,)]:
                raise ContractError("unsupported owner schema revision")
            rows = database.execute("SELECT owner,epoch,generation FROM meta")
            identity = rows.fetchone()
            if identity is None or rows.fetchone() is not None:
                raise ContractError("one explicit owner identity required")
            key, epoch, generation = identity
            if key != expected or epoch != owner["epoch"]:
                raise ContractError("owner identity mismatch")
            validate("adapter.schema.json", generation, "Generation")
        _sidecars_absent(directory, name)
        after = _regular(descriptor)
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(
            getattr(before, field) != getattr(row, field)
            for row in (after, current)
            for field in fields
        ):
            raise ContractError("owner database changed during inspection")
        return {"owner": dict(owner), "schema_revision": HEAD, "generation": generation}
    finally:
        os.close(descriptor)


def inspect(path: Path, owner: dict[str, Any]) -> dict[str, Any]:
    """Verify existing identity/schema without creating or changing owner data."""
    _owner_key(owner)
    try:
        with _directory(path) as directory:
            _lock(directory, exclusive=False)
            _absent(directory, PENDING)
            return _inspect(directory, DATABASE, owner)
    except (sqlite3.DatabaseError, SQLAlchemyError, CommandError):
        raise ContractError("invalid owner database") from None


def initialize(path: Path, owner: dict[str, Any]) -> dict[str, Any]:
    """Commit a fresh identity; preserve every existing or interrupted attempt."""
    _owner_key(owner)
    with _directory(path) as directory:
        _lock(directory, exclusive=True)
        with os.scandir(directory) as entries:
            if next(entries, None) is not None:
                raise ContractError("fresh owner storage required")
        descriptor = os.open(
            PENDING,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory,
        )
        try:
            os.fchmod(descriptor, 0o600)
            _regular(descriptor)
            try:
                with closing(
                    sqlite3.connect(
                        _uri(directory, PENDING, inspect=False), uri=True, isolation_level=None
                    )
                ) as database:
                    if hasattr(database, "enable_load_extension"):
                        database.enable_load_extension(False)
                    database.execute("PRAGMA journal_mode=DELETE")
                    database.execute("PRAGMA synchronous=FULL")
                    database.execute("PRAGMA foreign_keys=ON")
                    _construct(database, owner)
            except (sqlite3.DatabaseError, SQLAlchemyError, CommandError):
                raise ContractError("owner identity initialization failed") from None
            try:
                result = _inspect(directory, PENDING, owner)
            except (sqlite3.DatabaseError, SQLAlchemyError, CommandError):
                raise ContractError("owner identity inspection failed") from None
            _regular(descriptor)
            os.fsync(descriptor)
            # No replacement: publication cannot adopt another initializer's file.
            # A kill between link/unlink leaves private, detectably incomplete custody.
            os.link(
                PENDING, DATABASE, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False
            )
            os.unlink(PENDING, dir_fd=directory)
            os.fsync(directory)
            return result
        finally:
            os.close(descriptor)
