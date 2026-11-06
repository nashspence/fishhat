"""Explicit, forward-only reference-state upgrades; never invoked by store open."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from alembic import command
from alembic.config import Config
from fishhat_contracts import ContractError
from sqlalchemy import URL, Connection, create_engine, event

HEAD = "v1_0003"
ACTIVE_PREDICATE = "state IN ('accepted','running','waiting','quarantined') OR (state IN ('failed','cancelled') AND effect != 'none')"
ACTIVE_INDEX = "CREATE INDEX requests_active ON requests(request_id) WHERE " + ACTIVE_PREDICATE

EFFECT_TABLE = "CREATE TABLE request_effects(request_id TEXT PRIMARY KEY REFERENCES requests(request_id),known INTEGER,revision INTEGER NOT NULL,held INTEGER NOT NULL)"
EFFECT_INDEX = "CREATE INDEX request_effects_held ON request_effects(request_id) WHERE held=1"
RESOLUTION_TABLE = "CREATE TABLE effect_resolutions(request_id TEXT NOT NULL REFERENCES requests(request_id),transition INTEGER NOT NULL,evidence_digest TEXT NOT NULL,PRIMARY KEY(request_id,transition))"


def check_revision(db: sqlite3.Connection) -> None:
    if db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='alembic_version'"
    ).fetchone():
        if db.execute("SELECT version_num FROM alembic_version").fetchall() != [(HEAD,)]:
            raise ContractError("unsupported migration revision")

    if db.execute(
        "SELECT sql FROM sqlite_master WHERE type='index' AND name='requests_active'"
    ).fetchone() != (ACTIVE_INDEX,):
        raise ContractError("explicit owner index upgrade required")

    for name, expected in (
        ("request_effects", EFFECT_TABLE),
        ("request_effects_held", EFFECT_INDEX),
        ("effect_resolutions", RESOLUTION_TABLE),
    ):
        if db.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone() != (
            expected,
        ):
            raise ContractError("explicit owner effect-history upgrade required")


def configuration(connection: Connection) -> Config:
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).parent))
    config.attributes["connection"] = connection
    return config


def upgrade(path: Path) -> None:
    if not path.is_file() or path.is_symlink():
        raise ContractError("explicit existing state required for migration")
    engine = create_engine(
        URL.create("sqlite", database=str(path.resolve())), connect_args={"isolation_level": None}
    )

    @event.listens_for(engine, "begin")
    def begin(connection: Connection) -> None:
        connection.exec_driver_sql("BEGIN EXCLUSIVE")

    try:
        with engine.begin() as connection:
            # Validate legacy format and exact schema before adopting its baseline.
            tables = set(
                connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).scalars()
            )
            expected = {
                "meta": [
                    ("owner", "TEXT", 0, 1),
                    ("epoch", "TEXT", 1, 0),
                    ("generation", "INTEGER", 1, 0),
                ],
                "requests": [
                    ("request_id", "TEXT", 0, 1),
                    ("payload_digest", "TEXT", 1, 0),
                    ("principal", "TEXT", 1, 0),
                    ("state", "TEXT", 1, 0),
                    ("effect", "TEXT", 1, 0),
                ],
            }
            effect_tables = {"request_effects", "effect_resolutions"}
            present = tables & effect_tables
            if present and present != effect_tables:
                raise ContractError("unrecognized legacy state")
            current = present == effect_tables
            if current:
                expected.update(
                    {
                        "request_effects": [
                            ("request_id", "TEXT", 0, 1),
                            ("known", "INTEGER", 0, 0),
                            ("revision", "INTEGER", 1, 0),
                            ("held", "INTEGER", 1, 0),
                        ],
                        "effect_resolutions": [
                            ("request_id", "TEXT", 1, 1),
                            ("transition", "INTEGER", 1, 2),
                            ("evidence_digest", "TEXT", 1, 0),
                        ],
                    }
                )
            if tables - {"alembic_version", "sqlite_sequence"} != set(expected):
                raise ContractError("unrecognized legacy state")
            for table, columns in expected.items():
                actual = [
                    (row[1], row[2], row[3], row[5])
                    for row in connection.exec_driver_sql(
                        "SELECT * FROM pragma_table_info(?)", (table,)
                    )
                ]
                if actual != columns:
                    raise ContractError("unrecognized legacy schema")
            active_index = connection.exec_driver_sql(
                "SELECT sql FROM sqlite_master WHERE type='index' AND name='requests_active'"
            ).fetchone()
            if active_index is not None and active_index[0] != ACTIVE_INDEX:
                raise ContractError("unrecognized owner active index")
            indexes: dict[str, set[tuple[int, tuple[str, ...]]]] = {
                "meta": {(1, ("owner",))},
                "requests": {(1, ("request_id",))},
            }
            if active_index is not None:
                indexes["requests"].add((0, ("request_id",)))
            if current:
                if active_index is None:
                    raise ContractError("migration revision/index mismatch")
                indexes.update(
                    {
                        "request_effects": {(1, ("request_id",)), (0, ("request_id",))},
                        "effect_resolutions": {(1, ("request_id", "transition"))},
                    }
                )
                for name, sql in (
                    ("request_effects", EFFECT_TABLE),
                    ("request_effects_held", EFFECT_INDEX),
                    ("effect_resolutions", RESOLUTION_TABLE),
                ):
                    if connection.exec_driver_sql(
                        "SELECT sql FROM sqlite_master WHERE name=?", (name,)
                    ).fetchone() != (sql,):
                        raise ContractError("unrecognized owner effect-history schema")
            for table, expected_indexes in indexes.items():
                actual_indexes = {
                    (
                        row[2],
                        tuple(
                            item[2]
                            for item in connection.exec_driver_sql(
                                "SELECT * FROM pragma_index_info(?)", (row[1],)
                            )
                        ),
                    )
                    for row in connection.exec_driver_sql(
                        "SELECT * FROM pragma_index_list(?)", (table,)
                    )
                }
                if actual_indexes != expected_indexes or len(
                    list(connection.exec_driver_sql("SELECT * FROM pragma_index_list(?)", (table,)))
                ) != len(expected_indexes):
                    raise ContractError("unrecognized legacy indexes")
            validate_marker(connection)
            if "alembic_version" in tables:
                if list(
                    connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalars()
                ) not in (["v1_0001"], ["v1_0002"], [HEAD]):
                    raise ContractError("unsupported migration revision")
                revision = connection.exec_driver_sql(
                    "SELECT version_num FROM alembic_version"
                ).scalar_one()
                expected_revision = (
                    HEAD if current else "v1_0002" if active_index is not None else "v1_0001"
                )
                if revision != expected_revision:
                    raise ContractError("migration revision/index mismatch")
            else:
                command.stamp(
                    configuration(connection),
                    HEAD if current else "v1_0002" if active_index is not None else "v1_0001",
                )
            command.upgrade(configuration(connection), "head")
    finally:
        engine.dispose()


def validate_marker(connection: Connection) -> None:
    if connection.exec_driver_sql("PRAGMA user_version").scalar_one() != 1:
        raise ContractError("unsupported legacy schema")
