from __future__ import annotations

import importlib
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import URL, create_engine, event

from scripts.project_policy import ROOT, read_toml
from scripts.validation_timeouts import watchdog
from tests.test_component_policy import restore_fixture

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": ["state/inventory.toml"],
    "scope": "local SQLite/Alembic reference stores",
    "relationship": "candidate",
    "reason": "Preserved SQL fixtures, fixed data identities and subprocess transaction deaths exercise forward migration invariants, not native first-write recovery.",
    "claims": [],
}


OWNERS = read_toml(ROOT / "state/inventory.toml")["owners"]


def fixture(owner, tmp_path):
    return restore_fixture(tmp_path, "owner" if owner["id"] == "owner-journal" else "reporting")


def contents(path):
    with sqlite3.connect(path) as db:
        return list(db.iterdump())


def schema(path):
    with sqlite3.connect(path) as db:
        tables = [
            row[0]
            for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")
            if row[0] not in {"alembic_version", "sqlite_sequence"}
        ]
        return {
            name: (
                db.execute(f'PRAGMA table_info("{name}")').fetchall(),
                sorted(
                    (r[2], tuple(x[2] for x in db.execute(f'PRAGMA index_info("{r[1]}")')))
                    for r in db.execute(f'PRAGMA index_list("{name}")')
                ),
            )
            for name in tables
        }


def execute(module, path, history=None, direction="upgrade", revision="head"):
    engine = create_engine(
        URL.create("sqlite", database=str(path)), connect_args={"isolation_level": None}
    )
    event.listen(engine, "begin", lambda connection: connection.exec_driver_sql("BEGIN EXCLUSIVE"))
    try:
        with engine.begin() as connection:
            config = module.configuration(connection)
            if history:
                config.set_main_option("script_location", str(history))
            getattr(command, direction)(config, revision)
    finally:
        engine.dispose()


@pytest.mark.parametrize("owner", OWNERS, ids=lambda owner: owner["id"])
def test_preserved_v1_adoption_is_idempotent(owner, tmp_path):
    path = fixture(owner, tmp_path)
    before = contents(path)
    module = importlib.import_module(owner["migrations"])
    module.upgrade(path)
    first = contents(path)
    module.upgrade(path)
    assert contents(path) == first
    assert [line for line in first if "alembic_version" not in line] == before
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT version_num FROM alembic_version").fetchall() == [(module.HEAD,)]
        assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)


@pytest.mark.parametrize("owner", OWNERS, ids=lambda owner: owner["id"])
def test_alembic_baseline_matches_preserved_schema_and_refuses_downgrade(owner, tmp_path):
    legacy = fixture(owner, tmp_path)
    fresh = tmp_path / "fresh.sqlite"
    module = importlib.import_module(owner["migrations"])
    execute(module, fresh)
    assert schema(fresh) == schema(legacy)
    before = contents(fresh)
    with pytest.raises(RuntimeError, match="forward-only"):
        execute(module, fresh, direction="downgrade", revision="base")
    assert contents(fresh) == before


@pytest.mark.parametrize("owner", OWNERS, ids=lambda owner: owner["id"])
def test_unknown_or_corrupted_schema_is_not_adopted(owner, tmp_path):
    path = fixture(owner, tmp_path)
    module = importlib.import_module(owner["migrations"])
    module.upgrade(path)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE alembic_version SET version_num='future-unrecognized'")
    before = contents(path)
    with pytest.raises(ValueError, match="unsupported migration revision"):
        module.upgrade(path)
    assert contents(path) == before
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE alembic_version")
        db.execute("ALTER TABLE meta ADD COLUMN unrecognized TEXT")
    before = contents(path)
    with pytest.raises(ValueError, match="unrecognized legacy schema"):
        module.upgrade(path)
    assert contents(path) == before
    with pytest.raises(ValueError, match="existing state"):
        module.upgrade(tmp_path / "missing.sqlite")
    assert not (tmp_path / "missing.sqlite").exists()


@pytest.mark.parametrize("owner", OWNERS, ids=lambda owner: owner["id"])
def test_migration_failure_and_process_death_roll_back_then_retry(owner, tmp_path):
    path = fixture(owner, tmp_path)
    module = importlib.import_module(owner["migrations"])
    module.upgrade(path)
    before = contents(path)
    history = tmp_path / "history"
    shutil.copytree(
        Path(module.__file__).parent, history, ignore=shutil.ignore_patterns("__pycache__")
    )
    revision = history / "versions/v1_0002.py"
    prefix = """from alembic import op
revision = "v1_0002"
down_revision = "v1_0001"
def upgrade():
    op.execute("CREATE TABLE migration_probe(value TEXT NOT NULL)")
    op.execute("INSERT INTO migration_probe VALUES ('synthetic')")
"""
    revision.write_text(prefix + '    raise RuntimeError("injected migration failure")\n')
    with pytest.raises(RuntimeError, match="injected migration failure"):
        execute(module, path, history)
    assert contents(path) == before
    revision.write_text(prefix + "    import os\n    os._exit(23)\n")
    shutil.rmtree(history / "versions/__pycache__", ignore_errors=True)
    script = """import importlib, sys
from pathlib import Path
from tests.test_migrations import execute
execute(importlib.import_module(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
"""
    child = subprocess.run(
        [sys.executable, "-B", "-c", script, owner["migrations"], str(path), str(history)],
        capture_output=True,
        timeout=watchdog(15),
        check=False,
    )
    assert child.returncode == 23, child.stderr.decode()
    assert contents(path) == before
    revision.write_text(prefix)
    shutil.rmtree(history / "versions/__pycache__", ignore_errors=True)
    execute(module, path, history)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT value FROM migration_probe").fetchall() == [("synthetic",)]
        assert db.execute("SELECT version_num FROM alembic_version").fetchall() == [("v1_0002",)]
        assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    with pytest.raises(
        ValueError, match=r"unrecognized legacy state|unsupported migration revision"
    ):
        module.upgrade(path)


@pytest.mark.parametrize("owner", OWNERS, ids=lambda owner: owner["id"])
def test_store_open_rejects_unknown_alembic_revision_without_changing_state(owner, tmp_path):
    from fishhat_owner.journal import Journal
    from fishhat_reporting.store import EventStore

    from tests.test_engineering import EPOCH, OWNER, SERVICE, event

    path = fixture(owner, tmp_path)
    module = importlib.import_module(owner["migrations"])
    module.upgrade(path)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE alembic_version SET version_num='future-unrecognized'")
    before = contents(path)
    with pytest.raises(ValueError, match="unsupported migration revision"):
        if owner["id"] == "owner-journal":
            Journal(path, OWNER, EPOCH)
        else:
            EventStore(path, event()["domain_id"], SERVICE)
    assert contents(path) == before


def test_alembic_requires_a_real_sqlite_transaction_before_ddl(tmp_path):
    from fishhat_owner import migrations

    engine = create_engine(URL.create("sqlite", database=str(tmp_path / "example.sqlite")))
    try:
        with engine.begin() as connection, pytest.raises(RuntimeError, match="transaction-owned"):
            command.upgrade(migrations.configuration(connection), "head")
        with engine.connect() as connection:
            assert (
                list(
                    connection.exec_driver_sql("SELECT name FROM sqlite_master WHERE type='table'")
                )
                == []
            )
    finally:
        engine.dispose()


CHECK_OVERRIDES = {
    "test_preserved_v1_adoption_is_idempotent": {
        "purpose": "implementation",
        "authority": ["state/inventory.toml"],
        "scope": "local SQLite migration history; not native first-write recovery",
        "relationship": "scoped-witness",
        "reason": "Immutable fixture data, literal revision/schema assertions, controlled failing DDL and process-death rollback/retry.",
        "claims": ["migration:owner-journal", "migration:reported-events"],
    },
    "test_alembic_baseline_matches_preserved_schema_and_refuses_downgrade": {
        "purpose": "implementation",
        "authority": ["state/inventory.toml"],
        "scope": "local SQLite migration history; not native first-write recovery",
        "relationship": "scoped-witness",
        "reason": "Immutable fixture data, literal revision/schema assertions, controlled failing DDL and process-death rollback/retry.",
        "claims": ["migration:owner-journal", "migration:reported-events"],
    },
    "test_unknown_or_corrupted_schema_is_not_adopted": {
        "purpose": "implementation",
        "authority": ["state/inventory.toml"],
        "scope": "local SQLite migration history; not native first-write recovery",
        "relationship": "scoped-witness",
        "reason": "Immutable fixture data, literal revision/schema assertions, controlled failing DDL and process-death rollback/retry.",
        "claims": ["migration:owner-journal", "migration:reported-events"],
    },
    "test_store_open_rejects_unknown_alembic_revision_without_changing_state": {
        "purpose": "implementation",
        "authority": ["state/inventory.toml"],
        "scope": "local SQLite migration history; not native first-write recovery",
        "relationship": "scoped-witness",
        "reason": "Immutable fixture data, literal revision/schema assertions, controlled failing DDL and process-death rollback/retry.",
        "claims": ["migration:owner-journal", "migration:reported-events"],
    },
    "test_alembic_requires_a_real_sqlite_transaction_before_ddl": {
        "purpose": "implementation",
        "authority": ["state/inventory.toml"],
        "scope": "local SQLite migration history; not native first-write recovery",
        "relationship": "scoped-witness",
        "reason": "Immutable fixture data, literal revision/schema assertions, controlled failing DDL and process-death rollback/retry.",
        "claims": ["migration:owner-journal", "migration:reported-events"],
    },
    "test_migration_failure_and_process_death_roll_back_then_retry": {
        "purpose": "implementation",
        "authority": ["state/inventory.toml"],
        "scope": "local SQLite migration history; not native first-write recovery",
        "relationship": "scoped-witness",
        "reason": "Immutable fixture data, literal revision/schema assertions, controlled failing DDL and process-death rollback/retry.",
        "claims": ["migration:owner-journal", "migration:reported-events"],
    },
}
