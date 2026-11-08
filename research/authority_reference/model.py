"""Test-only, executable authority model; NOT a native fishhat owner or enforcer.

The owner and the resource have separate SQLite files to model separate rollback
and serialization domains. Resource methods represent *one* serialized resource
service, not clients sharing SQLite WAL over a network. Its entire write path is
inside one resource transaction. Real drivers must qualify this same invariant.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from pathlib import Path
from typing import Any

from fishhat_contracts.validation import canonical, validate


class UnsafeAuthority(RuntimeError):
    """A proposed effect lacks positive authority, custody or certainty."""


def _connection(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(path, isolation_level=None, timeout=5)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    return db


def _commit(db: sqlite3.Connection, operation: Any) -> Any:
    db.execute("BEGIN IMMEDIATE")
    try:
        result = operation()
        db.commit()
        return result
    except BaseException:
        db.rollback()
        raise


class TransactionalResource:
    """Reference resource-side serializable fence plus atomic effect/idempotency log.

    The resource's database is NOT a deployable multi-host service. Each method
    simulates an RPC handled by the *single* authoritative resource. No method
    authorizes fishhat management. Live-memory clones of the same session remain
    indistinguishable; the opt-in counterexamples exercise that limitation.
    """

    def __init__(self, path: Path, *, initialize: bool = False) -> None:
        if initialize and path.exists():
            raise UnsafeAuthority("RESOURCE_ALREADY_INITIALIZED")
        if not path.exists() and not initialize:
            raise UnsafeAuthority("RESOURCE_MISSING")
        self.path = path
        self.available = True
        with _connection(path) as db:
            if initialize:
                db.executescript(
                    "CREATE TABLE IF NOT EXISTS writers("
                    "scope TEXT PRIMARY KEY, generation INTEGER NOT NULL, session TEXT, value INTEGER NOT NULL);"
                    "CREATE TABLE IF NOT EXISTS effects("
                    "id TEXT PRIMARY KEY, scope TEXT NOT NULL, delta INTEGER NOT NULL, "
                    "state TEXT NOT NULL, result INTEGER);"
                )

    def _connect(self) -> sqlite3.Connection:
        if not self.available:
            raise UnsafeAuthority("RESOURCE_UNAVAILABLE")
        return _connection(self.path)

    def generation(self, scope: str) -> int:
        with self._connect() as db:
            row = db.execute("SELECT generation FROM writers WHERE scope=?", (scope,)).fetchone()
            return 0 if row is None else int(row[0])

    def claim(self, scope: str, expected: int, session: str) -> int:
        if not session:
            raise UnsafeAuthority("EMPTY_SESSION")
        with self._connect() as db:
            def change() -> int:
                row = db.execute(
                    "SELECT generation FROM writers WHERE scope=?", (scope,)
                ).fetchone()
                current = 0 if row is None else int(row[0])
                if current != expected:
                    raise UnsafeAuthority("FENCE_STALE")
                if row is None:
                    db.execute(
                        "INSERT INTO writers VALUES(?,?,?,0)", (scope, current + 1, session)
                    )
                else:
                    db.execute(
                        "UPDATE writers SET generation=?,session=? WHERE scope=?",
                        (current + 1, session, scope),
                    )
                return current + 1
            return int(_commit(db, change))

    def observe(self, effect_id: str) -> tuple[str, int, str, int | None] | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT scope,delta,state,result FROM effects WHERE id=?", (effect_id,)
            ).fetchone()
            return None if row is None else (str(row[0]), int(row[1]), str(row[2]), row[3])

    def effect(self, scope: str, generation: int, session: str, effect_id: str, delta: int) -> int:
        """Enforce the fence and commit the effect in the SAME resource transaction."""
        if type(delta) is not int:
            raise UnsafeAuthority("INVALID_EFFECT")
        with self._connect() as db:
            def change() -> int:
                previous = db.execute(
                    "SELECT scope,delta,state,result FROM effects WHERE id=?", (effect_id,)
                ).fetchone()
                if previous is not None:
                    if (previous[0], previous[1]) != (scope, delta):
                        raise UnsafeAuthority("EFFECT_ID_CONFLICT")
                    if previous[2] == "absent":
                        raise UnsafeAuthority("EFFECT_PERMANENTLY_CLOSED")
                    return int(previous[3])
                writer = db.execute(
                    "SELECT generation,session,value FROM writers WHERE scope=?", (scope,)
                ).fetchone()
                if writer is None or (writer[0], writer[1]) != (generation, session):
                    raise UnsafeAuthority("FENCE_STALE")
                value = int(writer[2]) + delta
                db.execute("UPDATE writers SET value=? WHERE scope=?", (value, scope))
                db.execute(
                    "INSERT INTO effects VALUES(?,?,?,?,?)",
                    (effect_id, scope, delta, "applied", value),
                )
                return value
            return int(_commit(db, change))

    def close_absent(self, scope: str, effect_id: str, delta: int) -> bool:
        """Atomic no-effect tombstone: prevents a late use of this exact effect ID."""
        with self._connect() as db:
            def change() -> bool:
                previous = db.execute(
                    "SELECT scope,delta,state FROM effects WHERE id=?", (effect_id,)
                ).fetchone()
                if previous is not None:
                    if (previous[0], previous[1]) != (scope, delta):
                        raise UnsafeAuthority("EFFECT_ID_CONFLICT")
                    return previous[2] == "absent"
                db.execute(
                    "INSERT INTO effects VALUES(?,?,?,?,NULL)",
                    (effect_id, scope, delta, "absent"),
                )
                return True
            return bool(_commit(db, change))

    def value(self, scope: str) -> int:
        with self._connect() as db:
            row = db.execute("SELECT value FROM writers WHERE scope=?", (scope,)).fetchone()
            return 0 if row is None else int(row[0])


class LocalOwner:
    """Portable SQLite acceptance/recovery reference, not installed native state.

    Starting a new object is a process restart: no cached writer activation is
    restored. Only this owner's local DB is consulted for admission and reads.
    A cloned DB is locally indistinguishable from its original: production effects
    require an independently claimed resource generation on each cold start.
    """

    def __init__(self, path: Path, owner: dict[str, str], *, initialize: bool = False) -> None:
        validate("common.schema.json", owner, "Owner")
        if initialize and path.exists():
            raise UnsafeAuthority("OWNER_ALREADY_INITIALIZED")
        if not path.exists() and not initialize:
            raise UnsafeAuthority("OWNER_STATE_MISSING")
        self.path = path
        self.owner = dict(owner)
        self.db = _connection(path)
        if initialize:
            self.db.executescript(
                "CREATE TABLE IF NOT EXISTS meta(owner TEXT PRIMARY KEY);"
                "CREATE TABLE IF NOT EXISTS requests("
                "id TEXT PRIMARY KEY, body BLOB NOT NULL, principal TEXT NOT NULL, "
                "state TEXT NOT NULL, certainty TEXT NOT NULL, result INTEGER);"
                "CREATE TABLE IF NOT EXISTS activations("
                "id TEXT PRIMARY KEY, scope TEXT NOT NULL, expected INTEGER NOT NULL, "
                "session TEXT NOT NULL, generation INTEGER, state TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS history("
                "origin TEXT NOT NULL, request_id TEXT NOT NULL, body BLOB NOT NULL, "
                "principal TEXT NOT NULL, state TEXT NOT NULL, certainty TEXT NOT NULL, "
                "PRIMARY KEY(origin,request_id));"
            )
            _commit(self.db, lambda: self.db.execute(
                "INSERT INTO meta VALUES(?)", (canonical(owner).decode("utf-8"),)
            ))
        row = self.db.execute("SELECT owner FROM meta").fetchone()
        if row is None or row[0] != canonical(owner).decode("utf-8"):
            self.db.close()
            raise UnsafeAuthority("OWNER_EPOCH_MISMATCH")
        self.live: dict[str, tuple[int, str]] = {}

    def close(self) -> None:
        self.db.close()

    def accepted(self, request_id: str) -> dict[str, Any] | None:
        row = self.db.execute(
            "SELECT body,principal,state,certainty,result FROM requests WHERE id=?",
            (request_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "body": json.loads(row[0]), "principal": row[1], "state": row[2],
            "certainty": row[3], "result": row[4],
        }

    def accept(self, request_id: str, subject: dict[str, Any], principal: str, *,
               authorized: bool) -> dict[str, Any]:
        if not authorized:
            raise UnsafeAuthority("LOCAL_PERMISSION_DENIED")
        if (
            set(subject) != {"scope", "delta"}
            or not isinstance(subject["scope"], str)
            or not subject["scope"]
            or type(subject["delta"]) is not int
        ):
            raise UnsafeAuthority("INVALID_INTENT")
        body = canonical(subject)
        def change() -> None:
            old = self.db.execute(
                "SELECT body FROM requests WHERE id=?", (request_id,)
            ).fetchone()
            if old is not None:
                if old[0] != body:
                    raise UnsafeAuthority("REQUEST_ID_CONFLICT")
                return
            reused = self.db.execute(
                "SELECT 1 FROM history WHERE request_id=? LIMIT 1", (request_id,)
            ).fetchone()
            if reused is not None:
                raise UnsafeAuthority("HISTORICAL_REQUEST_ID")
            self.db.execute(
                "INSERT INTO requests VALUES(?,?,?,'accepted','none',NULL)",
                (request_id, body, principal),
            )
        _commit(self.db, change)
        result = self.accepted(request_id)
        assert result is not None
        return result

    def claim(self, activation_id: str, scope: str, resource: TransactionalResource, *,
              authorized: bool) -> int:
        """Persist pending first; never reanimate a saved session on cold open."""
        if not authorized:
            raise UnsafeAuthority("LOCAL_PERMISSION_DENIED")
        # No operation may call a remote resource while reserving SQLite writer.
        row = self.db.execute(
            "SELECT scope,expected,session,state,generation FROM activations WHERE id=?",
            (activation_id,),
        ).fetchone()
        if row is None:
            expected = resource.generation(scope)
            session = secrets.token_hex(24)
            def write_pending() -> None:
                old = self.db.execute(
                    "SELECT scope FROM activations WHERE id=?", (activation_id,)
                ).fetchone()
                if old is not None:
                    raise UnsafeAuthority("ACTIVATION_RACE_RETRY")
                self.db.execute(
                    "INSERT INTO activations VALUES(?,?,?,?,NULL,'pending')",
                    (activation_id, scope, expected, session),
                )
            _commit(self.db, write_pending)
            row = self.db.execute(
                "SELECT scope,expected,session,state,generation FROM activations WHERE id=?",
                (activation_id,),
            ).fetchone()
        assert row is not None
        if row[0] != scope:
            raise UnsafeAuthority("ACTIVATION_ID_CONFLICT")
        if row[3] == "active":
            # Historical evidence, NOT a new live writer grant on restart.
            if self.live.get(scope) != (row[4], row[2]):
                raise UnsafeAuthority("REACTIVATION_REQUIRED")
            return int(row[4])
        if row[3] != "pending":
            raise UnsafeAuthority("ACTIVATION_CLOSED")
        expected, session = int(row[1]), str(row[2])
        generation = resource.claim(scope, expected, session)
        _commit(self.db, lambda: self.db.execute(
            "UPDATE activations SET state='active',generation=? WHERE id=? AND state='pending'",
            (generation, activation_id),
        ))
        self.live[scope] = (generation, session)
        return generation

    def run(self, request_id: str, resource: TransactionalResource) -> int:
        """Commit uncertain dispatch locally *before* touching the resource."""
        result = self.accepted(request_id)
        if result is None:
            raise UnsafeAuthority("NOT_ACCEPTED")
        if result["state"] == "succeeded":
            return int(result["result"])
        if result["state"] != "accepted":
            raise UnsafeAuthority("RECONCILIATION_REQUIRED")
        subject = result["body"]
        scope = subject["scope"]
        if scope not in self.live:
            raise UnsafeAuthority("FENCE_NOT_ACTIVATED")
        generation, session = self.live[scope]
        def reserve_dispatch() -> None:
            changed = self.db.execute(
                "UPDATE requests SET state='dispatched',certainty='unknown' "
                "WHERE id=? AND state='accepted'", (request_id,)
            )
            if changed.rowcount != 1:
                raise UnsafeAuthority("RECONCILIATION_REQUIRED")
        _commit(self.db, reserve_dispatch)
        # A lost response leaves a durable unknown; do not repeat this call blindly.
        value = resource.effect(scope, generation, session, request_id, subject["delta"])
        self._settle(request_id, "succeeded", "known", value)
        return value

    def _settle(self, request_id: str, state: str, certainty: str, value: int | None) -> None:
        def change() -> None:
            row = self.db.execute(
                "SELECT state FROM requests WHERE id=?", (request_id,)
            ).fetchone()
            if row is None or row[0] != "dispatched":
                raise UnsafeAuthority("SETTLEMENT_PREDECESSOR_CHANGED")
            self.db.execute(
                "UPDATE requests SET state=?,certainty=?,result=? WHERE id=?",
                (state, certainty, value, request_id),
            )
        _commit(self.db, change)

    def reconcile(self, request_id: str, resource: TransactionalResource) -> dict[str, Any]:
        retained = self.accepted(request_id)
        if retained is None:
            raise UnsafeAuthority("NOT_ACCEPTED")
        if retained["state"] != "dispatched":
            return retained
        fact = resource.observe(request_id)
        if fact is None:
            raise UnsafeAuthority("EFFECT_UNRESOLVED")
        subject = retained["body"]
        if (fact[0], fact[1]) != (subject["scope"], subject["delta"]):
            raise UnsafeAuthority("EFFECT_ID_CONFLICT")
        if fact[2] == "applied":
            self._settle(request_id, "succeeded", "known", fact[3])
        elif fact[2] == "absent":
            self._settle(request_id, "failed", "none", None)
        else:
            raise UnsafeAuthority("INVALID_RESOURCE_FACT")
        result = self.accepted(request_id)
        assert result is not None
        return result

    def close_absent(self, request_id: str, resource: TransactionalResource) -> dict[str, Any]:
        retained = self.accepted(request_id)
        if retained is None or retained["state"] != "dispatched":
            raise UnsafeAuthority("NOT_UNCERTAIN")
        subject = retained["body"]
        if not resource.close_absent(subject["scope"], request_id, subject["delta"]):
            raise UnsafeAuthority("EFFECT_ALREADY_APPLIED")
        return self.reconcile(request_id, resource)

    def export_manifest(self) -> tuple[str, list[tuple[str, bytes, str, str, str]]]:
        records = self.db.execute(
            "SELECT id,body,principal,state,certainty FROM requests ORDER BY id"
        ).fetchall()
        material = [[r[0], json.loads(r[1]), r[2], r[3], r[4]] for r in records]
        earlier = [
            [r[0], r[1], json.loads(r[2]), r[3], r[4], r[5]]
            for r in self.db.execute(
                "SELECT origin,request_id,body,principal,state,certainty "
                "FROM history ORDER BY origin,request_id"
            )
        ]
        identity = hashlib.sha256(
            canonical({"owner": self.owner, "records": material, "history": earlier})
        ).hexdigest()
        return "sha256:" + identity, records

    @classmethod
    def restore(cls, source: LocalOwner, destination: Path, new_owner: dict[str, str], *,
                expected_manifest: str, approved: bool) -> LocalOwner:
        """Historical custody only. Caller independently pins manifest; no anti-rollback proof."""
        if not approved:
            raise UnsafeAuthority("RESTORE_NOT_APPROVED")
        if new_owner["epoch"] == source.owner["epoch"] or any(
            json.loads(row[0])["epoch"] == new_owner["epoch"]
            for row in source.db.execute("SELECT DISTINCT origin FROM history")
        ):
            raise UnsafeAuthority("RESTORED_EPOCH_REUSED")
        manifest, records = source.export_manifest()
        if manifest != expected_manifest:
            raise UnsafeAuthority("RESTORE_MANIFEST_MISMATCH")
        destination_owner = cls(destination, new_owner, initialize=True)
        try:
            origin = canonical(source.owner).decode("utf-8")
            def commit_history() -> None:
                for row in source.db.execute(
                    "SELECT origin,request_id,body,principal,state,certainty FROM history"
                ):
                    destination_owner.db.execute("INSERT INTO history VALUES(?,?,?,?,?,?)", row)
                for request_id, body, principal, state, certainty in records:
                    destination_owner.db.execute(
                        "INSERT INTO history VALUES(?,?,?,?,?,?)",
                        (origin, request_id, body, principal, state, certainty),
                    )
            _commit(destination_owner.db, commit_history)
            return destination_owner
        except BaseException:
            destination_owner.close()
            raise
