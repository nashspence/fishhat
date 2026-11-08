"""Test-only same-host owner/effect model; no central or off-host authority.

Both SQLite databases are **local to one managed computer**. LocalOwner is the
sole management authority. LocalEffectTarget is an owner-enrolled, same-host
native-effect *simulation*, not a network resource, election service, RPC,
SSH authorizer, or a deployable executor. Its transactions model effects on its
own database only. Native effects require separately qualified adapters.

A complete clone of a host, its journal and its protected target can operate
independently elsewhere. Without off-host arbitration no software-only local
algorithm can reject exactly one clone. This model makes no such promise.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from fishhat_contracts.validation import canonical, validate


class UnsafeAuthority(RuntimeError):
    """A proposed operation lacks current local authority, custody, or certainty."""


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


def _origin(owner: dict[str, str]) -> str:
    return canonical(owner).decode("utf-8")


def _effect_id(owner: dict[str, str], scope: str, request_id: str) -> str:
    # Identity is global to this local target's retained history, not merely a
    # client-provided request string. New owner epochs cannot replay old effects.
    data = canonical({"owner": owner, "scope": scope, "request_id": request_id, "step": "apply"})
    return "sha256:" + hashlib.sha256(data).hexdigest()


class LocalEffectTarget:
    """One owner-enrolled same-host transactional effect domain.

    A caller-supplied authorized=True is test-injected, authenticated local
    receiver context. Production must obtain it from trusted local OS/IPC
    credentials, never an untrusted request or source configuration. Every
    claim, outcome and mutation below runs *locally*. The target's database is
    neither an off-host authority nor a network-shared SQLite WAL file.
    """

    def __init__(self, path: Path, owner: dict[str, str], scopes: tuple[str, ...], *,
                 initialize: bool = False) -> None:
        validate("common.schema.json", owner, "Owner")
        if not scopes or any(not isinstance(s, str) or not s for s in scopes) or (
            len(set(scopes)) != len(scopes)
        ):
            raise UnsafeAuthority("INVALID_LOCAL_ENROLLMENT")
        self.scopes = frozenset(scopes)
        if initialize and path.exists():
            raise UnsafeAuthority("TARGET_ALREADY_INITIALIZED")
        if not path.exists() and not initialize:
            raise UnsafeAuthority("TARGET_MISSING")
        self.path = path
        self.owner = dict(owner)
        self.available = True  # Simulates an unavailable *local* native adapter.
        with closing(_connection(path)) as db:
            if initialize:
                db.executescript(
                    "CREATE TABLE meta(owner TEXT NOT NULL);"
                    "CREATE TABLE enrolled(scope TEXT PRIMARY KEY);"
                    "CREATE TABLE writers("
                    "scope TEXT PRIMARY KEY, generation INTEGER NOT NULL, "
                    "session_digest TEXT, value INTEGER NOT NULL);"
                    "CREATE TABLE claims("
                    "origin TEXT NOT NULL, id TEXT NOT NULL, scope TEXT NOT NULL, "
                    "expected INTEGER NOT NULL, session_digest TEXT NOT NULL, "
                    "generation INTEGER NOT NULL, PRIMARY KEY(origin,id));"
                    "CREATE TABLE effects("
                    "id TEXT PRIMARY KEY, origin TEXT NOT NULL, scope TEXT NOT NULL, "
                    "intent BLOB NOT NULL, state TEXT NOT NULL, result INTEGER);"
                )
                def enroll() -> None:
                    db.execute("INSERT INTO meta VALUES(?)", (_origin(owner),))
                    db.executemany("INSERT INTO enrolled VALUES(?)", ((s,) for s in scopes))
                _commit(db, enroll)
            if db.execute("SELECT owner FROM meta").fetchone() != (_origin(owner),):
                raise UnsafeAuthority("TARGET_EPOCH_MISMATCH")
            enrolled = frozenset(row[0] for row in db.execute("SELECT scope FROM enrolled"))
            if enrolled != self.scopes:
                raise UnsafeAuthority("TARGET_SCOPE_MISMATCH")

    def _connect(self) -> sqlite3.Connection:
        if not self.available:
            raise UnsafeAuthority("TARGET_UNAVAILABLE")
        return _connection(self.path)

    def _require(self, db: sqlite3.Connection, owner: dict[str, str], authorized: bool,
                 scope: str | None = None) -> None:
        if not authorized:
            raise UnsafeAuthority("LOCAL_PERMISSION_DENIED")
        if db.execute("SELECT owner FROM meta").fetchone() != (_origin(owner),):
            raise UnsafeAuthority("TARGET_EPOCH_MISMATCH")
        if scope is not None and db.execute(
            "SELECT 1 FROM enrolled WHERE scope=?", (scope,)
        ).fetchone() is None:
            raise UnsafeAuthority("SCOPE_NOT_ENROLLED")

    def generation(self, scope: str, owner: dict[str, str], *, authorized: bool) -> int:
        with closing(self._connect()) as db:
            self._require(db, owner, authorized, scope)
            row = db.execute("SELECT generation FROM writers WHERE scope=?", (scope,)).fetchone()
            return 0 if row is None else int(row[0])

    def claim(self, scope: str, expected: int, session: str, activation_id: str,
              owner: dict[str, str], *, authorized: bool) -> int:
        if not session or not activation_id:
            raise UnsafeAuthority("INVALID_ACTIVATION")
        session_digest = hashlib.sha256(session.encode("utf-8")).hexdigest()
        origin = _origin(owner)
        with closing(self._connect()) as db:
            def change() -> int:
                self._require(db, owner, authorized, scope)
                previous = db.execute(
                    "SELECT scope,expected,session_digest,generation "
                    "FROM claims WHERE origin=? AND id=?", (origin, activation_id)
                ).fetchone()
                if previous is not None:
                    if previous[:3] != (scope, expected, session_digest):
                        raise UnsafeAuthority("ACTIVATION_ID_CONFLICT")
                    return int(previous[3])  # A lost claim reply is idempotently resolvable.
                row = db.execute(
                    "SELECT generation FROM writers WHERE scope=?", (scope,)
                ).fetchone()
                current = 0 if row is None else int(row[0])
                if current != expected:
                    raise UnsafeAuthority("FENCE_STALE")
                if row is None:
                    db.execute(
                        "INSERT INTO writers VALUES(?,?,?,0)",
                        (scope, current + 1, session_digest),
                    )
                else:
                    db.execute(
                        "UPDATE writers SET generation=?,session_digest=? WHERE scope=?",
                        (current + 1, session_digest, scope),
                    )
                db.execute(
                    "INSERT INTO claims VALUES(?,?,?,?,?,?)",
                    (origin, activation_id, scope, expected, session_digest, current + 1),
                )
                return current + 1
            return int(_commit(db, change))

    def observe_claim(self, scope: str, activation_id: str, owner: dict[str, str],
                      *, authorized: bool) -> int | None:
        """Historical claim fact, never a transferable live session credential."""
        with closing(self._connect()) as db:
            self._require(db, owner, authorized)
            row = db.execute(
                "SELECT scope,generation FROM claims WHERE origin=? AND id=?",
                (_origin(owner), activation_id),
            ).fetchone()
            if row is None:
                return None
            if row[0] != scope:
                raise UnsafeAuthority("ACTIVATION_ID_CONFLICT")
            return int(row[1])

    def observe(self, effect_id: str, owner: dict[str, str], *, authorized: bool
                ) -> tuple[str, bytes, str, int | None] | None:
        with closing(self._connect()) as db:
            self._require(db, owner, authorized)
            row = db.execute(
                "SELECT scope,intent,state,result FROM effects WHERE id=?", (effect_id,)
            ).fetchone()
            return None if row is None else (str(row[0]), bytes(row[1]), str(row[2]), row[3])

    def effect(self, scope: str, generation: int, session: str, effect_id: str,
               subject: dict[str, Any], owner: dict[str, str], *, authorized: bool) -> int:
        """Check the local fence, replay identity and simulated effect atomically."""
        if subject.get("scope") != scope or type(subject.get("delta")) is not int:
            raise UnsafeAuthority("INVALID_EFFECT")
        intent = canonical(subject)
        session_digest = hashlib.sha256(session.encode("utf-8")).hexdigest()
        with closing(self._connect()) as db:
            def change() -> int:
                self._require(db, owner, authorized, scope)
                previous = db.execute(
                    "SELECT scope,intent,state,result FROM effects WHERE id=?", (effect_id,)
                ).fetchone()
                if previous is not None:
                    if (previous[0], previous[1]) != (scope, intent):
                        raise UnsafeAuthority("EFFECT_ID_CONFLICT")
                    if previous[2] == "absent":
                        raise UnsafeAuthority("EFFECT_PERMANENTLY_CLOSED")
                    return int(previous[3])
                row = db.execute(
                    "SELECT generation,session_digest,value FROM writers WHERE scope=?",
                    (scope,),
                ).fetchone()
                if row is None or (row[0], row[1]) != (generation, session_digest):
                    raise UnsafeAuthority("FENCE_STALE")
                value = int(row[2]) + int(subject["delta"])
                db.execute("UPDATE writers SET value=? WHERE scope=?", (value, scope))
                db.execute(
                    "INSERT INTO effects VALUES(?,?,?,?,?,?)",
                    (effect_id, _origin(owner), scope, intent, "applied", value),
                )
                return value
            return int(_commit(db, change))

    def close_absent(self, scope: str, effect_id: str, subject: dict[str, Any],
                     owner: dict[str, str], *, authorized: bool) -> bool:
        """Local positive tombstone: serializes against any later same-ID effect."""
        intent = canonical(subject)
        with closing(self._connect()) as db:
            def change() -> bool:
                self._require(db, owner, authorized, scope)
                previous = db.execute(
                    "SELECT scope,intent,state FROM effects WHERE id=?", (effect_id,)
                ).fetchone()
                if previous is not None:
                    if (previous[0], previous[1]) != (scope, intent):
                        raise UnsafeAuthority("EFFECT_ID_CONFLICT")
                    return previous[2] == "absent"
                db.execute(
                    "INSERT INTO effects VALUES(?,?,?,?,?,NULL)",
                    (effect_id, _origin(owner), scope, intent, "absent"),
                )
                return True
            return bool(_commit(db, change))

    def adopt_epoch(self, new_owner: dict[str, str], *, authorized: bool) -> None:
        """Explicit same-host restore authorization, fences all earlier sessions."""
        validate("common.schema.json", new_owner, "Owner")
        if not authorized:
            raise UnsafeAuthority("LOCAL_PERMISSION_DENIED")
        if any(self.owner[k] != new_owner[k] for k in ("tool", "id")) or (
            self.owner["epoch"] == new_owner["epoch"]
        ):
            raise UnsafeAuthority("INVALID_EPOCH_HANDOFF")
        with closing(self._connect()) as db:
            def change() -> None:
                self._require(db, self.owner, True)
                db.execute("UPDATE writers SET generation=generation+1,session_digest=NULL")
                db.execute("UPDATE meta SET owner=?", (_origin(new_owner),))
            _commit(db, change)
        self.owner = dict(new_owner)

    def value(self, scope: str) -> int:
        """Test-only direct inspection, not an exposed management endpoint."""
        with closing(self._connect()) as db:
            row = db.execute("SELECT value FROM writers WHERE scope=?", (scope,)).fetchone()
            return 0 if row is None else int(row[0])


class LocalOwner:
    """Portable owner-local acceptance and recovery without off-host dependencies.

    No saved activation is a live writer after a process restart, even if the
    local activation claim was committed immediately before a lost reply. A
    whole-host clone remains indistinguishable without independent authority;
    local correctness is scoped to one host, not a replicated shared resource.
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
                "CREATE TABLE meta(owner TEXT PRIMARY KEY);"
                "CREATE TABLE requests("
                "id TEXT PRIMARY KEY, body BLOB NOT NULL, principal TEXT NOT NULL, "
                "state TEXT NOT NULL, certainty TEXT NOT NULL, result INTEGER);"
                "CREATE TABLE activations("
                "id TEXT PRIMARY KEY, scope TEXT NOT NULL, expected INTEGER NOT NULL, "
                "session TEXT NOT NULL, generation INTEGER, state TEXT NOT NULL);"
                "CREATE TABLE history("
                "origin TEXT NOT NULL, request_id TEXT NOT NULL, body BLOB NOT NULL, "
                "principal TEXT NOT NULL, state TEXT NOT NULL, certainty TEXT NOT NULL, "
                "result INTEGER, PRIMARY KEY(origin,request_id));"
            )
            _commit(self.db, lambda: self.db.execute("INSERT INTO meta VALUES(?)", (_origin(owner),)))
        if self.db.execute("SELECT owner FROM meta").fetchone() != (_origin(owner),):
            self.db.close()
            raise UnsafeAuthority("OWNER_EPOCH_MISMATCH")
        self.live: dict[str, tuple[int, str]] = {}
        self.pending_here: set[str] = set()

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
            not request_id or not principal or set(subject) != {"scope", "delta"}
            or not isinstance(subject["scope"], str) or not subject["scope"]
            or type(subject["delta"]) is not int
        ):
            raise UnsafeAuthority("INVALID_INTENT")
        body = canonical(subject)
        def change() -> None:
            old = self.db.execute("SELECT body FROM requests WHERE id=?", (request_id,)).fetchone()
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

    def claim(self, activation_id: str, scope: str, target: LocalEffectTarget, *,
              authorized: bool) -> int:
        """A claim can be retried in-process, but never reanimated on cold start."""
        if not authorized:
            raise UnsafeAuthority("LOCAL_PERMISSION_DENIED")
        row = self.db.execute(
            "SELECT scope,expected,session,state,generation FROM activations WHERE id=?",
            (activation_id,),
        ).fetchone()
        if row is None:
            expected = target.generation(scope, self.owner, authorized=True)
            session = secrets.token_hex(24)
            def write_pending() -> None:
                old = self.db.execute(
                    "SELECT 1 FROM activations WHERE id=?", (activation_id,)
                ).fetchone()
                if old is not None:
                    raise UnsafeAuthority("ACTIVATION_RACE_RETRY")
                self.db.execute(
                    "INSERT INTO activations VALUES(?,?,?,?,NULL,'pending')",
                    (activation_id, scope, expected, session),
                )
            _commit(self.db, write_pending)
            self.pending_here.add(activation_id)
            row = self.db.execute(
                "SELECT scope,expected,session,state,generation "
                "FROM activations WHERE id=?", (activation_id,)
            ).fetchone()
        assert row is not None
        if row[0] != scope:
            raise UnsafeAuthority("ACTIVATION_ID_CONFLICT")
        if row[3] == "active":
            if self.live.get(scope) != (row[4], row[2]):
                raise UnsafeAuthority("REACTIVATION_REQUIRED")
            return int(row[4])
        if row[3] != "pending":
            raise UnsafeAuthority("ACTIVATION_CLOSED")
        if activation_id not in self.pending_here:
            raise UnsafeAuthority("REACTIVATION_REQUIRED")
        expected, session = int(row[1]), str(row[2])
        generation = target.claim(
            scope, expected, session, activation_id, self.owner, authorized=True
        )
        def settle() -> None:
            update = self.db.execute(
                "UPDATE activations SET state='active',generation=? "
                "WHERE id=? AND state='pending'", (generation, activation_id),
            )
            if update.rowcount != 1:
                raise UnsafeAuthority("ACTIVATION_PREDECESSOR_CHANGED")
        _commit(self.db, settle)
        self.pending_here.discard(activation_id)
        self.live[scope] = (generation, session)
        return generation

    def run(self, request_id: str, target: LocalEffectTarget, *, authorized: bool) -> int:
        if not authorized:
            raise UnsafeAuthority("LOCAL_PERMISSION_DENIED")
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
        value = target.effect(
            scope, generation, session, _effect_id(self.owner, scope, request_id),
            subject, self.owner, authorized=True,
        )
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

    def reconcile(self, request_id: str, target: LocalEffectTarget, *,
                  authorized: bool) -> dict[str, Any]:
        if not authorized:
            raise UnsafeAuthority("LOCAL_PERMISSION_DENIED")
        retained = self.accepted(request_id)
        if retained is None:
            raise UnsafeAuthority("NOT_ACCEPTED")
        if retained["state"] != "dispatched":
            return retained
        subject = retained["body"]
        fact = target.observe(
            _effect_id(self.owner, subject["scope"], request_id),
            self.owner, authorized=True,
        )
        if fact is None:
            raise UnsafeAuthority("EFFECT_UNRESOLVED")
        if (fact[0], fact[1]) != (subject["scope"], canonical(subject)):
            raise UnsafeAuthority("EFFECT_ID_CONFLICT")
        if fact[2] == "applied":
            self._settle(request_id, "succeeded", "known", fact[3])
        elif fact[2] == "absent":
            self._settle(request_id, "failed", "none", None)
        else:
            raise UnsafeAuthority("INVALID_TARGET_FACT")
        result = self.accepted(request_id)
        assert result is not None
        return result

    def close_absent(self, request_id: str, target: LocalEffectTarget, *,
                     authorized: bool) -> dict[str, Any]:
        if not authorized:
            raise UnsafeAuthority("LOCAL_PERMISSION_DENIED")
        retained = self.accepted(request_id)
        if retained is None or retained["state"] != "dispatched":
            raise UnsafeAuthority("NOT_UNCERTAIN")
        subject = retained["body"]
        if not target.close_absent(
            subject["scope"], _effect_id(self.owner, subject["scope"], request_id),
            subject, self.owner, authorized=True,
        ):
            raise UnsafeAuthority("EFFECT_ALREADY_APPLIED")
        return self.reconcile(request_id, target, authorized=True)

    def _snapshot(self) -> tuple[str, list[tuple], list[tuple]]:
        """A *consistent* local snapshot; caller must independently pin the root."""
        self.db.execute("BEGIN")
        try:
            owner_row = self.db.execute("SELECT owner FROM meta").fetchone()
            if owner_row != (_origin(self.owner),):
                raise UnsafeAuthority("OWNER_EPOCH_MISMATCH")
            records = self.db.execute(
                "SELECT id,body,principal,state,certainty,result FROM requests ORDER BY id"
            ).fetchall()
            history = self.db.execute(
                "SELECT origin,request_id,body,principal,state,certainty,result "
                "FROM history ORDER BY origin,request_id"
            ).fetchall()
            activations = self.db.execute(
                "SELECT id,scope,expected,session,generation,state "
                "FROM activations ORDER BY id"
            ).fetchall()
            identity = hashlib.sha256(canonical({
                "owner": self.owner,
                "records": [[r[0], json.loads(r[1]), *r[2:]] for r in records],
                "history": [[r[0], r[1], json.loads(r[2]), *r[3:]] for r in history],
                "activations": [
                    [r[0], r[1], r[2], hashlib.sha256(r[3].encode()).hexdigest(), *r[4:]]
                    for r in activations
                ],
            })).hexdigest()
            return "sha256:" + identity, records, history
        finally:
            self.db.rollback()  # Releases the read snapshot without modifying state.

    def export_manifest(self) -> tuple[str, list[tuple]]:
        digest, records, _ = self._snapshot()
        return digest, records

    @classmethod
    def restore(cls, source: LocalOwner, destination: Path, new_owner: dict[str, str], *,
                expected_manifest: str, approved: bool) -> LocalOwner:
        """Historical custody only; no off-host approval or rollback oracle."""
        if not approved:
            raise UnsafeAuthority("RESTORE_NOT_APPROVED")
        validate("common.schema.json", new_owner, "Owner")
        if (new_owner["tool"], new_owner["id"]) != (
            source.owner["tool"], source.owner["id"]
        ):
            raise UnsafeAuthority("RESTORE_OWNER_MISMATCH")
        manifest, records, history = source._snapshot()
        if new_owner["epoch"] == source.owner["epoch"] or any(
            json.loads(row[0])["epoch"] == new_owner["epoch"] for row in history
        ):
            raise UnsafeAuthority("RESTORED_EPOCH_REUSED")
        if manifest != expected_manifest:
            raise UnsafeAuthority("RESTORE_MANIFEST_MISMATCH")
        restored = cls(destination, new_owner, initialize=True)
        try:
            origin = _origin(source.owner)
            def commit_history() -> None:
                for row in history:
                    restored.db.execute("INSERT INTO history VALUES(?,?,?,?,?,?,?)", row)
                for request_id, body, principal, state, certainty, result in records:
                    restored.db.execute(
                        "INSERT INTO history VALUES(?,?,?,?,?,?,?)",
                        (origin, request_id, body, principal, state, certainty, result),
                    )
            _commit(restored.db, commit_history)
            return restored
        except BaseException:
            restored.close()
            raise
