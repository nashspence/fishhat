"""Offline owner admission/replay model. No worker, native effect or SSH auth.

The `authorized` argument represents an already trusted receiver decision in a
unit test. A production caller cannot assert that decision in request JSON.

The minimal requests rows are epoch-lifetime replay reservations, independent of
optional terminal-detail history. They are never garbage-collected or reused;
capacity refusal for new identities must preserve these accepted commitments.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, cast

from fishhat_contracts.bounds import Bounds, bounds
from fishhat_contracts.validation import ROOT, ContractError, digest

from fishhat_owner.migrations import check_revision

STATES = json.loads((ROOT / "contracts/states.json").read_text())["owner"]


class Journal:
    def __init__(self, path: Path, owner: str, epoch: str, initialize: bool = False):
        new = not path.exists()
        if new and not initialize:
            raise ContractError("missing journal is not empty state")
        self.db = sqlite3.connect(path)
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version != 1 and not (new and initialize and version == 0):
            self.db.close()
            raise ContractError("unsupported journal schema")
        try:
            check_revision(self.db)
        except Exception:
            self.db.close()
            raise
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA busy_timeout=5000")
        if new:
            with self.db:
                self.db.execute("PRAGMA user_version=1")
                self.db.execute(
                    "CREATE TABLE IF NOT EXISTS meta(owner TEXT PRIMARY KEY,epoch TEXT NOT NULL,generation INTEGER NOT NULL)"
                )
                self.db.execute(
                    "CREATE TABLE IF NOT EXISTS requests(request_id TEXT PRIMARY KEY,payload_digest TEXT NOT NULL,principal TEXT NOT NULL,state TEXT NOT NULL,effect TEXT NOT NULL)"
                )
                self.db.execute("INSERT OR IGNORE INTO meta VALUES(?,?,0)", (owner, epoch))
        try:
            found = self.db.execute("SELECT owner,epoch FROM meta").fetchone()
        except sqlite3.DatabaseError as exc:
            self.db.close()
            raise ContractError("invalid journal") from exc
        if found != (owner, epoch):
            self.db.close()
            raise ContractError("owner epoch mismatch")
        self.owner, self.epoch = owner, epoch

    @property
    def generation(self) -> int:
        return cast(int, self.db.execute("SELECT generation FROM meta").fetchone()[0])

    @bounds(
        Bounds(
            id="journal.submit",
            linear_proofs=("tests/test_linear_growth.py::test_journal_linear_work",),
            work="O(retained_requests + input_bytes)-reference-scan",
            extent="one-durable-request-identity",
            limits=(),
            capacity=(),
            proofs=(
                "tests/test_engineering.py::test_journal_reference_scan_and_replay_identity",
                "tests/test_engineering.py::test_owner_crash_replay_preserves_state",
            ),
        )
    )
    def submit(
        self,
        request_id: str,
        subject: dict[str, Any],
        *,
        principal: str,
        authorized: bool,
        expected_epoch: str,
        expected_generation: int,
        expires: int,
        now: int,
    ) -> dict[str, Any]:
        if not authorized:
            raise ContractError("permission denied")
        if expected_epoch != self.epoch:
            raise ContractError("owner epoch changed")
        # New client attribution does not change immutable request identity.
        payload = digest(
            {
                "subject": subject,
                "epoch": expected_epoch,
                "generation": expected_generation,
                "expires": expires,
            }
        )
        self.db.execute("BEGIN IMMEDIATE")
        try:
            old = self.db.execute(
                "SELECT payload_digest,principal,state,effect FROM requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if old:
                if old[0] != payload:
                    raise ContractError("same ID changed payload")
                self.db.commit()
                return {
                    "request_id": request_id,
                    "principal": old[1],
                    "state": old[2],
                    "effect": old[3],
                }
            if expires <= now:
                raise ContractError("plan expired")
            if self.generation != expected_generation:
                raise ContractError("generation conflict")
            active = self.db.execute(
                "SELECT 1 FROM requests WHERE state IN ('accepted','running','waiting','quarantined') OR (state IN ('failed','cancelled') AND effect != 'none')"
            ).fetchone()
            if active:
                raise ContractError("resource held/busy")
            self.db.execute(
                "INSERT INTO requests VALUES(?,?,?,?,?)",
                (request_id, payload, principal, "accepted", "none"),
            )
            self.db.commit()
            return {
                "request_id": request_id,
                "principal": principal,
                "state": "accepted",
                "effect": "none",
            }
        except Exception:
            self.db.rollback()
            raise

    def transition(self, request_id: str, new_state: str, effect: str) -> None:
        if effect not in ("none", "known", "unknown"):
            raise ContractError("unknown effect classification")
        with self.db:
            old = self.db.execute(
                "SELECT state FROM requests WHERE request_id=?", (request_id,)
            ).fetchone()
            if not old or new_state not in STATES.get(old[0], []):
                raise ContractError("illegal transition")
            if new_state == "succeeded" and effect != "known":
                raise ContractError("success requires verified known effect")
            self.db.execute(
                "UPDATE requests SET state=?,effect=? WHERE request_id=?",
                (new_state, effect, request_id),
            )
            if new_state == "succeeded":
                self.db.execute("UPDATE meta SET generation=generation+1")

    def close(self) -> None:
        self.db.close()
