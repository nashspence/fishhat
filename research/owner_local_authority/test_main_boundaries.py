"""Opt-in counterexamples against main's maintained owner Journal, not a new owner.

These tests model only local accepted-work state. They do not execute native
operations, authenticate real OS callers, or qualify a real host's storage.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from fishhat_contracts.validation import ContractError
from fishhat_owner.journal import Journal

OWNER = "local-test-host"
EPOCH = "11111111-1111-4111-8111-111111111111"
SUBJECT = {"scope": "host-local:demo", "delta": 1}


def _accept(local: Journal, request_id: str, *, authorized: bool = True) -> dict:
    return local.submit(
        request_id, SUBJECT, principal="receiver-test-actor", authorized=authorized,
        expected_epoch=EPOCH, expected_generation=0, expires=20, now=10,
    )


def _copy_consistent(source: Path, destination: Path) -> None:
    """SQLite online-backup snapshot; never assume copying an open WAL file is safe."""
    with sqlite3.connect(source) as db, sqlite3.connect(destination) as target:
        db.backup(target)


def test_main_owner_locally_accepts_and_replays_without_other_authority(tmp_path: Path):
    path = tmp_path / "owner.sqlite"
    local = Journal(path, OWNER, EPOCH, initialize=True)
    try:
        with pytest.raises(ContractError, match="permission denied"):
            _accept(local, "denied", authorized=False)
        original = _accept(local, "request")
        assert original["state"] == "accepted"
    finally:
        local.close()
    reopened = Journal(path, OWNER, EPOCH)
    try:
        assert _accept(reopened, "request") == original
        with pytest.raises(ContractError, match="owner epoch mismatch"):
            Journal(path, OWNER, "22222222-2222-4222-8222-222222222222")
    finally:
        reopened.close()


def test_main_owner_never_treats_unresolved_effect_as_absent(tmp_path: Path):
    path = tmp_path / "owner.sqlite"
    local = Journal(path, OWNER, EPOCH, initialize=True)
    try:
        _accept(local, "uncertain")
        local.transition("uncertain", "running", "unknown")
    finally:
        local.close()
    reopened = Journal(path, OWNER, EPOCH)
    try:
        with pytest.raises(ContractError, match="positive no-effect evidence required"):
            reopened.transition("uncertain", "failed", "none")
        with pytest.raises(ContractError, match="resource held/busy"):
            _accept(reopened, "later")
        assert reopened.db.execute(
            "SELECT effect FROM requests WHERE request_id='uncertain'"
        ).fetchone() == ("unknown",)
    finally:
        reopened.close()


def test_disconnected_copies_do_not_elect_global_owner(tmp_path: Path):
    initial = tmp_path / "initial.sqlite"
    local = Journal(initial, OWNER, EPOCH, initialize=True)
    local.close()
    first, second = tmp_path / "host-a.sqlite", tmp_path / "host-b.sqlite"
    _copy_consistent(initial, first)
    _copy_consistent(initial, second)
    a, b = Journal(first, OWNER, EPOCH), Journal(second, OWNER, EPOCH)
    try:
        assert _accept(a, "same-local-request")["state"] == "accepted"
        assert _accept(b, "same-local-request")["state"] == "accepted"
        # Both decisions are local facts. Neither grants an external global lock.
    finally:
        a.close()
        b.close()


def test_complete_local_rollback_is_not_detected_by_the_rolled_back_state(tmp_path: Path):
    path, earlier = tmp_path / "current.sqlite", tmp_path / "prior.sqlite"
    local = Journal(path, OWNER, EPOCH, initialize=True)
    local.close()
    _copy_consistent(path, earlier)
    current = Journal(path, OWNER, EPOCH)
    try:
        _accept(current, "later-accepted")
    finally:
        current.close()
    with sqlite3.connect(earlier) as source, sqlite3.connect(path) as target:
        # Restore a previously consistent image of the entire owner-local DB.
        source.backup(target)
    rolled_back = Journal(path, OWNER, EPOCH)
    try:
        assert rolled_back.db.execute(
            "SELECT 1 FROM requests WHERE request_id='later-accepted'"
        ).fetchone() is None
        assert _accept(rolled_back, "later-accepted")["state"] == "accepted"
        # This proves the absence of an independent monotonic anti-rollback
        # witness in copyable local state; it is not permission to replay effects.
    finally:
        rolled_back.close()
