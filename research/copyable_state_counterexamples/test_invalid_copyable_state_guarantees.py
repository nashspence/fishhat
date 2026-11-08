"""Deliberately false guarantees from *copyable host-local journal state alone*.

Run only via tests/test_copyable_state_counterexamples.py. Both assertions MUST
fail for the named reasons. Neither is a test of native effect execution or
of designs with independently trusted, host-local noncopyable evidence.

An off-host manager, coordinator, or witness must never become a prerequisite
for host-ops/app-ops to accept, inspect or recover their own local work.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from fishhat_owner.journal import Journal

OWNER = "copyable-state-experiment"
EPOCH = "11111111-1111-4111-8111-111111111111"
SUBJECT = {"scope": "local-only:illustrative", "delta": 1}


def _accept(journal: Journal, request_id: str) -> dict:
    return journal.submit(
        request_id,
        SUBJECT,
        principal="locally-authorized-fixture",
        authorized=True,  # Test-injected receiver decision, not a native credential.
        expected_epoch=EPOCH,
        expected_generation=0,
        expires=20,
        now=10,
    )


def _snapshot(source: Path, destination: Path) -> None:
    # SQLite online backup makes a consistent copy even with WAL; no live
    # network-shared database or external authoritative component is used.
    with sqlite3.connect(source) as opened, sqlite3.connect(destination) as copy:
        opened.backup(copy)


def test_false_claim_disconnected_journal_copies_elect_one_global_writer(tmp_path: Path) -> None:
    """Copyable local records cannot elect a unique writer for *shared* resources."""
    original = tmp_path / "original.db"
    initial = Journal(original, OWNER, EPOCH, initialize=True)
    initial.close()
    host_a, host_b = tmp_path / "host-a.db", tmp_path / "host-b.db"
    _snapshot(original, host_a)
    _snapshot(original, host_b)
    a, b = Journal(host_a, OWNER, EPOCH), Journal(host_b, OWNER, EPOCH)
    try:
        # Independent local admissions are allowed. This does not perform any
        # shared-resource effect or claim the two hosts have a common lock.
        admitted = (
            _accept(a, "identical-local-request")["state"] == "accepted",
            _accept(b, "identical-local-request")["state"] == "accepted",
        )
        assert sum(admitted) == 1, "COPYABLE_STATE_CANNOT_ELECT_GLOBAL_WRITER"
    finally:
        a.close()
        b.close()


def test_false_claim_rolled_back_journal_detects_its_missing_tail(tmp_path: Path) -> None:
    """A fully copied-back journal has no independent freshness evidence."""
    current, prior = tmp_path / "current.db", tmp_path / "prior.db"
    original = Journal(current, OWNER, EPOCH, initialize=True)
    original.close()
    _snapshot(current, prior)
    later = Journal(current, OWNER, EPOCH)
    try:
        _accept(later, "lost-tail")
    finally:
        later.close()
    # Restore the entire copyable journal state to an internally consistent
    # earlier image; no independently protected local monotonic anchor exists.
    _snapshot(prior, current)
    rolled_back = Journal(current, OWNER, EPOCH)
    try:
        assert (
            rolled_back.db.execute("SELECT 1 FROM requests WHERE request_id='lost-tail'").fetchone()
            is not None
        ), "COPYABLE_STATE_CANNOT_ATTEST_ROLLBACK_FRESHNESS"
    finally:
        rolled_back.close()
