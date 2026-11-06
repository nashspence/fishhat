"""Owner facts survive weaker summaries; only positive exact evidence resolves uncertainty."""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import sys
from collections import Counter
from pathlib import Path
from unittest.mock import patch

import pytest
from fishhat_contracts import ContractError, canonical, digest
from fishhat_owner import migrations
from fishhat_owner.journal import Journal

from scripts.validation_timeouts import observe_child, watchdog
from tests.linear_support import assert_linear, measure
from tests.test_component_policy import restore_fixture
from tests.test_engineering import EPOCH, OWNER, subject
from tests.test_migrations import contents, execute, preserved_owner_rows

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/states.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Operation/properties/effect_certainty",
    ],
    "scope": "reference owner cumulative facts, independent no-effect evidence, immutable terminal outcomes and retained admission holds",
    "relationship": "candidate",
    "reason": "Temporary SQLite stores and independent receiver callbacks challenge loss of confirmed facts through failure, cancellation, uncertainty, restart and competing connections. This supplies no native effect, proof authentication, cessation or recovery qualification.",
    "claims": [],
}
CHECK_OVERRIDES = {
    "test_complete_effect_resolution_sequences_are_linear": {
        "purpose": "implementation",
        "authority": [
            "fishhat/owner-support/src/fishhat_owner/journal.py#Journal.submit",
            "release.toml#/engineering",
        ],
        "scope": "complete alternating-connection admission, uncertainty-resolution, known/unknown, rejected-transition, success and replay sequences",
        "relationship": "scoped-witness",
        "reason": "Increasing complete histories count Python, JSON and SQLite work from both connections, without a native qualification claim.",
        "claims": ["engineering:journal.submit"],
    },
}


def submit(journal, identity="original", **changes):
    context = dict(
        principal="operator",
        authorized=True,
        expected_epoch=EPOCH,
        expected_generation=0,
        expires=20,
        now=10,
    )
    context.update(changes)
    return journal.submit(identity, subject(), **context)


def context(identity="original", *, revision=1, generation=0):
    return {
        "owner": OWNER,
        "epoch": EPOCH,
        "request_id": identity,
        "payload_digest": digest(
            {"subject": subject(), "epoch": EPOCH, "generation": generation, "expires": 20}
        ),
        "principal": "operator",
        "state": "running",
        "effect": "unknown",
        "revision": revision,
    }


def verifier(approved):
    """Exact already-authenticated receiving context, supplied outside the request."""

    def verify(value):
        expected = approved.get(canonical(value))
        if expected is None:
            raise ContractError("no independently verified exact no-effect proof")
        return expected

    return verify


def reopen(journal, path, **kwargs):
    journal.close()
    return Journal(path, OWNER, EPOCH, **kwargs)


@pytest.mark.parametrize("terminal", ["failed", "cancelled"])
@pytest.mark.parametrize("intermediate", [False, True])
def test_known_facts_cannot_be_erased_directly_or_through_uncertainty(
    tmp_path, terminal, intermediate
):
    path = tmp_path / "owner.sqlite"
    journal = Journal(path, OWNER, EPOCH, initialize=True)
    try:
        submit(journal)
        journal.transition("original", "running", "known")
        if intermediate:
            other = Journal(path, OWNER, EPOCH)
            try:
                other.transition("original", "waiting", "unknown")
                journal.transition("original", "running", "unknown")
            finally:
                other.close()
        journal = reopen(
            journal, path, verify_no_effect=lambda _: pytest.fail("known facts cannot be disproved")
        )
        before = contents(path)
        with pytest.raises(ContractError, match="effect history requires separate recovery"):
            journal.transition("original", terminal, "none")
        assert contents(path) == before
        assert journal.db.execute("SELECT known FROM request_effects").fetchone() == (1,)
        journal.transition("original", terminal, "unknown" if intermediate else "known")
        journal = reopen(journal, path)
        receipt = submit(journal, now=99, principal="replacement-reader")
        assert receipt == {
            "request_id": "original",
            "principal": "operator",
            "state": terminal,
            "effect": "unknown" if intermediate else "known",
        }
        with pytest.raises(ContractError, match="resource held/busy"):
            submit(journal, "next")
        with pytest.raises(ContractError, match="same ID changed payload"):
            submit(journal, expires=21)
        before = contents(path)
        with pytest.raises(ContractError, match="illegal transition"):
            journal.transition("original", terminal, "none")
        assert contents(path) == before
    finally:
        journal.close()


@pytest.mark.parametrize(
    "approval", ["absent", "wrong-request", "wrong-revision", "denied", "invalid-digest"]
)
def test_unknown_cannot_become_none_without_exact_positive_receiver_evidence(tmp_path, approval):
    path = tmp_path / "owner.sqlite"
    approved = context()
    if approval == "wrong-request":
        approved["request_id"] = "other"
    if approval == "wrong-revision":
        approved["revision"] = 0
    proof = "invalid" if approval == "invalid-digest" else digest({"verified": approved})
    verify = None if approval == "absent" else verifier({canonical(approved): proof})
    if approval == "denied":
        verify = verifier({})
    journal = Journal(path, OWNER, EPOCH, initialize=True, verify_no_effect=verify)
    try:
        submit(journal)
        journal.transition("original", "running", "unknown")
        before = contents(path)
        with pytest.raises(ContractError):
            journal.transition("original", "failed", "none")
        assert contents(path) == before
        with pytest.raises(ContractError, match="resource held/busy"):
            submit(journal, "next")
    finally:
        journal.close()


def test_positive_resolution_is_revision_bound_retained_and_does_not_erase_later_facts(tmp_path):
    path = tmp_path / "owner.sqlite"
    selected = context()
    proof = digest({"verified": selected})
    journal = Journal(
        path, OWNER, EPOCH, initialize=True, verify_no_effect=verifier({canonical(selected): proof})
    )
    try:
        submit(journal)
        journal.transition("original", "running", "unknown")
        journal.transition("original", "waiting", "none")
        assert journal.db.execute("SELECT * FROM effect_resolutions").fetchall() == [
            ("original", 1, proof)
        ]
        journal = reopen(journal, path, verify_no_effect=verifier({canonical(selected): proof}))
        journal.transition("original", "running", "unknown")
        before = contents(path)
        with pytest.raises(ContractError, match="no independently verified exact"):
            journal.transition("original", "waiting", "none")
        assert contents(path) == before
        journal.transition("original", "waiting", "known")
        journal.transition("original", "running", "unknown")
        with pytest.raises(ContractError, match="success requires verified known effect"):
            journal.transition("original", "succeeded", "unknown")
        with pytest.raises(ContractError, match="effect history requires separate recovery"):
            journal.transition("original", "failed", "none")
        journal.transition("original", "succeeded", "known")
        assert journal.db.execute("SELECT known,revision,held FROM request_effects").fetchone() == (
            1,
            6,
            0,
        )
        assert journal.db.execute("SELECT * FROM effect_resolutions").fetchall() == [
            ("original", 1, proof)
        ]
        assert submit(journal, now=99)["effect"] == "known"
    finally:
        journal.close()


@pytest.mark.parametrize("uncertain", [False, True])
def test_cancellation_without_effects_can_clear_admission_after_positive_resolution(
    tmp_path, uncertain
):
    path = tmp_path / "owner.sqlite"
    selected = context()
    proof = digest({"verified": selected})
    journal = Journal(
        path, OWNER, EPOCH, initialize=True, verify_no_effect=verifier({canonical(selected): proof})
    )
    try:
        submit(journal)
        if uncertain:
            journal.transition("original", "running", "unknown")
        journal.transition("original", "cancelled", "none")
        journal = reopen(journal, path)
        original = submit(journal, now=99, principal="replacement")
        assert original == {
            "request_id": "original",
            "principal": "operator",
            "state": "cancelled",
            "effect": "none",
        }
        assert submit(journal, "next")["state"] == "accepted"
        assert journal.db.execute("SELECT * FROM effect_resolutions").fetchall() == (
            [("original", 1, proof)] if uncertain else []
        )
    finally:
        journal.close()


def test_imported_history_preserves_rows_and_keeps_unproved_absence_held(tmp_path):
    path = restore_fixture(tmp_path, "owner")
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE alembic_version(version_num VARCHAR(32) NOT NULL PRIMARY KEY)")
        db.execute("INSERT INTO alembic_version VALUES ('v1_0001')")
    execute(migrations, path, revision="v1_0002")
    with sqlite3.connect(path) as db:
        db.execute("UPDATE requests SET state='failed',effect='none'")
        before = db.execute("SELECT * FROM requests").fetchall()
    with pytest.raises(ContractError, match=r"upgrade required|unsupported migration revision"):
        Journal(path, OWNER, EPOCH)
    migrations.upgrade(path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT * FROM requests").fetchall() == before
        assert db.execute("SELECT known,revision,held FROM request_effects").fetchall() == [
            (None, 0, 1)
        ]
    journal = Journal(path, OWNER, EPOCH)
    try:
        with pytest.raises(ContractError, match="resource held/busy"):
            submit(journal, "new")
    finally:
        journal.close()


@pytest.mark.parametrize("failure", ["exception", "process-death"])
def test_effect_history_upgrade_is_atomic_and_retryable(tmp_path, failure):
    path = restore_fixture(tmp_path, "owner")
    before = contents(path)
    history = tmp_path / "history"
    shutil.copytree(
        Path(migrations.__file__).parent, history, ignore=shutil.ignore_patterns("__pycache__")
    )
    revision = history / "versions/v1_0003.py"
    injection = (
        '    raise RuntimeError("injected effect-history failure")'
        if failure == "exception"
        else "    import os; os._exit(39)"
    )
    revision.write_text(
        revision.read_text().replace("\n\ndef downgrade", "\n" + injection + "\n\ndef downgrade")
    )
    script = """import sys
from pathlib import Path
from fishhat_owner import migrations
original = migrations.configuration
def configuration(connection):
    config = original(connection)
    config.set_main_option("script_location", sys.argv[2])
    return config
migrations.configuration = configuration
migrations.upgrade(Path(sys.argv[1]))
"""
    child = subprocess.run(
        [sys.executable, "-B", "-c", script, str(path), str(history)],
        capture_output=True,
        timeout=watchdog(15),
        check=False,
    )
    assert child.returncode == (1 if failure == "exception" else 39), child.stderr.decode()
    assert contents(path) == before
    migrations.upgrade(path)
    assert preserved_owner_rows(contents(path), migrations) == before


@pytest.mark.parametrize("reopen_each", [False, True])
def test_complete_effect_resolution_sequences_are_linear(tmp_path, reopen_each):
    samples = []
    for count in (16, 64, 256):
        path = tmp_path / f"owner-{count}.sqlite"
        approvals = {
            canonical(context(str(i), generation=i)): digest(
                {"verified": context(str(i), generation=i)}
            )
            for i in range(count)
        }
        first = Journal(path, OWNER, EPOCH, initialize=True, verify_no_effect=verifier(approvals))
        second = Journal(path, OWNER, EPOCH, verify_no_effect=verifier(approvals))

        journals = [first, second]
        sql_work = Counter(sqlite=0)
        original_connect = sqlite3.connect

        def progress(sql_work=sql_work):
            sql_work["sqlite"] += 1
            return 0

        def connected(*args, original_connect=original_connect, progress=progress, **kwargs):
            db = original_connect(*args, **kwargs)
            db.set_progress_handler(progress, 1)
            return db

        def complete(
            count=count, journals=journals, reopen_each=reopen_each, approvals=approvals, path=path
        ):
            for i in range(count):
                identity = str(i)
                slot = i % 2
                if reopen_each:
                    journals[slot].close()
                    journals[slot] = Journal(
                        path, OWNER, EPOCH, verify_no_effect=verifier(approvals)
                    )
                journal = journals[slot]
                submit(journal, identity, expected_generation=i)
                journal.transition(identity, "running", "unknown")
                journal.transition(identity, "waiting", "none")
                journal.transition(identity, "running", "known")
                journal.transition(identity, "waiting", "unknown")
                with pytest.raises(
                    ContractError, match="effect history requires separate recovery"
                ):
                    journal.transition(identity, "cancelled", "none")
                journal.transition(identity, "running", "known")
                journal.transition(identity, "succeeded", "known")
                assert (
                    submit(
                        journal, identity, expected_generation=i, now=99, principal="replacement"
                    )["principal"]
                    == "operator"
                )

        try:
            for journal in journals:
                journal.db.set_progress_handler(progress, 1)
            with patch("fishhat_owner.journal.sqlite3.connect", side_effect=connected):
                _, work = measure(complete)
            work.update(sql_work)
            first = journals[0]
            assert first.generation == count
            assert first.db.execute("SELECT count(*) FROM effect_resolutions").fetchone() == (
                count,
            )
            assert first.db.execute(
                "SELECT count(*) FROM request_effects WHERE known=1 AND held=0"
            ).fetchone() == (count,)
            samples.append((count, work))
        finally:
            for journal in journals:
                journal.close()
    assert_linear(samples)


def test_competing_uncertainty_and_cancellation_preserve_confirmed_facts(tmp_path):
    script = """from pathlib import Path
import json,sys
from scripts.validation_timeouts import Policy,using
from tests.test_journal_concurrency import _competing_terminal_transitions
with using(Policy.resolve()) as policy:
    _competing_terminal_transitions(Path(sys.argv[1]), "cancelled", "none", "waiting")
    print(json.dumps(policy.report()))
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=watchdog(90),
    )
    assert result.returncode == 0, result.stderr
    observe_child(json.loads(result.stdout))


@pytest.mark.parametrize("failure", ["exception", "process-death"])
def test_resolution_and_effect_update_commit_atomically(tmp_path, failure):
    path = tmp_path / "owner.sqlite"
    journal = Journal(path, OWNER, EPOCH, initialize=True)
    submit(journal)
    journal.transition("original", "running", "unknown")
    journal.close()
    if failure == "exception":
        with sqlite3.connect(path) as db:
            db.execute(
                "CREATE TRIGGER fail_resolution BEFORE UPDATE ON request_effects BEGIN SELECT RAISE(ABORT,'injected resolution failure'); END"
            )
    before = contents(path)
    script = """import os,sys
from pathlib import Path
from fishhat_owner.journal import Journal
from tests.test_owner_effect_history import OWNER,EPOCH,context,verifier,canonical,digest
selected=context()
j=Journal(Path(sys.argv[1]), OWNER,EPOCH,verify_no_effect=verifier({canonical(selected):digest({"verified":selected})}))
if sys.argv[2] == "process-death":
    def trace(sql):
        if sql.startswith("UPDATE request_effects"):
            os._exit(41)
    j.db.set_trace_callback(trace)
j.transition("original","failed","none")
"""
    child = subprocess.run(
        [sys.executable, "-c", script, str(path), failure],
        capture_output=True,
        timeout=watchdog(15),
    )
    assert child.returncode == (1 if failure == "exception" else 41), child.stderr.decode()
    assert contents(path) == before
    if failure == "exception":
        with sqlite3.connect(path) as db:
            db.execute("DROP TRIGGER fail_resolution")
    selected = context()
    proof = digest({"verified": selected})
    journal = Journal(path, OWNER, EPOCH, verify_no_effect=verifier({canonical(selected): proof}))
    try:
        with pytest.raises(ContractError, match="resource held/busy"):
            submit(journal, "next")
        journal.transition("original", "failed", "none")
        assert journal.db.execute("SELECT * FROM effect_resolutions").fetchall() == [
            ("original", 1, proof)
        ]
        assert submit(journal, "next")["state"] == "accepted"
    finally:
        journal.close()
