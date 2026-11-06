"""Complete retained-state workloads, including retries and interleaved writers."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from collections import Counter

import pytest
from fishhat_contracts import ContractError
from fishhat_owner.journal import Journal
from fishhat_reporting.store import EventStore

from scripts.validation_timeouts import watchdog
from tests.linear_support import assert_linear, measure
from tests.test_contracts import uid
from tests.test_engineering import AUTH, EPOCH, OWNER, SERVICE, event, seed, subject

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": ["release.toml#/engineering"],
    "scope": "complete local SQLite workloads, independent writers, bounded retries and cold reconstruction",
    "relationship": "candidate",
    "reason": "Actual Python, JSON and SQLite work across increasing complete workloads; no native execution qualification.",
    "claims": [],
}

SCALES = (16, 64, 256)
APPEND = {"principal": "test-reader", "scopes": {"append", "read"}}


def measured(call, *stores):
    """Include SQLite work from every participating connection, not just the reader."""
    extra = Counter(sqlite=0)

    def progress():
        extra["sqlite"] += 1
        return 0

    for store in stores[1:]:
        store.db.set_progress_handler(progress, 1)
    try:
        result, work = measure(call, database=stores[0].db)
        work.update(extra)
        return result, work
    finally:
        for store in stores[1:]:
            store.db.set_progress_handler(None, 0)


def test_complete_admission_sequences_are_linear(tmp_path):
    samples = []
    for count in SCALES:
        path = tmp_path / f"owner-{count}.sqlite"
        first = Journal(path, OWNER, EPOCH, initialize=True)
        second = Journal(path, OWNER, EPOCH)
        inputs = [(uid(f"admit-{i}"), subject(), i) for i in range(count)]

        def complete(first=first, second=second, inputs=inputs):
            results = []
            for identity, request, generation in inputs:
                journal = first if generation % 2 else second
                arguments = dict(
                    principal="reader",
                    authorized=True,
                    expected_epoch=EPOCH,
                    expected_generation=generation,
                    expires=200,
                    now=100,
                )
                receipt = journal.submit(identity, request, **arguments)
                assert receipt["state"] == "accepted"
                journal.transition(identity, "running", "none")
                journal.transition(identity, "succeeded", "known")
                arguments.update(now=1000, principal="replacement")
                replay = journal.submit(identity, request, **arguments)
                assert replay == {**receipt, "state": "succeeded", "effect": "known"}
                results.append(replay)
            return results

        try:
            result, work = measured(complete, first, second)
            assert len(result) == first.generation == count
            assert first.db.execute("SELECT count(*) FROM requests").fetchone() == (count,)
            assert first.db.execute(
                "SELECT count(*) FROM requests WHERE state IN ('accepted','running','waiting','quarantined') OR (state IN ('failed','cancelled') AND effect != 'none')"
            ).fetchone() == (0,)
            samples.append((count, work))
        finally:
            second.close()
            first.close()
    assert_linear(samples)


@pytest.mark.parametrize("writer", ["same", "external"])
def test_workflow_traversals_with_interleaved_appends_are_linear(tmp_path, writer):
    samples = []
    for count in SCALES:
        original = event()
        path = tmp_path / f"pages-{count}.sqlite"
        store = EventStore(path, original["domain_id"], SERVICE, initialize=True)
        external = EventStore(path, original["domain_id"], SERVICE)
        seed(store, count, workflows=True)
        expected = [
            row[0] for row in store.db.execute("SELECT workflow_id FROM events ORDER BY sequence")
        ]
        additions = [
            {**original, "id": uid(f"interleaved-{i}"), "workflow_id": expected[0]}
            for i in range(count // 4)
        ]

        def complete(store=store, external=external, additions=additions):
            found, after, index = [], 0, 0
            while True:
                target = store if writer == "same" else external
                value = additions[index]
                assert target.put(value, **APPEND)[0] == 201
                assert target.put(value, **APPEND)[0] == 200
                index += 1
                page = store.workflows(
                    after=after, limit=4, expected_store_epoch=store.epoch, **AUTH
                )
                found.extend(item["workflow_id"] for item in page["items"])
                if page["next_after"] is None:
                    return found
                assert page["next_after"] > after
                after = page["next_after"]

        try:
            found, work = measured(complete, store, external)
            assert found == expected and len(set(found)) == count
            # Reopening explicitly pays one cold reconstruction; it must return
            # the same complete first-seen workflow identities and ordering.
            store.close()
            store = EventStore(path, original["domain_id"], SERVICE)
            found, cold = measured(lambda store=store: all_workflows(store), store)
            assert found == expected
            work.update(cold)
            samples.append((count, work))
        finally:
            external.close()
            store.close()
    assert_linear(samples)


def all_workflows(store):
    found, after = [], 0
    while True:
        page = store.workflows(after=after, limit=4, expected_store_epoch=store.epoch, **AUTH)
        found.extend(item["workflow_id"] for item in page["items"])
        if page["next_after"] is None:
            return found
        after = page["next_after"]


def correction_inputs(count, shape):
    original = event()
    identities = [uid(f"correction-{i}") for i in range(2 * count + 1)]
    if shape == "backward":
        links = [(i, i - 1) for i in range(1, count)]
        initial = [{**original, "id": identities[0]}]
    elif shape == "forward":
        links = [(i, i + 1) for i in range(count)]
        initial = []
    else:
        links, width = [], 1
        while width < count:
            links.extend((i + width - 1, i + 2 * width - 1) for i in range(0, count, 2 * width))
            width *= 2
        links.extend((i, 0) for i in range(count, 2 * count))
        initial = []
    values = initial + [
        {
            **original,
            "id": identities[source],
            "kind": "correction",
            "supersedes": identities[target],
        }
        for source, target in links
    ]
    return values


@pytest.mark.parametrize("shape", ["backward", "forward", "balanced"])
def test_correction_sequences_obey_approved_growth(tmp_path, shape):
    samples = []
    for count in SCALES:
        original = event()
        path = tmp_path / f"corrections-{count}.sqlite"
        first = EventStore(path, original["domain_id"], SERVICE, initialize=True)
        second = EventStore(path, original["domain_id"], SERVICE)
        values = correction_inputs(count, shape)

        def complete(first=first, second=second, values=values):
            for index, value in enumerate(values):
                store = first if index % 2 else second
                assert store.put(value, **APPEND)[0] == 201
                assert store.put(value, **APPEND)[0] == 200

        try:
            _, work = measured(complete, first, second)
            assert first.db.execute("SELECT count(*) FROM events").fetchone() == (len(values),)
            first.close()
            first = EventStore(path, original["domain_id"], SERVICE)
            probe = {
                **original,
                "id": uid("cold-probe"),
                "kind": "correction",
                "supersedes": values[0]["id"],
            }
            _, cold = measured(lambda first=first, probe=probe: first.put(probe, **APPEND), first)
            work.update(cold)
            samples.append((count, work))
        finally:
            second.close()
            first.close()
    # This finite-size envelope rejects repeated graph scans. The approved
    # mathematical bound remains O(N alpha(N)), justified by union by rank and
    # path compression; passing these samples does not establish strict linearity.
    assert_linear(samples)


@pytest.mark.parametrize("committed", [False, True], ids=["before-commit", "after-commit"])
def test_correction_cache_preserves_failed_or_uncertain_commit(tmp_path, committed):
    original = event()
    path = tmp_path / "commit.sqlite"
    store = EventStore(path, original["domain_id"], SERVICE, initialize=True)
    a, b, c = (uid(name) for name in ("a", "b", "c"))
    first = {**original, "id": a, "kind": "correction", "supersedes": b}
    attempted = {**original, "id": b, "kind": "correction", "supersedes": c}

    class FailedCommit:
        def __getattr__(self, name):
            return getattr(database, name)

        def commit(self):
            if committed:
                database.commit()
            raise sqlite3.OperationalError("injected commit failure")

    try:
        store.put(first, **APPEND)
        database = store.db
        store.db = FailedCommit()
        with pytest.raises(sqlite3.OperationalError, match="injected"):
            store.put(attempted, **APPEND)
        store.db = database
        assert (store.get(original["workflow_id"], b, **AUTH) is not None) == committed
        closing = {**original, "id": c, "kind": "correction", "supersedes": a}
        if committed:
            with pytest.raises(ContractError, match="cycle"):
                store.put(closing, **APPEND)
            assert store.put(attempted, **APPEND)[0] == 200
        else:
            assert store.put(closing, **APPEND)[0] == 201
            with pytest.raises(ContractError, match="cycle"):
                store.put(attempted, **APPEND)
    finally:
        store.db = database
        store.close()


@pytest.mark.parametrize("committed", [False, True], ids=["uncommitted", "committed"])
def test_correction_crash_reconstruction_preserves_forward_references(tmp_path, committed):
    original = event()
    path = tmp_path / "crash.sqlite"
    a, b, c = (uid(name) for name in ("a", "b", "c"))
    store = EventStore(path, original["domain_id"], SERVICE, initialize=True)
    store.put({**original, "id": a, "kind": "correction", "supersedes": b}, **APPEND)
    store.close()
    script = """import os, sys
from pathlib import Path
from fishhat_reporting.store import EventStore
from tests.test_aggregate_growth import APPEND
from tests.test_contracts import uid
from tests.test_engineering import event, SERVICE
value = event()
store = EventStore(Path(sys.argv[1]), value['domain_id'], SERVICE)
database = store.db
class CrashCommit:
    def __getattr__(self, name): return getattr(database, name)
    def commit(self):
        if sys.argv[2] == 'True': database.commit()
        os._exit(31)
store.db = CrashCommit()
store.put({**value, 'id': uid('b'), 'kind': 'correction', 'supersedes': uid('c')}, **APPEND)
"""
    child = subprocess.run(
        [sys.executable, "-c", script, str(path), str(committed)],
        capture_output=True,
        timeout=watchdog(15),
        check=False,
    )
    assert child.returncode == 31, child.stderr.decode()
    store = EventStore(path, original["domain_id"], SERVICE)
    try:
        assert store.get(original["workflow_id"], a, **AUTH)["event"]["supersedes"] == b
        closing = {**original, "id": c, "kind": "correction", "supersedes": a}
        if committed:
            with pytest.raises(ContractError, match="cycle"):
                store.put(closing, **APPEND)
        else:
            assert store.put(closing, **APPEND)[0] == 201
    finally:
        store.close()


def test_correction_forest_scopes_branches_and_missing_originals(tmp_path):
    original = event()
    path = tmp_path / "forest.sqlite"
    first = EventStore(path, original["domain_id"], SERVICE, initialize=True)
    second = EventStore(path, original["domain_id"], SERVICE)
    a, b, c, d = (uid(name) for name in ("a", "b", "c", "d"))
    try:
        for source, target in ((a, b), (c, b), (b, d)):
            assert (
                second.put(
                    {**original, "id": source, "kind": "correction", "supersedes": target}, **APPEND
                )[0]
                == 201
            )
        # Same identity strings in a different workflow are independent vertices.
        other = {
            **original,
            "workflow_id": uid("other-workflow"),
            "id": b,
            "kind": "correction",
            "supersedes": a,
        }
        assert first.put(other, **APPEND)[0] == 201
        closing = {**original, "id": d, "kind": "correction", "supersedes": c}
        with pytest.raises(ContractError, match="permission"):
            first.put(closing, principal="reader", scopes={"read"})
        with pytest.raises(ContractError, match="cycle"):
            first.put(closing, **APPEND)
        assert first.put({**original, "id": d}, **APPEND)[0] == 201
        assert first.get(original["workflow_id"], a, **AUTH)["event"]["supersedes"] == b
        assert first.db.execute("SELECT count(*) FROM events").fetchone() == (5,)
    finally:
        second.close()
        first.close()


def interrupt_reads(database, call):
    steps = 0

    def interrupt():
        nonlocal steps
        steps += 1
        return steps == 40

    database.set_progress_handler(interrupt, 1)
    try:
        with pytest.raises(sqlite3.OperationalError, match="interrupted"):
            call()
    finally:
        database.set_progress_handler(None, 0)


def test_interrupted_correction_reconstruction_retries_from_committed_rows(tmp_path):
    original = event()
    path = tmp_path / "interrupted-corrections.sqlite"
    store = EventStore(path, original["domain_id"], SERVICE, initialize=True)
    for value in correction_inputs(16, "forward"):
        store.put(value, **APPEND)
    store.close()
    store = EventStore(path, original["domain_id"], SERVICE)
    closing = {
        **original,
        "id": uid("correction-16"),
        "kind": "correction",
        "supersedes": uid("correction-0"),
    }
    try:
        interrupt_reads(store.db, lambda: store.put(closing, **APPEND))
        with pytest.raises(ContractError, match="cycle"):
            store.put(closing, **APPEND)
        assert store.db.execute("SELECT count(*) FROM events").fetchone() == (16,)
    finally:
        store.close()


def test_interrupted_workflow_reconstruction_preserves_complete_extent(tmp_path):
    original = event()
    store = EventStore(
        tmp_path / "interrupted-pages.sqlite", original["domain_id"], SERVICE, initialize=True
    )
    try:
        seed(store, 16, workflows=True)
        expected = [
            row[0] for row in store.db.execute("SELECT workflow_id FROM events ORDER BY sequence")
        ]
        interrupt_reads(store.db, lambda: store.workflows(limit=4, **AUTH))
        assert all_workflows(store) == expected
    finally:
        store.close()


CHECK_OVERRIDES = {
    name: {
        **CHECK_PURPOSE,
        "relationship": "scoped-witness",
        "authority": [
            *CHECK_PURPOSE["authority"],
            "fishhat/owner-support/src/fishhat_owner/journal.py#Journal.submit"
            if identity == "journal.submit"
            else "some-implementations/fishhat/applications/receipts/src/fishhat_reporting/store.py#EventStore."
            + ("workflows" if identity == "reporting.workflows" else "put"),
        ],
        "claims": ["engineering:" + identity],
    }
    for name, identity in {
        "test_complete_admission_sequences_are_linear": "journal.submit",
        "test_workflow_traversals_with_interleaved_appends_are_linear": "reporting.workflows",
        "test_correction_sequences_obey_approved_growth": "reporting.put",
        "test_correction_cache_preserves_failed_or_uncertain_commit": "reporting.put",
        "test_correction_crash_reconstruction_preserves_forward_references": "reporting.put",
        "test_correction_forest_scopes_branches_and_missing_originals": "reporting.put",
        "test_interrupted_correction_reconstruction_retries_from_committed_rows": "reporting.put",
        "test_interrupted_workflow_reconstruction_preserves_complete_extent": "reporting.workflows",
    }.items()
}
