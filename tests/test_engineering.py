from __future__ import annotations

import io
import json
import struct
import subprocess
import sys
import uuid

import pytest
from fishhat_client.wire import frame, read_frame
from fishhat_contracts import ContractError
from fishhat_contracts.validation import MAX_BYTES, canonical
from fishhat_directory.projection import load_directory, prepare_projection
from fishhat_owner.journal import Journal
from fishhat_reporting.store import EventStore

from scripts.engineering import declarations
from tests.support import FIXTURES
from tests.test_component_policy import restore_fixture

CHECK_PURPOSE = {
    "purpose": "implementation",
    "authority": ["release.toml"],
    "scope": "reference-model engineering checks",
    "relationship": "candidate",
    "reason": "Fixed fixture identities/counts, bounded I/O, SQLite VM work and crash subprocesses establish only the recorded local model behavior.",
    "claims": [],
}


OWNER = "00000000-0000-4000-8000-000000000001"
EPOCH = "00000000-0000-4000-8000-000000000002"
REQUEST = "00000000-0000-4000-8000-000000000003"
SERVICE = "00000000-0000-4000-8000-000000000004"
AUTH = {"principal": "test-reader", "scopes": {"read"}}


def event():
    return json.loads((FIXTURES / "tracking/event.json").read_text())


def subject():
    return json.loads((FIXTURES / "plan-input.json").read_text())["subject"]


def replay(journal):
    return journal.submit(
        REQUEST,
        subject(),
        principal="replacement-reader",
        authorized=True,
        expected_epoch=EPOCH,
        expected_generation=0,
        expires=200,
        now=1000,
    )


def test_frame_work_tracks_current_frame_not_stream_extent():
    class Counting(io.BytesIO):
        def __init__(self, data):
            super().__init__(data)
            self.read_bytes = 0
            self.limits = []

        def read(self, size=-1):
            assert size >= 0
            self.limits.append(size)
            result = super().read(min(size, 7))
            self.read_bytes += len(result)
            return result

    for size in (16, 1024, 8192):
        message = {"payload": "x" * size}
        encoded = frame(message)
        stream = Counting(encoded + frame({"next": True}) * 100)
        assert read_frame(stream) == message
        assert stream.read_bytes == len(encoded)
        assert max(stream.limits) <= len(encoded)
        assert read_frame(stream) == {"next": True}
    oversized = Counting(struct.pack(">I", MAX_BYTES + 1) + b"ignored")
    with pytest.raises(ContractError, match="frame size"):
        read_frame(oversized)
    assert oversized.read_bytes == 4
    with pytest.raises(ContractError, match="truncated"):
        read_frame(io.BytesIO(frame({"x": 1})[:-1]))


def test_directory_capacity_is_rejection_not_silent_truncation():
    text = (FIXTURES / "directory/directory.yaml").read_text()
    data = load_directory(text)
    assert prepare_projection(data)["catalogue"]["owner_endpoints"] == data["owner_endpoints"]
    with pytest.raises(ContractError, match="input limit"):
        load_directory(" " * 65537)
    with pytest.raises(ContractError, match="nesting limit"):
        load_directory("[" * 17 + "]" * 17)
    with pytest.raises(ContractError, match="bounded projection"):
        prepare_projection(data, limit=1)


def test_journal_reference_scan_and_replay_identity(tmp_path):
    path = restore_fixture(tmp_path, "owner")
    journal = Journal(path, OWNER, EPOCH)
    try:
        first = replay(journal)
        assert first["principal"] == "fixture-maintainer"
        statements = []
        journal.db.set_trace_callback(statements.append)
        assert replay(journal) == first
        assert not any(s.startswith("INSERT") for s in statements)
        assert journal.db.execute("SELECT count(*) FROM requests").fetchone() == (1,)
        journal.transition(REQUEST, "running", "unknown")
        with pytest.raises(ContractError, match="held/busy"):
            journal.submit(
                str(uuid.uuid4()),
                subject(),
                principal="reader",
                authorized=True,
                expected_epoch=EPOCH,
                expected_generation=0,
                expires=2000,
                now=1000,
            )
    finally:
        journal.close()


@pytest.mark.parametrize("committed", [False, True], ids=["uncommitted", "committed"])
def test_owner_crash_replay_preserves_state(tmp_path, committed):
    path = restore_fixture(tmp_path, "owner")
    script = """import os, sys
from pathlib import Path
from fishhat_owner.journal import Journal
j = Journal(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
class CrashCommit:
    def __init__(self, db): self.db = db
    def __getattr__(self, name): return getattr(self.db, name)
    def __enter__(self): return self
    def __exit__(self, *exc):
        if sys.argv[4] == "True": self.db.__exit__(*exc)
        os._exit(29)
j.db = CrashCommit(j.db)
j.transition(sys.argv[5], "running", "unknown")
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(path), OWNER, EPOCH, str(committed), REQUEST],
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 29, result.stderr.decode()
    journal = Journal(path, OWNER, EPOCH)
    try:
        receipt = replay(journal)
        assert (receipt["state"], receipt["effect"]) == (
            ("running", "unknown") if committed else ("accepted", "none")
        )
        assert receipt["principal"] == "fixture-maintainer"
        assert journal.generation == 0
        assert journal.db.execute("SELECT count(*) FROM requests").fetchone() == (1,)
        assert journal.db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        journal.close()


@pytest.mark.parametrize("committed", [False, True], ids=["uncommitted", "committed"])
def test_reporting_crash_replay_preserves_committed_event(tmp_path, committed):
    path = restore_fixture(tmp_path, "reporting")
    expected = event()
    pending = {**expected, "id": str(uuid.uuid4())}
    script = """import json, os, sys
from pathlib import Path
from fishhat_reporting.store import EventStore
sample = json.loads(sys.argv[3])
store = EventStore(Path(sys.argv[1]), sample["domain_id"], sys.argv[4])
class CrashCommit:
    def __init__(self, db): self.db = db
    def __getattr__(self, name): return getattr(self.db, name)
    def commit(self):
        if sys.argv[2] == "True": self.db.commit()
        os._exit(29)
store.db = CrashCommit(store.db)
store.put(sample, principal="child-reporter", scopes={"append"})
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(path), str(committed), json.dumps(pending), SERVICE],
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 29, result.stderr.decode()
    store = EventStore(path, expected["domain_id"], SERVICE)
    try:
        status, receipt = store.put(expected, principal="replacement", scopes={"append"})
        assert status == 200 and receipt["event"] == expected
        assert receipt["reporter"] == "fixture-reporter"
        assert store.epoch == "00000000-0000-4000-8000-000000000005"
        assert store.db.execute("SELECT count(*) FROM events").fetchone() == (
            (2,) if committed else (1,)
        )
        status, replayed = store.put(pending, principal="replacement", scopes={"append"})
        assert status == (200 if committed else 201)
        assert replayed["reporter"] == ("child-reporter" if committed else "replacement")
        assert store.db.execute("SELECT count(*) FROM events").fetchone() == (2,)
        assert store.db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        store.close()


def test_reporting_capacity_rejects_new_identity_but_allows_replay(tmp_path):
    original = event()
    store = EventStore(
        restore_fixture(tmp_path, "reporting"),
        original["domain_id"],
        SERVICE,
        max_events=1,
        max_workflows=1,
    )
    try:
        assert store.put(original, principal="reader", scopes={"append"})[0] == 200
        changed = {**original, "id": str(uuid.uuid4())}
        with pytest.raises(ContractError, match="quota"):
            store.put(changed, principal="reader", scopes={"append"})
        assert store.db.execute("SELECT count(*) FROM events").fetchone() == (1,)
        assert store.events(original["workflow_id"], **AUTH)["items"][0]["event"] == original
    finally:
        store.close()


def seed(store, count, workflows=False):
    original = event()
    with store.db:
        for _ in range(count):
            sample = {**original, "id": str(uuid.uuid4())}
            if workflows:
                sample["workflow_id"] = str(uuid.uuid4())
            store.db.execute(
                "INSERT INTO events(domain_id,workflow_id,event_id,content_digest,canonical_event,reporter,received_at) VALUES(?,?,?,?,?,?,?)",
                (
                    sample["domain_id"],
                    sample["workflow_id"],
                    sample["id"],
                    "synthetic-digest",
                    json.dumps(sample).encode(),
                    "synthetic",
                    "2026-01-01T00:00:00Z",
                ),
            )


def test_event_pages_use_bounded_indexed_work_and_preserve_full_extent(tmp_path):
    original = event()
    store = EventStore(tmp_path / "events.sqlite", original["domain_id"], SERVICE, initialize=True)
    try:
        counts = []
        for count in (32, 512):
            seed(store, count)
            instructions = [0]

            def progress(instructions=instructions):
                instructions[0] += 1
                return 0

            store.db.set_progress_handler(progress, 1)
            page = store.events(original["workflow_id"], limit=7, **AUTH)
            store.db.set_progress_handler(None, 0)
            counts.append(instructions[0])
            assert len(page["items"]) == 7
            assert page["next_after"] == page["items"][-1]["sequence"]
        # VM instructions measure actual SQLite work, independently of wall/CPU/RSS.
        assert max(counts) <= min(counts) + 20
        plan = store.db.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM events WHERE domain_id=? AND workflow_id=? AND sequence>? ORDER BY sequence LIMIT ?",
            (store.domain, original["workflow_id"], 0, 8),
        ).fetchall()
        assert any("SEARCH" in row[3] and "events_by_workflow" in row[3] for row in plan)
        sequences, after = [], 0
        while True:
            page = store.events(
                original["workflow_id"],
                limit=31,
                after=after,
                expected_store_epoch=store.epoch,
                **AUTH,
            )
            sequences.extend(item["sequence"] for item in page["items"])
            if page["next_after"] is None:
                break
            assert page["next_after"] > after
            after = page["next_after"]
        assert len(sequences) == 544 and len(set(sequences)) == 544
        assert sequences == sorted(sequences)
    finally:
        store.close()


def test_workflow_pagination_preserves_logical_extent(tmp_path):
    store = EventStore(
        tmp_path / "workflows.sqlite", event()["domain_id"], SERVICE, initialize=True
    )
    try:
        seed(store, 23, workflows=True)
        identifiers, after = [], 0
        while True:
            page = store.workflows(limit=4, after=after, expected_store_epoch=store.epoch, **AUTH)
            identifiers.extend(item["workflow_id"] for item in page["items"])
            if page["next_after"] is None:
                break
            assert page["next_after"] > after
            after = page["next_after"]
        assert len(identifiers) == len(set(identifiers)) == 23
    finally:
        store.close()


def test_operation_owned_bounds_are_discovered_and_never_claim_native_qualification():
    found = declarations()
    assert set(found) == {
        "bootstrap.catalogue",
        "wire.read-frame",
        "directory.load",
        "journal.submit",
        "record-delivery.chunk",
        "reporting.put",
        "reporting.events",
        "reporting.workflows",
        "workflow.phase-evidence",
    }
    assert all(item["qualification"] == "reference-model" for item in found.values())
    assert "reference-scan" in found["reporting.put"]["work"]
    assert all(item["proofs"] and item["sources"] for item in found.values())
    phase_evidence = found["workflow.phase-evidence"]
    assert phase_evidence["symbol"] == "fishhat_contracts.workflow_evidence:validate_phase_evidence"
    assert phase_evidence["limits"] == ()
    assert phase_evidence["proofs"] == (
        "tests/test_workflow_evidence.py::test_phase_evidence_checks_complete_child_extent",
    )
    assert set(phase_evidence["sources"]) == {
        "packages/fishhat-contracts/src/fishhat_contracts/workflow_evidence.py",
        "tests/test_workflow_evidence.py",
    }


def test_event_byte_capacity_continues_or_rejects_explicitly(tmp_path):
    store = EventStore(tmp_path / "bytes.sqlite", event()["domain_id"], SERVICE, initialize=True)
    try:
        seed(store, 80)
        with store.db:
            store.db.execute("UPDATE events SET reporter=?", ("x" * 20000,))
        total, after = 0, 0
        while True:
            page = store.events(
                event()["workflow_id"], after=after, expected_store_epoch=store.epoch, **AUTH
            )
            assert len(canonical(page["items"])) <= 1000000
            assert page["items"]
            total += len(page["items"])
            if page["next_after"] is None:
                break
            assert page["next_after"] > after
            after = page["next_after"]
        assert total == 80
        with store.db:
            store.db.execute("UPDATE events SET reporter=?", ("x" * 1000000,))
        with pytest.raises(ContractError, match="response capacity"):
            store.events(event()["workflow_id"], **AUTH)
        assert store.db.execute("SELECT count(*) FROM events").fetchone() == (80,)
    finally:
        store.close()


CHECK_OVERRIDES = {
    "test_frame_work_tracks_current_frame_not_stream_extent": {
        "purpose": "implementation",
        "authority": ["packages/fishhat-client/src/fishhat_client/wire.py#read_frame"],
        "scope": "local reference model; no native deployment or recovery",
        "relationship": "scoped-witness",
        "reason": "Fixed fixture values, explicit rejection, counted work and complete pagination assertions independently challenge the operation-owned bounds.",
        "claims": ["engineering:wire.read-frame"],
    },
    "test_directory_capacity_is_rejection_not_silent_truncation": {
        "purpose": "implementation",
        "authority": [
            "some-implementations/fishhat/applications/directory/src/fishhat_directory/projection.py#load_directory"
        ],
        "scope": "local reference model; no native deployment or recovery",
        "relationship": "scoped-witness",
        "reason": "Fixed fixture values, explicit rejection, counted work and complete pagination assertions independently challenge the operation-owned bounds.",
        "claims": ["engineering:directory.load"],
    },
    "test_journal_reference_scan_and_replay_identity": {
        "purpose": "implementation",
        "authority": ["fishhat/owner-support/src/fishhat_owner/journal.py#Journal.submit"],
        "scope": "local reference model; no native deployment or recovery",
        "relationship": "scoped-witness",
        "reason": "Fixed fixture values, explicit rejection, counted work and complete pagination assertions independently challenge the operation-owned bounds.",
        "claims": ["engineering:journal.submit"],
    },
    "test_owner_crash_replay_preserves_state": {
        "purpose": "implementation",
        "authority": ["fishhat/owner-support/src/fishhat_owner/journal.py#Journal.submit"],
        "scope": "local reference model; no native deployment or recovery",
        "relationship": "scoped-witness",
        "reason": "Fixed fixture values, explicit rejection, counted work and complete pagination assertions independently challenge the operation-owned bounds.",
        "claims": ["engineering:journal.submit"],
    },
    "test_reporting_capacity_rejects_new_identity_but_allows_replay": {
        "purpose": "implementation",
        "authority": [
            "some-implementations/fishhat/applications/receipts/src/fishhat_reporting/store.py#EventStore.put"
        ],
        "scope": "local reference model; no native deployment or recovery",
        "relationship": "scoped-witness",
        "reason": "Fixed fixture values, explicit rejection, counted work and complete pagination assertions independently challenge the operation-owned bounds.",
        "claims": ["engineering:reporting.put"],
    },
    "test_reporting_crash_replay_preserves_committed_event": {
        "purpose": "implementation",
        "authority": [
            "some-implementations/fishhat/applications/receipts/src/fishhat_reporting/store.py#EventStore.put"
        ],
        "scope": "local reference model; no native deployment or recovery",
        "relationship": "scoped-witness",
        "reason": "Fixed fixture values, explicit rejection, counted work and complete pagination assertions independently challenge the operation-owned bounds.",
        "claims": ["engineering:reporting.put"],
    },
    "test_event_pages_use_bounded_indexed_work_and_preserve_full_extent": {
        "purpose": "implementation",
        "authority": [
            "some-implementations/fishhat/applications/receipts/src/fishhat_reporting/store.py#EventStore.events"
        ],
        "scope": "local reference model; no native deployment or recovery",
        "relationship": "scoped-witness",
        "reason": "Fixed fixture values, explicit rejection, counted work and complete pagination assertions independently challenge the operation-owned bounds.",
        "claims": ["engineering:reporting.events"],
    },
    "test_event_byte_capacity_continues_or_rejects_explicitly": {
        "purpose": "implementation",
        "authority": [
            "some-implementations/fishhat/applications/receipts/src/fishhat_reporting/store.py#EventStore.events"
        ],
        "scope": "local reference model; no native deployment or recovery",
        "relationship": "scoped-witness",
        "reason": "Fixed fixture values, explicit rejection, counted work and complete pagination assertions independently challenge the operation-owned bounds.",
        "claims": ["engineering:reporting.events"],
    },
    "test_workflow_pagination_preserves_logical_extent": {
        "purpose": "implementation",
        "authority": [
            "some-implementations/fishhat/applications/receipts/src/fishhat_reporting/store.py#EventStore.workflows"
        ],
        "scope": "local reference model; no native deployment or recovery",
        "relationship": "scoped-witness",
        "reason": "Fixed fixture values, explicit rejection, counted work and complete pagination assertions independently challenge the operation-owned bounds.",
        "claims": ["engineering:reporting.workflows"],
    },
}
