"""Optional SQLite metadata-index model; NOT an HTTP/auth server or dispatcher.

Uses real SQLite on private temporary local stores in tests. No SSH, Forgejo,
subprocess, socket, URL dereferencing or owner-library imports. Production must
qualify path custody, tokens, disk quotas, actual deadlines and shutdown.
"""

from __future__ import annotations

import bisect
import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fishhat_contracts.bounds import Bounds, bounds
from fishhat_contracts.validation import ContractError, canonical, digest

from fishhat_reporting.migrations import check_revision
from fishhat_reporting.reports import validate_event


class _Corrections:
    """Workflow-scoped forest connectivity, union by rank with path compression.

    An event has at most one immutable outgoing correction edge. A fresh source
    has no outgoing edge, so joining vertices already in one component creates
    exactly a directed cycle. Missing originals are ordinary placeholder vertices.
    Aggregate forest work is O(N alpha(N)), not a strict linear-growth claim.
    """

    def __init__(self) -> None:
        self.parents: dict[tuple[str, str], tuple[str, str]] = {}
        self.ranks: dict[tuple[str, str], int] = {}

    def _root(self, node: tuple[str, str]) -> tuple[str, str]:
        root = node
        while self.parents.get(root, root) != root:
            root = self.parents[root]
        while self.parents.get(node, node) != root:
            parent = self.parents[node]
            self.parents[node] = root
            node = parent
        return root

    def connected(self, source: tuple[str, str], target: tuple[str, str]) -> bool:
        # A refused or failed candidate must not retain new placeholder vertices.
        return self._root(source) == self._root(target)

    def retain(self, source: tuple[str, str], target: tuple[str, str]) -> None:
        left, right = self._root(source), self._root(target)
        if left == right:
            raise ContractError("correction cycle")
        for node in (left, right):
            self.parents.setdefault(node, node)
            self.ranks.setdefault(node, 0)
        if self.ranks[left] < self.ranks[right]:
            left, right = right, left
        self.parents[right] = left
        if self.ranks[left] == self.ranks[right]:
            self.ranks[left] += 1


class EventStore:
    def __init__(
        self,
        path: Path,
        domain_id: str,
        service_id: str,
        *,
        initialize: bool = False,
    ) -> None:
        new = not path.exists()
        if new and not initialize:
            raise ContractError("missing index; explicit initialization required")
        self.db = sqlite3.connect(path, timeout=0.25)
        try:
            check_revision(self.db)
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA foreign_keys=ON")
            if new:
                self.db.executescript(
                    (Path(__file__).resolve().parent / "schema/receipts-v1.sql").read_text()
                )
                with self.db:
                    self.db.executemany(
                        "INSERT INTO meta VALUES (?,?)",
                        [
                            ("domain", domain_id),
                            ("service", service_id),
                            ("schema", "1"),
                            ("epoch", str(uuid.uuid4())),
                        ],
                    )
            meta = dict(self.db.execute("SELECT key,value FROM meta"))
            if (
                meta.get("domain") != domain_id
                or meta.get("service") != service_id
                or meta.get("schema") != "1"
            ):
                raise ContractError("index identity/schema mismatch")
            self.epoch = meta["epoch"]
        except Exception:
            self.db.close()
            raise
        self.domain, self.service = domain_id, service_id
        self._correction_sequence = 0
        self._corrections = _Corrections()
        self._workflow_sequence = 0
        self._workflow_ids: set[str] = set()
        self._workflow_rows: list[tuple[str, int, str]] = []
        self._workflow_sequences: list[int] = []
        self._workflow_positions: dict[int, int] = {}

    def _auth(self, principal: str, scopes: set[str], action: str, domain: str | None) -> None:
        # Trusted server auth output in tests, never read from event payload.
        if not principal or action not in scopes or domain != self.domain:
            raise ContractError("report permission denied")

    def _envelope(self, row: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "format": "deployment-ops/index-record/v1",
            "service_id": self.service,
            "store_epoch": self.epoch,
            "sequence": row[0],
            "received_at": row[7],
            "reporter": row[6],
            "content_digest": row[4],
            "authority": "reported",
            "event": json.loads(row[5]),
        }

    def _append_response(self, row: tuple[Any, ...], scopes: set[str]) -> dict[str, Any]:
        if "read" in scopes:
            return self._envelope(row)
        return {
            "format": "deployment-ops/index-append-ack/v1",
            "workflow_id": row[2],
            "event_id": row[3],
            "content_digest": row[4],
        }

    @bounds(
        Bounds(
            id="reporting.put",
            growth="inverse-ackermann",
            growth_proofs=(
                "tests/test_linear_growth.py::test_event_put_linear_work",
                "tests/test_aggregate_growth.py::test_correction_sequences_obey_approved_growth",
            ),
            work="O(total_event_bytes + correction_edges * alpha(correction_vertices)) across append and bounded retry sequences, including one cold reconstruction per connection; only correction forest connectivity has the approved near-linear allowance; ordinary appends use indexed identity lookup",
            extent="one-immutable-event",
            limits=(),
            capacity=(),
            proofs=(
                "tests/test_engineering.py::test_reporting_accepts_complete_extent_and_preserves_replay",
                "tests/test_engineering.py::test_reporting_crash_replay_preserves_committed_event",
                "tests/test_aggregate_growth.py::test_correction_cache_preserves_failed_or_uncertain_commit",
                "tests/test_aggregate_growth.py::test_correction_crash_reconstruction_preserves_forward_references",
                "tests/test_aggregate_growth.py::test_correction_forest_scopes_branches_and_missing_originals",
                "tests/test_aggregate_growth.py::test_interrupted_correction_reconstruction_retries_from_committed_rows",
            ),
        )
    )
    def put(
        self,
        event: dict[str, Any],
        *,
        principal: str,
        scopes: set[str],
        workflow_id: str | None = None,
        event_id: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        self._auth(principal, scopes, "append", event.get("domain_id"))
        validate_event(event)
        if workflow_id is not None and workflow_id != event["workflow_id"]:
            raise ContractError("path/workflow mismatch")
        if event_id is not None and event_id != event["id"]:
            raise ContractError("path/event mismatch")
        key = (self.domain, event["workflow_id"], event["id"])
        data = canonical(event)
        hash_ = digest(event)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute(
                "SELECT * FROM events WHERE domain_id=? AND workflow_id=? AND event_id=?", key
            ).fetchone()
            if row:
                if row[5] != data:
                    raise ContractError("immutable event conflict")
                self.db.commit()
                return 200, self._append_response(row, scopes)
            successor = event["supersedes"]
            if successor:
                self._catch_up_corrections()
                if self._corrections.connected(
                    (event["workflow_id"], event["id"]), (event["workflow_id"], successor)
                ):
                    raise ContractError("correction cycle")
            # Do not cache this candidate before commit. The next catch-up reads
            # it from SQLite, so failed/uncertain commits cannot invent an edge.
            now = datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
            self.db.execute(
                "INSERT INTO events(domain_id,workflow_id,event_id,content_digest,canonical_event,reporter,received_at) VALUES(?,?,?,?,?,?,?)",
                (*key, hash_, data, principal, now),
            )
            row = self.db.execute(
                "SELECT * FROM events WHERE domain_id=? AND workflow_id=? AND event_id=?", key
            ).fetchone()
            self.db.commit()
            return 201, self._append_response(row, scopes)
        except Exception:
            self.db.rollback()
            raise

    def _catch_up_corrections(self) -> None:
        try:
            for sequence, workflow, identity, encoded in self.db.execute(
                "SELECT sequence,workflow_id,event_id,canonical_event FROM events NOT INDEXED "
                "WHERE sequence>? AND domain_id=? ORDER BY sequence",
                (self._correction_sequence, self.domain),
            ):
                successor = json.loads(encoded)["supersedes"]
                if successor is not None:
                    self._corrections.retain((workflow, identity), (workflow, successor))
                self._correction_sequence = sequence
        except BaseException:
            # An interrupted reconstruction is discarded; a retry is an explicit
            # cold rebuild. Previously committed records remain the authority.
            self._corrections = _Corrections()
            self._correction_sequence = 0
            raise

    def get(
        self, workflow_id: str, event_id: str, *, principal: str, scopes: set[str]
    ) -> dict[str, Any] | None:
        self._auth(principal, scopes, "read", self.domain)
        row = self.db.execute(
            "SELECT * FROM events WHERE domain_id=? AND workflow_id=? AND event_id=?",
            (self.domain, workflow_id, event_id),
        ).fetchone()
        return self._envelope(row) if row else None

    @bounds(
        Bounds(
            id="reporting.events",
            linear_proofs=("tests/test_linear_growth.py::test_event_page_linear_work",),
            work="O(log(retained_events) + page_bytes) indexed seek and linear page construction with one serialization per returned event",
            extent="complete-page-with-resume-cursor",
            limits=(("page_items", 100), ("page_items_bytes", 1000000)),
            capacity=(),
            proofs=(
                "tests/test_engineering.py::test_event_pages_use_bounded_indexed_work_and_preserve_full_extent",
                "tests/test_engineering.py::test_event_byte_capacity_continues_or_rejects_explicitly",
            ),
        )
    )
    def events(
        self,
        workflow_id: str,
        *,
        principal: str,
        scopes: set[str],
        after: int = 0,
        limit: int = 100,
        expected_store_epoch: str | None = None,
    ) -> dict[str, Any]:
        self._auth(principal, scopes, "read", self.domain)
        self._page_args(after, limit, expected_store_epoch)
        rows = self.db.execute(
            "SELECT * FROM events WHERE domain_id=? AND workflow_id=? AND sequence>? ORDER BY sequence LIMIT ?",
            (self.domain, workflow_id, after, limit + 1),
        ).fetchall()
        items: list[dict[str, Any]] = []
        size = 2  # JSON array brackets; each additional item contributes one comma.
        for row in rows[:limit]:
            item = self._envelope(row)
            added = len(canonical(item)) + bool(items)
            if size + added > 1000000:
                if not items:
                    raise ContractError("record exceeds response capacity")
                break
            items.append(item)
            size += added
        more = len(rows) > len(items)
        return {
            "format": "deployment-ops/index-page/v1",
            "service_id": self.service,
            "store_epoch": self.epoch,
            "authority": "reported",
            "items": items,
            "next_after": items[-1]["sequence"] if more and items else None,
        }

    @bounds(
        Bounds(
            id="reporting.workflows",
            linear_proofs=(
                "tests/test_linear_growth.py::test_workflow_pages_linear_work",
                "tests/test_aggregate_growth.py::test_workflow_traversals_with_interleaved_appends_are_linear",
            ),
            work="O(retained_events + appended_events + returned_items) across complete traversals and interleaved appends; one cold scan per connection, incremental rowid catch-up, constant-work issued cursors and one seek for arbitrary positions",
            extent="complete-page-with-resume-cursor",
            limits=(("page_items", 100),),
            capacity=(),
            proofs=(
                "tests/test_engineering.py::test_workflow_pagination_preserves_logical_extent",
                "tests/test_aggregate_growth.py::test_interrupted_workflow_reconstruction_preserves_complete_extent",
            ),
        )
    )
    def workflows(
        self,
        *,
        principal: str,
        scopes: set[str],
        after: int = 0,
        limit: int = 100,
        expected_store_epoch: str | None = None,
    ) -> dict[str, Any]:
        self._auth(principal, scopes, "read", self.domain)
        self._page_args(after, limit, expected_store_epoch)
        # Events are immutable and append-only. Catch up only rows committed after
        # this connection's previous observation, including other connections' writes.
        # A fixed rowid range preserves linear traversal even when every page is
        # separated by a new append to an existing workflow.
        try:
            for workflow, sequence, received in self.db.execute(
                "SELECT workflow_id,sequence,received_at FROM events NOT INDEXED "
                "WHERE sequence>? AND domain_id=? ORDER BY sequence",
                (self._workflow_sequence, self.domain),
            ):
                if workflow not in self._workflow_ids:
                    self._workflow_ids.add(workflow)
                    self._workflow_rows.append((workflow, sequence, received))
                    self._workflow_sequences.append(sequence)
                    self._workflow_positions[sequence] = len(self._workflow_rows)
                self._workflow_sequence = sequence
        except BaseException:
            self._workflow_sequence = 0
            self._workflow_ids.clear()
            self._workflow_rows.clear()
            self._workflow_sequences.clear()
            self._workflow_positions.clear()
            raise
        # Issued continuations resume in constant work; arbitrary positions use
        # one indexed seek. Cold open visits retained rows once per connection.
        start = self._workflow_positions.get(after)
        if start is None:
            start = bisect.bisect_right(self._workflow_sequences, after)
        selected = self._workflow_rows[start : start + limit + 1]
        items = [
            {"workflow_id": r[0], "first_sequence": r[1], "first_received_at": r[2]}
            for r in selected[:limit]
        ]
        return {
            "format": "deployment-ops/workflow-index-page/v1",
            "service_id": self.service,
            "store_epoch": self.epoch,
            "authority": "reported",
            "items": items,
            "next_after": items[-1]["first_sequence"] if len(selected) > limit else None,
        }

    def _page_args(self, after: int, limit: int, epoch: str | None) -> None:
        if (
            type(after) is not int
            or type(limit) is not int
            or not 0 <= after <= 9007199254740991
            or not 1 <= limit <= 100
        ):
            raise ContractError("INVALID_INPUT")
        if after and epoch is None:
            raise ContractError("INVALID_INPUT")
        if epoch is not None and epoch != self.epoch:
            raise ContractError("EPOCH_CHANGED")

    def restore_epoch(self) -> None:
        """Explicit offline recovery mechanic only; never run as an API endpoint."""
        self.epoch = str(uuid.uuid4())
        with self.db:
            self.db.execute("UPDATE meta SET value=? WHERE key='epoch'", (self.epoch,))

    def close(self) -> None:
        self.db.close()
