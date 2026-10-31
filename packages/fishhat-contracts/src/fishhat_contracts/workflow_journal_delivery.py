"""Staged journal commands and immutable record delivery, without native effects.

The receiver supplies protected staging and committed record bytes. This module
does not authenticate a principal, enroll a gate, persist an event, or authorize
native work. Complete bytes are admitted once; chunk reads use immutable indexes.
"""

from __future__ import annotations

import base64
import copy
import hashlib
from collections.abc import Callable
from typing import Any
from uuid import UUID, uuid4, uuid5

from .bounds import Bounds, bounds
from .handoffs import validate_staged_input, validate_staging
from .record_delivery import (
    CHUNK_BYTES,
    InstalledRecordSchema,
    RecordSnapshot,
    validate_content_chunk,
)
from .validation import ContractError, canonical, strict_json, validate


def _require(value: bool, message: str) -> None:
    if not value:
        raise ContractError(message)


def _bounds(name: str) -> Bounds:
    return Bounds(
        id="workflow.journal-delivery." + name,
        work="O(B) one complete new command/record; O(chunk bytes) per read; immutable references use indexed lookup",
        extent="Every complete selected command and record byte across all chunks and retries",
        limits=(),
        capacity=("Explicit receiving byte capacity may refuse new input without truncation",),
        proofs=(
            "tests/test_workflow_journal_surface.py::test_staged_command_and_record_delivery_bind_exact_owner_and_bytes",
        ),
        linear_proofs=(
            "tests/test_workflow_journal_surface.py::test_complete_journal_delivery_growth",
        ),
    )


@bounds(_bounds("decode"))
def decode_journal_command(
    reference: dict[str, Any],
    data: bytes,
    *,
    expected_owner: dict[str, Any],
    max_bytes: int | None = None,
) -> dict[str, Any]:
    """Decode complete staged canonical input; no frame-sized total-input cap."""
    validate("workflow-journal.schema.json", reference, "InputReference")
    handle = reference["input"]
    _require(reference["owner"] == handle["owner"] == expected_owner, "journal receiver changed")
    _require(
        len(data) == handle["size"]
        and "sha256:" + hashlib.sha256(data).hexdigest() == handle["digest"],
        "journal input bytes changed",
    )
    if max_bytes is not None:
        _require(type(max_bytes) is int and max_bytes >= 0, "invalid receiving capacity")
    command = strict_json(data, max_bytes=len(data) if max_bytes is None else max_bytes)
    validate("workflow-journal.schema.json", command, "Command")
    _require(canonical(command) == data, "journal command is not canonical JSON")
    _require(
        command["id"] == reference["command_id"]
        and command["workflow_id"] == reference["workflow_id"],
        "journal staged identity changed",
    )
    return dict(command)


@bounds(_bounds("custody"))
def validate_journal_input_custody(
    reference: dict[str, Any],
    command: dict[str, Any],
    staging: dict[str, Any],
    *,
    principal: str,
    now: str,
    retained_command: dict[str, Any] | None = None,
) -> None:
    """Join trusted staging after current read authorization and replay lookup.

    retained_command comes only from the receiving owner's protected exact-ID
    index. It is not a wire field. Replays do not renew any admission deadline.
    """
    validate("workflow-journal.schema.json", reference, "InputReference")
    validate("workflow-journal.schema.json", command, "Command")
    handle = reference["input"]
    encoded = canonical(command)
    _require(
        handle["owner"] == reference["owner"]
        and reference["command_id"] == command["id"]
        and reference["workflow_id"] == command["workflow_id"]
        and len(encoded) == handle["size"]
        and "sha256:" + hashlib.sha256(encoded).hexdigest() == handle["digest"],
        "journal custody input changed",
    )
    resource = {"kind": "workflow", "id": command["workflow_id"]}
    if retained_command is not None:
        _require(command == retained_command, "retained journal command changed")
        validate_staging(staging, expected_owner=reference["owner"], resource=resource)
        if staging["accepted_references"] > 0:
            _require(
                staging["state"] == "committed"
                and staging["handle"] == handle
                and staging["purpose"] == "workflow-input",
                "retained journal input lacks pinned custody",
            )
            return
    validate_staged_input(
        staging,
        handle,
        expected_owner=reference["owner"],
        principal=principal,
        resource=resource,
        purpose="workflow-input",
        now=now,
    )


class WorkflowRecordDelivery:
    """Index committed immutable journal outcomes for reference/chunk delivery.

    Register exactly once on durable append, or once while cold restore visits
    each retained event. The owning native journal remains the custody authority.
    Authorization is independent and current for every reference and chunk read.
    """

    def __init__(
        self,
        owner: dict[str, Any],
        *,
        authorize_read: Callable[[str, str], bool],
    ) -> None:
        self.owner = dict(owner)
        self._authorize = authorize_read
        self._schema = InstalledRecordSchema("WorkflowJournalRecord")
        self._records: dict[str, RecordSnapshot] = {}
        self._inputs: dict[str, tuple[dict[str, Any], bytes]] = {}
        self._workflows: dict[str, str] = {}
        self._by_workflow: dict[str, list[str]] = {}
        self._workflow_order: list[str] = []
        self._cursors: dict[str, tuple[str | None, int, int]] = {}
        self._cursor_namespace = uuid4()

    @bounds(_bounds("retain"))
    def retain(self, data: bytes, *, command_bytes: bytes) -> dict[str, Any]:
        """Index exact owner-committed canonical bytes; never accept wire custody."""
        record = strict_json(data, max_bytes=len(data))
        validate("workflow-journal.schema.json", record, "JournalRecord")
        _require(record["owner"] == self.owner, "journal record owner changed")
        _require(canonical(record) == data, "journal record bytes are not canonical")
        record_id = record["id"]
        command = strict_json(command_bytes, max_bytes=len(command_bytes))
        validate("workflow-journal.schema.json", command, "Command")
        command_digest = "sha256:" + hashlib.sha256(command_bytes).hexdigest()
        _require(
            canonical(command) == command_bytes
            and command["id"] == record_id
            and command["workflow_id"] == record["workflow_id"]
            and record["body"]["command_digest"] == command_digest,
            "journal accepted input bytes changed",
        )
        existing = self._records.get(record_id)
        identity = "sha256:" + hashlib.sha256(data).hexdigest()
        if existing is not None:
            _require(existing.reference["digest"] == identity, "journal record ID conflict")
            return existing.reference
        snapshot_id = str(uuid5(UUID(record_id), identity))
        snapshot = RecordSnapshot(record, snapshot_id, installed_schema=self._schema)
        self._records[record_id] = snapshot
        workflow_id = record["workflow_id"]
        self._inputs[record_id] = (
            {
                "owner": dict(self.owner),
                "id": str(uuid5(UUID(record_id), "accepted-input:" + command_digest)),
                "purpose": "workflow-input",
                "binding": {
                    "kind": "workflow-journal",
                    "workflow_id": workflow_id,
                    "command_id": record_id,
                },
                "digest": command_digest,
                "size": len(command_bytes),
            },
            command_bytes,
        )
        self._workflows[record_id] = workflow_id
        if workflow_id not in self._by_workflow:
            self._by_workflow[workflow_id] = []
            self._workflow_order.append(workflow_id)
        self._by_workflow[workflow_id].append(record_id)
        return snapshot.reference

    @bounds(_bounds("get"))
    def get(self, lookup: dict[str, Any], *, principal: str) -> dict[str, Any]:
        validate("workflow-journal.schema.json", lookup, "Lookup")
        _require(lookup["owner"] == self.owner, "journal lookup owner changed")
        _require(self._authorize(principal, lookup["workflow_id"]), "journal read denied")
        identifier = lookup["record_id"]
        _require(self._workflows.get(identifier) == lookup["workflow_id"], "journal record missing")
        return self._records[identifier].reference

    @bounds(_bounds("input"))
    def input(self, lookup: dict[str, Any], *, principal: str) -> dict[str, Any]:
        """Locate complete original accepted bytes without the driver's saved IDs."""
        acceptance = self.get(lookup, principal=principal)
        handle, _ = self._inputs[lookup["record_id"]]
        return {
            "format": "deployment-ops/workflow-journal-input/v1",
            "kind": "WorkflowJournalInputReference",
            "owner": dict(self.owner),
            "workflow_id": lookup["workflow_id"],
            "command_id": lookup["record_id"],
            "acceptance": acceptance,
            "input": copy.deepcopy(handle),
        }

    @bounds(_bounds("read-input"))
    def read_input(
        self,
        handle: dict[str, Any],
        *,
        principal: str,
        offset: int,
        length: int,
    ) -> dict[str, Any]:
        """Read a bounded exact input range under current local disclosure rights."""
        validate("common.schema.json", handle, "Handle")
        _require(handle["binding"]["kind"] == "workflow-journal", "journal input binding changed")
        identifier = handle["binding"]["command_id"]
        workflow_id = self._workflows.get(identifier)
        _require(workflow_id is not None, "journal input missing")
        assert workflow_id is not None
        _require(self._authorize(principal, workflow_id), "journal input read denied")
        expected, data = self._inputs[identifier]
        _require(handle == expected, "journal input handle changed")
        _require(
            type(offset) is int
            and 0 <= offset <= len(data)
            and type(length) is int
            and 1 <= length <= CHUNK_BYTES,
            "journal input range changed",
        )
        chunk = data[offset : offset + length]
        result = {
            "format": "deployment-ops/content-chunk/v1",
            "kind": "ContentChunk",
            "handle": copy.deepcopy(expected),
            "offset": offset,
            "base64": base64.b64encode(chunk).decode(),
            "next_offset": offset + len(chunk),
            "complete": offset + len(chunk) == len(data),
        }
        validate_content_chunk(result, handle, offset=offset, length=length)
        return result

    @bounds(_bounds("read"))
    def read(
        self,
        reference: dict[str, Any],
        *,
        principal: str,
        offset: int,
        length: int,
    ) -> dict[str, Any]:
        validate("workflow-journal.schema.json", reference, "RecordReference")
        _require(reference["owner"] == self.owner, "journal read owner changed")
        identifier = reference["record"]["id"]
        workflow_id = self._workflows.get(identifier)
        _require(workflow_id is not None, "journal record missing")
        assert workflow_id is not None
        _require(self._authorize(principal, workflow_id), "journal read denied")
        return self._records[identifier].chunk(reference, offset=offset, length=length)

    @bounds(_bounds("events"))
    def events(self, query: dict[str, Any], *, principal: str) -> dict[str, Any]:
        """Traverse every event through a stable high-water mark, without caller IDs.

        The in-memory reference resumes while this owner process retains its
        cursor. Restart explicitly rejects that cursor; a new traversal discovers
        all durable records again. It never silently rebinds a prior traversal.
        """
        validate("workflow-journal.schema.json", query, "EventsRequest")
        _require(query["owner"] == self.owner, "journal events owner changed")
        workflow_id = query["workflow_id"]
        _require(self._authorize(principal, workflow_id), "journal read denied")
        _require(workflow_id in self._by_workflow, "journal workflow is not retained")
        identifiers = self._by_workflow[workflow_id]
        cursor = query["cursor"]
        if cursor is None:
            offset, high_water = 0, len(identifiers)
        else:
            retained = self._cursors.get(cursor)
            _require(
                retained is not None and retained[0] == workflow_id,
                "journal cursor expired or changed scope",
            )
            assert retained is not None
            _, offset, high_water = retained
        end = min(offset + 64, high_water)
        items = [self._records[identifier].reference for identifier in identifiers[offset:end]]
        next_cursor = None
        if end < high_water:
            next_cursor = uuid5(self._cursor_namespace, f"{workflow_id}:{end}:{high_water}").hex
            self._cursors[next_cursor] = (workflow_id, end, high_water)
        return {
            "format": "deployment-ops/workflow-journal-page/v1",
            "kind": "WorkflowJournalPage",
            "owner": dict(self.owner),
            "items": items,
            "next_cursor": next_cursor,
            "history_complete": True,
        }

    @bounds(_bounds("heads"))
    def heads(self, query: dict[str, Any], *, principal: str) -> dict[str, Any]:
        """Discover each retained workflow through its immutable first record.

        Scan at most one bounded window per call, including denied workflows.
        Empty pages can still have a continuation. No page restarts a scan or
        materializes the complete workflow catalog; current permission applies
        independently to each returned workflow.
        """
        validate("workflow-journal.schema.json", query, "ListRequest")
        _require(query["owner"] == self.owner, "journal list owner changed")
        cursor = query["cursor"]
        if cursor is None:
            offset, high_water = 0, len(self._workflow_order)
        else:
            retained = self._cursors.get(cursor)
            _require(
                retained is not None and retained[0] is None,
                "journal cursor expired or changed scope",
            )
            assert retained is not None
            _, offset, high_water = retained
        end = min(offset + 64, high_water)
        items = [
            self._records[self._by_workflow[workflow_id][0]].reference
            for workflow_id in self._workflow_order[offset:end]
            if self._authorize(principal, workflow_id)
        ]
        next_cursor = None
        if end < high_water:
            next_cursor = uuid5(self._cursor_namespace, f"heads:{end}:{high_water}").hex
            self._cursors[next_cursor] = (None, end, high_water)
        return {
            "format": "deployment-ops/workflow-journal-page/v1",
            "kind": "WorkflowJournalPage",
            "owner": dict(self.owner),
            "items": items,
            "next_cursor": next_cursor,
            "history_complete": True,
        }
