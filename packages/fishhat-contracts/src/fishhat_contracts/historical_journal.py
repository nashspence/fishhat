"""Indexed original-epoch journal inspection under current custody and permission.

The receiver independently verifies the restoration manifest, signatures, complete
record/input custody and qualified historical readers. This in-memory delivery
model preserves those bytes; it does not restore a store or authorize execution.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable, Mapping
from copy import deepcopy
from typing import Any
from uuid import uuid4

from .bounds import Bounds, bounds
from .handoffs import schema_identity
from .history import (
    authorize_history_request,
    validate_history_result,
    validate_owner_custody,
)
from .record_delivery import RecordSnapshot, validate_record_payload
from .validation import ContractError, canonical, strict_json, validate

Readers = Mapping[tuple[str, str], Callable[[dict[str, Any]], None]]
Authorize = Callable[[str, str | None], bool]
JournalIdentity = tuple[str, str]
_COMMAND_URI = "https://fishhat.invalid/contracts/workflow-journal.schema.json#/$defs/Command"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _bounds(name: str) -> Bounds:
    proof = "tests/test_historical_journal.py::test_complete_historical_journal_delivery_is_linear"
    return Bounds(
        id="history.journal." + name,
        work="O(B) complete original registration once; indexed O(page window) discovery and O(selected chunk bytes) reads without journal rescans",
        extent="Every retained original event and accepted command across bounded pages and chunks, including denied scan windows and exact retries",
        limits=(("page_scan", 128), ("chunk_bytes", 196608)),
        capacity=("current owner retains complete verified historical record/input custody",),
        proofs=(proof,),
        linear_proofs=(proof,),
    )


@bounds(_bounds("command"))
def validate_historical_journal_command(
    result: dict[str, Any],
    record_bytes: bytes,
    input_bytes: bytes,
    *,
    expected_request: dict[str, Any],
    verified_custody: dict[str, Any],
    retained_readers: Readers | None = None,
) -> dict[str, Any]:
    """Join exact old signed acceptance, handle and independently installed reader.

    Current read permission, signature authenticity and restoration membership
    are independent owner duties. Returned historical input is inspection only;
    it never passes through ordinary submission or supplies current authority.
    """
    validate_history_result(
        result,
        expected_request=expected_request,
        verified_custody=verified_custody,
        retained_readers=retained_readers,
    )
    _require(result["kind"] == "HistoricalJournalInputReference", "not historical journal input")
    record = validate_record_payload(
        expected_request["reference"],
        record_bytes,
        expected_owner=verified_custody["origin"],
        retained_readers=retained_readers,
    )
    handle = result["input"]
    _require(
        len(input_bytes) == handle["size"]
        and "sha256:" + hashlib.sha256(input_bytes).hexdigest()
        == handle["digest"]
        == record["body"]["command_digest"],
        "historical journal command bytes differ from original acceptance",
    )
    command = strict_json(input_bytes, max_bytes=len(input_bytes))
    _require(isinstance(command, dict), "historical journal command is not an object")
    identity = result["input_schema"]
    if identity == schema_identity(_COMMAND_URI):
        validate("workflow-journal.schema.json", command, "Command")
    else:
        reader = (retained_readers or {}).get((identity["uri"], identity["digest"]))
        _require(reader is not None, "historical journal input reader is not installed")
        assert reader is not None
        reader(command)
    _require(
        canonical(command) == input_bytes
        and command["id"] == record["id"]
        and command["workflow_id"] == record["workflow_id"],
        "historical journal command identity or canonical bytes changed",
    )
    return dict(command)


class HistoricalJournalDelivery:
    """Pure bounded delivery of one independently verified historical origin.

    Register each exact original record and accepted input once while the native
    owner verifies its restoration closure. No method registers request-provided
    trust, custody or readers. Current authorization is checked on every page,
    lookup and chunk; cursors are principal/custody/filter/high-water bound and
    expire with this model instance. Epoch changes require a new independently
    approved custody descriptor and index, preserving the original references.
    """

    def __init__(
        self,
        verified_custody: dict[str, Any],
        *,
        authorize: Authorize,
        retained_readers: Readers | None = None,
    ) -> None:
        validate_owner_custody(verified_custody)
        self._custody = deepcopy(verified_custody)
        self._authorize = authorize
        self._readers = retained_readers
        self._records: dict[JournalIdentity, RecordSnapshot] = {}
        self._inputs: dict[JournalIdentity, tuple[dict[str, Any], dict[str, Any], bytes]] = {}
        self._handles: dict[str, JournalIdentity] = {}
        self._order: list[JournalIdentity] = []
        self._by_workflow: dict[str, list[JournalIdentity]] = {}
        self._cursors: dict[str, tuple[str, bytes, int, int, int]] = {}

    def _request(self, reference: dict[str, Any]) -> dict[str, Any]:
        return {
            "custodian": deepcopy(self._custody["custodian"]),
            "custody_id": self._custody["id"],
            "reference": deepcopy(reference),
        }

    def _result(self, kind: str, request: dict[str, Any], **fields: Any) -> dict[str, Any]:
        return {
            "format": "deployment-ops/owner-history/v1",
            "kind": kind,
            "request": deepcopy(request),
            "origin": deepcopy(self._custody["origin"]),
            **fields,
        }

    def _authorize_request(
        self, method: str, request: dict[str, Any], principal: str, workflow_id: str | None
    ) -> None:
        authorize_history_request(
            method,
            request,
            current_owner=self._custody["custodian"],
            read_authorized=self._authorize(principal, workflow_id),
            verified_custody=self._custody,
        )

    @bounds(_bounds("register"))
    def register(
        self,
        reference: dict[str, Any],
        record_bytes: bytes,
        *,
        input_handle: dict[str, Any],
        input_schema: dict[str, Any],
        input_bytes: bytes,
    ) -> None:
        """Index original immutable custody supplied by verified native restoration."""
        validate("owner-history.schema.json", reference, "JournalReference")
        request = self._request(reference)
        result = self._result(
            "HistoricalJournalInputReference",
            request,
            input=input_handle,
            input_schema=input_schema,
        )
        command = validate_historical_journal_command(
            result,
            record_bytes,
            input_bytes,
            expected_request=request,
            verified_custody=self._custody,
            retained_readers=self._readers,
        )
        workflow_id = command["workflow_id"]
        identifier = (workflow_id, command["id"])
        existing = self._records.get(identifier)
        if existing is not None:
            _require(
                existing.reference == reference
                and self._inputs[identifier] == (input_handle, input_schema, input_bytes),
                "historical journal identity conflict",
            )
            return
        _require(input_handle["id"] not in self._handles, "historical input handle reused")
        snapshot = RecordSnapshot.restore(
            reference,
            record_bytes,
            expected_owner=self._custody["origin"],
            retained_readers=self._readers,
        )
        self._records[identifier] = snapshot
        self._inputs[identifier] = (
            deepcopy(input_handle),
            deepcopy(input_schema),
            bytes(input_bytes),
        )
        self._handles[input_handle["id"]] = identifier
        self._order.append(identifier)
        self._by_workflow.setdefault(workflow_id, []).append(identifier)

    @bounds(_bounds("list"))
    def list(self, request: dict[str, Any], *, principal: str) -> dict[str, Any]:
        """Visit one bounded indexed window; null scope discovers every permitted event."""
        validate("owner-history.schema.json", request, "ListRequest")
        _require(request["record_kind"] == "WorkflowJournalRecord", "not journal history")
        resource = request["resource"]
        workflow_id = None if resource is None else resource["id"]
        self._authorize_request("history.list", request, principal, workflow_id)
        identities = self._order if workflow_id is None else self._by_workflow.get(workflow_id, [])
        scope = canonical(
            {
                "custody": self._custody["digest"],
                "resource": resource,
                "record_kind": request["record_kind"],
                "active_only": request["active_only"],
            }
        )
        cursor, limit = request["cursor"], request["limit"]
        if cursor is None:
            offset, high_water = 0, len(identities)
        else:
            selected = self._cursors.get(cursor)
            _require(
                selected is not None and selected[:3] == (principal, scope, limit),
                "historical journal cursor expired or changed scope",
            )
            assert selected is not None
            _, _, _, offset, high_water = selected
        end = min(offset + limit, high_water)
        items = [
            self._records[identifier].reference
            for identifier in identities[offset:end]
            if self._authorize(principal, identifier[0])
        ]
        next_cursor = None
        if end < high_water:
            next_cursor = uuid4().hex
            self._cursors[next_cursor] = (principal, scope, limit, end, high_water)
        return self._result(
            "HistoricalRecordPage",
            request,
            items=items,
            next_cursor=next_cursor,
            history_complete=True,
        )

    def _selected(self, method: str, request: dict[str, Any], principal: str) -> JournalIdentity:
        reference = request["reference"]
        workflow_id = reference["record"]["resource"]["id"]
        self._authorize_request(method, request, principal, workflow_id)
        identifier = (workflow_id, reference["record"]["id"])
        existing = self._records.get(identifier)
        _require(
            existing is not None and existing.reference == reference,
            "historical journal reference is outside verified custody",
        )
        return identifier

    @bounds(_bounds("input"))
    def input(self, request: dict[str, Any], *, principal: str) -> dict[str, Any]:
        """Find the unchanged command handle/schema from the discovered event reference."""
        validate("owner-history.schema.json", request, "InputRequest")
        identifier = self._selected("history.input", request, principal)
        handle, identity, _ = self._inputs[identifier]
        return self._result(
            "HistoricalJournalInputReference",
            request,
            input=deepcopy(handle),
            input_schema=deepcopy(identity),
        )

    @bounds(_bounds("read"))
    def read(self, request: dict[str, Any], *, principal: str) -> dict[str, Any]:
        validate("owner-history.schema.json", request, "ReadRequest")
        validate("owner-history.schema.json", request["reference"], "JournalReference")
        identifier = self._selected("history.read", request, principal)
        chunk = self._records[identifier].chunk(
            request["reference"], offset=request["offset"], length=request["length"]
        )
        return self._result("HistoricalRecordChunk", request, chunk=chunk)

    @bounds(_bounds("content"))
    def content(self, request: dict[str, Any], *, principal: str) -> dict[str, Any]:
        validate("owner-history.schema.json", request, "ContentRequest")
        handle = request["handle"]
        _require(handle["binding"]["kind"] == "workflow-journal", "not journal input custody")
        self._authorize_request(
            "history.content", request, principal, handle["binding"]["workflow_id"]
        )
        identifier = self._handles.get(handle["id"])
        _require(identifier is not None, "historical journal input is outside verified custody")
        assert identifier is not None
        original, _, data = self._inputs[identifier]
        _require(handle == original, "historical journal input handle changed")
        offset = request["offset"]
        chunk = data[offset : offset + request["length"]]
        return self._result(
            "HistoricalContentChunk",
            request,
            base64=base64.b64encode(chunk).decode(),
            next_offset=offset + len(chunk),
            complete=offset + len(chunk) == len(data),
        )
