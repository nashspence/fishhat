"""Immutable record delivery reference models; no store, transport or authorization.

An owner must independently establish custody and permission before publishing or
reading a snapshot. Serialization happens once; chunks do not reprocess the record.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
from collections.abc import Callable, Mapping
from typing import Any, cast

from .bounds import Bounds, bounds
from .handoffs import schema_identity, validate_workflow
from .operations import validate_operation
from .validation import (
    MAX_BYTES,
    SCHEMAS,
    ContractError,
    canonical,
    strict_json,
    validate,
    validate_plan,
)

CHUNK_BYTES = 196608
RECORD_SCHEMAS = {
    "Plan": ("records.schema.json", "Plan"),
    "Operation": ("records.schema.json", "Operation"),
    "Workflow": ("records.schema.json", "Workflow"),
    "Discovery": ("records.schema.json", "Info"),
    "ResourceReport": ("resource-records.schema.json", "ResourceReport"),
    "Observation": ("records.schema.json", "Observation"),
    "ProblemEvidence": ("records.schema.json", "ProblemEvidence"),
}
SNAPSHOT_ID_KINDS = {"Discovery", "ResourceReport", "Observation", "ProblemEvidence"}
SCOPED_KINDS = {"Observation", "ProblemEvidence"}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _identity(record: dict[str, Any], kind: str, snapshot_id: str) -> dict[str, Any]:
    identity = {
        "kind": kind,
        "id": snapshot_id if kind in SNAPSHOT_ID_KINDS else record["id"],
        "generation": None if kind == "Plan" or kind in SNAPSHOT_ID_KINDS else record["generation"],
    }
    if kind in SCOPED_KINDS:
        identity["resource"] = copy.deepcopy(record["resource"])
    return identity


def _schema_uri(kind: str) -> str:
    _require(kind in RECORD_SCHEMAS, "unsupported record snapshot kind")
    schema, definition = RECORD_SCHEMAS[kind]
    return str(SCHEMAS[schema]["$id"]) + "#/$defs/" + definition


def _validate_record(
    record: dict[str, Any],
    kind: str,
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    _require(kind in RECORD_SCHEMAS, "unsupported record snapshot kind")
    if kind == "Plan":
        validate_plan(record)
    elif kind == "Workflow":
        validate_workflow(record, recovery_readers=recovery_readers)
    elif kind == "Operation":
        validate_operation(record, recovery_readers=recovery_readers)
    elif kind == "Observation":
        validate_observation(record)
    else:
        schema, definition = RECORD_SCHEMAS[kind]
        validate(schema, record, definition)


def validate_record_reference(
    reference: dict[str, Any],
    *,
    expected_owner: dict[str, Any] | None = None,
    expected_record: dict[str, Any] | None = None,
    expected_resource: dict[str, Any] | None = None,
    retained_readers: Mapping[str, Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Check exact installed/retained schema and independent owner/record expectations.

    Without independent expectations this checks shape and schema only, never origin
    or permission. A newer record generation cannot silently replace a pinned one.
    """
    validate("common.schema.json", reference, "RecordReference")
    kind = reference["record"]["kind"]
    uri = _schema_uri(kind)
    if kind in SNAPSHOT_ID_KINDS:
        _require(
            reference["record"]["id"] == reference["snapshot_id"],
            "record snapshot identity changed",
        )
    current = reference["schema"] == schema_identity(uri)
    # Historical documents are read-only. The independent receiving owner installs
    # and qualifies an immutable reader against the exact prior closure digest;
    # an untrusted record, payload, URL or caller cannot register that reader.
    retained = retained_readers is not None and reference["schema"]["digest"] in retained_readers
    _require(
        reference["schema"]["uri"] == uri and (current or retained), "record schema substitution"
    )
    if expected_owner is not None:
        _require(reference["owner"] == expected_owner, "record owner epoch substitution")
    if expected_record is not None:
        _require(
            reference["record"] == expected_record, "record identity or generation substitution"
        )
    if expected_resource is not None:
        _require(
            reference["record"].get("resource") == expected_resource,
            "record disclosure resource substitution",
        )


class RecordSnapshot:
    """Pure immutable-byte model for an already authorized owner record.

    No object created here proves native snapshot durability, receiving permission,
    retention or signature authenticity. Native stores must provide those boundaries.
    """

    def __init__(
        self,
        record: dict[str, Any],
        snapshot_id: str,
        *,
        record_kind: str | None = None,
        recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
    ) -> None:
        # Info has no kind discriminator. Its only valid snapshot kind is the
        # explicitly schema-pinned Discovery projection, never a ledger record.
        kind = record_kind if record_kind is not None else record.get("kind", "Discovery")
        _validate_record(record, kind, recovery_readers=recovery_readers)
        validate("common.schema.json", snapshot_id, "UUID")
        self._record = copy.deepcopy(record)
        self._data = canonical(self._record)
        uri = _schema_uri(kind)
        self._reference = {
            "format": "deployment-ops/record-reference/v1",
            "kind": "RecordReference",
            "snapshot_id": snapshot_id,
            "owner": copy.deepcopy(record["owner"]),
            "record": _identity(record, kind, snapshot_id),
            "schema": schema_identity(uri),
            "digest": "sha256:" + hashlib.sha256(self._data).hexdigest(),
            "size": len(self._data),
        }
        validate("common.schema.json", self._reference, "RecordReference")

    @property
    def reference(self) -> dict[str, Any]:
        return copy.deepcopy(self._reference)

    def delivery(self, *, max_inline_bytes: int) -> dict[str, Any]:
        """Select whole inline bytes or a reference within the caller's reserved budget.

        The caller accounts for its envelope and any other page items separately;
        the framing boundary still validates the complete serialized response.
        """
        _require(
            type(max_inline_bytes) is int and 0 < max_inline_bytes <= MAX_BYTES,
            "invalid inline record budget",
        )
        if len(self._data) <= max_inline_bytes:
            return copy.deepcopy(self._record)
        _require(len(canonical(self._reference)) <= max_inline_bytes, "record reference capacity")
        return self.reference

    @bounds(
        Bounds(
            id="record-delivery.chunk",
            work="O(chunk_bytes)",
            extent="one-record-chunk",
            limits=(("chunk_bytes", CHUNK_BYTES),),
            capacity=(),
            proofs=(
                "tests/test_record_delivery.py::test_record_chunk_work_tracks_requested_range",
            ),
        )
    )
    def chunk(self, reference: dict[str, Any], *, offset: int, length: int) -> dict[str, Any]:
        """Read one immutable range after the native caller's current authorization check."""
        _require(reference == self._reference, "record snapshot reference changed")
        _require(
            type(offset) is int and 0 <= offset <= len(self._data),
            "record offset outside snapshot",
        )
        _require(type(length) is int and 1 <= length <= CHUNK_BYTES, "record chunk length")
        data = self._data[offset : offset + length]
        next_offset = offset + len(data)
        return {
            "format": "deployment-ops/record-chunk/v1",
            "kind": "RecordChunk",
            "reference": self.reference,
            "offset": offset,
            "base64": base64.b64encode(data).decode("ascii"),
            "next_offset": next_offset,
            "complete": next_offset == len(self._data),
        }


def validate_record_chunk(
    chunk: dict[str, Any],
    reference: dict[str, Any],
    *,
    offset: int,
    length: int,
) -> bytes:
    """Check a response against the independently retained exact range request."""
    validate("common.schema.json", chunk, "RecordChunk")
    _require(
        type(offset) is int
        and 0 <= offset <= reference["size"]
        and type(length) is int
        and 1 <= length <= CHUNK_BYTES,
        "record range request invalid",
    )
    _require(
        chunk["reference"] == reference and chunk["offset"] == offset,
        "record chunk identity or offset substitution",
    )
    try:
        data = base64.b64decode(chunk["base64"], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ContractError("invalid record chunk encoding") from exc
    end = offset + len(data)
    _require(
        len(data) <= length and end <= reference["size"] and chunk["next_offset"] == end,
        "record chunk range mismatch",
    )
    _require(chunk["complete"] == (end == reference["size"]), "record completion mismatch")
    _require(bool(data) or chunk["complete"], "record chunk made no progress")
    return data


def validate_record_payload(
    reference: dict[str, Any],
    data: bytes,
    *,
    expected_owner: dict[str, Any],
    expected_record: dict[str, Any] | None = None,
    expected_resource: dict[str, Any] | None = None,
    retained_readers: Mapping[str, Callable[[dict[str, Any]], None]] | None = None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> dict[str, Any]:
    """Verify complete transferred bytes once; a transport frame cap is not a record cap.

    A native receiver can enforce explicit local capacity while streaming and must
    preserve custody on failure. This finite in-memory model asserts no native bound.
    """
    validate_record_reference(
        reference,
        expected_owner=expected_owner,
        expected_record=expected_record,
        expected_resource=expected_resource,
        retained_readers=retained_readers,
    )
    _require(
        len(data) == reference["size"]
        and "sha256:" + hashlib.sha256(data).hexdigest() == reference["digest"],
        "record content identity mismatch",
    )
    value = strict_json(data, max_bytes=reference["size"])
    _require(isinstance(value, dict), "record payload must be object")
    kind = reference["record"]["kind"]
    uri = _schema_uri(kind)
    if reference["schema"] == schema_identity(uri):
        _validate_record(value, kind, recovery_readers=recovery_readers)
    else:
        assert retained_readers is not None
        retained_readers[reference["schema"]["digest"]](value)
    _require(
        value["owner"] == reference["owner"]
        and _identity(value, kind, reference["snapshot_id"]) == reference["record"],
        "record payload binding mismatch",
    )
    _require(canonical(value) == data, "record payload encoding is not canonical")
    return cast(dict[str, Any], value)


def validate_observation(observation: dict[str, Any]) -> None:
    """Check one complete observation without upgrading its provenance or authority."""
    validate("records.schema.json", observation, "Observation")
    witness = observation["witness"]
    if witness is not None:
        _require(witness["owner"] == observation["owner"], "observation witness owner mismatch")


def validate_observation_page(
    page: dict[str, Any],
    *,
    expected_owner: dict[str, Any],
    resources: list[dict[str, Any]] | None = None,
    retained_readers: Mapping[str, Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Join inline/reference observations to the retained query, including empty replies.

    Query matching does not authorize disclosure. The native owner independently
    checks current principal permission for each protected resource and snapshot.
    """
    validate("records.schema.json", page, "ObservationPage")
    _require(page["owner"] == expected_owner, "observation page owner epoch changed")
    selected = None if resources is None else {canonical(resource) for resource in resources}
    seen: set[bytes] = set()
    for item in page["items"]:
        _require(item["owner"] == expected_owner, "observation page contains another owner epoch")
        if item.get("kind") == "RecordReference":
            validate_record_reference(
                item, expected_owner=expected_owner, retained_readers=retained_readers
            )
            resource = item["record"]["resource"]
        else:
            validate_observation(item)
            resource = item["resource"]
        identity = canonical(resource)
        _require(identity not in seen, "observation page repeats resource")
        seen.add(identity)
        _require(
            selected is None or identity in selected, "observation outside requested selection"
        )


def validate_problem(
    problem: dict[str, Any],
    *,
    retained_readers: Mapping[str, Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Check complete inline evidence or its exact owner/resource snapshot binding.

    The Problem cannot install a historical reader or grant access to its evidence.
    Retrieval must reauthorize the protected scope and verify the complete payload.
    """
    validate("records.schema.json", problem, "Problem")
    evidence = problem["evidence"]
    if isinstance(evidence, dict):
        validate_record_reference(
            evidence,
            expected_owner=problem["owner"],
            expected_resource=problem["resource"],
            retained_readers=retained_readers,
        )


def validate_log_page(
    page: dict[str, Any], *, expected_owner: dict[str, Any], resource: dict[str, Any]
) -> None:
    """Validate even an empty log reply against independently retained query context."""
    validate("records.schema.json", page, "EventPage")
    _require(
        page["owner"] == expected_owner and page["resource"] == resource,
        "log page owner epoch or resource changed",
    )
    positions = [event["cursor"] for event in page["events"]]
    _require(positions == sorted(set(positions)), "log event positions are not strictly ordered")
