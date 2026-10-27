"""Complete observation selections and retained traversal reference models.

The receiving owner supplies authenticated principals, current permissions,
authoritative inventory and durable custody. This pure model establishes none
of those native facts and does not execute a health check or contact a resource.
"""

from __future__ import annotations

import copy
import hashlib
import uuid
from collections.abc import Callable, Iterable
from typing import Any

from .bounds import Bounds, bounds
from .handoffs import validate_staged_input
from .record_delivery import RecordSnapshot, validate_observation
from .validation import MAX_BYTES, ContractError, canonical, digest, strict_json, validate

Authorize = Callable[[dict[str, Any]], bool]
PAGE_RESERVE_BYTES = 4096


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ContractError(code)


def _selection_bounds(name: str) -> Bounds:
    return Bounds(
        id="observations." + name,
        work="O(B + N) complete admitted selection/inventory bytes and selected records",
        extent="complete exact selection, including an empty selection",
        limits=(),
        capacity=("Receiver-approved staging and retained snapshot capacities reject explicitly",),
        proofs=("tests/test_observation_selection.py::test_large_selection_roundtrips_once",),
        linear_proofs=(
            "tests/test_observation_selection.py::test_complete_traversal_request_work_is_linear",
        ),
    )


@bounds(_selection_bounds("decode"))
def decode_observation_selection(
    request: dict[str, Any],
    data: bytes,
    *,
    expected_owner: dict[str, Any],
    method: str,
    capacity_bytes: int | None = None,
) -> dict[str, Any]:
    """Verify the entire staged exact selection once, outside the wire frame bound."""
    validate("observation.schema.json", request, "StartRequest")
    _require(request["selection"]["kind"] == "exact", "EXACT_SELECTION_REQUIRED")
    handle = request["selection"]["input"]
    _require(request["owner"] == handle["owner"] == expected_owner, "OWNER_EPOCH_CHANGED")
    _require(
        capacity_bytes is None or (type(capacity_bytes) is int and capacity_bytes > 0),
        "INVALID_CAPACITY",
    )
    _require(
        len(data) == handle["size"]
        and "sha256:" + hashlib.sha256(data).hexdigest() == handle["digest"],
        "SELECTION_CONTENT_IDENTITY",
    )
    value = strict_json(data, max_bytes=len(data) if capacity_bytes is None else capacity_bytes)
    validate("observation.schema.json", value, "SelectionInput")
    _require(
        value["owner"] == expected_owner and value["method"] == method,
        "SELECTION_CONTEXT_CHANGED",
    )
    _require(canonical(value) == data, "SELECTION_NOT_CANONICAL")
    return dict(value)


def validate_observation_selection_custody(
    request: dict[str, Any],
    payload: dict[str, Any],
    staging: dict[str, Any],
    *,
    expected_owner: dict[str, Any],
    method: str,
    principal: str,
    now: str,
    staging_authorized: bool,
) -> None:
    """Use independently loaded staging and its actual current disclosure decision.

    The staging resource belongs to protected owner state, not the selection.
    Upload/custody permission never substitutes for selected-resource permission.
    """
    _require(staging_authorized, "PERMISSION_DENIED")
    decode_observation_selection(
        request, canonical(payload), expected_owner=expected_owner, method=method
    )
    validate_staged_input(
        staging,
        request["selection"]["input"],
        expected_owner=expected_owner,
        principal=principal,
        resource=staging["resource"],
        purpose="content",
        now=now,
    )


class ObservationTraversal:
    """A retained finite snapshot, with constant-size continuations and linear scans.

    Native owners must durably retain this state before disclosure and reauthorize
    snapshot reads. A restored/expired native store cannot reconstruct a traversal
    from its cursor. The model keeps original observations without freshening them.
    """

    @bounds(_selection_bounds("start"))
    def __init__(
        self,
        request: dict[str, Any],
        *,
        method: str,
        principal: str,
        expected_owner: dict[str, Any],
        traversal_id: str,
        records: Iterable[dict[str, Any]],
        authorize: Authorize,
        selected_input: dict[str, Any] | None = None,
        input_custody_verified: bool = False,
    ) -> None:
        validate("observation.schema.json", request, "StartRequest")
        validate("common.schema.json", traversal_id, "UUID")
        _require(request["owner"] == expected_owner, "OWNER_EPOCH_CHANGED")
        _require(method in {"observe", "check"} and bool(principal), "INVALID_INPUT")
        self.owner = copy.deepcopy(expected_owner)
        self.principal = principal
        self.method = method
        self._start = copy.deepcopy(request)
        self._available = True
        inventory: dict[bytes, dict[str, Any]] = {}
        for record in records:
            validate_observation(record)
            _require(record["owner"] == self.owner, "OBSERVATION_OWNER_CHANGED")
            key = canonical(record["resource"])
            _require(key not in inventory, "DUPLICATE_RESOURCE")
            inventory[key] = record
        if request["selection"]["kind"] == "exact":
            _require(
                selected_input is not None and input_custody_verified, "SELECTION_CUSTODY_REQUIRED"
            )
            assert selected_input is not None
            payload = decode_observation_selection(
                request, canonical(selected_input), expected_owner=self.owner, method=method
            )
            resources = payload["resources"]
            for resource in resources:
                _require(authorize(resource), "PERMISSION_DENIED")
                _require(canonical(resource) in inventory, "NOT_FOUND")
        else:
            _require(selected_input is None, "UNREQUESTED_SELECTION_INPUT")
            resources = [
                record["resource"] for record in inventory.values() if authorize(record["resource"])
            ]
            payload = {
                "format": "deployment-ops/observation-selection/v1",
                "owner": self.owner,
                "method": method,
                "resources": resources,
            }
        self.traversal = {"id": traversal_id, "method": method, "selection_digest": digest(payload)}
        self._items: list[tuple[dict[str, Any], dict[str, Any], int]] = []
        self._snapshots: dict[str, RecordSnapshot] = {}
        for resource in resources:
            record = copy.deepcopy(inventory[canonical(resource)])
            size = len(canonical(record))
            if size + 1 > MAX_BYTES - PAGE_RESERVE_BYTES:
                snapshot = RecordSnapshot(record, str(uuid.uuid4()), record_kind="Observation")
                self._snapshots[snapshot.reference["snapshot_id"]] = snapshot
                record = snapshot.reference
                size = len(canonical(record))
            self._items.append((copy.deepcopy(resource), record, size))
        self._cursors: dict[str, int] = {}
        self._positions: dict[int, str] = {}

    def expire(self) -> None:
        """Model lost or explicitly expired custody; no request silently restarts it."""
        self._available = False

    @bounds(
        Bounds(
            id="observations.record-chunk",
            work="O(C) requested immutable record chunk bytes",
            extent="one complete retained observation through bounded chunks",
            limits=(("chunk_bytes", 196608),),
            capacity=(),
            proofs=(
                "tests/test_observation_selection.py::test_large_snapshot_chunks_reauthorize_original_custody",
            ),
            linear_proofs=(
                "tests/test_observation_selection.py::test_large_snapshot_chunks_reauthorize_original_custody",
            ),
        )
    )
    def record_chunk(
        self,
        reference: dict[str, Any],
        *,
        offset: int,
        length: int,
        principal: str,
        expected_owner: dict[str, Any],
        authorize: Authorize,
    ) -> dict[str, Any]:
        """Redeem an advertised snapshot under current independent read permission."""
        _require(expected_owner == self.owner, "OWNER_EPOCH_CHANGED")
        _require(principal == self.principal, "PERMISSION_DENIED")
        _require(self._available, "RETENTION_GAP")
        snapshot = self._snapshots.get(reference.get("snapshot_id", ""))
        _require(snapshot is not None, "RETENTION_GAP")
        assert snapshot is not None
        _require(reference == snapshot.reference, "RECORD_IDENTITY_CHANGED")
        _require(authorize(snapshot.reference["record"]["resource"]), "PERMISSION_DENIED")
        return snapshot.chunk(reference, offset=offset, length=length)

    @bounds(
        Bounds(
            id="observations.page",
            work="O(P) emitted page bytes and page-resource authorization checks",
            extent="complete retained traversal through bounded independent pages",
            limits=(("page_items", 256), ("frame_bytes", MAX_BYTES)),
            capacity=(),
            proofs=("tests/test_observation_selection.py::test_large_selection_roundtrips_once",),
            linear_proofs=(
                "tests/test_observation_selection.py::test_complete_traversal_request_work_is_linear",
            ),
        )
    )
    def page(
        self,
        request: dict[str, Any],
        *,
        method: str,
        principal: str,
        expected_owner: dict[str, Any],
        authorize: Authorize,
    ) -> dict[str, Any]:
        validate("observation.schema.json", request, "Request")
        _require(request["owner"] == self.owner == expected_owner, "OWNER_EPOCH_CHANGED")
        _require(principal == self.principal, "PERMISSION_DENIED")
        _require(method == self.method, "TRAVERSAL_METHOD_CHANGED")
        _require(self._available, "RETENTION_GAP")
        if "cursor" in request:
            position = self._cursors.get(request["cursor"])
            _require(position is not None, "RETENTION_GAP")
            assert position is not None
        else:
            _require(request == self._start, "TRAVERSAL_SELECTION_CHANGED")
            position = 0
        items: list[dict[str, Any]] = []
        used = PAGE_RESERVE_BYTES
        end = position
        while end < len(self._items) and len(items) < request["limit"]:
            resource, record, size = self._items[end]
            if used + size + 1 > MAX_BYTES:
                break
            _require(authorize(resource), "PERMISSION_DENIED")
            items.append(copy.deepcopy(record))
            used += size + 1
            end += 1
        cursor = None
        if end < len(self._items):
            _require(end > position, "OUTPUT_LIMIT")
            if end not in self._positions:
                self._positions[end] = uuid.uuid4().hex
                self._cursors[self._positions[end]] = end
            cursor = self._positions[end]
        return {
            "format": "deployment-ops/record/v1",
            "kind": "ObservationPage",
            "owner": copy.deepcopy(self.owner),
            "traversal": copy.deepcopy(self.traversal),
            "position": position,
            "items": items,
            "next_cursor": cursor,
        }
