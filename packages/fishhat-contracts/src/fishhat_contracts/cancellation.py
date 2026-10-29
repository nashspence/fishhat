"""Durable stop-intent contract model, separate from operation execution.

The receiver supplies current authenticated permissions and independently loaded
target facts under native transition exclusion. This in-memory model proves no
authentication, persistence, atomic storage, stopping or native recovery. Its
complete retained receipts can be serialized and restored without client state.
"""

from __future__ import annotations

import copy
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .bounds import Bounds, bounds
from .validation import ContractError, digest, validate

_TERMINAL = {"succeeded", "failed", "cancelled", "quarantined"}


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ContractError(code)


def _bounds(name: str, work: str, extent: str) -> Bounds:
    return Bounds(
        id="cancellation." + name,
        work=work,
        extent=extent,
        limits=(("page_items", 128),) if name == "list" else (),
        capacity=(
            "Native receiver capacity rejects new intent explicitly; accepted identities remain",
        ),
        proofs=("tests/test_cancellation.py::test_restart_and_replay_preserve_original_intent",),
        linear_proofs=(
            "tests/test_cancellation_growth.py::test_complete_admission_restart_listing_and_retries_are_linear",
        ),
    )


def _request(receipt: dict[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(receipt[key]) for key in ("owner", "request_id", "cancellation_id")}


@bounds(
    _bounds("validate", "O(1) finite receipt and expected request", "Complete original decision")
)
def validate_cancellation_receipt(
    value: dict[str, Any], *, expected_request: dict[str, Any] | None = None
) -> None:
    """Check an original decision; authentication and current authorization are external."""
    validate("cancellation.schema.json", value, "Receipt")
    request = _request(value)
    _require(value["request_digest"] == digest(request), "CANCELLATION_REQUEST_CHANGED")
    if expected_request is not None:
        validate("cancellation.schema.json", expected_request, "Request")
        _require(request == expected_request, "CANCELLATION_REQUEST_CHANGED")


def validate_cancellation_page(
    value: dict[str, Any],
    *,
    expected_owner: dict[str, Any],
    request_id: str,
    expected_custodian: dict[str, Any] | None = None,
    custody_id: str | None = None,
    traversal_id: str | None = None,
    position: int | None = None,
    limit: int = 128,
) -> None:
    """Correlate a complete page without interpreting it as operation termination."""
    validate("cancellation.schema.json", value, "Page")
    _require(type(limit) is int and 1 <= limit <= 128, "INVALID_LIMIT")
    _require(
        value["owner"] == expected_owner and value["request_id"] == request_id,
        "CANCELLATION_PAGE_SCOPE_CHANGED",
    )
    custodian = expected_owner if expected_custodian is None else expected_custodian
    _require(
        value["custodian"] == custodian and value["custody_id"] == custody_id,
        "CANCELLATION_CUSTODY_CHANGED",
    )
    _require(
        all(custodian[key] == expected_owner[key] for key in ("tool", "id"))
        and ((custodian == expected_owner) == (custody_id is None)),
        "CANCELLATION_CUSTODY_CHANGED",
    )
    if traversal_id is not None:
        _require(value["traversal_id"] == traversal_id, "CANCELLATION_TRAVERSAL_CHANGED")
    if position is not None:
        _require(value["position"] == position, "CANCELLATION_POSITION_CHANGED")
    _require(len(value["items"]) <= limit, "CANCELLATION_PAGE_LIMIT")
    _require(bool(value["items"]) or value["next_cursor"] is None, "CANCELLATION_NO_PROGRESS")
    seen: set[str] = set()
    for receipt in value["items"]:
        validate_cancellation_receipt(receipt)
        _require(
            receipt["owner"] == expected_owner and receipt["request_id"] == request_id,
            "CANCELLATION_PAGE_SCOPE_CHANGED",
        )
        _require(receipt["cancellation_id"] not in seen, "CANCELLATION_PAGE_DUPLICATE")
        seen.add(receipt["cancellation_id"])


def validate_cancellation_result(value: dict[str, Any]) -> None:
    """Validate a decoded decision or page without granting receiving authority."""
    validate("cancellation.schema.json", value)
    if value["kind"] == "OperationCancellationReceipt":
        validate_cancellation_receipt(value)
    else:
        validate_cancellation_page(
            value,
            expected_owner=value["owner"],
            request_id=value["request_id"],
            expected_custodian=value["custodian"],
            custody_id=value["custody_id"],
        )


@dataclass(frozen=True)
class _Traversal:
    principal: str
    request_id: str
    limit: int
    extent: int


class CancellationJournal:
    """Indexed decision journal; never a native authority or executor.

    A native implementation commits receipt and stop intent in the same durable
    transaction before advertising success, serialized against target completion.
    It independently restores retained intent after restart. Cancellation does
    not modify an Operation snapshot or remove any of its effect/hold custody.
    Opening original receipts under a different current custodian requires
    independently verified protected restoration custody and supplies historical
    reads only. Its verified manifest must include these exact receipts and
    target scope; this model does not authenticate descriptors or prove inclusion.
    An epoch change never installs old executable stop flags or revives work.
    """

    @bounds(
        _bounds(
            "restore",
            "O(N) one pass over all finite retained receipts; no prefix truncation",
            "Every retained cancellation identity, original decision and attribution",
        )
    )
    def __init__(
        self,
        owner: dict[str, Any],
        *,
        retained: Iterable[dict[str, Any]] = (),
        custodian: dict[str, Any] | None = None,
        verified_custody: dict[str, Any] | None = None,
    ) -> None:
        validate("common.schema.json", owner, "Owner")
        self._owner = copy.deepcopy(owner)
        self._custodian = copy.deepcopy(owner if custodian is None else custodian)
        validate("common.schema.json", self._custodian, "Owner")
        self._custody = copy.deepcopy(verified_custody)
        self._check_custody(verified_custody)
        self._receipts: dict[str, dict[str, Any]] = {}
        self._by_target: dict[str, list[str]] = {}
        self._stop_requests: set[str] = set()
        self._traversals: dict[str, _Traversal] = {}
        self._cursors: dict[str, tuple[str, int]] = {}
        self._positions: dict[tuple[str, int], str] = {}
        for receipt in retained:
            validate_cancellation_receipt(receipt)
            _require(receipt["owner"] == owner, "OWNER_EPOCH_CHANGED")
            _require(receipt["cancellation_id"] not in self._receipts, "CONFLICT")
            self._retain(receipt)

    def _retain(self, receipt: dict[str, Any]) -> None:
        identity, target = receipt["cancellation_id"], receipt["request_id"]
        self._receipts[identity] = copy.deepcopy(receipt)
        self._by_target.setdefault(target, []).append(identity)
        if receipt["decision"] == "stop-requested" and self._owner == self._custodian:
            self._stop_requests.add(target)

    def _check_custody(self, verified_custody: dict[str, Any] | None) -> None:
        """Join independently verified protected context; no descriptor authenticates itself."""
        if self._owner == self._custodian:
            _require(verified_custody is None, "CANCELLATION_CUSTODY_CHANGED")
            return
        from .history import validate_owner_custody

        _require(verified_custody is not None, "CANCELLATION_CUSTODY_REQUIRED")
        assert verified_custody is not None
        validate_owner_custody(verified_custody, expected_custodian=self._custodian)
        _require(
            verified_custody["origin"] == self._owner and verified_custody == self._custody,
            "CANCELLATION_CUSTODY_CHANGED",
        )

    def _authorize_read(
        self,
        request: dict[str, Any],
        *,
        expected_owner: dict[str, Any],
        principal: str,
        read_authorized: bool,
        verified_custody: dict[str, Any] | None,
    ) -> None:
        """Recheck current trusted receiving context, including exact custody membership."""
        _require(
            request["owner"] == self._owner
            and request["custodian"] == expected_owner == self._custodian,
            "OWNER_EPOCH_CHANGED",
        )
        validate("common.schema.json", principal, "Id")
        _require(read_authorized is True, "PERMISSION_DENIED")
        self._check_custody(verified_custody)
        custody_id = None if self._custody is None else self._custody["id"]
        _require(request["custody_id"] == custody_id, "CANCELLATION_CUSTODY_CHANGED")

    def _authorize(
        self,
        owner: dict[str, Any],
        *,
        expected_owner: dict[str, Any],
        principal: str,
        read_authorized: bool,
    ) -> None:
        _require(owner == expected_owner == self._owner == self._custodian, "OWNER_EPOCH_CHANGED")
        validate("common.schema.json", principal, "Id")
        _require(read_authorized is True, "PERMISSION_DENIED")

    @bounds(
        _bounds(
            "admit",
            "O(1) finite request/target and indexed accepted replay; O(N) for N decisions and retries",
            "Exact durable stop intent or terminal-race decision without changing target outcomes",
        )
    )
    def cancel(
        self,
        request: dict[str, Any],
        *,
        principal: str,
        expected_owner: dict[str, Any],
        read_authorized: bool,
        cancel_authorized: bool,
        target: dict[str, Any] | None,
        now: str,
        cancellation_supported: bool = True,
    ) -> dict[str, Any]:
        """Record an independently authorized decision, or replay its exact original.

        target is finite independently verified current context, never a caller
        assertion accepted on the wire. The native caller supplies read permission
        for this exact target before lookup; new cancellation permission, supported
        stopping and target state are checked only after accepted replay/conflict.
        """
        validate("cancellation.schema.json", request, "Request")
        self._authorize(
            request["owner"],
            expected_owner=expected_owner,
            principal=principal,
            read_authorized=read_authorized,
        )
        previous = self._receipts.get(request["cancellation_id"])
        if previous is not None:
            _require(_request(previous) == request, "CONFLICT")
            return copy.deepcopy(previous)
        _require(cancel_authorized is True, "PERMISSION_DENIED")
        _require(target is not None, "NOT_FOUND")
        assert target is not None
        validate("cancellation.schema.json", target, "Target")
        _require(
            target["owner"] == self._owner and target["request_id"] == request["request_id"],
            "CANCELLATION_TARGET_CHANGED",
        )
        terminal = target["state"] in _TERMINAL
        _require(terminal or cancellation_supported is True, "UNSUPPORTED_CAPABILITY")
        validate("common.schema.json", now, "Time")
        receipt = {
            "format": "deployment-ops/cancellation/v1",
            "kind": "OperationCancellationReceipt",
            **copy.deepcopy(request),
            "request_digest": digest(request),
            "authenticated_principal": principal,
            "resource": copy.deepcopy(target["resource"]),
            "decision": "already-terminal" if terminal else "stop-requested",
            "operation_id": target["operation_id"],
            "operation_generation": target["generation"],
            "operation_state": target["state"],
            "effect_certainty": target["effect_certainty"],
            "decided_at": now,
        }
        validate_cancellation_receipt(receipt, expected_request=request)
        self._retain(receipt)
        return copy.deepcopy(receipt)

    @bounds(_bounds("lookup", "O(1) indexed original receipt", "One complete retained decision"))
    def get(
        self,
        request: dict[str, Any],
        *,
        principal: str,
        expected_owner: dict[str, Any],
        read_authorized: bool,
        verified_custody: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        validate("cancellation.schema.json", request, "GetRequest")
        self._authorize_read(
            request,
            expected_owner=expected_owner,
            principal=principal,
            read_authorized=read_authorized,
            verified_custody=verified_custody,
        )
        receipt = self._receipts.get(request["cancellation_id"])
        _require(
            receipt is not None and receipt["request_id"] == request["request_id"], "NOT_FOUND"
        )
        assert receipt is not None
        return copy.deepcopy(receipt)

    @bounds(
        _bounds(
            "list",
            "O(P) each page/retry after O(1) retained extent selection; O(N + sum P) for a complete traversal",
            "Every retained decision for the exact target in its pinned append-order traversal",
        )
    )
    def page(
        self,
        request: dict[str, Any],
        *,
        principal: str,
        expected_owner: dict[str, Any],
        read_authorized: bool,
        verified_custody: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        validate("cancellation.schema.json", request, "ListRequest")
        self._authorize_read(
            request,
            expected_owner=expected_owner,
            principal=principal,
            read_authorized=read_authorized,
            verified_custody=verified_custody,
        )
        cursor = request["cursor"]
        if cursor is None:
            identity, position = str(uuid.uuid4()), 0
            traversal = _Traversal(
                principal,
                request["request_id"],
                request["limit"],
                len(self._by_target.get(request["request_id"], ())),
            )
            self._traversals[identity] = traversal
        else:
            _require(cursor in self._cursors, "RETENTION_GAP")
            identity, position = self._cursors[cursor]
            traversal = self._traversals[identity]
            _require(
                (principal, request["request_id"], request["limit"])
                == (traversal.principal, traversal.request_id, traversal.limit),
                "CANCELLATION_TRAVERSAL_CHANGED",
            )
        end = min(position + traversal.limit, traversal.extent)
        identities = self._by_target.get(traversal.request_id, ())
        items = [copy.deepcopy(self._receipts[identities[index]]) for index in range(position, end)]
        next_cursor = None
        if end < traversal.extent:
            key = (identity, end)
            if key not in self._positions:
                token = uuid.uuid4().hex
                self._positions[key] = token
                self._cursors[token] = key
            next_cursor = self._positions[key]
        result: dict[str, Any] = {
            "format": "deployment-ops/cancellation/v1",
            "kind": "OperationCancellationPage",
            "owner": copy.deepcopy(self._owner),
            "custodian": copy.deepcopy(self._custodian),
            "custody_id": None if self._custody is None else self._custody["id"],
            "request_id": traversal.request_id,
            "traversal_id": identity,
            "position": position,
            "items": items,
            "next_cursor": next_cursor,
        }
        validate_cancellation_page(
            result,
            expected_owner=self._owner,
            request_id=traversal.request_id,
            expected_custodian=self._custodian,
            custody_id=result["custody_id"],
            traversal_id=identity,
            position=position,
            limit=traversal.limit,
        )
        return result

    @bounds(
        _bounds("snapshot", "O(N) complete finite retained decisions", "Every accepted identity")
    )
    def snapshot(self) -> list[dict[str, Any]]:
        """Export complete protected reference state; not a public read endpoint."""
        return [copy.deepcopy(value) for value in self._receipts.values()]

    def stop_requested(self, request_id: str) -> bool:
        """Inspect retained owner intent internally, never infer current execution state."""
        return request_id in self._stop_requests

    def expire_traversals(self) -> None:
        """Drop only optional read traversal custody, never decisions or stop intents."""
        self._traversals.clear()
        self._cursors.clear()
        self._positions.clear()
