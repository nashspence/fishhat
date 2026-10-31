"""Read-only historical custody joins; no native restore, authentication or execution.

The receiving owner supplies verified restoration custody and current scoped
authorization independently of the request. Original record bytes never acquire
new execution authority merely because a current custodian can read them.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable, Mapping
from typing import Any

from .record_delivery import (
    validate_record_chunk,
    validate_record_payload,
    validate_record_reference,
)
from .validation import ContractError, canonical, digest, validate, validate_plan

REQUESTS = {
    "owner.history": "HistoryRequest",
    "history.list": "ListRequest",
    "history.read": "ReadRequest",
    "history.content": "ContentRequest",
}
RESULTS = {
    "OwnerHistoryPage": "owner.history",
    "HistoricalRecordPage": "history.list",
    "HistoricalRecordChunk": "history.read",
    "HistoricalContentChunk": "history.content",
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _epochs(custodian: dict[str, Any], origin: dict[str, Any]) -> None:
    _require(
        all(custodian[key] == origin[key] for key in ("tool", "id"))
        and custodian["epoch"] != origin["epoch"],
        "historical custody owner or epoch mismatch",
    )


def validate_owner_custody(
    custody: dict[str, Any], *, expected_custodian: dict[str, Any] | None = None
) -> None:
    """Check descriptor integrity only; the descriptor cannot prove its own authenticity."""
    validate("owner-history.schema.json", custody, "OwnerCustody")
    _epochs(custody["custodian"], custody["origin"])
    _require(
        custody["digest"] == digest({k: v for k, v in custody.items() if k != "digest"}),
        "historical custody digest mismatch",
    )
    if expected_custodian is not None:
        _require(custody["custodian"] == expected_custodian, "current custodian changed")


def authorize_history_request(
    method: str,
    request: dict[str, Any],
    *,
    current_owner: dict[str, Any],
    read_authorized: bool,
    verified_custody: dict[str, Any] | None,
) -> None:
    """Join protected receiving context to one exact read, without implementing that context.

    read_authorized is the owner's current decision for the actual principal,
    exact request and protected record/handle resource, including custody
    membership and continuation scope. It is not a wire field. verified_custody
    comes from the independently verified local restoration manifest, never from
    trusting a caller-supplied descriptor or its digest. Revocation applies to
    each read. This helper supplies no authentication or native membership proof.
    """
    _require(method in REQUESTS, "historical route is not read-only")
    validate("owner-history.schema.json", request, REQUESTS[method])
    validate("common.schema.json", current_owner, "Owner")
    _require(read_authorized is True, "current historical read permission required")
    _require(request["custodian"] == current_owner, "current custodian changed")
    if method == "owner.history":
        _require(verified_custody is None, "epoch discovery does not select prior custody")
        return
    _require(verified_custody is not None, "independent historical custody required")
    assert verified_custody is not None
    validate_owner_custody(verified_custody, expected_custodian=current_owner)
    _require(request["custody_id"] == verified_custody["id"], "historical custody substitution")
    if method in ("history.read", "history.content"):
        material = request["reference"] if method == "history.read" else request["handle"]
        _require(
            material["owner"] == verified_custody["origin"], "historical material origin changed"
        )
        _require(request["offset"] <= material["size"], "historical range outside material")


def validate_history_result(
    result: dict[str, Any],
    *,
    expected_request: dict[str, Any] | None = None,
    verified_custody: dict[str, Any] | None = None,
    retained_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Check immutable read correlations, not permission to read or execute.

    Independent expected_request and verified_custody establish response identity.
    Without them, this checks internal shape and joins only. A native caller must
    separately use current receiving authority before disclosing any material.
    """
    kind = result.get("kind")
    _require(kind in RESULTS, "unsupported historical result")
    validate("owner-history.schema.json", result, kind)
    request = result["request"]
    if expected_request is not None:
        _require(request == expected_request, "historical response request substitution")
    if kind == "OwnerHistoryPage":
        origins: set[bytes] = set()
        identities: set[str] = set()
        for item in result["items"]:
            validate_owner_custody(item, expected_custodian=request["custodian"])
            origin = canonical(item["origin"])
            _require(
                origin not in origins and item["id"] not in identities,
                "duplicate historical custody",
            )
            origins.add(origin)
            identities.add(item["id"])
    else:
        _epochs(request["custodian"], result["origin"])
        if verified_custody is not None:
            validate_owner_custody(verified_custody, expected_custodian=request["custodian"])
            _require(
                request["custody_id"] == verified_custody["id"]
                and result["origin"] == verified_custody["origin"],
                "historical response custody substitution",
            )
        if kind == "HistoricalRecordPage":
            records: set[bytes] = set()
            snapshots: set[str] = set()
            for item in result["items"]:
                validate_record_reference(
                    item, expected_owner=result["origin"], retained_readers=retained_readers
                )
                _require(
                    item["record"]["kind"] == request["record_kind"],
                    "historical record kind substitution",
                )
                if (
                    request["record_kind"] in {"WorkflowTransferRecord", "WorkflowPhaseAttestation"}
                    and request["resource"] is not None
                ):
                    _require(
                        item["record"]["resource"] == request["resource"],
                        "historical workflow resource substitution",
                    )
                identity = canonical(
                    [
                        item["record"]["kind"],
                        item["record"]["id"],
                        item["record"].get("resource"),
                    ]
                )
                _require(
                    identity not in records and item["snapshot_id"] not in snapshots,
                    "duplicate historical record",
                )
                records.add(identity)
                snapshots.add(item["snapshot_id"])
        elif kind == "HistoricalRecordChunk":
            reference = request["reference"]
            validate_record_reference(
                reference, expected_owner=result["origin"], retained_readers=retained_readers
            )
            validate_record_chunk(
                result["chunk"], reference, offset=request["offset"], length=request["length"]
            )
        else:
            handle = request["handle"]
            _require(handle["owner"] == result["origin"], "historical content origin changed")
            try:
                data = base64.b64decode(result["base64"], validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ContractError("invalid historical content encoding") from exc
            end = request["offset"] + len(data)
            _require(
                request["offset"] <= handle["size"]
                and len(data) <= request["length"]
                and end <= handle["size"]
                and result["next_offset"] == end,
                "historical content range mismatch",
            )
            _require(
                result["complete"] == (end == handle["size"]), "historical completion mismatch"
            )
            _require(bool(data) or result["complete"], "historical content made no progress")
    if kind in ("OwnerHistoryPage", "HistoricalRecordPage"):
        _require(len(result["items"]) <= request["limit"], "historical page exceeds request limit")
        _require(
            result["next_cursor"] is None or result["next_cursor"] != request["cursor"],
            "historical continuation made no progress",
        )


def validate_recovery_plan_origin(plan: dict[str, Any]) -> None:
    """Check historical recovery provenance already covered by the complete Plan digest."""
    subject = plan["subject"]
    if subject["action"] not in ("app.recover", "host.recover", "operation.recover"):
        return
    origin = subject["arguments"]["origin"]
    if origin is None:
        return
    reference = origin["reference"]
    _epochs(plan["owner"], reference["owner"])
    _require(
        reference["record"]["id"] == subject["arguments"]["operation_id"],
        "historical recovery operation substitution",
    )
    expected_action = "app.recover" if plan["owner"]["tool"] == "app-ops" else "host.recover"
    _require(
        subject["action"] in {expected_action, "operation.recover"},
        "historical recovery owner tool mismatch",
    )


def validate_historical_recovery(
    plan: dict[str, Any],
    operation_bytes: bytes,
    *,
    current_owner: dict[str, Any],
    current_generation: int,
    verified_custody: dict[str, Any],
    verified_reference: dict[str, Any],
    recovery_authorized: bool,
    retained_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> dict[str, Any]:
    """Join a newly reviewed recovery Plan to unchanged original accepted work.

    Native admission must retain the verified original input and hold closure,
    fence former executors, reconcile uncertain outcomes and admit a new recovery
    operation under current authority. This model performs none of those effects.
    A read grant cannot be supplied as recovery_authorized; that is a separate
    protected decision for the actual principal and exact new Plan.
    verified_reference is independently selected from the verified restoration
    manifest as the latest retained authoritative Operation snapshot, including
    every confirmed outcome and unresolved hold. A caller cannot select an older
    valid member to erase later accepted work, or authenticate its own bytes.
    """
    validate_plan(plan)
    _require(recovery_authorized is True, "current recovery permission required")
    _require(plan["owner"] == current_owner, "historical recovery needs current owner")
    validate_owner_custody(verified_custody, expected_custodian=current_owner)
    _require(
        plan["subject"]["action"] in ("app.recover", "host.recover", "operation.recover"),
        "historical recovery requires a recovery action",
    )
    origin = plan["subject"]["arguments"]["origin"]
    _require(origin is not None, "historical recovery origin required")
    _require(origin["custody_id"] == verified_custody["id"], "historical recovery custody changed")
    reference = origin["reference"]
    _require(reference == verified_reference, "historical recovery authoritative record changed")
    original = validate_record_payload(
        reference,
        operation_bytes,
        expected_owner=verified_custody["origin"],
        retained_readers=retained_readers,
    )
    _require(
        original["subject"]["resource"] == plan["subject"]["resource"],
        "historical recovery resource substitution",
    )
    _require(
        type(current_generation) is int and current_generation >= 0, "invalid current generation"
    )
    local = next(
        item
        for item in plan["preconditions"]
        if item["owner"] == current_owner and item["resource"] == plan["subject"]["resource"]
    )
    _require(local["generation"] == current_generation, "historical recovery generation changed")
    _require(plan["digest"] != original["plan_digest"], "historical recovery requires a fresh Plan")
    return original
