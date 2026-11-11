"""Owner queue input and record joins, without native custody or authorization.

The receiving host independently loads current policy, work context and earlier
custody. These pure checks do not accept an Operation, allocate capacity, commit a
queue transition, authorize a principal or release a hold.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from typing import Any

from .bounds import Bounds, bounds
from .resource_admission import (
    check_scheduler_request,
    check_scheduler_response,
    validate_resource_request,
)
from .validation import ContractError, canonical, digest, strict_json, validate

_SCHEMA = "resource-queue.schema.json"
_METHODS = {"resources.admission." + verb for verb in ("submit", "get", "list", "cancel")}


def _bounds(name: str) -> Bounds:
    return Bounds(
        id="resource_queue." + name,
        work="O(B) complete selected input, record, previous facts and bounded page bytes",
        extent="Complete staged ResourceRequest and retained evidence; pages never cap total custody",
        limits=(
            (("references per page with explicit continuation", 64),)
            if name in {"validate_admission_page", "validate_admission_response"}
            else ()
        ),
        capacity=(
            "Receiving owner memory; native queue persistence and authorization are not implemented",
        ),
        proofs=("tests/test_resource_queue.py::test_resource_queue_boundaries",),
        linear_proofs=("tests/test_resource_queue.py::test_resource_queue_linear_work",),
    )


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


@bounds(_bounds("decode_admission_input"))
def decode_admission_input(
    reference: dict[str, Any],
    data: bytes,
    *,
    expected_owner: dict[str, Any],
    policy: dict[str, Any],
    context: dict[str, Any],
    capacity_bytes: int | None = None,
) -> dict[str, Any]:
    """Decode complete new input against independent current host/work context.

    An owner resolves authorized retained replay before calling this new-input
    path. The original queue request is not readmitted after staging expiry.
    """
    validate(_SCHEMA, reference, "InputReference")
    handle = reference["input"]
    _require(
        reference["owner"] == handle["owner"] == expected_owner
        and expected_owner["tool"] == "host-ops",
        "RESOURCE_QUEUE_OWNER",
    )
    _require(
        capacity_bytes is None or (type(capacity_bytes) is int and capacity_bytes > 0),
        "RESOURCE_QUEUE_CAPACITY",
    )
    _require(
        len(data) == handle["size"]
        and "sha256:" + hashlib.sha256(data).hexdigest() == handle["digest"],
        "RESOURCE_QUEUE_INPUT_IDENTITY",
    )
    payload = strict_json(data, max_bytes=len(data) if capacity_bytes is None else capacity_bytes)
    validate_resource_request(payload, policy=policy, context=context)
    _require(
        canonical(payload) == data
        and payload["id"] == reference["request_id"]
        and payload["domain"]["owner"] == expected_owner,
        "RESOURCE_QUEUE_INPUT_IDENTITY",
    )
    return dict(payload)


@bounds(_bounds("validate_admission_input_custody"))
def validate_admission_input_custody(
    reference: dict[str, Any],
    payload: dict[str, Any],
    staging: dict[str, Any],
    *,
    expected_owner: dict[str, Any],
    policy: dict[str, Any],
    context: dict[str, Any],
    principal: str,
    now: str,
) -> None:
    """Join new input to independently retained staging; never authenticate a caller."""
    from .handoffs import validate_staged_input

    decode_admission_input(
        reference,
        canonical(payload),
        expected_owner=expected_owner,
        policy=policy,
        context=context,
    )
    validate_staged_input(
        staging,
        reference["input"],
        expected_owner=expected_owner,
        principal=principal,
        resource={"kind": "host", "id": payload["domain"]["host"]},
        purpose="resource-admission",
        now=now,
    )


def _query(resource: dict[str, Any], retained: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "contract": "fishhat.scheduler",
        "method": "observe",
        "input": {
            "scope": resource["domain"]["scheduler"]["scope"],
            "request": resource,
            "submission": None if retained is None else retained["submission"],
            "grant": None if retained is None else retained["grant"],
        },
    }


def _observation(
    resource: dict[str, Any],
    observation: dict[str, Any],
    retained: dict[str, Any] | None = None,
) -> None:
    query = _query(resource, retained)
    check_scheduler_request(query)
    check_scheduler_response(
        query,
        {
            "coverage": "unknown" if observation["state"] == "unknown" else "complete",
            "continuation": None,
            "output": {"observation": observation},
        },
    )


@bounds(_bounds("validate_admission_record"))
def validate_admission_record(
    record: dict[str, Any],
    *,
    previous: dict[str, Any] | None = None,
    expected_request: dict[str, Any] | None = None,
    expected_target: dict[str, Any] | None = None,
) -> None:
    """Preserve exact request custody and known facts across unknown observations.

    Expectations are independently loaded owner custody, never values selected
    by the new record. A cancellation command requires its retained resource
    target; a context-free reader checks shape only. A native writer still needs
    current exclusion, expected-generation comparison and a durable commit.
    """
    kind = record.get("kind")
    _require(kind in {"ResourceAdmission", "ResourceAdmissionCancellation"}, "RESOURCE_QUEUE_KIND")
    validate(_SCHEMA, record, "Record" if kind == "ResourceAdmission" else "CancellationReceipt")
    if kind == "ResourceAdmissionCancellation":
        if expected_request is not None:
            validate(_SCHEMA, expected_request, "CancelRequest")
            _require(expected_target is not None, "RESOURCE_QUEUE_CANCELLATION_TARGET_REQUIRED")
            _require(
                record["owner"] == expected_request["owner"]
                and record["id"] == expected_request["cancellation_id"]
                and record["request_id"] == expected_request["request_id"]
                and record["request_digest"] == expected_request["request_digest"],
                "RESOURCE_QUEUE_CANCELLATION_IDENTITY",
            )
        if expected_target is not None:
            check_scheduler_request(_query(expected_target, None))
            _require(
                record["request_id"] == expected_target["id"]
                and record["request_digest"] == digest(expected_target)
                and record["owner"] == expected_target["domain"]["owner"]
                and record["resource"] == {"kind": "host", "id": expected_target["domain"]["host"]},
                "RESOURCE_QUEUE_CANCELLATION_TARGET",
            )
        _require(previous is None or record == previous, "RESOURCE_QUEUE_CANCELLATION_CHANGED")
        return
    resource = record["request"]
    check_scheduler_request(_query(resource, None))
    _require(
        record["id"] == resource["id"]
        and record["owner"] == resource["domain"]["owner"]
        and record["resource"] == {"kind": "host", "id": resource["domain"]["host"]},
        "RESOURCE_QUEUE_RECORD_IDENTITY",
    )
    _require(
        expected_request is None or resource == expected_request,
        "RESOURCE_QUEUE_REQUEST_CHANGED",
    )
    known, latest = record["last_known"], record["observation"]
    if known is not None:
        _require(known["state"] != "unknown", "RESOURCE_QUEUE_KNOWN_STATE")
        _observation(resource, known)
        _require(
            known["state"] not in {"released", "cancelled", "rejected", "stop-requested"}
            or record["eligibility"] == "closed",
            "RESOURCE_QUEUE_CLOSED_LAUNCH",
        )
    if latest is not None:
        _observation(resource, latest, known)
        _require(
            latest["state"] == "unknown" or latest == known,
            "RESOURCE_QUEUE_KNOWN_STATE_CHANGED",
        )
    if previous is None:
        return
    validate_admission_record(previous)
    _require(
        previous["kind"] == "ResourceAdmission"
        and all(record[key] == previous[key] for key in ("id", "owner", "resource", "request")),
        "RESOURCE_QUEUE_REQUEST_CHANGED",
    )
    _require(
        record == previous or record["generation"] > previous["generation"],
        "RESOURCE_QUEUE_GENERATION",
    )
    _require(
        previous["eligibility"] != "closed" or record["eligibility"] == "closed",
        "RESOURCE_QUEUE_REOPENED",
    )
    _require(
        previous["eligibility"] != "review-required"
        or record["eligibility"] in {"review-required", "closed"},
        "RESOURCE_QUEUE_UNREVIEWED_READMISSION",
    )
    prior = previous["last_known"]
    if latest is None or latest["state"] == "unknown":
        _require(known == prior, "RESOURCE_QUEUE_KNOWN_FACTS_LOST")
    elif prior is not None:
        _observation(resource, latest, prior)
        if prior["state"] in {"released", "cancelled", "rejected"}:
            _require(known == prior, "RESOURCE_QUEUE_TERMINAL_FACTS_CHANGED")


@bounds(_bounds("validate_admission_page"))
def validate_admission_page(
    page: dict[str, Any],
    *,
    request: dict[str, Any] | None = None,
    retained_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Check a bounded page against the original selection; no native completeness claim."""
    from .record_delivery import validate_record_reference

    validate(_SCHEMA, page, "Page")
    selection = page["request"]
    _require(request is None or selection == request, "RESOURCE_QUEUE_PAGE_REQUEST")
    _require(len(page["items"]) <= selection["limit"], "RESOURCE_QUEUE_PAGE_LIMIT")
    identities: set[str] = set()
    for item in page["items"]:
        validate_record_reference(
            item,
            expected_owner=selection["owner"],
            expected_resource=selection["resource"],
            retained_readers=retained_readers,
        )
        identity = item["record"]
        _require(
            identity["kind"] == selection["record_kind"] and identity["id"] not in identities,
            "RESOURCE_QUEUE_PAGE_IDENTITY",
        )
        identities.add(identity["id"])


@bounds(_bounds("validate_admission_response"))
def validate_admission_response(
    request: dict[str, Any],
    response: dict[str, Any],
    *,
    expected_owner: dict[str, Any],
    retained_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Join a typed owner response to the exact independently retained wire request."""
    from .record_delivery import validate_record_reference

    validate("ssh-request.schema.json", request)
    validate("ssh-response.schema.json", response)
    method, params = request["method"], request["params"]
    _require(
        method in _METHODS
        and expected_owner["tool"] == "host-ops"
        and params["owner"] == expected_owner
        and response["method"] == method
        and response["message_id"] == request["message_id"],
        "RESOURCE_QUEUE_RESPONSE_IDENTITY",
    )
    if not response["ok"]:
        return
    result = response["result"]
    if method == "resources.admission.list":
        validate_admission_page(result, request=params, retained_readers=retained_readers)
        return
    if method == "resources.admission.submit":
        kind, identity = "ResourceAdmission", params["request_id"]
    elif method == "resources.admission.cancel":
        kind, identity = "ResourceAdmissionCancellation", params["cancellation_id"]
    else:
        kind, identity = params["record_kind"], params["id"]
    validate_record_reference(
        result, expected_owner=expected_owner, retained_readers=retained_readers
    )
    _require(
        result["record"]["kind"] == kind and result["record"]["id"] == identity,
        "RESOURCE_QUEUE_RESPONSE_RECORD",
    )
