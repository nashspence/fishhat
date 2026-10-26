"""Complete staged Plan inputs and immutable lookups, without native admission.

The owner independently authenticates and authorizes each request before using
these checks. Neither a content handle nor this decoded model supplies authority,
retention, a native planning effect or a permission to apply a Plan.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .handoffs import validate_staged_input
from .validation import ContractError, canonical, strict_json, validate, validate_plan


def decode_plan_input(
    reference: dict[str, Any],
    data: bytes,
    *,
    expected_owner: dict[str, Any],
    capacity_bytes: int | None = None,
) -> dict[str, Any]:
    """Decode one complete input; the frame size never becomes its extent cap."""
    validate("plan-input.schema.json", reference, "InputReference")
    handle = reference["input"]
    if reference["owner"] != expected_owner or handle["owner"] != expected_owner:
        raise ContractError("plan input owner epoch mismatch")
    if capacity_bytes is not None and (type(capacity_bytes) is not int or capacity_bytes < 1):
        raise ContractError("invalid plan input capacity")
    if not (
        len(data) == handle["size"]
        and "sha256:" + hashlib.sha256(data).hexdigest() == handle["digest"]
    ):
        raise ContractError("plan input content identity mismatch")
    payload = strict_json(data, max_bytes=len(data) if capacity_bytes is None else capacity_bytes)
    validate("plan-input.schema.json", payload, "PrepareRequest")
    if payload["owner"] != expected_owner or canonical(payload) != data:
        raise ContractError("plan input owner or canonical encoding mismatch")
    return dict(payload)


def validate_plan_input_custody(
    reference: dict[str, Any],
    payload: dict[str, Any],
    staging: dict[str, Any],
    *,
    expected_owner: dict[str, Any],
    principal: str,
    now: str,
) -> None:
    """Join exact decoded input to independently loaded current staging custody."""
    decode_plan_input(reference, canonical(payload), expected_owner=expected_owner)
    validate_staged_input(
        staging,
        reference["input"],
        expected_owner=expected_owner,
        principal=principal,
        resource=payload["subject"]["resource"],
        purpose="plan-input",
        now=now,
    )


def validate_plan_lookup(
    plan: dict[str, Any], request: dict[str, Any], *, expected_owner: dict[str, Any]
) -> None:
    """Check an authorized read against the exact independently retained query.

    Expiry forbids new admission, not reading the original reviewed Plan for an
    accepted Operation. Historical epochs use the separate custody/read routes.
    """
    validate("plan-input.schema.json", request, "LookupRequest")
    validate_plan(plan)
    if not (
        request["owner"] == plan["owner"] == expected_owner
        and request["plan_digest"] == plan["digest"]
    ):
        raise ContractError("Plan lookup owner or identity mismatch")
