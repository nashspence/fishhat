"""In-memory submission reference. No files, tracker clients, SQLite or network implementation.

An injected owner transport represents a separately authorized SSH call in tests.
This is a contract model, not the production client or a general exactly-once engine.
"""

from __future__ import annotations

import copy
import uuid
from collections.abc import Callable
from typing import Any

from fishhat_contracts.operations import validate_operation
from fishhat_contracts.validation import ContractError, digest, validate


def prepare_delivery(template: dict[str, Any], request_id: str | None = None) -> dict[str, Any]:
    value = copy.deepcopy(template)
    value["request_id"] = request_id or str(uuid.uuid4())
    value["state"] = "prepared"  # in-memory identity; no reservation or persistence claim
    validate("client-records.schema.json", value, "Delivery")
    return value


def submit_once(
    delivery: dict[str, Any], owner_transport: Callable[[dict[str, Any]], object]
) -> dict[str, Any]:
    """Submit once and keep acceptance separate from the owner's execution result.

    Exit 0 means the owner accepted the request or reported success, not that
    accepted/running/waiting work is complete. Exit 1 reports failed, cancelled
    or quarantined work; retained effects and holds still belong to the owner.
    Exit 8 means acceptance is unknown, never rejected or safe to submit anew.

    The injected transport must authenticate the owner and verify its evidence.
    This model checks the decoded Operation's shape and exact delivery bindings;
    those checks are not authentication or native execution qualification.
    """
    validate("client-records.schema.json", delivery, "Delivery")
    value = copy.deepcopy(delivery)
    if value["state"] != "prepared":
        raise ContractError("new submission needs prepared identity; reconcile unknown work")
    value["state"] = "acceptance_unknown"
    unknown = {
        "exit_code": 8,
        "delivery": value,
        "owner_receipt": None,
        "tracking": "not-attempted",
    }
    try:
        receipt = owner_transport(copy.deepcopy(value))
    except (TimeoutError, ConnectionError):
        return unknown
    if not isinstance(receipt, dict):
        return unknown
    try:
        validate_operation(receipt)
    except ContractError:
        return unknown
    bindings = (
        receipt["request_id"] == value["request_id"],
        receipt["owner"] == value["owner"],
        receipt["plan_digest"] == value["plan_digest"],
        digest(receipt["subject"]) == value["subject_digest"],
        receipt["subject"]["action"] == value["action"],
        receipt["subject"]["resource"] == value["resource"],
    )
    if not all(bindings):
        return unknown
    value["state"] = "accepted"
    return {
        "exit_code": 1 if receipt["state"] in ("failed", "cancelled", "quarantined") else 0,
        "delivery": value,
        "owner_receipt": copy.deepcopy(receipt),
        "tracking": "not-attempted",
    }
