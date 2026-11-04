"""In-memory submission reference. No files, tracker clients, SQLite or network implementation.

An injected owner transport represents a separately authorized SSH call in tests.
This is a contract model, not the production client or a general exactly-once engine.
"""

from __future__ import annotations

import copy
import uuid
from collections.abc import Callable
from typing import Any

from fishhat_contracts.operations import (
    operation_matches_delivery,
    validate_operation,
    validate_submission_refusal,
)
from fishhat_contracts.validation import ContractError, validate


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
    or quarantined work, or verified nonacceptance of the exact request.
    Exit 8 means acceptance is unknown, never rejected or safe to submit anew.

    The injected transport must authenticate the owner, correlate the SSH reply to
    its exact submitted message and verify its evidence. An authenticated refusal
    proves the owner closed this unaccepted identity. All other errors are ambiguous.
    This model checks the decoded Operation's shape and exact delivery bindings;
    those checks are not authentication or native execution qualification.
    """
    validate("client-records.schema.json", delivery, "Delivery")
    if delivery["state"] != "prepared":
        raise ContractError("new submission needs prepared identity; reconcile unknown work")
    params = {**copy.deepcopy(delivery), "state": "acceptance_unknown"}
    return _resolve(delivery, owner_transport, params, "operation.submit")


def reconcile_delivery(
    delivery: dict[str, Any], owner_lookup: Callable[[dict[str, Any]], object]
) -> dict[str, Any]:
    """Resolve uncertain delivery through an authenticated, read-only operation.get.

    The transport sends only lookup params and verifies the reply's owner and message
    correlation. Missing decisions and unavailable reads preserve the original identity.
    """
    validate("client-records.schema.json", delivery, "Delivery")
    if delivery["state"] != "acceptance_unknown":
        raise ContractError("lookup requires an uncertain delivery")
    params = {"owner": copy.deepcopy(delivery["owner"]), "request_id": delivery["request_id"]}
    return _resolve(delivery, owner_lookup, params, "operation.get")


def _resolve(
    delivery: dict[str, Any],
    transport: Callable[[dict[str, Any]], object],
    params: dict[str, Any],
    method: str,
) -> dict[str, Any]:
    value = copy.deepcopy(delivery)
    value["state"] = "acceptance_unknown"
    unknown = {
        "exit_code": 8,
        "delivery": value,
        "owner_receipt": None,
        "tracking": "not-attempted",
    }
    try:
        receipt = transport(params)
    except (OSError, ContractError):
        # SSH I/O, authentication or response verification failed at the transport.
        return unknown
    if not isinstance(receipt, dict):
        return unknown
    if "nonacceptance" in receipt:
        if receipt.get("method") != method:
            return unknown
        try:
            validate("ssh-response.schema.json", receipt)
            validate_submission_refusal(receipt["nonacceptance"], receipt["problem"], value)
        except ContractError:
            return unknown
        value["state"] = "rejected"
        return {
            "exit_code": 1,
            "delivery": value,
            "owner_receipt": None,
            "refusal": copy.deepcopy(receipt["nonacceptance"]),
            "problem": copy.deepcopy(receipt["problem"]),
            "tracking": "not-attempted",
        }
    try:
        validate_operation(receipt)
    except ContractError:
        return unknown
    if not operation_matches_delivery(receipt, value):
        return unknown
    value["state"] = "accepted"
    return {
        "exit_code": 1 if receipt["state"] in ("failed", "cancelled", "quarantined") else 0,
        "delivery": value,
        "owner_receipt": copy.deepcopy(receipt),
        "tracking": "not-attempted",
    }
