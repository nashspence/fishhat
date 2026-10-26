"""One decoded Operation integrity boundary, separate from native authority.

Schema and relationship checks do not authenticate signatures, grant permission,
establish freshness or verify native effects. Receiving transports independently
provide those checks before treating a decoded record as owner evidence.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

from .validation import SCHEMAS, ContractError, validate, validate_plan


def validate_operation(operation: dict[str, Any]) -> None:
    """Validate every current Operation representation through the same joins."""
    from .handoffs import ACTIONS, schema_identity

    validate("records.schema.json", operation, "Operation")
    if operation["witness"]["owner"] != operation["owner"]:
        raise ContractError("operation witness owner epoch mismatch")
    # Also declared in the schema so shape-only wire readers cannot accept it.
    if operation["state"] == "succeeded" and operation["effect_certainty"] != "known":
        raise ContractError("successful operation has unverified effects")
    result = operation["result_handle"]
    if result is None:
        return
    spec = ACTIONS[operation["subject"]["action"]]["result"]
    if spec["mode"] == "receipt-only":
        raise ContractError("action declares no result payload")
    handle = result["handle"]
    if not (
        handle["owner"] == operation["owner"]
        and handle["binding"] == {"kind": "operation", "operation_id": operation["id"]}
    ):
        raise ContractError("result handle operation binding mismatch")
    if spec["mode"] == "schema":
        uri = urljoin(SCHEMAS["records.schema.json"]["$id"], spec["schema"]["$ref"])
        expected = schema_identity(uri)
    else:
        expected = operation["subject"]["arguments"][spec["subject_field"]]
    if result["schema"] != expected:
        raise ContractError("action result schema substitution")


def operation_plan_request(operation: dict[str, Any]) -> dict[str, Any]:
    """Recover the exact immutable Plan lookup from owner-discovered work."""
    validate_operation(operation)
    return {
        "owner": dict(operation["owner"]),
        "plan_digest": operation["plan_digest"],
    }


def validate_operation_plan(operation: dict[str, Any], plan: dict[str, Any]) -> None:
    """Check retained review identity without reapplying admission expiry."""
    validate_operation(operation)
    validate_plan(plan)
    if not (
        plan["owner"] == operation["owner"]
        and plan["digest"] == operation["plan_digest"]
        and plan["subject"] == operation["subject"]
    ):
        raise ContractError("accepted operation Plan identity mismatch")
