"""One decoded Operation integrity boundary, separate from native authority.

Schema and relationship checks do not authenticate signatures, grant permission,
establish freshness or verify native effects. Receiving transports independently
provide those checks before treating a decoded record as owner evidence.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urljoin

from .validation import SCHEMAS, ContractError, digest, validate, validate_plan


def validate_operation(
    operation: dict[str, Any],
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Validate exact snapshot joins and independently installed result compatibility.

    A qualified recovery reader is trusted receiving context for an exact URI and
    schema closure, never a claim embedded in the record. Its payload checks must
    also run on the complete result bytes before use. This check grants neither
    new execution authority nor permission to change an accepted result.
    """
    from .handoffs import ACTIONS, schema_identity

    validate("records.schema.json", operation, "Operation")
    witness = operation["witness"]
    if witness["owner"] != operation["owner"]:
        raise ContractError("operation witness owner epoch mismatch")
    # Also declared in the schema so shape-only wire readers cannot accept it.
    if operation["state"] == "succeeded" and operation["effect_certainty"] != "known":
        raise ContractError("successful operation has unverified effects")
    if not (
        witness["subject_digest"]
        == digest({key: value for key, value in operation.items() if key != "witness"})
        and witness["state"] == operation["state"]
        and witness["generation"] == operation["generation"]
        and witness["kind"] == ("acceptance" if operation["state"] == "accepted" else "effect")
    ):
        raise ContractError("operation witness snapshot mismatch")
    result = operation["result_handle"]
    spec = ACTIONS[operation["subject"]["action"]]["result"]
    if result is None:
        if operation["state"] == "succeeded" and spec.get("required_on_success", False):
            raise ContractError("successful operation lacks its required retained result")
        return
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
        result_schema = result["schema"]
        if (
            result_schema["uri"] == uri
            and recovery_readers is not None
            and (uri, result_schema["digest"]) in recovery_readers
        ):
            return
    else:
        expected = operation["subject"]["arguments"][spec["subject_field"]]
    if result["schema"] != expected:
        raise ContractError("action result schema substitution")


def operation_plan_request(
    operation: dict[str, Any],
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> dict[str, Any]:
    """Recover the exact immutable Plan lookup from owner-discovered work."""
    validate_operation(operation, recovery_readers=recovery_readers)
    return {
        "owner": dict(operation["owner"]),
        "plan_digest": operation["plan_digest"],
    }


def validate_operation_plan(
    operation: dict[str, Any],
    plan: dict[str, Any],
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Check retained review identity without reapplying admission expiry."""
    validate_operation(operation, recovery_readers=recovery_readers)
    validate_plan(plan)
    if not (
        plan["owner"] == operation["owner"]
        and plan["digest"] == operation["plan_digest"]
        and plan["subject"] == operation["subject"]
    ):
        raise ContractError("accepted operation Plan identity mismatch")
