"""Pure owner handoff checks; no transport, staging store, authorization or effects.

Trusted receiver context and installed schemas are supplied explicitly. These checks
make record relationships testable without claiming native custody or authentication.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any
from urllib.parse import unquote, urldefrag, urljoin

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from .validation import (
    FORMAT_CHECKER,
    MAX_BYTES,
    ROOT,
    SCHEMAS,
    ContractError,
    canonical,
    digest,
    strict_json,
    validate,
)

ACTIONS = {
    action["name"]: action
    for action in json.loads((ROOT / "contracts/actions.json").read_text())["actions"]
}
PHASES = json.loads((ROOT / "contracts/states.json").read_text())["workflow_phases"]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _schema_documents(
    uri: str, installed: dict[str, dict[str, Any]] | None = None
) -> dict[str, dict[str, Any]]:
    available = {schema["$id"]: schema for schema in SCHEMAS.values()}
    if installed is not None:
        for identity, schema in installed.items():
            _require(schema.get("$id") == identity, "installed schema identity mismatch")
            _require(identity not in available, "installed schema replaces core contract")
            available[identity] = schema
    found: dict[str, dict[str, Any]] = {}
    pending = [urldefrag(uri)[0]]
    targets = [uri]

    def references(value: Any, base: str, *, root: bool = False) -> None:
        if isinstance(value, dict):
            _require(
                "$dynamicRef" not in value and "$recursiveRef" not in value,
                "result schemas require static local references",
            )
            _require("$id" not in value or root, "nested result schema identity")
            if "$ref" in value:
                target = urljoin(base, value["$ref"])
                targets.append(target)
                pending.append(urldefrag(target)[0])
            for key in (
                "additionalProperties",
                "unevaluatedProperties",
                "items",
                "contains",
                "propertyNames",
                "not",
                "if",
                "then",
                "else",
                "contentSchema",
                "unevaluatedItems",
            ):
                if key in value:
                    references(value[key], base)
            for key in (
                "properties",
                "patternProperties",
                "$defs",
                "definitions",
                "dependentSchemas",
            ):
                for child in value.get(key, {}).values():
                    references(child, base)
            for key in ("allOf", "anyOf", "oneOf", "prefixItems"):
                for child in value.get(key, []):
                    references(child, base)

    while pending:
        identity = pending.pop()
        if identity in found:
            continue
        _require(identity in available, "result schema is not installed")
        schema = available[identity]
        found[identity] = schema
        references(schema, identity, root=True)
    for target in targets:
        identity, fragment = urldefrag(target)
        node: Any = found[identity]
        if fragment:
            _require(fragment.startswith("/"), "result schema requires JSON pointer fragments")
            try:
                for part in fragment[1:].split("/"):
                    key = unquote(part).replace("~1", "/").replace("~0", "~")
                    node = node[int(key)] if isinstance(node, list) else node[key]
            except (KeyError, ValueError, IndexError, TypeError) as exc:
                raise ContractError("result schema reference is unresolved") from exc
        _require(isinstance(node, (dict, bool)), "result reference is not a schema")
    return found


def schema_identity(uri: str, installed: dict[str, dict[str, Any]] | None = None) -> dict[str, str]:
    """Pin the complete installed document closure; URI resolution never uses a network."""
    documents = _schema_documents(uri, installed)
    return {"uri": uri, "digest": digest({"root": uri, "documents": documents})}


def validate_workflow(value: dict[str, Any]) -> None:
    from .transfers import validate_workflow_transfer
    from .workflows import validate_workflow_proposal_binding

    validate("records.schema.json", value, "Workflow")
    validate_workflow_proposal_binding(value)
    _require(value["phase"] in PHASES[value["type"]], "workflow phase outside installed procedure")
    if value["state"] == "completed":
        _require(value["phase"] == PHASES[value["type"]][-1], "workflow completion phase mismatch")
    pairs: set[bytes] = set()
    requests: set[bytes] = set()
    local = False
    for participant in value["participants"]:
        pair = canonical([participant["owner"], participant["resource"]])
        _require(pair not in pairs, "duplicate workflow participant")
        pairs.add(pair)
        local = local or participant["owner"] == value["owner"]
        for request_id in participant["request_ids"]:
            identity = canonical([participant["owner"], request_id])
            _require(identity not in requests, "duplicate participant request identity")
            requests.add(identity)
        witness = participant["last_witness"]
        if witness is not None:
            _require(witness["owner"] == participant["owner"], "participant witness owner mismatch")
            _require(witness["workflow_id"] == value["id"], "participant witness workflow mismatch")
    _require(local, "workflow capsule owner is not a participant")
    validate_workflow_transfer(value)


def validate_staging(
    value: dict[str, Any],
    *,
    expected_owner: dict[str, Any] | None = None,
    principal: str | None = None,
    resource: dict[str, Any] | None = None,
) -> None:
    """Validate custody joins against independently trusted context when supplied."""
    validate("records.schema.json", value, "ContentStaging")
    if expected_owner is not None:
        _require(value["owner"] == expected_owner, "staging owner epoch mismatch")
    if principal is not None:
        _require(value["authenticated_principal"] == principal, "staging principal mismatch")
    if resource is not None:
        _require(value["resource"] == resource, "staging resource mismatch")
    _require(value["offset"] <= value["size"], "staging offset exceeds declared size")
    if value["expires_at"] is not None:
        _require(
            datetime.fromisoformat(value["expires_at"])
            > datetime.fromisoformat(value["created_at"]),
            "staging expiry is not after creation",
        )
    handle = value["handle"]
    if value["state"] == "committed":
        _require(handle is not None, "committed staging lacks immutable handle")
        _require(value["offset"] == value["size"], "committed staging is incomplete")
        _require(
            handle["binding"] == {"kind": "staging", "staging_id": value["id"]}
            and all(handle[key] == value[key] for key in ("owner", "purpose", "digest", "size")),
            "committed handle custody mismatch",
        )
    else:
        _require(handle is None, "uncommitted staging exposes handle")
        _require(value["accepted_references"] == 0, "accepted input cannot lose committed custody")


def validate_staged_input(
    staging: dict[str, Any],
    handle: dict[str, Any],
    *,
    expected_owner: dict[str, Any],
    principal: str,
    resource: dict[str, Any],
    purpose: str,
    now: str,
) -> None:
    """Require immutable authorized input before plan construction, without admitting work."""
    validate_staging(staging, expected_owner=expected_owner, principal=principal, resource=resource)
    _require(staging["state"] == "committed", "plan input is not committed")
    _require(staging["purpose"] == purpose, "staging purpose mismatch")
    _require(staging["handle"] == handle, "plan input handle substitution")
    validate("common.schema.json", now, "Time")
    _require(
        staging["expires_at"] is None
        or datetime.fromisoformat(now) < datetime.fromisoformat(staging["expires_at"]),
        "staging admission deadline expired",
    )


def validate_result_reference(operation: dict[str, Any]) -> None:
    validate("records.schema.json", operation, "Operation")
    result = operation["result_handle"]
    if result is None:
        return
    spec = ACTIONS[operation["subject"]["action"]]["result"]
    _require(spec["mode"] != "receipt-only", "action declares no result payload")
    handle = result["handle"]
    _require(
        handle["owner"] == operation["owner"]
        and handle["binding"] == {"kind": "operation", "operation_id": operation["id"]},
        "result handle operation binding mismatch",
    )
    if spec["mode"] == "schema":
        uri = urljoin(SCHEMAS["records.schema.json"]["$id"], spec["schema"]["$ref"])
        expected = schema_identity(uri)
    else:
        expected = operation["subject"]["arguments"][spec["subject_field"]]
    _require(result["schema"] == expected, "action result schema substitution")


def validate_result_payload(
    operation: dict[str, Any],
    data: bytes,
    *,
    max_bytes: int = MAX_BYTES,
    installed: dict[str, dict[str, Any]] | None = None,
) -> Any:
    """Check transferred bytes and their declared schema; this supplies no owner authenticity."""
    validate_result_reference(operation)
    result = operation["result_handle"]
    _require(result is not None, "operation has no result payload")
    handle = result["handle"]
    _require(
        len(data) == handle["size"]
        and "sha256:" + hashlib.sha256(data).hexdigest() == handle["digest"],
        "result content identity mismatch",
    )
    value = strict_json(data, max_bytes=max_bytes)
    identity = result["schema"]
    _require(
        schema_identity(identity["uri"], installed) == identity, "installed result schema changed"
    )
    documents = _schema_documents(identity["uri"], installed)
    registry = Registry().with_resources(
        (uri, Resource.from_contents(schema)) for uri, schema in documents.items()
    )
    validator = Draft202012Validator(
        {"$ref": identity["uri"]}, registry=registry, format_checker=FORMAT_CHECKER
    )
    _require(not any(validator.iter_errors(value)), "result payload violates action schema")
    return value


def validate_cli_result(
    result: Any,
    *,
    retained_readers: Mapping[str, Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Check CLI and SSH results with the receiving owner's installed readers.

    Propagate the same trusted context through pages and chunks. Reference shape
    does not grant authority to install a reader or to accept new historical work.
    """
    if not isinstance(result, dict):
        return
    kind = result.get("kind")
    if kind == "Operation":
        validate_result_reference(result)
    elif kind == "Workflow":
        validate_workflow(result)
    elif kind == "ContentStaging":
        validate_staging(result)
    elif kind in ("RecordReference", "RecordChunk", "EventPage"):
        from .record_delivery import (
            CHUNK_BYTES,
            validate_log_page,
            validate_record_chunk,
            validate_record_reference,
        )

        if kind == "RecordReference":
            validate_record_reference(result, retained_readers=retained_readers)
        elif kind == "RecordChunk":
            validate_record_reference(result["reference"], retained_readers=retained_readers)
            validate_record_chunk(
                result, result["reference"], offset=result["offset"], length=CHUNK_BYTES
            )
        else:
            validate_log_page(result, expected_owner=result["owner"], resource=result["resource"])
    elif kind in ("OperationPage", "WorkflowPage"):
        validate("records.schema.json", result, kind)
        identities: set[str] = set()
        for item in result["items"]:
            _require(item["owner"] == result["owner"], "page contains another owner epoch")
            identity = item["record"]["id"] if item.get("kind") == "RecordReference" else item["id"]
            _require(identity not in identities, "page repeats retained work")
            identities.add(identity)
            validate_cli_result(item, retained_readers=retained_readers)
