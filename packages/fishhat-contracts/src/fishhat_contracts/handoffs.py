"""Pure owner handoff checks; no transport, staging store, authorization or effects.

Trusted receiver context and installed schemas are supplied explicitly. These checks
make record relationships testable without claiming native custody or authentication.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from copy import deepcopy
from datetime import datetime
from typing import Any
from urllib.parse import urldefrag, urljoin

from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from .adapter_semantics import ROLES, check_retained_result
from .bounds import Bounds, bounds
from .operations import validate_operation
from .schema_profile import (
    MAPPINGS,
    SEQUENCES,
    SINGLE,
    SchemaNode,
    check_assertions,
    check_document,
    check_reference_graph,
    pointer_tokens,
    schema_children,
)
from .validation import (
    _SCHEMA_VALIDATOR,
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
    targets: list[tuple[str, SchemaNode | None]] = [(uri, None)]
    positions: set[SchemaNode] = set()
    graph: dict[SchemaNode, list[SchemaNode]] = {}
    execution: dict[SchemaNode, list[SchemaNode]] = {}

    def references(
        value: Any, base: str, path: tuple[str, ...] = (), *, root: bool = False
    ) -> None:
        position = (base, path)
        positions.add(position)
        custom = base in (installed or {})
        if custom:
            graph[position] = []
            execution[position] = []
        if isinstance(value, dict):
            _require(
                value.get("$schema") == _SCHEMA_VALIDATOR.META_SCHEMA["$id"]
                if root
                else "$schema" not in value,
                "installed schemas require the fixed root Draft 2020-12 dialect",
            )
            _require(
                "$dynamicRef" not in value and "$recursiveRef" not in value,
                "result schemas require static local references",
            )
            _require("$id" not in value or root, "nested result schema identity")
            _require(
                "x-fishhat-contract-dependencies" not in value or root,
                "contract dependencies require a document root",
            )
            if custom:
                check_assertions(value)
            if root:
                dependencies = value.get("x-fishhat-contract-dependencies", [])
                _require(
                    isinstance(dependencies, list)
                    and all(isinstance(target, str) for target in dependencies)
                    and len(set(dependencies)) == len(dependencies),
                    "invalid contract dependencies",
                )
                for dependency in dependencies:
                    target = urljoin(base, dependency)
                    targets.append((target, None))
                    pending.append(urldefrag(target)[0])
            if "$ref" in value:
                target = urljoin(base, value["$ref"])
                targets.append((target, position))
                pending.append(urldefrag(target)[0])
            for suffix, child in schema_children(value):
                child_position = (base, (*path, *suffix))
                if custom:
                    graph[position].append(child_position)
                    if suffix[0] not in {"$defs", "definitions"}:
                        execution[position].append(child_position)
                references(child, base, child_position[1])

    while pending:
        identity = pending.pop()
        if identity in found:
            continue
        _require(identity in available, "result schema is not installed")
        schema = available[identity]
        if identity in (installed or {}):
            check_document(schema, code="INVALID_INSTALLED_SCHEMA")
        found[identity] = schema
        references(schema, identity, root=True)
    for target, source in targets:
        identity, fragment = urldefrag(target)
        node: Any = found[identity]
        path = pointer_tokens(fragment, code="invalid result schema pointer escape")
        for key in path:
            try:
                node = node[int(key)] if isinstance(node, list) else node[key]
            except (KeyError, ValueError, IndexError, TypeError) as exc:
                raise ContractError("result schema reference is unresolved") from exc
        _require(
            isinstance(node, (dict, bool)) and (identity, path) in positions,
            "result reference is not a schema position",
        )
        if source in graph:
            assert source is not None
            graph[source].append((identity, path))
            execution[source].append((identity, path))
    check_reference_graph(graph, execution)
    return found


def _schema_closure(
    uri: str, documents: dict[str, dict[str, Any]], *, document: bool = False
) -> dict[str, Any]:
    """Flatten reachable schema positions once, preserving literal data and annotations.

    Definitions declare locations, rather than evaluating their contents. Admission
    still checks their complete installed documents before this projection is made.
    A child schema is represented by its absolute document-local JSON Pointer;
    referenced targets enter the same graph without recursively expanding aliases.
    """
    nodes: dict[str, dict[str, Any]] = {}
    identity, fragment = urldefrag(uri)
    complete_document = identity if document else None
    pending = [(identity, pointer_tokens(fragment, code="invalid result schema pointer escape"))]

    def pointer(path: tuple[str, ...]) -> str:
        return "".join("/" + key.replace("~", "~0").replace("/", "~1") for key in path)

    while pending:
        identity, path = pending.pop()
        location = pointer(path)
        new_document = identity not in nodes
        locations = nodes.setdefault(identity, {})
        if new_document:
            for dependency in documents[identity].get("x-fishhat-contract-dependencies", []):
                base, fragment = urldefrag(urljoin(identity, dependency))
                pending.append(
                    (base, pointer_tokens(fragment, code="invalid result schema pointer escape"))
                )
        if location in locations:
            continue
        node: Any = documents[identity]
        for key in path:
            node = node[int(key)] if isinstance(node, list) else node[key]
        if isinstance(node, bool):
            locations[location] = node
            continue
        # Shallow copies avoid repeating complete nested schemas at every node.
        declarations = identity == complete_document
        projected = {
            key: value
            for key, value in node.items()
            if declarations or key not in {"$defs", "definitions"}
        }
        for key in MAPPINGS:
            if key in projected:
                projected[key] = dict(projected[key])
        for key in SEQUENCES:
            if key in projected:
                projected[key] = list(projected[key])
        for suffix, _ in schema_children(node):
            if not declarations and suffix[0] in {"$defs", "definitions"}:
                continue
            child = pointer((*path, *suffix))
            if suffix[0] in SINGLE:
                projected[suffix[0]] = child
            elif suffix[0] in SEQUENCES:
                projected[suffix[0]][int(suffix[1])] = child
            else:
                projected[suffix[0]][suffix[1]] = child
            # Keep decoded paths: a literal '%' or '#' in a member name must
            # not become URI syntax or be percent-decoded for a second time.
            pending.append((identity, (*path, *suffix)))
        if "$ref" in node:
            base, fragment = urldefrag(urljoin(identity, node["$ref"]))
            pending.append(
                (base, pointer_tokens(fragment, code="invalid result schema pointer escape"))
            )
        locations[location] = projected
    # Document annotations can define rules shared by every definition, such as
    # canonical commitments or the native authority boundary. Selecting a
    # fragment must not silently discard that normative context.
    metadata = (
        "$schema",
        "$id",
        "$comment",
        "title",
        "description",
        "default",
        "examples",
        "deprecated",
        "readOnly",
        "writeOnly",
        "x-fishhat-contract-dependencies",
    )
    envelopes = {
        identity: {key: documents[identity][key] for key in metadata if key in documents[identity]}
        for identity in nodes
    }
    profile = "fishhat.schema-document-closure/v1" if document else "fishhat.schema-closure/v1"
    return {"profile": profile, "root": uri, "documents": envelopes, "nodes": nodes}


def schema_identity(uri: str, installed: dict[str, dict[str, Any]] | None = None) -> dict[str, str]:
    """Pin the rooted installed schema closure; URI resolution never uses a network."""
    documents = _schema_documents(uri, installed)
    return {"uri": uri, "digest": digest(_schema_closure(uri, documents))}


def schema_document_digest(uri: str) -> str:
    """Pin one complete core protocol document plus its rooted reference dependencies."""
    _require(not urldefrag(uri)[1], "protocol document digest requires a document root")
    documents = _schema_documents(uri)
    return digest(_schema_closure(uri, documents, document=True))


def validate_workflow(
    value: dict[str, Any],
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    from .transfers import validate_workflow_transfer
    from .workflows import validate_workflow_proposal_binding

    validate("records.schema.json", value, "Workflow")
    validate_workflow_proposal_binding(value, recovery_readers=recovery_readers)
    _require(value["phase"] in PHASES[value["type"]], "workflow phase outside installed procedure")
    _require(
        (value["state"] == "completed") == (value["phase"] == PHASES[value["type"]][-1]),
        "workflow completion phase and lifecycle mismatch",
    )
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


def _adapter_result_contract(
    arguments: dict[str, Any],
    *,
    installed: dict[str, dict[str, Any]] | None,
) -> tuple[str, dict[str, str]] | None:
    """Resolve core semantics from the pinned input, never a caller's result wrapper."""
    identity = arguments["input_schema"]
    base, fragment = urldefrag(identity["uri"])
    role = next(
        (role for role in ROLES if SCHEMAS[role + "-adapter.schema.json"]["$id"] == base),
        None,
    )
    if role is not None:
        _require(
            fragment == "/$defs/MutationRequest", "core adapter input requires MutationRequest"
        )
        _require(
            arguments["result_schema"]["uri"]
            == SCHEMAS[role + "-adapter.schema.json"]["$id"] + "#/$defs/RetainedResult",
            "typed adapter results require the complete retained invocation and response",
        )
        return role, schema_identity(identity["uri"])
    result_base = urldefrag(arguments["result_schema"]["uri"])[0]
    _require(
        all(result_base != SCHEMAS[role + "-adapter.schema.json"]["$id"] for role in ROLES),
        "retained adapter input schema binding changed",
    )
    _require(
        base in (installed or {}) and identity == schema_identity(identity["uri"], installed),
        "custom adapter input schema is not independently installed",
    )
    _require(
        not _wraps_core_adapter_input(identity["uri"], installed),
        "custom input cannot wrap a core adapter mutation contract",
    )
    return None


def _wraps_core_adapter_input(uri: str, installed: dict[str, dict[str, Any]] | None) -> bool:
    """Inspect one selected input's whole-instance references, without reverse lookup."""
    core = {
        (SCHEMAS[role + "-adapter.schema.json"]["$id"], path)
        for role in ROLES
        for path in ((), ("$defs", "MutationRequest"))
    }
    core.update(
        (SCHEMAS["adapter.schema.json"]["$id"], ("$defs", name))
        for name in ("MutationRequest", "Invocation")
    )
    documents = _schema_documents(uri, installed)
    pending = [uri]
    seen: set[SchemaNode] = set()
    inspected: set[int] = set()
    while pending:
        target = pending.pop()
        base, fragment = urldefrag(target)
        path = pointer_tokens(fragment, code="invalid result schema pointer escape")
        position = (base, path)
        if position in core:
            return True
        if position in seen:
            continue
        seen.add(position)
        value: Any = documents[base]
        for key in path:
            value = value[int(key)] if isinstance(value, list) else value[key]
        nodes = [value]
        while nodes:
            node = nodes.pop()
            if not isinstance(node, dict) or id(node) in inspected:
                continue
            inspected.add(id(node))
            if "$ref" in node:
                pending.append(urljoin(base, node["$ref"]))
            for keyword in ("allOf", "anyOf", "oneOf"):
                nodes.extend(node.get(keyword, []))
            for keyword in ("then", "else"):
                if keyword in node:
                    nodes.append(node[keyword])
    return False


@bounds(
    Bounds(
        id="handoffs.retained-result",
        work="Admission O(S + E) schema bytes and references without unfolding; payload O(B) complete bytes under a fixed admitted schema profile",
        extent="Exact committed result bytes, every nested invocation/output artifact and full selected schema closure",
        limits=(),
        capacity=(
            "The receiving max_bytes capacity rejects before parsing; it never truncates",
            "Custom schema profiles share depth 32 and static expansion work 4096; complete result and unused-definition counts remain uncapped",
        ),
        proofs=("tests/test_retained_result_growth.py::test_retained_adapter_results_linear_work",),
        linear_proofs=(
            "tests/test_retained_result_growth.py::test_retained_adapter_results_linear_work",
            "tests/test_result_schema_admission.py::test_custom_result_complete_validation_linear_work",
            "tests/test_result_schema_admission.py::test_custom_schema_closure_admission_linear_work",
        ),
    )
)
def validate_result_payload(
    operation: dict[str, Any],
    data: bytes,
    *,
    max_bytes: int = MAX_BYTES,
    installed: dict[str, dict[str, Any]] | None = None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> Any:
    """Check exact bytes with installed compatible readers and current v1 semantics.

    Qualified historical readers may inspect unchanged payloads, never translate
    them. Neither schema compatibility nor a transfer digest authenticates owners.
    """
    validate_operation(operation, recovery_readers=recovery_readers)
    result = operation["result_handle"]
    _require(result is not None, "operation has no result payload")
    handle = result["handle"]
    _require(
        len(data) == handle["size"]
        and "sha256:" + hashlib.sha256(data).hexdigest() == handle["digest"],
        "result content identity mismatch",
    )
    value = strict_json(data, max_bytes=max_bytes)
    _require(canonical(value) == data, "result payload encoding is not canonical")
    identity = result["schema"]
    if schema_identity(identity["uri"], installed) != identity:
        reader = (recovery_readers or {}).get((identity["uri"], identity["digest"]))
        _require(reader is not None, "installed result schema changed")
        assert reader is not None
        inspected = deepcopy(value)
        reader(inspected)
        _require(canonical(inspected) == canonical(value), "result reader changed original bytes")
    documents = _schema_documents(identity["uri"], installed)
    registry = Registry().with_resources(
        (
            uri,
            Resource.from_contents(
                {key: value for key, value in schema.items() if key != "$schema"},
                default_specification=DRAFT202012,
            ),
        )
        for uri, schema in documents.items()
    )
    # Identity retains the complete published documents. Evaluation uses the
    # fixed installed dialect without selecting the stock class through $ref.
    validator = _SCHEMA_VALIDATOR(
        {"$ref": identity["uri"]}, registry=registry, format_checker=FORMAT_CHECKER
    )
    _require(not any(validator.iter_errors(value)), "result payload violates action schema")
    action = operation["subject"]["action"]
    if action == "app.cleanup":
        from .action_results import validate_cleanup_result

        validate_cleanup_result(value, operation)
    if action == "app.maintenance-run":
        from .maintenance import validate_maintenance_result

        validate_maintenance_result(value, operation)
    if action == "host.capture-changes":
        from .action_results import validate_source_proposal

        validate_source_proposal(value, operation=operation)
    if action == "app.backup":
        from .backup_results import validate_backup_result

        validate_backup_result(value, operation=operation)
    if action == "app.drill":
        from .drill_results import validate_drill_result

        validate_drill_result(value, operation=operation)
    if action == "adapter.execute":
        selected = _adapter_result_contract(
            operation["subject"]["arguments"],
            installed=installed,
        )
        if selected is not None:
            role, input_schema = selected
            input_digest = operation["subject"]["arguments"]["input_schema"]["digest"]
            if input_digest != input_schema["digest"]:
                reader = (recovery_readers or {}).get((input_schema["uri"], input_digest))
                _require(reader is not None, "retained adapter input schema binding changed")
                assert reader is not None
                original = value["invocation"]["request"]
                inspected = deepcopy(original)
                reader(inspected)
                _require(
                    canonical(inspected) == canonical(original),
                    "adapter input reader changed original bytes",
                )
            check_retained_result(role, value, operation=operation)
    if action in {"publisher.publish", "publisher.recover"}:
        from .publication import validate_publication, validate_publication_result

        if action == "publisher.publish":
            validate_publication_result(
                value, operation["subject"], expected_custodian=operation["owner"]
            )
        else:
            validate_publication(value)
            arguments = operation["subject"]["arguments"]
            _require(
                value["custodian"] == operation["owner"]
                and value["id"] == arguments["publication_id"]
                and value["recovery_handle"]["digest"] == arguments["candidate_digest"],
                "publication recovery result identity mismatch",
            )
        _require(
            operation["state"] != "succeeded" or value["state"] == "completed",
            "successful publication lacks completed result",
        )
    return value


def _validate_workflow_result(
    result: dict[str, Any],
    *,
    retained_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None,
) -> None:
    if result["kind"] == "Workflow":
        validate_workflow(result, recovery_readers=recovery_readers)
    elif result["kind"] == "WorkflowTransferRecord":
        from .workflow_transfer_history import validate_transfer_record

        validate_transfer_record(result)
    elif result["kind"] == "WorkflowPhaseAttestation":
        from .workflow_attestations import validate_attestation

        validate_attestation(result)
    else:
        from .record_delivery import validate_record_reference

        validate("workflow-evidence.schema.json", result, "CurrentAttestation")
        validate_record_reference(result["reference"], retained_readers=retained_readers)
        _require(
            result["reference"]["record"]["resource"]
            == {"kind": "workflow", "id": result["transition"]["workflow_id"]},
            "current attestation check workflow changed",
        )


def _validate_record_result(
    result: dict[str, Any],
    *,
    retained_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None,
) -> None:
    from .record_delivery import (
        CHUNK_BYTES,
        validate_log_page,
        validate_record_chunk,
        validate_record_reference,
    )

    if result["kind"] == "RecordReference":
        validate_record_reference(result, retained_readers=retained_readers)
    elif result["kind"] == "RecordChunk":
        validate_record_reference(result["reference"], retained_readers=retained_readers)
        validate_record_chunk(
            result, result["reference"], offset=result["offset"], length=CHUNK_BYTES
        )
    else:
        validate_log_page(result, expected_owner=result["owner"], resource=result["resource"])


def _validate_content_result(result: dict[str, Any]) -> None:
    if result["kind"] == "ContentStaging":
        validate_staging(result)
        return
    from .record_delivery import CHUNK_BYTES, validate_content_chunk

    validate_content_chunk(result, result["handle"], offset=result["offset"], length=CHUNK_BYTES)


def validate_cli_result(
    result: Any,
    *,
    retained_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Check CLI and SSH results with the receiving owner's installed readers.

    Propagate the same trusted context through pages and chunks. Reference shape
    does not grant authority to install a reader or to accept new historical work.
    """
    if not isinstance(result, dict):
        return
    kind = result.get("kind")
    if kind == "Operation":
        validate_operation(result, recovery_readers=recovery_readers)
    elif kind == "Checkpoint":
        from .checkpoints import validate_checkpoint

        validate_checkpoint(result)
    elif kind == "BackupResult":
        from .backup_results import validate_backup_result

        validate_backup_result(result)
    elif kind == "DrillResult":
        from .drill_results import validate_drill_result

        validate_drill_result(result)
    elif kind == "LifecycleEvidenceReference":
        from .lifecycle import validate_lifecycle_reference

        validate_lifecycle_reference(result)
    elif kind in {
        "Workflow",
        "WorkflowTransferRecord",
        "WorkflowPhaseAttestation",
        "CurrentWorkflowAttestation",
    }:
        _validate_workflow_result(
            result, retained_readers=retained_readers, recovery_readers=recovery_readers
        )
    elif kind in {"OperationCancellationReceipt", "OperationCancellationPage"}:
        from .cancellation import validate_cancellation_result

        validate_cancellation_result(result)
    elif kind in ("ContentStaging", "ContentChunk"):
        _validate_content_result(result)
    elif kind == "WorkflowAbandonment":
        from .workflow_abandonment import validate_abandonment

        validate_abandonment(result)
    elif kind == "WorkflowNeverPrepared":
        from .workflow_unprepared import validate_never_prepared

        validate_never_prepared(result)
    elif kind == "WorkflowLifecycleResult":
        from .workflow_lifecycle import validate_lifecycle_result

        validate_lifecycle_result(result)
    elif kind == "ObservationPage":
        from .record_delivery import validate_observation_page

        owner = result.get("owner")
        if not isinstance(owner, dict):
            raise ContractError("observation page lacks its owner")
        validate_observation_page(result, expected_owner=owner, retained_readers=retained_readers)
    elif kind is None and "origin" in result and "resource" in result:
        from .record_delivery import validate_observation

        validate_observation(result)
    elif kind in (
        "OwnerHistoryPage",
        "HistoricalRecordPage",
        "HistoricalRecordChunk",
        "HistoricalContentChunk",
    ):
        from .history import validate_history_result

        validate_history_result(result, retained_readers=retained_readers)
    elif kind in ("RecordReference", "RecordChunk", "EventPage"):
        _validate_record_result(result, retained_readers=retained_readers)
    elif kind in ("OperationPage", "WorkflowPage"):
        validate("records.schema.json", result, kind)
        identities: set[str] = set()
        for item in result["items"]:
            _require(item["owner"] == result["owner"], "page contains another owner epoch")
            identity = item["record"]["id"] if item.get("kind") == "RecordReference" else item["id"]
            _require(identity not in identities, "page repeats retained work")
            identities.add(identity)
            validate_cli_result(
                item, retained_readers=retained_readers, recovery_readers=recovery_readers
            )
