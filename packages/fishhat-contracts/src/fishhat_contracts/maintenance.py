"""Retained maintenance expansion and result joins, without native scheduling or authority.

Receiving owners supply accepted source, occurrence, checkpoint and byte custody
independently. These checks do not authenticate those facts, launch a child,
retain durable state or authorize a hook. The original reviewed Plan owns every
selection; replay does not consult a newer source, schedule or checkpoint.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from datetime import datetime
from io import BytesIO
from typing import Any, BinaryIO
from uuid import UUID, uuid5

from .artifact_custody import verify_artifact_stream
from .bounds import Bounds, bounds
from .hooks import validate_hook_result
from .operations import validate_operation, validate_operation_plan
from .validation import (
    MAX_BYTES,
    SCHEMAS,
    ContractError,
    _material_digests,
    digest,
    validate,
)

_RESTORE_ROLES = {"restore", "verify-restore"}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _bounds(name: str) -> Bounds:
    proofs = (
        ("tests/test_maintenance_handoffs.py::test_maintenance_checkpoint_selection_linear_work",)
        if name == "checkpoint-selection"
        else (
            "tests/test_maintenance_handoffs.py::test_maintenance_result_linear_work",
            "tests/test_maintenance_handoffs.py::test_maintenance_native_result_linear_work",
        )
    )
    return Bounds(
        id="maintenance." + name,
        work="O(B) complete task, selection, Plan, child result and distinct immutable content-handle bytes; no recursive maintenance expansion",
        extent="Complete resolved inputs and retained ordinary child or hook result; no collection-count ceiling",
        limits=(),
        capacity=("owner-admitted complete material and metadata capacity",),
        proofs=proofs,
        linear_proofs=proofs,
    )


def validate_maintenance_task(task: dict[str, Any], hooks: Mapping[str, dict[str, Any]]) -> None:
    """Check source selection; these proposed hooks supply no independent approval."""
    validate("maintenance.schema.json", task, "Task")
    if task["action"] != "native-maintenance":
        return
    hook = hooks.get(task["hook"])
    _require(hook is not None, "unknown maintenance hook")
    assert hook is not None
    validate("source.schema.json", hook, "Hook")
    _require(
        (task["checkpoint"] is not None) == (hook["role"] in _RESTORE_ROLES),
        "maintenance hook checkpoint policy differs from its role",
    )


@bounds(_bounds("checkpoint-selection"))
def select_maintenance_checkpoint(
    policy: dict[str, Any],
    checkpoints: Mapping[str, dict[str, Any]],
    *,
    expected_app_instance: str,
    now: str,
) -> str:
    """Resolve once from the owner's complete authenticated usable inventory.

    The caller has independently established current custody, eligibility,
    signatures and completeness. No list supplied by a requester can establish
    those facts. A selected digest is retained in the Plan before admission.
    """
    from .checkpoints import validate_checkpoint

    validate("maintenance.schema.json", policy, "CheckpointSelection")
    validate("common.schema.json", now, "Time")
    when = datetime.fromisoformat(now.replace("Z", "+00:00"))
    selected: tuple[datetime, str] | None = None
    for identity, checkpoint in checkpoints.items():
        validate_checkpoint(checkpoint)
        verified = datetime.fromisoformat(checkpoint["verified_at"].replace("Z", "+00:00"))
        _require(
            digest(checkpoint) == identity
            and checkpoint["app_instance"] == expected_app_instance
            and verified <= when,
            "maintenance checkpoint inventory identity or observation mismatch",
        )
        candidate = verified, identity
        if selected is None or candidate > selected:
            selected = candidate
    _require(selected is not None, "maintenance lacks a verified checkpoint")
    assert selected is not None
    if policy["mode"] == "exact":
        _require(policy["checkpoint"] in checkpoints, "selected maintenance checkpoint unavailable")
        return str(policy["checkpoint"])
    return selected[1]


def _selected_checkpoint(execution: dict[str, Any]) -> str | None:
    selection = execution["selection"]
    if selection["kind"] == "action":
        subject = selection["subject"]
        return subject["arguments"].get("checkpoint") if subject["action"] == "app.drill" else None
    restore = selection["restore_input"]
    return None if restore is None else str(restore["checkpoint_digest"])


@bounds(_bounds("execution"))
def validate_maintenance_execution(execution: dict[str, Any]) -> None:
    """Check the immutable resolved shape, without deriving trusted source context."""
    validate("maintenance.schema.json", execution, "MaintenanceExecution")
    task, selection = execution["task_definition"], execution["selection"]
    if selection["kind"] == "action":
        subject = selection["subject"]
        _require(
            task["action"] != "native-maintenance"
            and subject["action"] == "app." + task["action"]
            and subject["resource"] == execution["resource"],
            "maintenance expanded action or resource mismatch",
        )
        if subject["action"] == "app.backup":
            _require(
                subject["arguments"]["selection"]["release_digest"] == execution["release_digest"],
                "maintenance backup accepted release changed",
            )
    else:
        _require(
            task["action"] == "native-maintenance" and selection["name"] == task["hook"],
            "maintenance native hook selection changed",
        )
        validate_maintenance_task(task, {selection["name"]: selection["procedure"]})
        _require(
            (selection["restore_input"] is not None)
            == (selection["procedure"]["role"] in _RESTORE_ROLES),
            "maintenance restore hook lacks exact input selection",
        )
    checkpoint = _selected_checkpoint(execution)
    _require(
        (task["checkpoint"] is not None) == (checkpoint is not None),
        "maintenance checkpoint policy or resolution missing",
    )
    if task["checkpoint"] is not None and task["checkpoint"]["mode"] == "exact":
        _require(
            checkpoint == task["checkpoint"]["checkpoint"],
            "maintenance exact checkpoint substituted",
        )


def require_maintenance_review(
    execution: dict[str, Any],
    *,
    expected_owner: dict[str, Any],
    expected_resource: dict[str, Any],
    accepted_release_digest: str,
    accepted_task_name: str,
    accepted_task: dict[str, Any],
    approved_occurrence: dict[str, Any],
    approved_selection: dict[str, Any],
) -> None:
    """Join independently loaded accepted source and native resolution before review.

    approved_selection is the full owner-resolved ordinary subject or accepted
    hook and exact restore closure. For backup it includes independently verified
    application/dataset/secret selection; for drill it includes the once-resolved
    checkpoint. Source, request and embedded result fields cannot supply it.
    Current action-expanded permissions and atomic custody remain native duties.
    """
    validate_maintenance_execution(execution)
    _require(
        execution["owner"] == expected_owner
        and execution["resource"] == expected_resource
        and execution["release_digest"] == accepted_release_digest
        and execution["task"] == accepted_task_name
        and execution["task_definition"] == accepted_task
        and execution["occurrence"] == approved_occurrence
        and execution["selection"] == approved_selection,
        "maintenance differs from accepted task or approved resolution",
    )


def maintenance_material_digests(execution: dict[str, Any]) -> set[str]:
    """Return direct material roots; the owner retains their complete byte closures."""
    validate_maintenance_execution(execution)
    roots = {execution["release_digest"], digest(execution)}
    selection = execution["selection"]
    if selection["kind"] == "action":
        subject = selection["subject"]
        schema = SCHEMAS["actions.schema.json"]
        roots.update(
            _material_digests(
                subject["arguments"], schema["$defs"][subject["action"]], schema["$id"]
            )
        )
    else:
        roots.add(digest(selection["procedure"]))
        checkpoint = _selected_checkpoint(execution)
        if checkpoint is not None:
            roots.add(checkpoint)
    return roots


def validate_maintenance_plan(plan: dict[str, Any]) -> None:
    """Check capsule joins after the ordinary Plan shape/digest boundary."""
    if plan["subject"]["action"] != "app.maintenance-run":
        return
    execution = plan["maintenance"]
    _require(
        execution["owner"] == plan["owner"]
        and execution["resource"] == plan["subject"]["resource"]
        and execution["task"] == plan["subject"]["arguments"]["task"],
        "maintenance Plan identity mismatch",
    )
    _require(
        maintenance_material_digests(execution) <= set(plan["input_digests"]),
        "maintenance material outside reviewed Plan",
    )


def maintenance_child_request_id(operation: dict[str, Any]) -> str:
    """Derive one ordinary child/hook retry identity from the accepted parent."""
    validate("common.schema.json", operation["request_id"], "UUID")
    validate("common.schema.json", operation["owner"], "Owner")
    owner = operation["owner"]
    name = "deployment-ops/maintenance-child/v1/" + "/".join(
        owner[key] for key in ("tool", "id", "epoch")
    )
    return str(uuid5(UUID(operation["request_id"]), name))


def retained_maintenance_execution(
    operation: dict[str, Any], plan: dict[str, Any]
) -> dict[str, Any]:
    """Recover the original capsule after client loss; current source is not an input."""
    validate_operation_plan(operation, plan)
    _require(operation["subject"]["action"] == "app.maintenance-run", "not maintenance work")
    return deepcopy(plan["maintenance"])


def _validate_hook_handoff(
    hook: dict[str, Any], execution: dict[str, Any], operation: dict[str, Any]
) -> None:
    request, result = hook["request"], hook["result"]
    selection, procedure = execution["selection"], execution["selection"]["procedure"]
    _require(
        request["id"] == maintenance_child_request_id(operation)
        and request["operation_id"] == operation["id"]
        and request["subject"] == operation["subject"]["resource"]
        and request["release_digest"] == execution["release_digest"]
        and request["procedure_digest"] == digest(procedure)
        and request["executor_component"] == procedure["component"]
        and request["role"] == procedure["role"]
        and request["timeout_seconds"] == procedure["timeout_seconds"]
        and request["required_checks"] == procedure["required_checks"]
        and set(request["dataset_handles"]) == set(procedure["datasets"])
        and set(request["secret_paths"]) == set(procedure["secrets"])
        and (procedure["network"] != "none" or not request["endpoint_bindings"])
        and request["restore_input"] == selection["restore_input"],
        "maintenance hook differs from reviewed procedure or inputs",
    )
    if result is None:
        _require(not hook["artifacts"], "maintenance artifacts lack their original hook result")
        _require(operation["state"] != "succeeded", "maintenance hook result is missing")
        return
    validate_hook_result(request, result)
    _require(
        operation["state"] != "succeeded" or result["outcome"] == "succeeded",
        "maintenance hook did not succeed",
    )
    _require(
        (result["effects"] != "unknown" or operation["effect_certainty"] == "unknown")
        and (result["effects"] == "none" or operation["effect_certainty"] != "none"),
        "maintenance hook effect facts were discarded",
    )
    artifacts = {item["path"]: item for item in result["artifacts"]}
    seen: set[str] = set()
    handles: dict[str, tuple[str, int]] = {}
    for item in hook["artifacts"]:
        path, content = item["path"], item["content"]
        _require(path in artifacts and path not in seen, "maintenance hook artifact substituted")
        seen.add(path)
        _require(
            content["owner"] == operation["owner"]
            and content["binding"] == {"kind": "operation", "operation_id": operation["id"]}
            and content["purpose"] == "content"
            and content["digest"] == artifacts[path]["digest"]
            and content["size"] == artifacts[path]["bytes"],
            "maintenance hook artifact custody mismatch",
        )
        identity = content["digest"], content["size"]
        _require(
            content["id"] not in handles or handles[content["id"]] == identity,
            "maintenance hook content handle changed identity",
        )
        handles[content["id"]] = identity
    _require(seen == artifacts.keys(), "maintenance hook artifact custody incomplete")


@bounds(_bounds("result"))
def validate_maintenance_result(value: dict[str, Any], operation: dict[str, Any]) -> None:
    """Join the complete original Plan and ordinary child; verify bytes separately."""
    validate("maintenance.schema.json", value, "MaintenanceResult")
    execution = retained_maintenance_execution(operation, value["plan"])
    _require(
        value["owner"] == operation["owner"]
        and value["operation_id"] == operation["id"]
        and value["request_id"] == operation["request_id"]
        and value["plan_digest"] == operation["plan_digest"],
        "maintenance result parent identity mismatch",
    )
    child, hook = value["child"], value["hook"]
    if execution["selection"]["kind"] == "hook":
        _require(child is None, "native maintenance cannot substitute an ordinary child")
        _require(hook is not None or operation["state"] != "succeeded", "maintenance hook missing")
        if hook is not None:
            _validate_hook_handoff(hook, execution, operation)
        return
    _require(hook is None, "ordinary maintenance cannot substitute a hook")
    _require(child is not None or operation["state"] != "succeeded", "maintenance child missing")
    if child is None:
        return
    validate_operation(child)
    _require(
        child["owner"] == operation["owner"]
        and child["id"] != operation["id"]
        and child["request_id"] == maintenance_child_request_id(operation)
        and child["subject"] == execution["selection"]["subject"]
        and child["witness"]["workflow_id"] == operation["witness"]["workflow_id"],
        "maintenance child identity or expanded subject mismatch",
    )
    _require(
        operation["state"] != "succeeded" or child["state"] == "succeeded",
        "maintenance child did not succeed",
    )
    _require(
        (child["effect_certainty"] != "unknown" or operation["effect_certainty"] == "unknown")
        and (child["effect_certainty"] == "none" or operation["effect_certainty"] != "none"),
        "maintenance child effect facts were discarded",
    )


@bounds(_bounds("result-custody"))
def require_maintenance_result_custody(
    value: dict[str, Any],
    operation: dict[str, Any],
    *,
    open_content: Callable[[dict[str, Any]], BinaryIO],
    max_bytes: int = MAX_BYTES,
) -> None:
    """Check exact independently retained child payload or hook artifact byte custody.

    open_content opens authorized immutable owner handles, not requester-selected
    paths. The receiver authenticates every signed record and protects all nested
    material before settlement; this helper does not establish native retention.
    Original Plan and child/result handles remain unchanged after client loss.
    """
    from .handoffs import validate_result_payload

    validate_maintenance_result(value, operation)
    _require(type(max_bytes) is int and max_bytes > 0, "invalid maintenance result capacity")
    child = value["child"]
    if child is not None:
        _require(child["state"] == "succeeded", "maintenance child did not succeed")
        if child["result_handle"] is not None:
            content = child["result_handle"]["handle"]
            _require(
                content["size"] <= max_bytes, "maintenance child result exceeds local capacity"
            )
            retained = BytesIO()
            with open_content(content) as stream:
                verify_artifact_stream(
                    {
                        "digest": content["digest"],
                        "size_bytes": content["size"],
                        "media_type": "application/octet-stream",
                    },
                    stream,
                    destination=retained,
                )
            validate_result_payload(child, retained.getvalue(), max_bytes=max_bytes)
        return
    hook = value["hook"]
    _require(
        hook is not None
        and hook["result"] is not None
        and hook["result"]["outcome"] == "succeeded",
        "maintenance hook did not succeed",
    )
    assert hook is not None
    verified: set[str] = set()
    for item in hook["artifacts"]:
        content = item["content"]
        if content["id"] in verified:
            continue
        with open_content(content) as stream:
            verify_artifact_stream(
                {
                    "digest": content["digest"],
                    "size_bytes": content["size"],
                    "media_type": "application/octet-stream",
                },
                stream,
            )
        verified.add(content["id"])
