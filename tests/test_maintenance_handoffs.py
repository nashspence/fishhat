"""Maintenance retains exact task expansion, ordinary results and recovery inputs."""

from copy import deepcopy
from io import BytesIO

import pytest
from fishhat_contracts import maintenance
from fishhat_contracts.authorization import minimum_action_role
from fishhat_contracts.handoffs import schema_identity, validate_result_payload
from fishhat_contracts.maintenance import (
    maintenance_child_request_id,
    maintenance_material_digests,
    require_maintenance_result_custody,
    require_maintenance_review,
    retained_maintenance_execution,
    select_maintenance_checkpoint,
    validate_maintenance_execution,
    validate_maintenance_result,
)
from fishhat_contracts.validation import (
    ContractError,
    canonical,
    digest,
    strict_yaml,
    validate_plan,
)

from tests.backup_support import backup_result
from tests.drill_support import attach_drill, drill_result
from tests.linear_support import assert_linear, measure
from tests.operation_support import seal_operation
from tests.support import FIXTURES
from tests.test_backup_results import attach as attach_backup
from tests.test_backup_results import pair as backup_pair
from tests.test_checkpoint_resolution import fixture as checkpoint_fixture
from tests.test_checkpoint_resolution import seal as seal_checkpoint
from tests.test_contracts import plan as ordinary_plan
from tests.test_contracts import uid
from tests.test_hook_results import records as hook_records
from tests.test_owner_handoffs import operation
from tests.test_plan_review import reseal

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/maintenance.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Plan",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.json",
    ],
    "scope": "exact accepted maintenance expansion, occurrence, ordinary child/result and native hook custody",
    "relationship": "candidate",
    "reason": "Independent changed selections and resealed child outcomes challenge complete public handoffs. Lost-client recovery retains original source and checkpoint choices. Synthetic records and streams do not implement native scheduling, authentication, isolation or durable custody.",
    "claims": [],
}

CHECK_OVERRIDES = {
    "test_maintenance_result_linear_work": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/maintenance.py#validate_maintenance_execution",
            "packages/fishhat-contracts/src/fishhat_contracts/maintenance.py#validate_maintenance_result",
            "packages/fishhat-contracts/src/fishhat_contracts/maintenance.py#require_maintenance_result_custody",
            "release.toml#/engineering",
        ],
        "scope": "complete original Plan, exact expansion and ordinary child result/custody over increasing effect extent",
        "relationship": "scoped-witness",
        "reason": "Executed work includes complete Plan/capsule checks and result custody without repeated per-effect validation; no native or timing qualification is inferred.",
        "claims": [
            "engineering:maintenance.execution",
            "engineering:maintenance.result",
            "engineering:maintenance.result-custody",
        ],
    },
    "test_maintenance_checkpoint_selection_linear_work": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/maintenance.py#select_maintenance_checkpoint",
            "release.toml#/engineering",
        ],
        "scope": "complete authenticated-candidate metadata traversal with one maximum selection",
        "relationship": "scoped-witness",
        "reason": "Executed work visits every supplied checkpoint once over increasing inventory extent; supplied metadata does not authenticate or establish native completeness.",
        "claims": ["engineering:maintenance.checkpoint-selection"],
    },
    "test_maintenance_native_result_linear_work": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/maintenance.py#validate_maintenance_execution",
            "packages/fishhat-contracts/src/fishhat_contracts/maintenance.py#validate_maintenance_result",
            "packages/fishhat-contracts/src/fishhat_contracts/maintenance.py#require_maintenance_result_custody",
            "release.toml#/engineering",
        ],
        "scope": "complete native hook artifact metadata with one byte verification per immutable content handle",
        "relationship": "scoped-witness",
        "reason": "Executed work grows across complete artifact inventories, including repeated references to one retained byte identity; stream openings prove shared content is not rescanned per reference.",
        "claims": [
            "engineering:maintenance.execution",
            "engineering:maintenance.result",
            "engineering:maintenance.result-custody",
        ],
    },
}


def task():
    source = strict_yaml((FIXTURES / "demo-app/app.yaml").read_text())
    return deepcopy(source["maintenance"]["daily-backup"])


def parent_operation(resource, owner):
    value = operation()
    value.update(
        id=uid("maintenance-parent"),
        request_id=uid("maintenance-request"),
        owner=deepcopy(owner),
        subject={
            "action": "app.maintenance-run",
            "resource": resource,
            "arguments": {"task": "daily-backup"},
        },
        state="succeeded",
        effect_certainty="known",
        result_handle=None,
    )
    return value


def reviewed(parent, selection, *, definition=None, release=None):
    value = ordinary_plan()
    resource, owner = deepcopy(parent["subject"]["resource"]), deepcopy(parent["owner"])
    value.update(owner=owner, subject=deepcopy(parent["subject"]))
    value["preconditions"][0].update(owner=owner, resource=resource)
    value["effects"][0].update(executor=owner, resource=resource)
    value["witness"]["owner"] = deepcopy(owner)
    value["maintenance"] = {
        "format": "deployment-ops/maintenance/v1",
        "kind": "MaintenanceExecution",
        "owner": owner,
        "resource": resource,
        "task": "daily-backup",
        "release_digest": release or digest("accepted release"),
        "task_definition": task() if definition is None else definition,
        "occurrence": {"kind": "scheduled", "due_at": "2026-10-17T10:00:00Z", "fold": 0},
        "selection": deepcopy(selection),
    }
    value["effects"][0]["input_digest"] = digest(value["maintenance"])
    value["input_digests"] = sorted(maintenance_material_digests(value["maintenance"]))
    reseal(value)
    parent["plan_digest"] = value["digest"]
    return value


def result(parent, plan, *, child=None, hook=None):
    return {
        "format": "deployment-ops/maintenance/v1",
        "kind": "MaintenanceResult",
        "owner": deepcopy(parent["owner"]),
        "operation_id": parent["id"],
        "request_id": parent["request_id"],
        "plan_digest": parent["plan_digest"],
        "plan": plan,
        "child": child,
        "hook": hook,
    }


def attach(parent, value):
    data = canonical(value)
    parent["result_handle"] = {
        "handle": {
            "owner": deepcopy(parent["owner"]),
            "id": uid("maintenance-result"),
            "purpose": "content",
            "binding": {"kind": "operation", "operation_id": parent["id"]},
            "digest": digest(value),
            "size": len(data),
        },
        "schema": schema_identity(
            "https://fishhat.invalid/contracts/maintenance.schema.json#/$defs/MaintenanceResult"
        ),
    }
    seal_operation(parent)
    return data


def backup_records(count=2):
    child, payload, _ = backup_pair(count)
    parent = parent_operation(deepcopy(child["subject"]["resource"]), child["owner"])
    child.update(id=uid("maintenance-child"), request_id=maintenance_child_request_id(parent))
    child["witness"]["workflow_id"] = parent["witness"]["workflow_id"]
    payload = backup_result(payload["checkpoint"], child)
    child_data = attach_backup(child, payload)
    plan = reviewed(
        parent,
        {"kind": "action", "subject": child["subject"]},
        release=child["subject"]["arguments"]["selection"]["release_digest"],
    )
    value = result(parent, plan, child=child)
    attach(parent, value)
    return parent, value, child_data


def test_maintenance_backup_preserves_required_child_result_after_lost_reply():
    parent, value, data = backup_records()
    original = canonical(value)
    discovered = deepcopy(parent)
    assert validate_result_payload(discovered, original) == value
    requested = []

    def opened(handle):
        requested.append(deepcopy(handle))
        assert handle == value["child"]["result_handle"]["handle"]
        return BytesIO(data)

    require_maintenance_result_custody(value, discovered, open_content=opened)
    assert len(requested) == 1
    assert canonical(value) == original
    assert retained_maintenance_execution(discovered, value["plan"]) == value["plan"]["maintenance"]


@pytest.mark.parametrize(
    "change",
    [
        "missing-child",
        "missing-result",
        "failed-child",
        "unknown-child",
        "foreign-request",
        "foreign-owner",
        "foreign-workflow",
        "different-subject",
    ],
)
def test_maintenance_cannot_weaken_or_substitute_ordinary_child_obligations(change):
    parent, value, _ = backup_records()
    child = value["child"]
    if change == "missing-child":
        value["child"] = None
    elif change == "missing-result":
        child["result_handle"] = None
    elif change == "failed-child":
        child["state"] = "failed"
    elif change == "unknown-child":
        child.update(state="quarantined", effect_certainty="unknown")
    elif change == "foreign-request":
        child["request_id"] = uid("unrelated-child-request")
    elif change == "foreign-owner":
        child["owner"]["epoch"] = uid("unrelated-owner-epoch")
    elif change == "foreign-workflow":
        child["witness"]["workflow_id"] = uid("unrelated-workflow")
    else:
        child["subject"]["resource"]["id"] = "unrelated-app"
    if value["child"] is not None:
        seal_operation(child)
    data = attach(parent, value)
    with pytest.raises(ContractError):
        validate_result_payload(parent, data)


def test_metadata_success_does_not_substitute_missing_or_changed_child_bytes():
    parent, value, data = backup_records()
    with pytest.raises(ContractError, match="artifact size"):
        require_maintenance_result_custody(
            value, parent, open_content=lambda _: BytesIO(data + b" ")
        )
    child = value["child"]
    from fishhat_contracts.validation import strict_json

    payload = strict_json(data)
    payload["operation_id"] = uid("another-backup")
    changed = attach_backup(child, payload)
    attach(parent, value)
    with pytest.raises(ContractError):
        require_maintenance_result_custody(value, parent, open_content=lambda _: BytesIO(changed))


@pytest.mark.parametrize("changed", ["release", "task-name", "task", "occurrence", "selection"])
def test_embedded_maintenance_never_supplies_its_own_approval(changed):
    _, value, _ = backup_records()
    accepted = deepcopy(value["plan"]["maintenance"])
    proposed = deepcopy(accepted)
    if changed == "release":
        proposed["release_digest"] = digest("replacement release")
        proposed["selection"]["subject"]["arguments"]["selection"]["release_digest"] = proposed[
            "release_digest"
        ]
    elif changed == "task-name":
        proposed["task"] = "another-task"
    elif changed == "task":
        proposed["task_definition"]["calendar"] = "*-*-* 04:00:00"
    elif changed == "occurrence":
        proposed["occurrence"]["due_at"] = "2026-10-18T10:00:00Z"
    else:
        proposed["selection"]["subject"]["arguments"]["selection"]["secret_generations"] = [
            digest("different secret generation")
        ]
    with pytest.raises(ContractError, match="accepted task"):
        require_maintenance_review(
            proposed,
            expected_owner=accepted["owner"],
            expected_resource=accepted["resource"],
            accepted_release_digest=accepted["release_digest"],
            accepted_task_name=accepted["task"],
            accepted_task=accepted["task_definition"],
            approved_occurrence=accepted["occurrence"],
            approved_selection=accepted["selection"],
        )


def test_latest_drill_resolves_once_and_original_plan_survives_new_release_and_backup():
    old, _, snapshots = checkpoint_fixture(1)
    policy = {"mode": "latest-verified"}
    inventory = {digest(old): old}
    selected = select_maintenance_checkpoint(
        policy, inventory, expected_app_instance=old["app_instance"], now="2026-10-25T00:00:00Z"
    )
    parent = parent_operation({"kind": "app", "id": "accepted-application"}, old["owner"])
    definition = task()
    definition.update(action="drill", checkpoint=policy)
    subject = {
        "action": "app.drill",
        "resource": parent["subject"]["resource"],
        "arguments": {"checkpoint": selected},
    }
    plan = reviewed(
        parent,
        {"kind": "action", "subject": subject},
        definition=definition,
        release=old["release_digest"],
    )
    child = operation()
    child.update(
        id=uid("maintenance-child"),
        owner=deepcopy(parent["owner"]),
        request_id=maintenance_child_request_id(parent),
        subject=deepcopy(subject),
        state="succeeded",
        effect_certainty="known",
        result_handle=None,
    )
    attach_drill(child, drill_result(old, child, snapshots))
    value = result(parent, plan, child=child)
    attach(parent, value)
    newer = deepcopy(old)
    newer.update(id=uid("newer-checkpoint"), verified_at="2026-10-26T00:00:00Z")
    seal_checkpoint(newer)
    inventory[digest(newer)] = newer
    assert select_maintenance_checkpoint(
        policy, inventory, expected_app_instance=old["app_instance"], now="2026-10-27T00:00:00Z"
    ) == digest(newer)
    changed_source_task = task()
    changed_source_task.update(
        action="drill", checkpoint={"mode": "exact", "checkpoint": digest(newer)}
    )
    assert changed_source_task != definition
    recovered = retained_maintenance_execution(deepcopy(parent), deepcopy(plan))
    assert recovered["task_definition"] == definition
    assert recovered["release_digest"] == old["release_digest"]
    assert recovered["selection"]["subject"]["arguments"]["checkpoint"] == selected
    assert validate_result_payload(parent, canonical(value)) == value


@pytest.mark.parametrize(
    "change",
    [
        "missing-capsule",
        "missing-release",
        "missing-resolved-material",
        "wrong-task",
        "recursive-action",
    ],
)
def test_maintenance_review_requires_complete_immutable_inputs(change):
    _, value, _ = backup_records()
    plan = value["plan"]
    if change == "missing-capsule":
        del plan["maintenance"]
    elif change == "missing-release":
        plan["input_digests"].remove(plan["maintenance"]["release_digest"])
    elif change == "missing-resolved-material":
        plan["input_digests"].remove(digest(plan["maintenance"]))
    elif change == "wrong-task":
        plan["maintenance"]["task"] = "another-task"
    else:
        plan["maintenance"]["selection"]["subject"] = deepcopy(plan["subject"])
    with pytest.raises(ContractError):
        validate_plan(reseal(plan))


def native_records():
    request, outcome, procedure = hook_records(role="verify-config")
    parent = parent_operation({"kind": "app", "id": "accepted-application"}, operation()["owner"])
    definition = task()
    definition.update(action="native-maintenance", hook="verify")
    selection = {"kind": "hook", "name": "verify", "procedure": procedure, "restore_input": None}
    plan = reviewed(parent, selection, definition=definition)
    request.update(
        id=maintenance_child_request_id(parent),
        operation_id=parent["id"],
        subject=parent["subject"]["resource"],
        release_digest=plan["maintenance"]["release_digest"],
    )
    payload = b"synthetic maintenance output"
    outcome.update(
        request_id=request["id"],
        request_digest=digest(request),
        operation_id=parent["id"],
        release_digest=request["release_digest"],
    )
    outcome["artifacts"] = [
        {"path": "verified.bin", "digest": digest("artifact"), "bytes": len(payload)}
    ]
    import hashlib

    outcome["artifacts"][0]["digest"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    content = {
        "owner": parent["owner"],
        "id": uid("native-maintenance-artifact"),
        "purpose": "content",
        "binding": {"kind": "operation", "operation_id": parent["id"]},
        "digest": outcome["artifacts"][0]["digest"],
        "size": len(payload),
    }
    value = result(
        parent,
        plan,
        hook={
            "request": request,
            "result": outcome,
            "artifacts": [{"path": "verified.bin", "content": content}],
        },
    )
    attach(parent, value)
    return parent, value, payload


def test_native_maintenance_keeps_administrator_floor_and_exact_hook_artifacts():
    parent, value, payload = native_records()
    assert (
        minimum_action_role("app.maintenance-run", task_action="native-maintenance")
        == "administrator"
    )
    validate_maintenance_result(value, parent)
    require_maintenance_result_custody(value, parent, open_content=lambda _: BytesIO(payload))
    value["hook"]["artifacts"] = []
    attach(parent, value)
    with pytest.raises(ContractError, match="incomplete"):
        validate_maintenance_result(value, parent)


def test_native_maintenance_rejects_changed_identity_for_a_retained_content_handle():
    parent, value, _ = native_records()
    hook = value["hook"]
    artifact = {**hook["result"]["artifacts"][0], "path": "second.bin"}
    artifact["digest"] = digest("different output")
    hook["result"]["artifacts"].append(artifact)
    content = {**hook["artifacts"][0]["content"], "digest": artifact["digest"]}
    hook["artifacts"].append({"path": "second.bin", "content": content})
    attach(parent, value)
    with pytest.raises(ContractError, match="handle changed identity"):
        validate_maintenance_result(value, parent)


@pytest.mark.parametrize("change", ["request", "procedure", "outcome", "check", "branch"])
def test_native_maintenance_cannot_rewrite_accepted_hook_or_claim_false_success(change):
    parent, value, _ = native_records()
    if change == "request":
        value["hook"]["request"]["id"] = uid("unrelated-hook")
    elif change == "procedure":
        value["hook"]["request"]["procedure_digest"] = digest("different hook")
    elif change == "outcome":
        value["hook"]["result"]["outcome"] = "failed"
    elif change == "check":
        value["hook"]["result"]["checks"][0]["passed"] = False
    else:
        value["child"] = operation()
    attach(parent, value)
    with pytest.raises(ContractError):
        validate_maintenance_result(value, parent)


def test_maintenance_result_linear_work():
    samples = []
    for count in (32, 256, 1024):
        parent, value, data = backup_records(1)
        plan = value["plan"]
        effect = deepcopy(plan["effects"][0])
        plan["effects"] = [{**effect, "step": f"effect-{index:05d}"} for index in range(count)]
        reseal(plan)
        parent["plan_digest"] = value["plan_digest"] = plan["digest"]
        attach(parent, value)

        def run(plan=plan, value=value, parent=parent, data=data):
            validate_maintenance_execution(plan["maintenance"])
            validate_maintenance_result(value, parent)
            require_maintenance_result_custody(value, parent, open_content=lambda _: BytesIO(data))

        _, work = measure(run, modules=(maintenance,))
        samples.append((len(canonical(value)) + len(data), work))
    assert_linear(samples)


def test_maintenance_checkpoint_selection_linear_work():
    template, _, _ = checkpoint_fixture(1)
    samples = []
    for count in (2, 16, 64):
        inventory = {}
        for index in range(count):
            item = deepcopy(template)
            item["id"] = uid(f"checkpoint-{index:06d}")
            seal_checkpoint(item)
            inventory[digest(item)] = item
        _, work = measure(
            lambda inventory=inventory: select_maintenance_checkpoint(
                {"mode": "latest-verified"},
                inventory,
                expected_app_instance=template["app_instance"],
                now="2026-10-27T00:00:00Z",
            ),
            modules=(maintenance,),
        )
        samples.append((len(canonical(inventory)), work))
    assert_linear(samples)


def test_maintenance_native_result_linear_work():
    samples = []
    for count in (32, 256, 1024):
        parent, value, payload = native_records()
        hook = value["hook"]
        artifact, content = hook["result"]["artifacts"][0], hook["artifacts"][0]["content"]
        hook["result"]["artifacts"] = [
            {**artifact, "path": f"output-{index:05d}.bin"} for index in range(count)
        ]
        hook["artifacts"] = [
            {"path": item["path"], "content": deepcopy(content)}
            for item in hook["result"]["artifacts"]
        ]
        attach(parent, value)
        opened = []

        def stream(handle, opened=opened, payload=payload):
            opened.append(handle["id"])
            return BytesIO(payload)

        def run(value=value, parent=parent, stream=stream):
            validate_maintenance_execution(value["plan"]["maintenance"])
            validate_maintenance_result(value, parent)
            require_maintenance_result_custody(value, parent, open_content=stream)

        _, work = measure(run, modules=(maintenance,))
        assert opened == [content["id"]]
        samples.append((len(canonical(value)) + len(payload), work))
    assert_linear(samples)
