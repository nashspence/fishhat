"""Backup success cannot substitute another producer or accepted application selection."""

from copy import deepcopy

import pytest
from fishhat_contracts import backup_results
from fishhat_contracts.backup_results import validate_backup_result, validate_backup_selection
from fishhat_contracts.handoffs import schema_identity, validate_result_payload
from fishhat_contracts.validation import ContractError, canonical, digest, validate, validate_plan

from tests.backup_support import backup_result, backup_selection
from tests.linear_support import assert_linear, measure
from tests.operation_support import seal_operation
from tests.test_checkpoint_resolution import fixture, resolve_checkpoint, seal
from tests.test_contracts import plan, uid
from tests.test_owner_handoffs import operation
from tests.test_plan_review import reseal

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/backup-result.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.schema.json#/$defs/app.backup",
    ],
    "scope": "exact backup producer and accepted application/release/dataset result binding",
    "relationship": "candidate",
    "reason": "Independently retained synthetic accepted selection and resealed substituted outputs challenge the public handoff; native capture, custody and authentication remain unqualified.",
    "claims": [],
}

CHECK_OVERRIDES = {
    "test_backup_result_retains_exact_producer_and_checkpoint": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/backup_results.py#validate_backup_result",
            "packages/fishhat-contracts/src/fishhat_contracts/contracts/backup-result.schema.json",
        ],
        "scope": "complete immutable backup result and exact producing operation joins",
        "relationship": "scoped-witness",
        "reason": "Executed validation preserves every synthetic checkpoint dataset and proves exact repeated delivery without qualifying native capture or custody.",
        "claims": ["engineering:backup.result"],
    },
    "test_backup_result_complete_selection_linear_work": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/backup_results.py#validate_backup_result",
            "release.toml#/engineering",
        ],
        "scope": "complete backup wrapper and selected dataset/secret result joins",
        "relationship": "scoped-witness",
        "reason": "Executed work covers complete results across sixteenfold selected dataset extent; no native or timing qualification is inferred.",
        "claims": ["engineering:backup.result"],
    },
}


def pair(count=2):
    checkpoint, context, _ = fixture(count)
    record = operation()
    record.update(
        owner=deepcopy(checkpoint["owner"]),
        state="succeeded",
        effect_certainty="known",
        subject={
            "action": "app.backup",
            "resource": {"kind": "app", "id": "accepted-application"},
            "arguments": {"selection": backup_selection(checkpoint)},
        },
    )
    return record, backup_result(checkpoint, record), context


def attach(record, result):
    data = canonical(result)
    record["result_handle"] = {
        "handle": {
            "owner": deepcopy(record["owner"]),
            "id": uid("backup-result"),
            "purpose": "content",
            "binding": {"kind": "operation", "operation_id": record["id"]},
            "digest": digest(result),
            "size": len(data),
        },
        "schema": schema_identity(
            "https://fishhat.invalid/contracts/backup-result.schema.json#/$defs/BackupResult"
        ),
    }
    seal_operation(record)
    return data


def test_backup_result_retains_exact_producer_and_checkpoint():
    record, result, context = pair()
    original = canonical(result["checkpoint"])
    data = attach(record, result)
    assert validate_result_payload(record, data) == result
    assert validate_result_payload(deepcopy(record), data) == result
    assert canonical(result["checkpoint"]) == original
    assert set(resolve_checkpoint(result["checkpoint"], **context).snapshots) == set(
        result["selection"]["preserved_datasets"]
    )


@pytest.mark.parametrize(
    "field", ["owner", "operation_id", "request_id", "plan_digest", "resource"]
)
def test_backup_result_cannot_relabel_another_producer(field):
    record, result, _ = pair()
    if field == "owner":
        result[field]["epoch"] = uid("foreign-owner")
    elif field == "resource":
        result[field]["id"] = "different-application"
    else:
        result[field] = digest("other-plan") if field == "plan_digest" else uid("other-producer")
    with pytest.raises(ContractError, match=r"backup .*selection|producing operation"):
        validate_result_payload(record, attach(record, result))


@pytest.mark.parametrize(
    "field", ["app_instance", "release_digest", "preserved_datasets", "secret_generations"]
)
def test_backup_result_rejects_old_or_foreign_checkpoint_selection(field):
    record, result, _ = pair()
    selection = record["subject"]["arguments"]["selection"]
    replacements = {
        "app_instance": "prod:" + "b" * 64,
        "release_digest": digest("different accepted release"),
        "preserved_datasets": ["different-dataset"],
        "secret_generations": [digest("different accepted secrets")],
    }
    selection[field] = replacements[field]
    result["selection"] = deepcopy(selection)
    with pytest.raises(ContractError, match="checkpoint differs from accepted application"):
        validate_result_payload(record, attach(record, result))


def test_backup_result_cannot_change_the_reviewed_selection_with_its_checkpoint():
    record, result, _ = pair()
    result["checkpoint"]["release_digest"] = digest("another release")
    result["checkpoint"]["recovery_closure"].append(result["checkpoint"]["release_digest"])
    seal(result["checkpoint"])
    result["selection"] = backup_selection(result["checkpoint"])
    with pytest.raises(ContractError, match="producing operation or reviewed selection"):
        validate_result_payload(record, attach(record, result))


def test_backup_selection_requires_independently_retained_accepted_owner_context():
    _, result, _ = pair()
    resource, selection = deepcopy(result["resource"]), deepcopy(result["selection"])
    validate_backup_selection(
        selection,
        resource=resource,
        expected_resource=result["resource"],
        expected_selection=result["selection"],
    )
    selection["app_instance"] = "prod:" + "c" * 64
    with pytest.raises(ContractError, match="accepted application selection changed"):
        validate_backup_selection(
            selection,
            resource=resource,
            expected_resource=result["resource"],
            expected_selection=result["selection"],
        )
    resource["id"] = "another-application"
    with pytest.raises(ContractError, match="application resource changed"):
        validate_backup_selection(
            result["selection"],
            resource=resource,
            expected_resource=result["resource"],
            expected_selection=result["selection"],
        )


def test_backup_hard_cut_rejects_unselected_action_and_bare_checkpoint_result():
    record, result, _ = pair()
    with pytest.raises(ContractError):
        validate("actions.schema.json", {}, "app.backup")
    with pytest.raises(ContractError):
        validate_result_payload(record, attach(record, result["checkpoint"]))
    validate("records.schema.json", result["checkpoint"], "Checkpoint")


def test_backup_plan_retains_exact_release_and_secret_generation_material():
    value = deepcopy(plan())
    selection = {
        "app_instance": "prod:" + "a" * 64,
        "release_digest": digest("accepted release"),
        "preserved_datasets": ["database"],
        "secret_generations": [digest("accepted secrets")],
    }
    value["subject"].update(action="app.backup", arguments={"selection": selection})
    with pytest.raises(ContractError, match="subject material input outside reviewed plan"):
        validate_plan(reseal(value))
    value["input_digests"].append(selection["release_digest"])
    with pytest.raises(ContractError, match="subject material input outside reviewed plan"):
        validate_plan(reseal(value))
    value["input_digests"].extend(selection["secret_generations"])
    validate_plan(reseal(value))


def test_backup_result_complete_selection_linear_work():
    samples = []
    for count in (4, 16, 64):
        record, result, _ = pair(count)
        attach(record, result)
        _, work = measure(
            lambda result=result, record=record: validate_backup_result(result, operation=record),
            modules=(backup_results,),
        )
        samples.append((count, work))
    assert_linear(samples)
