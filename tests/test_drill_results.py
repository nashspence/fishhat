"""Exact immutable drill handoffs and adverse retained evidence substitutions."""

from copy import deepcopy

import pytest
from fishhat_contracts import drill_results
from fishhat_contracts.drill_results import validate_drill_result
from fishhat_contracts.handoffs import validate_cli_result, validate_result_payload
from fishhat_contracts.operations import validate_operation
from fishhat_contracts.validation import ContractError, canonical, digest, validate

from tests.drill_support import attach_drill, drill_result, refresh_evidence
from tests.linear_support import assert_linear, measure
from tests.operation_support import seal_operation
from tests.test_checkpoint_resolution import fixture, resolve_checkpoint
from tests.test_contracts import plan as ordinary_plan
from tests.test_contracts import uid
from tests.test_owner_handoffs import operation
from tests.test_plan_review import reseal

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/drill-result.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/actions.schema.json#/$defs/app.drill",
    ],
    "scope": "immutable checkpoint, exact producer, complete restore/verification and separate cleanup evidence",
    "relationship": "candidate",
    "reason": "Adverse resealed results and authenticated synthetic checkpoint inputs challenge exact handoffs; native isolation, artifact bytes and execution remain separately qualified.",
    "claims": [],
}
CHECK_OVERRIDES = {
    name: {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/drill_results.py#validate_drill_result"
        ],
        "scope": "complete immutable drill result and indexed producer/dataset/procedure joins",
        "relationship": "scoped-witness",
        "reason": "Executed reference validation retains the original checkpoint and complete evidence across increasing dataset extent; it does not qualify native isolation or execution.",
        "claims": ["engineering:drill.result"],
    }
    for name in (
        "test_drill_retains_original_checkpoint_and_exact_evidence",
        "test_complete_drill_result_linear_work",
    )
}


def pair(count=2):
    checkpoint, context, snapshots = fixture(count)
    record = operation()
    record.update(
        owner=deepcopy(checkpoint["owner"]),
        state="succeeded",
        effect_certainty="known",
        subject={
            "action": "app.drill",
            "resource": {"kind": "app", "id": "accepted-application"},
            "arguments": {"checkpoint": digest(checkpoint)},
        },
    )
    value = drill_result(checkpoint, record, snapshots)
    accepted = {
        digest(entry["procedure"]): deepcopy(entry["procedure"])
        for entry in [*value["restorations"], *value["verifications"]]
    }
    return record, value, resolve_checkpoint(checkpoint, **context), accepted


def test_drill_retains_original_checkpoint_and_exact_evidence():
    record, value, inputs, procedures = pair()
    original = canonical(value["checkpoint"])
    data = attach_drill(record, value)
    assert validate_result_payload(record, data) == value
    validate_cli_result(value)
    validate_drill_result(
        value,
        operation=record,
        checkpoint_inputs=inputs,
        accepted_procedures=procedures,
        expected_production_binding=value["production_binding"],
        expected_target_binding=value["target_binding"],
    )
    assert validate_result_payload(deepcopy(record), data) == value
    assert canonical(value["checkpoint"]) == original
    assert value["cleanup"]["state"] == "retained"
    recovered_owner = deepcopy(record)
    recovered_owner["owner"]["epoch"] = uid("independently-authorized-new-epoch")
    recovered_owner.update(
        id=uid("new-drill"),
        request_id=uid("new-drill-request"),
        plan_digest=digest("new-drill-plan"),
    )
    later = drill_result(value["checkpoint"], recovered_owner, inputs.snapshots)
    assert validate_result_payload(recovered_owner, attach_drill(recovered_owner, later)) == later
    assert canonical(later["checkpoint"]) == original


@pytest.mark.parametrize(
    "field", ["owner", "operation_id", "request_id", "plan_digest", "resource"]
)
def test_drill_cannot_substitute_producer(field):
    record, value, _, _ = pair(1)
    if field == "owner":
        value[field]["epoch"] = uid("other-owner")
    elif field == "resource":
        value[field]["id"] = "another-application"
    else:
        value[field] = digest("other-plan") if field == "plan_digest" else uid("other-operation")
    with pytest.raises(ContractError):
        validate_result_payload(record, attach_drill(record, value))


@pytest.mark.parametrize(
    "change",
    [
        "missing-dataset",
        "missing-check",
        "failed-check",
        "diagnostic-check",
        "different-target",
        "different-snapshot",
        "different-checkpoint",
        "production-target",
        "missing-custody",
        "unaccepted-procedure",
        "production-hook",
    ],
)
def test_drill_rejects_incomplete_or_substituted_evidence(change):
    record, value, inputs, procedures = pair()
    verification = value["verifications"][0]
    if change == "missing-dataset":
        value["verifications"].pop()
    elif change == "missing-check":
        verification["result"]["checks"] = []
    elif change == "failed-check":
        verification["result"]["checks"][0]["passed"] = False
    elif change == "diagnostic-check":
        verification["result"]["checks"][0]["requirement"] = "diagnostic"
    elif change == "different-target":
        next(iter(verification["request"]["dataset_handles"].values()))["path"] = "/synthetic/other"
    elif change == "different-snapshot":
        next(iter(verification["request"]["restore_input"]["datasets"].values()))["snapshot"][
            "handle"
        ] = "snapshot:other"
    elif change == "different-checkpoint":
        record["subject"]["arguments"]["checkpoint"] = digest("different-checkpoint")
    elif change == "production-target":
        value["target_binding"] = deepcopy(value["production_binding"])
    elif change == "unaccepted-procedure":
        verification["procedure"]["argv"] = ["/synthetic/other-verification"]
    elif change == "production-hook":
        verification["request"]["runtime_binding_digest"] = digest(
            {
                key: item
                for key, item in value["production_binding"].items()
                if key != "admission_generation"
            }
        )
    refresh_evidence(value)
    if change == "missing-custody":
        value["evidence_closure"].remove(digest(verification["result"]))
    with pytest.raises(ContractError):
        validate_drill_result(
            value, operation=record, checkpoint_inputs=inputs, accepted_procedures=procedures
        )


def test_drill_cannot_replace_both_restored_and_verified_snapshot():
    record, value, inputs, procedures = pair(1)
    for entry in [*value["restorations"], *value["verifications"]]:
        next(iter(entry["request"]["restore_input"]["datasets"].values()))["snapshot"]["handle"] = (
            "snapshot:substituted"
        )
    refresh_evidence(value)
    with pytest.raises(ContractError, match="authenticated checkpoint"):
        validate_drill_result(
            value, operation=record, checkpoint_inputs=inputs, accepted_procedures=procedures
        )


def test_drill_plan_pins_inputs_without_predicting_execution_evidence():
    record, value, inputs, procedures = pair(1)
    plan = deepcopy(ordinary_plan())
    plan.update(owner=deepcopy(record["owner"]), subject=deepcopy(record["subject"]))
    plan["witness"]["owner"] = deepcopy(record["owner"])
    plan["preconditions"][0].update(
        owner=deepcopy(record["owner"]), resource=deepcopy(record["subject"]["resource"])
    )
    plan["effects"][0].update(
        step="restore-verify",
        executor=deepcopy(record["owner"]),
        resource=deepcopy(record["subject"]["resource"]),
        summary="Restore and verify the selected checkpoint in the isolated runtime.",
        action="isolated-drill",
        input_digest=digest(value["checkpoint"]),
    )
    target_digest = digest(
        {
            key: item
            for key, item in value["target_binding"].items()
            if key != "admission_generation"
        }
    )
    plan["input_digests"] = [
        digest(value["checkpoint"]),
        target_digest,
        digest(
            {
                key: item
                for key, item in value["production_binding"].items()
                if key != "admission_generation"
            }
        ),
        *procedures,
    ]
    reseal(plan)
    record["plan_digest"] = value["plan_digest"] = plan["digest"]
    attach_drill(record, value)
    assert value["isolation_evidence"] not in plan["input_digests"]
    assert value["isolation_evidence"] in value["evidence_closure"]
    validate_drill_result(
        value, operation=record, plan=plan, checkpoint_inputs=inputs, accepted_procedures=procedures
    )
    plan["input_digests"].remove(target_digest)
    reseal(plan)
    record["plan_digest"] = value["plan_digest"] = plan["digest"]
    attach_drill(record, value)
    with pytest.raises(ContractError, match="reviewed Plan inputs"):
        validate_drill_result(value, operation=record, plan=plan)


def test_drill_hard_cut_requires_result_and_rejects_mutable_checkpoint_annotation():
    record, value, _, _ = pair(1)
    record["result_handle"] = None
    seal_operation(record)
    with pytest.raises(ContractError):
        validate_operation(record)
    value["checkpoint"]["restore_tested_at"] = "2026-10-25T00:00:00Z"
    with pytest.raises(ContractError):
        validate("records.schema.json", value["checkpoint"], "Checkpoint")


def test_complete_drill_result_linear_work():
    samples = []
    for count in (2, 8, 32):
        record, value, inputs, procedures = pair(count)
        _, work = measure(
            lambda value=value, record=record, inputs=inputs, procedures=procedures: (
                validate_drill_result(
                    value,
                    operation=record,
                    checkpoint_inputs=inputs,
                    accepted_procedures=procedures,
                )
            ),
            modules=(drill_results,),
        )
        samples.append((count, work))
    assert_linear(samples)
