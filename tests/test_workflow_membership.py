"""One child membership rule across continuation, phase and recovery boundaries."""

from __future__ import annotations

import copy

import pytest
from fishhat_contracts.handoffs import validate_workflow
from fishhat_contracts.validation import ContractError, digest
from fishhat_contracts.workflow_bindings import bind_workflow_view
from fishhat_contracts.workflow_evidence import validate_phase_evidence
from fishhat_contracts.workflow_recovery import validate_recovery_proposal

from tests.operation_support import seal_operation
from tests.test_contracts import uid
from tests.test_owner_handoffs import workflow
from tests.test_plan_review import reseal
from tests.test_workflow_continuations import bind_request, context, move, successor_stage
from tests.test_workflow_recovery import child_operation, commit, prepare, scenario
from tests.workflow_evidence_support import advance_request, seal_phase_participant

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/RequestBinding",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/CompletedBinding",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-recovery.schema.json#/$defs/RecoveryProposal",
    ],
    "scope": "ordinary child workflow membership and exact completed-ancestor preservation",
    "relationship": "candidate",
    "reason": "Resealed synthetic Operations challenge null and foreign workflow membership at each semantic boundary with a preserved recovered ancestor positive control. Independently supplied fixture context does not qualify native authentication or recovery.",
    "claims": [],
}


@pytest.mark.parametrize("workflow_id", [None, uid("unrelated-workflow")])
def test_binding_and_phase_reject_standalone_or_other_workflow_child(workflow_id):
    value, query = successor_stage()
    bound = bind_workflow_view(query, value, **context(query))
    operation = query["predecessors"][0]
    operation["witness"]["workflow_id"] = workflow_id
    seal_operation(operation)
    with pytest.raises(ContractError, match="exact successful child"):
        bind_workflow_view(query, value, **context(query))

    transition = advance_request(bound, "reconciling")
    participant = transition["phase_evidence"]["participants"][0]
    participant["operations"][0]["operation"] = copy.deepcopy(operation)
    seal_phase_participant(transition["phase_evidence"], participant)
    with pytest.raises(ContractError, match="child or workflow identity"):
        validate_phase_evidence(transition, bound)


@pytest.mark.parametrize("workflow_id", [None, uid("unrelated-workflow")])
def test_recovery_rejects_standalone_or_other_workflow_child(workflow_id):
    original = workflow()
    participant = original["proposal"]["participants"][0]
    slot = participant["requests"][0]
    operation = child_operation(slot, participant["owner"], workflow_id=workflow_id)
    proposal, records = scenario(
        original=original,
        kinds=["completed"],
        outcomes={slot["request_id"]: operation},
    )
    with pytest.raises(ContractError, match="substituted original child work"):
        validate_recovery_proposal(proposal, verified_origins=records)


@pytest.mark.parametrize("workflow_id", [None, uid("unrelated-workflow")])
def test_retained_binding_cannot_reassign_its_predecessor_membership(workflow_id):
    original, query = successor_stage()
    bound = bind_workflow_view(query, original, **context(query))
    receipt = bound["bindings"][0]
    operation = receipt["request"]["predecessors"][0]
    operation["witness"]["workflow_id"] = workflow_id
    seal_operation(operation)
    receipt["request_digest"] = digest(receipt["request"])
    with pytest.raises(ContractError, match="exact successful child"):
        validate_workflow(bound)


def test_completed_ancestor_keeps_original_workflow_membership_for_later_binding():
    original, initial = successor_stage()
    predecessor = copy.deepcopy(initial["predecessors"][0])
    proposal, records = scenario(
        original=original,
        kinds=["completed", "unaccepted"],
        outcomes={predecessor["request_id"]: predecessor},
    )
    _, successor = commit(prepare(proposal, records), proposal)
    successor = move(successor, "host-effect")
    participant = successor["proposal"]["participants"][0]
    first, second = participant["requests"]
    assert first["completed"]["operation"] == predecessor
    query = bind_request(
        successor,
        participant,
        second["intent"]["subject"],
        predecessor,
        generation=participant["expected_generation"],
    )
    query["binding"]["plan"].update(
        created_at="2026-10-18T12:00:00Z", expires_at="2026-10-18T13:00:00Z"
    )
    reseal(query["binding"]["plan"])
    trusted = context(query)
    trusted.update(
        verified_driver={
            "principal": successor["driver_principal"],
            "term": successor["driver_term"],
        },
        now="2026-10-18T12:30:00Z",
    )
    bound = bind_workflow_view(query, successor, **trusted)
    assert bound["bindings"][0]["request"]["predecessors"][0] == predecessor
    assert predecessor["witness"]["workflow_id"] == original["id"]
    assert predecessor["witness"]["workflow_id"] != bound["id"]

    changed = copy.deepcopy(query)
    changed["predecessors"][0]["witness"]["workflow_id"] = successor["id"]
    seal_operation(changed["predecessors"][0])
    with pytest.raises(ContractError, match="exact successful child"):
        bind_workflow_view(changed, successor, **trusted)
