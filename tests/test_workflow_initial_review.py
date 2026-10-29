"""Fresh first-child review after an installed barrier, without replanning accepted work."""

from __future__ import annotations

import copy

import pytest
from fishhat_contracts.handoffs import validate_workflow
from fishhat_contracts.validation import ContractError, canonical, digest
from fishhat_contracts.workflow_bindings import bind_workflow
from fishhat_contracts.workflows import validate_workflow_proposal

from scripts.check_evidence import evidence_group
from tests.operation_support import seal_operation
from tests.test_contracts import uid
from tests.test_owner_handoffs import workflow
from tests.test_plan_review import reseal
from tests.test_workflow_continuations import bind_request, context, move, prepare
from tests.test_workflow_inputs import material_handle
from tests.test_workflow_recovery import commit as commit_recovery
from tests.test_workflow_recovery import prepare as prepare_recovery
from tests.test_workflow_recovery import scenario
from tests.workflow_evidence_support import advance_request, seal_phase_participant
from tests.workflow_evidence_support import advance_with_evidence as advance_workflow

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/ContinuationIntent",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/BindRequest",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-evidence.schema.json#/$defs/InstalledProcedureRequirements",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-recovery.schema.json#/$defs/RecoveryProposal",
    ],
    "scope": "installed first-child review barrier, fresh current-generation review, immutable binding and safe later expiry recovery",
    "relationship": "candidate",
    "reason": "A synthetic provider/consumer workflow delays first consumer review until exact provider success is retained. Negative cases challenge invented dependencies, premature or late binding, stale review and changed accepted identity; supersession preserves known provider success. These cases do not establish native verification, authorization, persistent custody or execution.",
    "claims": [],
}

CHECK_OVERRIDES = {
    "test_consumer_first_plan_is_reviewed_after_provider_success_without_supersession": {
        "contract": CHECK_PURPOSE,
        "extent": {
            "purpose": "implementation",
            "authority": [
                "packages/fishhat-contracts/src/fishhat_contracts/workflow_bindings.py#validate_workflow_bindings"
            ],
            "scope": "complete retained first-child binding request and installed dependency outcome through workflow completion",
            "relationship": "scoped-witness",
            "reason": "Compares the entire accepted binding request and provider outcome after later phase validation, preserving all original inputs and phase evidence. This establishes reference retained-input extent, not native review, custody or execution.",
            "claims": ["engineering:workflow.bindings"],
        },
    }
}

LATE_NOW = "2026-10-18T12:30:00Z"


def interface_proposal(consumers=1):
    original = workflow()["proposal"]
    template = original["participants"][0]
    selected = copy.deepcopy(original)
    selected["type"] = "interface-binding"
    selected["participants"] = []
    selected["content"] = []
    references = []
    for index in range(consumers + 1):
        owner = {
            "tool": "app-ops",
            "id": uid(f"interface-owner-{index}"),
            "epoch": uid("interface-epoch"),
        }
        resource = {"kind": "app", "id": f"interface-app-{index}"}
        participant = {
            "owner": owner,
            "resource": resource,
            "expected_generation": 9,
            "requests": [],
        }
        identifier = uid(f"interface-child-{index}")
        subject = {"action": "app.repair", "resource": copy.deepcopy(resource), "arguments": {}}
        phase = "provider-verified" if index == 0 else "consumer-adopting"
        slot = {"request_id": identifier, "phase": phase}
        if index == 0:
            plan = copy.deepcopy(template["requests"][0]["plan"])
            plan.update(id=uid("interface-provider-plan"), owner=owner, subject=subject)
            for condition in plan["preconditions"]:
                condition.update(owner=owner, resource=resource)
            for effect in plan["effects"]:
                effect.update(executor=owner, resource=resource, action="admitted-app-repair")
            plan["witness"]["owner"] = owner
            reseal(plan)
            slot["plan"] = plan
            selected["content"].extend(
                material_handle(owner, item) for item in plan["input_digests"]
            )
        else:
            slot["intent"] = {"kind": "reviewed-initial", "subject": subject}
        participant["requests"].append(slot)
        selected["participants"].append(participant)
        references.append({"owner": owner, "request_id": identifier})
    selected["target"] = {"provider": references[0], "consumers": references[1:]}
    validate_workflow_proposal(selected)
    return selected


def initial_stage(consumers=1):
    value = prepare(interface_proposal(consumers))
    return move(value, "consumer-adopting")


def initial_request(value, index=1):
    participant = value["proposal"]["participants"][index]
    intent = participant["requests"][0]["intent"]
    query = bind_request(value, participant, intent["subject"], None, generation=12)
    query["predecessors"] = []
    plan = query["binding"]["plan"]
    plan.update(created_at="2026-10-18T12:00:00Z", expires_at="2026-10-18T13:00:00Z")
    reseal(plan)
    trusted = context(query)
    trusted["now"] = LATE_NOW
    return query, trusted


def provider_outcome(value):
    barrier = next(
        receipt for receipt in value["advances"] if receipt["phase"] == "consumer-adopting"
    )
    return barrier["request"]["phase_evidence"]["participants"][0]["operations"][0]["operation"]


def test_consumer_first_plan_is_reviewed_after_provider_success_without_supersession():
    value = initial_stage()
    proposal = copy.deepcopy(value["proposal"])
    provider = copy.deepcopy(provider_outcome(value))
    query, trusted = initial_request(value)
    with evidence_group("contract"):
        assert provider["state"] == "succeeded"
        assert "plan" not in proposal["participants"][1]["requests"][0]
        assert (
            query["binding"]["plan"]["created_at"]
            > proposal["participants"][0]["requests"][0]["plan"]["expires_at"]
        )
        bound = bind_workflow(query, value, **trusted)
        assert bound["id"] == value["id"]
        assert bound["proposal"] == proposal
        assert provider_outcome(bound) == provider
        assert (
            bound["bindings"][0]["request"]["binding"]["plan"]["created_at"]
            == "2026-10-18T12:00:00Z"
        )
        assert query["binding"]["plan"]["preconditions"][0]["generation"] == 12
        assert proposal["participants"][1]["expected_generation"] == 9
        assert "recovery" not in bound
        assert bind_workflow(query, bound, **{**trusted, "now": "2026-10-19T00:00:00Z"}) == bound
        final = move(bound, "completed")
        assert final["state"] == "completed"
    with evidence_group("extent"):
        assert len(final["bindings"]) == 1
        assert final["bindings"][0]["request"] == query
        assert provider_outcome(final) == provider


@pytest.mark.parametrize("phase", ["prepared", "provider-verified"])
def test_initial_review_cannot_precede_the_installed_barrier(phase):
    value = move(prepare(interface_proposal()), phase)
    query, trusted = initial_request(value)
    with pytest.raises(ContractError):
        bind_workflow(query, value, **trusted)


def test_failed_provider_cannot_create_a_consumer_review_barrier():
    value = move(prepare(interface_proposal()), "provider-verified")
    query = advance_request(value, "consumer-adopting")
    proof = query["phase_evidence"]["participants"][0]
    operation = proof["operations"][0]["operation"]
    operation["state"] = "failed"
    seal_operation(operation)
    seal_phase_participant(query["phase_evidence"], proof)
    with pytest.raises(ContractError, match="successful known child"):
        advance_workflow(query, value)


@pytest.mark.parametrize("change", ["first-phase", "later-child", "graph", "resource"])
def test_initial_intent_cannot_expand_the_installed_procedure(change):
    selected = interface_proposal()
    if change == "first-phase":
        slot = selected["participants"][0]["requests"][0]
        subject = slot.pop("plan")["subject"]
        slot["intent"] = {"kind": "reviewed-initial", "subject": subject}
    else:
        participant = selected["participants"][1]
        slot = participant["requests"][0]
        if change == "later-child":
            later = copy.deepcopy(slot)
            later["request_id"] = uid("invented-later-initial")
            participant["requests"].append(later)
        elif change == "graph":
            slot["intent"]["predecessor"] = selected["target"]["provider"]
        else:
            slot["intent"]["subject"]["resource"]["id"] = "unrelated-app"
    with pytest.raises(ContractError):
        validate_workflow_proposal(selected)


@pytest.mark.parametrize("change", ["generation", "expiry", "subject", "predecessor"])
def test_initial_review_still_requires_fresh_exact_authorized_context(change):
    value = initial_stage()
    query, trusted = initial_request(value)
    if change == "generation":
        trusted["current_generations"][0]["generation"] += 1
    elif change == "expiry":
        trusted["now"] = "2026-10-18T13:00:00Z"
    elif change == "subject":
        query["binding"]["plan"]["subject"]["action"] = "app.deploy"
        query["binding"]["plan"]["subject"]["arguments"] = {
            "release_digest": query["binding"]["plan"]["input_digests"][0]
        }
        reseal(query["binding"]["plan"])
    else:
        query["predecessors"] = [copy.deepcopy(provider_outcome(value))]
    with pytest.raises(ContractError):
        bind_workflow(query, value, **trusted)


@pytest.mark.parametrize("after_exit", [False, True])
def test_retained_initial_binding_cannot_be_moved_outside_its_phase_window(after_exit):
    value = initial_stage()
    query, trusted = initial_request(value)
    bound = bind_workflow(query, value, **trusted)
    if after_exit:
        bound = move(bound, "consumer-verified")
    receipt = bound["bindings"][0]
    receipt["request"]["expected_generation"] = bound["generation"] if after_exit else 0
    receipt["generation"] = receipt["request"]["expected_generation"] + 1
    receipt["request_digest"] = digest(receipt["request"])
    bound["generation"] = max(bound["generation"], receipt["generation"])
    with pytest.raises(ContractError):
        validate_workflow(bound)


def test_binding_expiry_cannot_replace_its_plan_and_uses_safe_successor_recovery():
    value = initial_stage()
    query, trusted = initial_request(value)
    bound = bind_workflow(query, value, **trusted)
    changed = copy.deepcopy(query)
    changed["bind_id"] = uid("replacement-bind")
    changed["expected_generation"] = bound["generation"]
    changed["binding"]["plan"].update(
        id=uid("replacement-plan"),
        created_at="2026-10-19T00:00:00Z",
        expires_at="2026-10-19T01:00:00Z",
    )
    reseal(changed["binding"]["plan"])
    with pytest.raises(ContractError, match="already bound"):
        bind_workflow(changed, bound, **trusted)
    provider = provider_outcome(bound)
    selected, records = scenario(
        original=bound,
        kinds=["completed", "unaccepted"],
        outcomes={provider["request_id"]: provider},
    )
    _, successor = commit_recovery(prepare_recovery(selected, records), selected)
    children = successor["proposal"]["participants"]
    assert children[0]["requests"][0]["completed"]["operation"] == provider
    assert children[1]["requests"][0]["request_id"] != query["child"]["request_id"]
    assert canonical(bound["bindings"][0]["request"]) == canonical(query)
