"""Installed phase obligations and exact synthetic evidence, not native execution."""

from __future__ import annotations

import copy

import pytest
from fishhat_contracts.handoffs import PHASES, schema_identity, validate_workflow
from fishhat_contracts.validation import SCHEMAS, ContractError, canonical, digest
from fishhat_contracts.workflow_evidence import REQUIREMENTS, validate_phase_evidence
from fishhat_contracts.workflows import PHASE_ACTIONS, advance_workflow

from scripts.check_evidence import evidence_group
from tests.operation_support import seal_operation
from tests.test_contracts import uid
from tests.test_owner_handoffs import V, workflow
from tests.test_plan_review import reseal
from tests.test_workflow_continuations import move, prepare
from tests.test_workflow_inputs import material_handle
from tests.workflow_evidence_support import (
    advance_request,
    advance_with_evidence,
    seal_phase_participant,
    synthetic_operation,
)

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-evidence.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/AdvanceRequest",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-evidence.schema.json#/$defs/InstalledProcedureRequirements",
    ],
    "scope": "complete proposal-bound phase evidence, native prerequisite custody and installed child success barriers",
    "relationship": "candidate",
    "reason": "Explicit synthetic observations and signed outcomes exercise complete evidence joins, interrupted multi-phase work, substitutions, replay and the distinction between ready Plans and successful Operations. They do not authenticate native owners, verify native material or qualify exclusion, fencing, storage or actual effects.",
    "claims": [],
}

CHECK_OVERRIDES = {
    "test_phase_evidence_checks_complete_child_extent": {
        "extent": {
            "purpose": "implementation",
            "authority": [
                "packages/fishhat-contracts/src/fishhat_contracts/workflow_evidence.py#validate_phase_evidence"
            ],
            "scope": "complete-input phase evidence iteration over every required child",
            "relationship": "scoped-witness",
            "reason": "Counts exactly one semantic check per child in a 33-participant closure; this is reference scan/extent evidence, not bounded native execution or a performance claim.",
            "claims": ["engineering:workflow.phase-evidence"],
        },
        "closure": CHECK_PURPOSE,
    }
}


def relocation():
    intent = workflow()["proposal"]
    participant = intent["participants"][0]
    participant["owner"]["tool"] = "app-ops"
    participant["resource"] = {"kind": "app", "id": "demo-app"}
    binding = participant["requests"][0]
    binding["phase"] = "source-quiescing"
    plan = binding["plan"]
    plan["owner"] = copy.deepcopy(participant["owner"])
    checkpoint = "sha256:" + "b" * 64
    plan["subject"] = {
        "action": "app.relocate",
        "resource": copy.deepcopy(participant["resource"]),
        "arguments": {
            "destination_host": "node-b",
            "placement_generation": 3,
            "recovery_basis": {"kind": "checkpoint", "checkpoint_digest": checkpoint},
        },
    }
    for condition in plan["preconditions"]:
        condition.update(owner=participant["owner"], resource=participant["resource"])
    for effect in plan["effects"]:
        effect.update(executor=participant["owner"], resource=participant["resource"])
    plan["input_digests"].append(checkpoint)
    plan["witness"]["owner"] = copy.deepcopy(participant["owner"])
    reseal(plan)
    for handle in intent["content"]:
        handle["owner"] = copy.deepcopy(participant["owner"])
    intent["content"].append(material_handle(participant["owner"], checkpoint))
    intent.update(
        type="relocation",
        target={"relocation": {"owner": participant["owner"], "request_id": V}},
    )
    return prepare(intent)


@pytest.mark.parametrize("procedure", PHASES)
def test_each_installed_procedure_owns_complete_native_and_success_barriers(procedure):
    phases = PHASES[procedure]
    requirements = REQUIREMENTS[procedure]
    assert set(requirements["phases"]) == set(phases[1:])
    assert all(requirements["phases"].values())
    assert set(requirements["child_completion"]) == set(PHASE_ACTIONS[procedure])
    for start, barrier in requirements["child_completion"].items():
        assert phases.index(start) < phases.index(barrier) <= len(phases) - 1


def test_native_requirement_changes_change_the_retained_workflow_schema_identity(monkeypatch):
    uri = "https://fishhat.invalid/contracts/records.schema.json#/$defs/Workflow"
    original = schema_identity(uri)
    changed = copy.deepcopy(SCHEMAS["workflow-evidence.schema.json"])
    changed["$defs"]["InstalledProcedureRequirements"]["const"]["host-drain"]["phases"][
        "quiescent"
    ] += " Require an independently installed additional native check."
    monkeypatch.setitem(SCHEMAS, "workflow-evidence.schema.json", changed)
    assert schema_identity(uri)["digest"] != original["digest"]


def test_phase_progress_requires_independent_evidence_and_preserves_exact_replay():
    value = workflow()
    query = advance_request(value, "draining")
    with pytest.raises(ContractError, match="not independently verified"):
        advance_workflow(query, value)
    result = advance_with_evidence(query, value)
    assert result["phase"] == "draining"
    assert result["advances"][0]["request"]["phase_evidence"] == query["phase_evidence"]
    assert advance_workflow(copy.deepcopy(query), result) == result
    changed = copy.deepcopy(query)
    proof = changed["phase_evidence"]["participants"][0]
    proof["resource_generation"] += 1
    seal_phase_participant(changed["phase_evidence"], proof)
    with pytest.raises(ContractError, match="accepted workflow advance input changed"):
        advance_with_evidence(changed, result)


def test_native_settlement_authority_is_signed_and_cannot_be_claimed_by_driver_input():
    value = move(workflow(), "reconciling")
    query = advance_request(value, "completed")
    evidence = query["phase_evidence"]
    evidence["transition"]["authority"] = "native-owner"
    with pytest.raises(ContractError, match="witness preimage"):
        validate_phase_evidence(query, value, authority="native-owner")
    for proof in evidence["participants"]:
        seal_phase_participant(evidence, proof)
    validate_phase_evidence(query, value, authority="native-owner")
    with pytest.raises(ContractError, match="transition changed"):
        validate_phase_evidence(query, value)
    with pytest.raises(ContractError):
        advance_with_evidence(query, value)


def test_native_settlement_evidence_cannot_authorize_an_intermediate_phase():
    value = workflow()
    query = advance_request(value, "draining")
    evidence = query["phase_evidence"]
    evidence["transition"]["authority"] = "native-owner"
    for proof in evidence["participants"]:
        seal_phase_participant(evidence, proof)
    with pytest.raises(ContractError, match="requires terminal phase"):
        validate_phase_evidence(query, value, authority="native-owner")


@pytest.mark.parametrize("change", ["null", "empty", "missing-native"])
def test_ready_plans_and_empty_witnesses_cannot_stand_in_for_native_phase_evidence(change):
    value = workflow()
    query = advance_request(value, "draining")
    if change == "null":
        query["phase_evidence"] = None
    elif change == "empty":
        query["phase_evidence"]["participants"] = []
    else:
        proof = query["phase_evidence"]["participants"][0]
        proof["native_evidence"] = []
        seal_phase_participant(query["phase_evidence"], proof)
    with pytest.raises(ContractError):
        advance_with_evidence(query, value)


@pytest.mark.parametrize(
    "state,certainty",
    [
        ("accepted", "none"),
        ("running", "known"),
        ("waiting", "known"),
        ("failed", "known"),
        ("cancelled", "known"),
        ("quarantined", "unknown"),
        ("succeeded", "unknown"),
    ],
)
def test_host_effect_success_barrier_rejects_non_success_and_unknown(state, certainty):
    value = move(workflow(), "host-effect")
    query = advance_request(value, "reconciling")
    proof = query["phase_evidence"]["participants"][0]
    outcome = proof["operations"][0]["operation"]
    outcome.update(state=state, effect_certainty=certainty)
    seal_operation(outcome)
    seal_phase_participant(query["phase_evidence"], proof)
    with pytest.raises(ContractError):
        advance_with_evidence(query, value)


@pytest.mark.parametrize(
    "change",
    [
        "proposal",
        "receiver-epoch",
        "generation",
        "phase",
        "requirements",
        "participant",
        "participant-epoch",
        "resource-generation",
        "child",
        "operation-plan",
        "operation-workflow",
        "native-owner",
        "duplicate",
        "missing-outcome",
        "witness-state",
        "witness-subject",
    ],
)
def test_signed_phase_evidence_cannot_substitute_its_exact_context(change):
    value = move(workflow(), "host-effect")
    query = advance_request(value, "reconciling")
    evidence = query["phase_evidence"]
    transition, proof = evidence["transition"], evidence["participants"][0]
    outcome = proof["operations"][0]
    if change == "proposal":
        transition["proposal_digest"] = "sha256:" + "e" * 64
    elif change == "receiver-epoch":
        transition["owner"]["epoch"] = uid("different-epoch")
    elif change == "generation":
        transition["expected_generation"] += 1
    elif change == "phase":
        transition["from_phase"] = "quiescent"
    elif change == "requirements":
        transition["requirements_digest"] = "sha256:" + "e" * 64
    elif change == "participant":
        proof["resource"]["id"] = "another-host"
    elif change == "participant-epoch":
        proof["owner"]["epoch"] = uid("another-participant-epoch")
    elif change == "resource-generation":
        proof["resource_generation"] = 0
    elif change == "child":
        outcome["child"]["request_id"] = uid("another-child")
    elif change == "operation-plan":
        outcome["operation"]["plan_digest"] = "sha256:" + "e" * 64
        seal_operation(outcome["operation"])
    elif change == "operation-workflow":
        outcome["operation"]["witness"]["workflow_id"] = uid("another-workflow")
        seal_operation(outcome["operation"])
    elif change == "native-owner":
        proof["native_evidence"][0]["owner"]["epoch"] = uid("another-native-epoch")
    elif change == "duplicate":
        evidence["participants"].append(copy.deepcopy(proof))
    elif change == "missing-outcome":
        proof["operations"] = []
    seal_phase_participant(evidence, proof)
    if change == "witness-state":
        proof["witness"]["state"] = "succeeded"
    elif change == "witness-subject":
        proof["witness"]["subject_digest"] = value["proposal_digest"]
    with pytest.raises(ContractError):
        advance_with_evidence(query, value)


def test_multi_phase_relocation_requires_native_milestones_before_final_operation_success():
    value = relocation()
    value = advance_with_evidence(advance_request(value, "source-quiescing"), value)
    participant = value["proposal"]["participants"][0]
    binding = participant["requests"][0]
    reference = {"owner": participant["owner"], "request_id": binding["request_id"]}
    active = synthetic_operation(value, participant, binding, state="running")
    for phase in PHASES["relocation"][2:-1]:
        query = advance_request(value, phase, operations={canonical(reference): active})
        value = advance_with_evidence(query, value)
        assert value["phase"] == phase and value["state"] == "active"
    query = advance_request(value, "completed", operations={canonical(reference): active})
    with pytest.raises(ContractError, match="successful known child"):
        advance_with_evidence(query, value)
    successful = synthetic_operation(value, participant, binding)
    query = advance_request(value, "completed", operations={canonical(reference): successful})
    complete = advance_with_evidence(query, value)
    assert complete["state"] == "completed"
    validate_workflow(complete)


@pytest.mark.parametrize("change", ["evidence", "outcome", "history"])
def test_retained_completion_cannot_erase_its_required_proof(change):
    value = move(workflow(), "completed")
    if change == "history":
        value["advances"] = []
    else:
        receipt = value["advances"][-1]
        if change == "evidence":
            receipt["request"]["phase_evidence"] = None
        else:
            evidence = receipt["request"]["phase_evidence"]
            evidence["participants"][0]["operations"] = []
            seal_phase_participant(evidence, evidence["participants"][0])
        receipt["request_digest"] = digest(receipt["request"])
    with pytest.raises(ContractError):
        validate_workflow(value)


def test_phase_evidence_checks_complete_child_extent(monkeypatch):
    """Each synthetic participant is visited, including an omitted tail outcome."""
    from fishhat_contracts import workflow_evidence as module

    intent = workflow()["proposal"]
    template = copy.deepcopy(intent["participants"][0])
    for index in range(1, 33):
        participant = copy.deepcopy(template)
        participant["owner"]["id"] = uid(f"extent-owner-{index}")
        participant["resource"]["id"] = f"node-{index}"
        binding = participant["requests"][0]
        binding["request_id"] = uid(f"extent-child-{index}")
        plan = binding["plan"]
        plan["id"] = uid(f"extent-plan-{index}")
        plan["owner"] = copy.deepcopy(participant["owner"])
        plan["subject"]["resource"] = copy.deepcopy(participant["resource"])
        for condition in plan["preconditions"]:
            condition.update(owner=participant["owner"], resource=participant["resource"])
        for effect in plan["effects"]:
            effect.update(executor=participant["owner"], resource=participant["resource"])
        plan["witness"]["owner"] = copy.deepcopy(participant["owner"])
        reseal(plan)
        intent["participants"].append(participant)
        intent["content"].extend(
            material_handle(participant["owner"], content) for content in plan["input_digests"]
        )
    value = move(prepare(intent), "host-effect")
    query = advance_request(value, "reconciling")
    visited = []
    original = module._child_outcome

    def observe(outcome, *args, **kwargs):
        visited.append(outcome["child"]["request_id"])
        return original(outcome, *args, **kwargs)

    monkeypatch.setattr(module, "_child_outcome", observe)
    with evidence_group("extent"):
        validate_phase_evidence(query, value)
        assert len(visited) == len(set(visited)) == 33
    with evidence_group("closure"):
        proof = query["phase_evidence"]["participants"][-1]
        proof["operations"] = []
        seal_phase_participant(query["phase_evidence"], proof)
        with pytest.raises(ContractError, match="missing required child"):
            validate_phase_evidence(query, value)
