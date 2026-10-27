"""Explicit owner-native final settlement preserves driver and accepted custody."""

from __future__ import annotations

import copy

import pytest
from fishhat_contracts.handoffs import PHASES, validate_workflow
from fishhat_contracts.validation import ContractError, canonical, digest, validate
from fishhat_contracts.workflow_settlement import record_native_completion
from fishhat_contracts.workflows import advance_workflow

from tests.operation_support import seal_operation
from tests.test_contracts import uid
from tests.test_owner_handoffs import workflow
from tests.test_workflow_continuations import move
from tests.test_workflow_recovery import finish_transfer, native_completion_input
from tests.test_workflow_transfer import committed, completion_request, frozen
from tests.workflow_evidence_support import advance_request, seal_phase_participant
from tests.workflow_lifecycle_support import lifecycle

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/NativeCompletion",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/AdvanceReceipt",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-evidence.schema.json#/$defs/PhaseEvidence",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/WorkflowTransfer",
    ],
    "scope": "native final settlement authority, exact replay and immutable transfer custody",
    "relationship": "candidate",
    "reason": "Synthetic protected native context challenges authority substitution, final-phase and successful-outcome boundaries, current generation, replay and impossible historical driver admission. Exact field preservation demonstrates the reference transition does not authorize new work, release holds or finish a pending transfer; it does not qualify native authorization, observation, authentication or persistence.",
    "claims": [],
}


def ready(transfer_phase=None, state="active"):
    value = workflow()
    value = move(value, PHASES[value["type"]][-2])
    if state == "paused":
        value = lifecycle(value, "pause")
    if transfer_phase == "freeze":
        value, _ = frozen(value)
    elif transfer_phase == "commit":
        value, _ = committed(value)
    elif transfer_phase == "completed":
        value, _ = finish_transfer(value)
    return value


def settle(query, value, **changes):
    context = {
        "expected_owner": copy.deepcopy(value["owner"]),
        "native_authorized": True,
        "verified_phase_evidence": copy.deepcopy(query["phase_evidence"]),
    }
    context.update(changes)
    return record_native_completion(query, value, **context)


@pytest.mark.parametrize("transfer_phase", [None, "freeze", "commit", "completed"])
@pytest.mark.parametrize("state", ["active", "paused"])
def test_native_completion_preserves_all_other_custody_and_exact_replay(transfer_phase, state):
    value = ready(transfer_phase, state)
    query = native_completion_input(value)
    before = canonical(value)
    result = settle(query, value)
    assert result["phase"] == PHASES[value["type"]][-1]
    assert result["state"] == "completed"
    assert result["generation"] == value["generation"] + 1
    for key in value.keys() - {"generation", "phase", "state", "advances"}:
        assert result[key] == value[key]
    assert result["advances"][:-1] == value["advances"]
    receipt = result["advances"][-1]
    assert receipt["authority"] == "native-owner"
    assert receipt["completion"] == query
    assert receipt["completion_digest"] == digest(query)
    assert canonical(value) == before
    result["generation"] += 1
    assert settle(query, result, verified_phase_evidence=None) == result
    with pytest.raises(ContractError, match="authority"):
        settle(query, result, native_authorized=False)


@pytest.mark.parametrize("change", ["authority", "evidence", "owner", "generation", "term"])
def test_native_completion_requires_independent_current_owner_context(change):
    value = ready("commit")
    query = native_completion_input(value)
    context = {}
    if change == "authority":
        context["native_authorized"] = False
    elif change == "evidence":
        context["verified_phase_evidence"] = None
    elif change == "owner":
        context["expected_owner"] = {**value["owner"], "epoch": uid("other-native-owner")}
    else:
        field = "expected_generation" if change == "generation" else "driver_term"
        query[field] += 1
        query["phase_evidence"]["transition"][field] = query[field]
        for proof in query["phase_evidence"]["participants"]:
            seal_phase_participant(query["phase_evidence"], proof)
    with pytest.raises(ContractError):
        settle(query, value, **context)


@pytest.mark.parametrize("phase", ["prepared", "draining", "host-effect"])
def test_native_completion_cannot_skip_to_the_final_phase(phase):
    value = workflow()
    if phase != value["phase"]:
        value = move(value, phase)
    with pytest.raises(ContractError, match="final installed transition"):
        settle(native_completion_input(value), value)


@pytest.mark.parametrize("state", ["cancelled", "recovery-required", "completed"])
def test_native_completion_cannot_revive_a_restricted_lifecycle(state):
    value = ready()
    if state == "completed":
        value = move(value, PHASES[value["type"]][-1])
    else:
        value = lifecycle(value, "cancel" if state == "cancelled" else "require-recovery")
    with pytest.raises(ContractError, match="final installed transition"):
        settle(native_completion_input(value), value)


@pytest.mark.parametrize("state,certainty", [("failed", "known"), ("quarantined", "unknown")])
def test_native_completion_requires_successful_known_child_outcomes(state, certainty):
    value = ready("freeze")
    query = native_completion_input(value)
    proof = query["phase_evidence"]["participants"][0]
    operation = proof["operations"][0]["operation"]
    operation.update(state=state, effect_certainty=certainty)
    seal_operation(operation)
    seal_phase_participant(query["phase_evidence"], proof)
    with pytest.raises(ContractError):
        settle(query, value)


def test_native_replay_cannot_change_input_or_become_a_driver_request():
    value = ready()
    query = native_completion_input(value)
    result = settle(query, value)
    changed = copy.deepcopy(query)
    changed["expected_generation"] += 1
    with pytest.raises(ContractError, match="accepted native completion input changed"):
        settle(changed, result)
    with pytest.raises(ContractError):
        validate("workflow.schema.json", query, "AdvanceRequest")
    driver = advance_request(value, PHASES[value["type"]][-1], advance_id=query["advance_id"])
    native_claim = {**driver, "authority": "native-owner"}
    with pytest.raises(ContractError):
        validate("workflow.schema.json", native_claim, "AdvanceRequest")
    with pytest.raises(ContractError, match="changed authority"):
        advance_workflow(driver, result)
    driver["phase_evidence"] = copy.deepcopy(query["phase_evidence"])
    with pytest.raises(ContractError):
        validate("workflow.schema.json", driver, "AdvanceRequest")


@pytest.mark.parametrize("transfer_phase", ["freeze", "commit"])
def test_history_rejects_a_fabricated_driver_advance_during_pending_transfer(transfer_phase):
    value = ready(transfer_phase)
    query = advance_request(value, PHASES[value["type"]][-1])
    with pytest.raises(ContractError, match="transfer"):
        advance_workflow(query, value, verified_phase_evidence=query["phase_evidence"])
    forged = copy.deepcopy(value)
    forged.update(generation=value["generation"] + 1, phase=query["phase"], state="completed")
    forged["advances"].append(
        {
            "authority": "driver",
            "request": query,
            "request_digest": digest(query),
            **{key: forged[key] for key in ("generation", "driver_term", "phase", "state")},
        }
    )
    with pytest.raises(ContractError, match="inside a pending transfer"):
        validate_workflow(forged)


def test_native_terminal_history_cannot_accept_a_later_transfer_completion():
    value = ready("commit")
    value = settle(native_completion_input(value), value)
    query = completion_request(value)
    query["phase"] = value["phase"]
    with pytest.raises(ContractError, match="cannot advance"):
        advance_workflow(query, value)
    forged = copy.deepcopy(value)
    forged["transfer"]["phase"] = "completed"
    forged["transfer"]["commit_witnesses"] = copy.deepcopy(
        query["transfer_completion"]["witnesses"]
    )
    forged["generation"] += 1
    forged["advances"].append(
        {
            "authority": "driver",
            "request": query,
            "request_digest": digest(query),
            **{key: forged[key] for key in ("generation", "driver_term", "phase", "state")},
        }
    )
    with pytest.raises(ContractError, match="follows terminal settlement"):
        validate_workflow(forged)
