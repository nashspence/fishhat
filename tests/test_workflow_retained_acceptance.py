"""Recovery joins signed accepted facts across the complete original custody closure."""

from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_contracts.handoffs import validate_workflow
from fishhat_contracts.record_delivery import RecordSnapshot
from fishhat_contracts.validation import ContractError, canonical, digest
from fishhat_contracts.witness import verify
from fishhat_contracts.workflow_bindings import bind_workflow
from fishhat_contracts.workflow_evidence import phase_subject
from fishhat_contracts.workflow_recovery import validate_recovery_proposal

from tests.operation_support import seal_operation
from tests.test_contracts import uid
from tests.test_owner_handoffs import workflow
from tests.test_plan_review import reseal
from tests.test_workflow_continuations import (
    context,
    move,
    successor_stage,
)
from tests.test_workflow_continuations import (
    prepare as prepare_original,
)
from tests.test_workflow_evidence import relocation
from tests.test_workflow_recovery import (
    commit,
    native_completion,
    participant_capsule,
    prepare,
    scenario,
)
from tests.test_workflow_transfer import capsule
from tests.workflow_evidence_support import (
    advance_request,
    advance_with_evidence,
    seal_phase_participant,
    synthetic_operation,
)

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-recovery.schema.json#/$defs/ChildDisposition",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-recovery.schema.json#/$defs/RecoveryProposal",
    ],
    "scope": "complete retained acceptance joins, original Operation identity and exact successful outcome preservation",
    "relationship": "candidate",
    "reason": "Valid signed synthetic origins exercise the public recovery validator with conflicting dispositions and exact nonexecutable successors, including evidence retained only by another owner. Native latest-snapshot selection, retirement, authentication and effect cessation remain independently supplied context and are not qualified.",
    "claims": [],
}


def _phase_outcomes(value):
    result = {}
    for receipt in value["advances"]:
        source = receipt.get("request", receipt.get("completion", {}))
        phase = source.get("phase_evidence")
        if phase is not None:
            for participant in phase["participants"]:
                verify(
                    participant["witness"],
                    Ed25519PrivateKey.from_private_bytes(b"\x31" * 32).public_key(),
                    participant["owner"],
                    digest(phase_subject(phase["transition"], participant)),
                )
                for outcome in participant["operations"]:
                    operation = outcome["operation"]
                    verify(
                        operation["witness"],
                        Ed25519PrivateKey.from_private_bytes(b"\x17" * 32).public_key(),
                        operation["owner"],
                        digest({k: v for k, v in operation.items() if k != "witness"}),
                    )
                    result[canonical(outcome["child"])] = operation
    return result


def _retained_case(source):
    if source == "predecessor":
        value, request = successor_stage()
        value = bind_workflow(request, value, **context(request))
        operation = request["predecessors"][0]
        reference = {"owner": operation["owner"], "request_id": operation["request_id"]}
        return value, {canonical(reference): operation}, ["completed", "unaccepted"], 0
    if source == "native":
        proposal = capsule()["proposal"]
        participant = proposal["participants"][1]
        original_owner = copy.deepcopy(participant["owner"])
        participant["owner"]["tool"] = "app-ops"
        participant["resource"]["kind"] = "app"
        slot = participant["requests"][0]
        slot["phase"] = "reconciling"
        plan = slot["plan"]
        plan["owner"] = copy.deepcopy(participant["owner"])
        plan["witness"]["owner"] = copy.deepcopy(participant["owner"])
        plan["subject"] = {
            "action": "app.restart",
            "resource": copy.deepcopy(participant["resource"]),
            "arguments": {"components": []},
        }
        for condition in plan["preconditions"]:
            condition.update(owner=participant["owner"], resource=participant["resource"])
        for effect in plan["effects"]:
            effect.update(executor=participant["owner"], resource=participant["resource"])
        for handle in proposal["content"]:
            if handle["owner"] == original_owner:
                handle["owner"] = copy.deepcopy(participant["owner"])
        reseal(plan)
        value = native_completion(move(prepare_original(proposal), "reconciling"))
        return value, _phase_outcomes(value), ["completed", "completed"], 1
    value = move(workflow(), "reconciling")
    outcomes = _phase_outcomes(value)
    if source == "completed":
        proposal, records = scenario(original=value, kinds=["completed"], outcomes=outcomes)
        _, value = commit(prepare(proposal, records), proposal)
        slot = value["proposal"]["participants"][0]["requests"][0]
        reference = {"owner": value["owner"], "request_id": slot["request_id"]}
        outcomes = {canonical(reference): slot["completed"]["operation"]}
    return value, outcomes, ["completed"], 0


@pytest.mark.parametrize("source", ["driver", "native", "predecessor", "completed"])
def test_recovery_cannot_call_retained_accepted_work_unaccepted(source):
    value, outcomes, kinds, index = _retained_case(source)
    validate_workflow(value)
    kinds[index] = "unaccepted"
    proposal, records = scenario(original=value, kinds=kinds, outcomes=outcomes)
    with pytest.raises(
        ContractError, match="retained accepted workflow child cannot become unaccepted"
    ):
        validate_recovery_proposal(proposal, verified_origins=records)


@pytest.mark.parametrize("source", ["driver", "native", "predecessor", "completed"])
@pytest.mark.parametrize("historical", [False, True], ids=["current", "restored"])
def test_recovery_preserves_exact_retained_success_as_nonexecutable(source, historical):
    value, outcomes, kinds, _ = _retained_case(source)
    before = canonical(value)
    proposal, records = scenario(
        original=value, kinds=kinds, outcomes=outcomes, historical=historical
    )
    validate_recovery_proposal(proposal, verified_origins=records)
    _, successor = commit(prepare(proposal, records), proposal)
    completed = [
        slot["completed"]["operation"]
        for participant in successor["proposal"]["participants"]
        for slot in participant["requests"]
        if "completed" in slot
    ]
    assert completed == list(outcomes.values())
    assert canonical(value) == before


@pytest.mark.parametrize("state", ["accepted", "running"])
def test_recovery_cannot_reinterpret_retained_inflight_work_as_unaccepted(state):
    value = move(relocation(), "source-quiescing")
    participant = value["proposal"]["participants"][0]
    slot = participant["requests"][0]
    operation = synthetic_operation(value, participant, slot, state=state)
    reference = {"owner": participant["owner"], "request_id": slot["request_id"]}
    query = advance_request(value, "source-fenced", operations={canonical(reference): operation})
    value = advance_with_evidence(query, value)
    validate_workflow(value)
    _phase_outcomes(value)
    proposal, records = scenario(original=value)
    with pytest.raises(
        ContractError, match="retained accepted workflow child cannot become unaccepted"
    ):
        validate_recovery_proposal(proposal, verified_origins=records)


@pytest.mark.parametrize("change", ["identity", "outcome"])
def test_recovery_rejects_substitution_of_retained_success(change):
    value, outcomes, kinds, _ = _retained_case("driver")
    original = next(iter(outcomes.values()))
    replacement = copy.deepcopy(original)
    if change == "identity":
        replacement["id"] = uid("substituted-current-authority-operation")
    else:
        replacement["generation"] += 1
    seal_operation(replacement)
    proposal, records = scenario(
        original=value, kinds=kinds, outcomes={original["request_id"]: replacement}
    )
    expected = (
        "Operation identity changed"
        if change == "identity"
        else "successful workflow child outcome"
    )
    with pytest.raises(ContractError, match=expected):
        validate_recovery_proposal(proposal, verified_origins=records)


def test_recovery_cannot_replace_retained_success_with_failure_and_separate_recovery():
    value, _, _, _ = _retained_case("driver")
    proposal, records = scenario(original=value, kinds=["recovered"])
    with pytest.raises(ContractError, match="requires completed disposition"):
        validate_recovery_proposal(proposal, verified_origins=records)


def _replace_origin(proposal, records, index, record):
    validate_workflow(record)
    reference = RecordSnapshot(record, uid("retained-origin-" + record["owner"]["id"])).reference
    records[index] = {"record": record, "reference": reference, "custody": None}
    proposal["origins"][index] = {"reference": reference, "custody": None}


def test_recovery_joins_evidence_retained_only_by_another_original_owner():
    prepared = capsule()
    value = move(prepared, "reconciling")
    outcomes = _phase_outcomes(value)
    proposal, records = scenario(
        original=value, kinds=["completed", "completed"], outcomes=outcomes
    )
    _replace_origin(proposal, records, 0, participant_capsule(prepared, prepared["owner"]))
    validate_recovery_proposal(proposal, verified_origins=records)
    changed = copy.deepcopy(proposal)
    disposition = changed["children"][0]
    disposition["kind"] = "unaccepted"
    del disposition["operation"]
    slot = changed["successor"]["participants"][0]["requests"][0]
    ready, _ = scenario(original=prepared)
    changed["successor"]["participants"][0]["requests"][0] = ready["successor"]["participants"][0][
        "requests"
    ][0]
    assert (
        slot["request_id"] == changed["successor"]["participants"][0]["requests"][0]["request_id"]
    )
    with pytest.raises(
        ContractError, match="retained accepted workflow child cannot become unaccepted"
    ):
        validate_recovery_proposal(changed, verified_origins=records)


@pytest.mark.parametrize("change", ["identity", "outcome"])
def test_recovery_rejects_conflicting_retained_facts_across_original_owners(change):
    value = move(capsule(), "reconciling")
    outcomes = _phase_outcomes(value)
    proposal, records = scenario(
        original=value, kinds=["completed", "completed"], outcomes=outcomes
    )
    other = copy.deepcopy(records[1]["record"])
    phase = other["advances"][-1]["request"]["phase_evidence"]
    participant = phase["participants"][0]
    operation = participant["operations"][0]["operation"]
    if change == "identity":
        operation["id"] = uid("conflicting-retained-operation")
    else:
        operation["generation"] += 1
    seal_operation(operation)
    seal_phase_participant(phase, participant)
    other["advances"][-1]["request_digest"] = digest(other["advances"][-1]["request"])
    _replace_origin(proposal, records, 1, other)
    expected = (
        "Operation identity changed" if change == "identity" else "successful outcome changed"
    )
    with pytest.raises(ContractError, match=expected):
        validate_recovery_proposal(proposal, verified_origins=records)
