"""Owner-native local admission decisions preserve retained workflow custody."""

from __future__ import annotations

import copy

import pytest
from fishhat_contracts.handoffs import PHASES, validate_workflow
from fishhat_contracts.transfers import validate_transfer_request
from fishhat_contracts.validation import ContractError, canonical, digest, validate
from fishhat_contracts.workflow_abandonment import record_workflow_abandonment_view
from fishhat_contracts.workflow_bindings import validate_bind_request
from fishhat_contracts.workflow_lifecycle import (
    record_native_lifecycle_view,
    require_workflow_child_admission,
)
from fishhat_contracts.workflows import advance_workflow_view, prepare_workflow_view

from tests.test_contracts import uid
from tests.test_owner_handoffs import workflow
from tests.test_workflow_abandonment import abandon
from tests.test_workflow_continuations import move, publication_stage
from tests.test_workflow_recovery import (
    commit,
    finish_transfer,
    native_completion_input,
    prepare,
    scenario,
)
from tests.test_workflow_settlement import ready, settle
from tests.test_workflow_transfer import attestation, capsule, committed, frozen, proposal
from tests.workflow_evidence_support import advance_request, seal_phase_participant
from tests.workflow_lifecycle_support import lifecycle, lifecycle_decision, seal_lifecycle

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/states.json#/workflow_lifecycle",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/states.json#/workflow_meanings",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/NativeLifecycleDecision",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/AdvanceReceipt",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-recovery.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Workflow",
    ],
    "scope": "local lifecycle authority, future admission, exact replay, terminal history and preserved custody",
    "relationship": "candidate",
    "reason": "Synthetic independent native context exercises legal transitions, partial initial cancellation, pause/resume barriers, generation and authority conflicts, transfer orthogonality and rejected history relabeling. Exact field preservation demonstrates no reference transition releases inputs or holds. This does not prove native signing, reconciliation, transaction serialization, remote cancellation or child termination.",
    "claims": [],
}


def record(decision, value, **changes):
    context = {
        "expected_owner": value["owner"],
        "native_authorized": True,
        "verified_decision": copy.deepcopy(decision),
        "verified_driver": {"principal": value["driver_principal"], "term": value["driver_term"]},
        "verified_reconciled": True,
    }
    context.update(changes)
    return record_native_lifecycle_view(decision, value, **context)


@pytest.mark.parametrize("phase", ["prepared", "draining"])
def test_pause_and_resume_require_explicit_local_decisions_and_preserve_custody(phase):
    value = move(workflow(), phase)
    value["holds"] = [uid("retained-workflow-hold")]
    before = canonical(value)
    paused = lifecycle(value, "pause")
    assert paused["state"] == "paused"
    assert paused["generation"] == value["generation"] + 1
    for key in value.keys() - {"generation", "state", "advances"}:
        assert paused[key] == value[key]
    assert paused["advances"][:-1] == value["advances"]
    assert canonical(value) == before
    with pytest.raises(ContractError, match="blocks new child"):
        require_workflow_child_admission(paused)
    following = PHASES[value["type"]][PHASES[value["type"]].index(phase) + 1]
    with pytest.raises(ContractError, match="cannot advance"):
        advance_workflow_view(advance_request(paused, following), paused)
    resumed = lifecycle(paused, "resume")
    assert resumed["state"] == value["state"]
    assert resumed["phase"] == value["phase"]
    assert resumed["holds"] == value["holds"]
    assert resumed["generation"] == value["generation"] + 2
    require_workflow_child_admission(resumed)


def test_pause_rejects_new_binding_but_preserves_already_accepted_binding_replay():
    from fishhat_contracts.workflow_bindings import bind_workflow_view

    from tests.test_workflow_continuations import context

    value, query = publication_stage()
    accepted = bind_workflow_view(query, value, **context(query))
    paused = lifecycle(accepted, "pause")
    assert validate_bind_request(query, paused) == "replay"
    changed = copy.deepcopy(query)
    changed.update(bind_id=uid("new-paused-binding"), expected_generation=paused["generation"])
    with pytest.raises(ContractError, match="state changed"):
        validate_bind_request(changed, paused)


@pytest.mark.parametrize(
    "change", ["authority", "decision", "generation", "term", "driver", "reconciliation"]
)
def test_resume_requires_current_native_authority_and_independent_reconciliation(change):
    value = lifecycle(workflow(), "pause")
    decision = lifecycle_decision(value, "resume")
    context = {}
    if change == "authority":
        context["native_authorized"] = False
    elif change == "decision":
        context["verified_decision"] = None
    elif change == "driver":
        context["verified_driver"] = {"principal": "other-driver", "term": value["driver_term"]}
    elif change == "reconciliation":
        context["verified_reconciled"] = False
    else:
        decision["expected_generation" if change == "generation" else "driver_term"] += 1
        seal_lifecycle(decision, value)
    with pytest.raises(ContractError):
        record(decision, value, **context)


@pytest.mark.parametrize("transfer_phase", [None, "freeze", "commit"])
def test_partial_initial_cancellation_preserves_custody_and_never_claims_remote_stop(
    transfer_phase,
):
    value = capsule()
    value["holds"] = [uid("initial-preparation-hold")]
    assert len(value["prerequisite_witnesses"]) < len(value["participants"])
    with pytest.raises(ContractError, match="complete same-proposal participant agreement"):
        require_workflow_child_admission(value)
    resumed = lifecycle(lifecycle(value, "pause"), "resume")
    with pytest.raises(ContractError, match="complete same-proposal participant agreement"):
        require_workflow_child_admission(resumed)
    if transfer_phase == "freeze":
        value, accepted_transfer = frozen(value)
    elif transfer_phase == "commit":
        value, accepted_transfer = committed(value)
    before = canonical(value)
    decision = lifecycle_decision(value, "cancel")
    result = record(decision, value)
    assert result["state"] == "cancelled"
    assert result["phase"] == "prepared"
    assert canonical(value) == before
    for key in value.keys() - {"generation", "state", "advances"}:
        assert result[key] == value[key]
    with pytest.raises(ContractError, match="blocks new child"):
        require_workflow_child_admission(result)
    with pytest.raises(ContractError, match="cannot advance"):
        advance_workflow_view(advance_request(result, "draining"), result)
    if transfer_phase is not None:
        assert validate_transfer_request(accepted_transfer, result) == "replay"
    assert record(decision, result, verified_decision=None, verified_reconciled=False) == result
    assert (
        prepare_workflow_view(
            {"owner": result["owner"], "proposal": result["proposal"]},
            expected_owner=result["owner"],
            principal="current-reader",
            verified_driver=result["proposal"]["initial_driver"],
            verified_content=[],
            verified_preparation=None,
            retained=result,
        )
        == result
    )
    with pytest.raises(ContractError, match="authority"):
        record(decision, result, native_authorized=False)


@pytest.mark.parametrize("transfer_phase", ["freeze", "commit"])
def test_resume_cannot_clear_an_incomplete_transfer(transfer_phase):
    value = lifecycle(workflow(), "pause")
    value, _ = frozen(value) if transfer_phase == "freeze" else committed(value)
    with pytest.raises(ContractError, match="incomplete driver transfer"):
        lifecycle(value, "resume")
    cancelled = lifecycle(value, "cancel")
    assert cancelled["transfer"] == value["transfer"]
    assert cancelled["driver_term"] == value["driver_term"]


def test_transfer_completion_preserves_pause_until_native_resume():
    value = lifecycle(workflow(), "pause")
    result, accepted = finish_transfer(value)
    assert result["state"] == "paused"
    with pytest.raises(ContractError, match="blocks new child"):
        require_workflow_child_admission(result)
    result = lifecycle(result, "resume")
    assert result["state"] == "prepared"
    assert advance_workflow_view(accepted, result) == result
    require_workflow_child_admission(result)


def test_recovery_required_cannot_resume_or_advance_and_can_cancel_without_releasing():
    value = lifecycle(workflow(), "require-recovery")
    value["holds"] = [uid("unresolved-workflow-hold")]
    attempted_resume = lifecycle_decision(lifecycle(workflow(), "pause"), "resume")
    attempted_resume["from_state"] = "recovery-required"
    with pytest.raises(ContractError, match="illegal workflow lifecycle"):
        record(attempted_resume, value)
    with pytest.raises(ContractError, match="cannot advance"):
        advance_workflow_view(advance_request(value, "draining"), value)
    with pytest.raises(ContractError, match="blocks new child"):
        require_workflow_child_admission(value)
    result = lifecycle(value, "cancel")
    assert result["holds"] == value["holds"]
    assert result["advances"][:-1] == value["advances"]
    recovery, records = scenario(original=result)
    retained = canonical(records)
    successor = prepare(recovery, records)
    with pytest.raises(ContractError, match="explicit abandonment"):
        lifecycle(successor, "cancel")
    _, successor = commit(successor, recovery)
    assert successor["id"] != result["id"]
    assert successor["state"] == "prepared"
    assert canonical(records) == retained
    assert records[0]["record"]["state"] == "cancelled"
    assert records[0]["record"]["holds"] == result["holds"]


@pytest.mark.parametrize("terminal", ["completed", "cancelled"])
@pytest.mark.parametrize("relabeled", ["prepared", "active", "paused", "recovery-required"])
def test_terminal_retained_history_cannot_be_relabeled_for_new_work(terminal, relabeled):
    value = ready()
    value = (
        settle(native_completion_input(value), value)
        if terminal == "completed"
        else lifecycle(value, "cancel")
    )
    value["state"] = relabeled
    with pytest.raises(ContractError, match="lifecycle"):
        validate_workflow(value)
    query = {
        "owner": value["owner"],
        "expected_generation": value["generation"],
        "proposal": proposal(value),
        "phase": "freeze",
        "witnesses": [],
    }
    with pytest.raises(ContractError, match="lifecycle"):
        validate_transfer_request(query, value)


def test_native_lifecycle_identity_replay_cannot_change_input_or_authority():
    value = workflow()
    decision = lifecycle_decision(value, "pause")
    result = record(decision, value)
    changed = copy.deepcopy(decision)
    changed["expected_generation"] += 1
    seal_lifecycle(changed, value)
    with pytest.raises(ContractError, match="accepted lifecycle decision changed"):
        record(changed, result)
    with pytest.raises(ContractError):
        validate("workflow.schema.json", decision, "AdvanceRequest")
    query = advance_request(value, "draining", advance_id=decision["advance_id"])
    with pytest.raises(ContractError, match="changed authority"):
        advance_workflow_view(query, result)


def test_cancelled_history_cannot_append_a_fabricated_resume():
    paused = lifecycle(workflow(), "pause")
    resumed = lifecycle(paused, "resume")
    cancelled = lifecycle(paused, "cancel")
    forged = copy.deepcopy(cancelled)
    receipt = copy.deepcopy(resumed["advances"][-1])
    receipt["decision"]["expected_generation"] += 1
    receipt["generation"] += 1
    forged["generation"] += 1
    forged["state"] = "prepared"
    forged["advances"].append(receipt)
    with pytest.raises(ContractError, match="follows terminal"):
        validate_workflow(forged)


@pytest.mark.parametrize("terminal", ["cancelled", "completed", "abandoned"])
@pytest.mark.parametrize("phase", ["freeze", "commit"])
def test_terminal_history_rejects_later_retained_transfer_phase(terminal, phase):
    base = ready() if terminal == "completed" else workflow()
    if terminal == "abandoned":
        recovery, records = scenario()
        _, base = commit(prepare(recovery, records), recovery)
    value = frozen(base)[0] if phase == "commit" else base
    if terminal == "completed":
        value = settle(native_completion_input(value), value)
    elif terminal == "abandoned":
        _, proof = abandon(recovery, value["owner"])
        value = record_workflow_abandonment_view(value, proof)
    else:
        value = lifecycle(value, "cancel")
    transferring, request = frozen(base) if phase == "freeze" else committed(base)
    request["expected_generation"] = value["generation"]
    with pytest.raises(ContractError, match="terminal workflow"):
        validate_transfer_request(request, value)
    forged = copy.deepcopy(value)
    transfer = copy.deepcopy(transferring["transfer"])
    transfer["accepted_phases"][-1]["expected_generation"] = value["generation"]
    transfer[phase + "_witnesses"] = [
        attestation(
            transfer["proposal"],
            value["owner"],
            "frozen" if phase == "freeze" else "transferred",
            value["generation"] + 1,
        )
    ]
    forged.update(
        generation=value["generation"] + 1,
        transfer=transfer,
        driver_term=transferring["driver_term"],
        driver_principal=transferring["driver_principal"],
    )
    with pytest.raises(ContractError, match="retained transfer follows terminal"):
        validate_workflow(forged)


@pytest.mark.parametrize("admission", ["freeze", "advance", "lifecycle"])
def test_recovery_history_cannot_admit_before_its_committed_preparation(admission):
    recovery, records = scenario()
    _, value = commit(prepare(recovery, records), recovery)
    assert value["recovery"]["commit"]["generation"] == 1
    if admission == "freeze":
        value, _ = frozen(value)
        transfer = value["transfer"]
        transfer["accepted_phases"][0]["expected_generation"] = 0
        transfer["freeze_witnesses"] = [
            attestation(transfer["proposal"], value["owner"], "frozen", 1)
        ]
    else:
        value = move(value, "draining") if admission == "advance" else lifecycle(value, "pause")
        receipt = value["advances"][-1]
        source = "request" if admission == "advance" else "decision"
        original = receipt[source]
        original["expected_generation"] = 0
        receipt["generation"] = 1
        if admission == "advance":
            evidence = original["phase_evidence"]
            evidence["transition"]["expected_generation"] = 0
            for participant in evidence["participants"]:
                seal_phase_participant(evidence, participant)
        else:
            seal_lifecycle(original, value)
        receipt[source + "_digest"] = digest(original)
    with pytest.raises(ContractError, match="precedes committed recovery preparation"):
        validate_workflow(value)


def test_retained_binding_cannot_bypass_an_incomplete_driver_transfer():
    from fishhat_contracts.workflow_bindings import bind_workflow_view

    from tests.test_workflow_continuations import context

    value, request = publication_stage()
    accepted = bind_workflow_view(request, value, **context(request))
    freeze, _ = frozen(value)
    changed = copy.deepcopy(request)
    changed["expected_generation"] = freeze["generation"]
    with pytest.raises(ContractError, match="transfer is incomplete"):
        validate_bind_request(changed, freeze)
    forged = copy.deepcopy(accepted)
    forged["transfer"] = copy.deepcopy(freeze["transfer"])
    forged["generation"] += 1
    receipt = forged["bindings"][-1]
    receipt["generation"] += 1
    receipt["request"]["expected_generation"] += 1
    receipt["request_digest"] = digest(receipt["request"])
    with pytest.raises(ContractError, match="binding was recorded inside a pending transfer"):
        validate_workflow(forged)


def test_retained_recovery_commit_cannot_invent_an_earlier_successor_generation():
    from fishhat_contracts.workflow_recovery import commit_workflow_recovery_view

    recovery, records = scenario()
    prepared = prepare(recovery, records)
    request, value = commit(prepared, recovery)
    changed = copy.deepcopy(request)
    changed["expected_generation"] = 1
    with pytest.raises(ContractError, match="recovery commit generation changed"):
        commit_workflow_recovery_view(
            changed,
            prepared,
            recovery_authorized=True,
            verified_preparations=changed["preparations"],
        )
    forged = copy.deepcopy(value)
    forged["generation"] = 2
    receipt = forged["recovery"]["commit"]
    receipt.update(request=changed, request_digest=digest(changed), generation=2)
    with pytest.raises(ContractError, match="first successor generation"):
        validate_workflow(forged)
