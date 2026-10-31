"""Independent destination obligations in the installed relocation procedure.

All native material and verified context here are synthetic. These tests establish
contract joins and custody, not real writer cessation, fencing or production moves.
"""

from __future__ import annotations

import copy
import json

import pytest
from fishhat_contracts.handoffs import PHASES, validate_workflow
from fishhat_contracts.transfers import validate_transfer_request
from fishhat_contracts.validation import ContractError, canonical, validate
from fishhat_contracts.workflow_evidence import validate_phase_evidence
from fishhat_contracts.workflow_lifecycle import require_workflow_child_admission
from fishhat_contracts.workflow_recovery import (
    commit_workflow_recovery_view,
    validate_recovery_proposal,
)
from fishhat_contracts.workflows import (
    advance_workflow_view,
    prepare_workflow_view,
    validate_workflow_proposal,
)

from tests.linear_support import assert_linear, measure
from tests.support import FIXTURES
from tests.test_contracts import uid
from tests.test_owner_handoffs import preparation_witness
from tests.test_workflow_continuations import prepare
from tests.test_workflow_initial_custody import retire, retirement
from tests.test_workflow_recovery import commit, scenario
from tests.test_workflow_recovery import prepare as prepare_recovery
from tests.test_workflow_transfer import commit_input, frozen
from tests.workflow_evidence_support import (
    advance_request,
    advance_with_evidence,
    seal_phase_participant,
    synthetic_operation,
)

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/Participant",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json#/$defs/RelocationTarget",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-evidence.schema.json#/$defs/InstalledProcedureRequirements",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-recovery.schema.json#/$defs/RecoveryProposal",
    ],
    "scope": "exact destination host role, complete two-owner preparation and phase evidence, transfer and restored recovery custody",
    "relationship": "candidate",
    "reason": "Distinct synthetic source/destination owners walk every phase and challenge omission, role substitution, missing native verification, driver loss and incomplete recovery. No native dispatch, authentication, exclusion or fencing is qualified.",
    "claims": [],
}

CHECK_OVERRIDES = {
    "test_relocation_destination_evidence_complete_linear_work": {
        "purpose": "implementation",
        "authority": [
            "packages/fishhat-contracts/src/fishhat_contracts/workflow_evidence.py#validate_phase_evidence",
            "release.toml#/engineering",
        ],
        "scope": "complete destination native-material validation over sixteenfold extent",
        "relationship": "scoped-witness",
        "reason": "Executed work counters include every supplied native handle and signed proof while source and destination remain distinct participants. Setup is outside measurement; no total evidence cap or native qualification is introduced.",
        "claims": ["engineering:workflow.phase-evidence"],
    }
}


def proposal():
    return json.loads((FIXTURES / "workflow/relocation-proposal.json").read_text())


def participants():
    intent = proposal()
    return [prepare(intent, participant["owner"]) for participant in intent["participants"]]


def child_context(value, *, state="running"):
    source = value["proposal"]["participants"][0]
    binding = source["requests"][0]
    identity = {"owner": source["owner"], "request_id": binding["request_id"]}
    return {canonical(identity): synthetic_operation(value, source, binding, state=state)}


def advance_pair(values, phase, *, state="running"):
    outcomes = child_context(values[0], state=state)
    return [
        advance_with_evidence(advance_request(value, phase, operations=outcomes), value)
        for value in values
    ]


def test_two_owner_relocation_retains_destination_authority_through_every_phase():
    values = participants()
    source, destination = values[0]["proposal"]["participants"]
    assert source["owner"] != destination["owner"]
    assert destination["owner"]["tool"] == "host-ops"
    assert destination["requests"] == []
    plan = source["requests"][0]["plan"]
    assert any(effect["executor"] == destination["owner"] for effect in plan["effects"])
    for phase in PHASES["relocation"][1:]:
        values = advance_pair(
            values, phase, state="succeeded" if phase == "completed" else "running"
        )
        for value in values:
            validate_workflow(value)
            assert value["participants"][1]["native_role"] == "relocation-destination"
            assert value["participants"][1]["request_ids"] == []
            proofs = value["advances"][-1]["request"]["phase_evidence"]["participants"]
            assert [proof["owner"] for proof in proofs] == [source["owner"], destination["owner"]]
            assert proofs[1]["operations"] == [] and proofs[1]["native_evidence"]
    assert all(value["state"] == "completed" for value in values)


@pytest.mark.parametrize(
    "change",
    ["missing-participant", "missing-target", "owner", "host", "unmarked", "fake-child", "role"],
)
def test_relocation_requires_exact_destination_and_childless_role(change):
    intent = proposal()
    destination = intent["participants"][1]
    if change == "missing-participant":
        intent["participants"].pop()
    elif change == "missing-target":
        del intent["target"]["destination"]
    elif change == "owner":
        intent["target"]["destination"]["owner"]["epoch"] = uid("other-destination-epoch")
    elif change == "host":
        destination["resource"]["id"] = "another-host"
        intent["target"]["destination"]["resource"] = destination["resource"]
    elif change == "unmarked":
        del destination["native_role"]
    elif change == "fake-child":
        destination["requests"] = copy.deepcopy(intent["participants"][0]["requests"])
    else:
        destination["native_role"] = "caller-defined-native-role"
    with pytest.raises(ContractError):
        validate_workflow_proposal(intent)


def test_childless_native_role_cannot_relax_other_installed_procedures():
    intent = json.loads((FIXTURES / "workflow/proposal.json").read_text())
    intent["participants"].append(proposal()["participants"][1])
    with pytest.raises(ContractError):
        validate("workflow.schema.json", intent, "WorkflowProposal")
    with pytest.raises(ContractError):
        validate_workflow_proposal(intent)


def test_destination_preparation_requires_local_material_and_its_own_proof():
    intent = proposal()
    destination = intent["participants"][1]
    query = {"owner": destination["owner"], "proposal": intent}
    context = {
        "expected_owner": destination["owner"],
        "principal": "transport-operator",
        "verified_driver": intent["initial_driver"],
        "verified_content": intent["content"],
        "verified_preparation": preparation_witness(intent, destination["owner"]),
    }
    for field, missing in (("verified_content", []), ("verified_preparation", None)):
        with pytest.raises(ContractError):
            prepare_workflow_view(query, **{**context, field: missing})
    value = prepare_workflow_view(query, **context)
    assert value["owner"] == destination["owner"] and value["participants"][1]["request_ids"] == []


@pytest.mark.parametrize("phase", PHASES["relocation"][1:])
def test_destination_proof_and_current_native_verification_are_required_at_every_phase(phase):
    values = participants()
    for earlier in PHASES["relocation"][1 : PHASES["relocation"].index(phase)]:
        values = advance_pair(values, earlier)
    source = values[0]
    query = advance_request(source, phase, operations=child_context(source, state="succeeded"))
    missing = copy.deepcopy(query)
    missing["phase_evidence"]["participants"].pop()
    with pytest.raises(ContractError, match="missing participant evidence"):
        advance_with_evidence(missing, source)
    with pytest.raises(ContractError, match="independently verified"):
        advance_workflow_view(
            query, source, verified_phase_evidence=None, now="2026-11-01T00:00:00Z"
        )


def test_driver_loss_preserves_source_fence_and_destination_transfer_obligation():
    values = advance_pair(advance_pair(participants(), "source-quiescing"), "source-fenced")
    source, destination = values
    before = copy.deepcopy(source["advances"])
    held, original = frozen(source)
    restored = json.loads(canonical(held))
    assert prepare(restored["proposal"], retained=restored, principal="replacement-reader") == held
    assert validate_transfer_request(original, restored) == "replay"
    assert restored["advances"] == before
    with pytest.raises(ContractError, match="completed driver transfer"):
        require_workflow_child_admission(restored)
    complete = commit_input(restored)
    omitted = copy.deepcopy(complete)
    omitted["witnesses"] = [p for p in omitted["witnesses"] if p["owner"] != destination["owner"]]
    with pytest.raises(ContractError, match="complete freeze closure"):
        validate_transfer_request(omitted, restored)
    assert validate_transfer_request(complete, restored) == "new"
    assert all(
        any(
            proof["owner"] == destination["owner"]
            for proof in receipt["request"]["phase_evidence"]["participants"]
        )
        for receipt in restored["advances"]
    )


@pytest.mark.parametrize("historical", [False, True], ids=["same-epoch", "restored-epochs"])
def test_relocation_recovery_retains_childless_destination_custody(historical):
    source = participants()[0]
    intent, records = scenario(original=source, historical=historical)
    validate_recovery_proposal(intent, verified_origins=records)
    destination = intent["successor"]["participants"][1]
    assert intent["successor"]["target"]["destination"] == {
        key: destination[key] for key in ("owner", "resource")
    }
    assert destination["native_role"] == "relocation-destination" and destination["requests"] == []
    assert all(child["successor"]["owner"] != destination["owner"] for child in intent["children"])
    prepared = prepare_recovery(intent, records)
    request, successor = commit(prepared, intent)
    omitted = copy.deepcopy(request)
    omitted["preparations"] = [
        p for p in omitted["preparations"] if p["owner"] != destination["owner"]
    ]
    with pytest.raises(ContractError, match="complete participant retirement"):
        commit_workflow_recovery_view(
            omitted,
            prepared,
            recovery_authorized=True,
            verified_preparations=request["preparations"],
        )
    assert successor["recovery"]["request"]["proposal"]["origins"] == intent["origins"]
    assert successor["participants"][1]["native_role"] == "relocation-destination"
    assert len(successor["recovery"]["preparations"]) == 2


def test_childless_destination_still_requires_positive_unprepared_retirement():
    source = participants()[0]
    intent, records = scenario(original=source, historical=True)
    destination, origin = intent["participants"][1], intent["origins"][1]
    query, proof = retirement(
        source["proposal"], destination["origin"], destination["owner"], origin["custody"]
    )
    with pytest.raises(ContractError, match="positive never-prepared proof"):
        retire(query, proof, verified_never_prepared=False)
    proof = retire(query, proof)
    intent["origins"][1] = {"never_prepared": proof}
    records[1] = copy.deepcopy(intent["origins"][1])
    validate_recovery_proposal(intent, verified_origins=records)
    omitted = copy.deepcopy(intent)
    omitted["origins"].pop()
    with pytest.raises(ContractError, match="origin owner closure"):
        validate_recovery_proposal(omitted, verified_origins=records)
    prepared = prepare_recovery(intent, records, owner=destination["owner"])
    _, successor = commit(prepared, intent)
    assert successor["owner"] == destination["owner"]
    assert successor["recovery"]["request"]["proposal"]["origins"][1] == {"never_prepared": proof}
    assert successor["participants"][1]["request_ids"] == []


def test_relocation_destination_evidence_complete_linear_work():
    value = advance_pair(participants(), "source-quiescing")[0]
    samples = []
    for count in (4, 16, 64):
        query = advance_request(value, "source-fenced", operations=child_context(value))
        proof = query["phase_evidence"]["participants"][1]
        original = proof["native_evidence"][0]
        proof["native_evidence"] = [
            {**copy.deepcopy(original), "id": uid(f"destination-material-{index}")}
            for index in range(count)
        ]
        seal_phase_participant(query["phase_evidence"], proof)
        _, work = measure(lambda query=query: validate_phase_evidence(query, value))
        assert len(proof["native_evidence"]) == count and proof["operations"] == []
        samples.append((count, work))
    assert_linear(samples)
