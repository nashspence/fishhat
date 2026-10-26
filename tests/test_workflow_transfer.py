"""Discoverable transfer inputs and exact replay, without owner persistence or dispatch."""

from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_client.wire import frame
from fishhat_contracts.handoffs import validate_cli_result, validate_workflow
from fishhat_contracts.transfers import validate_transfer_proposal, validate_transfer_request
from fishhat_contracts.validation import MAX_BYTES, ContractError, digest, validate
from fishhat_contracts.witness import sign, verify
from fishhat_contracts.workflows import advance_workflow, validate_advance_request

from tests.test_contracts import uid
from tests.test_owner_handoffs import (
    U,
    V,
    operation,
    rebind_workflow_proposal,
    request,
    staged_workflow_input,
    wire,
    work_page,
    workflow,
)

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Workflow",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/WorkflowTransfer",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/WorkflowTransferRequest",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/WorkflowTransferWitness",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-request.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-response.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json",
    ],
    "scope": "retained transfer proposal, participant evidence and lost-client phase reconstruction",
    "relationship": "candidate",
    "reason": "Synthetic independent capsules challenge discoverability, exact replay after generation changes and complete freeze/commit closure. They do not prove native atomic durability, receiving authorization or a coordinator.",
    "claims": [],
}


def capsule():
    value = workflow()
    other = copy.deepcopy(value["participants"][0])
    other["owner"]["id"] = V
    other["resource"]["id"] = "other-app"
    value["participants"].append(other)
    rebind_workflow_proposal(value)
    return value


def proposal(value):
    return {
        "workflow_id": value["id"],
        "workflow_proposal_digest": value["proposal_digest"],
        "transfer_id": V,
        "current_principal": value["driver_principal"],
        "expected_term": value["driver_term"],
        "new_principal": "replacement-operator",
        "participants": [
            {"owner": copy.deepcopy(item["owner"]), "resource": copy.deepcopy(item["resource"])}
            for item in value["participants"]
        ],
    }


def attestation(preimage, owner, state, generation):
    body = {k: v for k, v in operation()["witness"].items() if k != "signature"}
    body.update(
        id=uid(f"transfer-{owner['id']}-{state}"),
        owner=copy.deepcopy(owner),
        kind="transfer",
        subject_digest=digest(preimage),
        workflow_id=preimage["workflow_id"],
        state=state,
        generation=generation,
    )
    key = Ed25519PrivateKey.generate()
    result = sign(body, key)
    verify(result, key.public_key(), owner, digest(preimage))
    return result


def frozen(value=None):
    value = capsule() if value is None else copy.deepcopy(value)
    preimage = proposal(value)
    original = {
        "owner": value["owner"],
        "expected_generation": value["generation"],
        "proposal": preimage,
        "phase": "freeze",
        "witnesses": [],
    }
    assert validate_transfer_request(original, value) == "new"
    value["generation"] += 1
    value["transfer"] = {
        "proposal": copy.deepcopy(preimage),
        "proposal_digest": digest(preimage),
        "phase": "freeze",
        "accepted_phases": [
            {
                key: copy.deepcopy(original[key])
                for key in ("phase", "expected_generation", "witnesses")
            }
        ],
        "freeze_witnesses": [attestation(preimage, value["owner"], "frozen", value["generation"])],
        "commit_witnesses": [],
    }
    validate_workflow(value)
    return value, original


def commit_input(value):
    preimage = value["transfer"]["proposal"]
    proofs = copy.deepcopy(value["transfer"]["freeze_witnesses"])
    owners = {item["owner"]["id"] for item in proofs}
    for participant in preimage["participants"]:
        if participant["owner"]["id"] not in owners:
            proofs.append(attestation(preimage, participant["owner"], "frozen", 7))
            owners.add(participant["owner"]["id"])
    return {
        "owner": value["owner"],
        "expected_generation": value["generation"],
        "proposal": copy.deepcopy(preimage),
        "phase": "commit",
        "witnesses": proofs,
    }


def committed(value=None):
    value, _ = frozen(value)
    original = commit_input(value)
    assert validate_transfer_request(original, value) == "new"
    transfer = value["transfer"]
    transfer["phase"] = "commit"
    transfer["accepted_phases"].append(
        {key: copy.deepcopy(original[key]) for key in ("phase", "expected_generation", "witnesses")}
    )
    transfer["freeze_witnesses"] = copy.deepcopy(original["witnesses"])
    value["generation"] += 1
    value["driver_principal"] = transfer["proposal"]["new_principal"]
    value["driver_term"] = transfer["proposal"]["expected_term"] + 1
    transfer["commit_witnesses"] = [
        attestation(transfer["proposal"], value["owner"], "transferred", value["generation"])
    ]
    validate_workflow(value)
    return value, original


def reconstruct(value, phase):
    transfer = value["transfer"]
    original = next(item for item in transfer["accepted_phases"] if item["phase"] == phase)
    return {"owner": value["owner"], "proposal": transfer["proposal"], **original}


def test_pending_transfer_exposes_exact_original_input_without_client_state():
    value, original = frozen()
    for method, result in (
        ("workflow.get", value),
        ("workflow.list", work_page("WorkflowPage", [value])),
    ):
        validate("ssh-response.schema.json", wire(method, result))
        validate_cli_result(result)
    recovered = reconstruct(value, "freeze")
    assert recovered == original
    staged_workflow_input("workflow.transfer", recovered)
    value["generation"] = 5
    assert validate_transfer_request(recovered, value) == "replay"
    assert recovered["expected_generation"] == 0
    assert value["transfer"]["freeze_witnesses"][0]["generation"] == 1


def test_pending_transfer_cannot_omit_proposal_or_local_freeze_custody():
    value, _ = frozen()
    missing = copy.deepcopy(value)
    del missing["transfer"]["proposal"]
    with pytest.raises(ContractError):
        validate("records.schema.json", missing, "Workflow")
    missing = copy.deepcopy(value)
    missing["transfer"]["freeze_witnesses"] = []
    with pytest.raises(ContractError, match="local transfer phase lacks"):
        validate_workflow(missing)
    missing = copy.deepcopy(value)
    missing["transfer"]["accepted_phases"] = []
    with pytest.raises(ContractError):
        validate_workflow(missing)
    missing = copy.deepcopy(value)
    missing["transfer"]["freeze_witnesses"][0]["generation"] = 0
    with pytest.raises(ContractError, match="witness generation"):
        validate_workflow(missing)


@pytest.mark.parametrize(
    "field", ["expected_generation", "witnesses", "new_principal", "transfer_id"]
)
def test_lost_reply_replay_rejects_changed_transfer_or_original_phase_input(field):
    value, original = frozen()
    value["generation"] = 5
    changed = copy.deepcopy(original)
    if field == "expected_generation":
        changed[field] = value["generation"]
    elif field == "witnesses":
        changed[field] = copy.deepcopy(value["transfer"]["freeze_witnesses"])
    else:
        changed["proposal"][field] = "different-principal" if field == "new_principal" else U
    with pytest.raises(ContractError):
        validate_transfer_request(changed, value)


def test_commit_requires_every_participant_owner_freeze_before_new_driver():
    value, _ = frozen()
    original = commit_input(value)
    assert validate_transfer_request(original, value) == "new"
    missing = copy.deepcopy(original)
    missing["witnesses"].pop()
    with pytest.raises(ContractError, match="complete freeze closure"):
        validate_transfer_request(missing, value)
    changed = copy.deepcopy(original)
    changed["expected_generation"] += 1
    with pytest.raises(ContractError, match="capsule generation changed"):
        validate_transfer_request(changed, value)
    changed = copy.deepcopy(original)
    changed["witnesses"][0]["generation"] = 100
    with pytest.raises(ContractError, match="substituted retained local freeze"):
        validate_transfer_request(changed, value)
    advanced = copy.deepcopy(value)
    advanced["driver_principal"] = original["proposal"]["new_principal"]
    with pytest.raises(ContractError, match="driver preimage"):
        validate_workflow(advanced)
    fresh = capsule()
    original["expected_generation"] = fresh["generation"]
    with pytest.raises(ContractError, match="no retained local freeze"):
        validate_transfer_request(original, fresh)


def completion_request(value):
    transfer = value["transfer"]
    witnesses = copy.deepcopy(transfer["commit_witnesses"])
    owners = {canonical_owner(item["owner"]) for item in witnesses}
    for participant in value["participants"]:
        if canonical_owner(participant["owner"]) not in owners:
            witnesses.append(
                attestation(transfer["proposal"], participant["owner"], "transferred", 8)
            )
            owners.add(canonical_owner(participant["owner"]))
    return {
        "owner": value["owner"],
        "workflow_id": value["id"],
        "advance_id": uid("transfer-completion-advance"),
        "driver_term": value["driver_term"],
        "expected_generation": value["generation"],
        "phase": value["phase"],
        "phase_evidence": None,
        "witnesses": [],
        "transfer_completion": {
            "transfer_id": transfer["proposal"]["transfer_id"],
            "proposal_digest": transfer["proposal_digest"],
            "witnesses": witnesses,
        },
    }


def canonical_owner(owner):
    return owner["tool"], owner["id"], owner["epoch"]


def test_local_commit_replays_original_generation_and_completion_needs_all_commits():
    value, original = committed()
    value["generation"] = 6
    impossible = copy.deepcopy(value)
    impossible["transfer"]["freeze_witnesses"][0]["generation"] = 3
    impossible["transfer"]["accepted_phases"][1]["witnesses"][0]["generation"] = 3
    with pytest.raises(ContractError, match="freeze witness follows commit"):
        validate_workflow(impossible)
    recovered = reconstruct(value, "commit")
    assert recovered == original
    assert validate_transfer_request(recovered, value) == "replay"
    assert validate_transfer_request(reconstruct(value, "freeze"), value) == "replay"
    assert value["state"] == "prepared"
    assert value["driver_term"] == 2
    advance = completion_request(value)
    incomplete = copy.deepcopy(advance)
    incomplete["transfer_completion"]["witnesses"].pop()
    with pytest.raises(ContractError, match="participant commits"):
        advance_workflow(incomplete, value)
    staged_workflow_input("workflow.advance", advance)
    complete = advance_workflow(advance, value)
    assert complete["generation"] == value["generation"] + 1
    assert complete["state"] == "prepared"
    assert complete["transfer"]["phase"] == "completed"
    assert complete["advances"][0]["request"] == advance
    validate_workflow(complete)
    assert validate_transfer_request(recovered, complete) == "replay"
    assert advance_workflow(advance, complete) == complete
    complete["generation"] += 1
    assert validate_advance_request(advance, complete) == "replay"


@pytest.mark.parametrize("field", ["owner", "workflow_id", "subject_digest", "state"])
def test_transfer_proofs_cannot_change_owner_epoch_workflow_proposal_or_phase(field):
    value, _ = frozen()
    original = commit_input(value)
    proof = original["witnesses"][-1]
    if field == "owner":
        proof["owner"]["epoch"] = U
    elif field == "workflow_id":
        proof[field] = V
    elif field == "subject_digest":
        proof[field] = "sha256:" + "0" * 64
    else:
        proof[field] = "transferred"
    with pytest.raises(ContractError, match="transfer witness"):
        validate_transfer_request(original, value)


def test_transfer_proposal_exactly_matches_unique_retained_participant_closure():
    value = capsule()
    preimage = proposal(value)
    preimage["participants"].append(copy.deepcopy(preimage["participants"][0]))
    with pytest.raises(ContractError, match="duplicate transfer participant"):
        validate_transfer_proposal(preimage)
    preimage["participants"].pop()
    preimage["participants"][1]["resource"]["id"] = "unrelated-app"
    query = {
        "owner": value["owner"],
        "expected_generation": 0,
        "proposal": preimage,
        "phase": "freeze",
        "witnesses": [],
    }
    with pytest.raises(ContractError, match="owner or closure"):
        validate_transfer_request(query, value)
    query["proposal"] = proposal(value)
    query["owner"] = {**value["owner"], "epoch": U}
    with pytest.raises(ContractError, match="owner or closure"):
        validate_transfer_request(query, value)


def test_staged_commit_request_keeps_complete_owner_closure():
    value = workflow()
    template = value["participants"][0]
    value["participants"] = [copy.deepcopy(template)]
    for index in range(1, 64):
        item = copy.deepcopy(template)
        item["owner"]["id"] = uid(f"transfer-owner-{index}")
        item["resource"]["id"] = f"app-{index}"
        value["participants"].append(item)
    rebind_workflow_proposal(value)
    value, _ = frozen(value)
    query = commit_input(value)
    reference, _ = staged_workflow_input("workflow.transfer", query)
    assert validate_transfer_request(query, value) == "new"
    assert len(query["witnesses"]) == 64
    assert len(frame(request("workflow.transfer", reference))) <= MAX_BYTES + 4
    query["witnesses"][0]["evidence_digests"] = ["sha256:" + "0" * 64]
    with pytest.raises(ContractError):
        staged_workflow_input("workflow.transfer", query)


def test_obsolete_unretained_transfer_shape_is_rejected():
    value = capsule()
    old = {
        "owner": value["owner"],
        "workflow_id": value["id"],
        "expected_generation": value["generation"],
        "transfer_id": V,
        "new_principal": "replacement-operator",
        "expected_term": value["driver_term"],
        "phase": "freeze",
        "witnesses": [],
    }
    with pytest.raises(ContractError):
        validate("ssh-request.schema.json", request("workflow.transfer", old))
