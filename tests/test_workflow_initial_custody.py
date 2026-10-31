"""Initial participant agreement and positive retirement without fabricated capsules."""

from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_client.wire import frame
from fishhat_contracts.handoffs import PHASES, validate_cli_result, validate_workflow
from fishhat_contracts.transfers import validate_transfer_request
from fishhat_contracts.validation import MAX_BYTES, ContractError, canonical, digest, validate
from fishhat_contracts.witness import sign
from fishhat_contracts.workflow_preparation import validate_workflow_agreement
from fishhat_contracts.workflow_recovery import validate_recovery_proposal
from fishhat_contracts.workflow_unprepared import (
    retire_unprepared_workflow_view,
    validate_never_prepared,
)
from fishhat_contracts.workflows import (
    advance_workflow_view,
    decode_workflow_audit_input,
    prepare_workflow_view,
)

from tests.test_contracts import uid
from tests.test_owner_handoffs import (
    cli,
    operation,
    preparation_witness,
    preparation_witnesses,
    request,
    staged_workflow_audit_input,
    wire,
)
from tests.test_plan_review import reseal
from tests.test_workflow_continuations import prepare as prepare_initial
from tests.test_workflow_recovery import commit, prepare, scenario
from tests.test_workflow_transfer import capsule, frozen
from tests.workflow_evidence_support import advance_request

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-recovery.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/WorkflowTransferProposal",
    ],
    "scope": "initial same-proposal agreement and positive never-prepared retirement across epochs",
    "relationship": "candidate",
    "reason": "Divergent signed proposals, omitted agreement owners, initial partial preparation, changed epochs, unavailable origin capsules, substituted native proofs and exact replay challenge decoded custody. Synthetic protected context does not prove native absence, fencing, authorization, signing custody or durable tombstones.",
    "claims": [],
}


def seal_retirement(value):
    body = {k: v for k, v in operation()["witness"].items() if k != "signature"}
    body.update(
        owner=copy.deepcopy(value["owner"]),
        workflow_id=value["workflow_id"],
        kind="approval",
        state="workflow-never-prepared",
        subject_digest=digest({k: v for k, v in value.items() if k != "witness"}),
        evidence_digests=[],
    )
    value["witness"] = sign(body, Ed25519PrivateKey.from_private_bytes(b"\x31" * 32))
    return value


def retirement(proposal, origin, owner, custody):
    query = {
        "owner": copy.deepcopy(owner),
        "phase": "retire-unprepared",
        "origin": copy.deepcopy(origin),
        "proposal": copy.deepcopy(proposal),
        "custody": copy.deepcopy(custody),
    }
    proof = {
        "format": "deployment-ops/workflow-never-prepared/v1",
        "kind": "WorkflowNeverPrepared",
        "owner": copy.deepcopy(owner),
        "origin": copy.deepcopy(origin),
        "custody": copy.deepcopy(custody),
        "workflow_id": proposal["workflow_id"],
        "proposal_digest": digest(proposal),
        "participants_digest": digest(
            [p for p in proposal["participants"] if p["owner"] == origin]
        ),
        "request_commitment": digest(
            {
                **{key: query[key] for key in ("owner", "origin", "phase", "custody")},
                "proposal_digest": digest(query["proposal"]),
            }
        ),
        "native_fence_digest": digest({"native": "independently-fenced-original-execution"}),
        "tombstone_digest": digest({"durable": "closed-original-workflow-and-child-identities"}),
        "retained_closure_digest": digest({"retained": "original-inputs-and-preparation-holds"}),
        "state": "closed",
    }
    return query, seal_retirement(proof)


def retire(query, proof, **changes):
    context = {
        "expected_owner": query["owner"],
        "recovery_authorized": True,
        "verified_proposal": copy.deepcopy(query["proposal"]),
        "verified_proof": copy.deepcopy(proof),
        "verified_never_prepared": True,
        "verified_no_child_admission": True,
    }
    context.update(changes)
    return retire_unprepared_workflow_view(query, **context)


def partial(historical=True, kinds=None):
    proposal, records = scenario(multiple=True, historical=historical, kinds=kinds)
    original = records[0]["record"]["proposal"]
    mapping, absent = proposal["participants"][1], proposal["origins"][1]
    query, proof = retirement(original, mapping["origin"], mapping["owner"], absent["custody"])
    proof = retire(query, proof)
    # This original participant never stored a capsule. Its positive proof does
    # not manufacture one, and the other original capsule stays byte-for-byte.
    proposal["origins"][1] = {"never_prepared": proof}
    records[1] = copy.deepcopy(proposal["origins"][1])
    return proposal, records, query, proof


@pytest.mark.parametrize("historical", [False, True])
def test_partial_initial_preparation_recovers_without_inventing_an_origin(historical):
    proposal, records, query, proof = partial(historical)
    original = canonical(records[0]["record"])
    validate_recovery_proposal(proposal, verified_origins=records)
    for participant in proposal["participants"]:
        prepared = prepare(proposal, records, owner=participant["owner"])
        _, committed = commit(prepared, proposal)
        validate_workflow(committed)
        assert committed["recovery"]["phase"] == "committed"
        assert committed["recovery"]["request"]["proposal"]["origins"][1] == {
            "never_prepared": proof
        }
    assert canonical(records[0]["record"]) == original
    assert proof["request_commitment"] == digest(
        {
            **{key: query[key] for key in ("owner", "origin", "phase", "custody")},
            "proposal_digest": digest(query["proposal"]),
        }
    )


@pytest.mark.parametrize(
    "change", ["native-absence", "child-admitted", "untrusted-proposal", "authority", "input"]
)
def test_retirement_requires_independent_positive_native_facts(change):
    _, _, query, proof = partial()
    context = {}
    if change == "native-absence":
        context["verified_never_prepared"] = False
    elif change == "child-admitted":
        context["verified_no_child_admission"] = False
    elif change == "untrusted-proposal":
        context["verified_proposal"] = {}
    elif change == "authority":
        context["recovery_authorized"] = False
    else:
        proof["native_fence_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ContractError):
        retire(query, proof, **context)


@pytest.mark.parametrize("change", ["omitted", "untrusted", "closure", "proposal", "epoch"])
def test_recovery_rejects_missing_or_substituted_unprepared_origin(change):
    proposal, records, _, _ = partial()
    proof = proposal["origins"][1]["never_prepared"]
    if change == "omitted":
        proposal["origins"].pop()
    elif change == "untrusted":
        records.pop()
    else:
        field = {"closure": "participants_digest", "proposal": "proposal_digest"}.get(change)
        if field:
            proof[field] = "sha256:" + "0" * 64
            if field == "proposal_digest":
                proof["request_commitment"] = digest(
                    {
                        **{
                            key: proof[key]
                            for key in ("owner", "origin", "custody", "proposal_digest")
                        },
                        "phase": "retire-unprepared",
                    }
                )
        else:
            proof["origin"]["epoch"] = uid("substituted-original-epoch")
        seal_retirement(proof)
        records[1] = copy.deepcopy(proposal["origins"][1])
    with pytest.raises(ContractError):
        validate_recovery_proposal(proposal, verified_origins=records)


def test_unprepared_origin_cannot_claim_previously_completed_work():
    proposal, records, _, _ = partial(kinds=["unaccepted", "completed"])
    with pytest.raises(ContractError, match="accepted child"):
        validate_recovery_proposal(proposal, verified_origins=records)


def test_retirement_replay_preserves_proof_and_tombstone_blocks_repreparation():
    _, _, query, proof = partial(historical=False)
    assert (
        retire(
            query,
            proof,
            retained=proof,
            verified_never_prepared=False,
            verified_no_child_admission=False,
            verified_proposal={},
        )
        == proof
    )
    changed = copy.deepcopy(query)
    changed["proposal"]["initial_driver"]["principal"] = "another-operator"
    with pytest.raises(ContractError):
        retire(changed, proof, retained=proof)
    with pytest.raises(ContractError, match="cannot prepare again"):
        prepare_workflow_view(
            {"owner": query["owner"], "proposal": query["proposal"]},
            expected_owner=query["owner"],
            principal="operator",
            verified_driver=query["proposal"]["initial_driver"],
            verified_content=query["proposal"]["content"],
            verified_preparation=preparation_witness(query["proposal"], query["owner"]),
            retained_retirement=proof,
        )


@pytest.mark.parametrize("field", ["owner", "origin", "phase", "custody", "proposal_digest"])
def test_retirement_commitment_pins_every_compact_request_field(field):
    _, _, query, proof = partial(historical=True)
    preimage = {
        **{key: copy.deepcopy(query[key]) for key in ("owner", "origin", "phase", "custody")},
        "proposal_digest": digest(query["proposal"]),
    }
    if field in {"owner", "origin"}:
        preimage[field]["epoch"] = uid("different-commitment-epoch")
    elif field == "phase":
        preimage[field] = "abandon"
    elif field == "custody":
        preimage[field] = None
    else:
        preimage[field] = "sha256:" + "0" * 64
    proof["request_commitment"] = digest(preimage)
    seal_retirement(proof)
    with pytest.raises(ContractError, match="retirement input changed"):
        validate_never_prepared(proof)
    with pytest.raises(ContractError, match="retirement input changed"):
        retire(query, proof, retained=proof)


@pytest.mark.parametrize("spelling", ["old-only", "both"])
def test_retirement_rejects_obsolete_digest_field(spelling):
    _, _, query, proof = partial(historical=False)
    proof["request_digest"] = digest(query)
    if spelling == "old-only":
        del proof["request_commitment"]
    seal_retirement(proof)
    with pytest.raises(ContractError):
        validate_never_prepared(proof, proposal=query["proposal"])


def test_retirement_commitment_preserves_nonlocal_proposal_content_on_replay():
    _, _, query, proof = partial(historical=False)
    changed = copy.deepcopy(query)
    original_local = [p for p in query["proposal"]["participants"] if p["owner"] == query["origin"]]
    plan = changed["proposal"]["participants"][0]["requests"][0]["plan"]
    assert plan["owner"] != query["origin"]
    plan["summary"] = "A different reviewed nonlocal operation."
    reseal(plan)
    assert [
        p for p in changed["proposal"]["participants"] if p["owner"] == query["origin"]
    ] == original_local
    with pytest.raises(ContractError, match="original proposal or local child closure"):
        retire(changed, proof, retained=proof)
    with pytest.raises(ContractError, match="original proposal or local child closure"):
        retire(changed, proof)


def test_retirement_uses_complete_staged_input_and_finite_lost_reply_result():
    _, _, query, _ = partial()
    template = query["proposal"]["content"][0]
    query["proposal"]["content"].extend(
        {
            **copy.deepcopy(template),
            "id": uid("retirement-content-" + str(i)),
            "binding": {"kind": "staging", "staging_id": uid("retirement-stage-" + str(i))},
        }
        for i in range(3000)
    )
    query, proof = retirement(query["proposal"], query["origin"], query["owner"], query["custody"])
    reference, data = staged_workflow_audit_input("workflow.recover", query)
    assert len(data) > MAX_BYTES
    assert len(frame(request("workflow.recover", reference))) < MAX_BYTES
    assert (
        decode_workflow_audit_input(
            "workflow.recover", reference, data, expected_owner=query["owner"]
        )
        == query
    )
    result = retire(query, proof)
    validate_never_prepared(result, proposal=query["proposal"])
    with pytest.raises(ContractError):
        validate("ssh-response.schema.json", wire("workflow.recover", result))
    validate("cli-output.schema.json", cli(result))
    validate_cli_result(result)
    assert len(frame(wire("workflow.recover", result))) < MAX_BYTES
    assert retire(query, proof, retained=result) == result


def test_initial_agreement_requires_every_exact_owner_and_retained_local_proof():
    value = capsule()
    with pytest.raises(ContractError, match="complete same-proposal"):
        validate_workflow_agreement(value, require_complete=True)
    complete = preparation_witnesses(value["proposal"])
    validate_workflow_agreement(value, witnesses=complete, require_complete=True)
    changed = copy.deepcopy(complete)
    changed[0]["id"] = uid("substituted-local-preparation")
    with pytest.raises(ContractError, match="replaced"):
        validate_workflow_agreement(value, witnesses=changed, require_complete=True)
    query = advance_request(value, PHASES[value["type"]][1])
    verified = copy.deepcopy(query["phase_evidence"])
    with pytest.raises(ContractError, match="not independently authenticated"):
        advance_workflow_view(
            query, value, verified_phase_evidence=verified, now="2026-11-01T00:00:00Z"
        )
    advanced = advance_workflow_view(
        query,
        value,
        verified_phase_evidence=verified,
        now="2026-11-01T00:00:00Z",
        verified_preparations=copy.deepcopy(complete),
    )
    validate_workflow_agreement(advanced, require_complete=True)
    assert advance_workflow_view(query, advanced) == advanced


def test_signed_divergent_intents_cannot_agree_or_commit_one_driver_transfer():
    intent_a = capsule()["proposal"]
    intent_b = copy.deepcopy(intent_a)
    plan = intent_b["participants"][0]["requests"][0]["plan"]
    plan["subject"]["action"] = "host.sleep"
    reseal(plan)
    a = prepare_initial(intent_a, intent_a["participants"][0]["owner"])
    b = prepare_initial(intent_b, intent_b["participants"][1]["owner"])
    assert a["proposal_digest"] != b["proposal_digest"]
    with pytest.raises(ContractError, match="changed proposal"):
        validate_workflow_agreement(a, witnesses=b["prerequisite_witnesses"], require_complete=True)
    frozen_a, _ = frozen(a)
    frozen_b, _ = frozen(b)
    assert frozen_a["transfer"]["proposal"] != frozen_b["transfer"]["proposal"]
    query = {
        "owner": frozen_b["owner"],
        "expected_generation": frozen_b["generation"],
        "proposal": copy.deepcopy(frozen_a["transfer"]["proposal"]),
        "phase": "commit",
        "witnesses": frozen_a["transfer"]["freeze_witnesses"]
        + frozen_b["transfer"]["freeze_witnesses"],
    }
    with pytest.raises(ContractError, match="owner or closure mismatch"):
        validate_transfer_request(query, frozen_b)
