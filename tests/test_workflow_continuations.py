"""Causal late workflow review, independent driver agreement and retained custody."""

from __future__ import annotations

import copy
import hashlib
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_client.wire import frame
from fishhat_contracts.handoffs import PHASES, schema_identity, validate_workflow
from fishhat_contracts.transfers import validate_transfer_request
from fishhat_contracts.validation import MAX_BYTES, ContractError, canonical, digest, validate
from fishhat_contracts.witness import sign
from fishhat_contracts.workflow_bindings import bind_workflow, validate_bind_request
from fishhat_contracts.workflows import (
    advance_workflow,
    prepare_workflow,
    validate_workflow_proposal,
)

from tests.test_contracts import uid
from tests.test_owner_handoffs import operation, request, staged_workflow_input, workflow
from tests.test_plan_review import reseal
from tests.test_workflow_inputs import adapter_proposal, material_handle, rotation_intent
from tests.test_workflow_transfer import capsule, proposal

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Workflow",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/states.json#/workflow_phases",
    ],
    "scope": "partial preparation, later reviewed output/generation bindings and exact retained replay",
    "relationship": "candidate",
    "reason": "Synthetic independently supplied authorization, successful predecessor and verified material context exercise causal lifecycle joins and rejected substitutions. No native authorization, derivation, transaction or effect is established.",
    "claims": [],
}

NOW = "2026-10-17T00:30:00Z"


def prepare(intent, owner=None, principal="transport-operator", retained=None):
    owner = owner or intent["participants"][0]["owner"]
    adapters = [
        b["adapter"] for p in intent["participants"] for b in p["requests"] if "adapter" in b
    ]
    return prepare_workflow(
        {"owner": owner, "proposal": intent},
        expected_owner=owner,
        principal=principal,
        verified_driver=intent["initial_driver"],
        verified_content=intent["content"],
        verified_adapters=adapters,
        retained=retained,
    )


def move(value, phase):
    phases = PHASES[value["type"]]
    while value["phase"] != phase:
        following = phases[phases.index(value["phase"]) + 1]
        value = advance_workflow(
            {
                "owner": value["owner"],
                "workflow_id": value["id"],
                "advance_id": uid(f"advance-{following}-{value['generation']}"),
                "driver_term": value["driver_term"],
                "expected_generation": value["generation"],
                "phase": following,
                "witnesses": [],
                "transfer_completion": None,
            },
            value,
        )
    return value


def successful(reference, binding, generation=1):
    result = operation()
    result.update(
        id=uid("finished-" + reference["request_id"]),
        owner=copy.deepcopy(reference["owner"]),
        request_id=reference["request_id"],
        subject=copy.deepcopy(binding["plan"]["subject"]),
        plan_digest=binding["plan"]["digest"],
        state="succeeded",
        effect_certainty="known",
        generation=generation,
    )
    result["witness"].update(owner=result["owner"], state="succeeded", generation=generation)
    return result


def seal_material(material, workflow_id):
    body = {k: v for k, v in operation()["witness"].items() if k != "signature"}
    body.update(
        owner=material["material"]["owner"],
        kind="binding",
        state="verified",
        workflow_id=workflow_id,
        subject_digest=digest({k: v for k, v in material.items() if k != "witness"}),
    )
    material["witness"] = sign(body, Ed25519PrivateKey.from_private_bytes(b"\x17" * 32))
    return material


def attach_result(record, value, custodian):
    handle = material_handle(record["owner"], digest(value), size=len(canonical(value)))
    handle["binding"] = {"kind": "operation", "operation_id": record["id"]}
    schema = (
        record["subject"]["arguments"]["result_schema"]
        if record["subject"]["action"] == "adapter.execute"
        else schema_identity("https://fishhat.invalid/contracts/publisher-receipt.schema.json")
    )
    record["result_handle"] = {"handle": handle, "schema": schema}
    return material_handle(custodian, digest(value), size=len(canonical(value)))


def bind_request(
    value, participant, subject, predecessor, *, content=None, material=None, generation=0
):
    slot = participant["requests"][-1]
    template = workflow()["proposal"]["participants"][0]["requests"][0]["plan"]
    plan = copy.deepcopy(template)
    plan.update(
        id=uid("late-plan-" + slot["request_id"]), owner=participant["owner"], subject=subject
    )
    for condition in plan["preconditions"]:
        condition.update(
            owner=participant["owner"], resource=participant["resource"], generation=generation
        )
    for effect in plan["effects"]:
        effect.update(executor=participant["owner"], resource=participant["resource"])
    plan["witness"]["owner"] = participant["owner"]
    contents = list(content or [])
    original = material_handle(participant["owner"], plan["input_digests"][0])
    contents.append(original)
    plan["input_digests"] = list(dict.fromkeys(h["digest"] for h in contents))
    reseal(plan)
    return {
        "owner": value["owner"],
        "workflow_id": value["id"],
        "bind_id": uid("bind-" + slot["request_id"]),
        "expected_generation": value["generation"],
        "driver_term": value["driver_term"],
        "child": {"owner": participant["owner"], "request_id": slot["request_id"]},
        "binding": {"request_id": slot["request_id"], "phase": slot["phase"], "plan": plan},
        "content": contents,
        "predecessors": [predecessor],
        "materials": [] if material is None else [material],
    }


def context(query):
    return {
        "verified_binding": copy.deepcopy(query["binding"]),
        "verified_driver": {"principal": "ops-app-operate", "term": query["driver_term"]},
        "current_generations": [
            {k: c[k] for k in ("owner", "resource", "generation")}
            for c in query["binding"]["plan"]["preconditions"]
        ],
        "verified_operations": copy.deepcopy(query["predecessors"]),
        "verified_materials": copy.deepcopy(query["materials"]),
        "verified_content": copy.deepcopy(query["content"]),
        "now": NOW,
    }


def publication_stage():
    intent = rotation_intent()
    value = move(prepare(intent), "issuer-changing")
    issuer, publisher, _ = intent["participants"]
    reference = intent["target"]["issuer_change"]
    issued = successful(reference, issuer["requests"][0], generation=10)
    # The candidate is created only after preparation and issuer completion.
    output = {
        "leases": [
            {
                "identity": "demo-user",
                "consumer": "demo-app",
                "value_handle": str(uuid.uuid4()),
                "lease": str(uuid.uuid4()),
                "validity": "valid",
                "expires_at": "2026-10-17T01:00:00Z",
                "valid_from": "2026-10-17T00:00:00Z",
                "renewable": True,
                "issuer": issuer["requests"][0]["adapter"]["executor"],
            }
        ]
    }
    validate("credential-issuer-adapter.schema.json", output, "Output")
    copied_output = attach_result(issued, output, publisher["owner"])
    ciphertext = b"newly-issued-unpredictable-ciphertext-" + str(uuid.uuid4()).encode()
    candidate = material_handle(
        publisher["owner"], "sha256:" + hashlib.sha256(ciphertext).hexdigest(), size=len(ciphertext)
    )
    candidate["purpose"] = "secret-candidate"
    material = seal_material(
        {
            "producer": reference,
            "operation": issued,
            "material": candidate,
            "producer_output": copied_output,
            "publication_receipt": None,
        },
        value["id"],
    )
    subject = {
        "action": "publisher.publish",
        "resource": publisher["resource"],
        "arguments": {"candidate": candidate, "expected_previous": None},
    }
    query = bind_request(
        value, publisher, subject, issued, content=[candidate, copied_output], material=material
    )
    return value, query


def adoption_stage():
    value, publication = publication_stage()
    value = bind_workflow(publication, value, **context(publication))
    value = move(value, "publishing")
    intent = value["proposal"]
    publisher, consumer = intent["participants"][1:]
    reference = intent["target"]["publication"]
    published = successful(reference, publication["binding"])
    candidate = publication["binding"]["plan"]["subject"]["arguments"]["candidate"]
    receipt = {
        "format": "deployment-ops/publication/v1",
        "id": str(uuid.uuid4()),
        "repository": {"instance": uid("repository"), "repository_id": 1, "name": "demo/secrets"},
        "tag": "secrets-bundle",
        "asset": "secrets.tar.age",
        "catalogue_digest": digest({"catalogue": 1}),
        "previous": None,
        "current": {
            "release_id": 17,
            "asset_id": 23,
            "ciphertext_digest": candidate["digest"],
            "bytes": candidate["size"],
            "generation": uid("new-secret-generation"),
        },
        "custodian": publisher["owner"],
        "recovery_handle": candidate,
        "state": "completed",
        "verified_at": NOW,
        "witness": copy.deepcopy(published["witness"]),
    }
    validate("publisher-receipt.schema.json", receipt)
    handle = attach_result(published, receipt, consumer["owner"])
    material = seal_material(
        {
            "producer": reference,
            "operation": published,
            "material": handle,
            "producer_output": handle,
            "publication_receipt": receipt,
        },
        value["id"],
    )
    subject = {
        "action": "app.secrets-adopt",
        "resource": consumer["resource"],
        "arguments": {"bundle_receipt": digest(receipt)},
    }
    query = bind_request(value, consumer, subject, published, content=[handle], material=material)
    return value, query


def test_partial_preparation_retains_one_independently_authorized_initial_driver():
    intent = capsule()["proposal"]
    owner_a, owner_b = [p["owner"] for p in intent["participants"]]
    a = prepare(intent, owner_a, "alice")
    recovered_a = prepare(intent, owner_a, "bob", a)
    b = prepare(intent, owner_b, "bob")
    assert recovered_a["proposal_digest"] == b["proposal_digest"]
    assert (
        recovered_a["driver_principal"]
        == b["driver_principal"]
        == intent["initial_driver"]["principal"]
    )
    transfer = proposal(recovered_a)
    for value in (recovered_a, b):
        assert (
            validate_transfer_request(
                {
                    "owner": value["owner"],
                    "expected_generation": 0,
                    "proposal": transfer,
                    "phase": "freeze",
                    "witnesses": [],
                },
                value,
            )
            == "new"
        )
    with pytest.raises(ContractError, match="independently authorized"):
        prepare_workflow(
            {"owner": owner_b, "proposal": intent},
            expected_owner=owner_b,
            principal="bob",
            verified_driver={"principal": "bob", "term": 1},
            verified_content=intent["content"],
        )


def test_rotation_prepares_without_future_receipt_then_retains_exact_issued_publication():
    intent = rotation_intent()
    assert all("intent" in p["requests"][0] for p in intent["participants"][1:])
    assert not any(h["owner"] == intent["participants"][2]["owner"] for h in intent["content"])
    value, query = adoption_stage()
    original = copy.deepcopy(value["proposal"])
    completed = bind_workflow(query, value, **context(query))
    completed = move(completed, "completed")
    validate_workflow(completed)
    assert completed["proposal"] == original
    assert len(completed["bindings"]) == 2
    assert (
        completed["bindings"][-1]["request"]["materials"][0]["publication_receipt"]["current"][
            "asset_id"
        ]
        == 23
    )
    # The complete accepted continuation is retrievable without the original client.
    restored = copy.deepcopy(completed)
    del completed, query
    recovered = restored["bindings"][-1]["request"]
    assert validate_bind_request(recovered, restored) == "replay"


@pytest.mark.parametrize("kind", ["secret-publication", "secret-adoption"])
def test_rotation_output_intent_cannot_bypass_same_participant_predecessor(kind):
    intent = rotation_intent()
    participant = intent["participants"][1 if kind == "secret-publication" else 2]
    second = copy.deepcopy(participant["requests"][0])
    second["request_id"] = uid("second-output-" + kind)
    participant["requests"].append(second)
    if kind == "secret-adoption":
        intent["target"]["consumer_adoptions"].append(
            {"owner": participant["owner"], "request_id": second["request_id"]}
        )
    with pytest.raises(ContractError, match="later participant output requires reviewed successor"):
        validate_workflow_proposal(intent)


@pytest.mark.parametrize("stage", ["publication", "adoption"])
def test_phase_cannot_finish_with_an_unbound_required_child(stage):
    value, _ = publication_stage() if stage == "publication" else adoption_stage()
    phase = "publishing" if stage == "publication" else "consumers-adopting"
    value = move(value, phase)
    with pytest.raises(ContractError, match="unresolved required child"):
        move(value, PHASES[value["type"]][PHASES[value["type"]].index(phase) + 1])


@pytest.mark.parametrize(
    "change",
    [
        "unreviewed",
        "stale-generation",
        "unverified-operation",
        "unverified-material",
        "missing-content",
        "expired",
        "wrong-phase",
        "issuer",
        "publisher",
        "receipt-candidate",
        "receipt-bytes",
        "receipt-custodian",
        "receipt-state",
        "changed-subject",
    ],
)
def test_output_binding_rejects_substitution_without_independent_review_and_custody(change):
    value, query = adoption_stage()
    trusted = context(query)
    if change == "unreviewed":
        trusted["verified_binding"] = {}
    elif change == "stale-generation":
        trusted["current_generations"][0]["generation"] += 1
    elif change == "unverified-operation":
        trusted["verified_operations"] = []
    elif change == "unverified-material":
        trusted["verified_materials"] = []
    elif change == "missing-content":
        trusted["verified_content"] = []
    elif change == "expired":
        trusted["now"] = "2026-10-18T00:00:00Z"
    elif change == "wrong-phase":
        query["binding"]["phase"] = "verifying"
    elif change in {"issuer", "publisher"}:
        query["materials"][0]["producer"]["request_id"] = uid("different-" + change)
    elif change == "changed-subject":
        query["binding"]["plan"]["subject"]["arguments"]["bundle_receipt"] = digest(
            {"unrelated": 1}
        )
        reseal(query["binding"]["plan"])
    else:
        receipt = query["materials"][0]["publication_receipt"]
        if change == "receipt-candidate":
            receipt["current"]["ciphertext_digest"] = digest({"old": 1})
        elif change == "receipt-bytes":
            receipt["current"]["bytes"] += 1
        elif change == "receipt-custodian":
            receipt["custodian"]["epoch"] = uid("other-epoch")
        else:
            receipt["state"] = "uncertain"
        seal_material(query["materials"][0], value["id"])
    with pytest.raises(ContractError):
        bind_workflow(query, value, **trusted)


def successor_stage():
    intent = workflow()["proposal"]
    participant = intent["participants"][0]
    previous = participant["requests"][0]
    reference = {"owner": participant["owner"], "request_id": previous["request_id"]}
    participant["requests"].append(
        {
            "request_id": uid("second-host-change"),
            "phase": "host-effect",
            "intent": {
                "kind": "reviewed-successor",
                "predecessor": reference,
                "subject": copy.deepcopy(previous["plan"]["subject"]),
            },
        }
    )
    validate_workflow_proposal(intent)
    value = move(prepare(intent), "host-effect")
    succeeded = successful(reference, previous, generation=10)
    query = bind_request(
        value,
        participant,
        participant["requests"][1]["intent"]["subject"],
        succeeded,
        generation=10,
    )
    return value, query


def test_successor_plan_uses_fresh_generation_after_exact_predecessor_and_replays():
    value, query = successor_stage()
    trusted = context(query)
    advanced = bind_workflow(query, value, **trusted)
    assert (
        advanced["bindings"][0]["request"]["binding"]["plan"]["preconditions"][0]["generation"]
        == 10
    )
    assert value["proposal"]["participants"][0]["expected_generation"] == 9
    late = {
        **trusted,
        "now": "2027-01-01T00:00:00Z",
        "verified_binding": {},
        "current_generations": [],
        "verified_operations": [],
        "verified_content": [],
    }
    assert bind_workflow(copy.deepcopy(query), advanced, **late) == advanced
    changed = copy.deepcopy(query)
    changed["binding"]["plan"]["preconditions"][0]["generation"] += 1
    reseal(changed["binding"]["plan"])
    with pytest.raises(ContractError, match="accepted workflow binding input changed"):
        bind_workflow(changed, advanced, **late)


@pytest.mark.parametrize("change", ["missing", "after-advance", "generation-collision"])
def test_retained_phase_history_cannot_erase_or_backdate_its_required_binding(change):
    value, query = successor_stage()
    bound = bind_workflow(query, value, **context(query))
    finished = move(bound, "reconciling")
    receipt = finished["bindings"][0]
    if change == "missing":
        finished["bindings"] = []
    else:
        receipt["generation"] = finished["generation"] + (change == "after-advance")
        receipt["request"]["expected_generation"] = receipt["generation"] - 1
        receipt["request_digest"] = digest(receipt["request"])
        finished["generation"] = max(finished["generation"], receipt["generation"])
    with pytest.raises(ContractError):
        validate_workflow(finished)


def test_same_ciphertext_other_publication_receipt_is_not_the_exact_child_output():
    value, query = adoption_stage()
    changed = copy.deepcopy(query)
    material = changed["materials"][0]
    receipt = material["publication_receipt"]
    receipt["current"]["asset_id"] += 1
    replacement = material_handle(
        material["material"]["owner"], digest(receipt), size=len(canonical(receipt))
    )
    old_digest = material["material"]["digest"]
    material["material"] = material["producer_output"] = replacement
    changed["content"] = [
        replacement if h["digest"] == old_digest else h for h in changed["content"]
    ]
    plan = changed["binding"]["plan"]
    plan["input_digests"] = [
        digest(receipt) if d == old_digest else d for d in plan["input_digests"]
    ]
    plan["subject"]["arguments"]["bundle_receipt"] = digest(receipt)
    reseal(plan)
    seal_material(material, value["id"])
    # Even a newly reviewed envelope cannot substitute another operation output.
    with pytest.raises(ContractError, match="producer result"):
        bind_workflow(changed, value, **context(changed))


def test_installed_target_phase_cannot_be_replaced_by_another_allowed_adapter_phase():
    intent = adapter_proposal()
    intent["participants"][0]["requests"][0]["phase"] = "reloaded"
    with pytest.raises(ContractError, match="installed procedure phase"):
        validate_workflow_proposal(intent)


def test_complete_late_binding_larger_than_frame_retains_all_staged_input():
    value, query = successor_stage()
    query["content"].extend(
        material_handle(value["owner"], "sha256:" + f"{index:064x}") for index in range(3000)
    )
    data = canonical(query)
    assert len(data) > MAX_BYTES
    reference, decoded_data = staged_workflow_input("workflow.bind", query)
    assert decoded_data == data
    assert len(frame(request("workflow.bind", reference))) < 4096
    with pytest.raises(ContractError, match="frame size"):
        frame(request("workflow.bind", query))
    with pytest.raises(ContractError):
        validate("ssh-request.schema.json", request("workflow.bind", query))


@pytest.mark.parametrize(
    "change", ["preplanned", "wrong-predecessor", "different-resource", "reversed-phase"]
)
def test_successor_intent_cannot_invent_a_new_graph_or_preaccept_a_stale_plan(change):
    value, _ = successor_stage()
    intent = value["proposal"]
    participant = intent["participants"][0]
    slot = participant["requests"][1]
    if change == "preplanned":
        participant["requests"][1] = {
            **copy.deepcopy(participant["requests"][0]),
            "request_id": slot["request_id"],
        }
    elif change == "wrong-predecessor":
        slot["intent"]["predecessor"]["request_id"] = uid("not-previous")
    elif change == "different-resource":
        slot["intent"]["subject"]["resource"]["id"] = "other-host"
    else:
        slot["phase"] = "draining"
    with pytest.raises(ContractError):
        validate_workflow_proposal(intent)
