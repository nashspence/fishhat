"""Explicit successor custody and preserved lifecycle, without native qualification."""

from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fishhat_contracts.handoffs import PHASES, validate_workflow
from fishhat_contracts.record_delivery import RecordSnapshot, validate_record_payload
from fishhat_contracts.transfers import validate_transfer_request
from fishhat_contracts.validation import ContractError, canonical, digest, validate
from fishhat_contracts.witness import sign
from fishhat_contracts.workflow_bindings import bind_workflow
from fishhat_contracts.workflow_recovery import (
    commit_workflow_recovery,
    prepare_workflow_recovery,
    validate_recovery_proposal,
)
from fishhat_contracts.workflow_settlement import record_native_completion
from fishhat_contracts.workflow_unprepared import origin_digest, origin_owner, origin_workflow_id
from fishhat_contracts.workflows import advance_workflow, decode_workflow_input, prepare_workflow

from tests.operation_support import seal_operation
from tests.test_contracts import uid
from tests.test_owner_handoffs import (
    operation,
    preparation_witnesses,
    request,
    staged_workflow_input,
    workflow,
)
from tests.test_owner_history import custody_for
from tests.test_plan_review import reseal
from tests.test_workflow_continuations import (
    adoption_stage,
    bind_request,
    context,
    move,
    publication_stage,
    seal_material,
    successor_stage,
)
from tests.test_workflow_transfer import (
    attestation,
    capsule,
    commit_input,
    committed,
    completion_request,
    frozen,
)
from tests.test_workflow_transfer import (
    proposal as transfer_proposal,
)
from tests.workflow_evidence_support import phase_evidence, seal_phase_participant
from tests.workflow_lifecycle_support import lifecycle, seal_lifecycle

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-recovery.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/Workflow",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/WorkflowTransfer",
    ],
    "scope": "orthogonal driver transfer and explicit current-authority workflow supersession",
    "relationship": "candidate",
    "reason": "Independent lost-client, expired-Plan, failed-child recovery, historical-custody and partial-transfer scenarios check preserved inputs and closed participant/disposition joins. Synthetic receiver context does not qualify native retirement, fencing, authentication, persistence or execution.",
    "claims": [],
}

NOW = "2026-10-18T12:00:00Z"
KEY = Ed25519PrivateKey.from_private_bytes(b"\x29" * 32)


def evidence(record):
    return {
        "reference": RecordSnapshot(record, uid("snapshot-" + digest(record))).reference,
        "operation": copy.deepcopy(record),
    }


def child_operation(binding, owner, *, state="succeeded", workflow_id=None):
    value = operation()
    plan = binding["plan"]
    value.update(
        id=uid("original-operation-" + binding["request_id"]),
        request_id=binding["request_id"],
        owner=copy.deepcopy(owner),
        subject=copy.deepcopy(plan["subject"]),
        plan_digest=plan["digest"],
        state=state,
        effect_certainty="known" if state == "succeeded" else "unknown",
        result_handle=None,
    )
    value["witness"]["workflow_id"] = workflow_id
    return seal_operation(value)


def selected_binding(record, participant, slot):
    for receipt in record["bindings"]:
        child = receipt["request"]["child"]
        if child == {"owner": participant["owner"], "request_id": slot["request_id"]}:
            return receipt["request"]["binding"]
    return slot


def original_disposition(binding, selected, disposition, origin, outcome):
    kind = disposition["kind"]
    owner = disposition["origin"]["owner"]
    if kind == "completed":
        done = copy.deepcopy(outcome or selected.get("operation")) or child_operation(
            selected, owner, workflow_id=origin_workflow_id(origin)
        )
        disposition["operation"] = evidence(done)
        result = {
            "request_id": binding["request_id"],
            "phase": binding["phase"],
            "completed": {"plan": copy.deepcopy(selected["plan"]), "operation": done},
        }
        if "adapter" in selected:
            result["completed"]["adapter"] = copy.deepcopy(selected["adapter"])
        return result
    if kind == "recovered":
        failed = child_operation(
            selected, owner, state="quarantined", workflow_id=origin_workflow_id(origin)
        )
        disposition["operation"] = evidence(failed)
        plan = copy.deepcopy(binding["plan"])
        plan["id"] = uid("recovery-plan-" + binding["request_id"])
        historical = (
            {
                "custody_id": origin["custody"]["id"],
                "reference": disposition["operation"]["reference"],
            }
            if origin["custody"] is not None
            else None
        )
        plan["subject"] = {
            "action": "operation.recover",
            "resource": plan["subject"]["resource"],
            "arguments": {
                "operation_id": failed["id"],
                "disposition": "native-reconcile",
                "origin": historical,
            },
        }
        if historical is not None:
            plan["input_digests"].append(disposition["operation"]["reference"]["digest"])
        reseal(plan)
        recovery = child_operation(
            {"request_id": uid("recovery-request-" + binding["request_id"]), "plan": plan},
            plan["owner"],
        )
        disposition["recovery"] = {**evidence(recovery), "plan": plan}
    return binding


def remap_children(value, changed_refs):
    if isinstance(value, dict):
        if set(value) == {"owner", "request_id"}:
            return copy.deepcopy(changed_refs[canonical(value)])
        return {k: remap_children(v, changed_refs) for k, v in value.items()}
    if isinstance(value, list):
        return [remap_children(v, changed_refs) for v in value]
    return value


def participant_capsule(original, owner):
    """Construct independent synthetic receiver evidence for the same proposal."""
    record = copy.deepcopy(original)
    record["owner"] = copy.deepcopy(owner)
    if "recovery" not in record:
        existing = {canonical(w) for w in record["prerequisite_witnesses"]}
        record["prerequisite_witnesses"].extend(
            w for w in preparation_witnesses(record["proposal"]) if canonical(w) not in existing
        )
    for receipt in record["bindings"] + record["advances"]:
        source = {"native-owner": "completion", "native-lifecycle": "decision"}.get(
            receipt.get("authority"), "request"
        )
        original = receipt[source]
        original["owner"] = copy.deepcopy(record["owner"])
        if source == "decision":
            seal_lifecycle(original, record)
        evidence = original.get("phase_evidence")
        if evidence is not None:
            evidence["transition"]["owner"] = copy.deepcopy(record["owner"])
            for proof in evidence["participants"]:
                seal_phase_participant(evidence, proof)
        receipt[source + "_digest"] = digest(original)
    return record


def scenario(
    *,
    historical=False,
    kinds=None,
    original=None,
    multiple=False,
    outcomes=None,
    never_prepared=None,
):
    original = copy.deepcopy(original or (capsule() if multiple else workflow()))
    kinds = kinds or ["unaccepted"] * sum(
        len(p["requests"]) for p in original["proposal"]["participants"]
    )
    outcomes = outcomes or {}
    records, origins, mappings = [], [], []
    for participant in original["proposal"]["participants"]:
        if any(p["origin"] == participant["owner"] for p in mappings):
            continue
        proof = (never_prepared or {}).get(canonical(participant["owner"]))
        if proof is not None:
            origins.append({"never_prepared": copy.deepcopy(proof)})
            records.append({"never_prepared": copy.deepcopy(proof)})
            current = copy.deepcopy(proof["owner"])
        else:
            record = participant_capsule(original, participant["owner"])
            custody = custody_for(record) if historical else None
            current = copy.deepcopy(custody["custodian"] if custody else record["owner"])
            reference = RecordSnapshot(record, uid("origin-" + record["owner"]["id"])).reference
            origins.append({"reference": reference, "custody": custody})
            records.append({"reference": reference, "custody": custody, "record": record})
        mappings.append({"origin": participant["owner"], "owner": current})

    def current(owner):
        return copy.deepcopy(next(p["owner"] for p in mappings if p["origin"] == owner))

    successor = copy.deepcopy(original["proposal"])
    successor["workflow_id"] = uid("successor-" + original["id"])
    successor["initial_driver"] = {"principal": "recovery-operator", "term": 1}
    changed_refs, children, declarations = {}, [], []
    index = 0
    for source in original["proposal"]["participants"]:
        participant = copy.deepcopy(source)
        participant["owner"] = current(source["owner"])
        participant["expected_generation"] = 20
        participant["requests"] = []
        for slot in source["requests"]:
            selected = selected_binding(original, source, slot)
            if "completed" in selected:
                selected = selected["completed"]
            new_id = uid("successor-child-" + slot["request_id"])
            old_ref = {"owner": source["owner"], "request_id": slot["request_id"]}
            new_ref = {"owner": participant["owner"], "request_id": new_id}
            changed_refs[canonical(old_ref)] = new_ref
            kind = kinds[index]
            index += 1
            disposition = {"origin": old_ref, "successor": new_ref, "kind": kind}
            if "plan" not in selected:
                assert kind == "unaccepted"
                participant["requests"].append({**copy.deepcopy(slot), "request_id": new_id})
                children.append(disposition)
                continue
            plan = copy.deepcopy(selected["plan"])
            plan.update(
                id=uid("new-plan-" + new_id),
                owner=participant["owner"],
                created_at=NOW,
                expires_at="2026-10-18T13:00:00Z",
            )
            for condition in plan["preconditions"]:
                condition.update(owner=current(condition["owner"]), generation=20)
            for effect in plan["effects"]:
                effect["executor"] = current(effect["executor"])
            plan["witness"]["owner"] = participant["owner"]
            reseal(plan)
            binding = {"request_id": new_id, "phase": slot["phase"], "plan": plan}
            if "adapter" in selected:
                binding["adapter"] = copy.deepcopy(selected["adapter"])
            origin = next(o for o in origins if origin_owner(o) == source["owner"])
            binding = original_disposition(
                binding,
                selected,
                disposition,
                origin,
                outcomes.get(canonical(old_ref), outcomes.get(slot["request_id"])),
            )
            if (
                "intent" in slot
                and kind != "completed"
                and (
                    original["type"] == "secret-rotation"
                    or any("completed" not in prior for prior in participant["requests"])
                )
            ):
                binding = {**copy.deepcopy(slot), "request_id": new_id}
            children.append(disposition)
            participant["requests"].append(binding)
        declarations.append(participant)
    successor["participants"] = declarations

    successor["target"] = remap_children(original["proposal"]["target"], changed_refs)
    for participant in successor["participants"]:
        for slot in participant["requests"]:
            if "intent" in slot:
                slot["intent"] = remap_children(slot["intent"], changed_refs)
    contents = list(original["proposal"]["content"])
    for receipt in original["bindings"]:
        contents.extend(receipt["request"]["content"])
    successor["content"] = []
    for handle in contents:
        handle = {**copy.deepcopy(handle), "owner": current(handle["owner"])}
        if handle not in successor["content"]:
            successor["content"].append(handle)
    proposal = {
        "format": "deployment-ops/workflow-recovery/v1",
        "recovery_id": uid("recovery-" + original["id"]),
        "workflow_id": successor["workflow_id"],
        "origins": origins,
        "participants": mappings,
        "children": children,
        "successor": successor,
        "abandonments": [],
    }
    return proposal, copy.deepcopy(records)


def preparation(proposal, owner):
    mapping = next(p for p in proposal["participants"] if p["owner"] == owner)
    origin = next(o for o in proposal["origins"] if origin_owner(o) == mapping["origin"])
    children = [c for c in proposal["children"] if c["origin"]["owner"] == mapping["origin"]]
    value = {
        "owner": copy.deepcopy(owner),
        "recovery_id": proposal["recovery_id"],
        "proposal_digest": digest(proposal),
        "retirement": {
            "format": "deployment-ops/workflow-retirement/v1",
            "owner": copy.deepcopy(owner),
            "origin": copy.deepcopy(mapping["origin"]),
            "recovery_id": proposal["recovery_id"],
            "proposal_digest": digest(proposal),
            "origin_digest": origin_digest(origin),
            "children_digest": digest(children),
            "native_evidence": digest({"independently-verified": "closed-and-settled"}),
            "retained_closure_digest": digest({"retained": "old-inputs-holds-and-readers"}),
            "state": "closed",
        },
    }
    body = {k: v for k, v in operation()["witness"].items() if k != "signature"}
    body.update(
        owner=copy.deepcopy(owner),
        kind="approval",
        state="workflow-supersession-prepared",
        workflow_id=proposal["workflow_id"],
        subject_digest=digest(value),
        generation=0,
    )
    value["witness"] = sign(body, KEY)
    return value


def prepare(proposal, records, *, owner=None, **overrides):
    owner = owner or proposal["participants"][0]["owner"]
    query = {"owner": owner, "phase": "prepare", "proposal": proposal}
    arguments = {
        "expected_owner": owner,
        "recovery_authorized": True,
        "verified_proposal": copy.deepcopy(proposal),
        "verified_origins": records,
        "verified_preparation": preparation(proposal, owner),
        "verified_content": proposal["successor"]["content"],
        "retained_preparation": None,
        "reserved_successor": None,
        "verified_abandonments": [],
        "local_abandonments": [],
    }
    arguments.update(overrides)
    return prepare_workflow_recovery(query, **arguments)


def commit(value, proposal, **context):
    preparations = [preparation(proposal, p["owner"]) for p in proposal["participants"]]
    query = {
        "owner": value["owner"],
        "phase": "commit",
        "workflow_id": value["id"],
        "recovery_id": proposal["recovery_id"],
        "proposal_digest": digest(proposal),
        "expected_generation": value["generation"],
        "preparations": preparations,
    }
    return query, commit_workflow_recovery(
        query, value, recovery_authorized=True, verified_preparations=preparations, **context
    )


@pytest.mark.parametrize("historical", [False, True], ids=["current", "restored"])
@pytest.mark.parametrize("kind", ["unaccepted", "completed", "recovered"])
def test_successor_retains_original_outcomes_and_current_authority(historical, kind):
    proposal, records = scenario(historical=historical, kinds=[kind])
    originals = [canonical(r["record"]) for r in records]
    value = prepare(proposal, records)
    assert value["id"] != records[0]["record"]["id"]
    assert value["recovery"]["phase"] == "prepared"
    assert value["state"] == "prepared"
    query, result = commit(value, proposal)
    assert result["recovery"]["phase"] == "committed"
    assert result["generation"] == 1
    assert [canonical(r["record"]) for r in records] == originals
    assert result["recovery"]["request"]["proposal"] == proposal
    assert result["recovery"]["commit"]["request"] == query
    assert result["driver_term"] == 1
    assert result["driver_principal"] == "recovery-operator"
    assert ("completed" in result["proposal"]["participants"][0]["requests"][0]) == (
        kind == "completed"
    )


def test_expired_bound_child_gets_fresh_request_after_completed_predecessor():
    original, binding = successor_stage()
    original = bind_workflow(binding, original, **context(binding))
    predecessor = binding["predecessors"][0]
    proposal, records = scenario(
        original=original,
        kinds=["completed", "unaccepted"],
        outcomes={predecessor["request_id"]: predecessor},
    )
    _, successor = commit(prepare(proposal, records), proposal)
    children = successor["proposal"]["participants"][0]["requests"]
    assert "completed" in children[0]
    assert children[1]["plan"]["created_at"] == NOW
    assert children[1]["request_id"] != binding["child"]["request_id"]
    assert original["bindings"][0]["request"] == binding
    collision = copy.deepcopy(proposal)
    old_request_id = original["proposal"]["participants"][0]["requests"][0]["request_id"]
    old_reference = collision["children"][1]["successor"]
    replacement = {**copy.deepcopy(old_reference), "request_id": old_request_id}
    references = {canonical(d["successor"]): d["successor"] for d in collision["children"]}
    references[canonical(old_reference)] = replacement
    collision["successor"]["target"] = remap_children(collision["successor"]["target"], references)
    collision["successor"]["participants"][0]["requests"][1]["request_id"] = old_request_id
    collision["children"][1]["successor"] = replacement
    with pytest.raises(ContractError, match="reused an old request identity"):
        validate_recovery_proposal(collision, verified_origins=records)


@pytest.mark.parametrize("historical", [False, True], ids=["current", "restored"])
@pytest.mark.parametrize("stage", ["publication", "adoption"])
def test_rotation_recovery_keeps_completed_output_and_rebinds_only_unused_child(stage, historical):
    original, previous = publication_stage() if stage == "publication" else adoption_stage()
    original = bind_workflow(previous, original, **context(previous))
    issued = original["bindings"][0]["request"]["predecessors"][0]
    outcomes = {issued["request_id"]: issued}
    kinds = ["completed", "unaccepted", "unaccepted"]
    index = 1
    if stage == "adoption":
        published = previous["predecessors"][0]
        outcomes[published["request_id"]] = published
        kinds = ["completed", "completed", "unaccepted"]
        index = 2
    proposal, records = scenario(
        original=original, historical=historical, kinds=kinds, outcomes=outcomes
    )
    _, successor = commit(prepare(proposal, records), proposal)
    successor = move(successor, "issuer-changing" if stage == "publication" else "publishing")
    participant = successor["proposal"]["participants"][index]
    material = copy.deepcopy(previous["materials"][0])
    material["producer"] = successor["proposal"]["target"][
        "issuer_change" if stage == "publication" else "publication"
    ]
    for key in ("material", "producer_output"):
        material[key]["owner"] = copy.deepcopy(participant["owner"])
    seal_material(material, successor["id"])
    subject = copy.deepcopy(previous["binding"]["plan"]["subject"])
    if stage == "publication":
        subject["arguments"]["candidate"] = material["material"]
    content = list(
        {canonical(material[k]): material[k] for k in ("material", "producer_output")}.values()
    )
    query = bind_request(
        successor,
        participant,
        subject,
        previous["predecessors"][0],
        content=content,
        material=material,
        generation=participant["expected_generation"],
    )
    plan = query["binding"]["plan"]
    plan.update(created_at=NOW, expires_at="2026-10-18T13:00:00Z")
    reseal(plan)
    authority = context(query)
    authority.update(
        verified_driver={
            "principal": successor["driver_principal"],
            "term": successor["driver_term"],
        },
        now=NOW,
    )
    result = bind_workflow(query, successor, **authority)
    assert result["bindings"][0]["request"]["predecessors"] == previous["predecessors"]
    assert result["proposal"]["participants"][0]["requests"][0]["completed"]["operation"] == issued
    assert (
        result["bindings"][0]["request"]["child"]["request_id"] != previous["child"]["request_id"]
    )


@pytest.mark.parametrize("producer", ["issuer", "publisher"])
def test_generic_recovery_links_adapter_and_publisher_failure_to_exact_original_operation(producer):
    original, binding = publication_stage()
    if producer == "publisher":
        original = bind_workflow(binding, original, **context(binding))
    kinds = (
        ["recovered", "unaccepted", "unaccepted"]
        if producer == "issuer"
        else ["completed", "recovered", "unaccepted"]
    )
    issued = binding["predecessors"][0]
    proposal, records = scenario(
        original=original, kinds=kinds, outcomes={issued["request_id"]: issued}
    )
    value = prepare(proposal, records)
    disposition = proposal["children"][0 if producer == "issuer" else 1]
    recovery = disposition["recovery"]
    assert recovery["plan"]["subject"]["action"] == "operation.recover"
    assert (
        recovery["plan"]["subject"]["resource"]
        == disposition["operation"]["operation"]["subject"]["resource"]
    )
    assert value["recovery"]["phase"] == "prepared"


@pytest.mark.parametrize("kind", ["Workflow", "Operation"])
def test_other_historical_schema_reader_is_inspection_only_for_workflow_recovery(kind):
    proposal, records = scenario(historical=True, kinds=["completed"])
    if kind == "Workflow":
        reference = proposal["origins"][0]["reference"]
        record = records[0]["record"]
    else:
        reference = proposal["children"][0]["operation"]["reference"]
        record = proposal["children"][0]["operation"]["operation"]
    reader_digest = digest({"installed-previous-semantic-reader": kind})
    reference["schema"]["digest"] = reader_digest
    if kind == "Workflow":
        records[0]["reference"] = copy.deepcopy(reference)
    readers = {reader_digest: lambda value: validate("records.schema.json", value, kind)}
    assert (
        validate_record_payload(
            reference,
            canonical(record),
            expected_owner=reference["owner"],
            retained_readers=readers,
        )
        == record
    )
    with pytest.raises(ContractError, match="unsupported workflow recovery schema"):
        validate_recovery_proposal(proposal, verified_origins=records, retained_readers=readers)


def test_historical_prepared_capsule_recovers_partial_transfer_without_an_operation():
    original, freeze = frozen(workflow())
    proposal, records = scenario(original=original, historical=True)
    _, value = commit(prepare(proposal, records), proposal)
    assert all(d["kind"] == "unaccepted" for d in proposal["children"])
    assert records[0]["record"]["transfer"]["phase"] == "freeze"
    assert (
        records[0]["record"]["transfer"]["accepted_phases"][0]["expected_generation"]
        == freeze["expected_generation"]
    )
    assert value["transfer"] is None
    assert value["owner"]["epoch"] != original["owner"]["epoch"]


def test_restored_partial_commit_requires_both_current_custodians():
    proposal, records = scenario(multiple=True, historical=True)
    committed_origin, accepted_commit = committed()
    peer = capsule()
    peer["owner"] = copy.deepcopy(peer["participants"][1]["owner"])
    peer["prerequisite_witnesses"] = preparation_witnesses(peer["proposal"])
    frozen_origin, accepted_freeze = frozen(peer)
    for index, record in enumerate((committed_origin, frozen_origin)):
        custody = custody_for(record)
        reference = RecordSnapshot(record, uid("partial-origin-" + str(index))).reference
        proposal["origins"][index] = {"reference": reference, "custody": custody}
        records[index] = copy.deepcopy(
            {"reference": reference, "custody": custody, "record": record}
        )
    before = [canonical(r["record"]) for r in records]
    a = prepare(proposal, records, owner=proposal["participants"][0]["owner"])
    b = prepare(proposal, records, owner=proposal["participants"][1]["owner"])
    query, result = commit(a, proposal)
    assert len(query["preparations"]) == 2
    assert [canonical(r["record"]) for r in records] == before
    assert records[0]["record"]["driver_term"] == 2
    assert records[1]["record"]["driver_term"] == 1
    assert (
        records[0]["record"]["transfer"]["accepted_phases"][1]["witnesses"]
        == accepted_commit["witnesses"]
    )
    assert (
        records[1]["record"]["transfer"]["accepted_phases"][0]["expected_generation"]
        == (accepted_freeze["expected_generation"])
    )
    assert b["recovery"]["preparations"][0] in query["preparations"]
    assert result["driver_term"] == 1
    assert result["transfer"] is None
    query["preparations"].pop()
    with pytest.raises(ContractError, match="complete participant"):
        commit_workflow_recovery(
            query, a, recovery_authorized=True, verified_preparations=query["preparations"]
        )


@pytest.mark.parametrize(
    "field", ["recovery_authorized", "verified_proposal", "verified_origins", "verified_content"]
)
def test_recovery_request_cannot_supply_its_own_authority_or_custody(field):
    proposal, records = scenario()
    bad = False if field == "recovery_authorized" else ({} if field == "verified_proposal" else [])
    with pytest.raises(ContractError):
        prepare(proposal, records, **{field: bad})


@pytest.mark.parametrize(
    "change",
    [
        "missing-origin",
        "missing-child",
        "old-id",
        "wrong-resource",
        "wrong-epoch",
        "stale-reference",
    ],
)
def test_successor_cannot_omit_or_retarget_protected_predecessor_closure(change):
    proposal, records = scenario(multiple=True)
    if change == "missing-origin":
        proposal["origins"].pop()
    elif change == "missing-child":
        proposal["children"].pop()
    elif change == "old-id":
        proposal["workflow_id"] = records[0]["record"]["id"]
        proposal["successor"]["workflow_id"] = proposal["workflow_id"]
    elif change == "wrong-resource":
        proposal["successor"]["participants"][0]["resource"]["id"] = "different-host"
    elif change == "wrong-epoch":
        proposal["participants"][0]["owner"]["epoch"] = uid("unproven-epoch")
    else:
        proposal["origins"][0]["reference"]["snapshot_id"] = uid("older-valid-snapshot")
    with pytest.raises(ContractError):
        validate_recovery_proposal(proposal, verified_origins=records)


@pytest.mark.parametrize(
    "change",
    ["failed-recovery", "unknown-recovery", "different-operation", "changed-original-plan"],
)
def test_failed_child_requires_separate_exact_successful_recovery(change):
    proposal, records = scenario(kinds=["recovered"])
    disposition = proposal["children"][0]
    changed = disposition["recovery"]
    if change == "failed-recovery":
        disposition["recovery"]["operation"]["state"] = "failed"
    elif change == "unknown-recovery":
        disposition["recovery"]["operation"]["effect_certainty"] = "unknown"
    elif change == "different-operation":
        disposition["recovery"]["plan"]["subject"]["arguments"]["operation_id"] = uid("unrelated")
        reseal(disposition["recovery"]["plan"])
        changed["operation"]["plan_digest"] = changed["plan"]["digest"]
        changed["operation"]["subject"] = copy.deepcopy(changed["plan"]["subject"])
    else:
        disposition["operation"]["operation"]["plan_digest"] = digest({"other": "plan"})
        changed = disposition["operation"]
    seal_operation(changed["operation"])
    data = canonical(changed["operation"])
    changed["reference"].update(digest=digest(changed["operation"]), size=len(data))
    with pytest.raises(ContractError):
        validate_recovery_proposal(proposal, verified_origins=records)


def test_partial_preparation_blocks_progress_and_all_participants_are_required():
    proposal, records = scenario(multiple=True)
    value = prepare(proposal, records)
    advance = {
        "owner": value["owner"],
        "workflow_id": value["id"],
        "advance_id": uid("early-advance"),
        "driver_term": 1,
        "expected_generation": 0,
        "phase": "draining",
        "witnesses": [],
        "transfer_completion": None,
        "phase_evidence": None,
    }
    with pytest.raises(ContractError, match="not committed"):
        advance_workflow(advance, value)
    transfer = {
        "owner": value["owner"],
        "expected_generation": 0,
        "proposal": transfer_proposal(value),
        "phase": "freeze",
        "witnesses": [],
    }
    with pytest.raises(ContractError, match="not committed"):
        validate_transfer_request(transfer, value)
    query, _ = commit(value, proposal)
    query["preparations"].pop()
    with pytest.raises(ContractError, match="complete participant"):
        commit_workflow_recovery(
            query, value, recovery_authorized=True, verified_preparations=query["preparations"]
        )


def test_preparation_and_commit_replay_keep_original_inputs_after_expiry():
    proposal, records = scenario()
    value = prepare(proposal, records)
    query, result = commit(value, proposal)
    replay = prepare(proposal, records, reserved_successor=result, verified_proposal={})
    assert replay == result
    assert (
        commit_workflow_recovery(query, result, recovery_authorized=True, verified_preparations=[])
        == result
    )
    changed = copy.deepcopy(query)
    changed["expected_generation"] += 1
    with pytest.raises(ContractError, match="accepted recovery commit"):
        commit_workflow_recovery(
            changed, result, recovery_authorized=True, verified_preparations=[]
        )
    with pytest.raises(ContractError, match="authority"):
        commit_workflow_recovery(query, result, recovery_authorized=False, verified_preparations=[])


def test_retained_success_is_not_executable_through_ordinary_prepare():
    proposal, records = scenario(kinds=["completed"])
    successor = proposal["successor"]
    owner = successor["participants"][0]["owner"]
    with pytest.raises(ContractError, match="explicit recovery"):
        prepare_workflow(
            {"owner": owner, "proposal": successor},
            expected_owner=owner,
            principal="operator",
            verified_driver=successor["initial_driver"],
            verified_content=successor["content"],
            verified_preparation=None,
        )
    validate_recovery_proposal(proposal, verified_origins=records)


def test_recovery_uses_bounded_staged_transport_and_discoverable_workflow_output():
    proposal, records = scenario(historical=True)
    owner = proposal["participants"][0]["owner"]
    query = {"owner": owner, "phase": "prepare", "proposal": proposal}
    reference, data = staged_workflow_input("workflow.recover", query)
    validate("ssh-request.schema.json", request("workflow.recover", reference))
    assert decode_workflow_input("workflow.recover", reference, data, expected_owner=owner) == query
    result = prepare(proposal, records)
    validate("records.schema.json", result, "Workflow")
    assert result["recovery"]["request"] == query


def finish_transfer(value):
    value, _ = frozen(value)
    original = commit_input(value)
    assert validate_transfer_request(original, value) == "new"
    transfer = value["transfer"]
    transfer["phase"] = "commit"
    transfer["accepted_phases"].append(
        {k: copy.deepcopy(original[k]) for k in ("phase", "expected_generation", "witnesses")}
    )
    transfer["freeze_witnesses"] = copy.deepcopy(original["witnesses"])
    value["generation"] += 1
    value["driver_principal"] = transfer["proposal"]["new_principal"]
    value["driver_term"] = transfer["proposal"]["expected_term"] + 1
    transfer["commit_witnesses"] = [
        attestation(transfer["proposal"], value["owner"], "transferred", value["generation"])
    ]
    query = completion_request(value)
    query["phase"] = value["phase"]
    return advance_workflow(query, value), query


@pytest.mark.parametrize("state", ["prepared", "active", "paused", "recovery-required"])
def test_driver_transfer_preserves_lifecycle_and_exact_replay(state):
    original = workflow()
    if state == "active":
        original = move(original, PHASES[original["type"]][1])
    elif state != "prepared":
        original = lifecycle(original, "pause" if state == "paused" else "require-recovery")
    value, query = finish_transfer(original)
    assert value["state"] == state
    assert value["phase"] == original["phase"]
    assert advance_workflow(query, value) == value
    if state == "recovery-required":
        following = {
            **query,
            "advance_id": uid("unsafe-revival"),
            "expected_generation": value["generation"],
            "phase": "draining",
            "transfer_completion": None,
        }
        with pytest.raises(ContractError, match="cannot advance"):
            advance_workflow(following, value)


@pytest.mark.parametrize("state", ["cancelled", "completed"])
def test_terminal_workflow_cannot_begin_new_driver_transfer(state):
    value = workflow()
    if state == "completed":
        value = move(value, PHASES[value["type"]][-1])
    else:
        value = lifecycle(value, "cancel")
    validate_workflow(value)
    query = {
        "owner": value["owner"],
        "expected_generation": value["generation"],
        "proposal": transfer_proposal(value),
        "phase": "freeze",
        "witnesses": [],
    }
    with pytest.raises(ContractError, match="terminal workflow"):
        validate_transfer_request(query, value)


def native_completion_input(value):
    """Construct an explicit synthetic native event, never a driver request."""
    query = {
        "owner": copy.deepcopy(value["owner"]),
        "workflow_id": value["id"],
        "advance_id": uid(f"native-completion-{value['id']}-{value['generation']}"),
        "expected_generation": value["generation"],
        "driver_term": value["driver_term"],
    }
    query["phase_evidence"] = phase_evidence(
        value, {**query, "phase": PHASES[value["type"]][-1]}, authority="native-owner"
    )
    return query


def native_completion(value):
    query = native_completion_input(value)
    return record_native_completion(
        query,
        value,
        expected_owner=value["owner"],
        native_authorized=True,
        verified_phase_evidence=copy.deepcopy(query["phase_evidence"]),
    )


@pytest.mark.parametrize("phase", ["freeze", "commit", "completed"])
@pytest.mark.parametrize("state", ["cancelled", "completed"])
def test_terminal_lifecycle_keeps_exact_accepted_transfer_replay(phase, state):
    start = capsule()
    if state == "completed":
        start = move(start, PHASES[start["type"]][-2])
    if phase == "freeze":
        value, original = frozen(start)
    elif phase == "commit":
        value, original = committed(start)
    else:
        value, original = finish_transfer(start)
    if state == "completed":
        value = native_completion(value)
    else:
        value = lifecycle(value, "cancel")
    value["generation"] += 1
    validate_workflow(value)
    if phase == "completed":
        assert advance_workflow(original, value) == value
    else:
        assert validate_transfer_request(original, value) == "replay"
    if phase == "freeze":
        with pytest.raises(ContractError, match="terminal workflow"):
            validate_transfer_request(commit_input(value), value)
    elif phase == "commit":
        with pytest.raises(ContractError, match="cannot advance"):
            advance_workflow(completion_request(value), value)


@pytest.mark.parametrize("state", ["prepared", "active", "paused", "recovery-required"])
def test_transfer_completion_cannot_combine_driver_change_with_phase_progress(state):
    value = capsule()
    if state == "active":
        value = move(value, PHASES[value["type"]][1])
    elif state != "prepared":
        value = lifecycle(value, "pause" if state == "paused" else "require-recovery")
    value, _ = committed(value)
    query = completion_request(value)
    phases = PHASES[value["type"]]
    query["phase"] = phases[phases.index(value["phase"]) + 1]
    with pytest.raises(ContractError):
        advance_workflow(query, value)
