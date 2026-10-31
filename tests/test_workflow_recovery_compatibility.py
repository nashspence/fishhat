"""Exact installed recovery readers preserve compatible immutable v1 evidence."""

from __future__ import annotations

import copy

import pytest
from fishhat_contracts.handoffs import schema_identity, validate_result_payload, validate_workflow
from fishhat_contracts.operations import (
    operation_plan_request,
    validate_operation,
    validate_operation_plan,
)
from fishhat_contracts.record_delivery import RecordSnapshot, validate_record_payload
from fishhat_contracts.validation import SCHEMAS, ContractError, canonical, digest, validate
from fishhat_contracts.workflow_recovery import validate_recovery_proposal
from fishhat_contracts.workflows import advance_workflow_view

from tests.test_contracts import uid
from tests.test_workflow_continuations import adoption_stage
from tests.test_workflow_recovery import commit, prepare, scenario

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-recovery.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/workflow_recovery.py",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow.schema.json",
    ],
    "scope": "explicit installed recovery compatibility and unchanged original evidence",
    "relationship": "candidate",
    "reason": "Reachable description changes exercise retained compatible records and producer outputs through successor custody. Missing, miskeyed, mutating and semantically incompatible readers are rejected. Synthetic installed context does not prove native authentication, qualification or execution.",
    "claims": [],
}


def editorial_change(monkeypatch):
    changed = copy.deepcopy(SCHEMAS["records.schema.json"])
    workflow = changed["$defs"]["Workflow"]
    workflow["description"] = workflow.get("description", "") + " Retained workflow clarification."
    monkeypatch.setitem(SCHEMAS, "records.schema.json", changed)
    changed = copy.deepcopy(SCHEMAS["publisher-receipt.schema.json"])
    changed["description"] = changed.get("description", "") + " Retained publication clarification."
    monkeypatch.setitem(SCHEMAS, "publisher-receipt.schema.json", changed)


def installed_readers(proposal):
    """Synthetic owner installation, deliberately separate from wire evidence."""
    inspected, qualified = {}, {}
    references = [o["reference"] for o in proposal["origins"]]
    operations = []
    for child in proposal["children"]:
        for name in ("operation", "recovery"):
            if name in child:
                evidence = child[name]
                references.append(evidence["reference"])
                operations.append(evidence["operation"])
    for operation in operations:
        result = operation["result_handle"]
        if result is not None:
            identity = result["schema"]
            schema, definition = identity["uri"].split("/contracts/")[1], None
            if "#/$defs/" in schema:
                schema, definition = schema.split("#/$defs/")

            def payload_reader(value, schema=schema, definition=definition):
                validate(schema, value, definition)

            qualified[(identity["uri"], identity["digest"])] = payload_reader
    for reference in references:
        kind = reference["record"]["kind"]

        def reader(value, kind=kind):
            if kind == "Workflow":
                validate_workflow(value, recovery_readers=qualified)
            else:
                validate_operation(value, recovery_readers=qualified)

        identity = reference["schema"]
        inspected[(identity["uri"], identity["digest"])] = reader
        qualified[(identity["uri"], identity["digest"])] = reader
    return inspected, qualified


def test_editorial_schema_change_requires_explicit_recovery_qualification(monkeypatch):
    proposal, records = scenario(historical=True, kinds=["completed"])
    retained, qualified = installed_readers(proposal)
    before = canonical({"proposal": proposal, "records": records})
    reference = proposal["origins"][0]["reference"]
    editorial_change(monkeypatch)
    assert reference["schema"] != schema_identity(reference["schema"]["uri"])
    with pytest.raises(ContractError, match="independently installed compatible v1 reader"):
        validate_recovery_proposal(proposal, verified_origins=records, retained_readers=retained)
    with pytest.raises(ContractError, match="record schema substitution"):
        validate_recovery_proposal(proposal, verified_origins=records, recovery_readers=qualified)
    value = prepare(proposal, records, retained_readers=retained, recovery_readers=qualified)
    _, committed = commit(value, proposal, recovery_readers=qualified)
    replayed = prepare(
        proposal,
        records,
        retained_preparation=committed,
        verified_proposal={},
        verified_origins=[],
        verified_content=[],
        retained_readers=retained,
        recovery_readers=qualified,
    )
    assert replayed == committed
    assert committed["recovery"]["request"]["proposal"] == proposal
    assert canonical({"proposal": proposal, "records": records}) == before


@pytest.mark.parametrize("change", ["wrong-uri", "wrong-digest"])
def test_recovery_qualification_matches_both_exact_schema_identity_parts(monkeypatch, change):
    proposal, records = scenario(historical=True, kinds=["completed"])
    retained, qualified = installed_readers(proposal)
    identity = proposal["origins"][0]["reference"]["schema"]
    reader = qualified.pop((identity["uri"], identity["digest"]))
    key = (
        identity["uri"] + "/other" if change == "wrong-uri" else identity["uri"],
        digest({"other": "closure"}) if change == "wrong-digest" else identity["digest"],
    )
    qualified[key] = reader
    editorial_change(monkeypatch)
    with pytest.raises(ContractError, match="independently installed compatible v1 reader"):
        prepare(proposal, records, retained_readers=retained, recovery_readers=qualified)


def test_recovery_reader_cannot_translate_original_evidence(monkeypatch):
    proposal, records = scenario(historical=True, kinds=["completed"])
    retained, qualified = installed_readers(proposal)
    identity = proposal["origins"][0]["reference"]["schema"]
    before = canonical(records)

    def rewrite(record):
        record["generation"] += 1

    qualified[(identity["uri"], identity["digest"])] = rewrite
    editorial_change(monkeypatch)
    with pytest.raises(ContractError, match="reader changed original bytes"):
        prepare(proposal, records, retained_readers=retained, recovery_readers=qualified)
    assert canonical(records) == before


def test_qualified_reader_cannot_bypass_current_v1_recovery_semantics(monkeypatch):
    proposal, records = scenario(historical=True, kinds=["completed"])
    retained, qualified = installed_readers(proposal)
    original = records[0]
    original["record"]["phase"] = "outside-procedure"
    data = canonical(original["record"])
    original["reference"].update(digest=digest(original["record"]), size=len(data))
    proposal["origins"][0]["reference"] = copy.deepcopy(original["reference"])
    identity = original["reference"]["schema"]
    retained[identity["digest"]] = lambda value: None
    qualified[(identity["uri"], identity["digest"])] = lambda value: None
    editorial_change(monkeypatch)
    with pytest.raises(ContractError, match="phase outside installed procedure"):
        prepare(proposal, records, retained_readers=retained, recovery_readers=qualified)


def test_reader_rejection_and_wire_claim_cannot_grant_recovery_compatibility(monkeypatch):
    proposal, records = scenario(historical=True, kinds=["completed"])
    retained, qualified = installed_readers(proposal)
    identity = proposal["origins"][0]["reference"]["schema"]

    def unsupported(record):
        raise ContractError("incompatible historical recovery semantics")

    qualified[(identity["uri"], identity["digest"])] = unsupported
    editorial_change(monkeypatch)
    with pytest.raises(ContractError, match="incompatible historical recovery semantics"):
        prepare(proposal, records, retained_readers=retained, recovery_readers=qualified)
    proposal["origins"][0]["recovery_compatible"] = True
    with pytest.raises(ContractError):
        prepare(proposal, records, retained_readers=retained)


def test_historical_publisher_output_remains_usable_through_successor_lifecycle(monkeypatch):
    original, adoption = adoption_stage()
    issued = original["bindings"][0]["request"]["predecessors"][0]
    published = adoption["predecessors"][0]
    receipt = adoption["materials"][0]["publication_receipt"]
    proposal, records = scenario(
        original=original,
        historical=True,
        kinds=["completed", "completed", "unaccepted"],
        outcomes={issued["request_id"]: issued, published["request_id"]: published},
    )
    retained, qualified = installed_readers(proposal)
    before = canonical({"proposal": proposal, "records": records})
    original_result = copy.deepcopy(published["result_handle"])
    editorial_change(monkeypatch)
    result_schema = original_result["schema"]
    assert result_schema != schema_identity(result_schema["uri"])
    missing_result_reader = dict(qualified)
    missing_result_reader.pop((result_schema["uri"], result_schema["digest"]))
    with pytest.raises(ContractError, match="action result schema substitution"):
        prepare(
            proposal, records, retained_readers=retained, recovery_readers=missing_result_reader
        )
    value = prepare(proposal, records, retained_readers=retained, recovery_readers=qualified)
    _, value = commit(value, proposal, recovery_readers=qualified)
    snapshot = RecordSnapshot(value, uid("compatible-successor-read"), recovery_readers=qualified)
    read = validate_record_payload(
        snapshot.reference,
        canonical(value),
        expected_owner=value["owner"],
        recovery_readers=qualified,
    )
    assert read == value
    with pytest.raises(ContractError, match="action result schema substitution"):
        RecordSnapshot.restore(snapshot.reference, canonical(value), expected_owner=value["owner"])
    restored = RecordSnapshot.restore(
        snapshot.reference,
        canonical(value),
        expected_owner=value["owner"],
        recovery_readers=qualified,
    )
    assert restored.reference == snapshot.reference
    assert restored.record == value
    advance = {
        "owner": value["owner"],
        "workflow_id": value["id"],
        "advance_id": uid("compatible-successor-advance"),
        "driver_term": value["driver_term"],
        "expected_generation": value["generation"],
        "phase": "participants-quiescent",
        "witnesses": [],
        "transfer_completion": None,
    }
    from tests.workflow_evidence_support import phase_evidence

    advance["phase_evidence"] = phase_evidence(value, advance)
    moved = advance_workflow_view(
        advance,
        value,
        verified_phase_evidence=copy.deepcopy(advance["phase_evidence"]),
        now="2026-11-01T00:00:00Z",
        recovery_readers=qualified,
    )
    validate_workflow(moved, recovery_readers=qualified)
    kept = moved["proposal"]["participants"][1]["requests"][0]["completed"]["operation"]
    assert kept == published
    assert kept["result_handle"] == original_result
    plan = moved["proposal"]["participants"][1]["requests"][0]["completed"]["plan"]
    assert operation_plan_request(kept, recovery_readers=qualified) == {
        "owner": published["owner"],
        "plan_digest": plan["digest"],
    }
    validate_operation_plan(kept, plan, recovery_readers=qualified)
    assert validate_result_payload(kept, canonical(receipt), recovery_readers=qualified) == receipt
    rejecting = dict(qualified)

    def reject_payload(value):
        raise ContractError("historical publication semantics unsupported")

    rejecting[(result_schema["uri"], result_schema["digest"])] = reject_payload
    with pytest.raises(ContractError, match="historical publication semantics unsupported"):
        validate_result_payload(kept, canonical(receipt), recovery_readers=rejecting)

    def mutate_payload(value):
        value["id"] = uid("translated-publication")

    rejecting[(result_schema["uri"], result_schema["digest"])] = mutate_payload
    with pytest.raises(ContractError, match="result reader changed original bytes"):
        validate_result_payload(kept, canonical(receipt), recovery_readers=rejecting)
    assert canonical({"proposal": proposal, "records": records}) == before
