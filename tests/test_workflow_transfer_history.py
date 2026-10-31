"""Complete transfer rediscovery across multiple drivers and bounded transport."""

from __future__ import annotations

import copy

import pytest
from fishhat_client.wire import frame
from fishhat_contracts.handoffs import validate_cli_result, validate_workflow
from fishhat_contracts.record_delivery import (
    CHUNK_BYTES,
    RecordSnapshot,
    validate_record_chunk,
    validate_record_payload,
)
from fishhat_contracts.transfers import validate_transfer_request
from fishhat_contracts.validation import MAX_BYTES, ContractError, canonical, digest, validate
from fishhat_contracts.workflow_transfer_history import (
    transfer_phase_request,
    transfer_record,
    validate_transfer_lookup_result,
    validate_transfer_record,
    workflow_transfer_ids,
)
from fishhat_contracts.workflows import advance_workflow_view

from scripts.check_evidence import evidence_group
from tests.test_contracts import uid
from tests.test_owner_handoffs import request, wire
from tests.test_workflow_transfer import (
    attestation,
    commit_input,
    committed,
    completion_request,
    proposal,
)

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/workflow-transfer-history.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/records.schema.json#/$defs/WorkflowTransfer",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json#/$defs/RecordReference",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-request.schema.json",
        "packages/fishhat-contracts/src/fishhat_contracts/contracts/ssh-response.schema.json",
    ],
    "scope": "old and current transfer identity discovery, exact original phase reconstruction and complete scoped record delivery",
    "relationship": "candidate",
    "reason": "Two independently modeled transfer sequences and explicit retained records challenge lost-client replay, substituted identities, omitted custody and complete oversized delivery. Synthetic records do not qualify native authorization, indexing, persistence or signature authentication.",
    "claims": [],
}

CHECK_OVERRIDES = {
    "test_two_transfers_are_rediscoverable_without_client_state": {
        "contract": CHECK_PURPOSE,
        "extent": {
            "purpose": "implementation",
            "authority": [
                "packages/fishhat-contracts/src/fishhat_contracts/workflow_transfer_history.py#validate_transfer_record"
            ],
            "scope": "both independently retained transfer identities and their complete original accepted phase inputs",
            "relationship": "scoped-witness",
            "reason": "Reconstructs both accepted phases for each of two successive transfers after the current driver changes. Exact retained-input and witness comparisons establish reference record extent, not native retention, authentication or indexed lookup.",
            "claims": ["engineering:workflow.transfer-record"],
        },
    },
    "test_transfer_record_preserves_complete_witness_extent": {
        "contract": CHECK_PURPOSE,
        "extent": {
            "purpose": "implementation",
            "authority": [
                "packages/fishhat-contracts/src/fishhat_contracts/workflow_transfer_history.py#validate_transfer_record"
            ],
            "scope": "complete 600-participant transfer record after all bounded record chunks are reassembled",
            "relationship": "scoped-witness",
            "reason": "The independently constructed complete record survives semantic validation and bounded delivery byte-for-byte, including all original phase inputs and freeze/commit witnesses. This establishes complete reference input extent, not a count cap or native retrieval qualification.",
            "claims": ["engineering:workflow.transfer-record"],
        },
    },
}


def completed_record():
    value, _ = committed()
    value = advance_workflow_view(completion_request(value), value)
    return transfer_record(value)


def second_transfer(value):
    """Independent synthetic owner commits; production validators supply no native effect."""
    value = copy.deepcopy(value)
    selected = proposal(value)
    selected.update(transfer_id=uid("second-transfer"), new_principal="third-operator")
    freeze = {
        "owner": value["owner"],
        "proposal": selected,
        "expected_generation": value["generation"],
        "phase": "freeze",
        "witnesses": [],
    }
    assert validate_transfer_request(freeze, value) == "new"
    value["generation"] += 1
    value["transfer"] = {
        "proposal": copy.deepcopy(selected),
        "proposal_digest": digest(selected),
        "phase": "freeze",
        "accepted_phases": [
            {
                key: copy.deepcopy(freeze[key])
                for key in ("phase", "expected_generation", "witnesses")
            }
        ],
        "freeze_witnesses": [attestation(selected, value["owner"], "frozen", value["generation"])],
        "commit_witnesses": [],
    }
    validate_workflow(value)
    commit = commit_input(value)
    assert validate_transfer_request(commit, value) == "new"
    value["generation"] += 1
    value["driver_principal"] = selected["new_principal"]
    value["driver_term"] = selected["expected_term"] + 1
    transfer = value["transfer"]
    transfer["phase"] = "commit"
    transfer["accepted_phases"].append(
        {key: copy.deepcopy(commit[key]) for key in ("phase", "expected_generation", "witnesses")}
    )
    transfer["freeze_witnesses"] = copy.deepcopy(commit["witnesses"])
    transfer["commit_witnesses"] = [
        attestation(selected, value["owner"], "transferred", value["generation"])
    ]
    validate_workflow(value)
    completion = completion_request(value)
    completion["advance_id"] = uid("second-transfer-completion")
    return advance_workflow_view(completion, value)


def lookup(record):
    return {
        "owner": copy.deepcopy(record["owner"]),
        "workflow_id": record["workflow_id"],
        "transfer_id": record["id"],
    }


def many_participant_record(count):
    value = completed_record()
    transfer = value["transfer"]
    selected = transfer["proposal"]
    owners = [value["owner"]] + [
        {**value["owner"], "id": uid(f"history-owner-{index}")} for index in range(1, count)
    ]
    selected["participants"] = [
        {"owner": copy.deepcopy(owner), "resource": {"kind": "host", "id": f"host-{index}"}}
        for index, owner in enumerate(owners)
    ]
    transfer["proposal_digest"] = digest(selected)
    transfer["freeze_witnesses"] = [attestation(selected, owner, "frozen", 1) for owner in owners]
    transfer["commit_witnesses"] = [
        attestation(selected, owner, "transferred", 2) for owner in owners
    ]
    transfer["accepted_phases"][1]["witnesses"] = copy.deepcopy(transfer["freeze_witnesses"])
    receipt = value["completion"]
    completion = receipt["request"]["transfer_completion"]
    completion["proposal_digest"] = transfer["proposal_digest"]
    completion["witnesses"] = copy.deepcopy(transfer["commit_witnesses"])
    receipt["request_digest"] = digest(receipt["request"])
    validate_transfer_record(value)
    return value


def test_two_transfers_are_rediscoverable_without_client_state():
    first, _ = committed()
    first = advance_workflow_view(completion_request(first), first)
    retained = transfer_record(first)
    current = second_transfer(first)
    current_record = transfer_record(current)
    # This owner-selected index is independent of the incoming lookup and replay.
    protected = {record["id"]: record for record in (retained, current_record)}
    with evidence_group("extent"):
        identifiers = workflow_transfer_ids(current)
        assert identifiers == [retained["id"], current_record["id"]]
        for result in protected.values():
            assert len(result["transfer"]["accepted_phases"]) == 2
            for accepted in result["transfer"]["accepted_phases"]:
                original = transfer_phase_request(result, accepted["phase"])
                assert original == {
                    "owner": result["owner"],
                    "proposal": result["transfer"]["proposal"],
                    **accepted,
                }
        assert transfer_phase_request(retained, "freeze")["expected_generation"] == 0
        assert retained["generation"] < current_record["generation"]
    with evidence_group("contract"):
        assert current["driver_term"] == 3
        assert current["transfer"]["proposal"]["transfer_id"] != retained["id"]
        for identifier in identifiers:
            query = {
                "owner": current["owner"],
                "workflow_id": current["id"],
                "transfer_id": identifier,
            }
            result = protected[identifier]
            with pytest.raises(ContractError):
                validate("ssh-request.schema.json", request("workflow.transfer.get", query))
            with pytest.raises(ContractError):
                validate("ssh-response.schema.json", wire("workflow.transfer.get", result))
            validate_cli_result(result)
            validate_transfer_lookup_result(query, result)
            for phase in ("freeze", "commit"):
                original = transfer_phase_request(result, phase)
                assert original is not None
                before = canonical(current)
                assert (
                    validate_transfer_request(original, current, retained_transfer=result)
                    == "replay"
                )
                assert canonical(current) == before


@pytest.mark.parametrize("field", ["generation", "witnesses", "principal"])
def test_old_transfer_replay_does_not_refresh_original_input(field):
    first, _ = committed()
    first = advance_workflow_view(completion_request(first), first)
    retained = transfer_record(first)
    current = second_transfer(first)
    changed = transfer_phase_request(retained, "commit")
    assert changed is not None
    if field == "generation":
        changed["expected_generation"] = current["generation"]
    elif field == "witnesses":
        changed["witnesses"].reverse()
    else:
        changed["proposal"]["new_principal"] = current["driver_principal"]
    with pytest.raises(ContractError, match="changed"):
        validate_transfer_request(changed, current, retained_transfer=retained)


@pytest.mark.parametrize("field", ["owner", "workflow_id", "transfer_id"])
def test_transfer_lookup_correlates_every_requested_identity(field):
    value = completed_record()
    query = lookup(value)
    if field == "owner":
        query["owner"]["epoch"] = uid("unrelated-owner-epoch")
    else:
        query[field] = uid("unrelated-" + field)
    with pytest.raises(ContractError):
        validate_transfer_lookup_result(query, value)


def test_transfer_lookup_preserves_independently_installed_reader_context():
    value = completed_record()
    reference = RecordSnapshot(value, uid("retained-transfer-reader")).reference
    reference["schema"]["digest"] = "sha256:" + "9" * 64
    with pytest.raises(ContractError, match="schema substitution"):
        validate_transfer_lookup_result(lookup(value), reference)
    readers = {
        (reference["schema"]["uri"], reference["schema"]["digest"]): validate_transfer_record
    }
    validate_transfer_lookup_result(lookup(value), reference, retained_readers=readers)
    reference["record"]["resource"]["id"] = uid("unrelated-retained-workflow")
    with pytest.raises(ContractError, match="resource substitution"):
        validate_transfer_lookup_result(lookup(value), reference, retained_readers=readers)


@pytest.mark.parametrize("change", ["freeze", "commit", "phase", "completion", "generation"])
def test_transfer_record_rejects_omitted_or_substituted_retained_custody(change):
    value = completed_record()
    if change in {"freeze", "commit"}:
        value["transfer"][change + "_witnesses"].pop()
    elif change == "phase":
        value["transfer"]["accepted_phases"].pop()
    elif change == "completion":
        value["completion"]["request"]["transfer_completion"]["proposal_digest"] = (
            "sha256:" + "0" * 64
        )
        value["completion"]["request_digest"] = digest(value["completion"]["request"])
    else:
        value["generation"] += 1
    with pytest.raises(ContractError):
        validate_transfer_record(value)


def test_transfer_record_preserves_complete_witness_extent():
    value = many_participant_record(600)
    with evidence_group("contract"):
        encoded = canonical(value)
        assert len(encoded) > MAX_BYTES
        with pytest.raises(ContractError, match="frame size"):
            frame(wire("workflow.transfer.get", value))
        snapshot = RecordSnapshot(value, uid("large-transfer-history"))
        result = snapshot.delivery(max_inline_bytes=4096)
        assert result["kind"] == "RecordReference"
        validate_transfer_lookup_result(lookup(value), result)
        with pytest.raises(ContractError):
            validate("ssh-response.schema.json", wire("workflow.transfer.get", result))
        assert len(frame(wire("workflow.transfer.get", result))) < 4096
        parts = []
        offset = 0
        while offset < result["size"]:
            chunk = snapshot.chunk(result, offset=offset, length=CHUNK_BYTES)
            parts.append(validate_record_chunk(chunk, result, offset=offset, length=CHUNK_BYTES))
            offset = chunk["next_offset"]
    with evidence_group("extent"):
        recovered = validate_record_payload(
            result,
            b"".join(parts),
            expected_owner=value["owner"],
            expected_resource=value["resource"],
        )
        validate_transfer_lookup_result(lookup(value), recovered)
        assert recovered == value
        assert len(recovered["transfer"]["freeze_witnesses"]) == 600
        assert len(recovered["completion"]["request"]["transfer_completion"]["witnesses"]) == 600


def test_transfer_history_never_embeds_previous_workflow_snapshots():
    record = completed_record()
    assert set(record) == {
        "format",
        "kind",
        "id",
        "owner",
        "workflow_id",
        "resource",
        "generation",
        "transfer",
        "completion",
    }
    changed = copy.deepcopy(record)
    changed["previous_workflow"] = {"kind": "Workflow"}
    with pytest.raises(ContractError):
        validate_transfer_record(changed)
