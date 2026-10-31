"""Complete shared workflow inspection models; no live owner admission.

These full-value helpers construct and validate an explicitly requested audit
projection from independently retained facts. They are not a journal writer or
a participant protocol: live admission uses workflow_journal and its partitioned
owner journals. Materialize complete views only for explicit inspection, never
after each accepted child or at every participating owner.

Discoverable exact driver-transfer custody, independent of the current transfer.

These pure models do not create a store or authenticate a native owner. Native
lookups use protected transfer identity indexes and current workflow read scope;
old custody is retained before the current Workflow selects another transfer.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from typing import Any

from .bounds import Bounds, bounds
from .transfers import _accepted_phases, _local_commits, _proofs, validate_transfer_proposal
from .validation import ContractError, canonical, digest, validate


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _completion(record: dict[str, Any]) -> None:
    transfer, receipt = record["transfer"], record["completion"]
    if transfer["phase"] != "completed":
        _require(receipt is None, "unfinished transfer has a completion receipt")
        return
    _require(receipt is not None, "completed transfer history lacks its original receipt")
    assert receipt is not None
    request, proposal = receipt["request"], transfer["proposal"]
    completion = request["transfer_completion"]
    _require(completion is not None, "transfer history receipt is not a completion")
    assert completion is not None
    _require(
        receipt["authority"] == "driver"
        and request["owner"] == record["owner"]
        and request["workflow_id"] == record["workflow_id"]
        and request["driver_term"] == receipt["driver_term"] == proposal["expected_term"] + 1
        and request["expected_generation"] + 1 == receipt["generation"] == record["generation"]
        and request["phase"] == receipt["phase"]
        and receipt["state"] in {"prepared", "active", "paused", "recovery-required"}
        and request["phase_evidence"] is None
        and receipt["request_digest"] == digest(request),
        "transfer history completion outcome changed",
    )
    _require(
        completion["transfer_id"] == record["id"]
        and completion["proposal_digest"] == transfer["proposal_digest"]
        and len(completion["witnesses"]) == len(transfer["commit_witnesses"])
        and {canonical(w) for w in completion["witnesses"]}
        == {canonical(w) for w in transfer["commit_witnesses"]},
        "transfer history completion witness closure changed",
    )
    local = next(w for w in transfer["commit_witnesses"] if w["owner"] == record["owner"])
    _require(
        local["generation"] < receipt["generation"],
        "transfer history completion precedes local commit",
    )


@bounds(
    Bounds(
        id="workflow.transfer-record",
        work="O(B) complete selected transfer record bytes, with owner-indexed witness joins; unrelated transfer history is not an input",
        extent="Every original proposal participant, accepted phase input, freeze/commit witness and exact completion receipt for the selected transfer identity",
        limits=(),
        capacity=("native receiving capacity may explicitly refuse reads without truncation",),
        proofs=(
            "tests/test_workflow_transfer_history.py::test_two_transfers_are_rediscoverable_without_client_state",
            "tests/test_workflow_transfer_history.py::test_transfer_record_preserves_complete_witness_extent",
        ),
        linear_proofs=(
            "tests/test_workflow_transfer_history_growth.py::test_transfer_history_validation_linear_complete_witness_work",
        ),
    )
)
def validate_transfer_record(
    record: dict[str, Any],
    *,
    expected_owner: dict[str, Any] | None = None,
    workflow_id: str | None = None,
    transfer_id: str | None = None,
) -> None:
    """Check the complete selected record and independent lookup expectations.

    Native witness authentication, latest-custody selection and current read
    permission remain required. This does not validate unrelated workflow history
    or turn a retained transfer receipt into a new driver capability.
    """
    validate("workflow-transfer-history.schema.json", record, "WorkflowTransferRecord")
    transfer = record["transfer"]
    proposal = transfer["proposal"]
    validate_transfer_proposal(proposal)
    _require(
        record["id"] == proposal["transfer_id"]
        and record["workflow_id"] == proposal["workflow_id"]
        and record["resource"] == {"kind": "workflow", "id": record["workflow_id"]}
        and transfer["proposal_digest"] == digest(proposal),
        "transfer history identity changed",
    )
    if expected_owner is not None:
        _require(record["owner"] == expected_owner, "transfer history receiving owner changed")
    if workflow_id is not None:
        _require(record["workflow_id"] == workflow_id, "transfer history workflow changed")
    if transfer_id is not None:
        _require(record["id"] == transfer_id, "transfer history selected transfer changed")
    owners = {canonical(p["owner"]) for p in proposal["participants"]}
    _require(canonical(record["owner"]) in owners, "transfer history owner is not a participant")
    frozen = _proofs(transfer["freeze_witnesses"], proposal, "frozen")
    committed = _proofs(transfer["commit_witnesses"], proposal, "transferred")
    phases = _accepted_phases(transfer, record["generation"])
    _local_commits(transfer, phases, record)
    if transfer["phase"] == "freeze":
        _require(not committed, "transfer history commits before freeze closure")
    else:
        _require(frozen == owners, "transfer history lacks complete freeze closure")
        _require(
            {canonical(w) for w in phases["commit"]["witnesses"]}
            <= {canonical(w) for w in transfer["freeze_witnesses"]},
            "transfer history discarded accepted commit prerequisites",
        )
    if transfer["phase"] == "completed":
        _require(committed == owners, "transfer history lacks complete commit closure")
    else:
        local = next(
            w for w in transfer[transfer["phase"] + "_witnesses"] if w["owner"] == record["owner"]
        )
        _require(
            record["generation"] == local["generation"],
            "transfer history generation is not its original local outcome",
        )
    _completion(record)


def transfer_record(
    workflow: dict[str, Any],
    *,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> dict[str, Any]:
    """Project current custody for atomic native retention before replacement.

    The returned record is independent of later capsule generations and contains
    no recursively embedded Workflow. Native persistence is not supplied here.
    """
    from .handoffs import validate_workflow

    validate_workflow(workflow, recovery_readers=recovery_readers)
    transfer = workflow["transfer"]
    _require(transfer is not None, "workflow has no retained transfer")
    assert transfer is not None
    identifier = transfer["proposal"]["transfer_id"]
    receipt = next(
        (
            r
            for r in workflow["advances"]
            if r["authority"] == "driver"
            and r["request"]["transfer_completion"] is not None
            and r["request"]["transfer_completion"]["transfer_id"] == identifier
        ),
        None,
    )
    phase = "commit" if transfer["phase"] == "completed" else transfer["phase"]
    local = next(w for w in transfer[phase + "_witnesses"] if w["owner"] == workflow["owner"])
    result = {
        "format": "deployment-ops/record/v1",
        "kind": "WorkflowTransferRecord",
        "id": identifier,
        "owner": copy.deepcopy(workflow["owner"]),
        "workflow_id": workflow["id"],
        "resource": {"kind": "workflow", "id": workflow["id"]},
        "generation": local["generation"] if receipt is None else receipt["generation"],
        "transfer": copy.deepcopy(transfer),
        "completion": copy.deepcopy(receipt),
    }
    validate_transfer_record(result)
    return result


def workflow_transfer_ids(workflow: dict[str, Any]) -> list[str]:
    """Enumerate IDs from complete inspected capsule history, without a count cap.

    The caller first verifies this Workflow's bytes, schema, owner and current
    read scope. Each subsequent lookup independently authorizes that transfer.
    """
    result: list[str] = []
    for receipt in workflow["advances"]:
        if receipt["authority"] != "driver":
            continue
        completion = receipt["request"]["transfer_completion"]
        if completion is not None:
            result.append(completion["transfer_id"])
    _require(len(set(result)) == len(result), "workflow repeats a completed transfer identity")
    transfer = workflow["transfer"]
    if transfer is not None:
        identifier = transfer["proposal"]["transfer_id"]
        if transfer["phase"] == "completed":
            _require(
                bool(result) and result[-1] == identifier,
                "current transfer is not latest completion",
            )
        else:
            _require(identifier not in result, "pending transfer reused completed identity")
            result.append(identifier)
    return result


def transfer_phase_request(record: dict[str, Any], phase: str) -> dict[str, Any] | None:
    """Reconstruct an accepted original input from complete verified transfer custody."""
    validate_transfer_record(record)
    _require(phase in {"freeze", "commit"}, "unknown workflow transfer phase")
    original = next(
        (item for item in record["transfer"]["accepted_phases"] if item["phase"] == phase), None
    )
    if original is None:
        return None
    return {
        "owner": copy.deepcopy(record["owner"]),
        "proposal": copy.deepcopy(record["transfer"]["proposal"]),
        **copy.deepcopy(original),
    }


def validate_transfer_lookup_result(
    request: dict[str, Any],
    result: dict[str, Any],
    *,
    retained_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> None:
    """Correlate inline or bounded-reference lookup output before using its custody."""
    validate("workflow-transfer-history.schema.json", request, "LookupRequest")
    if result.get("kind") == "RecordReference":
        from .record_delivery import validate_record_reference

        validate_record_reference(
            result,
            expected_owner=request["owner"],
            expected_resource={"kind": "workflow", "id": request["workflow_id"]},
            retained_readers=retained_readers,
        )
        _require(
            result["record"]["kind"] == "WorkflowTransferRecord"
            and result["record"]["id"] == request["transfer_id"],
            "transfer lookup reference changed selected identity",
        )
        return
    validate_transfer_record(
        result,
        expected_owner=request["owner"],
        workflow_id=request["workflow_id"],
        transfer_id=request["transfer_id"],
    )
