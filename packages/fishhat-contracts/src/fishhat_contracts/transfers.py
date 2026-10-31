"""Complete shared workflow inspection models; no live owner admission.

These full-value helpers construct and validate an explicitly requested audit
projection from independently retained facts. They are not a journal writer or
a participant protocol: live admission uses workflow_journal and its partitioned
owner journals. Materialize complete views only for explicit inspection, never
after each accepted child or at every participating owner.

Decoded workflow-transfer custody checks, not a coordinator or an authorization layer.

The caller must independently authenticate participant witnesses and current receiving
permissions. Retained inputs model exact replay without mutating a store or driver.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .validation import ContractError, canonical, digest, validate


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _pairs(participants: list[dict[str, Any]]) -> set[bytes]:
    pairs = [canonical([item["owner"], item["resource"]]) for item in participants]
    _require(len(pairs) == len(set(pairs)), "duplicate transfer participant")
    return set(pairs)


def validate_transfer_proposal(proposal: dict[str, Any]) -> None:
    validate("records.schema.json", proposal, "WorkflowTransferProposal")
    _pairs(proposal["participants"])


def _proofs(witnesses: list[dict[str, Any]], proposal: dict[str, Any], state: str) -> set[bytes]:
    owners = {canonical(item["owner"]) for item in proposal["participants"]}
    proposal_digest = digest(proposal)
    found: set[bytes] = set()
    for witness in witnesses:
        validate("records.schema.json", witness, "WorkflowTransferWitness")
        owner = canonical(witness["owner"])
        _require(owner in owners and owner not in found, "transfer witness owner closure mismatch")
        _require(
            witness["kind"] == "transfer"
            and witness["workflow_id"] == proposal["workflow_id"]
            and witness["subject_digest"] == proposal_digest
            and witness["state"] == state,
            "transfer witness preimage or phase mismatch",
        )
        found.add(owner)
    return found


def _accepted_phases(transfer: dict[str, Any], generation: int) -> dict[str, dict[str, Any]]:
    phases: dict[str, dict[str, Any]] = {}
    proposal = transfer["proposal"]
    owners = {canonical(item["owner"]) for item in proposal["participants"]}
    for original in transfer["accepted_phases"]:
        phase = original["phase"]
        _require(phase not in phases, "duplicate retained transfer phase")
        _require(original["expected_generation"] < generation, "uncommitted transfer input")
        verified = _proofs(original["witnesses"], proposal, "frozen")
        if phase == "commit":
            _require(verified == owners, "commit input lacks complete freeze closure")
        phases[phase] = original
    expected = {"freeze"} if transfer["phase"] == "freeze" else {"freeze", "commit"}
    _require(set(phases) == expected, "retained transfer phase input missing")
    if "commit" in phases:
        _require(
            phases["freeze"]["expected_generation"] < phases["commit"]["expected_generation"],
            "transfer commit precedes freeze",
        )
    return phases


def _local_commits(
    transfer: dict[str, Any], phases: dict[str, dict[str, Any]], workflow: dict[str, Any]
) -> None:
    for phase, original in phases.items():
        witnesses = transfer[phase + "_witnesses"]
        local = next((item for item in witnesses if item["owner"] == workflow["owner"]), None)
        _require(local is not None, "local transfer phase lacks retained witness")
        assert local is not None
        _require(
            original["expected_generation"] < local["generation"] <= workflow["generation"],
            "local transfer witness generation mismatch",
        )
        if phase == "freeze" and "commit" in phases:
            _require(
                local["generation"] <= phases["commit"]["expected_generation"],
                "local freeze witness follows commit input",
            )


def validate_workflow_transfer(workflow: dict[str, Any]) -> None:
    """Check a schema-validated capsule's retained transfer joins and discoverable inputs."""
    from .workflow_transfer_history import workflow_transfer_ids

    workflow_transfer_ids(workflow)
    transfer = workflow["transfer"]
    if transfer is None:
        return
    proposal = transfer["proposal"]
    validate_transfer_proposal(proposal)
    _require(
        proposal["workflow_id"] == workflow["id"]
        and proposal["workflow_proposal_digest"] == workflow["proposal_digest"]
        and transfer["proposal_digest"] == digest(proposal)
        and _pairs(proposal["participants"]) == _pairs(workflow["participants"]),
        "transfer workflow or participant closure mismatch",
    )
    owners = {canonical(item["owner"]) for item in proposal["participants"]}
    frozen = _proofs(transfer["freeze_witnesses"], proposal, "frozen")
    committed = _proofs(transfer["commit_witnesses"], proposal, "transferred")
    phases = _accepted_phases(transfer, workflow["generation"])
    _local_commits(transfer, phases, workflow)
    phase = transfer["phase"]
    if phase == "freeze":
        _require(not committed, "transfer commits before freeze closure")
        principal, term = proposal["current_principal"], proposal["expected_term"]
    else:
        _require(frozen == owners, "transfer lacks complete freeze closure")
        accepted = {canonical(item) for item in phases["commit"]["witnesses"]}
        _require(
            accepted <= {canonical(item) for item in transfer["freeze_witnesses"]},
            "transfer discarded original commit prerequisites",
        )
        principal, term = proposal["new_principal"], proposal["expected_term"] + 1
    if phase == "completed":
        _require(committed == owners, "completed transfer lacks participant commits")
        receipts = [
            receipt
            for receipt in workflow["advances"]
            if receipt["authority"] == "driver"
            and receipt["request"]["transfer_completion"] is not None
            and receipt["request"]["transfer_completion"]["transfer_id"] == proposal["transfer_id"]
        ]
        _require(len(receipts) == 1, "completed transfer lacks exact advance receipt")
        receipt = receipts[0]
        completion = receipt["request"]["transfer_completion"]
        local = next(
            witness
            for witness in transfer["commit_witnesses"]
            if witness["owner"] == workflow["owner"]
        )
        # Retained proofs have unique owners; equal lengths keep duplicate
        # completion witnesses from disappearing in the exact-byte set comparison.
        _require(
            completion["proposal_digest"] == transfer["proposal_digest"]
            and len(completion["witnesses"]) == len(transfer["commit_witnesses"])
            and {canonical(item) for item in completion["witnesses"]}
            == {canonical(item) for item in transfer["commit_witnesses"]}
            and receipt["driver_term"] == proposal["expected_term"] + 1
            and local["generation"] < receipt["generation"],
            "completed transfer advance evidence or generation changed",
        )
    _require(
        workflow["driver_principal"] == principal and workflow["driver_term"] == term,
        "transfer driver preimage mismatch",
    )


def validate_transfer_request(
    request: dict[str, Any],
    workflow: dict[str, Any],
    *,
    retained_transfer: dict[str, Any] | None = None,
    recovery_readers: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]] | None = None,
) -> str:
    """Return replay or new for decoded current-capsule input; never grant execution.

    retained_transfer is independently selected protected custody for this exact
    transfer identity, including an older transfer exposed by workflow.transfer.get.
    Native owners check that index before new admission and authorize current read
    access before replay. Request bytes cannot supply their own retained record.
    Exact accepted input is replayable after later generation or driver changes;
    changed input never gains that rule.
    """
    from .handoffs import validate_workflow

    validate("records.schema.json", request, "WorkflowTransferRequest")
    validate_workflow(workflow, recovery_readers=recovery_readers)
    proposal = request["proposal"]
    validate_transfer_proposal(proposal)
    _require(
        request["owner"] == workflow["owner"]
        and proposal["workflow_id"] == workflow["id"]
        and proposal["workflow_proposal_digest"] == workflow["proposal_digest"]
        and _pairs(proposal["participants"]) == _pairs(workflow["participants"]),
        "transfer request owner or closure mismatch",
    )
    if retained_transfer is not None:
        from .workflow_transfer_history import transfer_phase_request, validate_transfer_record

        validate_transfer_record(
            retained_transfer,
            expected_owner=workflow["owner"],
            workflow_id=workflow["id"],
            transfer_id=proposal["transfer_id"],
        )
        _require(
            retained_transfer["transfer"]["proposal"] == proposal,
            "transfer identity reused with changed proposal",
        )
        original = transfer_phase_request(retained_transfer, request["phase"])
        if original is not None:
            _require(request == original, "accepted transfer phase input changed")
            return "replay"
        _require(
            workflow["transfer"] == retained_transfer["transfer"],
            "older transfer custody cannot admit a new phase",
        )
    retained = workflow["transfer"]
    if retained is not None and retained["proposal"]["transfer_id"] == proposal["transfer_id"]:
        _require(proposal == retained["proposal"], "transfer identity reused with changed proposal")
        for original in retained["accepted_phases"]:
            if original["phase"] == request["phase"]:
                expected = {"owner": workflow["owner"], "proposal": proposal, **original}
                _require(request == expected, "accepted transfer phase input changed")
                return "replay"
    elif retained is not None:
        _require(retained["phase"] == "completed", "another transfer retains custody")
    _require(
        workflow["state"] in {"prepared", "active", "paused", "recovery-required"},
        "terminal workflow cannot begin a driver transfer",
    )
    _require(
        workflow.get("recovery", {}).get("phase", "committed") == "committed",
        "workflow recovery preparation is not committed",
    )
    _require(
        request["expected_generation"] == workflow["generation"] < 9007199254740991,
        "transfer capsule generation changed",
    )
    _require(
        proposal["current_principal"] == workflow["driver_principal"]
        and proposal["expected_term"] == workflow["driver_term"],
        "transfer original driver changed",
    )
    frozen = _proofs(request["witnesses"], proposal, "frozen")
    if request["phase"] == "commit":
        _require(
            retained is not None and retained["proposal"] == proposal,
            "commit has no retained local freeze",
        )
        owners = {canonical(item["owner"]) for item in proposal["participants"]}
        _require(frozen == owners, "commit requires complete freeze closure")
        local = next(item for item in request["witnesses"] if item["owner"] == workflow["owner"])
        _require(
            local in retained["freeze_witnesses"],
            "commit substituted retained local freeze witness",
        )
    return "new"
